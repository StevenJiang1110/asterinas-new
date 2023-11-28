use jinux_rights::Rights;
use smoltcp::wire::IpEndpoint;

use crate::events::IoEvents;
use crate::fs::file_handle::FileLike;
use crate::fs::utils::{IoctlCmd, StatusFlags};
use crate::net::iface::RawTcpSocket;
use crate::net::socket::ip::tcp_options::TcpWindowClamp;
use crate::net::socket::util::{
    send_recv_flags::SendRecvFlags, shutdown_cmd::SockShutdownCmd, sockaddr::SocketAddr,
};
use crate::process::signal::Poller;
use crate::{match_sock_option_ref, prelude::*};

use crate::match_sock_option_mut;
use crate::net::socket::options::{
    SockErrors, SockOption, SocketError, SocketLinger, SocketOptions, SocketRecvBuf,
    SocketReuseAddr, SocketReusePort, SocketSendBuf, MIN_RECVBUF, MIN_SENDBUF,
};
use crate::net::socket::Socket;

use self::options::{TcpCongestion, TcpMaxseg, TcpNoDelay, TcpOptions, DEFAULT_MAXSEG};
use self::{connected::ConnectedStream, init::InitStream, listen::ListenStream};

mod connected;
mod init;
mod listen;
pub mod options;
mod util;

pub struct StreamSocket {
    options: RwLock<Options>,
    state: RwLock<State>,
    // TODO: Avoid using mutex here
    rights: Mutex<Rights>,
}

enum State {
    // Start state
    Init(Arc<InitStream>),
    // Final State 1
    Connected(Arc<ConnectedStream>),
    // Final State 2
    Listen(Arc<ListenStream>),
}

#[derive(Debug, Clone)]
struct Options {
    socket: SocketOptions,
    tcp: TcpOptions,
}

impl Options {
    fn new() -> Self {
        let socket = SocketOptions::new_tcp();
        let tcp = TcpOptions::new();
        Options { socket, tcp }
    }
}

impl StreamSocket {
    pub fn new(nonblocking: bool) -> Self {
        let options = Options::new();
        let state = State::Init(Arc::new(InitStream::new(nonblocking)));
        Self {
            options: RwLock::new(options),
            state: RwLock::new(state),
            rights: Mutex::new(Rights::all()),
        }
    }

    fn is_nonblocking(&self) -> bool {
        match &*self.state.read() {
            State::Init(init) => init.is_nonblocking(),
            State::Connected(connected) => connected.is_nonblocking(),
            State::Listen(listen) => listen.is_nonblocking(),
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) {
        match &*self.state.read() {
            State::Init(init) => init.set_nonblocking(nonblocking),
            State::Connected(connected) => connected.set_nonblocking(nonblocking),
            State::Listen(listen) => listen.set_nonblocking(nonblocking),
        }
    }

    fn check_rights(&self, rights: Rights) -> Result<()> {
        if self.rights.lock().contains(rights) {
            Ok(())
        } else {
            return_errno_with_message!(Errno::EPIPE, "The local end has been shut down");
        }
    }

    fn do_connect(&self, remote_endpoint: IpEndpoint) -> Result<()> {
        let init_stream = match &*self.state.read() {
            State::Init(init_stream) => init_stream.clone(),
            State::Connected(..) => {
                return_errno_with_message!(Errno::EISCONN, "the endpoint is already connected")
            }
            _ => return_errno_with_message!(Errno::EINVAL, "cannot connect"),
        };

        let mut sock_errors = SockErrors::no_error();
        if let Err(e) = init_stream.connect(&remote_endpoint, &mut sock_errors) {
            let mut options = self.options.write();
            options.socket.set_sock_errors(sock_errors);
            return Err(e);
        };

        let connected_stream = {
            let nonblocking = init_stream.is_nonblocking();
            let bound_socket = init_stream.bound_socket().unwrap();

            let state = bound_socket.raw_with(|socket: &mut RawTcpSocket| socket.state());
            println!("state = {:?}", state);
            let remote_endpoint = init_stream.remote_endpoint()?;
            Arc::new(ConnectedStream::new(
                nonblocking,
                bound_socket,
                remote_endpoint,
            ))
        };

        *self.state.write() = State::Connected(connected_stream);
        Ok(())
    }
}

impl FileLike for StreamSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // FIXME: set correct flags
        let flags = SendRecvFlags::empty();
        let (recv_len, _) = self.recvfrom(buf, flags)?;
        Ok(recv_len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        // FIXME: set correct flags
        let flags = SendRecvFlags::empty();
        self.sendto(buf, None, flags)
    }

    fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        let state = self.state.read();
        match &*state {
            State::Init(init) => init.poll(mask, poller),
            State::Connected(connected) => connected.poll(mask, poller),
            State::Listen(listen) => listen.poll(mask, poller),
        }
    }

    fn ioctl(&self, cmd: IoctlCmd, arg: usize) -> Result<i32> {
        match cmd {
            IoctlCmd::FIONBIO => {
                self.set_nonblocking(true);
            }
            _ => return_errno_with_message!(Errno::EINVAL, "unsupported ioctl cmd"),
        }
        Ok(0)
    }

    fn status_flags(&self) -> StatusFlags {
        if self.is_nonblocking() {
            StatusFlags::O_NONBLOCK
        } else {
            StatusFlags::empty()
        }
    }

    fn set_status_flags(&self, new_flags: StatusFlags) -> Result<()> {
        if new_flags.contains(StatusFlags::O_NONBLOCK) {
            self.set_nonblocking(true);
        } else {
            self.set_nonblocking(false);
        }
        Ok(())
    }

    fn as_socket(&self) -> Option<&dyn Socket> {
        Some(self)
    }

    fn clean_for_close(&self) -> Result<()> {
        Ok(())
    }
}

impl Socket for StreamSocket {
    fn bind(&self, sockaddr: SocketAddr) -> Result<()> {
        let endpoint = sockaddr.try_into()?;
        let state = self.state.read();
        match &*state {
            State::Init(init_stream) => init_stream.bind(endpoint),
            _ => return_errno_with_message!(Errno::EINVAL, "cannot bind"),
        }
    }

    fn connect(&self, sockaddr: SocketAddr) -> Result<()> {
        let remote_endpoint = sockaddr.try_into()?;

        self.do_connect(remote_endpoint)
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let mut state = self.state.write();
        match &*state {
            State::Init(init_stream) => {
                if !init_stream.is_bound() {
                    init_stream.bind_to_ephemeral_endpoint()?;
                }
                let nonblocking = init_stream.is_nonblocking();
                let bound_socket = init_stream.bound_socket().unwrap();
                let listener = Arc::new(ListenStream::new(nonblocking, bound_socket, backlog)?);
                *state = State::Listen(listener);
                Ok(())
            }
            State::Listen(listen_stream) => listen_stream.listen(backlog),
            _ => return_errno_with_message!(Errno::EINVAL, "cannot listen"),
        }
    }

    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        self.check_rights(Rights::READ)
            .map_err(|_| Error::with_message(Errno::EINVAL, "the listening socket is shut down"))?;

        let listen_stream = match &*self.state.read() {
            State::Listen(listen_stream) => listen_stream.clone(),
            _ => return_errno_with_message!(Errno::EINVAL, "the socket is not listening"),
        };

        let (connected_stream, remote_endpoint, sock_errors) = {
            let listen_stream = listen_stream.clone();
            listen_stream.accept()?
        };

        let accepted_socket = {
            let state = RwLock::new(State::Connected(Arc::new(connected_stream)));

            let options = {
                let mut options = Options::new();
                options.socket.set_sock_errors(sock_errors);
                RwLock::new(options)
            };

            Arc::new(StreamSocket {
                options,
                state,
                rights: Mutex::new(Rights::all()),
            })
        };

        let socket_addr: SocketAddr = remote_endpoint.try_into()?;
        Ok((accepted_socket, socket_addr))
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        if cmd.shut_read() {
            *self.rights.lock() -= Rights::READ;
        }

        if cmd.shut_write() {
            *self.rights.lock() -= Rights::WRITE;
        }

        let state = self.state.read();
        match &*state {
            State::Connected(connected_stream) => connected_stream.shutdown(cmd),
            State::Listen(listen_stream) => listen_stream.shutdown(cmd),
            State::Init(init_stream) => init_stream.shutdown(cmd),
        }
    }

    fn addr(&self) -> Result<SocketAddr> {
        let state = self.state.read();
        let local_endpoint = match &*state {
            State::Init(init_stream) => init_stream.local_endpoint()?,
            State::Listen(listen_stream) => listen_stream.local_endpoint(),
            State::Connected(connected_stream) => connected_stream.local_endpoint(),
        };
        local_endpoint.try_into()
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let state = self.state.read();
        let remote_endpoint = match &*state {
            State::Init(init_stream) => init_stream.remote_endpoint(),
            State::Listen(listen_stream) => {
                return_errno_with_message!(Errno::EINVAL, "listening socket does not have peer")
            }
            State::Connected(connected_stream) => connected_stream.remote_endpoint(),
        }?;
        remote_endpoint.try_into()
    }

    fn recvfrom(&self, buf: &mut [u8], flags: SendRecvFlags) -> Result<(usize, SocketAddr)> {
        self.check_rights(Rights::READ)?;

        let connected_stream = match &*self.state.read() {
            State::Connected(connected_stream) => connected_stream.clone(),
            _ => return_errno_with_message!(Errno::EINVAL, "the socket is not connected"),
        };

        let (recv_size, remote_endpoint) = connected_stream.recvfrom(buf, flags)?;
        let socket_addr = remote_endpoint.try_into()?;
        Ok((recv_size, socket_addr))
    }

    fn sendto(
        &self,
        buf: &[u8],
        remote: Option<SocketAddr>,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        self.check_rights(Rights::WRITE)?;

        let state = self.state.read();
        match &*state {
            State::Init(_) => {
                // Connect if the socket is not connected
                // debug_assert!(remote.is_some());
                let Some(remote) = remote else {
                    return_errno_with_message!(Errno::EPIPE, "No peer address is set");
                };

                let remote_endpoint = remote.try_into()?;

                drop(state);
                self.do_connect(remote_endpoint).map_err(|e| match e {
                    e if e.error() == Errno::ECONNREFUSED => {
                        Error::with_message(Errno::EPIPE, "connection request was refused")
                    }
                    _ => e,
                })?;
            }
            State::Connected(connected_stream) => {
                debug_assert!(remote.is_none());
                if remote.is_some() {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "tcp socked should not provide remote addr"
                    );
                }

                let connected_stream = connected_stream.clone();
                drop(state);

                return connected_stream.sendto(buf, flags);
            }
            _ => return_errno_with_message!(Errno::EPIPE, "cannot send"),
        }

        let state = self.state.read();
        match &*state {
            State::Connected(connected_stream) => {
                let connected_stream = connected_stream.clone();
                drop(state);

                connected_stream.sendto(buf, flags)
            }
            _ => return_errno_with_message!(Errno::EPIPE, "invalid socket state"),
        }
    }

    fn option(&self, option: &mut dyn SockOption) -> Result<()> {
        let options = self.options.read();
        match_sock_option_mut!(option, {
            // Socket Options
            socket_errors: SocketError => {
                let sock_errors = options.socket.sock_errors();
                socket_errors.set_output(sock_errors);
            },
            socket_reuse_addr: SocketReuseAddr => {
                let reuse_addr = options.socket.reuse_addr();
                socket_reuse_addr.set_output(reuse_addr);
            },
            socket_send_buf: SocketSendBuf => {
                let send_buf = options.socket.send_buf();
                socket_send_buf.set_output(send_buf);
            },
            socket_recv_buf: SocketRecvBuf => {
                let recv_buf = options.socket.recv_buf();
                socket_recv_buf.set_output(recv_buf);
            },
            socket_reuse_port: SocketReusePort => {
                let reuse_port = options.socket.reuse_port();
                socket_reuse_port.set_output(reuse_port);
            },
            // Tcp Options
            tcp_no_delay: TcpNoDelay => {
                let no_delay = options.tcp.no_delay();
                tcp_no_delay.set_output(no_delay);
            },
            tcp_congestion: TcpCongestion => {
                let congestion = options.tcp.congestion();
                tcp_congestion.set_output(congestion);
            },
            tcp_maxseg: TcpMaxseg => {
                // It will always return the default MSS value defined above for an unconnected socket
                // and always return the actual current MSS for a connected one.

                // FIXME: how to get the current MSS?
                let maxseg = match &*self.state.read() {
                    State::Init(_) | State::Listen(_) => DEFAULT_MAXSEG,
                    State::Connected(_) => options.tcp.maxseg(),
                };
                tcp_maxseg.set_output(maxseg);
            },
            tcp_window_clamp: TcpWindowClamp => {
                let window_clamp = options.tcp.window_clamp();
                tcp_window_clamp.set_output(window_clamp);
            },
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "get unknown option")
        });
        Ok(())
    }

    fn set_option(&self, option: &dyn SockOption) -> Result<()> {
        let mut options = self.options.write();
        // FIXME: here we have only set the value of the option, without actually
        // making any real modifications.
        match_sock_option_ref!(option, {
            // Socket options
            socket_recv_buf: SocketRecvBuf => {
                let recv_buf = socket_recv_buf.input().unwrap();
                if *recv_buf <= MIN_RECVBUF {
                    options.socket.set_recv_buf(MIN_RECVBUF);
                } else{
                    options.socket.set_recv_buf(*recv_buf);
                }
            },
            socket_send_buf: SocketSendBuf => {
                let send_buf = socket_send_buf.input().unwrap();
                if *send_buf <= MIN_SENDBUF {
                    options.socket.set_send_buf(MIN_SENDBUF);
                } else {
                    options.socket.set_send_buf(*send_buf);
                }
            },
            socket_reuse_addr: SocketReuseAddr => {
                let reuse_addr = socket_reuse_addr.input().unwrap();
                options.socket.set_reuse_addr(*reuse_addr);
            },
            socket_reuse_port: SocketReusePort => {
                let reuse_port = socket_reuse_port.input().unwrap();
                options.socket.set_reuse_port(*reuse_port);
            },
            socket_linger: SocketLinger => {
                let linger = socket_linger.input().unwrap();
                options.socket.set_linger(*linger);
            },
            // Tcp options
            tcp_no_delay: TcpNoDelay => {
                let no_delay = tcp_no_delay.input().unwrap();
                options.tcp.set_no_delay(*no_delay);
            },
            tcp_congestion: TcpCongestion => {
                let congestion = tcp_congestion.input().unwrap();
                options.tcp.set_congestion(*congestion);
            },
            tcp_maxseg: TcpMaxseg => {
                const MIN_MAXSEG: u32 = 536;
                const MAX_MAXSEG: u32 = 65535;
                let maxseg = tcp_maxseg.input().unwrap();

                if *maxseg < MIN_MAXSEG || *maxseg > MAX_MAXSEG {
                    return_errno_with_message!(Errno::EINVAL, "New maxseg should be in allowed range.");
                }

                options.tcp.set_maxseg(*maxseg);
            },
            tcp_window_clamp: TcpWindowClamp => {
                let window_clamp = tcp_window_clamp.input().unwrap();
                let half_recv_buf = (options.socket.recv_buf()) / 2;
                if *window_clamp <= half_recv_buf {
                    options.tcp.set_window_clamp(half_recv_buf);
                } else {
                    options.tcp.set_window_clamp(*window_clamp);
                }
            },
            _ => return_errno_with_message!(Errno::ENOPROTOOPT, "set unknown option")
        });
        Ok(())
    }
}

impl Drop for StreamSocket {
    fn drop(&mut self) {
        println!("drop socket");
        match &*self.state.read() {
            State::Init(init_stream) => init_stream.clean_for_close(),
            State::Connected(connected_stream) => connected_stream.clean_for_close(),
            State::Listen(listen_stream) => listen_stream.clean_for_close(),
        }
    }
}
