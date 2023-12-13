use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use smoltcp::wire::IpListenEndpoint;

use crate::events::{IoEvents, Observer};
use crate::net::iface::{AnyUnboundSocket, BindConfig, IpEndpoint};

use crate::net::iface::{AnyBoundSocket, RawTcpSocket};
use crate::net::socket::options::SockErrors;
use crate::net::socket::SockShutdownCmd;
use crate::process::signal::Poller;
use crate::{net::poll_ifaces, prelude::*};

use super::connected::ConnectedStream;
use super::util::{close_and_submit_linger_workitem, is_local_closed, is_peer_closed};

pub struct ListenStream {
    is_nonblocking: AtomicBool,
    backlog: AtomicUsize,
    /// A bound socket held to ensure the TCP port cannot be released
    bound_socket: Arc<AnyBoundSocket>,
    /// Backlog sockets listening at the local endpoint
    /// Sockets also listening at LocalEndPoint when called `listen`
    backlog_sockets: RwLock<Vec<BacklogSocket>>,
}

impl ListenStream {
    pub fn new(
        nonblocking: bool,
        bound_socket: Arc<AnyBoundSocket>,
        backlog: usize,
    ) -> Result<Self> {
        // println!("listen, backlog = {}", backlog);
        // if backlog > 3 {
        //     backlog = 3;
        // }

        let listen_stream = Self {
            is_nonblocking: AtomicBool::new(nonblocking),
            backlog: AtomicUsize::new(backlog),
            bound_socket: bound_socket.clone(),
            backlog_sockets: RwLock::new(Vec::new()),
        };
        listen_stream.fill_backlog_sockets()?;
        close_and_submit_linger_workitem(bound_socket);
        Ok(listen_stream)
    }

    pub fn listen(&self, backlog: usize) -> Result<()> {
        debug_assert!(backlog >= self.backlog());
        // println!("listen again, backlog = {}", backlog);
        // if backlog >= 3 {
        //     backlog = 3;
        // }
        self.backlog.store(backlog, Ordering::Release);
        self.fill_backlog_sockets()
    }

    pub fn accept(&self) -> Result<(ConnectedStream, IpEndpoint, SockErrors)> {
        // wait to accept
        let poller = Poller::new();
        loop {
            poll_ifaces();
            let accepted_socket = match self.try_accept() {
                Ok(accepted_socket) => accepted_socket,
                Err(e) if e.error() == Errno::EAGAIN => {
                    let events = self.poll(IoEvents::IN | IoEvents::OUT, Some(&poller));
                    if !events.contains(IoEvents::IN) && !events.contains(IoEvents::OUT) {
                        if self.is_nonblocking() {
                            return Err(e);
                        }
                        // FIXME: deal with accept timeout
                        poller.wait()?;
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };

            let remote_endpoint = accepted_socket.remote_endpoint().unwrap();

            let sock_errors = if accepted_socket.is_closed_by_peer() {
                SockErrors::with_error(Error::with_message(
                    Errno::ECONNRESET,
                    "connection was closed by peer",
                ))
            } else {
                SockErrors::no_error()
            };

            let connected_stream = {
                let BacklogSocket {
                    bound_socket: backlog_socket,
                } = accepted_socket;

                ConnectedStream::new(false, backlog_socket, remote_endpoint)
            };
            return Ok((connected_stream, remote_endpoint, sock_errors));
        }
    }

    /// Append sockets listening at LocalEndPoint to support backlog
    fn fill_backlog_sockets(&self) -> Result<()> {
        let backlog = self.backlog();
        let mut backlog_sockets = self.backlog_sockets.write();
        let current_backlog_len = backlog_sockets.len();
        debug_assert!(backlog >= current_backlog_len);
        if backlog == current_backlog_len {
            return Ok(());
        }
        for _ in current_backlog_len..backlog {
            let backlog_socket = BacklogSocket::new(&self.bound_socket)?;
            backlog_sockets.push(backlog_socket);
        }

        for backlog_socket in backlog_sockets.iter() {
            if backlog_socket.is_closed() {
                backlog_socket.listen()?;
            }
        }

        Ok(())
    }

    fn try_accept(&self) -> Result<BacklogSocket> {
        let backlog_socket = {
            let mut backlog_sockets = self.backlog_sockets.write();
            let index = backlog_sockets
                .iter()
                .position(|backlog_socket| backlog_socket.is_active());

            if index.is_none() {
                let is_closed = backlog_sockets.iter().all(|socket| socket.is_closed());
                if is_closed {
                    return_errno_with_message!(Errno::EINVAL, "the socket is not listening");
                } else {
                    return_errno_with_message!(Errno::EAGAIN, "try accept again");
                }
            }

            backlog_sockets.remove(index.unwrap())
        };

        self.fill_backlog_sockets().unwrap();
        Ok(backlog_socket)
    }

    fn backlog(&self) -> usize {
        self.backlog.load(Ordering::Acquire)
    }

    pub fn local_endpoint(&self) -> IpEndpoint {
        self.bound_socket().local_endpoint()
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        // println!("poll listening stream");
        let backlog_sockets = self.backlog_sockets.read();
        for backlog_socket in backlog_sockets.iter() {
            // let state = backlog_socket.bound_socket.raw_with(|tcp_socket: &mut RawTcpSocket| tcp_socket.state());
            // println!("state = {:?}", state);

            if backlog_socket.is_active() {
                return IoEvents::IN;
            } else {
                // regiser poller to the backlog socket
                backlog_socket.poll(mask, poller);
            }
        }
        IoEvents::empty()
    }

    pub(super) fn register_observer(&self, observer: Weak<dyn Observer<IoEvents>>, mask: IoEvents) {
        // println!("register observer for listening socket");

        let backlog_sockets = self.backlog_sockets.read();
        for backlog_socket in backlog_sockets.iter() {
            backlog_socket
                .bound_socket
                .register_observer(observer.clone(), mask);
        }
    }

    pub(super) fn unregister_observer(
        &self,
        observer: &Weak<dyn Observer<IoEvents>>,
    ) -> Result<Weak<dyn Observer<IoEvents>>> {
        let backlog_sockets = self.backlog_sockets.read();
        for backlog_socket in backlog_sockets.iter() {
            backlog_socket.bound_socket.unregister_observer(observer)?;
        }
        Ok(observer.clone())
    }

    fn bound_socket(&self) -> Arc<AnyBoundSocket> {
        self.backlog_sockets.read()[0].bound_socket.clone()
    }

    pub fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.is_nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    pub fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        // TODO: deal with shut write.
        if cmd.shut_read() {
            for socket in self.backlog_sockets.read().iter() {
                socket.close();
            }
            poll_ifaces();
        }

        Ok(())
    }

    pub fn clean_for_close(&self) {
        for socket in self.backlog_sockets.read().iter() {
            socket.clean_for_close();
        }
    }
}

struct BacklogSocket {
    bound_socket: Arc<AnyBoundSocket>,
}

impl BacklogSocket {
    fn new(bound_socket: &Arc<AnyBoundSocket>) -> Result<Self> {
        let local_endpoint = bound_socket.local_endpoint();
        let unbound_socket = AnyUnboundSocket::new_tcp();
        let bound_socket = {
            let iface = bound_socket.iface();
            let bind_config = BindConfig::new(local_endpoint, true, false)?;
            iface
                .bind_socket(unbound_socket, bind_config)
                .map_err(|(e, _)| e)?
        };

        let backlog = Self { bound_socket };
        backlog.listen()?;
        Ok(backlog)
    }

    fn listen(&self) -> Result<()> {
        let local_endpoint = self.bound_socket.local_endpoint();

        let listen_endpoint: IpListenEndpoint = if local_endpoint.addr.is_unspecified() {
            IpListenEndpoint {
                addr: None,
                port: local_endpoint.port,
            }
        } else {
            local_endpoint.into()
        };

        self.bound_socket
            .raw_with(|raw_tcp_socket: &mut RawTcpSocket| {
                raw_tcp_socket
                    .listen(listen_endpoint)
                    .map_err(|_| Error::with_message(Errno::EINVAL, "fail to listen"))
            })?;

        self.bound_socket.update_socket_state();

        Ok(())
    }

    fn is_active(&self) -> bool {
        self.bound_socket
            .raw_with(|socket: &mut RawTcpSocket| socket.is_active())
    }

    fn is_closed(&self) -> bool {
        is_local_closed(&self.bound_socket)
    }

    fn is_closed_by_peer(&self) -> bool {
        is_peer_closed(&self.bound_socket)
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        self.bound_socket
            .raw_with(|socket: &mut RawTcpSocket| socket.remote_endpoint())
    }

    fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        self.bound_socket.poll(mask, poller)
    }

    fn close(&self) {
        self.bound_socket
            .raw_with(|raw_tcp_socket: &mut RawTcpSocket| raw_tcp_socket.close())
    }

    fn clean_for_close(&self) {
        close_and_submit_linger_workitem(self.bound_socket.clone());
    }
}
