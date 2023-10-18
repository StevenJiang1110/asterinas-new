use core::sync::atomic::{AtomicBool, Ordering};

use smoltcp::wire::IpListenEndpoint;

use crate::events::IoEvents;
use crate::net::iface::{AnyUnboundSocket, BindConfig, IpEndpoint};

use crate::net::iface::{AnyBoundSocket, RawTcpSocket};
use crate::process::signal::Poller;
use crate::{net::poll_ifaces, prelude::*};

use super::connected::ConnectedStream;

pub struct ListenStream {
    is_nonblocking: AtomicBool,
    backlog: usize,
    /// A bound socket held to ensure the TCP port cannot be released
    bound_socket: Arc<AnyBoundSocket>,
    /// Backlog sockets listening at the local endpoint
    backlog_sockets: RwLock<Vec<BacklogSocket>>,
}

impl ListenStream {
    pub fn new(
        nonblocking: bool,
        bound_socket: Arc<AnyBoundSocket>,
        backlog: usize,
    ) -> Result<Self> {
        let listen_stream = Self {
            is_nonblocking: AtomicBool::new(nonblocking),
            backlog,
            bound_socket,
            backlog_sockets: RwLock::new(Vec::new()),
        };
        listen_stream.fill_backlog_sockets()?;
        Ok(listen_stream)
    }

    pub fn accept(&self) -> Result<(ConnectedStream, IpEndpoint)> {
        // wait to accept
        let poller = Poller::new();
        loop {
            poll_ifaces();
            let accepted_socket = if let Some(accepted_socket) = self.try_accept() {
                accepted_socket
            } else {
                let events = self.poll(IoEvents::IN | IoEvents::OUT, Some(&poller));
                if !events.contains(IoEvents::IN) && !events.contains(IoEvents::OUT) {
                    if self.is_nonblocking() {
                        return_errno_with_message!(Errno::EAGAIN, "try accept again");
                    }
                    // FIXME: deal with accept timeout
                    poller.wait()?;
                }
                continue;
            };
            let remote_endpoint = accepted_socket.remote_endpoint().unwrap();
            let connected_stream = {
                let BacklogSocket {
                    bound_socket: backlog_socket,
                } = accepted_socket;
                ConnectedStream::new(false, backlog_socket, remote_endpoint)
            };
            return Ok((connected_stream, remote_endpoint));
        }
    }

    /// Append sockets listening at LocalEndPoint to support backlog
    fn fill_backlog_sockets(&self) -> Result<()> {
        let backlog = self.backlog;
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
        Ok(())
    }

    fn try_accept(&self) -> Option<BacklogSocket> {
        let backlog_socket = {
            let mut backlog_sockets = self.backlog_sockets.write();
            let index = backlog_sockets
                .iter()
                .position(|backlog_socket| backlog_socket.is_active())?;
            backlog_sockets.remove(index)
        };
        self.fill_backlog_sockets().unwrap();
        Some(backlog_socket)
    }

    pub fn local_endpoint(&self) -> IpEndpoint {
        self.bound_socket().local_endpoint()
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        let backlog_sockets = self.backlog_sockets.read();
        for backlog_socket in backlog_sockets.iter() {
            if backlog_socket.is_active() {
                return IoEvents::IN;
            } else {
                // regiser poller to the backlog socket
                backlog_socket.poll(mask, poller);
            }
        }
        IoEvents::empty()
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
}

struct BacklogSocket {
    bound_socket: Arc<AnyBoundSocket>,
}

impl BacklogSocket {
    fn new(bound_socket: &Arc<AnyBoundSocket>) -> Result<Self> {
        let local_endpoint = bound_socket.local_endpoint().ok_or(Error::with_message(
            Errno::EINVAL,
            "the socket is not bound",
        ))?;
        let unbound_socket = AnyUnboundSocket::new_tcp();
        let bound_socket = {
            let iface = bound_socket.iface();
            let bind_config = BindConfig::new(local_endpoint, true)?;
            iface
                .bind_socket(unbound_socket, bind_config)
                .map_err(|(e, _)| e)?
        };

        let listen_endpoint: IpListenEndpoint = if local_endpoint.addr.is_unspecified() {
            IpListenEndpoint {
                addr: None,
                port: local_endpoint.port,
            }
        } else {
            local_endpoint.into()
        };

        bound_socket.raw_with(|raw_tcp_socket: &mut RawTcpSocket| {
            raw_tcp_socket
                .listen(listen_endpoint)
                .map_err(|_| Error::with_message(Errno::EINVAL, "fail to listen"))
        })?;
        bound_socket.update_socket_state();
        Ok(Self { bound_socket })
    }

    fn is_active(&self) -> bool {
        self.bound_socket
            .raw_with(|socket: &mut RawTcpSocket| socket.is_active())
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        self.bound_socket
            .raw_with(|socket: &mut RawTcpSocket| socket.remote_endpoint())
    }

    fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        self.bound_socket.poll(mask, poller)
    }
}
