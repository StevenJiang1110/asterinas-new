use core::sync::atomic::{AtomicBool, Ordering};

use smoltcp::wire::{IpAddress, Ipv4Address};

use crate::events::IoEvents;
use crate::net::iface::{AnyBoundSocket, AnyUnboundSocket, Iface, IpEndpoint};
use crate::net::socket::ip::always_some::AlwaysSome;
use crate::net::socket::ip::common::{bind_socket, get_ephemeral_endpoint};
use crate::net::socket::options::SockErrors;
use crate::net::socket::SockShutdownCmd;
use crate::net::{get_localhost_iface, poll_ifaces};
use crate::prelude::*;
use crate::process::signal::Poller;

use super::util::{close_and_submit_linger_workitem, close_local_and_poll, is_local_closed};

pub struct InitStream {
    inner: RwLock<Inner>,
    is_nonblocking: AtomicBool,
}

enum Inner {
    Unbound(AlwaysSome<AnyUnboundSocket>),
    Bound(AlwaysSome<Arc<AnyBoundSocket>>),
    Connecting {
        bound_socket: AlwaysSome<Arc<AnyBoundSocket>>,
        remote_endpoint: IpEndpoint,
    },
}

impl Inner {
    fn is_bound(&self) -> bool {
        match self {
            Self::Unbound(_) => false,
            Self::Bound(..) | Self::Connecting { .. } => true,
        }
    }

    fn bind(&mut self, endpoint: IpEndpoint) -> Result<()> {
        let unbound_socket = if let Inner::Unbound(unbound_socket) = self {
            unbound_socket
        } else {
            return_errno_with_message!(Errno::EINVAL, "the socket is already bound to an address");
        };
        let bound_socket = unbound_socket
            .try_take_with(|raw_socket| bind_socket(raw_socket, endpoint, false, true))?;
        bound_socket.update_socket_state();
        *self = Inner::Bound(AlwaysSome::new(bound_socket));
        Ok(())
    }

    fn bind_to_ephemeral_endpoint(&mut self, remote_endpoint: &IpEndpoint) -> Result<()> {
        let endpoint = get_ephemeral_endpoint(remote_endpoint);
        self.bind(endpoint)
    }

    fn do_connect(&mut self, new_remote_endpoint: IpEndpoint) -> Result<()> {
        match self {
            Inner::Unbound(_) => return_errno_with_message!(Errno::EINVAL, "the socket is invalid"),
            Inner::Connecting {
                bound_socket,
                remote_endpoint,
            } => {
                *remote_endpoint = new_remote_endpoint;
                bound_socket.do_connect(new_remote_endpoint)?;
            }
            Inner::Bound(bound_socket) => {
                bound_socket.do_connect(new_remote_endpoint)?;
                *self = Inner::Connecting {
                    bound_socket: AlwaysSome::new(bound_socket.take()),
                    remote_endpoint: new_remote_endpoint,
                };
            }
        }
        Ok(())
    }

    fn bound_socket(&self) -> Option<&Arc<AnyBoundSocket>> {
        match self {
            Inner::Bound(bound_socket) | Inner::Connecting { bound_socket, .. } => {
                Some(bound_socket)
            }
            _ => None,
        }
    }

    fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        match self {
            Inner::Bound(bound_socket) => bound_socket.poll(mask, poller),
            Inner::Connecting { bound_socket, .. } => bound_socket.poll(mask, poller),
            Inner::Unbound(unbound_socket) => unbound_socket.poll(mask, poller),
        }
    }

    fn iface(&self) -> Option<Arc<dyn Iface>> {
        match self {
            Inner::Bound(bound_socket) => Some(bound_socket.iface().clone()),
            Inner::Connecting { bound_socket, .. } => Some(bound_socket.iface().clone()),
            _ => None,
        }
    }

    fn local_endpoint(&self) -> Option<IpEndpoint> {
        self.bound_socket().map(|socket| socket.local_endpoint())
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        if let Inner::Connecting {
            remote_endpoint, ..
        } = self
        {
            Some(*remote_endpoint)
        } else {
            None
        }
    }

    fn shutdown(&mut self, cmd: SockShutdownCmd) -> Result<()> {
        // TODO: how to shut read?
        if !cmd.shut_write() {
            return Ok(());
        }

        match self {
            Self::Unbound(..) => Ok(()),
            Self::Bound(bound_socket) => {
                close_local_and_poll(bound_socket);
                Ok(())
            }
            Self::Connecting { bound_socket, .. } => {
                close_local_and_poll(bound_socket);
                Ok(())
            }
        }
    }

    fn unbound(&mut self) {
        match self {
            Inner::Unbound(_) => (),
            Inner::Bound(bound_socket) => unreachable!("Only connecting socket can be unbound."),
            Inner::Connecting { bound_socket, .. } => {
                close_local_and_poll(bound_socket);
                let bound_socket = bound_socket.take();
                let unbound_socket = bound_socket.unbound();
                *self = Inner::Unbound(AlwaysSome::new(unbound_socket));
            }
        }
    }
}

impl InitStream {
    pub fn new(nonblocking: bool) -> Self {
        let socket = AnyUnboundSocket::new_tcp();
        let inner = Inner::Unbound(AlwaysSome::new(socket));
        Self {
            is_nonblocking: AtomicBool::new(nonblocking),
            inner: RwLock::new(inner),
        }
    }

    pub fn is_bound(&self) -> bool {
        self.inner.read().is_bound()
    }

    pub fn bind(&self, endpoint: IpEndpoint) -> Result<()> {
        self.inner.write().bind(endpoint)
    }

    pub fn bind_to_ephemeral_endpoint(&self) -> Result<()> {
        let endpoint = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
            port: 0,
        };
        self.inner.write().bind(endpoint)
    }

    pub fn connect(
        &self,
        remote_endpoint: &IpEndpoint,
        sock_errors: &mut SockErrors,
    ) -> Result<()> {
        let remote_endpoint = if remote_endpoint.addr.is_unspecified() {
            // FIXME: this is a temporary solution, when trying to connect to `0.0.0.0`,
            // sending connecting request to localhost.
            let ip_addr = get_localhost_iface().ipv4_addr().unwrap();
            IpEndpoint::new(IpAddress::Ipv4(ip_addr), remote_endpoint.port)
        } else {
            *remote_endpoint
        };

        if !self.is_bound() {
            self.inner
                .write()
                .bind_to_ephemeral_endpoint(&remote_endpoint)?;
        }

        let mut inner = self.inner.write();
        inner.do_connect(remote_endpoint).map_err(|e| {
            if self.is_nonblocking() {
                sock_errors.set_error(e);
                Error::with_message(
                    Errno::EINPROGRESS,
                    "the socket is non blocking and connection failed",
                )
            } else {
                e
            }
        })?;

        drop(inner);

        if self.is_nonblocking() {
            let events = self.inner.read().poll(IoEvents::OUT | IoEvents::IN, None);
            if events.contains(IoEvents::IN) || events.contains(IoEvents::OUT) {
                return Ok(());
            }
            // FIXME: this function should be done in a work item, instead of blocking current thread.
            poll_ifaces();
            return_errno_with_message!(Errno::EINPROGRESS, "try connect again");
        }

        // Wait until building connection
        let poller = Poller::new();
        loop {
            poll_ifaces();

            let events = self
                .inner
                .read()
                .poll(IoEvents::OUT | IoEvents::IN, Some(&poller));

            if events.contains(IoEvents::IN) || events.contains(IoEvents::OUT) {
                println!("connect succeeds.");
                return Ok(());
            } else {
                let is_closed = {
                    let inner = self.inner.read();
                    let bound_socket = inner.bound_socket().unwrap();
                    is_local_closed(bound_socket)
                };

                if is_closed {
                    self.inner.write().unbound();
                    return_errno_with_message!(Errno::ECONNREFUSED, "connection is refused");
                }

                // FIXME: deal with connecting timeout
                poller.wait()?;
            }
        }
    }

    pub fn local_endpoint(&self) -> Result<IpEndpoint> {
        self.inner
            .read()
            .local_endpoint()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "does not has local endpoint"))
    }

    pub fn remote_endpoint(&self) -> Result<IpEndpoint> {
        self.inner
            .read()
            .remote_endpoint()
            .ok_or_else(|| Error::with_message(Errno::ENOTCONN, "does not has remote endpoint"))
    }

    pub(super) fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        self.inner.read().poll(mask, poller)
    }

    pub fn bound_socket(&self) -> Option<Arc<AnyBoundSocket>> {
        self.inner.read().bound_socket().map(Clone::clone)
    }

    pub fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.is_nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    pub fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        self.inner.write().shutdown(cmd)
    }

    pub fn clean_for_close(&self) {
        match &*self.inner.read() {
            Inner::Unbound(_) => {}
            Inner::Bound(bound_socket) | Inner::Connecting { bound_socket, .. } => {
                close_and_submit_linger_workitem((*bound_socket).clone())
            }
        }
    }
}
