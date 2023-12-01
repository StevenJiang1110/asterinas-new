use super::Iface;
use super::IpEndpoint;
use crate::events::{IoEvents, Observer};
use crate::prelude::*;
use crate::process::signal::{Pollee, Poller};
use smoltcp::socket::tcp::State;

pub type RawTcpSocket = smoltcp::socket::tcp::Socket<'static>;
pub type RawUdpSocket = smoltcp::socket::udp::Socket<'static>;
pub type RawSocketHandle = smoltcp::iface::SocketHandle;

pub struct AnyUnboundSocket {
    socket_family: AnyRawSocket,
    pollee: Pollee,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(super) enum AnyRawSocket {
    Tcp(RawTcpSocket),
    Udp(RawUdpSocket),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SocketFamily {
    Tcp,
    Udp,
}

impl From<RawTcpSocket> for AnyUnboundSocket {
    fn from(tcp_socket: RawTcpSocket) -> Self {
        debug_assert!(is_tcp_closed(&tcp_socket));
        let pollee = Pollee::new(IoEvents::empty());
        Self {
            socket_family: AnyRawSocket::Tcp(tcp_socket),
            pollee,
        }
    }
}

impl AnyUnboundSocket {
    pub fn new_tcp() -> Self {
        let raw_tcp_socket = {
            let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; RECV_BUF_LEN]);
            let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; SEND_BUF_LEN]);
            RawTcpSocket::new(rx_buffer, tx_buffer)
        };
        let pollee = Pollee::new(IoEvents::empty());
        AnyUnboundSocket {
            socket_family: AnyRawSocket::Tcp(raw_tcp_socket),
            pollee,
        }
    }

    pub fn new_udp() -> Self {
        let raw_udp_socket = {
            let metadata = smoltcp::socket::udp::PacketMetadata::EMPTY;
            let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
                vec![metadata; UDP_METADATA_LEN],
                vec![0u8; UDP_RECEIVE_PAYLOAD_LEN],
            );
            let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
                vec![metadata; UDP_METADATA_LEN],
                vec![0u8; UDP_RECEIVE_PAYLOAD_LEN],
            );
            RawUdpSocket::new(rx_buffer, tx_buffer)
        };
        AnyUnboundSocket {
            socket_family: AnyRawSocket::Udp(raw_udp_socket),
            pollee: Pollee::new(IoEvents::empty()),
        }
    }

    pub(super) fn raw_socket_family(self) -> AnyRawSocket {
        self.socket_family
    }

    pub(super) fn socket_family(&self) -> SocketFamily {
        match &self.socket_family {
            AnyRawSocket::Tcp(_) => SocketFamily::Tcp,
            AnyRawSocket::Udp(_) => SocketFamily::Udp,
        }
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        self.pollee.poll(mask, poller)
    }

    pub fn register_observer(&self, observer: Weak<dyn Observer<IoEvents>>, mask: IoEvents) {
        self.pollee.register_observer(observer, mask);
    }

    pub fn unregister_observer(
        &self,
        observer: &Weak<dyn Observer<IoEvents>>,
    ) -> Result<Weak<dyn Observer<IoEvents>>> {
        self.pollee
            .unregister_observer(observer)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "cannot unregister observer"))
    }

    pub(super) fn pollee(&self) -> Pollee {
        self.pollee.clone()
    }
}

pub struct AnyBoundSocket {
    iface: Arc<dyn Iface>,
    handle: smoltcp::iface::SocketHandle,
    endpoint: IpEndpoint,
    pollee: Pollee,
    socket_family: SocketFamily,
    weak_self: Weak<Self>,
}

impl Drop for AnyBoundSocket {
    fn drop(&mut self) {
        match self.socket_family {
            SocketFamily::Tcp => {
                debug_assert!(self.raw_with(|socket: &mut RawTcpSocket| is_tcp_closed(socket)));
            }
            SocketFamily::Udp => {}
        }

        self.iface.common().remove_socket(self.handle);
        self.iface.common().release_port(self.endpoint.port);
        self.iface.common().remove_bound_socket(&self.weak_ref());
    }
}

impl AnyBoundSocket {
    pub(super) fn new(
        iface: Arc<dyn Iface>,
        handle: smoltcp::iface::SocketHandle,
        endpoint: IpEndpoint,
        pollee: Pollee,
        socket_family: SocketFamily,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            iface,
            handle,
            endpoint,
            pollee,
            socket_family,
            weak_self: weak_self.clone(),
        })
    }

    pub fn local_endpoint(&self) -> IpEndpoint {
        self.endpoint
    }

    pub fn raw_with<T: smoltcp::socket::AnySocket<'static>, R, F: FnMut(&mut T) -> R>(
        &self,
        mut f: F,
    ) -> R {
        let mut sockets = self.iface.sockets();
        let socket = sockets.get_mut::<T>(self.handle);
        f(socket)
    }

    /// Try to connect to a remote endpoint. Tcp socket only.
    pub fn do_connect(&self, remote_endpoint: IpEndpoint) -> Result<()> {
        let mut sockets = self.iface.sockets();
        let socket = sockets.get_mut::<RawTcpSocket>(self.handle);

        if socket.is_open() && let Some(current_remote_endpoint) = socket.remote_endpoint() && current_remote_endpoint == remote_endpoint{
            return Ok(());
        }

        self.pollee.del_events(IoEvents::ERR);
        let mut iface_inner = self.iface.iface_inner();
        let cx = iface_inner.context();
        socket
            .connect(cx, remote_endpoint, self.endpoint)
            .map_err(|_| {
                self.pollee.add_events(IoEvents::ERR);
                Error::with_message(Errno::ECONNREFUSED, "send connection request failed")
            })?;
        Ok(())
    }

    pub fn update_socket_state(&self) {
        let handle = &self.handle;
        let pollee = &self.pollee;
        let sockets = self.iface().sockets();
        match self.socket_family {
            SocketFamily::Tcp => {
                let socket = sockets.get::<RawTcpSocket>(*handle);
                update_tcp_socket_state(socket, pollee);
            }
            SocketFamily::Udp => {
                let udp_socket = sockets.get::<RawUdpSocket>(*handle);
                update_udp_socket_state(udp_socket, pollee);
            }
        }
    }

    pub fn iface(&self) -> &Arc<dyn Iface> {
        &self.iface
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        self.pollee.poll(mask, poller)
    }

    pub fn register_observer(&self, observer: Weak<dyn Observer<IoEvents>>, mask: IoEvents) {
        self.pollee.register_observer(observer, mask);
    }

    pub fn unregister_observer(
        &self,
        observer: &Weak<dyn Observer<IoEvents>>,
    ) -> Result<Weak<dyn Observer<IoEvents>>> {
        self.pollee
            .unregister_observer(observer)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "cannot unregister observer"))
    }

    pub fn weak_ref(&self) -> Weak<Self> {
        self.weak_self.clone()
    }

    /// Turns an `AnyBoundSocket` to AnyUnbound. This method will release port from iface.
    ///
    /// # Panic
    ///
    /// The strong count of self should be one.
    pub fn unbound(self: Arc<Self>) -> AnyUnboundSocket {
        debug_assert!(Arc::strong_count(&self) == 1);
        let socket = self.iface.common().remove_socket(self.handle);
        self.iface().common().release_port(self.endpoint.port);
        self.iface().common().remove_bound_socket(&self.weak_ref());
        core::mem::forget(self);
        match socket {
            smoltcp::socket::Socket::Tcp(tcp_socket) => AnyUnboundSocket::from(tcp_socket),
            _ => todo!(),
        }
    }
}

fn update_tcp_socket_state(socket: &RawTcpSocket, pollee: &Pollee) {
    if socket.can_recv() {
        pollee.add_events(IoEvents::IN);
    } else {
        pollee.del_events(IoEvents::IN);
    }

    if socket.can_send() {
        pollee.add_events(IoEvents::OUT);
    } else {
        pollee.del_events(IoEvents::OUT);
    }

    if is_tcp_peer_closed(socket) {
        pollee.add_events(IoEvents::HUP);
    } else {
        pollee.del_events(IoEvents::HUP);
    }
}

fn update_udp_socket_state(socket: &RawUdpSocket, pollee: &Pollee) {
    if socket.can_recv() {
        pollee.add_events(IoEvents::IN);
    } else {
        pollee.del_events(IoEvents::IN);
    }

    if socket.can_send() {
        pollee.add_events(IoEvents::OUT);
    } else {
        pollee.del_events(IoEvents::OUT);
    }
}

// For TCP
pub const RECV_BUF_LEN: usize = 4096;
pub const SEND_BUF_LEN: usize = 4096;

// For UDP
const UDP_METADATA_LEN: usize = 256;
const UDP_SEND_PAYLOAD_LEN: usize = 65536;
const UDP_RECEIVE_PAYLOAD_LEN: usize = 65536;

/// Returns whether the peer end of tcp socket is closed. That is to say, the peer end sends a
/// request to close the connection and local end is not closed yet.
pub fn is_tcp_peer_closed(socket: &RawTcpSocket) -> bool {
    socket.state() == State::CloseWait || socket.state() == State::LastAck
}

/// Returns whether the local end of tcp socket is closed.
pub fn is_tcp_closed(socket: &RawTcpSocket) -> bool {
    // FIXME: should we include TimeWait state here?
    socket.state() == State::Closed
}
