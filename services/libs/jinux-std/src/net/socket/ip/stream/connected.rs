use core::sync::atomic::{AtomicBool, Ordering};

use smoltcp::socket::tcp::RecvError;

use super::util::{
    close_and_submit_linger_workitem, close_local_and_poll, is_local_closed, is_peer_closed,
};
use crate::events::{IoEvents, Observer};
use crate::net::iface::{AnyBoundSocket, IpEndpoint, RawTcpSocket};
use crate::net::poll_ifaces;
use crate::net::socket::ip::stream::util::close_local;
use crate::net::socket::util::send_recv_flags::SendRecvFlags;
use crate::net::socket::util::shutdown_cmd::SockShutdownCmd;
use crate::prelude::*;
use crate::process::signal::Poller;

pub struct ConnectedStream {
    nonblocking: AtomicBool,
    bound_socket: Arc<AnyBoundSocket>,
    remote_endpoint: IpEndpoint,
}

impl ConnectedStream {
    pub fn new(
        is_nonblocking: bool,
        bound_socket: Arc<AnyBoundSocket>,
        remote_endpoint: IpEndpoint,
    ) -> Self {
        Self {
            nonblocking: AtomicBool::new(is_nonblocking),
            bound_socket,
            remote_endpoint,
        }
    }

    pub fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        // TODO: How to deal with shut read?

        if cmd.shut_write() {
            close_local_and_poll(&self.bound_socket);
        }

        Ok(())
    }

    pub fn recvfrom(&self, buf: &mut [u8], flags: SendRecvFlags) -> Result<(usize, IpEndpoint)> {
        debug_assert!(flags.is_all_supported());

        let poller = Poller::new();
        loop {
            let recv_len = self.try_recvfrom(buf, flags)?;

            // Fast path
            if recv_len > 0 {
                let remote_endpoint = self.remote_endpoint()?;
                return Ok((recv_len, remote_endpoint));
            }

            // Slow path
            let events = self.bound_socket.poll(IoEvents::IN, Some(&poller));

            // The socket is closed or the peer is closed.
            if events.contains(IoEvents::HUP) || is_local_closed(&self.bound_socket) {
                let remote_endpoint = self.remote_endpoint()?;
                return Ok((recv_len, remote_endpoint));
            }

            if events.contains(IoEvents::ERR) {
                return_errno_with_message!(Errno::ENOTCONN, "recv packet fails");
            }

            if !events.contains(IoEvents::IN) {
                if self.is_nonblocking() {
                    return_errno_with_message!(Errno::EAGAIN, "try to recv again");
                }
                // FIXME: deal with receive timeout
                poller.wait()?;
            }
        }
    }

    fn try_recvfrom(&self, buf: &mut [u8], flags: SendRecvFlags) -> Result<usize> {
        poll_ifaces();
        let res =
            self.bound_socket
                .raw_with(|socket: &mut RawTcpSocket| match socket.recv_slice(buf) {
                    Ok(size) => Ok(size),
                    Err(RecvError::Finished) => Ok(0),
                    Err(RecvError::InvalidState) => {
                        return_errno_with_message!(Errno::ENOTCONN, "fail to rece packet")
                    }
                });
        self.bound_socket.update_socket_state();
        res
    }

    pub fn sendto(&self, buf: &[u8], flags: SendRecvFlags) -> Result<usize> {
        debug_assert!(flags.is_all_supported());

        let poller = Poller::new();
        loop {
            let sent_len = self.try_sendto(buf, flags)?;

            // Close the socket if the socket is in closed by peer.
            // FIXME: This logic is used to pass gvisor network test. But
            // I'm sure whether it's really needed.
            if is_peer_closed(&self.bound_socket) {
                close_local(&self.bound_socket);
            }

            if sent_len > 0 {
                return Ok(sent_len);
            }

            let events = self.bound_socket.poll(IoEvents::OUT, Some(&poller));
            if events.contains(IoEvents::HUP) || events.contains(IoEvents::ERR) {
                return_errno_with_message!(Errno::EPIPE, "fail to send packets");
            }
            if !events.contains(IoEvents::OUT) {
                if self.is_nonblocking() {
                    return_errno_with_message!(Errno::EAGAIN, "try to send again");
                }
                // FIXME: deal with send timeout
                poller.wait()?;
            }
        }
    }

    fn try_sendto(&self, buf: &[u8], flags: SendRecvFlags) -> Result<usize> {
        let res = self
            .bound_socket
            .raw_with(|socket: &mut RawTcpSocket| socket.send_slice(buf));
        // .map_err(|_| Error::with_message(Errno::EPIPE, "cannot send packet"));
        match res {
            // We have to explicitly invoke `update_socket_state` when the send buffer becomes
            // full. Note that smoltcp does not think it is an interface event, so calling
            // `poll_ifaces` alone is not enough.
            Ok(0) => self.bound_socket.update_socket_state(),
            Ok(_) => poll_ifaces(),
            Err(e) => {
                let state = self
                    .bound_socket
                    .raw_with(|socket: &mut RawTcpSocket| socket.state());
                println!("state = {:?}", state);
                println!("e = {:?}", e);
                todo!()
            }
        };
        Ok(res.unwrap())
    }

    pub fn local_endpoint(&self) -> IpEndpoint {
        self.bound_socket.local_endpoint()
    }

    pub fn remote_endpoint(&self) -> Result<IpEndpoint> {
        Ok(self.remote_endpoint)
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&Poller>) -> IoEvents {
        self.bound_socket.poll(mask, poller)
    }

    pub fn register_observer(&self, observer: Weak<dyn Observer<IoEvents>>, mask: IoEvents) {
        self.bound_socket.register_observer(observer, mask);
    }

    pub fn unregister_observer(
        &self,
        observer: &Weak<dyn Observer<IoEvents>>,
    ) -> Result<Weak<dyn Observer<IoEvents>>> {
        self.bound_socket.unregister_observer(observer)
    }

    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    pub fn clean_for_close(&self) {
        close_and_submit_linger_workitem(self.bound_socket.clone())
    }
}
