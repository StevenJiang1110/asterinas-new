use crate::net::iface::{is_tcp_closed, is_tcp_peer_closed, AnyBoundSocket, RawTcpSocket};
use crate::prelude::*;
use crate::thread::work_queue::work_item::WorkItem;
use crate::thread::work_queue::{submit_work_item, WorkPriority};
use core::time::Duration;
use jinux_frame::sync::WaitQueue;

/// Returns whether the connection is closed by peer end. Note that if local
/// end is also closed, this method will always return false.
pub(super) fn is_peer_closed(bound_socket: &AnyBoundSocket) -> bool {
    bound_socket.raw_with(|socket: &mut RawTcpSocket| is_tcp_peer_closed(socket))
}

/// Returns whether the local end connection is closed. Tcp socket only.
pub(super) fn is_local_closed(bound_socket: &AnyBoundSocket) -> bool {
    bound_socket.raw_with(|socket: &mut RawTcpSocket| is_tcp_closed(socket))
}

/// Closes the local end.
pub(super) fn close_local(bound_socket: &AnyBoundSocket) {
    bound_socket.raw_with(|socket: &mut RawTcpSocket| socket.close());
}

/// Closes the local end and poll iface.
pub(super) fn close_local_and_poll(bound_socket: &AnyBoundSocket) {
    close_local(bound_socket);
    bound_socket.iface().poll();
}

/// Close the socket, and submit a `WorkItem` which waits until the socket status becomes
/// `Closed``, i.e., the socket received FIN-ACK from peer. After the socket becomed
/// `Closed``, all socket-related sources will be released, such as the port. The wait logic
/// is done in a `WorkItem`, so it will not block the execution of current thread. The
/// `WorkItem` can only live for a given timeout (currently, the timeout is a constant),
/// if the socket is not `Closed` until the timeout is reached, the socket is force to become
/// `Closed` by calling `abort``.
///
/// FIXME:
/// 1. If linger is on, the wait should be done in current thread.
/// 2. The wait timeout should be controlled by the linger option.
/// 3. Follow the default timeout as linux.
pub(super) fn close_and_submit_linger_workitem(bound_socket: Arc<AnyBoundSocket>) {
    bound_socket.raw_with(|socket: &mut RawTcpSocket| socket.close());
    bound_socket.iface().poll();

    // Fast path.
    if is_local_closed(&bound_socket) {
        return;
    }

    // Slow path
    let work_item = WorkItem::new(Box::new(move || {
        WaitQueue::new().wait_until_or_timeout(|| None::<()>, &CLOSE_TIMEOUT);

        bound_socket.iface().poll();
        if !is_local_closed(&bound_socket) {
            // If socket is not closed until timeout, we force to abort the connection.
            bound_socket.raw_with(|socket: &mut RawTcpSocket| socket.abort());
            bound_socket.iface().poll();
        }
    }));

    submit_work_item(Arc::new(work_item), WorkPriority::Normal);
}

const CLOSE_TIMEOUT: Duration = Duration::new(1, 0);
