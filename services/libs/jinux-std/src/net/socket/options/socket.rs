use crate::impl_sock_options;
use crate::net::iface::{RECV_BUF_LEN, SEND_BUF_LEN};
use crate::prelude::*;

#[derive(Debug, Clone, CopyGetters, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub struct SocketOptions {
    sock_errors: SockErrors,
    reuse_addr: bool,
    reuse_port: bool,
    send_buf: u32,
    recv_buf: u32,
}

impl SocketOptions {
    pub fn new_tcp() -> Self {
        Self {
            sock_errors: SockErrors::no_error(),
            reuse_addr: false,
            reuse_port: false,
            send_buf: SEND_BUF_LEN as u32,
            recv_buf: RECV_BUF_LEN as u32,
        }
    }
}

impl_sock_options!(
    pub struct SocketReuseAddr<input = bool, output = bool> {}
    pub struct SocketReusePort<input = bool, output = bool> {}
    pub struct SocketSendBuf<input = u32, output = u32> {}
    pub struct SocketError<input = (), output = SockErrors> {}
);

#[derive(Debug, Clone, Copy)]
pub struct SockErrors(Option<Error>);

impl SockErrors {
    pub const fn no_error() -> Self {
        Self(None)
    }

    pub const fn with_error(error: Error) -> Self {
        Self(Some(error))
    }

    pub const fn error(&self) -> Option<&Error> {
        self.0.as_ref()
    }

    pub const fn as_i32(&self) -> i32 {
        match &self.0 {
            None => 0,
            Some(err) => -(err.error() as i32),
        }
    }
}
