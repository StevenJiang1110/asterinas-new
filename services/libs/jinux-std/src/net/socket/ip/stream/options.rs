use crate::impl_sock_options;
use crate::prelude::*;

#[derive(Debug, Clone, Copy, CopyGetters, Setters)]
#[get_copy = "pub"]
#[set = "pub"]
pub struct TcpOptions {
    no_delay: bool,
}

impl TcpOptions {
    pub fn new() -> Self {
        Self { no_delay: false }
    }
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl_sock_options!(
    pub struct TcpNoDelay<input = bool, output = bool> {}
);
