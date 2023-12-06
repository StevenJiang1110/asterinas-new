use crate::log_syscall_entry;
use crate::prelude::*;

use super::{SyscallReturn, SYS_ALARM};

pub fn sys_alarm(seconds: u32) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_ALARM);
    debug!("seconds = {}", seconds);
    return_errno_with_message!(Errno::ENOSYS, "sys_alarm is not implemented");
}
