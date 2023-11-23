use crate::fs::file_table::FileDescripter;
use crate::log_syscall_entry;
use crate::prelude::*;

use super::{SyscallReturn, SYS_CHOWN};

pub fn sys_chown(fd: FileDescripter, uid: u32, gid: u32) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_CHOWN);

    debug!("fd = {}, uid = {}, gid = {}", fd, uid, gid);

    // Only check file existence here.
    // let current = current!();
    // let file_table = current.file_table().lock();
    // file_table.get_file(fd)?;

    Ok(SyscallReturn::Return(0))
}
