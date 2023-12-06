use crate::fs::file_table::FileDescripter;
use crate::log_syscall_entry;
use crate::prelude::*;

use super::{SyscallReturn, SYS_FTRUNCATE};

pub fn sys_ftruncate(fd: FileDescripter, length: usize) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_FTRUNCATE);
    debug!("fd = {}, length = 0x{:x}", fd, length);

    let current = current!();
    let file_table = current.file_table().lock();
    let _file = file_table.get_file(fd)?;

    // TODO: deal with ftruncate

    Ok(SyscallReturn::Return(0))
}
