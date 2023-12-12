use super::SyscallReturn;
use super::SYS_CLOSE;
use crate::log_syscall_entry;
use crate::{fs::file_table::FileDescripter, prelude::*};

pub fn sys_close(fd: FileDescripter) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_CLOSE);
    debug!("fd = {}", fd);
    let current = current!();
    // println!("lock file table");
    let mut file_table = current.file_table().lock();
    let _ = file_table.get_file(fd)?;
    let file = file_table.close_file(fd).unwrap();
    // println!("clean for close");
    drop(file_table);
    file.clean_for_close()?;
    drop(file);
    // println!("clean for close returns");
    Ok(SyscallReturn::Return(0))
}
