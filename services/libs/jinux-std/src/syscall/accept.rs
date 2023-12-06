use super::{SyscallReturn, SYS_ACCEPT, SYS_ACCEPT4};
use crate::fs::file_table::FileDescripter;
use crate::fs::utils::{CreationFlags, StatusFlags};
use crate::prelude::*;
use crate::util::net::write_socket_addr_to_user;
use crate::{get_socket_without_holding_filetable_lock, log_syscall_entry};

pub fn sys_accept(
    sockfd: FileDescripter,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_ACCEPT);
    debug!("sockfd = {sockfd}, sockaddr_ptr = 0x{sockaddr_ptr:x}, addrlen_ptr = 0x{addrlen_ptr:x}");

    let fd = do_accept(sockfd, sockaddr_ptr, addrlen_ptr, Flags::empty())?;
    Ok(SyscallReturn::Return(fd as _))
}

pub fn sys_accept4(
    sockfd: FileDescripter,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
    flags: u32,
) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_ACCEPT4);
    trace!("raw flags = 0x{:x}", flags);
    let flags = Flags::from_bits_truncate(flags);
    debug!(
        "sockfd = {}, sockaddr_ptr = 0x{:x}, addrlen_ptr = 0x{:x}, flags = {:?}",
        sockfd, sockaddr_ptr, addrlen_ptr, flags
    );

    let fd = do_accept(sockfd, sockaddr_ptr, addrlen_ptr, flags)?;
    Ok(SyscallReturn::Return(fd as _))
}

fn do_accept(
    sockfd: FileDescripter,
    sockaddr_ptr: Vaddr,
    addrlen_ptr: Vaddr,
    flags: Flags,
) -> Result<FileDescripter> {
    let current = current!();
    get_socket_without_holding_filetable_lock!(socket, current, sockfd);
    let (connected_socket, socket_addr) = socket.accept()?;

    if flags.contains(Flags::SOCK_NONBLOCK) {
        connected_socket.set_status_flags(StatusFlags::O_NONBLOCK)?;
    }

    if flags.contains(Flags::SOCK_CLOEXEC) {
        // TODO: deal with SOCK_CLOEXEC
        warn!("deal with sock cloexec");
    }

    if sockaddr_ptr != 0 {
        write_socket_addr_to_user(&socket_addr, sockaddr_ptr, addrlen_ptr)?;
    }

    let fd = {
        let mut file_table = current.file_table().lock();
        file_table.insert(connected_socket)
    };

    Ok(fd)
}

bitflags! {
    struct Flags: u32 {
        const SOCK_NONBLOCK = NONBLOCK;
        const SOCK_CLOEXEC = CLOEXEC;
    }
}

const NONBLOCK: u32 = StatusFlags::O_NONBLOCK.bits();
const CLOEXEC: u32 = CreationFlags::O_CLOEXEC.bits();
