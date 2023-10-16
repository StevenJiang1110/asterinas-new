use jinux_frame::vm::VmIo;
use jinux_rights::Full;

use crate::net::socket::options::SockErrors;
use crate::prelude::*;
use crate::vm::vmar::Vmar;

pub fn read_bool(vmar: &Vmar<Full>, addr: Vaddr, max_len: u32) -> Result<bool> {
    if (max_len as usize) < core::mem::size_of::<i32>() {
        return_errno_with_message!(Errno::EINVAL, "max_len is too short");
    }

    let val = vmar.read_val::<i32>(addr)?;

    Ok(val != 0)
}

pub fn write_bool(val: &bool, vmar: &Vmar<Full>, addr: Vaddr, max_len: u32) -> Result<usize> {
    let write_len = core::mem::size_of::<i32>();

    if (max_len as usize) < write_len {
        return_errno_with_message!(Errno::EINVAL, "max_len is too short");
    }

    let val = if *val { 1i32 } else { 0i32 };
    vmar.write_val(addr, &val)?;
    Ok(write_len)
}

pub fn write_errors(
    errors: &SockErrors,
    vmar: &Vmar<Full>,
    addr: Vaddr,
    max_len: u32,
) -> Result<usize> {
    let write_len = core::mem::size_of::<i32>();

    if (max_len as usize) < write_len {
        return_errno_with_message!(Errno::EINVAL, "max_len is too short");
    }

    let val = errors.as_i32();
    vmar.write_val(addr, &val)?;
    Ok(write_len)
}
