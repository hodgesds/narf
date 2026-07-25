#[allow(unused_imports)]
use super::*;

/// `open_by_handle_at(mount_fd, handle, flags)`.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_open_by_handle_at(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    const ESTALE: i64 = 116;
    const EFAULT: i64 = 14;
    let a = *ctx.args();
    // mount_fd (arg0) is ignored (single namespace; AT_FDCWD also accepted).
    let mut hdr = [0u8; 8];
    // SAFETY: copy_from_user validates the 8-byte header read.
    if unsafe { copy_from_user(&mut hdr, a.arg1) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let hbytes = u32::from_ne_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let htype = i32::from_ne_bytes(hdr[4..8].try_into().unwrap());
    if htype != NARF_HANDLE_TYPE {
        ctx.set_return(SyscallReturn::ok((-ESTALE) as u64));
        return;
    }
    if hbytes == 0 || hbytes > 4096 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // SAFETY: copy_from_user_vec validates the f_handle range.
    let path_bytes = match unsafe { copy_from_user_vec(a.arg1 + 8, hbytes) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    };
    let path = match alloc::string::String::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-ESTALE) as u64));
            return;
        }
    };
    let fd = fanotify_open_object(current_task_id(), &path);
    if fd < 0 {
        ctx.set_return(SyscallReturn::ok((-ESTALE) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(fd as u64));
}
