#[allow(unused_imports)]
use super::*;

/// `capset(hdrp, datap)` — set a task's capability sets.
pub(crate) fn sys_capset(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let hdrp = a.arg0;
    let datap = a.arg1;
    if hdrp == 0 || datap == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let mut hdr = [0u8; 8];
    // SAFETY: hdrp checked non-zero; copy_from_user range-validates the read.
    if unsafe { copy_from_user(&mut hdr, hdrp) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let version = u32::from_le_bytes(hdr[..4].try_into().unwrap());
    let pid = i32::from_le_bytes(hdr[4..].try_into().unwrap());
    let ndata = match cap_ndata(version) {
        Some(n) => n,
        None => {
            hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
            // SAFETY: hdrp validated by the read above; same 8-byte range.
            let _ = unsafe { copy_to_user(hdrp, &hdr) };
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };
    // Linux's `task_pid_vnr(current)` comparison is against the caller's
    // visible PID, not NARF's internal scheduler TaskId. A service launcher
    // obtains that value from getpid(2) and supplies it here.
    let task = current_task_id();
    let self_pid = task_to_pid_raw(task).unwrap_or(task);
    if pid != 0 && pid as u64 != self_pid {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    // SAFETY: datap checked non-zero above; copy_from_user_vec range-validates
    // the read before copying within the SMAP window.
    let buf = match unsafe { copy_from_user_vec(datap, ndata * 12) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let mut caps = [0u64; 3];
    for (field, slot) in caps.iter_mut().enumerate() {
        let lo = u32::from_le_bytes(buf[field * 4..field * 4 + 4].try_into().unwrap()) as u64;
        let hi = if ndata == 2 {
            u32::from_le_bytes(buf[12 + field * 4..12 + field * 4 + 4].try_into().unwrap()) as u64
        } else {
            0
        };
        *slot = lo | (hi << 32);
    }
    {
        let mut g = CAP_TABLE.lock();
        let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
        m.insert(task, caps);
    }
    ctx.set_return(SyscallReturn::ok(0));
}
