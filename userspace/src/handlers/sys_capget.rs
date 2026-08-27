#[allow(unused_imports)]
use super::*;

/// `kernel/capability.c::SYSCALL_DEFINE2(capget)` — read a task's
/// capability sets.
///
/// ```text
/// ret = cap_validate_magic(header, &tocopy);
/// if ((dataptr == NULL) || (ret != 0))
///         return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;
/// if (get_user(pid, &header->pid))        return -EFAULT;
/// if (pid < 0)                            return -EINVAL;
/// ret = cap_get_target_pid(pid, &pE, &pI, &pP);   /* -ESRCH if no task */
/// ...
/// if (copy_to_user(dataptr, kdata, tocopy * sizeof(kdata[0])))
///         return -EFAULT;
/// ```
///
/// `cap_validate_magic` writes the kernel's preferred version back into the
/// header before returning -EINVAL — that write-back IS the version
/// negotiation protocol libcap uses, so it has to happen even on the error
/// path or a caller compiled against a newer header can never discover what
/// this kernel speaks.
pub(crate) fn sys_capget(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    let a = *ctx.args();
    let hdrp = a.arg0;
    let datap = a.arg1;
    if hdrp == 0 {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let mut hdr = [0u8; 8];
    // SAFETY: hdrp checked non-zero; copy_from_user range-validates the read.
    if unsafe { copy_from_user(&mut hdr, hdrp) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let version = u32::from_le_bytes(hdr[..4].try_into().unwrap());
    // The header pid is `int`: `if (pid < 0) return -EINVAL;`.
    let pid = i32::from_le_bytes(hdr[4..].try_into().unwrap());
    let ndata = match cap_ndata(version) {
        Some(n) => n,
        None => {
            // Linux rewrites the header to the preferred version and
            // returns EINVAL so the caller can retry.
            hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
            // SAFETY: hdrp validated by the read above; same 8-byte range.
            let _ = unsafe { copy_to_user(hdrp, &hdr) };
            // `return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;`
            // With no data pointer this is a VERSION PROBE and it succeeds:
            // the caller learns the supported version from the rewritten
            // header and retries at it. libcap's `cap_get_proc` does exactly
            // that before allocating, so reporting -EINVAL here made it give
            // up instead of retrying.
            let probe = datap == 0;
            ctx.set_return(SyscallReturn::ok(if probe { 0 } else { (-EINVAL) as u64 }));
            return;
        }
    };
    // datap == NULL is a version probe — succeed without writing data.
    if datap == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if pid < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `cap_get_target_pid()` resolves the header pid with
    // `find_task_by_vpid()` — in the CALLER's pid namespace — and reports
    // -ESRCH when no such task exists. Using the inner pid as the raw
    // CAP_TABLE key both read an unrelated task's caps and reported an
    // all-zero set for a pid that does not exist at all, which a caller
    // cannot tell apart from "that process holds no capabilities".
    // (Same defect capset fixed as audit finding #19.)
    let task = current_task_id();
    let self_pid = task_to_pid_raw(task).unwrap_or(task);
    let target = if pid == 0 {
        task
    } else {
        match accept_pid_from(task, pid as u64) {
            Some(outer) if outer == self_pid => task,
            Some(outer) => proc_pid_to_tid(outer),
            None => {
                ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
                return;
            }
        }
    };
    let caps = read_caps(target);
    // `struct __user_cap_data_struct { __u32 effective, permitted,
    // inheritable; }` — capget/capset exchange exactly these three of the
    // five sets. The bounding set is read through prctl(PR_CAPBSET_READ)
    // and the ambient set through prctl(PR_CAP_AMBIENT), not here.
    let fields = [caps.effective, caps.permitted, caps.inheritable];
    let mut out = alloc::vec![0u8; ndata * 12];
    for (field, &val) in fields.iter().enumerate() {
        // data[0] carries the low 32 bits; data[1] (v2/v3) the high.
        out[field * 4..field * 4 + 4].copy_from_slice(&(val as u32).to_le_bytes());
        if ndata == 2 {
            let hi = (val >> 32) as u32;
            out[12 + field * 4..12 + field * 4 + 4].copy_from_slice(&hi.to_le_bytes());
        }
    }
    // SAFETY: datap checked non-zero; copy_to_user range-validates the write.
    if unsafe { copy_to_user(datap, &out) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
