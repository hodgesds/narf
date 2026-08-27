#[allow(unused_imports)]
use super::*;

/// `kernel/capability.c::SYSCALL_DEFINE2(capset)` — set a task's
/// capability sets.
///
/// ```text
/// ret = cap_validate_magic(header, &tocopy);
/// if (ret != 0)                                   return ret;
/// if (get_user(pid, &header->pid))                return -EFAULT;
/// /* may only affect current now */
/// if (pid != 0 && pid != task_pid_vnr(current))   return -EPERM;
/// copybytes = tocopy * sizeof(struct __user_cap_data_struct);
/// if (copybytes > sizeof(kdata))                  return -EFAULT;
/// if (copy_from_user(&kdata, data, copybytes))    return -EFAULT;
/// ```
///
/// The order is the point. EPERM is a LEGITIMATE answer from this call
/// (asking to change another task's caps), so it must not double as the
/// generic failure value — a caller that gets EPERM has to be able to
/// conclude "I asked about the wrong process", not "something, somewhere,
/// went wrong". Equally, the version check runs BEFORE the data pointer is
/// touched: a caller with a stale header version learns that first, and
/// gets the supported version written back, even when it also passed a
/// null `datap`.
pub(crate) fn sys_capset(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
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
    let pid = i32::from_le_bytes(hdr[4..].try_into().unwrap());
    let ndata = match cap_ndata(version) {
        Some(n) => n,
        None => {
            hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
            // SAFETY: hdrp validated by the read above; same 8-byte range.
            let _ = unsafe { copy_to_user(hdrp, &hdr) };
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
    };
    // Linux's `task_pid_vnr(current)` comparison is against the caller's
    // visible PID, not NARF's internal scheduler TaskId. A service launcher
    // obtains that value from getpid(2) and supplies it here.
    let task = current_task_id();
    let self_pid = task_to_pid_raw(task).unwrap_or(task);
    // The header pid is interpreted in the CALLER's pid namespace (Linux
    // kernel/capability.c:115 compares task_pid_vnr(current)). Translate the
    // inner pid to its outer ProcessId before comparing against the caller's
    // own outer self pid — a container passing getpid() (an inner value) must
    // not hit a spurious EPERM. Audit finding #19.
    let target_pid = if pid != 0 {
        match accept_pid_from(task, pid as u64) {
            Some(outer) => outer,
            None => {
                ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
                return;
            }
        }
    } else {
        0
    };
    if target_pid != 0 && target_pid != self_pid {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }
    // `copy_from_user(&kdata, data, copybytes)` is the LAST check, after the
    // version and the pid: a null/faulting `datap` is -EFAULT, and it must
    // not pre-empt the -EINVAL version handshake above.
    if datap == 0 {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    // SAFETY: datap checked non-zero above; copy_from_user_vec range-validates
    // the read before copying within the SMAP window.
    let buf = match unsafe { copy_from_user_vec(datap, ndata * 12) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    };
    // `struct __user_cap_data_struct { __u32 effective, permitted,
    // inheritable; }`, in that order.
    let mut requested = [0u64; 3];
    for (field, slot) in requested.iter_mut().enumerate() {
        let lo = u32::from_le_bytes(buf[field * 4..field * 4 + 4].try_into().unwrap()) as u64;
        let hi = if ndata == 2 {
            u32::from_le_bytes(buf[12 + field * 4..12 + field * 4 + 4].try_into().unwrap()) as u64
        } else {
            0
        };
        *slot = lo | (hi << 32);
    }
    let [effective, permitted, inheritable] = requested;
    // `security/commoncap.c::cap_capset` — this call used to write whatever
    // it was handed straight into the table, so any task could grant itself
    // any capability. Every `capable()` gate elsewhere in the tree depends
    // on this check: without it, a syscall guarded by CAP_SETUID is reached
    // simply by asking for CAP_SETUID first.
    match cap_capset(read_caps(task), effective, permitted, inheritable) {
        Ok(new) => {
            write_caps(task, new);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(errno) => ctx.set_return(SyscallReturn::ok((-errno) as u64)),
    }
}
