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
    let a = *ctx.args();
    let hdrp = a.arg0;
    let datap = a.arg1;
    if hdrp == 0 {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let mut hdr = [0u8; 8];
    // SAFETY: hdrp checked non-zero; copy_from_user range-validates the read.
    if unsafe { copy_from_user(&mut hdr, hdrp) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
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
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    };
    // kernel/capability.c:233: `if (pid != 0 && pid != task_pid_vnr(current))
    // return -EPERM;`. `task_pid_vnr` is PIDTYPE_PID — the caller's own TID
    // in its pid namespace, i.e. what gettid(2) returns. For a thread-group
    // leader that equals getpid(); a non-leader thread must name itself by
    // its tid, and its leader's pid is someone else (-EPERM).
    let task = current_task_id();
    if pid != 0 && i64::from(pid) != linux_tid_for_task(task) as i64 {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // `copy_from_user(&kdata, data, copybytes)` is the LAST check, after the
    // version and the pid: a null/faulting `datap` is -EFAULT, and it must
    // not pre-empt the -EINVAL version handshake above.
    if datap == 0 {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // SAFETY: datap checked non-zero above; copy_from_user_vec range-validates
    // the read before copying within the SMAP window.
    let buf = match unsafe { copy_from_user_vec(datap, ndata * 12) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(errno_ret(EFAULT));
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
        Err(errno) => ctx.set_return(errno_ret(errno)),
    }
}
