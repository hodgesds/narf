//! `sched_setattr(2)` — `kernel/sched/syscalls.c`.

#[allow(unused_imports)]
use super::*;

/// Returns the normalised attr bytes, or a positive errno.
fn copy_attr(uattr: u64) -> Result<[u8; SCHED_ATTR_SIZE], i64> {
    // `err_size` writes `sizeof(*attr)` back before failing. Best-effort:
    // the errno stands even if the caller's buffer turned out unwritable,
    // matching `put_user`'s return being ignored on this path.
    let err_size = || {
        // SAFETY: copy_to_user range-validates the four bytes; a failure is
        // deliberately not propagated, as in Linux.
        let _ = unsafe { copy_to_user(uattr, &(SCHED_ATTR_SIZE as u32).to_ne_bytes()) };
        E2BIG
    };

    let mut size_buf = [0u8; 4];
    // SAFETY: copy_from_user range-validates the four-byte read.
    if unsafe { copy_from_user(&mut size_buf, uattr) }.is_err() {
        return Err(EFAULT);
    }
    let mut size = u32::from_ne_bytes(size_buf) as usize;
    // `if (!size) size = SCHED_ATTR_SIZE_VER0;`
    if size == 0 {
        size = SCHED_ATTR_SIZE_VER0;
    }
    // `if (size < SCHED_ATTR_SIZE_VER0 || size > PAGE_SIZE) goto err_size;`
    if !(SCHED_ATTR_SIZE_VER0..=4096).contains(&size) {
        return Err(err_size());
    }

    let known = size.min(SCHED_ATTR_SIZE);
    let mut attr = [0u8; SCHED_ATTR_SIZE];
    // SAFETY: copy_from_user range-validates the read; `known` is at most
    // the struct this kernel knows.
    match unsafe { copy_from_user(&mut attr[..known], uattr) } {
        Ok(_) => {}
        Err(_) => return Err(EFAULT),
    }

    // `copy_struct_from_user`: every byte past the struct THIS kernel knows
    // must be zero. Truncating instead would silently discard a field the
    // caller set and believes is in effect — which is the whole reason the
    // extensible-struct rule exists.
    if size > SCHED_ATTR_SIZE {
        let rest = size - SCHED_ATTR_SIZE;
        // SAFETY: copy_from_user_vec range-validates the tail, which lies
        // inside the caller-declared struct.
        let tail = match unsafe { copy_from_user_vec(uattr + SCHED_ATTR_SIZE as u64, rest) } {
            Ok(v) => v,
            Err(_) => return Err(EFAULT),
        };
        if tail.iter().any(|&b| b != 0) {
            return Err(err_size());
        }
    }

    // `if ((attr->sched_flags & SCHED_FLAG_UTIL_CLAMP) && size <
    // SCHED_ATTR_SIZE_VER1) return -EINVAL;`
    //
    // -EINVAL here, NOT the -E2BIG above: the size was acceptable, the
    // combination was not. NARF knows only VER0, so every util-clamp
    // request lands here — a pre-VER1 kernel's answer, and the reason the
    // constant is named rather than inlined.
    let flags = u64::from_ne_bytes(attr[8..16].try_into().unwrap());
    if flags & SCHED_FLAG_UTIL_CLAMP != 0 && size < SCHED_ATTR_SIZE_VER1 {
        return Err(EINVAL);
    }
    // `__sched_setscheduler`: `if (attr->sched_flags & ~SCHED_FLAG_ALL)
    // return -EINVAL;` — a flag no kernel defines is a caller expecting
    // something that will not happen, and silence would be the wrong answer.
    if flags & !SCHED_FLAG_ALL != 0 {
        return Err(EINVAL);
    }
    Ok(attr)
}

/// `SYSCALL_DEFINE3(sched_setattr, pid_t pid, struct sched_attr __user *uattr,
/// unsigned int flags)`.
pub(crate) fn sys_sched_setattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let uattr = a.arg1;
    // `if (unlikely(!uattr || pid < 0 || flags)) return -EINVAL;` — all
    // three before the struct is read, so a caller that got two things wrong
    // is not told about the second one first.
    let pid = a.arg0 as u32 as i32;
    if uattr == 0 || pid < 0 || a.arg2 != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let attr = match copy_attr(uattr) {
        Ok(a) => a,
        Err(e) => {
            ctx.set_return(errno_ret(e));
            return;
        }
    };
    // `if ((int)attr.sched_policy < 0) return -EINVAL;` — the cast is
    // load-bearing: `sched_policy` is a `__u32`, and the check is for a
    // value that would be negative as a signed int.
    let policy = i32::from_ne_bytes(attr[4..8].try_into().unwrap());
    if policy < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `CLASS(find_get_task, p)(pid); if (!p) return -ESRCH;` — pid 0 is the
    // caller. Storing attributes for a pid that does not exist would leave
    // the table answering `sched_getattr` for a process nobody can see.
    let task = match resolve_sched_target(pid as u64) {
        Some(t) => t,
        None => {
            ctx.set_return(errno_ret(ESRCH));
            return;
        }
    };
    SCHED_ATTR_TABLE
        .lock()
        .get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(task, attr);
    ctx.set_return(SyscallReturn::ok(0));
}

/// `find_process_by_pid(pid)` with Linux's `pid == 0 ? current : ...`.
pub(crate) fn resolve_sched_target(pid: u64) -> Option<u64> {
    if pid == 0 {
        return Some(current_task_id());
    }
    pid_to_task_raw(pid).or_else(|| {
        // The harness and early boot register tasks by raw id; accept a live
        // registry entry under its own id so a self-directed call works
        // before the pid mapping exists.
        crate::task::task_get(pid).map(|_| pid)
    })
}
