#[allow(unused_imports)]
use super::*;

/// `rt_sigprocmask(how, nset, oset, sigsetsize)` — Linux `rt_sigprocmask(2)`.
///
/// Error order follows `SYSCALL_DEFINE4(rt_sigprocmask)` (kernel/signal.c,
/// Linux 7.0):
///   1. `sigsetsize != sizeof(sigset_t)` → -EINVAL,
///   2. snapshot the PRE-change mask for `oset`,
///   3. if `nset`: copy it in (-EFAULT on fault), then apply it under a valid
///      `how` — an invalid `how` is -EINVAL (from `sigprocmask`) and, like a
///      faulting `nset`, must leave `*oset` UNWRITTEN,
///   4. if `oset`: copy the snapshot out (-EFAULT on fault).
///
/// `how` is only inspected when `nset != NULL` — `rt_sigprocmask(garbage, NULL,
/// oset, 8)` is a pure query and returns 0, matching Linux.
pub(crate) fn sys_sigprocmask(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let how = args.arg0 as u32;
    let set_ptr = args.arg1;
    let old_ptr = args.arg2;
    let sigsetsize = args.arg3 as usize;

    if sigsetsize != 8 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    let task = current_task_id();
    // (2) Snapshot the pre-change mask (Linux `old_set = current->blocked`
    // before the nset install). NARF's internal mask layout is bit N-1 =
    // signal N — identical to a userspace `sigset_t` — so it copies out
    // verbatim later.
    let old_mask = signal_bits_get(&SIGNAL_MASK, task);

    if set_ptr != 0 {
        let mut buf = [0u8; 8];
        // SAFETY: `set_ptr` is the user new-sigmask pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 8-byte read.
        if unsafe { copy_from_user(&mut buf, set_ptr) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        // Validate `how` BEFORE mutating (Linux `sigprocmask` returns -EINVAL
        // for an unknown `how`, and nothing is installed).
        if how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
        // Userspace `sigset_t` bit N-1 == signal N == NARF's internal layout
        // (see SIGNAL_PENDING), so the new mask installs verbatim.
        let set = u64::from_ne_bytes(buf);
        let updated = signal_bits_update(&SIGNAL_MASK, task, |slot| {
            match how {
                SIG_BLOCK => *slot |= set,
                SIG_UNBLOCK => *slot &= !set,
                SIG_SETMASK => *slot = set,
                _ => return false, // unreachable — `how` validated above
            }
            // Linux strips SIGKILL/SIGSTOP from every installed mask —
            // a task must never be able to block its own fatal kill.
            *slot &= !UNBLOCKABLE_MASK;
            true
        });
        if updated != Some(true) {
            // No mask slot for the task (a NARF-internal condition, not a
            // Linux-reachable path); EINVAL is the least-wrong answer.
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
        // An explicit mask install means the user retook control of the
        // mask — drop any suspend-saved record a signal-less (aborted)
        // rt_sigsuspend left behind, so a much-later delivery can't
        // "restore" a stale pre-suspend mask over this one.
        let _ = take_suspend_saved_mask(task);
    }

    if old_ptr != 0 {
        // SAFETY: `old_ptr` is the user old-sigmask pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 8-byte write.
        if unsafe { copy_to_user(old_ptr, &old_mask.to_ne_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
