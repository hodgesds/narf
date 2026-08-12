#[allow(unused_imports)]
use super::*;

/// `rt_sigsuspend(set, sigsetsize)` — Linux `rt_sigsuspend(2)`.
/// Atomically swap the signal mask to `set`, wait for one signal
/// outside the new mask to be delivered, then restore the prior
/// mask. Always returns -1 (after delivery); errno = EINTR per
/// POSIX.
///
/// The wait itself is `sys_pause`'s park (u64::MAX deadline, broken by
/// `is_signal_pending` + `wake_signal`), which truly blocks under an
/// executor and degrades to a one-shot -1 in the kernel-test harness.
/// The prior mask is recorded in `SUSPEND_SAVED_MASK` so the
/// interrupting handler's `sys_sigreturn` restores the PRE-SUSPEND mask
/// instead of re-installing the temporary wait mask (Linux
/// TIF_RESTORE_SIGMASK — see `default_signal_delivery_restricted`).
///
/// arg0 = set in ptr, arg1 = sigsetsize (must be 8).
pub(crate) fn sys_rt_sigsuspend(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_uptr = args.arg0;
    let sigsetsize = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if sigsetsize != 8 || set_uptr == 0 {
        ctx.set_return(fail);
        return;
    }

    let mut buf = [0u8; 8];
    // SAFETY: `set_uptr` is the user sigset pointer (non-zero, sigsetsize==8, both
    // checked above); copy_from_user range-validates it and SMAP-brackets the 8-byte read.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut buf, set_uptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    // Userspace `sigset_t` bit N-1 == signal N == NARF's internal layout
    // (see SIGNAL_PENDING), so the suspend mask installs verbatim.
    // SIGKILL/SIGSTOP can never be blocked, in a suspend mask either.
    let mask = u64::from_ne_bytes(buf) & !UNBLOCKABLE_MASK;
    let task = current_task_id();

    // Temporarily install the new mask, remembering the prior one so the
    // interrupting delivery's sigreturn restores IT (not the temp mask).
    let prior = signal_bits_update_or_init(&SIGNAL_MASK, task, |slot| {
        let prior = *slot;
        *slot = mask;
        prior
    });
    set_suspend_saved_mask(task, prior);

    // Pause until signal.
    sys_pause(ctx);
}
