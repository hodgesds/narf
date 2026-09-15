#[allow(unused_imports)]
use super::*;

/// `clock_getres(clock_id, *timespec)` — report the resolution of a
/// supported clock. NARF's clocks are all derived from the cycle counter
/// via the calibrated mult/shift scale, so we report `{0, 1}`. `timespec`
/// may be NULL (the call then just validates the clock id).
///
/// `SYSCALL_DEFINE2(clock_getres)`:
///
///   const struct k_clock *kc = clockid_to_kclock(which_clock);
///   if (!kc) return -EINVAL;
///
/// so an id this kernel cannot serve is -EINVAL. This used to be
/// `invalid_op()`, whose `value` is 0 — the register the Linux ABI returns
/// — so the call reported success and left the caller's `struct timespec`
/// holding whatever was on its stack. A caller sizing a sleep or a poll
/// timeout off that resolution reads an uninitialised number as ns.
///
/// The accepted set was also shorter than `sys_clock_gettime`'s, so
/// `clock_getres(CLOCK_PROCESS_CPUTIME_ID)` refused — by fabricating
/// success — a clock `clock_gettime` answers. Both now consult
/// [`clock_id_supported`], and `smoke_abi_time_getres_matches_gettime_ids`
/// walks the id space asserting the two agree, so the lists cannot drift
/// apart again without a test failing.
pub(crate) fn sys_clock_getres(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let buf = args.arg1;
    if !clock_id_supported(id) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    if buf != 0 {
        let mut kbuf = [0u8; 16];
        // tv_sec = 0, tv_nsec = 1 (1 ns resolution).
        //
        // Linux reports a tick for the two CPU-time clocks
        // (`posix_cpu_clock_getres`: `tp->tv_nsec = (NSEC_PER_SEC + HZ - 1)
        // / HZ`). NARF's answer is genuinely finer: `sys_clock_gettime`
        // folds `current_slice_elapsed_ns()` — cycle-derived — into the
        // accumulated total, so two reads inside one tick do differ. 1 ns
        // describes this kernel; a tick would describe Linux's.
        kbuf[8..16].copy_from_slice(&1i64.to_ne_bytes());
        // SAFETY: `buf` is the user `timespec*` (non-zero); copy_to_user
        // range-validates the 16-byte write.
        if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
            // Faulting timespec buffer → EFAULT.
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
