#[allow(unused_imports)]
use super::*;

/// `clock_getres(clock_id, *timespec)` — report the resolution of a
/// supported clock. NARF's monotonic/wall clocks are nanosecond-
/// granular, so we report `{0, 1}`. `timespec` may be NULL (the call
/// then just validates the clock id).
pub(crate) fn sys_clock_getres(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let buf = args.arg1;
    if !matches!(
        id,
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME
    ) {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if buf != 0 {
        let mut kbuf = [0u8; 16];
        // tv_sec = 0, tv_nsec = 1 (1 ns resolution).
        kbuf[8..16].copy_from_slice(&1i64.to_ne_bytes());
        // SAFETY: `buf` is the user `timespec*` (non-zero); copy_to_user
        // range-validates the 16-byte write.
        if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
