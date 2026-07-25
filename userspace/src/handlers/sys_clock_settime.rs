#[allow(unused_imports)]
use super::*;

/// `sys_clock_settime(clock_id, *timespec)` — set CLOCK_REALTIME
/// by computing the wall-offset from the requested (sec, nsec) and
/// the current monotonic. Other clock_ids return -1.
pub(crate) fn sys_clock_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let ts = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ts == 0 {
        ctx.set_return(fail);
        return;
    }
    if id != CLOCK_REALTIME {
        // CLOCK_MONOTONIC and friends are not settable.
        ctx.set_return(fail);
        return;
    }
    // Read the timespec (two i64s) from user space under the SMAP bracket.
    let mut kbuf = [0u8; 16];
    // SAFETY: `ts` is the user timespec pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 16-byte read.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut kbuf, ts) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let sec = i64::from_ne_bytes(kbuf[..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(kbuf[8..].try_into().unwrap());
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        ctx.set_return(fail);
        return;
    }
    let target_ns = (sec as i128) * 1_000_000_000 + (nsec as i128);
    let mono_ns = narf_scheduler::narf_time::monotonic_ns() as i128;
    let offset_ns = (target_ns - mono_ns) as i64;
    narf_scheduler::narf_time::set_wall_offset_uncapped(offset_ns);
    // Republish the offset to the vDSO vvar so __vdso_clock_gettime
    // (CLOCK_REALTIME) tracks the new wall time without a syscall.
    crate::vdso::update_wall_offset(offset_ns);
    ctx.set_return(SyscallReturn::ok(0));
}
