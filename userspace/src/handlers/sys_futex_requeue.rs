#[allow(unused_imports)]
use super::*;

/// Linux futex2 `futex_requeue(waiters, flags, nr_wake, nr_requeue)`
/// (x86_64=456, aarch64=456). `waiters` points at two `futex_waitv`
/// entries: `[0]` the source word to wake, `[1]` the destination to
/// requeue onto. Under the counter model there is no per-task queue to
/// splice, so we wake the source (bump its counter); parked waiters
/// re-arm and re-evaluate against the destination word themselves.
/// Reports `nr_wake` released.
pub(crate) fn sys_futex_requeue(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let waiters = args.arg0;
    let nr_wake = args.arg2;
    if waiters != 0 {
        // struct futex_waitv { u64 val; u64 uaddr; u32 flags; u32 _r; } — 24B.
        let mut entry = [0u8; 24];
        // SAFETY: copy_from_user validates the 24-byte source range.
        if unsafe { copy_from_user(&mut entry, waiters) }.is_ok() {
            let src = u64::from_ne_bytes(entry[8..16].try_into().unwrap());
            if src != 0 {
                futex_bump_counter(src);
                let _ = futex_wake_waiters(src, nr_wake as u32);
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(nr_wake));
}
