#[allow(unused_imports)]
use super::*;

/// Linux futex2 `futex_wake(uaddr, mask, nr, flags)` (x86_64=454,
/// aarch64=454). Bumps the per-uaddr wake counter — every cooperative
/// waiter parked on this word observes the bump on its next poll and
/// re-arms — and reports the number of waiters released. NARF keeps no
/// per-task wait ownership (the counter is the queue), so we report the
/// `nr` the caller asked to wake, which the pthread fast paths treat as
/// "≤ nr released".
pub(crate) fn sys_futex_wake(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let uaddr = args.arg0;
    let nr = args.arg2;
    if uaddr == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Bump the gen counter AND fire up to `nr` parked waiters on the real
    // queue (futex2 and classic futex share the same words / queue).
    let key = futex_key(futex_namespace((args.arg3 & FUTEX_PRIVATE) != 0), uaddr);
    futex_bump_counter_key(key);
    let _ = futex_wake_waiters_key(key, nr as u32);
    ctx.set_return(SyscallReturn::ok(nr))
}
