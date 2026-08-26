#[allow(unused_imports)]
use super::*;

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE4(futex_wake)` (x86_64=454,
/// aarch64=454) — "Identical to the traditional FUTEX_WAKE_BITSET op,
/// except it is part of the futex2 family of calls."
///
/// Linux's rejection order:
///   1. `if (flags & ~FUTEX2_VALID_MASK) return -EINVAL;`
///   2. `if (!futex_flags_valid(flags)) return -EINVAL;` — the access
///      width must be `FUTEX2_SIZE_U32`.
///   3. `futex_wake()`: `if (!bitset) return -EINVAL;` — an all-zero mask
///      matches no waiter, so Linux calls it malformed rather than letting
///      it look like "nobody was waiting".
///   4. `get_futex_key()`: misaligned uaddr -EINVAL (not -EFAULT).
///   5. `if ((flags & FLAGS_STRICT) && !nr_wake) return 0;` — futex2 sets
///      FLAGS_STRICT, so `nr == 0` is a legal no-op, not an error.
///
/// A wake that comes back as EPERM instead of EINVAL is the worst case for
/// a condvar: `pthread_cond_signal` has no error path, so the wake is
/// simply lost and the waiter sleeps through its own signal.
///
/// Bumps the per-uaddr wake counter — every cooperative waiter parked on
/// this word observes the bump on its next poll and re-arms — and reports
/// the number of waiters released. NARF keeps no per-task wait ownership
/// (the counter is the queue), so we report the `nr` the caller asked to
/// wake, which the pthread fast paths treat as "≤ nr released".
pub(crate) fn sys_futex_wake(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    let args = *ctx.args();
    let uaddr = args.arg0;
    // `unsigned int flags`; `int nr` — a 64-bit read of `nr` would let a
    // caller's stale upper register bits come back as the return value,
    // where a large positive count is indistinguishable from a negative
    // errno once libc sign-checks it.
    let flags = args.arg3 as u32 as u64;
    if !handler_sys_futex_wait::futex2_flags_valid(flags) {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `futex_validate_input(flags, mask)`:
    //
    //     int bits = 8 * futex_size(flags);
    //     if (bits < 64 && (val >> bits)) return false;
    //
    // For FUTEX2_SIZE_U32 that is 32 bits, so a mask with anything set above
    // bit 31 is -EINVAL — "every bit" is 0xffffffff, not ~0UL. An empty mask
    // matches nothing and is likewise rejected.
    if !handler_sys_futex_wait::futex2_input_valid(flags, args.arg1) {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    if args.arg1 as u32 == 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    if uaddr % 4 != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let nr = args.arg2 as i32;
    if nr == 0 || uaddr == 0 {
        // FLAGS_STRICT: a zero count is a successful no-op. A null uaddr
        // has no wait queue in NARF, which is the same observable answer
        // Linux gives (a valid-but-empty key wakes nobody).
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // A negative count reaches `futex_wake`'s `if (++ret >= nr_wake) break;`
    // and stops after the first waiter, so it behaves as nr == 1.
    let want = if nr < 0 { 1u32 } else { nr as u32 };
    // Bump the gen counter AND fire up to `want` parked waiters on the real
    // queue (futex2 and classic futex share the same words / queue).
    let key = futex_key(futex_namespace((flags & FUTEX_PRIVATE) != 0), uaddr);
    futex_bump_counter_key(key);
    let _ = futex_wake_waiters_key(key, want);
    ctx.set_return(SyscallReturn::ok(want as u64))
}
