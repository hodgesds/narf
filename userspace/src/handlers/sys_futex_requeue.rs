#[allow(unused_imports)]
use super::*;

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE4(futex_requeue)` (x86_64=456,
/// aarch64=456) — "Identical to the traditional FUTEX_CMP_REQUEUE op,
/// except it is part of the futex2 family of calls."
///
/// `waiters` points at two `struct futex_waitv` entries: `[0]` the source
/// word to wake, `[1]` the destination to requeue onto.
///
/// Linux's rejection order:
///   1. `if (flags) return -EINVAL;` — the syscall-level flags word is
///      reserved; futex2 puts the real flags in each `futex_waitv` entry.
///   2. `if (!waiters) return -EINVAL;` — a null array is malformed, NOT a
///      no-op that still reports `nr_wake` released.
///   3. `futex_parse_waitv(futexes, waiters, 2, ...)` — -EFAULT on a
///      faulting array, -EINVAL on a bad per-entry flags/`__reserved`.
///   4. `if (futexes[0].w.flags != futexes[1].w.flags) return -EINVAL;` —
///      "For now mandate both flags are identical".
///   5. `futex_requeue()`: `if (nr_wake < 0 || nr_requeue < 0) return
///      -EINVAL;`, then the two `get_futex_key()` calls (-EINVAL for a
///      misaligned word, -EFAULT for an inaccessible one).
///
/// Why the errno matters here specifically: musl's `pthread_cond_broadcast`
/// hands off through requeue. A malformed requeue that comes back as EPERM
/// looks to musl like a completed handoff, and the next waiter stays parked
/// on a barrier word nobody will ever wake — a deterministic broadcast
/// strand rather than a reported error.
///
/// Wakes up to `nr_wake` source waiters and moves up to `nr_requeue` more
/// onto the destination queue, returning woken + requeued (`task_count`).
pub(crate) fn sys_futex_requeue(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let waiters = args.arg0;
    // `unsigned int flags`, `int nr_wake`, `int nr_requeue` — all 32-bit.
    if args.arg1 as u32 != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    if waiters == 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let entries = match handler_sys_futex_waitv::futex2_parse_waitv(waiters, 2) {
        Ok(e) => e,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    if entries[0].flags != entries[1].flags {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let nr_wake = args.arg2 as i32;
    let nr_requeue = args.arg3 as i32;
    if nr_wake < 0 || nr_requeue < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `futex_requeue()`: key1, then key2 (`get_futex_key` — a skewed word is
    // -EINVAL, an inaccessible one -EFAULT; each entry's natural alignment
    // follows its own flags, so a FUTEX2_NUMA entry must be 8-byte aligned).
    let src = entries[0].uaddr;
    let dst = entries[1].uaddr;
    let key1 = match get_futex_key_flags(entries[0].flags & FUTEX_PRIVATE != 0, src, entries[0].flags)
    {
        Ok(k) => k,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let key2 = match get_futex_key_flags(entries[1].flags & FUTEX_PRIVATE != 0, dst, entries[1].flags)
    {
        Ok(k) => k,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // `SYSCALL_DEFINE4(futex_requeue)` ends with
    //
    //     cmpval = futexes[0].w.val;
    //     return futex_requeue(uaddr1, ..., uaddr2, ..., nr_wake, nr_requeue,
    //                          &cmpval, 0);
    //
    // so the SOURCE entry's `val` is a compare operand, not a payload, and a
    // `*uaddr1` that has moved since the caller read it is -EAGAIN. That
    // compare is the whole point of the argument: it is how a condvar detects
    // that a signaller raced it between reading the word and asking to
    // requeue. Skipping it requeued waiters against a stale view.
    match futex_read_user_word(src) {
        Some(cur) if u64::from(cur) == entries[0].val => {}
        Some(_) => {
            ctx.set_return(errno_ret(EAGAIN));
            return;
        }
        None => {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    }
    // Wake up to `nr_wake` waiters on the source and MOVE up to
    // `nr_requeue` more onto the destination's queue without waking them,
    // exactly as FUTEX_CMP_REQUEUE does (`futex_requeue` is that op). A
    // requeued waiter stays blocked until a wake on the DESTINATION word.
    // The destination word is sampled for the park-loop movers' word
    // re-validation, as the classic op does.
    let new_val = futex_read_user_word(dst).unwrap_or(0);
    let (woken, moved) =
        futex_requeue_waiters_keyed(key1, key2, dst, nr_wake as u32, nr_requeue as u32, new_val);
    // `futex_requeue` returns `task_count`: woken plus requeued.
    ctx.set_return(SyscallReturn::ok((woken + moved) as u64));
}
