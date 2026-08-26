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
/// Under the counter model there is no per-task queue to splice, so we wake
/// the source (bump its counter); parked waiters re-arm and re-evaluate
/// against the destination word themselves. Reports `nr_wake` released.
pub(crate) fn sys_futex_requeue(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
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
    if entries[0].uaddr % 4 != 0 || entries[1].uaddr % 4 != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
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
    let src = entries[0].uaddr;
    if src != 0 {
        let mut word = [0u8; 4];
        // SAFETY: `src` was alignment- and range-checked above; copy_from_user
        // re-validates and SMAP-brackets the 4-byte read.
        match unsafe { copy_from_user(&mut word, src) } {
            Ok(()) => {
                if u64::from(u32::from_ne_bytes(word)) != entries[0].val {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
            }
            Err(errno) => {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
        }
    }
    if src != 0 {
        let namespace = futex_namespace((entries[0].flags & FUTEX_PRIVATE) != 0);
        let key = futex_key(namespace, src);
        futex_bump_counter_key(key);
        let _ = futex_wake_waiters_key(key, nr_wake as u32);
    }
    ctx.set_return(SyscallReturn::ok(nr_wake as u64));
}
