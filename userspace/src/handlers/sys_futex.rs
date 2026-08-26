#[allow(unused_imports)]
use super::*;

/// Ops NARF does not implement but that Linux's `do_futex` still
/// recognises. They are named here only for the two checks that run
/// BEFORE the dispatch switch — which ops carry a `struct timespec *`
/// (`futex_cmd_has_timeout`) and which may carry `FUTEX_CLOCK_REALTIME`.
/// Getting those sets wrong changes the errno an unimplemented op
/// reports, which is what a libc feature probe reads.
const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_WAIT_REQUEUE_PI: u64 = 11;
const FUTEX_LOCK_PI2: u64 = 13;

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE6(futex)` → `do_futex()`.
///
/// The errno a futex op returns is not advisory — glibc's and musl's
/// mutex/condvar fast paths branch on it. `EAGAIN` means "the word moved
/// under me, re-read it and retry", `ETIMEDOUT` means "the deadline won",
/// `EINVAL` means "this call is malformed, stop", and `ENOSYS` means
/// "fall back to the older op". Reporting the bare `-1` sentinel makes
/// every one of them arrive as `EPERM`, which no locking fast path knows
/// how to interpret — it does not slow locking down, it breaks it.
///
/// Order of the pre-dispatch checks, exactly as Linux stages them:
///   1. `SYSCALL_DEFINE6(futex)` decodes `utime` for the ops that take a
///      timeout, so `-EFAULT`/`-EINVAL` from a bad timespec beats
///      everything `do_futex` would say about the op itself.
///   2. `do_futex`: `if (flags & FLAGS_CLOCKRT) { if (cmd != ...) return
///      -ENOSYS; }` — `FUTEX_CLOCK_REALTIME` is only defined for the ops
///      that take an ABSOLUTE deadline.
///   3. the dispatch switch; anything unrecognised falls out the bottom
///      as `return -ENOSYS`.
pub(crate) fn sys_futex(ctx: &mut dyn TrapContext) {
    const EAGAIN: i64 = 11;
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    const ENOSYS: i64 = 38;
    const ETIMEDOUT: i64 = 110;
    let args = *ctx.args();
    let uaddr = args.arg0;
    // Linux declares the op as `int`, so only the low 32 bits ever reach
    // `do_futex`. Masking the full 64-bit register instead would turn a
    // caller that left junk in the upper half (a sign-extended `int` in a
    // hand-written stub is the usual source) into an unrecognised op.
    let raw_op = args.arg1 as u32 as u64;
    let namespace = futex_namespace((raw_op & FUTEX_PRIVATE) != 0);
    let key = futex_key(namespace, uaddr);
    let cmd = raw_op & FUTEX_OP_MASK;
    let val = args.arg2 as u32;
    // Start each futex op from clean park state so a stale `futex_uaddr` left
    // by a prior wait (e.g. a wake that cleared only the deadline) can't make
    // the poll routine re-register on the old word.
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: uctx is live for this trap; atomic field.
        unsafe {
            (*uctx).futex_uaddr.store(0, Ordering::Release);
            (*uctx).futex_namespace.store(0, Ordering::Release);
        }
    }
    // Step 1: the timespec is decoded in the syscall wrapper, before
    // `do_futex` sees the op. `futex_init_timeout` treats FUTEX_WAIT's
    // timespec as a RELATIVE duration and every other timeout-carrying
    // op's as an ABSOLUTE deadline; `timespec64_valid` rejects a negative
    // `tv_sec` or an out-of-range `tv_nsec` with -EINVAL, and a faulting
    // `utime` is -EFAULT.
    let realtime = (raw_op & FUTEX_CLOCK_REALTIME) != 0;
    let has_timeout = matches!(
        cmd,
        FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_WAIT_REQUEUE_PI
    );
    let deadline = if has_timeout && args.arg3 != 0 {
        match futex_timeout_deadline(args.arg3, cmd != FUTEX_WAIT, realtime) {
            Ok(d) => d,
            Err(errno) => {
                ctx.set_return(SyscallReturn::ok((-errno) as u64));
                return;
            }
        }
    } else {
        None
    };
    // Step 2: `FUTEX_CLOCK_REALTIME` on an op that has no absolute
    // deadline to reinterpret is -ENOSYS, NOT a silently ignored bit.
    // glibc probes exactly this: `futex_abstimed_wait` issues
    // FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME and treats ENOSYS as "this
    // kernel is too old, convert to a relative FUTEX_WAIT instead". A
    // kernel that accepts the bit everywhere hides the probe; one that
    // answers EPERM makes the probe look like a permission failure.
    if realtime
        && !matches!(
            cmd,
            FUTEX_WAIT_BITSET | FUTEX_LOCK_PI2 | FUTEX_WAIT_REQUEUE_PI
        )
    {
        ctx.set_return(SyscallReturn::ok((-ENOSYS) as u64));
        return;
    }
    // `futex_wake()` and `__futex_wait()` both open with
    // `if (!bitset) return -EINVAL;` — BEFORE `get_futex_key`, so an empty
    // bitset outranks a misaligned address and a stale value alike. Only
    // the _BITSET ops read `val3`: `do_futex` overwrites it with
    // FUTEX_BITSET_MATCH_ANY for plain FUTEX_WAIT/FUTEX_WAKE, which is why
    // those must not be checked (their arg5 is whatever the caller left in
    // r9 for a 4-argument syscall stub).
    if matches!(cmd, FUTEX_WAIT_BITSET | FUTEX_WAKE_BITSET) && args.arg5 as u32 == 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `get_futex_key()`: "The futex address must be naturally aligned" —
    // `if (unlikely((address % size) != 0)) return -EINVAL;`, and only
    // then `if (!access_ok(...)) return -EFAULT;`. So a misaligned word is
    // EINVAL, never EFAULT: a caller that mis-lays out its lock struct
    // must be able to tell "your pointer is skewed" (a bug it has to fix)
    // apart from "that page went away" (which a retry can resolve).
    let aligned = |p: u64| p % 4 == 0;
    // FUTEX_WAIT_BITSET behaves like FUTEX_WAIT for NARF's per-uaddr wait
    // queue (the bitmask only narrows WHICH wakes match; a superset wake is
    // safe and musl/glibc pass MATCH_ANY). Its timeout remains distinct:
    // WAIT_BITSET takes an absolute deadline while WAIT takes a relative
    // duration, as decoded above.
    let op = if cmd == FUTEX_WAIT_BITSET {
        FUTEX_WAIT
    } else if cmd == FUTEX_WAKE_BITSET {
        FUTEX_WAKE
    } else {
        cmd
    };
    match op {
        FUTEX_WAKE_OP => {
            // `futex_wake_op` keys BOTH words, so either one being skewed
            // is -EINVAL before any of the RMW work happens.
            if !aligned(uaddr) || !aligned(args.arg4) {
                ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
                return;
            }
            let r = futex_wake_op(
                namespace,
                uaddr,
                val,
                args.arg3 as u32,
                args.arg4,
                args.arg5 as u32,
            );
            ctx.set_return(SyscallReturn::ok(r as u64));
        }
        FUTEX_WAIT => {
            // REAL blocking futex. Sample *uaddr; if it already differs from
            // `val`, the wait condition no longer holds — return -EAGAIN
            // (Linux `futex_wait_setup`: `if (uval != val) return
            // -EWOULDBLOCK;`). Else register on the per-uaddr wait queue and
            // PARK until a `FUTEX_WAKE` on this word fires our waker (or,
            // with a timeout, until it expires) — NOT a fixed nanosleep. The
            // poll routine (`UserTaskFuture::poll`) does the actual waker
            // registration (it owns `cx.waker()`); here we just publish the
            // uaddr + a wake-counter snapshot for its lost-wakeup guard and
            // hand control back via the yield hook. On resume the user reads
            // RAX=0 and musl's recheck loop re-evaluates the word.
            if !aligned(uaddr) {
                ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
                return;
            }
            // Null uaddr: no wait queue — immediate (POSIX-permitted) spurious
            // wake so wake-path smokes run without a backing mapping.
            // LINUX-GAP: Linux would fault the read and answer -EFAULT.
            if uaddr == 0 {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            // Seqlock read: sample the wake generation BEFORE reading `*uaddr`
            // (see `futex_wait_seqlock_read` — sampling after the read loses a
            // racing FUTEX_WAKE and deadlocks a contended mutex/condvar on SMP).
            let (gen, current) = match futex_wait_seqlock_read_key(key, || {
                let mut buf4 = [0u8; 4];
                // SAFETY: `uaddr` is the user futex word pointer (non-zero, checked
                // above); copy_from_user range-validates it + SMAP-brackets the read.
                if unsafe { copy_from_user(&mut buf4, uaddr) }.is_ok() {
                    Some(u32::from_ne_bytes(buf4))
                } else {
                    None
                }
            }) {
                Some(x) => x,
                None => {
                    // `futex_wait_setup` retries the read outside the hash
                    // bucket via `get_user`, and reports its failure as
                    // -EFAULT. A caller whose lock page was reclaimed can
                    // fault it back in and retry; -EPERM told it to give up.
                    ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
                    return;
                }
            };
            if current != val {
                // Linux FUTEX_WAIT rejects a stale expected value with
                // EAGAIN. Returning success here makes pthread state machines
                // treat a wait that never happened as an actual wake, which
                // can lose the subsequent handoff.
                ctx.set_return(SyscallReturn::ok((-EAGAIN) as u64));
                return;
            }
            // Deadline: a real timeout when one was supplied (wakes at the
            // timeout OR on a FUTEX_WAKE, whichever first), else infinite
            // (`u64::MAX`) — the poll routine parks on the timer wheel with a
            // one-tick fallback as a lost-wake safety net, but the primary
            // wake is the registered futex waker.
            let deadline = deadline.unwrap_or(u64::MAX);
            if deadline <= narf_scheduler::narf_time::monotonic_ns() {
                ctx.set_return(SyscallReturn::ok((-ETIMEDOUT) as u64));
                return;
            }
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                ctx.set_return(SyscallReturn::ok(0));
                // SAFETY: uctx is live for the trap round-trip.
                unsafe {
                    let uc = &*uctx;
                    uc.futex_park_gen.store(gen, Ordering::Release);
                    // Expected word value — the park loop re-validates the
                    // word against this on every backstop re-check, so a
                    // word rewritten WITHOUT a wake (requeue handoffs,
                    // robust-owner death) unparks instead of stranding.
                    uc.futex_val.store(val, Ordering::Release);
                    uc.futex_uaddr.store(uaddr, Ordering::Release);
                    uc.futex_namespace.store(namespace, Ordering::Release);
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    if narf_scheduler::stackful::user_own_stack_enabled() {
                        own_stack_block(ctx);
                        return;
                    }
                    hook(uctx);
                }
                // unreachable
            }
            // Test/no-future fallback: synchronous success.
            ctx.set_return(SyscallReturn::ok(0));
        }
        FUTEX_WAKE => {
            // Bump the per-uaddr generation FIRST (the poll routine's
            // lost-wakeup guard reads it), THEN fire up to `val` parked
            // waiters' wakers. Returns the number actually woken (Linux
            // contract). A waiter not yet registered when we fire is caught
            // by the gen guard on its next poll.
            if !aligned(uaddr) {
                ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
                return;
            }
            futex_bump_counter_key(key);
            let woken = futex_wake_waiters_key(key, val);
            ctx.set_return(SyscallReturn::ok(woken as u64));
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            // futex(uaddr, REQUEUE, nr_wake, nr_requeue, uaddr2[, val3]):
            // wake up to `val` waiters on uaddr, move up to `arg3` more
            // onto uaddr2. CMP_REQUEUE first requires `*uaddr == val3`
            // (-EAGAIN otherwise; Linux futex(2)). Linux returns the count
            // WOKEN for REQUEUE, woken + requeued for CMP_REQUEUE.
            //
            // `futex_requeue()` order: the two counts, then key1, then
            // key2, then the compare. Both counts are `int`, and a
            // negative one is -EINVAL up front — a caller that passed
            // INT_MAX+1 through an `unsigned` variable must learn that the
            // request was malformed, not watch it silently wake everybody.
            let uaddr2 = args.arg4;
            if (args.arg2 as i32) < 0 || (args.arg3 as i32) < 0 {
                ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
                return;
            }
            if !aligned(uaddr) || !aligned(uaddr2) {
                ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
                return;
            }
            if uaddr2 == 0 {
                ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
                return;
            }
            if op == FUTEX_CMP_REQUEUE {
                match futex_read_user_word(uaddr) {
                    Some(cur) if cur == args.arg5 as u32 => {}
                    Some(_) => {
                        ctx.set_return(SyscallReturn::ok((-EAGAIN) as u64));
                        return;
                    }
                    None => {
                        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
                        return;
                    }
                }
            }
            // Sample the destination word for the movers' park-loop word
            // re-validation: a requeued waiter now waits for *uaddr2 to
            // change (the mutex handoff), so its expected value must be
            // the destination word as of the requeue. The requeuing
            // caller shares the movers' address space (futexes requeue
            // within one process), so reading it here resolves correctly.
            // An unreadable destination keeps expected at the sampled 0 —
            // the movers' next backstop re-check then proceeds to
            // userspace and re-evaluates there (spurious, never lost).
            let new_val = futex_read_user_word(uaddr2).unwrap_or(0);
            let (woken, moved) = futex_requeue_waiters_keyed(
                key,
                futex_key(namespace, uaddr2),
                uaddr2,
                val,
                args.arg3 as u32,
                new_val,
            );
            let r = if op == FUTEX_CMP_REQUEUE {
                woken + moved
            } else {
                woken
            };
            ctx.set_return(SyscallReturn::ok(r as u64));
        }
        // `do_futex` falls off the end of its switch with `return -ENOSYS`
        // — that includes the PI ops NARF does not implement. ENOSYS is
        // the word libc probes look for when they decide to fall back to
        // an older op; the bare -1 sentinel reached them as EPERM, which
        // reads as "you are not allowed to lock", not "try another way".
        _ => ctx.set_return(SyscallReturn::ok((-ENOSYS) as u64)),
    }
}
