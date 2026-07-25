#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_futex(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let uaddr = args.arg0;
    let namespace = futex_namespace((args.arg1 & FUTEX_PRIVATE) != 0);
    let key = futex_key(namespace, uaddr);
    let op = args.arg1 & FUTEX_OP_MASK;
    let val = args.arg2 as u32;
    // KNOWN ABI DIVERGENCE: Linux futex(2)'s 4th argument is a `struct
    // timespec *`, but this handler consumes it as a raw nanosecond count —
    // a stack-allocated timespec pointer (~0x7ffc_xxxx_xxxx) becomes a
    // ~39-hour relative timeout, i.e. every real timed FUTEX_WAIT is
    // effectively untimed and relies on the futex wake / signal wake alone.
    // (Observed directly in the stress-ng --futex SMP strand: the child's
    // "5 µs" wait parked with sleep_deadline_ns ≈ now + 0x7ffc_c8dd_03bd.)
    // Harmless for musl's dominant untimed waits (timeout == NULL == 0) and
    // for waiters that are reliably woken, and NARF's park already treats
    // the deadline only as a backstop — but timed waits never ETIMEDOUT on
    // schedule. Fixing this means copy_from_user of the timespec (+ the
    // WAIT_BITSET absolute-clock variant) and updating the NARF-native
    // callers that pass raw ns; tracked as follow-up, deliberately not
    // folded into the signal-interruptible-park fix.
    let timeout_ns = args.arg3; // 0 = no timeout
    let fail = SyscallReturn::ok((-1i64) as u64);
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
    // FUTEX_WAIT_BITSET behaves like FUTEX_WAIT for NARF's per-uaddr wait
    // queue (the bitmask only narrows WHICH wakes match; a superset wake is
    // safe and musl/glibc pass MATCH_ANY). The bitset timeout is ABSOLUTE in
    // Linux, but NARF's wait path uses the deadline only as a lost-wake
    // backstop (the real wake is the futex wake), so the relative/absolute
    // distinction doesn't affect correctness here.
    let op = if op == FUTEX_WAIT_BITSET {
        FUTEX_WAIT
    } else if op == FUTEX_WAKE_BITSET {
        FUTEX_WAKE
    } else {
        op
    };
    match op {
        FUTEX_WAKE_OP => {
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
            // `val`, the wait condition no longer holds — return 0 (caller's
            // fast path observes the change). Else register on the per-uaddr
            // wait queue and PARK until a `FUTEX_WAKE` on this word fires our
            // waker (or, with a timeout, until it expires) — NOT a fixed
            // nanosleep. The poll routine (`UserTaskFuture::poll`) does the
            // actual waker registration (it owns `cx.waker()`); here we just
            // publish the uaddr + a wake-counter snapshot for its lost-wakeup
            // guard and hand control back via the yield hook. On resume the
            // user reads RAX=0 and musl's recheck loop re-evaluates the word.
            //
            // Null uaddr: no wait queue — immediate (POSIX-permitted) spurious
            // wake so wake-path smokes run without a backing mapping.
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
                    ctx.set_return(fail);
                    return;
                }
            };
            if current != val {
                // Linux FUTEX_WAIT rejects a stale expected value with
                // EAGAIN. Returning success here makes pthread state machines
                // treat a wait that never happened as an actual wake, which
                // can lose the subsequent handoff.
                ctx.set_return(SyscallReturn::ok((-11i64) as u64));
                return;
            }
            // Deadline: a real timeout when one was supplied (wakes at the
            // timeout OR on a FUTEX_WAKE, whichever first), else infinite
            // (`u64::MAX`) — the poll routine parks on the timer wheel with a
            // one-tick fallback as a lost-wake safety net, but the primary
            // wake is the registered futex waker.
            let deadline = if timeout_ns == 0 {
                u64::MAX
            } else {
                narf_scheduler::narf_time::monotonic_ns().saturating_add(timeout_ns)
            };
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
            const EAGAIN: i64 = 11;
            const EFAULT: i64 = 14;
            let uaddr2 = args.arg4;
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
        _ => ctx.set_return(fail),
    }
}
