#[allow(unused_imports)]
use super::*;

/// `rt_sigtimedwait(set, info, timeout, sigsetsize)` — Linux
/// `rt_sigtimedwait(2)`. Synchronously wait for one of the signals in
/// `set` to become pending for the calling task, consume it WITHOUT
/// running its handler, and return its signum (+ its `siginfo_t` payload
/// through `info`). The `set` intersection deliberately ignores the block
/// mask: callers block the waited signals first (sigwaitinfo(2)) and this
/// wait dequeues them anyway — that IS the calling convention.
///
/// Blocking model: when nothing in `set` is pending, PARK — route the
/// park through `uctx.sigwait_set` (exactly like `flock_key` /
/// `futex_uaddr` route theirs), rewind RIP so the syscall RE-EXECUTES on
/// wake, and let `park_should_block` / `UserTaskFuture::poll` register
/// this task in `SIGNAL_WAKERS` so any raise path's `wake_signal` fires
/// it promptly (the ~1-tick wheel deadline is only the lost-wake
/// backstop). This is what lets stress-ng --sigrt's round-trip work: the
/// peer parks in sigwaitinfo until the sibling's sigqueue arrives,
/// instead of the old one-shot -1 return that deadlocked the pair.
///
/// Returns:
///   - the signum, when a signal in `set` was consumed (each queued RT
///     instance is an independent delivery — see `SIGQUEUE_INFO`),
///   - -EINTR, when a deliverable signal OUTSIDE `set` is pending (its
///     handler runs via the return-to-user hook),
///   - -EAGAIN, when the (finite) timeout expired — persisted across
///     re-executions in `blocking_deadline_ns`, same as poll/epoll,
///   - -EINVAL for a malformed timespec, -1 for the legacy bad-input
///     shape (sigsetsize != 8 / NULL set) the ABI tests pin.
///
/// arg0 = set ptr (in), arg1 = info ptr (out, may be 0),
/// arg2 = timeout timespec ptr (may be 0 = block indefinitely),
/// arg3 = sigsetsize (must be 8).
pub(crate) fn sys_rt_sigtimedwait(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_in = args.arg0;
    let info_out = args.arg1;
    let timeout_in = args.arg2;
    let sigsetsize = args.arg3;
    if sigsetsize != 8 || set_in == 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    // Read the user sigset through the SMAP-bracketed helper (a raw
    // read_unaligned here #PF'd under SMAP — kernel read of a user page —
    // the moment stress-ng --sigrt actually reached rt_sigtimedwait). The
    // set is already in NARF's bit-N-1 layout (== userspace sigset_t), so
    // it intersects `pending` directly with no shift.
    let mut set_buf = [0u8; 8];
    // SAFETY: set_in != 0 + sigsetsize == 8 checked above; copy_from_user
    // range-validates and SMAP-brackets the 8-byte read.
    if unsafe { copy_from_user(&mut set_buf, set_in) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    let set = u64::from_ne_bytes(set_buf);
    let task = current_task_id();
    let uctx_opt = crate::user_task::current_user_task();

    // Arm the STICKY waiter reservation for this set — it survives the
    // return-to-user gap between consecutive sigtimedwaits so a queued
    // backlog (including stress-ng --sigrt's graceful-shutdown sival=0
    // marker) can only be consumed HERE, never leak to a handler in the
    // processing window. Released by any non-sigwait park (see
    // `UserTaskCtx::sigwait_reserve`).
    if let Some(u) = uctx_opt {
        // SIGKILL(9)/SIGSTOP(19) can never be handler-delivered anyway and
        // must never be maskable from their eager paths — strip them.
        let reserve = set & !(1u64 << 8) & !(1u64 << 18);
        // SAFETY: the in-flight task's poller-pinned UserTaskCtx; atomic only.
        unsafe { (*u).sigwait_reserve.store(reserve, Ordering::Release) };
    }

    // Every return path below must tear the park routing down: the
    // sigwait routing + the persisted timeout deadline + the waker
    // registration (a stale SIGNAL_WAKERS entry only costs one spurious
    // re-poll, but a stale `sigwait_set`/`blocking_deadline_ns` would
    // mis-route the task's NEXT unrelated park / inherit a dead deadline).
    let clear_routing = |uctx_opt: Option<*mut crate::user_task::UserTaskCtx>| {
        if let Some(u) = uctx_opt {
            // SAFETY: the in-flight task's poller-pinned UserTaskCtx;
            // atomics only.
            unsafe {
                (*u).sigwait_set.store(0, Ordering::Release);
                (*u).sigwait_interrupted.store(false, Ordering::Release);
                (*u).blocking_deadline_ns.store(0, Ordering::Release);
            }
        }
        drop_signal_waker(task);
    };

    // A signal in `set` is pending → consume ONE instance and return it.
    if let Some(signum) = sigwait_consume(task, set) {
        // Attach the oldest queued payload (rt_sigqueueinfo/sigqueue), and
        // re-arm the bit when more instances remain queued behind it.
        let queued = take_sigqueue_info(task, signum);
        rearm_pending_if_queued(task, signum);
        clear_routing(uctx_opt);
        if info_out != 0 {
            // Build the 128-byte siginfo_t in kernel memory, then copy it
            // out through the SMAP bracket. si_signo/si_errno/si_code are
            // the union-discriminating prefix; si_pid (offset 16) + si_value
            // (the sigval union, offset 24) carry the queued sender payload
            // (stress-ng --sigrt's child replies to si_pid). Rest stays zero.
            let mut si = [0u8; 128];
            let (si_code, si_value, si_pid) = queued.unwrap_or((0, 0, 0)); // SI_USER shape
            si[..4].copy_from_slice(&(signum as i32).to_ne_bytes()); // si_signo
            si[8..12].copy_from_slice(&si_code.to_ne_bytes()); // si_code
            si[16..20].copy_from_slice(&si_pid.to_ne_bytes()); // si_pid
            si[24..32].copy_from_slice(&si_value.to_ne_bytes()); // si_value
                                                                 // SAFETY: info_out != 0; copy_to_user range-validates + SMAP-brackets.
            let _ = unsafe { copy_to_user(info_out, &si) };
        }
        ctx.set_return(SyscallReturn::ok(signum as u64));
        return;
    }

    // A deliverable signal OUTSIDE `set` interrupts the wait: return
    // -EINTR and let the return-to-user hook run its handler (Linux
    // rt_sigtimedwait(2) — never auto-restarted, see
    // `is_restartable_syscall`).
    if (signal_pending_of(task) & !signal_mask_of(task) & !set) != 0 {
        clear_routing(uctx_opt);
        ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
        return;
    }

    // A prior park was interrupted by an out-of-set signal that has ALREADY
    // been delivered (its handler ran on the resume's return-to-user, so
    // the pending check above reads 0). The delivery path flagged it —
    // honour the -EINTR now instead of re-parking forever. This is the
    // stress-ng --sigrt fix: SIGALRM breaks the sigwaitinfo loop.
    if let Some(u) = uctx_opt {
        // SAFETY: the in-flight task's poller-pinned UserTaskCtx; atomics only.
        if unsafe { (*u).sigwait_interrupted.load(Ordering::Acquire) } {
            clear_routing(uctx_opt);
            ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
            return;
        }
    }

    // Timeout. NULL → block indefinitely (u64::MAX park). A finite
    // timespec maps to an absolute wheel deadline persisted in
    // `blocking_deadline_ns` — the RIP-rewind re-executions must detect
    // expiry instead of re-arming now+timeout forever (the scheduler
    // clears `sleep_deadline_ns` on every wake; see poll/epoll).
    let mut deadline = u64::MAX;
    if timeout_in != 0 {
        let mut ts = [0u8; 16];
        // SAFETY: timeout_in != 0; copy_from_user range-validates and
        // SMAP-brackets the 16-byte timespec read.
        if unsafe { copy_from_user(&mut ts, timeout_in) }.is_err() {
            clear_routing(uctx_opt);
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        let sec = i64::from_ne_bytes(ts[..8].try_into().unwrap());
        let nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap());
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            clear_routing(uctx_opt);
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
        let dur_ns = (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec as u64);
        if dur_ns == 0 {
            // {0,0} = pure poll; nothing was pending above.
            clear_routing(uctx_opt);
            ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
            return;
        }
        if let Some(u) = uctx_opt {
            // SAFETY: as in clear_routing — atomics on the live uctx.
            let persisted = unsafe { (*u).blocking_deadline_ns.load(Ordering::Acquire) };
            deadline = if persisted != 0 {
                persisted
            } else {
                let d = narf_scheduler::narf_time::monotonic_ns().saturating_add(dur_ns);
                // SAFETY: as above.
                unsafe { (*u).blocking_deadline_ns.store(d, Ordering::Release) };
                d
            };
            if narf_scheduler::narf_time::monotonic_ns() >= deadline {
                clear_routing(uctx_opt);
                ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
                return;
            }
        }
    }

    // Park until a signal (or the deadline). Same shape as the blocking
    // F_SETLKW: rewind RIP over the 2-byte syscall so the WHOLE
    // rt_sigtimedwait re-executes on wake and re-runs the consume above.
    if let (Some(uctx), Some(hook)) = (uctx_opt, crate::user_task::yield_hook()) {
        ctx.set_rip(ctx.rip().wrapping_sub(2));
        // SAFETY: `uctx` is the live per-task UserTaskCtx from
        // current_user_task(); we hold the only reference while setting the
        // park routing and saving the RIP-rewound CPU state before the
        // yield hook / own-stack switch hands the task over.
        unsafe {
            let uc = &*uctx;
            // Clear stale routings so the park can't mis-register on the
            // futex / flock / io queues (same guard as the F_SETLKW park).
            uc.futex_uaddr.store(0, Ordering::Release);
            uc.flock_key.store(0, core::sync::atomic::Ordering::Release);
            uc.net_io_wait.store(false, Ordering::Release);
            uc.sigwait_set.store(set, Ordering::Release);
            uc.sleep_deadline_ns.store(deadline, Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable when parked
    }

    // No executor wired (the in-kernel test harness): there is nothing to
    // park on — degrade to the historical one-shot -1 answer the ABI
    // tests pin, exactly like pause's no-executor tail.
    clear_routing(uctx_opt);
    ctx.set_return(SyscallReturn::ok((-1i64) as u64));
}
