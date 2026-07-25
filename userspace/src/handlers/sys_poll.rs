#[allow(unused_imports)]
use super::*;

/// poll(2) entry: walk a user-supplied array of pollfd, OR each
/// fd's poll_readiness against the requested events, write revents,
/// return number of ready fds. Yield + re-poll on no-progress
/// when timeout != 0.
pub(crate) fn sys_poll(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pollfds_ptr = args.arg0;
    let n = args.arg1 as usize;
    let timeout_ms = args.arg2 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if n > 1024 {
        ctx.set_return(fail);
        return;
    }
    if n == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if pollfds_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // Each pollfd is [fd: i32 (4 B), events: i16 (2 B), revents: i16 (2 B)] = 8 B.
    const PF_LEN: usize = 8;
    let total = n * PF_LEN;
    // Pull the user buffer into a kernel scratch under SMAP bracket.
    let mut user_buf = alloc::vec![0u8; total];
    // SAFETY: pollfds_ptr is a user VA; AS active; SMAP bracket inside.
    if unsafe { copy_from_user(&mut user_buf, pollfds_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    // Absolute timeout deadline. `sys_poll` parks in ~1ms chunks and
    // RE-EXECUTES the whole syscall on each wake, so the deadline must be
    // PERSISTED across re-executions — recomputing `now + timeout_ms` every
    // chunk would push the deadline 1ms into the future forever and a
    // pure-timeout poll (nothing ever ready) would never expire. Stash it in
    // `blocking_deadline_ns` (which the scheduler never clears) on the first
    // entry and reuse it thereafter; cleared on every return below.
    let deadline_ns = if timeout_ms < 0 {
        None
    } else if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: `uctx` is the live per-task UserTaskCtx for this trap.
        let persisted = unsafe { (*uctx).blocking_deadline_ns.load(Ordering::Acquire) };
        let d = if persisted != 0 {
            persisted
        } else {
            let d = narf_scheduler::narf_time::monotonic_ns()
                .saturating_add((timeout_ms as u64).saturating_mul(1_000_000));
            // Only a finite, non-zero timeout needs to survive re-execution; a
            // `timeout_ms == 0` poll returns immediately below before parking.
            if timeout_ms > 0 {
                // SAFETY: as above.
                unsafe { (*uctx).blocking_deadline_ns.store(d, Ordering::Release) };
            }
            d
        };
        Some(d)
    } else {
        let now = narf_scheduler::narf_time::monotonic_ns();
        Some(now.saturating_add((timeout_ms as u64).saturating_mul(1_000_000)))
    };
    loop {
        let mut ready = 0u64;
        for i in 0..n {
            let off = i * PF_LEN;
            let fd_raw = i32::from_le_bytes([
                user_buf[off],
                user_buf[off + 1],
                user_buf[off + 2],
                user_buf[off + 3],
            ]);
            let events = u16::from_le_bytes([user_buf[off + 4], user_buf[off + 5]]) as u32;
            let revents = if fd_raw < 0 {
                0
            } else {
                let fd = fd_raw as u32;
                // Clone the FileOps out from under the fd-table lock before
                // polling: a nested-epoll fd's poll_readiness re-enters
                // `fd::with_table`, which would deadlock the non-reentrant
                // fd-table lock if held across the call (see epoll.rs
                // `poll_fd_readiness`).
                let file = fd::with_table(task, |t| t.get(fd).map(|e| (e.ops.clone(), e.offset)))
                    .flatten();
                match file.map(|(o, offset)| o.poll_readiness_at(offset)) {
                    Some(r) => (r & events) as u16,
                    None => narf_filesystem::POLL_NVAL as u16,
                }
            };
            user_buf[off + 6..off + 8].copy_from_slice(&revents.to_le_bytes());
            if revents != 0 {
                ready += 1;
            }
        }
        if ready > 0 || timeout_ms == 0 {
            // Copy revents back to user under SMAP bracket.
            // SAFETY: pollfds_ptr validated above; AS active.
            let _ = unsafe { copy_to_user(pollfds_ptr, &user_buf) };
            if let Some(uctx) = crate::user_task::current_user_task() {
                // SAFETY: live per-task ctx; clear the in-flight poll deadline.
                unsafe { (*uctx).blocking_deadline_ns.store(0, Ordering::Release) };
            }
            ctx.set_return(SyscallReturn::ok(ready));
            return;
        }
        if let Some(deadline) = deadline_ns {
            let now = narf_scheduler::narf_time::monotonic_ns();
            if now >= deadline {
                // Timeout — write back zero revents and return 0.
                // SAFETY: `pollfds_ptr` was validated earlier in this handler and the
                // AS is still active; copy_to_user re-validates and SMAP-brackets the write.
                // SAFETY: Valid memory or trusted environment
                let _ = unsafe { copy_to_user(pollfds_ptr, &user_buf) };
                if let Some(uctx) = crate::user_task::current_user_task() {
                    // SAFETY: live per-task ctx; clear the in-flight poll deadline.
                    unsafe { (*uctx).blocking_deadline_ns.store(0, Ordering::Release) };
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        }
        // Yield ~1ms, then re-walk.
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            // Stash partial revents back to user; the longjmp
            // doesn't return through us so they'd be lost.
            // BUT we're going to loop, not exit — only write back
            // after the loop finds something ready or times out.
            // No-op write; real write happens on the success path.
            ctx.set_return(SyscallReturn::ok(0));
            let park = 1_000_000u64;
            let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(park);
            // SAFETY: `uctx` is the live per-task UserTaskCtx from current_user_task();
            // we hold the only reference while setting the deadline and saving CPU state
            // into `uc.state` before the yield hook hands the task to the executor.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                let uc = &*uctx;
                uc.sleep_deadline_ns.store(dl, Ordering::Release);
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
        // Test fallback: just spin briefly.
        let chunk_end = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
        while narf_scheduler::narf_time::monotonic_ns() < chunk_end {
            sleep_pumps::run();
            core::hint::spin_loop();
        }
    }
}
