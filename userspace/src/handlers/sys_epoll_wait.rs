#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_epoll_wait(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let events_out = args.arg1;
    let max = args.arg2 as usize;
    let timeout_ms = args.arg3 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let ep_arc = match epoll_arc_from_fd(task, epfd) {
        Some(e) => e,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let deadline_ns = if timeout_ms < 0 {
        None
    } else {
        let now = narf_scheduler::narf_time::monotonic_ns();
        Some(now.saturating_add((timeout_ms as u64).saturating_mul(1_000_000)))
    };
    loop {
        let snap = ep_arc.snapshot();
        let mut written = 0;
        for (fd, entry) in snap.iter() {
            if written >= max {
                break;
            }
            let fd_u = if *fd < 0 {
                continue;
            } else {
                *fd as u32
            };
            // Clone the FileOps out before polling so a nested-epoll fd can't
            // re-enter (and deadlock) the non-reentrant fd-table lock.
            let file =
                fd::with_table(task, |t| t.get(fd_u).map(|e| (e.ops.clone(), e.offset))).flatten();
            let readiness = file
                .map(|(o, offset)| o.poll_readiness_at(offset))
                .unwrap_or(0);
            let active = readiness & entry.events;
            if active != 0 {
                let off = (written * 12) as u64;
                let mut rec = [0u8; 12];
                rec[..4].copy_from_slice(&active.to_le_bytes());
                rec[4..].copy_from_slice(&entry.user_data.to_le_bytes());
                // SAFETY: `events_out + off` is the user epoll_event slot for this entry
                // (`written < max`); copy_to_user range-validates it and SMAP-brackets the
                // 12-byte write.
                // SAFETY: Valid memory or trusted environment
                if unsafe { copy_to_user(events_out + off, &rec) }.is_err() {
                    break;
                }
                written += 1;
            }
        }
        if written > 0 || timeout_ms == 0 {
            ctx.set_return(SyscallReturn::ok(written as u64));
            return;
        }
        if let Some(dl) = deadline_ns {
            if narf_scheduler::narf_time::monotonic_ns() >= dl {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        }
        // Park until a watched fd becomes ready (or a ~1ms backstop tick).
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
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
                // Park on NET-I/O READINESS, not just the ~1ms timer-wheel
                // backstop. A socket/pipe/eventfd transition fires
                // `readiness::notify`, which wakes a registered net-I/O waiter
                // PROMPTLY; without this an epoll_wait park re-polled only off
                // the wheel, and under own-stack cooperative scheduling with
                // other busy tasks (a heavy Wayland client like a Qt6 app) that
                // wheel service is delayed enough that the readable fd sits
                // unserviced for many hundreds of ms per hop — so a compositor
                // idle in epoll_wait(-1) took tens of seconds to serve a new
                // client's first request (weston never composited kcalc). The
                // accept/poll parks already do this; epoll_wait was the gap.
                // Snapshot the readiness generation for the check→park lost-wake
                // guard (park_should_block re-executes if it advanced). Clear a
                // stale futex_uaddr so this can't be mis-routed to the futex arm.
                uc.futex_uaddr.store(0, Ordering::Release);
                uc.net_io_wait.store(true, Ordering::Release);
                uc.epoll_park_gen
                    .store(narf_net::readiness::generation(), Ordering::Release);
                ctx.save_user_state(uc.state.get() as *mut u8);
                *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                if narf_scheduler::stackful::user_own_stack_enabled() {
                    own_stack_block(ctx);
                    return;
                }
                hook(uctx);
            }
        }
        let chunk_end = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
        while narf_scheduler::narf_time::monotonic_ns() < chunk_end {
            sleep_pumps::run();
            core::hint::spin_loop();
        }
    }
}
