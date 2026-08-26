#[allow(unused_imports)]
use super::*;

/// `flock(fd, operation)` — `fs/locks.c::SYSCALL_DEFINE2(flock)`:
///
/// ```text
///   if (cmd & LOCK_MAND) return 0;                  /* removed in 5.15 */
///   type = flock_translate_cmd(cmd & ~LOCK_NB);
///   if (type < 0) return type;                      /* -EINVAL */
///   f = fdget(fd); if (fd_empty(f)) return -EBADF;
///   ... locks_lock_file_wait() -> -EWOULDBLOCK when LOCK_NB conflicts
/// ```
///
/// The `-1` sentinel used to cover all three, so the canonical single-instance
/// idiom — `flock(lockfd, LOCK_EX | LOCK_NB)` and treat EWOULDBLOCK as
/// "another copy is already running" — saw EPERM and aborted instead.
pub(crate) fn sys_flock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let op = args.arg1 as u32;
    // Conflict under LOCK_NB is EWOULDBLOCK, which on Linux is EAGAIN(11).
    let would_block = SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64);
    let task = current_task_id();
    // LOCK_MAND lost its meaning in 5.15; the syscall now warns once and
    // reports success without taking anything.
    const LOCK_MAND: u32 = 32;
    if op & LOCK_MAND != 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // `flock_translate_cmd(cmd & ~LOCK_NB)` runs BEFORE the fd lookup, so a
    // malformed operation outranks a closed descriptor: exactly one of
    // LOCK_SH / LOCK_EX / LOCK_UN, optionally OR'd with LOCK_NB.
    if !matches!(op & !LOCK_NB, LOCK_SH | LOCK_EX | LOCK_UN) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    let arc_ops = match arc_ops {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    let file_ptr = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let nonblock = op & LOCK_NB != 0;
    // The blocking path retries by parking via the yield hook and
    // re-executing the syscall on resume (a longjmp clippy can't see),
    // so every visible path through the body returns/diverges — hence
    // `never_loop`. The `loop` keeps the retry intent explicit.
    #[allow(clippy::never_loop)]
    loop {
        if flock_try(file_ptr, op, task).is_ok() {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        if nonblock {
            ctx.set_return(would_block);
            return;
        }
        // Yield ~1ms then retry. Same shape as sys_futex's wait
        // loop — the unlock side bumps the table; we just re-poll.
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            ctx.set_return(would_block);
            let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
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
        ctx.set_return(would_block);
        return;
    }
}
