#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_write(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Copy the user buffer into a kernel-owned allocation first so
    // FileOps::write never touches a user page directly — SMAP would
    // fault any kernel-mode dereference of a user-accessible page
    // outside an explicit STAC/CLAC window.
    // Validate length *before* allocating so an oversized len returns
    // EINVAL rather than OOMing the kernel heap.
    // SAFETY: single-threaded syscall; AS is still active.
    let kbuf = match unsafe { copy_from_user_vec(ptr, len) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };

    let task = current_task_id();

    // Job control: a background process writing its controlling tty with
    // TOSTOP set is stopped (SIGTTOU) before the write happens.
    #[cfg(feature = "linux-compat")]
    if let Some(ret) = tty_background_access(task, fd, true) {
        ctx.set_return(SyscallReturn::ok(ret as u64));
        return;
    }

    // EBADF: fd not open. Checked before the general write path so a
    // closed/bad fd is distinct from a write rejection (e.g. sealed memfd),
    // which stays in the `_` → InvalidOp arm. Special fds returned above.
    if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    // Snapshot ops + offset and drop the fd-table lock before calling into
    // FileOps — same rule as `sys_read`: a write whose FileOps consults the
    // fd table would otherwise re-enter the non-reentrant table lock and
    // spin forever with interrupts masked.
    let snapshot = fd::with_table(task, |t| {
        let e = t.get(fd)?;
        Some((e.ops.clone(), e.offset, e.status_flags))
    });
    let (ops, off, status_flags) = match snapshot {
        Some(Some(v)) => v,
        _ => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    let nonblock = status_flags & crate::fd::O_NONBLOCK != 0;
    // Closure error channel: `Err(true)` ⇒ broken pipe (raise SIGPIPE +
    // return -EPIPE), `Err(false)` ⇒ generic write failure / bad fd.
    let outcome = Some({
        let res =
            poll_blocking(ops.write(off, &kbuf)).unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(written) => {
                let _ = fd::with_table(task, |t| {
                    if let Some(e) = t.get_mut(fd) {
                        e.offset = off.saturating_add(written as u64);
                    }
                });
                Ok(written)
            }
            // A write to a FIFO / pipe with no remaining readers: SIGPIPE + EPIPE.
            Err(narf_filesystem::FsError::BrokenPipe) => Err(true),
            Err(_) => Err(false),
        }
    });
    // A write that made no progress on a full pipe (reader still open) must
    // BLOCK, not hand userspace a spurious 0. O_NONBLOCK → -EAGAIN; blocking →
    // park ~1ms and RE-EXECUTE (mirrors the empty-pipe read block).
    if let Some(Ok(0)) = outcome {
        if ops.write_should_block() {
            if nonblock {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                return;
            }
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                // Rewind past the 2-byte `syscall`/`int 0x80` so re-entry re-runs
                // this write with its original args.
                let resume_rip = ctx.rip().wrapping_sub(2);
                ctx.set_rip(resume_rip);
                // SAFETY: `uctx` is the live per-task UserTaskCtx; we hold the
                // only reference while setting the park deadline + saving the
                // RIP-rewound state before the yield hook hands off the task.
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns
                        .store(dl, core::sync::atomic::Ordering::Release);
                    uc.futex_uaddr
                        .store(0, core::sync::atomic::Ordering::Release);
                    uc.net_io_wait
                        .store(true, core::sync::atomic::Ordering::Release);
                    uc.epoll_park_gen.store(
                        narf_net::readiness::generation(),
                        core::sync::atomic::Ordering::Release,
                    );
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    if narf_scheduler::stackful::user_own_stack_enabled() {
                        own_stack_block(ctx);
                        return;
                    }
                    hook(uctx);
                }
                // unreachable — hook() longjmps to the executor
            }
            // No executor (kernel-test context): fall back to a 0-byte write.
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
    }
    match outcome {
        Some(Ok(n)) => {
            // inotify: a successful write is IN_MODIFY on the fd's file.
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_modify_fd(task, fd);
            ctx.set_return(SyscallReturn::ok(n as u64));
        }
        // Broken pipe: POSIX raises SIGPIPE on the writer (default action
        // terminates unless it's caught/ignored) AND the write returns -EPIPE.
        Some(Err(true)) => {
            raise_signal_pending(task, 13); // SIGPIPE
            ctx.set_return(SyscallReturn::ok((-32i64) as u64)); // -EPIPE
        }
        // TODO(linux-gap): bad fd should be -EBADF, but this `_` also catches
        // write rejections (e.g. sealed memfd → -EPERM) — needs a split.
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
