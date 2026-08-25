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

    // DIAG (syscall-trace): dump stdout/stderr content for trace-target
    // processes and the dbus-broker family. A daemon's byte-count alone does
    // not explain WHY it fails; dbus-broker prints its fatal error to stderr
    // right before exit(1), and that exit takes the whole session bus down.
    #[cfg(feature = "syscall-trace")]
    if fd == 1 || fd == 2 {
        let comm = crate::handlers::proc_comm_of_task(task).unwrap_or_default();
        if crate::syscall::syscall_trace_target_task() || comm.starts_with("dbus-broker") {
            use core::fmt::Write as _;
            let _ = write!(narf_console::Writer, "STDIO t={task} comm={comm} fd={fd}: ");
            for &b in kbuf.iter().take(240) {
                let c = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                };
                let _ = write!(narf_console::Writer, "{c}");
            }
            let _ = writeln!(narf_console::Writer);
        }
    }

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
    enum WriteError {
        BrokenPipe,
        NoSpace,
        QuotaExceeded,
        /// Descriptor's open mode forbids writing (a pipe read end):
        /// -EBADF, per the FMODE_WRITE check in `fs/read_write.c::vfs_write`.
        BadFd,
        Other,
    }
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
            Err(narf_filesystem::FsError::BrokenPipe) => Err(WriteError::BrokenPipe),
            Err(narf_filesystem::FsError::NoSpace) => Err(WriteError::NoSpace),
            Err(narf_filesystem::FsError::QuotaExceeded) => Err(WriteError::QuotaExceeded),
            Err(narf_filesystem::FsError::BadFd) => Err(WriteError::BadFd),
            Err(_) => Err(WriteError::Other),
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
            // Arm the descriptor's durable readiness before parking so a
            // pipe/FIFO drain wakes this writer without a global waiter scan.
            if park_reexecute_on_fd(
                ctx,
                ops.as_ref(),
                narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
            ) {
                return;
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
        Some(Err(WriteError::BrokenPipe)) => {
            raise_signal_pending(task, 13); // SIGPIPE
            ctx.set_return(SyscallReturn::ok((-32i64) as u64)); // -EPIPE
        }
        Some(Err(WriteError::NoSpace)) => {
            ctx.set_return(SyscallReturn::ok((-28i64) as u64)); // -ENOSPC
        }
        Some(Err(WriteError::QuotaExceeded)) => {
            ctx.set_return(SyscallReturn::ok((-122i64) as u64)); // -EDQUOT
        }
        // Wrong-direction descriptor (writing a pipe read end) → -EBADF;
        // no SIGPIPE — Linux never reaches the pipe op for these.
        Some(Err(WriteError::BadFd)) => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        }
        // TODO(linux-gap): bad fd should be -EBADF, but this `_` also catches
        // write rejections (e.g. sealed memfd → -EPERM) — needs a split.
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
