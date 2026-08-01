#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_read(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Validate the destination pointer before allocating the kernel
    // staging buffer — EFAULT early rather than after the FileOps call.
    if let Err(e) = validate_user_range(ptr, len) {
        ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
        return;
    }
    // Job control: a background process reading its controlling tty is
    // stopped (SIGTTIN) before the read runs — and before it is recorded
    // as the foreground reader below.
    #[cfg(feature = "linux-compat")]
    if let Some(ret) = tty_background_access(current_task_id(), fd, false) {
        ctx.set_return(SyscallReturn::ok(ret as u64));
        return;
    }
    // Track the foreground task: any read syscall counts as "this
    // task is currently consuming console input." When the input
    // ring later observes ^C, this is the task SIGINT goes to.
    note_console_reader(current_task_id());

    // Read into a kernel-owned staging buffer, then copy back with the SMAP
    // bracket (FileOps never touches user memory). A read() completes in this
    // frame — `poll_blocking` busy-polls in place and FileOps futures are
    // heap-boxed, so the kernel stack stays shallow — so the common small read
    // can stage through a stack buffer and skip a heap alloc+zero on every
    // call. That per-read churn (slab alloc/free + zero-fill + per-CPU RDTSCP,
    // ×thousands of small sysfs reads) is what made udev coldplug crawl.
    const READ_STACK_BUF: usize = 4096;
    let mut stack_buf = [0u8; READ_STACK_BUF];
    // Deferred init (no throwaway `Vec::new()` to satisfy -D unused-assignments):
    // the heap buffer is only assigned — and only borrowed — on the large-read
    // branch; small reads never touch it.
    let mut heap_buf: alloc::vec::Vec<u8>;
    let kbuf: &mut [u8] = if len <= READ_STACK_BUF {
        &mut stack_buf[..len]
    } else {
        heap_buf = alloc::vec![0u8; len];
        heap_buf.as_mut_slice()
    };
    let task = current_task_id();

    // fanotify groups deliver fixed-size metadata records, each carrying a
    // freshly-opened fd to the affected object. Installing that fd needs
    // the fd-table lock — which the `with_table` block below holds across
    // ops.read — so fanotify reads are handled here, before any lock is
    // taken, to avoid a re-entrant deadlock.
    #[cfg(feature = "linux-compat")]
    if crate::mqueue::fanotify_active() {
        if let Some(gid) = crate::mqueue::fanotify_instance_of(task, fd) {
            let n = fanotify_read_into(task, gid, &mut kbuf[..]);
            // SAFETY: ptr validated above; AS still active.
            match unsafe { copy_to_user(ptr, &kbuf[..n]) } {
                Ok(()) => ctx.set_return(SyscallReturn::ok(n as u64)),
                Err(e) => ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64)),
            }
            return;
        }
    }

    // EBADF: fd not open. Checked before the general read path so a
    // closed/bad fd is distinct from a read I/O error (which keeps the
    // `_` → InvalidOp arm). Special fds (console/fanotify) returned above.
    if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    // Snapshot the fd's ops + offset, then DROP the fd-table lock before
    // calling into FileOps.
    //
    // Holding it across `ops.read` self-deadlocks on any file whose read
    // consults the fd table: `/proc/<pid>/fdinfo/<n>` and `/proc/<pid>/fd/<n>`
    // render via `fd_path_of`, which re-enters `fd::with_table` on the SAME
    // task's table — and the table lock is a non-reentrant IrqSafeSpinLock,
    // so the CPU spins forever with interrupts masked. dbus-daemon does
    // exactly this (`pidfd_open` then read `/proc/self/fdinfo/<n>`), which
    // wedged the session bus and with it every KDE Plasma startup. Same
    // lesson as the nested-epoll fix: never call FileOps under the fd-table
    // lock.
    //
    // The offset is re-taken and advanced after the read. Two threads
    // sharing one fd can now interleave there; Linux serialises that case
    // with f_pos_lock, which NARF doesn't model yet.
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
    let advance = |n: usize| {
        let _ = fd::with_table(task, |t| {
            if let Some(e) = t.get_mut(fd) {
                e.offset = off.saturating_add(n as u64);
            }
        });
    };
    // Closure error channel: `Err(true)` ⇒ return EAGAIN, `Err(false)` ⇒
    // invalid-op sentinel (bad fd / read error).
    let outcome = Some((|| {
        let entry = &ops;
        let nonblock = status_flags & crate::fd::O_NONBLOCK != 0;
        // evdev device nodes (`nonblock_read_eagain`) provide EAGAIN-on-empty
        // semantics UNCONDITIONALLY — independent of the fd's O_NONBLOCK bit.
        //
        // Why not gate on `nonblock`: libinput/libevdev consume evdev nodes with
        // a drain-to-EAGAIN loop and are structurally incompatible with a
        // BLOCKING evdev fd (the sync loop never terminates; the post-epoll read
        // must not stall the single-threaded dispatch). Their fds SHOULD be
        // O_NONBLOCK, but when weston opens an input device through libseat/seatd
        // the fd arrives over SCM_RIGHTS, and NARF installs received fds with
        // status_flags = 0 (O_NONBLOCK is dropped — it lives per-FdEntry, not on
        // the shared FileOps). The old `nonblock &&` gate then sent that fd down
        // the `poll_blocking` path, which busy-spins the empty-ring read future
        // ~4M times and finally returns Err(ReadOnly) → read() reports EIO →
        // libinput treats the read error as device-removal and `EPOLL_CTL_DEL`s
        // the device, so the pointer goes dead. Surfacing EAGAIN here (what an
        // evdev node is *for*) fixes that and matches how these devices are used.
        if entry.nonblock_read_eagain() {
            return match poll_once(entry.read(off, &mut kbuf[..])) {
                Some(Ok(n)) if n > 0 => {
                    advance(n);
                    Ok((n, false, false))
                }
                // Empty / would-block ⇒ EAGAIN.
                Some(Ok(_)) | None => Err(true),
                Some(Err(_)) => Err(false),
            };
        }
        let res = poll_blocking(entry.read(off, &mut kbuf[..]))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(n) => {
                // A NON-BLOCKING read that finds an empty-but-open stream
                // (socket/pipe) must report EAGAIN, not a bare 0 — the caller
                // would mis-read that 0 as EOF. `read_should_block()` is true
                // exactly when the stream is open-but-empty (a real peer-close
                // makes it false, so a genuine EOF still returns 0). GLib's
                // GSocket/GDBus runs its own poll loop over O_NONBLOCK fds and
                // treats `read()==0` as a peer hangup; the spurious EOF during
                // the dbus EXTERNAL auth line-read ("Unexpected lack of content
                // trying to read a line") killed the KDE session bus. musl's
                // stdio/recv wrappers likewise expect EAGAIN, never a phantom 0.
                if n == 0 && nonblock && entry.read_should_block() {
                    return Err(true); // EAGAIN
                }
                // Block decision: a 0-byte read on a pipe/socket whose writer is
                // still open must wait for data (POSIX), not return a
                // spurious EOF — unless the fd is O_NONBLOCK (handled above).
                let should_block = n == 0 && !nonblock && entry.read_should_block();
                // Console fds park on the input waker (serial/keyboard IRQ)
                // instead of the 1ms re-poll, so an interactive shell truly
                // sleeps on `read(stdin)` rather than busy-polling.
                let input_block = n == 0 && !nonblock && entry.block_on_input();
                advance(n);
                Ok((n, should_block, input_block))
            }
            Err(_) => Err(false),
        }
    })());
    match outcome {
        Some(Ok((0, _, true))) => {
            // Empty console input ring: park on the input waker (woken by
            // the serial/keyboard IRQ via push_global → BYTE_RING_WAKER →
            // deferred_wake) and RE-EXECUTE the read on resume (rewind RIP,
            // no return value). The poll routine registers cx.waker() once
            // `console_read_pending` is set and parks with NO wake-by-ref,
            // so the task truly idles until a keystroke — no busy-poll.
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                let resume_rip = ctx.rip().wrapping_sub(2);
                ctx.set_rip(resume_rip);
                // SAFETY: `uctx` is the live per-task UserTaskCtx from
                // current_user_task(); we hold the only reference while
                // setting the flag + saving the RIP-rewound CPU state before
                // the yield hook hands the task to the executor.
                unsafe {
                    let uc = &*uctx;
                    uc.console_read_pending
                        .store(true, core::sync::atomic::Ordering::Release);
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
            // No executor (kernel-test context): fall back to a 0 read.
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Ok((0, true, _))) => {
            // Empty pipe, writer still open: park ~1ms and RE-EXECUTE the
            // read on resume (rewind RIP, leave the syscall number in
            // place — do NOT set a return value) so the read blocks until
            // data arrives or the last writer closes (which now happens
            // via fd::detach on the writer's exit), rather than handing
            // userspace a 0 it would mis-read as end-of-file.
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                // Rewind past the 2-byte `syscall`/`int 0x80` instruction so
                // re-entry re-runs this syscall with its original args.
                let resume_rip = ctx.rip().wrapping_sub(2);
                ctx.set_rip(resume_rip);
                // SAFETY: `uctx` is the live per-task UserTaskCtx from
                // current_user_task(); we hold the only reference while
                // setting the deadline + saving the (RIP-rewound) CPU state
                // before the yield hook hands the task to the executor.
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns
                        .store(dl, core::sync::atomic::Ordering::Release);
                    // Park on NET-I/O READINESS so a peer's `write` → `notify(0)`
                    // wakes this blocking `read()` PROMPTLY, with the ~1ms
                    // deadline as a mere backstop — mirroring `recv`/`accept`.
                    // Without net_io_wait a blocking POSIX `read()` on an empty
                    // AF_UNIX socket only re-polled off the 1ms timer wheel (no
                    // io-waiter, no lost-wake gen guard), so under own-stack
                    // cooperative scheduling with other busy tasks the reply sat
                    // unread past the client's deadline — a real asymmetry vs
                    // `recv`, and a likely cause of flaky D-Bus round-trips (Qt/
                    // libdbus read the bus socket via read()). Snapshot the
                    // readiness generation for the check→park lost-wake guard;
                    // clear a stale futex_uaddr so this can't mis-route into the
                    // futex branch. Harmless for pipes (no notify → the 1ms
                    // backstop still fires exactly as before).
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
            // No executor (kernel-test context): fall back to a 0 read.
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Ok((n, _, _))) => {
            // SAFETY: ptr validated above; AS still active.
            if let Err(e) = unsafe { copy_to_user(ptr, &kbuf[..n]) } {
                ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
        }
        // Non-blocking read with nothing ready → EAGAIN (errno 11).
        Some(Err(true)) => {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        }
        // TODO(linux-gap): bad fd should be -EBADF, but this `_` also
        // catches read I/O errors — needs surgical bad-fd-vs-error split.
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
