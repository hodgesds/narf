#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
fn write_flock_to_user(ptr: u64, flock: &UFlock) -> Result<(), ()> {
    let mut bytes = alloc::vec![0u8; flock_size()];
    // SAFETY: `UFlock` is repr(C) and `bytes` has the architecture's
    // exported flock size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            flock as *const _ as *const u8,
            bytes.as_mut_ptr(),
            flock_size(),
        );
    }
    // SAFETY: the syscall supplied `ptr`; copy_to_user validates the range.
    unsafe { copy_to_user(ptr, &bytes) }.map_err(|_| ())
}

pub(crate) fn sys_fcntl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1;
    let arg = args.arg2;
    let task = current_task_id();

    // F_SETFL on a socket: mirror O_NONBLOCK into the SocketFile so
    // recv/send/accept/connect see the flag.
    if cmd == F_SETFL {
        if let Some(sock) = current_socket(fd) {
            sock.set_nonblock((arg as u32) & crate::socket::O_NONBLOCK != 0);
        }
    }

    // F_DUPFD / F_DUPFD_CLOEXEC: dup oldfd into the lowest free slot
    // >= arg. Linux returns the new fd. CLOEXEC variant stamps
    // FD_CLOEXEC atomically.
    #[cfg(feature = "linux-compat")]
    {
        if cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC {
            let min_fd = arg as u32;
            let cloexec = cmd == F_DUPFD_CLOEXEC;
            let outcome = fd::with_table(task, |t| {
                let entry = t.get(fd)?;
                let clone = crate::fd::FdEntry {
                    ops: entry.ops.clone(),
                    offset: 0,
                    flags: if cloexec { crate::fd::FD_CLOEXEC } else { 0 },
                    status_flags: entry.status_flags,
                };
                Some(t.open_at_least(clone, min_fd))
            });
            match outcome {
                Some(Some(new_fd)) => ctx.set_return(SyscallReturn::ok(new_fd as u64)),
                // F_DUPFD on a fd that isn't open → -EBADF (was InvalidOp).
                _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
            }
            return;
        }
    }

    // F_GETLK / F_SETLK / F_SETLKW: advisory POSIX locking. Gated
    // under linux-compat because the wire `struct flock` layout +
    // BTreeMap lock table only matter for Linux ABI consumers.
    #[cfg(feature = "linux-compat")]
    {
        if cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW {
            // Resolve the open-file identity from the fd table.
            let ops_key = fd::with_table(task, |t| {
                t.get(fd).map(|e| {
                    (
                        e.ops.clone(),
                        alloc::sync::Arc::as_ptr(&e.ops) as *const () as usize,
                    )
                })
            });
            let (ops, key) = match ops_key {
                Some(Some(v)) => v,
                _ => {
                    ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                    return;
                }
            };
            // Pull the `struct flock` from user memory.
            let mut bytes = alloc::vec![0u8; flock_size()];
            // SAFETY: `arg` is the user `struct flock` pointer; copy_from_user
            // range-validates it and SMAP-brackets the read into the sized `bytes`.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_from_user(&mut bytes, arg) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                return;
            }
            // SAFETY: `bytes` holds exactly `flock_size()` validated bytes and
            // `tmp` is a default-initialized UFlock with at least that many bytes;
            // the copy reinterprets the wire layout into the repr(C) struct.
            // SAFETY: Valid memory or trusted environment
            let uf: UFlock = unsafe {
                let mut tmp = UFlock::default();
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    &mut tmp as *mut _ as *mut u8,
                    flock_size(),
                );
                tmp
            };
            // Only SEEK_SET (l_whence = 0) is supported on the wire
            // path. Other whence values would need the current offset
            // / file size, which is OFD-tier work.
            if uf.l_whence != 0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let req = crate::fd::locks::Lock {
                owner: task,
                ty: uf.l_type,
                start: uf.l_start,
                len: uf.l_len,
            };
            let (lock_start, end) = if uf.l_len == 0 {
                (uf.l_start, u64::MAX)
            } else if uf.l_len > 0 {
                (
                    uf.l_start,
                    (uf.l_start as u64).saturating_add(uf.l_len as u64 - 1),
                )
            } else {
                (
                    uf.l_start.saturating_add(uf.l_len),
                    (uf.l_start as u64).saturating_sub(1),
                )
            };
            if lock_start < 0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let native = narf_filesystem::FileLock {
                start: lock_start as u64,
                end,
                type_: uf.l_type as u32,
                pid: task as u32,
            };
            if cmd == F_GETLK {
                match poll_blocking(ops.get_lock(task, native)) {
                    Some(Ok(lock)) => {
                        let mut out = uf;
                        out.l_type = lock.type_ as i16;
                        out.l_start = lock.start as i64;
                        out.l_len = if lock.end == u64::MAX {
                            0
                        } else {
                            lock.end.saturating_sub(lock.start).saturating_add(1) as i64
                        };
                        out.l_pid = lock.pid as i32;
                        if write_flock_to_user(arg, &out).is_err() {
                            ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                        } else {
                            ctx.set_return(SyscallReturn::ok(0));
                        }
                        return;
                    }
                    Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
                    _ => {
                        ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                        return;
                    }
                }
                let blocker = crate::fd::locks::probe(key, req);
                let mut out = uf;
                match blocker {
                    None => out.l_type = crate::fd::locks::F_UNLCK,
                    Some(b) => {
                        out.l_type = b.ty;
                        out.l_start = b.start;
                        out.l_len = b.len;
                        out.l_pid = b.owner as i32;
                    }
                }
                if write_flock_to_user(arg, &out).is_err() {
                    ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                    return;
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            // F_SETLK / F_SETLKW.
            match poll_blocking(ops.set_lock(task, native, cmd == F_SETLKW)) {
                Some(Ok(())) => {
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
                Some(Err(narf_filesystem::FsError::Busy)) => {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                _ => {
                    ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                    return;
                }
            }
            match crate::fd::locks::try_set(key, req) {
                Ok(()) => {
                    // A re-executed SETLKW arrives here with the uctx
                    // routing still set — clear it so a later unrelated
                    // park can't spuriously register on the flock queue.
                    clear_flock_routing();
                    if uf.l_type == crate::fd::locks::F_UNLCK {
                        // A range was released — wake every parked
                        // F_SETLKW waiter on this file so it retries NOW
                        // instead of riding out its 1 ms backstop. Fired
                        // after the waiter lock drops (drain collects).
                        for (tid, w) in crate::fd::locks::drain_waiters(key) {
                            wake_one(tid, w);
                        }
                    } else {
                        // Acquire (possibly a re-executed SETLKW that just
                        // won): retire any waiter entry left from the park.
                        crate::fd::locks::drop_waiter(key, task);
                    }
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Err(_) if cmd == F_SETLKW => {
                    // Blocking acquire. Linux F_SETLKW is signal-
                    // interruptible (EINTR) — check before parking so a
                    // pending signal breaks the wait instead of being
                    // starved by the retry loop.
                    if is_signal_pending(task) {
                        crate::fd::locks::drop_waiter(key, task);
                        clear_flock_routing();
                        ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
                        return;
                    }
                    // Park ~1ms with RIP rewound so the WHOLE fcntl
                    // re-executes on resume and retries try_set — the
                    // same re-execute shape as the blocking console
                    // read; the holder's unlock (or exit — see
                    // `locks::release_owner` in the exit sweep) makes a
                    // later retry succeed. No executor wired (the
                    // kernel-test harness) → degrade to the
                    // non-blocking EAGAIN answer, like flock's
                    // no-executor tail.
                    if let (Some(uctx), Some(hook)) = (
                        crate::user_task::current_user_task(),
                        crate::user_task::yield_hook(),
                    ) {
                        let resume_rip = ctx.rip().wrapping_sub(2);
                        ctx.set_rip(resume_rip);
                        let dl =
                            narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                        // SAFETY: `uctx` is the live per-task UserTaskCtx from
                        // current_user_task(); we hold the only reference while
                        // setting the deadline and saving the RIP-rewound CPU
                        // state before the yield hook hands the task over.
                        // SAFETY: Valid memory or trusted environment
                        unsafe {
                            let uc = &*uctx;
                            // Clear a stale futex_uaddr so the park can't
                            // mis-route into the futex branch (same guard
                            // as the blocking pipe-read park).
                            uc.futex_uaddr
                                .store(0, core::sync::atomic::Ordering::Release);
                            // Route the park to the lock key's waiter queue
                            // (park_should_block registers the waker there),
                            // so the holder's unlock wakes us immediately.
                            uc.flock_key
                                .store(key, core::sync::atomic::Ordering::Release);
                            uc.sleep_deadline_ns
                                .store(dl, core::sync::atomic::Ordering::Release);
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
                    crate::fd::locks::drop_waiter(key, task);
                    clear_flock_routing();
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                }
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                }
            }
            return;
        }
    }

    // Wave-70: memfd seals. Route F_ADD_SEALS / F_GET_SEALS before
    // the generic fd-table lookup so the seal word lives on the
    // concrete MemFdFile rather than as a per-fd flag.
    #[cfg(feature = "linux-compat")]
    {
        if cmd == F_ADD_SEALS {
            if let Some(mfd) = memfd_arc_from_fd(task, fd) {
                let r = match mfd.add_seals(arg as u32) {
                    Ok(()) => SyscallReturn::ok(0),
                    Err(()) => SyscallReturn::ok((-1i64) as u64),
                };
                ctx.set_return(r);
                return;
            }
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        if cmd == F_GET_SEALS {
            if let Some(mfd) = memfd_arc_from_fd(task, fd) {
                ctx.set_return(SyscallReturn::ok(mfd.seals() as u64));
                return;
            }
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }

    // Resolve any socket-side flag BEFORE entering the fd-table
    // closure — `current_socket` itself locks the table, which would
    // re-enter and deadlock if called from inside `with_table`.
    let sock_nb = current_socket(fd).map(|s| s.is_nonblock());

    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd)?;
        Some(match cmd {
            F_GETFD => SyscallReturn::ok(entry.flags as u64),
            F_SETFD => {
                entry.flags = arg as u32;
                SyscallReturn::ok(0)
            }
            // F_GETFL: report the per-fd status_flags. Socket
            // O_NONBLOCK overrides the bit if the SocketFile carries
            // its own nonblock toggle (kept in sync via F_SETFL).
            F_GETFL => {
                let mut v = entry.status_flags as u64;
                if let Some(nb) = sock_nb {
                    if nb {
                        v |= crate::socket::O_NONBLOCK as u64;
                    } else {
                        v &= !(crate::socket::O_NONBLOCK as u64);
                    }
                }
                SyscallReturn::ok(v)
            }
            // F_SETFL: only the settable subset (O_NONBLOCK | O_APPEND
            // | O_DIRECT) is honoured. Access-mode bits are ignored.
            F_SETFL => {
                #[cfg(feature = "linux-compat")]
                let mask = crate::fd::O_SETFL_MASK;
                #[cfg(not(feature = "linux-compat"))]
                let mask = 0o4000u32; // O_NONBLOCK only.
                let new = (arg as u32) & mask;
                entry.status_flags = (entry.status_flags & !mask) | new;
                SyscallReturn::ok(0)
            }
            // F_GETPIPE_SZ (1032) / F_SETPIPE_SZ (1031): report the pipe buffer
            // capacity. NARF's pipe is a fixed-size ring, so F_SETPIPE_SZ can't
            // grow it — return the current capacity (Linux rounds the request
            // to a page/power-of-two anyway). EINVAL for a non-pipe fd, matching
            // Linux. stress-ng's pipe stressor queries F_GETPIPE_SZ to size its
            // I/O buffer; without this it fell back to a 4 KiB write + a stale
            // errno on the first full-pipe short write.
            1032 | 1031 => match entry.ops.pipe_capacity() {
                Some(cap) => SyscallReturn::ok(cap as u64),
                None => SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64),
            },
            _ => SyscallReturn::invalid_op(),
        })
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
