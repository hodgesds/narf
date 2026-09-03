#[allow(unused_imports)]
use super::*;

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
        crate::mqueue::set_fd_nonblock(task, fd, (arg as u32) & crate::fd::O_NONBLOCK != 0);
    }

    // F_DUPFD / F_DUPFD_CLOEXEC: dup oldfd into the lowest free slot
    // >= arg. Linux returns the new fd. CLOEXEC variant stamps
    // FD_CLOEXEC atomically.
    {
        if cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC {
            // `do_fcntl` receives an already-resolved `struct file *`, so a
            // closed descriptor is -EBADF from the entry's fdget_raw before
            // any per-command argument check runs.
            if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
                ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                return;
            }
            // `f_dupfd`: `if (from >= nofile) return -EINVAL;` — the floor is
            // rejected before any allocation is attempted, and separately from
            // the -EMFILE that a full table would produce. A caller doing
            // `fcntl(fd, F_DUPFD, 1024)` to park a descriptor above the
            // limit needs EINVAL to learn the floor is the problem.
            //
            // The floor is `int argi = (int)arg` widened back to `unsigned
            // int` by f_dupfd's parameter, i.e. the low 32 bits — NOT the
            // full register. `fcntl(fd, F_DUPFD, 1 << 32)` is a floor of 0 on
            // Linux and duplicates; comparing the untruncated value rejected
            // it with EINVAL instead.
            let min_fd = arg as u32;
            let nofile = read_rlimit(task, RLIMIT_NOFILE_RESOURCE)
                .map(|limit| limit.cur)
                .unwrap_or_else(|| default_rlimits()[RLIMIT_NOFILE_RESOURCE].cur);
            if u64::from(min_fd) >= nofile {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let cloexec = cmd == F_DUPFD_CLOEXEC;
            let outcome = fd::with_table_alloc(task, |t| {
                t.duplicate(fd, min_fd, if cloexec { crate::fd::FD_CLOEXEC } else { 0 })
            });
            match outcome {
                Some(Ok(new_fd)) => {
                    crate::mqueue::duplicate_fd_path(task, fd, new_fd);
                    ctx.set_return(SyscallReturn::ok(new_fd as u64));
                }
                // `f_dupfd` finishes with `alloc_fd(from, nofile, flags)`,
                // whose -EMFILE is distinct from the -EINVAL the floor check
                // above reports: the floor was legal, the table is simply
                // full between it and the limit.
                Some(Err(crate::fd::FdAllocError::TooManyFiles)) => {
                    ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
                }
                // F_DUPFD on a fd that isn't open → -EBADF (was InvalidOp).
                _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
            }
            return;
        }
    }

    // F_GETLK / F_SETLK / F_SETLKW: advisory POSIX locking. Gated
    // under linux-compat because the wire `struct flock` layout +
    // BTreeMap lock table only matter for Linux ABI consumers.
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
                        // l_pid is the CALLER's-namespace pid of the lock
                        // owner (Linux locks_translate_pid). The lock table
                        // stamps owners in TaskId space, so translate TaskId
                        // -> outer -> caller's ns view rather than leaking a
                        // raw scheduler id to lslocks/sqlite.
                        out.l_pid = report_pid_to(
                            task,
                            task_to_pid_raw(lock.pid as u64).unwrap_or(lock.pid as u64),
                        ) as i32;
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
                        // Owner is a TaskId; report it in the caller's ns view
                        // (see the get_lock path above).
                        out.l_pid =
                            report_pid_to(task, task_to_pid_raw(b.owner).unwrap_or(b.owner)) as i32;
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
    {
        // `fs/fcntl.c` routes both seal commands into `mm/memfd.c::
        // memfd_fcntl`, which reaches `memfd_file_seals_ptr(file)`:
        // a file that is not a sealable memfd yields NULL and the command
        // fails -EINVAL. Answering -EPERM instead (the old `-1` sentinel)
        // reads as "you are not allowed to seal this", which sends a caller
        // looking for a privilege it does not need — the file simply has no
        // seal word. A closed descriptor is still -EBADF, from the fdget in
        // the syscall entry, ahead of any of this.
        if cmd == F_ADD_SEALS || cmd == F_GET_SEALS {
            let open = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
            if !open {
                ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                return;
            }
            let Some(mfd) = memfd_arc_from_fd(task, fd) else {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            };
            if cmd == F_GET_SEALS {
                ctx.set_return(SyscallReturn::ok(mfd.seals() as u64));
                return;
            }
            // `memfd_add_seals` opens with
            // `if (!(file->f_mode & FMODE_WRITE)) return -EPERM;`: sealing
            // mutates shared state, so a read-only handle may not do it.
            let writable = fd::with_table(task, |t| {
                t.status_flags(fd).map(|flags| {
                    flags & crate::fd::O_ACCMODE != crate::fd::O_RDONLY
                        && flags & crate::fd::O_PATH == 0
                })
            })
            .flatten()
            .unwrap_or(false);
            if !writable {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
                return;
            }
            let r = match mfd.add_seals(arg as u32) {
                Ok(()) => SyscallReturn::ok(0),
                Err(crate::linux_compat::SealError::Invalid) => {
                    SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64)
                }
                Err(crate::linux_compat::SealError::Denied) => {
                    SyscallReturn::ok((-1i64) as u64) // -EPERM
                }
            };
            ctx.set_return(r);
            return;
        }
    }

    // Resolve any socket-side flag BEFORE entering the fd-table
    // closure — `current_socket` itself locks the table, which would
    // re-enter and deadlock if called from inside `with_table`.
    let sock_nb = current_socket(fd).map(|s| s.is_nonblock());
    let mq_nb = crate::mqueue::fd_nonblock(task, fd);

    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        Some(match cmd {
            F_GETFD => SyscallReturn::ok(entry.flags as u64),
            F_SETFD => {
                t.get_mut(fd)?.flags = arg as u32;
                SyscallReturn::ok(0)
            }
            // F_GETFL: report the per-fd status_flags. Socket
            // O_NONBLOCK overrides the bit if the SocketFile carries
            // its own nonblock toggle (kept in sync via F_SETFL).
            F_GETFL => {
                let mut v = t.status_flags(fd)? as u64;
                if let Some(nb) = sock_nb {
                    if nb {
                        v |= crate::socket::O_NONBLOCK as u64;
                    } else {
                        v &= !(crate::socket::O_NONBLOCK as u64);
                    }
                }
                if let Some(nb) = mq_nb {
                    if nb {
                        v |= crate::fd::O_NONBLOCK as u64;
                    } else {
                        v &= !(crate::fd::O_NONBLOCK as u64);
                    }
                }
                SyscallReturn::ok(v)
            }
            // F_SETFL: only the settable subset (O_NONBLOCK | O_APPEND
            // | O_DIRECT) is honoured. Access-mode bits are ignored.
            F_SETFL => {
                let mask = crate::fd::O_SETFL_MASK;
                let new = (arg as u32) & mask;
                let old = t.status_flags(fd)?;
                // Clone the handle out before the mutable `set_status_flags`
                // borrow so the pipe update below can still reach it.
                let ops = entry.ops.clone();
                t.set_status_flags(fd, (old & !mask) | new)?;
                // `fs/pipe.c::is_packetized` re-reads `filp->f_flags` on every
                // write, so O_DIRECT set (or cleared) here changes the framing
                // of subsequent writes. Storing it only in `status_flags` would
                // let F_GETFL report packet mode on a pipe that kept writing a
                // byte stream — the read end would then find no record
                // boundaries where the writer believed it had made them.
                if let Some(pipe) = ops
                    .as_any()
                    .and_then(|any| any.downcast_ref::<crate::pipe::PipeWrite>())
                {
                    pipe.set_packetized(new & crate::fd::O_DIRECT != 0);
                }
                SyscallReturn::ok(0)
            }
            // F_GETPIPE_SZ (1032) / F_SETPIPE_SZ (1031): report or resize the
            // pipe buffer. `pipe_fcntl()` returns EBADF, not EINVAL, when the
            // descriptor is valid but not a pipe. stress-ng's pipe stressor
            // queries F_GETPIPE_SZ to size its I/O buffer.
            1032 => match entry.ops.pipe_capacity() {
                Some(cap) => SyscallReturn::ok(cap as u64),
                None => SyscallReturn::ok((-(EBADF as i64)) as u64),
            },
            1031 => {
                // fcntl truncates arg through `int argi`; pipe_fcntl receives
                // that low 32-bit value as unsigned int.
                let size_arg = arg as u32;
                let resized = entry.ops.as_any().and_then(|any| {
                    if let Some(pipe) = any.downcast_ref::<crate::pipe::PipeRead>() {
                        Some(pipe.set_capacity(size_arg))
                    } else {
                        any.downcast_ref::<crate::pipe::PipeWrite>()
                            .map(|pipe| pipe.set_capacity(size_arg))
                    }
                });
                match resized {
                    Some(Ok(cap)) => SyscallReturn::ok(cap as u64),
                    Some(Err(errno)) => SyscallReturn::ok((-(errno as i64)) as u64),
                    // FIFOs expose pipe_capacity too. Their fixed backing is a
                    // compatibility implementation: validate Linux's global
                    // size errors, then report the live capacity.
                    None => match entry.ops.pipe_capacity() {
                        None => SyscallReturn::ok((-(EBADF as i64)) as u64),
                        Some(_) if size_arg > (1u32 << 31) => {
                            SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64)
                        }
                        Some(_) if (size_arg as usize).max(4096).next_power_of_two() > 1_048_576 => {
                            SyscallReturn::ok((-1i64) as u64) // -EPERM
                        }
                        Some(cap) => SyscallReturn::ok(cap as u64),
                    },
                }
            }
            _ => SyscallReturn::invalid_op(),
        })
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        // Linux validates the descriptor before dispatching the command
        // (`fs/fcntl.c::SYSCALL_DEFINE3(fcntl)`).  In particular, callers such
        // as D-Bus use F_GETFD to probe inherited descriptors and must observe
        // -EBADF for a closed slot, not NARF's internal InvalidOp value (zero
        // on the Linux return-value wire).
        _ => ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64)),
    }
}
