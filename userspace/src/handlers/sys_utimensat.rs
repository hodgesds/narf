#[allow(unused_imports)]
use super::*;

/// `utimensat(dirfd, path, timespec[2], flags)` — the modern entry musl
/// routes utime/utimes/futimens through. `times` NULL = both now;
/// tv_nsec may be UTIME_NOW / UTIME_OMIT per slot. `path` NULL is the
/// futimens form: operate on `dirfd` itself through the fd table.
pub(crate) fn sys_utimensat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    const UTIME_NOW: i64 = 0x3FFF_FFFF;
    const UTIME_OMIT: i64 = 0x3FFF_FFFE;

    // Decode the two timespec slots into Option<ns> (None = OMIT).
    let (at, mt) = if a.arg2 == 0 {
        let now = wall_now_ns();
        (Some(now), Some(now))
    } else {
        let mut buf = [0u8; 32];
        // SAFETY: non-zero user timespec[2] pointer; copy_from_user
        // range-validates and SMAP-brackets the 32-byte read.
        if unsafe { copy_from_user(&mut buf, a.arg2) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        let slot = |o: usize| -> Result<Option<u64>, ()> {
            let sec = i64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
            let nsec = i64::from_ne_bytes(buf[o + 8..o + 16].try_into().unwrap());
            match nsec {
                UTIME_OMIT => Ok(None),
                UTIME_NOW => Ok(Some(wall_now_ns())),
                n if (0..1_000_000_000).contains(&n) => Ok(Some(
                    (sec.max(0) as u64).saturating_mul(1_000_000_000) + n as u64,
                )),
                _ => Err(()), // Linux: EINVAL for an out-of-range tv_nsec
            }
        };
        match (slot(0), slot(16)) {
            (Ok(at), Ok(mt)) => (at, mt),
            _ => {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
                return;
            }
        }
    };

    if at.is_none() && mt.is_none() {
        // Nothing to do, we must not even check the path (Linux fs/utimes.c:153).
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let task = current_task_id();
    let flags = a.arg3;
    if a.arg1 == 0 {
        // futimens(fd) form — set times through the open fd's FileOps.
        // In Linux do_utimes_fd(fd, times, flags): if (flags) return -EINVAL;
        if flags != 0 {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
        let fd = a.arg0 as u32;
        let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
        match ops {
            Some(o) => {
                // set_times is lenient — unsupported FileOps → 0.
                let _ = o.set_times(at, mt);
                // inotify: a timestamp change is IN_ATTRIB on the fd's file.
                crate::mqueue::notify_attrib_fd(task, fd);
                ctx.set_return(SyscallReturn::ok(0));
            }
            None => ctx.set_return(SyscallReturn::ok((-9i64) as u64)), // -EBADF
        }
        return;
    }

    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    let raw = match copy_user_cstr_checked(a.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64)); // -EFAULT
            return;
        }
    };

    let dirfd = a.arg0 as i64;
    if raw.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
        if dirfd >= 0 {
            let ops =
                fd::with_table(task, |t| t.get(dirfd as u32).map(|e| e.ops.clone())).flatten();
            match ops {
                Some(o) => {
                    let _ = o.set_times(at, mt);
                    crate::mqueue::notify_attrib_fd(task, dirfd as u32);
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
                    return;
                }
            }
        } else if dirfd == -100 {
            let path = resolve_cwd_path(task, ".");
            let r = set_path_times(&path, at, mt);
            if r == 0 {
                let is_dir = resolve_dir_absolute(&path).is_some();
                crate::mqueue::notify_attrib(&path, is_dir);
            }
            ctx.set_return(SyscallReturn::ok(r as u64));
            return;
        } else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    }

    let eff = match resolve_at_path(task, dirfd, &raw) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    let path = resolve_cwd_path(task, &eff);
    let r = set_path_times(&path, at, mt);
    // inotify: a successful timestamp change is IN_ATTRIB on the path.
    if r == 0 {
        let is_dir = resolve_dir_absolute(&path).is_some();
        crate::mqueue::notify_attrib(&path, is_dir);
    }
    ctx.set_return(SyscallReturn::ok(r as u64));
}
