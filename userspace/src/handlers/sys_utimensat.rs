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

    let task = current_task_id();
    if a.arg1 == 0 {
        // futimens(fd) form — set times through the open fd's FileOps.
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

    let raw = match copy_user_cstr(a.arg1, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    };
    // Relative path against a real directory fd (AT_FDCWD / absolute
    // pass through) — same prepend as sys_readlinkat / sys_linkat.
    const AT_FDCWD: i64 = -100;
    let dirfd = a.arg0 as i64;
    let eff = if raw.starts_with('/') || dirfd == AT_FDCWD || dirfd < 0 {
        raw
    } else {
        match fd_path_for_task(task, dirfd as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), raw)
            }
            _ => raw,
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
