#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_newfstatat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int fstatat(int dirfd, const char *pathname,
    // struct stat *statbuf, int flags)`.
    let dirfd = args.arg0 as i32;
    let path_uptr = args.arg1;
    let stat_out = args.arg2;
    let flags = args.arg3 as u32;

    // AT_EMPTY_PATH + empty path → describe `dirfd` itself. This is how modern
    // glibc implements `fstat(fd, buf)`: `newfstatat(fd, "", buf,
    // AT_EMPTY_PATH)`. Without this, the empty path falls through to path
    // resolution and yields a garbage/ENOENT stat, so `fstat` on any open fd
    // reports a non-regular mode — which makes systemd's `read_full_virtual_file`
    // reject every sysfs `uevent` with EBADF and libudev resolve no devices
    // (kwin then gets no GPU). sys_statx already handles this; mirror it.
    let empty = (flags & linux_compat::AT_EMPTY_PATH) != 0 && {
        let mut first = [0u8; 1];
        // SAFETY: `path_uptr` is the user path pointer; copy_from_user
        // range-validates it and SMAP-brackets the 1-byte read into `first`.
        unsafe { copy_from_user(&mut first, path_uptr) }.is_ok() && first[0] == 0
    };
    if empty {
        let out_ptr = stat_out as *mut linux_compat::Stat;
        let fail = SyscallReturn::ok((-1i64) as u64);
        if out_ptr.is_null() || dirfd < 0 {
            ctx.set_return(fail);
            return;
        }
        let task = current_task_id();
        let stat = fd::with_table(task, |t| {
            t.get(dirfd as u32)
                .map(|e| (e.ops.stat(), e.ops.owners(), e.ops.rdev(), e.ops.ino()))
        });
        let (s, (uid, gid), rdev, ino) = match stat {
            Some(Some(tuple)) => tuple,
            _ => {
                ctx.set_return(fail);
                return;
            }
        };
        let out = linux_stat_from_fs(s, uid, gid, rdev, ino);
        // SAFETY: `out` is a live repr(C) Stat; the slice spans exactly its size.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &out as *const linux_compat::Stat as *const u8,
                core::mem::size_of::<linux_compat::Stat>(),
            )
        };
        // SAFETY: `out_ptr` null-checked above; copy_to_user range-validates it.
        if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // AT_SYMLINK_NOFOLLOW (lstat's shape via fstatat) means "describe the
    // symlink itself" — don't follow the final component. Without it,
    // fstatat follows like plain stat.
    let follow_final = flags & linux_compat::AT_SYMLINK_NOFOLLOW == 0;
    stat_linux_common(ctx, path_uptr, stat_out, follow_final);
}
