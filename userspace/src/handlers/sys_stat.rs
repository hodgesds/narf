#[allow(unused_imports)]
use super::*;

/// NARF-shape `stat` (a 64-byte `StatBuf` instead of Linux's 144-byte
/// `struct stat`).
///
/// SHADOWED under `linux-compat`: `install_core_syscalls` installs this on
/// `Syscall::Stat`/`Syscall::Lstat` early, then re-installs
/// [`sys_stat_linux`]/[`sys_lstat_linux`] over both slots, so only the
/// non-`linux-compat` build dispatches here. [`stat_absolute`] below is still
/// shared with [`sys_newfstatat`] (itself shadowed by `sys_newfstatat_linux`).
///
/// `fs/stat.c::SYSCALL_DEFINE2(newstat)` decides the errnos:
///
/// ```text
///     error = vfs_stat(filename, &stat);       /* -EFAULT / -ENOENT / … */
///     if (unlikely(error)) return error;
///     return cp_new_stat(&stat, statbuf);      /* copy_to_user → -EFAULT */
/// ```
///
/// Note the destination buffer is only touched AFTER the path resolves, so
/// `stat("/nope", NULL)` is ENOENT, not EFAULT.
pub(crate) fn sys_stat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int stat(const char *pathname, struct stat *statbuf)`.
    // Two args, path is NUL-terminated. (NARF-native callers used
    // the explicit-length triplet (path_ptr, path_len, out_ptr); we
    // cut over to the Linux shape so musl-built binaries can do PATH
    // search via stat — busybox sh's pipeline children stat their
    // way through `:`-separated $PATH looking for the binary, and
    // an EINVAL/EPERM return there masquerades as "Operation not
    // permitted", silently failing every `cat`/`tr`/`head` etc.)
    let path_ptr = args.arg0;
    let out_ptr = args.arg1 as *mut StatBuf;
    // `getname()`: -EFAULT for an unreadable pointer, -ENAMETOOLONG for a
    // path at PATH_MAX with no terminator.
    let path_owned = match copy_user_cstr_checked(path_ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let path_owned = apply_chroot(&path_owned);
    stat_absolute(ctx, &path_owned, out_ptr);
}

/// `stat` on an ALREADY chroot-resolved path, writing into `out_ptr`.
///
/// Split out so `sys_newfstatat` can join a relative path against its dirfd
/// and share this body. The out-pointer is passed explicitly because it
/// lives in a different argument slot for the two syscalls (arg1 for
/// `stat`, arg2 for `fstatat`), which is exactly the kind of mismatch the
/// old proxy-by-reshaping-args approach got wrong.
///
/// `vfs_stat` resolves before `cp_new_stat` copies, so this reports -ENOENT
/// for a path that names nothing and only then -EFAULT for a destination it
/// cannot write. The old bare -1 for both reached libc as EPERM, which is
/// what made a PATH search over a `:`-separated list report "Operation not
/// permitted" for every candidate that simply was not there.
pub(crate) fn stat_absolute(ctx: &mut dyn TrapContext, path: &str, out_ptr: *mut StatBuf) {
    let ops = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => {
            // `filename_lookup` splits this into -ENOENT, -ENOTDIR, -ELOOP
            // and -EACCES. `resolve_absolute` reports no reason, so the
            // walk is re-classified after the fact: see `path_lookup_errno`
            // for which of those NARF can recover (ENOENT / ENOTDIR) and
            // which still need machinery it lacks.
            ctx.set_return(SyscallReturn::ok((-path_lookup_errno(path)) as u64));
            return;
        }
    };
    // cp_new_stat's arm: the destination is inspected only now that the
    // path has resolved.
    if out_ptr.is_null() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let stat = StatBuf::from_stat(ops.stat());
    // Copy stat struct into user memory under the SMAP bracket.
    // SAFETY: stat is a plain-old-data repr(C) struct; transmuting
    // to bytes is sound.
    // SAFETY: Valid memory or trusted environment
    let stat_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &stat as *const StatBuf as *const u8,
            core::mem::size_of::<StatBuf>(),
        )
    };
    // SAFETY: `out_ptr` is the user StatBuf pointer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `stat_bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, stat_bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
