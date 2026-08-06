#[allow(unused_imports)]
use super::*;

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
    // POSIX-shaped failure sentinel. The user-runtime asm wrapper
    // observes only the `value` register, so we mirror libc and
    // return -1 on failure to disambiguate from a 0-valued success.
    // Without this the success ok(0) and the invalid_op rax=0 are
    // indistinguishable at the user side.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let path_owned = match copy_user_cstr(path_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
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
pub(crate) fn stat_absolute(ctx: &mut dyn TrapContext, path: &str, out_ptr: *mut StatBuf) {
    let fail = SyscallReturn::ok((-1i64) as u64);
    let ops = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
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
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
