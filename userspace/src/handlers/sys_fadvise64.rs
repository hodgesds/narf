#[allow(unused_imports)]
use super::*;

/// `posix_fadvise` advice values (`include/uapi/linux/fadvise.h`). NORMAL,
/// RANDOM, SEQUENTIAL and WILLNEED are architecture-independent; DONTNEED and
/// NOREUSE are 4/5 on s390 and 6/7 everywhere else. NARF targets x86_64 and
/// aarch64, so the 4/5 pair applies.
const POSIX_FADV_NORMAL: u64 = 0;
const POSIX_FADV_RANDOM: u64 = 1;
const POSIX_FADV_SEQUENTIAL: u64 = 2;
const POSIX_FADV_WILLNEED: u64 = 3;
const POSIX_FADV_DONTNEED: u64 = 4;
const POSIX_FADV_NOREUSE: u64 = 5;

/// `fadvise64(fd, offset, len, advice)` — access-pattern hint.
///
/// `mm/fadvise.c::ksys_fadvise64_64` resolves the fd (-EBADF), then
/// `generic_fadvise` applies:
///
/// ```text
///   if (S_ISFIFO(inode->i_mode)) return -ESPIPE;
///   if (!mapping || len < 0)     return -EINVAL;
///   ...
///   default:                     return -EINVAL;   /* unknown advice */
/// ```
///
/// NARF's in-memory filesystems have nothing to prefetch or drop, so a valid
/// call is a no-op success — but "ignore the hint" is not the same as "accept
/// any argument". A caller that passes an out-of-range advice constant (a
/// portability bug, or the s390 DONTNEED value on x86_64) needs to hear
/// -EINVAL, which is exactly how it discovers the mistake.
pub(crate) fn sys_fadvise64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let len = args.arg2;
    let advice = args.arg3;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    if endpoint.ops.stat().mode.file_type == narf_filesystem::FileType::Fifo {
        ctx.set_return(SyscallReturn::ok((-29i64) as u64)); // -ESPIPE
        return;
    }
    if (len as i64) < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    if !matches!(
        advice,
        POSIX_FADV_NORMAL
            | POSIX_FADV_RANDOM
            | POSIX_FADV_SEQUENTIAL
            | POSIX_FADV_WILLNEED
            | POSIX_FADV_DONTNEED
            | POSIX_FADV_NOREUSE
    ) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
