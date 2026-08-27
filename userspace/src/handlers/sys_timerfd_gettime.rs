#[allow(unused_imports)]
use super::*;

/// `fs/timerfd.c::SYSCALL_DEFINE2(timerfd_gettime, int, ufd,
/// struct __kernel_itimerspec __user *, otmr)`.
///
/// ```text
/// int ret = do_timerfd_gettime(ufd, &kotmr);
/// if (ret)
///         return ret;
/// return put_itimerspec64(&kotmr, otmr) ? -EFAULT : 0;
/// ```
///
/// with `do_timerfd_gettime` opening
///
/// ```text
/// if (fd_empty(f))                        return -EBADF;
/// if (fd_file(f)->f_op != &timerfd_fops)  return -EINVAL;
/// ```
///
/// Note there is NO null check on `otmr` — a null output pointer simply
/// faults in `put_itimerspec64`, which is -EFAULT. The old handler checked
/// `out_ptr == 0` FIRST and returned a bare -1, so it got both the errno
/// (EPERM instead of EFAULT) and the order wrong: `timerfd_gettime(-1, NULL)`
/// must report EBADF, because Linux validates the descriptor before it ever
/// looks at the output pointer.
pub(crate) fn sys_timerfd_gettime(ctx: &mut dyn TrapContext) {
    const EFAULT: i64 = 14;
    let args = *ctx.args();
    // `int ufd` — the descriptor is the low 32 bits.
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1;
    let task = current_task_id();
    // EBADF / EINVAL, before the output pointer is considered at all.
    let tfd = match timerfd_arc_from_fd_checked(task, fd) {
        Ok(t) => t,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let (value_remaining_ns, interval_ns) = tfd.current();
    // itimerspec = { interval: timespec, value: timespec },
    // timespec = { tv_sec: i64, tv_nsec: i64 }.
    let mut buf = [0u8; 32];
    let interval_sec = (interval_ns / 1_000_000_000) as i64;
    let interval_nsec = (interval_ns % 1_000_000_000) as i64;
    let value_sec = (value_remaining_ns / 1_000_000_000) as i64;
    let value_nsec = (value_remaining_ns % 1_000_000_000) as i64;
    buf[0..8].copy_from_slice(&interval_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&interval_nsec.to_le_bytes());
    buf[16..24].copy_from_slice(&value_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&value_nsec.to_le_bytes());
    // `put_itimerspec64(&kotmr, otmr) ? -EFAULT : 0`. A null `out_ptr`
    // lands here and fails range validation, which is exactly Linux's path.
    // SAFETY: copy_to_user range-validates `out_ptr` (including the null
    // case) and SMAP-brackets the 32-byte write.
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
