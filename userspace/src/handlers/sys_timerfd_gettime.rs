#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_timerfd_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    if out_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let tfd = match timerfd_arc_from_fd(task, fd) {
        Some(t) => t,
        None => {
            ctx.set_return(fail);
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
    // SAFETY: `out_ptr` is the user itimerspec pointer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the 32-byte write.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
