#[allow(unused_imports)]
use super::*;

/// `sched_rr_get_interval(pid, timespec*)` — the cooperative policy has no
/// round-robin quantum, so report `{0, 0}`. Linux's `put_timespec64(&t,
/// interval)` returns -EFAULT on a faulting destination.
/// LINUX-GAP: `pid` is ignored — Linux resolves it (`pid < 0` → -EINVAL, no
/// such task → -ESRCH).
pub(crate) fn sys_sched_rr_get_interval(ctx: &mut dyn TrapContext) {
    let buf = ctx.args().arg1;
    if buf != 0 {
        let kbuf = [0u8; 16]; // tv_sec = 0, tv_nsec = 0
                              // SAFETY: `buf` is the user `timespec*` (non-zero); copy_to_user
                              // range-validates the 16-byte write.
        if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
