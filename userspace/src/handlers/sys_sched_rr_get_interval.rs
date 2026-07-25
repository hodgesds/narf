#[allow(unused_imports)]
use super::*;

/// `sched_rr_get_interval(pid, timespec*)` — the cooperative policy
/// has no round-robin quantum, so report `{0, 0}`.
pub(crate) fn sys_sched_rr_get_interval(ctx: &mut dyn TrapContext) {
    let buf = ctx.args().arg1;
    if buf != 0 {
        let kbuf = [0u8; 16]; // tv_sec = 0, tv_nsec = 0
                              // SAFETY: `buf` is the user `timespec*` (non-zero); copy_to_user
                              // range-validates the 16-byte write.
        if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
