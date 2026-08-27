#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::SYSCALL_DEFINE3(getresuid, uid_t __user *, ruidp,
/// uid_t __user *, euidp, uid_t __user *, suidp)` — three chained
/// `put_user`s of the real, effective and SAVED uid.
///
/// The three slots used to receive the same value, because no saved uid
/// was tracked. That is observable, not cosmetic: a set-uid program that
/// has dropped to the invoking user reads `suid` to discover the id it can
/// still restore, and reporting the effective id there tells it the drop
/// was permanent.
pub(crate) fn sys_getresuid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let c = read_uidgid(current_task_id());
    write_res_ids(ctx, a.arg0, a.arg1, a.arg2, [c.uid, c.euid, c.suid]);
}
