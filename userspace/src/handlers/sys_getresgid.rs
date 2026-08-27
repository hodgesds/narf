#[allow(unused_imports)]
use super::*;

/// `getresgid(rgid, egid, sgid)` — mirror of getresuid for the gid, and
/// likewise now reporting the real saved gid in the third slot.
pub(crate) fn sys_getresgid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let c = read_uidgid(current_task_id());
    write_res_ids(ctx, a.arg0, a.arg1, a.arg2, [c.gid, c.egid, c.sgid]);
}
