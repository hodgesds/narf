#[allow(unused_imports)]
use super::*;

/// `getresgid(rgid, egid, sgid)` — mirror of getresuid for the gid.
pub(crate) fn sys_getresgid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let gid = read_uidgid(current_task_id()).gid;
    write_res_ids(ctx, a.arg0, a.arg1, a.arg2, gid);
}
