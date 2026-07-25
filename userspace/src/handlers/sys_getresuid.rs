#[allow(unused_imports)]
use super::*;

/// `getresuid(ruid, euid, suid)` — NARF tracks a single uid, returned
/// as all three id slots.
pub(crate) fn sys_getresuid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let uid = read_uidgid(current_task_id()).uid;
    write_res_ids(ctx, a.arg0, a.arg1, a.arg2, uid);
}
