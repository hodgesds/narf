#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fb_flush_wait(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let drained = (v.flush_wait)(handle);
    ctx.set_return(SyscallReturn::ok(drained));
}
