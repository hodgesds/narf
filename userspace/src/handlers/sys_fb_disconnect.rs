#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fb_disconnect(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    if (v.disconnect)(handle) {
        // Pair with on_connect: when the last live handle goes
        // away, restore the kernel FB console hook so subsequent
        // kernel prints render to screen again.
        fb_console_owner::on_disconnect();
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::invalid_op());
    }
}
