#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fb_connect(ctx: &mut dyn TrapContext) {
    let scanout_id = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pid = current_task_id();
    let h = (v.connect)(pid, scanout_id);
    if h == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
    } else {
        // First active FB-handle takes ownership of the framebuffer
        // away from the kernel-side FB console so kernel prints
        // don't paint glyphs over the user's pixels. Last
        // disconnect restores it. Serial / UART output is
        // unaffected — Console::Writer fans out to the FB only
        // through the optional hook this swaps.
        fb_console_owner::on_connect();
        ctx.set_return(SyscallReturn::ok(h));
    }
}
