#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_shmem_create(ctx: &mut dyn TrapContext) {
    let len = ctx.args().arg0;
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pid = current_task_id();
    let h = (v.create)(pid, len);
    if h == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
    } else {
        ctx.set_return(SyscallReturn::ok(h));
    }
}
