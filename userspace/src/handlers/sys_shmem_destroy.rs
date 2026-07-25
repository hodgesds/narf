#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_shmem_destroy(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pid = current_task_id();
    if (v.pid_of)(handle) != pid {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if (v.destroy)(handle) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::invalid_op());
    }
}
