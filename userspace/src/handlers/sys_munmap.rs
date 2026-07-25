#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_munmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    match as_ref
        .unmap_region(base)
        .map(|_| ())
        .or_else(|_| as_ref.unmap_huge_region(base))
    {
        Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
