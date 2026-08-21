#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_mprotect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    match mprotect_core(&as_ref, base, args.arg1, args.arg2 as u32) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        // e is the positive errno (ENOMEM for an unmapped range, EACCES for a
        // W^X denial / missing JIT cap); negate for the Linux ABI.
        Err(e) => ctx.set_return(SyscallReturn::ok((-e) as u64)),
    }
}
