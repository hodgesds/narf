#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getcpu(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let cpu_ptr = args.arg0;
    let node_ptr = args.arg1;
    // Write CPU=0, node=0 under the SMAP bracket.
    if cpu_ptr != 0 {
        // SAFETY: `cpu_ptr` is the user cpu out-pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { copy_to_user(cpu_ptr, &0u32.to_ne_bytes()) };
    }
    if node_ptr != 0 {
        // SAFETY: `node_ptr` is the user node out-pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { copy_to_user(node_ptr, &0u32.to_ne_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}
