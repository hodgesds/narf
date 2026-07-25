#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getcpu(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let cpu_ptr = args.arg0;
    let node_ptr = args.arg1;
    let cpu = narf_lib::percpu::current_cpu() as u32;
    let node = numa_node_for_cpu(cpu);
    if cpu_ptr != 0 {
        // SAFETY: `cpu_ptr` is the user cpu out-pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(cpu_ptr, &cpu.to_ne_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    if node_ptr != 0 {
        // SAFETY: `node_ptr` is the user node out-pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(node_ptr, &node.to_ne_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
