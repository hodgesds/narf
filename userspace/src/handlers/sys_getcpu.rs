#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup,
/// unsigned __user *, nodep, struct getcpu_cache __user *, unused)`.
///
/// ```text
/// int err = 0;
/// int cpu = raw_smp_processor_id();
/// if (cpup)  err |= put_user(cpu, cpup);
/// if (nodep) err |= put_user(cpu_to_node(cpu), nodep);
/// return err ? -EFAULT : 0;
/// ```
///
/// Both writes are ATTEMPTED even when the first faults — a caller with a
/// bad `cpup` but a good `nodep` still gets its node filled in, then
/// -EFAULT. Returning at the first fault skipped that write.
pub(crate) fn sys_getcpu(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let cpu_ptr = args.arg0;
    let node_ptr = args.arg1;
    let cpu = narf_lib::percpu::current_cpu() as u32;
    let node = numa_node_for_cpu(cpu);
    let mut fault = false;
    if cpu_ptr != 0 {
        // SAFETY: `cpu_ptr` is the user cpu out-pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
        fault |= unsafe { copy_to_user(cpu_ptr, &cpu.to_ne_bytes()) }.is_err();
    }
    if node_ptr != 0 {
        // SAFETY: `node_ptr` is the user node out-pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
        fault |= unsafe { copy_to_user(node_ptr, &node.to_ne_bytes()) }.is_err();
    }
    if fault {
        ctx.set_return(errno_ret(EFAULT));
    } else {
        ctx.set_return(SyscallReturn::ok(0));
    }
}
