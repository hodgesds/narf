#[allow(unused_imports)]
use super::*;

/// `ptrace(request, pid, addr, data)`
/// Currently a stub returning ENOSYS (-38) since the GDB stub
/// (observability) is not fully wired to the userspace process
/// table yet.
pub(crate) fn sys_ptrace(ctx: &mut dyn TrapContext) {
    {
        crate::ptrace::sys_ptrace(ctx);
    }
}
