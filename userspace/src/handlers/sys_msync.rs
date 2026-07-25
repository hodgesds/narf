#[allow(unused_imports)]
use super::*;

/// `msync(addr, len, flags)` — anonymous mappings have nothing to
/// write back; just validate the range starts inside a mapping.
pub(crate) fn sys_msync(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    if addr & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let mapped = current_address_space()
        .map(|as_ref| as_ref.lookup(VirtAddr::new(addr)).is_some())
        .unwrap_or(false);
    if mapped {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
    }
}
