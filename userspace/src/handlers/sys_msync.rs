#[allow(unused_imports)]
use super::*;

/// `msync(addr, len, flags)` — validate the range and commit fallback
/// file-backed MAP_SHARED pages. Anonymous and device mappings need no
/// writeback here.
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
        match crate::mapped_file::flush_current_range(addr, a.arg1) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(()) => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
        }
    } else {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
    }
}
