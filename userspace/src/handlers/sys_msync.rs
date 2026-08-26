#[allow(unused_imports)]
use super::*;

/// `msync(addr, len, flags)` — validate the range and commit fallback
/// file-backed MAP_SHARED pages. Anonymous and device mappings need no
/// writeback here.
pub(crate) fn sys_msync(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    const MS_ASYNC: u64 = 1;
    const MS_INVALIDATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    let flags = a.arg2;
    if addr & 0xFFF != 0
        || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & MS_ASYNC != 0 && flags & MS_SYNC != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // No AddressSpace can contain a VMA outside the canonical user half.
    // Return the required ENOMEM before cloning the current AS for the high
    // addresses mmapfixed probes on every pass.
    if addr >= AddressSpace::USER_HALF_END
        || a.arg1
            .checked_add(0xFFF)
            .and_then(|len| addr.checked_add(len & !0xFFF))
            .is_none_or(|end| end > AddressSpace::USER_HALF_END)
    {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    let mapped = current_address_space()
        .is_some_and(|as_ref| as_ref.residency_range(VirtAddr::new(addr), a.arg1).is_ok());
    if mapped {
        match crate::mapped_file::flush_current_range(addr, a.arg1) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(()) => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
        }
    } else {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
    }
}
