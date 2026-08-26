#[allow(unused_imports)]
use super::*;

/// `msync(addr, len, flags)` — validate the range and commit fallback
/// file-backed MAP_SHARED pages. Anonymous and device mappings need no
/// writeback here.
///
/// `mm/msync.c::SYSCALL_DEFINE3(msync)` fixes both the codes and their order:
///
/// ```text
///     int error = -EINVAL;
///     if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC))  goto out;
///     if (offset_in_page(start))                          goto out;
///     if ((flags & MS_ASYNC) && (flags & MS_SYNC))        goto out;
///     error = -ENOMEM;
///     len = (len + ~PAGE_MASK) & PAGE_MASK;
///     end = start + len;
///     if (end < start)                                    goto out;
///     error = 0;
///     if (end == start)                                   goto out;
///     ... /* unmapped gap in [start,end) => -ENOMEM */
/// ```
///
/// The `end == start` arm is a **success**, taken before any VMA is looked
/// up: a caller that flushes a computed sub-range and rounds down to nothing
/// (a database committing a partial page, or a mmap'd log writer whose dirty
/// window is empty) gets 0, not ENOMEM. ENOMEM from msync means "part of that
/// range is not mapped any more", which such a caller answers by re-mmapping
/// the file — an expensive and wrong reaction to an empty flush.
///
/// `flags` is an `int`, so only the low 32 bits are the caller's request.
pub(crate) fn sys_msync(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    const MS_ASYNC: u32 = 1;
    const MS_INVALIDATE: u32 = 2;
    const MS_SYNC: u32 = 4;
    let flags = a.arg2 as u32;
    if addr & 0xFFF != 0
        || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & MS_ASYNC != 0 && flags & MS_SYNC != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // `len = (len + ~PAGE_MASK) & PAGE_MASK` wraps to zero for a length in
    // the last page of the address space, which Linux then folds into the
    // `end == start` success arm rather than reporting an error.
    let len = a.arg1.wrapping_add(0xFFF) & !0xFFF;
    let end = addr.wrapping_add(len);
    if end < addr {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    if end == addr {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // No AddressSpace can contain a VMA outside the canonical user half, so
    // find_vma would fail there. Return the required ENOMEM before cloning
    // the current AS for the high addresses mmapfixed probes on every pass.
    if end > AddressSpace::USER_HALF_END {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    let mapped = current_address_space()
        .is_some_and(|as_ref| as_ref.residency_range(VirtAddr::new(addr), len).is_ok());
    if mapped {
        match crate::mapped_file::flush_current_range(addr, len) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(()) => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
        }
    } else {
        // LINUX-GAP: MS_INVALIDATE over an mlocked VMA is -EBUSY on Linux;
        // NARF has no per-VMA lock query on this path and reports the
        // coverage result instead.
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
    }
}
