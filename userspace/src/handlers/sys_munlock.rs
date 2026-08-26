#[allow(unused_imports)]
use super::*;

/// `munlock(addr, len)` — clear LOCKED flag (frames stay backed
/// since no swap exists yet to reclaim them). arg0 = base, arg1 = len.
///
/// `mm/mlock.c::SYSCALL_DEFINE2(munlock)`:
///
/// ```text
///     len = PAGE_ALIGN(len + (offset_in_page(start)));
///     start &= PAGE_MASK;
///     ret = apply_vma_lock_flags(start, len, 0);
/// ```
///
/// There is deliberately **no** `can_do_mlock()` check: dropping a lock is
/// always permitted. The remaining codes come from `apply_vma_lock_flags` —
/// EINVAL only for a wrapped `start + len`, 0 for an empty range, ENOMEM for
/// a range that is not fully covered by VMAs.
///
/// Like `mlock`, the address is rounded down rather than rejected. This is
/// the unlock half of the same pairing: a library that locked a `malloc`'d
/// secret buffer must be able to unlock the same pointer it passed in, and an
/// EINVAL here would leave the page permanently locked and counting against
/// RLIMIT_MEMLOCK for the rest of the process's life.
pub(crate) fn sys_munlock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let (start, len) = match super::handler_sys_mlock::mlock_align_range(args.arg0, args.arg1) {
        Ok(Some(range)) => range,
        Ok(None) => {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.munlock_range(VirtAddr::new(start), len) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        // Linux munlock(2): EINVAL for an out-of-range request, else ENOMEM for
        // a range that spans an unmapped hole.
        Err(narf_memory::AddressSpaceError::OutOfRange) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64))
        }
        Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)),
    }
}
