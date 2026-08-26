#[allow(unused_imports)]
use super::*;

/// Linux mlock-family errno projection. Keep this exhaustive so a new memory
/// error cannot silently fall into the wrong ABI bucket.
pub(super) fn mlock_errno(error: narf_memory::AddressSpaceError) -> i64 {
    match error {
        narf_memory::AddressSpaceError::OutOfRange
        | narf_memory::AddressSpaceError::AlignmentMismatch => 22, // EINVAL
        narf_memory::AddressSpaceError::Unmapped
        | narf_memory::AddressSpaceError::LockLimit
        | narf_memory::AddressSpaceError::MappingLimit
        | narf_memory::AddressSpaceError::StackLimit => 12, // ENOMEM
        narf_memory::AddressSpaceError::LockFailed
        | narf_memory::AddressSpaceError::AllocationFailed
        | narf_memory::AddressSpaceError::StaleMapping
        | narf_memory::AddressSpaceError::ReclaimPressure
        | narf_memory::AddressSpaceError::NotImplemented
        | narf_memory::AddressSpaceError::Overlap
        | narf_memory::AddressSpaceError::InvalidNode
        | narf_memory::AddressSpaceError::SharedMapping
        | narf_memory::AddressSpaceError::NoDemotionTarget => 11, // EAGAIN
    }
}

/// The `start`/`len` normalization every mlock-family syscall performs before
/// it touches a VMA. `mm/mlock.c` does it identically in `do_mlock` (mlock,
/// mlock2) and in `SYSCALL_DEFINE2(munlock)`:
///
/// ```text
///     len = PAGE_ALIGN(len + (offset_in_page(start)));
///     start &= PAGE_MASK;
/// ```
///
/// then `apply_vma_lock_flags` decides the two degenerate cases:
///
/// ```text
///     end = start + len;
///     if (end < start)  return -EINVAL;
///     if (end == start) return 0;
/// ```
///
/// So **mlock does not require a page-aligned address**: it locks the pages
/// containing `[start, start+len)`. That is not a nicety — it is how every
/// real caller uses it. gnupg/libsodium/OpenSSL mlock a secret buffer returned
/// by `malloc`, which is 16-byte aligned at best; a strict-alignment EINVAL
/// there makes the library conclude the platform forbids locking and fall back
/// to leaving key material swappable. Passing the raw address through to
/// `mlock_range_limited` produced exactly that (`AlignmentMismatch` → EINVAL).
///
/// Returns `Some(rounded_len)` to proceed with, or `None`/`Err(errno)` for the
/// two arms Linux answers without consulting the address space.
pub(super) fn mlock_align_range(start: u64, len: u64) -> Result<Option<(u64, u64)>, i64> {
    let offset = start & 0xFFF;
    // Linux computes this in wrapping unsigned arithmetic and lets the
    // `end < start` test below catch the overflow, so mirror that exactly
    // rather than inventing an earlier errno.
    let len = len.wrapping_add(offset).wrapping_add(0xFFF) & !0xFFF;
    let start = start & !0xFFF;
    let end = start.wrapping_add(len);
    if end < start {
        return Err(22); // EINVAL
    }
    if end == start {
        return Ok(None); // success, nothing to lock
    }
    Ok(Some((start, len)))
}

/// `mlock(addr, len)` — force-back lazy pages + set LOCKED flag.
///
/// `mm/mlock.c::do_mlock`:
///
/// ```text
///     if (!can_do_mlock())          return -EPERM;
///     len = PAGE_ALIGN(len + (offset_in_page(start)));
///     start &= PAGE_MASK;
///     ... if over RLIMIT_MEMLOCK and !CAP_IPC_LOCK: error stays -ENOMEM
///     error = apply_vma_lock_flags(start, len, flags);   /* -ENOMEM on a gap */
///     error = __mm_populate(start, len, 0);
///     if (error) return __mlock_posix_error_return(error); /* -ENOMEM => -EAGAIN */
/// ```
///
/// The three failures are genuinely different instructions to the caller:
/// **EPERM** = this process may never lock memory (raise RLIMIT_MEMLOCK or
/// grant CAP_IPC_LOCK); **ENOMEM** = the range has a hole or the limit is too
/// small (lock less); **EAGAIN** = transient population failure (retry). A
/// secret-memory allocator that sees EPERM stops trying for the lifetime of
/// the process, which is the wrong response to a transient EAGAIN.
pub(crate) fn sys_mlock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let authority = current_mlock_authority();
    if !can_do_mlock(authority) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    let (start, len) = match mlock_align_range(args.arg0, args.arg1) {
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
    match as_ref.mlock_range_limited(
        VirtAddr::new(start),
        len,
        authority.limit_bytes,
        authority.bypass_limit,
    ) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        // Linux: EINVAL for malformed/range-overflow input, ENOMEM for a VMA
        // coverage hole, and EAGAIN when eager population cannot complete.
        Err(error) => ctx.set_return(SyscallReturn::ok((-mlock_errno(error)) as u64)),
    }
}
