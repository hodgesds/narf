#[allow(unused_imports)]
use super::*;

/// Linux mlock-family errno projection. Keep this exhaustive so a new memory
/// error cannot silently fall into the wrong ABI bucket.
pub(super) fn mlock_errno(error: narf_memory::AddressSpaceError) -> i64 {
    match error {
        narf_memory::AddressSpaceError::OutOfRange
        | narf_memory::AddressSpaceError::AlignmentMismatch => 22, // EINVAL
        narf_memory::AddressSpaceError::Unmapped => 12, // ENOMEM
        narf_memory::AddressSpaceError::LockFailed
        | narf_memory::AddressSpaceError::ReclaimPressure
        | narf_memory::AddressSpaceError::NotImplemented
        | narf_memory::AddressSpaceError::Overlap
        | narf_memory::AddressSpaceError::InvalidNode
        | narf_memory::AddressSpaceError::SharedMapping
        | narf_memory::AddressSpaceError::NoDemotionTarget => 11, // EAGAIN
    }
}

/// `mprotect(base, len, prot)` — change permissions on every
/// region in the calling task's AS that intersects `[base,
/// base + len)`. Walks the region table, mutates `Region.perms`,
/// then re-installs the affected pages' PTEs with the new flag
/// set via `AddressSpace::change_perms_range`.
///
/// `prot` follows the POSIX bit layout we pin in `narf-libc`:
///   - bit 0 = PROT_READ
///   - bit 1 = PROT_WRITE
///   - bit 2 = PROT_EXEC
///
/// Returns Ok(0) on success, InvalidOp on bad AS or no
/// intersecting regions.
/// `mlock(addr, len)` — force-back lazy pages + set LOCKED flag.
/// arg0 = base, arg1 = len. Ok(0) on success, InvalidOp on
/// failure (range contains a hole, OOM, AS lookup failed).
pub(crate) fn sys_mlock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.mlock_range(VirtAddr::new(args.arg0), args.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        // Linux: EINVAL for malformed/range-overflow input, ENOMEM for a VMA
        // coverage hole, and EAGAIN when eager population cannot complete.
        Err(error) => ctx.set_return(SyscallReturn::ok((-mlock_errno(error)) as u64)),
    }
}
