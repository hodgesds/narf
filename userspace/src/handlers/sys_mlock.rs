#[allow(unused_imports)]
use super::*;

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
        // Linux mlock(2): EINVAL for an out-of-range request, EAGAIN when the
        // lock could not be satisfied (unimplemented backing here), and ENOMEM
        // for the dominant case — the range spans an unmapped hole.
        Err(narf_memory::AddressSpaceError::OutOfRange) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64))
        }
        Err(narf_memory::AddressSpaceError::NotImplemented) => {
            ctx.set_return(SyscallReturn::ok((-11i64) as u64))
        }
        Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)),
    }
}
