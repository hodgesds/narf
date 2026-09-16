#[allow(unused_imports)]
use super::*;

// `mseal(2)` — make a range of the address space permanently immune to the
// operations that could replace what is mapped there.
//
// Sealing is MONOTONIC: `unseal()` does not exist, by design. That is what
// makes a sorted interval set the right representation — nothing is ever
// removed except when the whole address space goes away — and it is why the
// seal does not need to live in the VMA and survive every split and merge
// the memory subsystem performs. Linux keeps it in `vm_flags`, but Linux
// also enforces it from the syscall paths (`mm/mprotect.c`, `mm/mremap.c`,
// `mm/vma.c`, `mm/madvise.c`), which is where it is enforced here.

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// Sealed `[start, end)` intervals per address space, sorted and coalesced.
///
/// Keyed by the address-space identity `mapped_file` uses, and retired
/// through the same `drop_address_space` hook — an entry that outlived its
/// address space would seal whatever a later one happened to map at the same
/// addresses.
/// Sorted, coalesced `[start, end)` intervals for one address space.
type SealedRanges = Vec<(u64, u64)>;
/// Every address space that has sealed anything, keyed by its identity.
type SealedByAs = alloc::collections::BTreeMap<u64, SealedRanges>;

static SEALED: IrqSafeSpinLock<Option<SealedByAs>> = IrqSafeSpinLock::new(None);

/// Retire an address space's seals. Called from the same teardown that
/// retires its file-backed VMA ownership.
pub(crate) fn drop_address_space_seals(address_space_id: u64) {
    let mut g = SEALED.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&address_space_id);
    }
}

/// Is any part of `[start, end)` sealed in this address space?
///
/// Any OVERLAP counts, not containment: `munmap` over a range that is half
/// sealed would still leave a hole where the sealed half was, which is the
/// whole thing sealing exists to prevent.
pub(crate) fn range_is_sealed(address_space_id: u64, start: u64, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    let end = start.saturating_add(len);
    let g = SEALED.lock();
    g.as_ref()
        .and_then(|m| m.get(&address_space_id))
        .is_some_and(|v| v.iter().any(|&(s, e)| start < e && s < end))
}

/// Add `[start, end)` to the sealed set, coalescing with anything it touches.
fn add_sealed(address_space_id: u64, start: u64, end: u64) {
    let mut g = SEALED.lock();
    let m = g.get_or_insert_with(SealedByAs::new);
    let v = m.entry(address_space_id).or_default();
    v.push((start, end));
    v.sort_unstable();
    let mut merged: SealedRanges = Vec::with_capacity(v.len());
    for &(s, e) in v.iter() {
        match merged.last_mut() {
            // `<=` and not `<`: abutting intervals coalesce, so repeatedly
            // sealing adjacent pages cannot grow the set without bound.
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    *v = merged;
}

/// `mm/mseal.c::SYSCALL_DEFINE3(mseal)` — x86_64/arm64 462.
///
/// ```text
/// if (flags)                    return -EINVAL;   /* reserved */
/// if (!PAGE_ALIGNED(start))     return -EINVAL;
/// len = PAGE_ALIGN(len_in);
/// if (len_in && !len)           return -EINVAL;   /* rounded up to zero */
/// end = start + len;
/// ...
/// ```
///
/// -ENOMEM for an address that is not mapped, or a gap inside the range:
/// sealing half a range would leave the caller believing the whole of it is
/// protected.
///
/// "user can call mseal(2) multiple times, adding a seal on an already
/// sealed memory is a no-action (no error)" — and `unseal()` is not
/// supported, deliberately: a seal that could be lifted is not a seal.
pub(crate) fn sys_mseal(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (start, len_in, flags) = (a.arg0, a.arg1, a.arg2);

    // `flags` is reserved and must be zero — the check comes first, before
    // the address is even looked at.
    if flags != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    if start & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    let len = len_in.wrapping_add(0xFFF) & !0xFFF;
    // "Check to see whether len was rounded up from small -ve to zero."
    if len_in != 0 && len == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if len == 0 {
        // Nothing to seal, and not an error.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let Some(end) = start.checked_add(len) else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // range overflow
        return;
    };
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(no_address_space());
            return;
        }
    };
    // Every page of the range must be mapped — "a gap (unallocated memory)
    // between start and end" is -ENOMEM. Checked BEFORE anything is
    // recorded, so a partially-valid request seals nothing rather than
    // leaving the caller with half a seal it cannot inspect or undo.
    if !as_ref.range_fully_mapped(narf_memory::VirtAddr::new(start), len) {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // -ENOMEM
        return;
    }
    add_sealed(as_ref.identity(), start, end);
    ctx.set_return(SyscallReturn::ok(0));
}
