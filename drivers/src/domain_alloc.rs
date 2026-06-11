//! Driver-side helper for claiming MMIO into a domain-private VA.
//!
//! Each registered driver belongs to one of NARF's 16 domains
//! (`DriverEntry.domain`). When a driver maps its MMIO/BAR region,
//! it can do so via `claim_mmio_in_domain` instead of relying on
//! the boot-time identity map. The function resolves the driver's
//! domain to a domain-private VA in PML4 slot 256+D, maps each 4
//! KiB page of the MMIO region with the supplied flags, and
//! returns the base VA for the driver to use.
//!
//! Under PKS / MTE the domain primitive does the access-rights
//! enforcement; the VA range is informational. Under PCID the VA
//! choice is the *primary* enforcement: the per-domain PML4 only
//! has a present PML4E at slot 256+D for its own domain, so a
//! cross-domain access #PFs at PML4 level. Either way the driver's
//! call site is identical; the kernel's enforcer choice decides
//! how the isolation is realised.
//!
//! Per-domain VA allocation: a bump pointer plus a per-domain
//! free-list. `claim_mmio_in_domain` first scans the free-list for
//! an exact-size match, falling back to the bump pointer; `release`
//! returns a previously-claimed range. The free-list does not
//! coalesce adjacent entries today — driver bind/unbind is rare,
//! and the simple list keeps the contract obvious. Future work can
//! add a coalescing buddy if churn ever justifies it.

#[cfg(target_arch = "x86_64")]
extern crate alloc;

#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use narf_lib::sync::IrqSafeSpinLock;

#[cfg(target_arch = "x86_64")]
use narf_memory::domain::{domain_va_base, map_domain_private, DomainMapError};
#[cfg(target_arch = "x86_64")]
use narf_memory::paging::PtFlags;
#[cfg(target_arch = "x86_64")]
use narf_memory::{PhysAddr, VirtAddr};

/// Errors from `claim_mmio_in_domain`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DomainAllocError {
    BadDomain,
    UnsupportedArch,
    OutOfRange,
    MapFailed,
}

#[cfg(target_arch = "x86_64")]
impl From<DomainMapError> for DomainAllocError {
    fn from(e: DomainMapError) -> Self {
        match e {
            DomainMapError::BadDomain => DomainAllocError::BadDomain,
            DomainMapError::AddressOutsideDomainRange => DomainAllocError::OutOfRange,
            DomainMapError::NoPml4Registered => DomainAllocError::MapFailed,
            DomainMapError::PdptNotInstalled => DomainAllocError::MapFailed,
            DomainMapError::FrameExhausted => DomainAllocError::MapFailed,
            DomainMapError::Map(_) => DomainAllocError::MapFailed,
        }
    }
}

/// Per-domain bump pointer for the next driver's claim. Starts a
/// few pages into the slot to leave room for headers / sentinels
/// the framework may want to install at the slot base later.
#[cfg(target_arch = "x86_64")]
const DOMAIN_HEAP_OFFSET: u64 = 0x10_0000; // 1 MiB

#[cfg(target_arch = "x86_64")]
const NUM_DOMAINS: usize = 16;

#[cfg(target_arch = "x86_64")]
static NEXT_VA: [AtomicU64; NUM_DOMAINS] = [const { AtomicU64::new(0) }; NUM_DOMAINS];

/// Per-domain free list of `(va_base, byte_len)` chunks released by
/// `release`. Reused before the bump pointer advances. Not
/// coalesced — see module doc.
#[cfg(target_arch = "x86_64")]
static FREE_LIST: [IrqSafeSpinLock<Vec<(u64, u64)>>; NUM_DOMAINS] =
    [const { IrqSafeSpinLock::new(Vec::new()) }; NUM_DOMAINS];

/// Number of bytes claimed in `domain`'s private heap so far.
#[cfg(target_arch = "x86_64")]
pub fn claimed_in_domain(domain: u8) -> u64 {
    if (domain as usize) >= NUM_DOMAINS {
        return 0;
    }
    let base = domain_va_base(domain).unwrap_or(0);
    let next = NEXT_VA[domain as usize].load(Ordering::Relaxed);
    next.saturating_sub(base + DOMAIN_HEAP_OFFSET)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn claimed_in_domain(_domain: u8) -> u64 {
    0
}

/// Claim a fresh private VA range in `domain`, mapping `len` bytes
/// of MMIO starting at `pa`. Returns the base VA (4 KiB-aligned)
/// the driver should use for its register accesses.
///
/// `len` is rounded up to the next 4 KiB boundary.
///
/// # Safety
/// - `pa` must be a valid MMIO physical address belonging to the
///   caller's device (the cap-system gates this).
/// - `flags` typically include `PRESENT | WRITABLE | NO_CACHE` for
///   MMIO; the helper does not impose them — caller decides.
/// - Concurrent claims to the same domain race only on the bump
///   pointer; ranges never overlap.
#[cfg(target_arch = "x86_64")]
pub unsafe fn claim_mmio_in_domain(
    domain: u8,
    pa: u64,
    len: usize,
    flags: PtFlags,
) -> Result<u64, DomainAllocError> {
    if (domain as usize) >= NUM_DOMAINS {
        return Err(DomainAllocError::BadDomain);
    }
    let base = domain_va_base(domain).ok_or(DomainAllocError::BadDomain)?;
    let pages = (len + 0xFFF) >> 12;
    let bytes = (pages as u64) << 12;

    // Try the per-domain free list first — exact-size match wins.
    let va_base = {
        let mut fl = FREE_LIST[domain as usize].lock();
        let mut hit: Option<usize> = None;
        for (i, &(_, l)) in fl.iter().enumerate() {
            if l == bytes {
                hit = Some(i);
                break;
            }
        }
        if let Some(i) = hit {
            let (va, _) = fl.remove(i);
            va
        } else {
            // Initialise the bump pointer on first use.
            let slot = &NEXT_VA[domain as usize];
            let init = base + DOMAIN_HEAP_OFFSET;
            let _ = slot.compare_exchange(0, init, Ordering::Relaxed, Ordering::Relaxed);
            let v = slot.fetch_add(bytes, Ordering::Relaxed);
            let slot_end = base + (1u64 << 39);
            if v + bytes > slot_end {
                slot.fetch_sub(bytes, Ordering::Relaxed);
                return Err(DomainAllocError::OutOfRange);
            }
            v
        }
    };

    // Map each 4 KiB page.
    for i in 0..pages {
        let va = VirtAddr::new(va_base + (i as u64) * 4096);
        let p = PhysAddr::new(pa + (i as u64) * 4096);
        // SAFETY: caller-asserted pa validity; va is freshly bumped
        // (no prior mapping at it); flags chosen by caller.
        unsafe {
            map_domain_private(domain, va, p, flags)?;
        }
    }
    Ok(va_base)
}

/// Release a previously-claimed range: unmap each 4 KiB page (which
/// fans out a TLB shootdown to peer CPUs via the
/// `paging::set_shootdown_hook` already installed at boot) and
/// return the VA range to `domain`'s free-list for reuse.
///
/// `(va_base, len)` must match a prior `claim_mmio_in_domain`
/// (or `claim_mmio_for_driver`) call — `len` is rounded up the
/// same way internally.
///
/// # Safety
/// - Caller must guarantee no live references / DMA into the range
///   (capability revocation is the typical sequencing tool here).
/// - `va_base` and `len` must match the prior claim.
#[cfg(target_arch = "x86_64")]
pub unsafe fn release(domain: u8, va_base: u64, len: usize) -> Result<(), DomainAllocError> {
    if (domain as usize) >= NUM_DOMAINS {
        return Err(DomainAllocError::BadDomain);
    }
    let pml4_phys = narf_arch::x86_64::pcid::get_domain_pml4(domain);
    if pml4_phys == 0 {
        return Err(DomainAllocError::MapFailed);
    }

    let pages = (len + 0xFFF) >> 12;
    let bytes = (pages as u64) << 12;

    // Unmap each 4 KiB page locally without firing N separate
    // single-page shootdowns. We use the lower-level `unmap_4kb`
    // which calls `invlpg_global` per page — but we override with
    // a single range broadcast at the end. Easiest path: tear down
    // the leaves with the page-table walker that does NOT call the
    // global hook, then issue one range shootdown.
    //
    // For now we still go through `unmap_4kb` (per-page hook fires)
    // because the per-page broadcast is correct, just N times.
    // The range hook below is a no-op de-dup since the per-page
    // hook already invalidated; calling it again is idempotent for
    // INVLPG. The win arrives once we add an unmap-range primitive
    // to memory/.
    for i in 0..pages {
        let va = VirtAddr::new(va_base + (i as u64) * 4096);
        // SAFETY: pml4_phys identity-mapped; va was previously mapped.
        let _ = unsafe { narf_memory::paging::unmap_4kb(PhysAddr::new(pml4_phys), va) };
    }
    // Single range broadcast — receiver loops INVLPG once.
    // SAFETY: pages just unmapped locally.
    unsafe {
        narf_memory::paging::invlpg_global_range(VirtAddr::new(va_base), pages as u64);
    }

    // Push the range onto the free-list for reuse.
    FREE_LIST[domain as usize].lock().push((va_base, bytes));
    Ok(())
}

/// `release` on non-x86_64 targets: reports unsupported.
///
/// # Safety
/// Mirrors the x86_64 `release` contract: `va_base` must be the base
/// of a range previously handed out for `domain` and no longer
/// referenced, since the real implementation tears down its page-table
/// leaves and broadcasts a TLB shootdown. This stub performs no memory
/// operations and only returns `UnsupportedArch`.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn release(_domain: u8, _va_base: u64, _len: usize) -> Result<(), DomainAllocError> {
    Err(DomainAllocError::UnsupportedArch)
}

/// Number of free chunks currently parked in `domain`'s free list.
/// Test helper.
#[cfg(target_arch = "x86_64")]
pub fn free_chunks_in_domain(domain: u8) -> usize {
    if (domain as usize) >= NUM_DOMAINS {
        return 0;
    }
    FREE_LIST[domain as usize].lock().len()
}

#[cfg(not(target_arch = "x86_64"))]
pub fn free_chunks_in_domain(_domain: u8) -> usize {
    0
}

/// `claim_mmio_in_domain` on non-x86_64 targets: reports unsupported.
///
/// # Safety
/// Mirrors the x86_64 `claim_mmio_in_domain` contract: `pa` must be a
/// valid MMIO physical address belonging to the caller's device (the
/// cap-system gates this) and `flags` are the page-table flags to map
/// it with. This stub maps nothing and only returns `UnsupportedArch`.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn claim_mmio_in_domain(
    _domain: u8,
    _pa: u64,
    _len: usize,
    _flags: u64,
) -> Result<u64, DomainAllocError> {
    Err(DomainAllocError::UnsupportedArch)
}

/// Convenience: look up a registered driver's assigned domain by
/// name and claim MMIO for it. Returns `BadDomain` if the driver
/// hasn't been registered yet.
///
/// # Safety
/// This forwards directly to [`claim_mmio_in_domain`], so the caller
/// must uphold that function's contract:
/// - `pa` must be a valid MMIO physical address belonging to the
///   device owned by the driver registered under `name` (the
///   cap-system gates this).
/// - `flags` typically include `PRESENT | WRITABLE | NO_CACHE` for
///   MMIO; the helper does not impose them — caller decides.
#[cfg(target_arch = "x86_64")]
pub unsafe fn claim_mmio_for_driver(
    name: &str,
    pa: u64,
    len: usize,
    flags: PtFlags,
) -> Result<u64, DomainAllocError> {
    let domain = match crate::bound::domain_of(name) {
        Some(d) => d,
        None => return Err(DomainAllocError::BadDomain),
    };
    // SAFETY: `domain` is the domain bound to `name`, so the mapping
    // lands in that driver's private address-space region. `pa`, `len`
    // and `flags` are passed through unchanged; the caller has asserted
    // (per this function's `# Safety`) that `pa..pa+len` is MMIO owned
    // by this driver, which is exactly `claim_mmio_in_domain`'s contract.
    unsafe { claim_mmio_in_domain(domain, pa, len, flags) }
}
