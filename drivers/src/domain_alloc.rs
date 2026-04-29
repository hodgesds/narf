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
//! Per-domain VA allocation is monotonic — each call hands out a
//! fresh sub-range starting `DOMAIN_HEAP_OFFSET` into the slot, so
//! drivers never collide with each other within a domain. There
//! is no current free path; drivers do not unbind in NARF today.

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use narf_memory::domain::{
    domain_va_base, map_domain_private, DomainMapError,
};
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
            DomainMapError::BadDomain                  => DomainAllocError::BadDomain,
            DomainMapError::AddressOutsideDomainRange  => DomainAllocError::OutOfRange,
            DomainMapError::NoPml4Registered           => DomainAllocError::MapFailed,
            DomainMapError::PdptNotInstalled           => DomainAllocError::MapFailed,
            DomainMapError::FrameExhausted             => DomainAllocError::MapFailed,
            DomainMapError::Map(_)                     => DomainAllocError::MapFailed,
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
static NEXT_VA: [AtomicU64; NUM_DOMAINS] = [
    const { AtomicU64::new(0) }; NUM_DOMAINS
];

/// Number of bytes claimed in `domain`'s private heap so far.
#[cfg(target_arch = "x86_64")]
pub fn claimed_in_domain(domain: u8) -> u64 {
    if (domain as usize) >= NUM_DOMAINS { return 0; }
    let base = domain_va_base(domain).unwrap_or(0);
    let next = NEXT_VA[domain as usize].load(Ordering::Relaxed);
    if next < base + DOMAIN_HEAP_OFFSET { 0 } else { next - (base + DOMAIN_HEAP_OFFSET) }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn claimed_in_domain(_domain: u8) -> u64 { 0 }

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
    pa:     u64,
    len:    usize,
    flags:  PtFlags,
) -> Result<u64, DomainAllocError> {
    if (domain as usize) >= NUM_DOMAINS {
        return Err(DomainAllocError::BadDomain);
    }
    let base = domain_va_base(domain).ok_or(DomainAllocError::BadDomain)?;
    let pages = (len + 0xFFF) >> 12;
    let bytes = (pages as u64) << 12;

    // Initialise the bump pointer on first use to base + offset.
    let slot = &NEXT_VA[domain as usize];
    let init = base + DOMAIN_HEAP_OFFSET;
    let _ = slot.compare_exchange(0, init, Ordering::Relaxed, Ordering::Relaxed);

    let va_base = slot.fetch_add(bytes, Ordering::Relaxed);
    // VA must stay inside the slot's 512-GiB range.
    let slot_end = base + (1u64 << 39);
    if va_base + bytes > slot_end {
        // Roll back the bump pointer.
        slot.fetch_sub(bytes, Ordering::Relaxed);
        return Err(DomainAllocError::OutOfRange);
    }

    // Map each 4 KiB page.
    for i in 0..pages {
        let va = VirtAddr::new(va_base + (i as u64) * 4096);
        let p  = PhysAddr::new(pa + (i as u64) * 4096);
        // SAFETY: caller-asserted pa validity; va is freshly bumped
        // (no prior mapping at it); flags chosen by caller.
        unsafe { map_domain_private(domain, va, p, flags)?; }
    }
    Ok(va_base)
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn claim_mmio_in_domain(
    _domain: u8,
    _pa:     u64,
    _len:    usize,
    _flags:  u64,
) -> Result<u64, DomainAllocError> {
    Err(DomainAllocError::UnsupportedArch)
}
