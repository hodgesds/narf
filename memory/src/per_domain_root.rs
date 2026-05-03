//! Per-domain page-table root.
//!
//! Spec: `memory/specification/asid-pcid-isolation.md` §1.
//!
//! Each NARF domain owns a private user-half page-table root
//! (PML4 on x86_64, TTBR0 root on aarch64). The kernel half is
//! shared across all domain roots — `clone_kernel_half` copies
//! the upper-half PML4 entries (256..511) into a freshly
//! allocated root frame.
//!
//! On switch, the arch primitive writes CR3 / TTBR0_EL1 with the
//! domain's ASID/PCID tag (see `asid_alloc`). Switches are
//! non-flushing: TLB entries from the destination tag stay live.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::asid_alloc::{self, DomainTag, N_DOMAINS};

/// Allocator errors surfaced by `allocate_root`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
    NotInitialised,
    AlreadyAllocated,
}

#[derive(Copy, Clone, Debug)]
pub struct PerDomainRoot {
    pub domain:     DomainId,
    pub root_phys:  u64,
    pub generation: u64,
}

const NONE_ROOT: PerDomainRoot = PerDomainRoot {
    // SCRATCH (15) is the closest to a "no-domain" sentinel. The
    // entry is treated as empty by `present_for(domain)`.
    domain: DomainId::SCRATCH,
    root_phys: 0,
    generation: 0,
};

static ROOTS: IrqSafeSpinLock<[PerDomainRoot; N_DOMAINS]> =
    IrqSafeSpinLock::new([NONE_ROOT; N_DOMAINS]);

static INITIALISED: AtomicU8 = AtomicU8::new(0);

/// Mark the registry initialised. Done once during boot after
/// the frame allocator is up.
pub fn init() {
    INITIALISED.store(1, Ordering::Release);
}

fn ready() -> bool { INITIALISED.load(Ordering::Acquire) != 0 }

/// Register a previously-allocated root for `domain`. The caller
/// has run `clone_kernel_half(into)` on `root_phys`; this function
/// just records the mapping.
pub fn register_root(domain: DomainId, root_phys: u64) -> Result<PerDomainRoot, AllocError> {
    if !ready() { return Err(AllocError::NotInitialised); }
    let idx = domain.raw() as usize;
    if idx >= N_DOMAINS { return Err(AllocError::OutOfMemory); }
    let mut g = ROOTS.lock();
    if g[idx].root_phys != 0 {
        return Err(AllocError::AlreadyAllocated);
    }
    let tag = asid_alloc::alloc(domain);
    let r = PerDomainRoot {
        domain, root_phys,
        generation: tag.generation,
    };
    g[idx] = r;
    Ok(r)
}

/// Look up the registered root for `domain`. Returns `None` if
/// nothing was registered.
pub fn lookup(domain: DomainId) -> Option<PerDomainRoot> {
    let idx = domain.raw() as usize;
    if idx >= N_DOMAINS { return None; }
    let g = ROOTS.lock();
    if g[idx].root_phys == 0 { return None; }
    Some(g[idx])
}

/// Drop the registered root for `domain`. The caller is
/// responsible for freeing the underlying frame + invalidating
/// the per-domain tag.
pub fn unregister_root(domain: DomainId) {
    let idx = domain.raw() as usize;
    if idx >= N_DOMAINS { return; }
    let mut g = ROOTS.lock();
    g[idx] = NONE_ROOT;
    asid_alloc::invalidate_tag(domain);
}

/// `(tag, generation)` snapshot for `domain`. Returns
/// `(0, 0)` when no root is registered.
pub fn tag_for(domain: DomainId) -> DomainTag {
    asid_alloc::cached(domain).unwrap_or_else(|| asid_alloc::alloc(domain))
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = ROOTS.lock();
    for slot in g.iter_mut() { *slot = NONE_ROOT; }
    asid_alloc::__reset_for_test();
    INITIALISED.store(1, Ordering::Release);
}

// ── Switch primitive (arch-dispatched) ─────────────────────────────
//
// Spec: `memory/specification/asid-pcid-isolation.md` §1.3.

/// Switch the user-half page-table root to `root`. Non-flushing
/// when the target tag was alive at the same generation.
///
/// # Safety
/// CPL = 0 (EL1); the caller is on the BSP or holds the per-CPU
/// lock that serialises page-table switches.
#[cfg(target_arch = "x86_64")]
pub unsafe fn switch_to(root: &PerDomainRoot) {
    let tag = asid_alloc::pcid_for(root.domain);
    let cr3 = (root.root_phys & 0xFFFF_FFFF_FFFF_F000)
            | (tag as u64 & 0xFFF)
            | (1u64 << 63);  // NOFLUSH
    // SAFETY: caller-asserted.
    unsafe { narf_arch::x86_64::cr::write_cr3(cr3); }
}

/// aarch64 variant — TTBR0_EL1 carries (root_phys, ASID).
///
/// # Safety
/// EL1; same precondition as the x86 path.
#[cfg(target_arch = "aarch64")]
pub unsafe fn switch_to(root: &PerDomainRoot) {
    let tag = asid_alloc::asid_for(root.domain);
    // SAFETY: caller-asserted.
    unsafe {
        narf_arch::aarch64::sysreg::write_ttbr0_el1_with_asid(root.root_phys, tag);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn switch_to(_root: &PerDomainRoot) {}
