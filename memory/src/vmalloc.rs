//! Kernel-VA allocator — hands out unbacked virtual address
//! ranges from a high-half cursor.
//!
//! Use case: mapping device BARs that fall outside the boot
//! identity map. ioremap (per-arch) calls `alloc(len)` here to
//! get a fresh kernel virtual range, then walks the active page
//! tables to install PTEs pointing at the device phys with the
//! appropriate device-memory attributes.
//!
//! Layout:
//!   * x86_64 — kernel VA space lives in the upper half. The
//!     vmalloc cursor starts at 0xFFFF_8800_0000_0000 (PML4
//!     slot 272 — bits 47:39 of that address are 0b1_0001_0000),
//!     well clear of:
//!       - the higher-half kernel image at PML4[511] (Stage 1 boot).
//!       - the per-driver-domain private slots 256..=271 we
//!         carved out for the PCID enforcer.
//!       - the upper user-mappable cursor at slot 256 (KPTI-style
//!         shared lower half, in case ASIDs ever come into play).
//!   * aarch64 — TTBR1 covers 0xFFFF_0000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF
//!     by convention; we pick a mid-TTBR1 range starting at
//!     0xFFFF_C000_0000_0000.
//!
//! No fragmentation handling yet. `alloc(len)` advances the
//! cursor monotonically; `free(range)` is a no-op for the bump
//! pointer. A real free list can land later when long-running
//! drivers actually exercise iounmap.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
const VMALLOC_BASE: u64 = 0xFFFF_8800_0000_0000;
#[cfg(target_arch = "aarch64")]
const VMALLOC_BASE: u64 = 0xFFFF_C000_0000_0000;

/// 4 GiB of vmalloc space — enough for any plausible BAR
/// allocation; trivial to bump if a driver wants more.
const VMALLOC_LIMIT: u64 = VMALLOC_BASE + (4u64 << 30);

static CURSOR: AtomicU64 = AtomicU64::new(VMALLOC_BASE);

/// A reserved kernel-VA range. Holders should keep it alive for
/// the lifetime of the mapping it backs (device BAR, etc.).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmRange {
    pub base: u64,
    pub len: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmallocError {
    /// Requested zero or non-page-aligned length.
    BadLen,
    /// Address space exhausted.
    Exhausted,
}

/// Allocate `len` bytes (rounded up to a page) of fresh kernel
/// VA. The returned range is unbacked — callers (ioremap,
/// vmap-style mappers) install PTEs themselves before
/// dereferencing.
pub fn alloc(len: u64) -> Result<VmRange, VmallocError> {
    let len_pg = (len + 0xFFF) & !0xFFFu64;
    if len_pg == 0 {
        return Err(VmallocError::BadLen);
    }
    // Bump-pointer atomic CAS so concurrent callers don't
    // overlap.
    loop {
        let cur = CURSOR.load(Ordering::Relaxed);
        let end = cur.checked_add(len_pg).ok_or(VmallocError::Exhausted)?;
        if end > VMALLOC_LIMIT {
            return Err(VmallocError::Exhausted);
        }
        match CURSOR.compare_exchange_weak(cur, end, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => {
                return Ok(VmRange {
                    base: cur,
                    len: len_pg,
                })
            }
            Err(_) => continue,
        }
    }
}

/// Free a previously-allocated range. Today's bump-pointer
/// allocator just drops the range on the floor — the cursor only
/// moves forward. iounmap callers still call this so the API
/// stays right when a real free list lands.
pub fn free(range: VmRange) {
    let _ = range;
}

/// Total bytes claimed since boot — diagnostic only.
pub fn claimed_bytes() -> u64 {
    CURSOR.load(Ordering::Relaxed) - VMALLOC_BASE
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    CURSOR.store(VMALLOC_BASE, Ordering::Relaxed);
}
