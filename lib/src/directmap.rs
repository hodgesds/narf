//! Direct-map offset — the one place crates that sit below `narf-memory`
//! in the dependency graph can turn a physical address into a
//! kernel-reachable one.
//!
//! `narf-memory` owns the mapping and publishes the offset here once the
//! high-half direct map is live; everyone else only reads it. Crates like
//! `narf-arch`, `narf-firmware`, and `narf-initramfs` cannot depend on
//! `narf-memory` (it depends on them), so before this existed each one
//! grew its own copy of the offset.
//!
//! OR, not add, mirroring [`narf_memory::PhysAddr::kernel_ptr`]: it is
//! idempotent if handed an address that already carries the base, and
//! before activation the offset is 0, so early boot transparently gets
//! the identity address it expects.

use core::sync::atomic::{AtomicU64, Ordering};

static PHYS_TO_VIRT: AtomicU64 = AtomicU64::new(0);

/// Publish the physical-to-virtual offset. Called once by `narf-memory`
/// after the direct map is live, before anything walks firmware tables
/// or DMA buffers through it.
pub fn set_offset(offset: u64) {
    PHYS_TO_VIRT.store(offset, Ordering::Release);
}

/// The published offset, or 0 while the direct map is not yet live.
#[inline]
pub fn offset() -> u64 {
    PHYS_TO_VIRT.load(Ordering::Acquire)
}

/// Kernel-reachable address for a physical one.
#[inline]
pub fn pv(phys: u64) -> u64 {
    phys | offset()
}

/// Kernel-reachable pointer for a physical address.
#[inline]
pub fn pv_ptr<T>(phys: u64) -> *mut T {
    pv(phys) as *mut T
}
