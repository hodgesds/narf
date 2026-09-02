//! ECAM segment mappings.
//!
//! PCIe configuration space is MMIO. It used to be reached by casting the
//! ACPI-described physical address straight to a pointer, which worked only
//! because the kernel identity-mapped low memory. That identity map is being
//! removed (it is what made ordinary `gcc -static` binaries unloadable, and
//! it silently absorbed a whole class of physical-address-dereference bugs),
//! so config space now goes through `ioremap` like any other device window.
//!
//! `BusDevice::cfg_phys` deliberately stays PHYSICAL: it is what firmware and
//! ACPI describe, and what gets handed back out in diagnostics. Translation
//! to a usable pointer happens here, at dereference time — the same split
//! Linux draws with `pci_ecam_map_bus()`.
//!
//! Segments are mapped once and looked up by a linear scan of at most
//! [`MAX_SEGMENTS`] entries, which is cheaper than the MMIO access it guards.

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::{ioremap, MmioAttrs};
use narf_memory::PhysAddr;

/// Firmware advertising more than this many ECAM segments is not something
/// this kernel has ever seen; the excess is refused rather than silently
/// left unmapped, so a config access can never fall back to a raw physical
/// dereference.
const MAX_SEGMENTS: usize = 8;

#[derive(Copy, Clone)]
struct Segment {
    phys: u64,
    virt: u64,
    len: u64,
}

static SEGMENTS: IrqSafeSpinLock<[Option<Segment>; MAX_SEGMENTS]> =
    IrqSafeSpinLock::new([None; MAX_SEGMENTS]);

/// Map an ECAM segment. Idempotent: a segment already covering `[base, base +
/// len)` is left alone, so repeated enumeration does not leak VA space.
///
/// # Safety
/// `base`/`len` must name a real ECAM window the caller owns.
pub unsafe fn map_segment(base: PhysAddr, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    let mut g = SEGMENTS.lock();
    for slot in g.iter().flatten() {
        if base.raw() >= slot.phys && base.raw() + len <= slot.phys + slot.len {
            return true;
        }
    }
    // SAFETY: caller's contract; ECAM is Device memory (uncached) — the
    // write-back direct map would be wrong for config space.
    let mapping = match unsafe { ioremap(base.raw(), len, MmioAttrs::Device) } {
        Ok(m) => m,
        Err(_) => return false,
    };
    for slot in g.iter_mut() {
        if slot.is_none() {
            *slot = Some(Segment {
                phys: base.raw(),
                virt: mapping.virt,
                len,
            });
            return true;
        }
    }
    false
}

/// Dereferenceable pointer for a config-space address, or `None` if no mapped
/// segment covers it.
///
/// Callers treat `None` as "no device" (all-ones), matching how a config read
/// of an absent slot already behaves. Returning `None` rather than falling
/// back to `phys as *mut _` is the point: a missing mapping must not silently
/// become a wild dereference.
#[inline]
/// Virtual address `phys` maps to inside its registered ECAM window,
/// or `None` if no segment covers it. Lets a caller rebase a whole
/// run of config-space arithmetic onto the mapped window once,
/// instead of translating every individual register offset.
pub fn va_for(phys: PhysAddr) -> Option<u64> {
    ptr_for(phys, 0).map(|p| p as u64)
}

pub fn ptr_for(phys: PhysAddr, offset: u64) -> Option<*mut u8> {
    let target = phys.raw().checked_add(offset)?;
    let g = SEGMENTS.lock();
    for slot in g.iter().flatten() {
        if target >= slot.phys && target < slot.phys + slot.len {
            return Some((slot.virt + (target - slot.phys)) as *mut u8);
        }
    }
    None
}

/// Test hook: forget every mapping so a unit test can re-register.
#[cfg(feature = "kernel-test")]
pub fn __reset_for_test() {
    *SEGMENTS.lock() = [None; MAX_SEGMENTS];
}
