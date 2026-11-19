//! LAPIC LVT-PC PMI vector binding.
//!
//! Spec: `arch/specification/cpu-info-errata.md` §4.
//!
//! Until LVT-PC is programmed + unmasked, PMU / LBR / Intel-PT
//! overflow events are silently masked. The PMU subsystem owns
//! the handler — this module only exposes the LVT-PC programming
//! primitive so the dependency graph stays one-way.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const LAPIC_LVT_PC_OFFSET: u32 = 0x340;

const LVT_DELIVERY_FIXED: u32 = 0b000 << 8;
const LVT_DELIVERY_NMI: u32 = 0b100 << 8;
const LVT_MASKED_BIT: u32 = 1 << 16;

unsafe fn lvt_addr(lapic_base: usize) -> *mut u32 {
    (lapic_base + LAPIC_LVT_PC_OFFSET as usize) as *mut u32
}

/// Program LVT-PC at `lapic_base + 0x340`.
///
/// `nmi = true` selects delivery mode 100 (NMI) — used when the
/// PMI must interrupt unconditionally. `masked = true` keeps the
/// entry inhibited until unmasked.
///
/// # Safety
/// CPL = 0; `lapic_base` is the local-APIC MMIO base for the
/// current CPU and the page is mapped strong-uncacheable.
#[inline]
pub unsafe fn program_lvt_pc(lapic_base: usize, vector: u8, nmi: bool, masked: bool) {
    let mut v = vector as u32;
    v |= if nmi {
        LVT_DELIVERY_NMI
    } else {
        LVT_DELIVERY_FIXED
    };
    v |= if masked { LVT_MASKED_BIT } else { 0 };
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile(lvt_addr(lapic_base), v);
    }
}

/// Mask the LVT-PC entry.
///
/// # Safety
/// As `program_lvt_pc`.
#[inline]
pub unsafe fn mask_lvt_pc(lapic_base: usize) {
    // SAFETY: caller-asserted.
    let cur = unsafe { read_volatile(lvt_addr(lapic_base)) };
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    unsafe {
        write_volatile(lvt_addr(lapic_base), cur | LVT_MASKED_BIT);
    }
}

/// Unmask the LVT-PC entry.
///
/// # Safety
/// `program_lvt_pc` has been called previously with a valid
/// vector; same constraints as `program_lvt_pc`.
#[inline]
pub unsafe fn unmask_lvt_pc(lapic_base: usize) {
    // SAFETY: caller-asserted.
    let cur = unsafe { read_volatile(lvt_addr(lapic_base)) };
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    unsafe {
        write_volatile(lvt_addr(lapic_base), cur & !LVT_MASKED_BIT);
    }
}
