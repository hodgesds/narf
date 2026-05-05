//! Intel VT-d remap-engine register layout + caps decode.
//!
//! Spec: `arch/specification/iommu-interconnect.md` §1.
//!
//! v0.1 carries the read-only caps decode + the GCMD / GSTS
//! programming primitives. Higher-level bring-up (root-table
//! allocation, queued invalidation, fault-handling pipeline)
//! lives in `bus/iommu/intel`.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const VTD_VER:    usize = 0x00;
pub const VTD_CAP:    usize = 0x08;
pub const VTD_ECAP:   usize = 0x10;
pub const VTD_GCMD:   usize = 0x18;
pub const VTD_GSTS:   usize = 0x1C;
pub const VTD_RTADDR: usize = 0x20;
pub const VTD_CCMD:   usize = 0x28;
pub const VTD_FSTS:   usize = 0x40;
pub const VTD_FECTL:  usize = 0x44;
pub const VTD_PMEN:   usize = 0x60;

pub const GCMD_TE:    u32 = 1 << 31;
pub const GCMD_SRTP:  u32 = 1 << 30;
pub const GCMD_QIE:   u32 = 1 << 26;
pub const GCMD_IRE:   u32 = 1 << 25;
pub const GCMD_SIRTP: u32 = 1 << 24;

pub const GSTS_TES:    u32 = 1 << 31;
pub const GSTS_RTPS:   u32 = 1 << 30;
pub const GSTS_QIES:   u32 = 1 << 26;
pub const GSTS_IRES:   u32 = 1 << 25;
pub const GSTS_IRTPS:  u32 = 1 << 24;

#[derive(Copy, Clone, Debug, Default)]
pub struct VtdCaps {
    pub version_major:       u8,
    pub version_minor:       u8,
    pub num_domains:         u32,
    pub sagaw:               u8,
    pub num_fault_regs:      u16,
    pub queued_invalidation: bool,
    pub interrupt_remap:     bool,
}

unsafe fn r32(base: usize, off: usize) -> u32 {
    // SAFETY: caller-asserted MMIO mapping covers the offset.
    unsafe { read_volatile((base + off) as *const u32) }
}

unsafe fn r64(base: usize, off: usize) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { read_volatile((base + off) as *const u64) }
}

unsafe fn w32(base: usize, off: usize, v: u32) {
    // SAFETY: caller-asserted.
    unsafe { write_volatile((base + off) as *mut u32, v); }
}

unsafe fn w64(base: usize, off: usize, v: u64) {
    // SAFETY: caller-asserted.
    unsafe { write_volatile((base + off) as *mut u64, v); }
}

/// Decode the read-only caps registers at `reg_base`.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of a VT-d
/// engine register block.
pub unsafe fn read_caps(reg_base: usize) -> VtdCaps {
    // SAFETY: caller-asserted.
    let ver  = unsafe { r32(reg_base, VTD_VER) };
    let cap  = unsafe { r64(reg_base, VTD_CAP) };
    let ecap = unsafe { r64(reg_base, VTD_ECAP) };
    decode_caps(ver, cap, ecap)
}

/// Pure-data decode helper — useful for tests that supply
/// synthetic register values.
pub fn decode_caps(ver: u32, cap: u64, ecap: u64) -> VtdCaps {
    let nd = (cap & 0x7) as u32;
    VtdCaps {
        version_major:       ((ver >> 4) & 0xF) as u8,
        version_minor:       (ver & 0xF) as u8,
        num_domains:         1 << (4 + 2 * nd),       // SDM Vol 3 §10.4.2
        sagaw:               ((cap >> 8) & 0x1F) as u8,
        num_fault_regs:      (((cap >> 40) & 0xFF) + 1) as u16,
        queued_invalidation: (ecap & 0x2) != 0,
        interrupt_remap:     (ecap & 0x8) != 0,
    }
}

/// # Safety
/// `reg_base` is the engine's MMIO mapping.
pub unsafe fn read_gsts(reg_base: usize) -> u32 {
    // SAFETY: caller-asserted.
    unsafe { r32(reg_base, VTD_GSTS) }
}

pub unsafe fn write_gcmd(reg_base: usize, bits: u32) {
    // SAFETY: caller-asserted.
    unsafe { w32(reg_base, VTD_GCMD, bits); }
}

pub unsafe fn write_rtaddr(reg_base: usize, paddr: u64) {
    // SAFETY: caller-asserted.
    unsafe { w64(reg_base, VTD_RTADDR, paddr); }
}
