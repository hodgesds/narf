//! aarch64 SMMUv3 register layout + caps decode.
//!
//! Spec: `arch/specification/iommu-interconnect.md` §4.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const SMMU_IDR0:        usize = 0x00;
pub const SMMU_IDR1:        usize = 0x04;
pub const SMMU_IDR2:        usize = 0x08;
pub const SMMU_IDR3:        usize = 0x0C;
pub const SMMU_IDR4:        usize = 0x10;
pub const SMMU_IDR5:        usize = 0x14;
pub const SMMU_CR0:         usize = 0x20;
pub const SMMU_CR0_ACK:     usize = 0x24;
pub const SMMU_CR1:         usize = 0x28;
pub const SMMU_CR2:         usize = 0x2C;
pub const SMMU_GBPA:        usize = 0x44;
pub const SMMU_STRTAB_BASE: usize = 0x80;
pub const SMMU_STRTAB_BASE_CFG: usize = 0x88;

pub const CR0_SMMUEN:  u32 = 1 << 0;
pub const CR0_PRIQEN:  u32 = 1 << 1;
pub const CR0_EVENTQEN:u32 = 1 << 2;
pub const CR0_CMDQEN:  u32 = 1 << 3;
pub const CR0_ATSCHK:  u32 = 1 << 4;

#[derive(Copy, Clone, Debug, Default)]
pub struct SmmuCaps {
    pub s2p:    bool,
    pub s1p:    bool,
    pub ttf16:  bool,
    pub ttf64:  bool,
    pub oas:    u8,
    pub sid_width: u8,
    pub queue_base_share: u8,
}

unsafe fn r32(base: usize, off: usize) -> u32 {
    // SAFETY: caller-asserted MMIO mapping.
    unsafe { read_volatile((base + off) as *const u32) }
}

unsafe fn w32(base: usize, off: usize, v: u32) {
    // SAFETY: caller-asserted.
    unsafe { write_volatile((base + off) as *mut u32, v); }
}

unsafe fn w64(base: usize, off: usize, v: u64) {
    // SAFETY: caller-asserted.
    unsafe { write_volatile((base + off) as *mut u64, v); }
}

/// Decode the read-only IDR caps at `reg_base`.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of an SMMUv3
/// register block.
pub unsafe fn read_caps(reg_base: usize) -> SmmuCaps {
    // SAFETY: caller-asserted.
    let idr0 = unsafe { r32(reg_base, SMMU_IDR0) };
    let idr1 = unsafe { r32(reg_base, SMMU_IDR1) };
    let idr5 = unsafe { r32(reg_base, SMMU_IDR5) };
    decode_caps(idr0, idr1, idr5)
}

/// Pure-data decoder for tests.
pub fn decode_caps(idr0: u32, idr1: u32, idr5: u32) -> SmmuCaps {
    // IDR0 bits per Arm IHI 0070:
    //   [0]  = S2P
    //   [1]  = S1P
    //   [11:10] = TTF (granule support: 01 = 4K only, 10 = +16K, 11 = +16K+64K)
    //   [13:12] = QUEUE_*SH share
    let ttf  = (idr0 >> 10) & 0x3;
    SmmuCaps {
        s2p:    idr0 & 1 != 0,
        s1p:    idr0 & 2 != 0,
        ttf16:  ttf >= 0b10,
        ttf64:  ttf == 0b11,
        oas:    (idr5 & 0x7) as u8,
        // IDR1 [5:0] = SIDSIZE
        sid_width: (idr1 & 0x3F) as u8,
        queue_base_share: ((idr0 >> 12) & 0x3) as u8,
    }
}

/// # Safety
/// `reg_base` is the engine's MMIO mapping.
pub unsafe fn read_cr0(reg_base: usize) -> u32 {
    // SAFETY: caller-asserted.
    unsafe { r32(reg_base, SMMU_CR0) }
}

pub unsafe fn write_cr0(reg_base: usize, v: u32) {
    // SAFETY: caller-asserted.
    unsafe { w32(reg_base, SMMU_CR0, v); }
}

pub unsafe fn write_strtab_base(reg_base: usize, paddr: u64, cfg: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, SMMU_STRTAB_BASE,     paddr);
        w64(reg_base, SMMU_STRTAB_BASE_CFG, cfg);
    }
}
