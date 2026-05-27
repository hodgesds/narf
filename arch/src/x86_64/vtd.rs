//! Intel VT-d remap-engine register layout + caps decode + the
//! root/context-entry, second-level page-table, and invalidation-
//! queue encoders.
//!
//! Spec: `arch/specification/iommu-interconnect.md` §1 + Intel
//! VT-d 4.1 §10. Cross-referenced against Linux
//! `drivers/iommu/intel/iommu.h` and `drivers/iommu/intel/iommu.c`
//! (GPL-2.0-or-later — see project relicense note 2026-05-20).
//!
//! v0.1 carried the read-only caps decode + the GCMD / GSTS
//! programming primitives. This pass adds the boot-time
//! programming surface a per-device IOMMU domain needs:
//!
//! - Root table (256 entries, one per bus)
//! - Context table (256 entries per bus, one per BDF on that bus)
//! - Second-level PTE (4K-page granularity)
//! - Invalidation queue descriptors (CC + IOTLB types)
//! - Enable-bit sequencing (`GCMD.TE` after `GSTS.RTPS`)

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const VTD_VER: usize = 0x00;
pub const VTD_CAP: usize = 0x08;
pub const VTD_ECAP: usize = 0x10;
pub const VTD_GCMD: usize = 0x18;
pub const VTD_GSTS: usize = 0x1C;
pub const VTD_RTADDR: usize = 0x20;
pub const VTD_CCMD: usize = 0x28;
pub const VTD_FSTS: usize = 0x40;
pub const VTD_FECTL: usize = 0x44;
pub const VTD_PMEN: usize = 0x60;

// Invalidation Queue + IRT regs (§10.4.23 - §10.4.27).
pub const VTD_IQH: usize = 0x80; // queue head
pub const VTD_IQT: usize = 0x88; // queue tail
pub const VTD_IQA: usize = 0x90; // queue address (base + size + width)
pub const VTD_ICS: usize = 0x9C; // invalidation completion status
pub const VTD_IRTA: usize = 0xB8; // interrupt-remapping table addr

pub const GCMD_TE: u32 = 1 << 31;
pub const GCMD_SRTP: u32 = 1 << 30;
pub const GCMD_QIE: u32 = 1 << 26;
pub const GCMD_IRE: u32 = 1 << 25;
pub const GCMD_SIRTP: u32 = 1 << 24;

pub const GSTS_TES: u32 = 1 << 31;
pub const GSTS_RTPS: u32 = 1 << 30;
pub const GSTS_QIES: u32 = 1 << 26;
pub const GSTS_IRES: u32 = 1 << 25;
pub const GSTS_IRTPS: u32 = 1 << 24;

/// VT-d always works in 4 KiB pages (§3.4).
pub const VTD_PAGE_SHIFT: u32 = 12;
pub const VTD_PAGE_SIZE: u64 = 1 << VTD_PAGE_SHIFT;
pub const VTD_PAGE_MASK: u64 = !((1 << VTD_PAGE_SHIFT) - 1);

// ── Root table entry (§9.1, 128 bits) ────────────────────────────
//
// Layout:
//   data[0] — low 64 bits
//     [0]      Present
//     [12..63] Context-Table Pointer (page-aligned)
//   data[1] — high 64 bits (reserved in legacy mode)
//
// A bus's root entry points at a 4 KiB context table holding 256
// 128-bit entries — one per (devfn) on that bus.

pub const ROOT_PRESENT: u64 = 1 << 0;
pub const ROOT_CTX_PTR_MASK: u64 = VTD_PAGE_MASK & 0x000F_FFFF_FFFF_FFFF;

/// 128-bit root-table entry.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RootEntry {
    pub lo: u64,
    pub hi: u64,
}

impl RootEntry {
    /// Build a present root entry pointing at a 4 KiB-aligned
    /// context-table base.
    pub const fn present(ctx_table_phys: u64) -> Self {
        RootEntry {
            lo: (ctx_table_phys & ROOT_CTX_PTR_MASK) | ROOT_PRESENT,
            hi: 0,
        }
    }

    pub const fn is_present(&self) -> bool {
        (self.lo & ROOT_PRESENT) != 0
    }

    pub const fn context_ptr(&self) -> u64 {
        self.lo & ROOT_CTX_PTR_MASK
    }
}

// ── Context entry (§9.3, 128 bits) ───────────────────────────────
//
// Layout (legacy DMA-remap mode):
//   lo:
//     [0]      Present
//     [1]      Fault-Processing Disable
//     [2..4]   Translation Type (00 = legacy 2nd-level, 02 = ID)
//     [12..63] Address Space Root (SLPT phys, page-aligned)
//   hi:
//     [0..3]   Address Width (000=30b, 001=39b, 010=48b, 011=57b, 100=64b)
//     [8..24]  Domain ID
//
// Per Linux: `context_set_present` writes bit 0 with dma_wmb()
// fencing, `context_set_translation_type` masks bits 2..4,
// `context_set_address_root` masks bits 12..52, etc.

pub const CTX_PRESENT: u64 = 1 << 0;
pub const CTX_FAULT_DISABLE: u64 = 1 << 1;
pub const CTX_TT_SHIFT: u32 = 2;
pub const CTX_TT_MASK: u64 = 0b11 << CTX_TT_SHIFT;
pub const CTX_ASR_MASK: u64 = VTD_PAGE_MASK & 0x000F_FFFF_FFFF_FFFF;

pub const CTX_AW_30BIT: u64 = 0;
pub const CTX_AW_39BIT: u64 = 1;
pub const CTX_AW_48BIT: u64 = 2;
pub const CTX_AW_57BIT: u64 = 3;
pub const CTX_AW_64BIT: u64 = 4;
pub const CTX_AW_MASK: u64 = 0b111;
pub const CTX_DID_SHIFT: u32 = 8;
pub const CTX_DID_MASK: u64 = 0xFFFF << CTX_DID_SHIFT;

pub const CTX_TT_LEGACY: u64 = 0; // legacy 2nd-level translation
pub const CTX_TT_DEV_TLB: u64 = 1; // legacy + device-IOTLB
pub const CTX_TT_PASSTHROUGH: u64 = 2; // hardware passthrough

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ContextEntry {
    pub lo: u64,
    pub hi: u64,
}

impl ContextEntry {
    /// Build a present, legacy-translation context entry. `slpt_phys`
    /// is the second-level page-table root (page-aligned). `agaw`
    /// is the address-width encoding (e.g. `CTX_AW_48BIT`).
    pub const fn legacy(slpt_phys: u64, domain_id: u16, agaw: u64) -> Self {
        let lo = CTX_PRESENT
            | (CTX_TT_LEGACY << CTX_TT_SHIFT)
            | (slpt_phys & CTX_ASR_MASK);
        let hi = (agaw & CTX_AW_MASK) | ((domain_id as u64) << CTX_DID_SHIFT);
        ContextEntry { lo, hi }
    }

    pub const fn passthrough(domain_id: u16) -> Self {
        let lo = CTX_PRESENT | (CTX_TT_PASSTHROUGH << CTX_TT_SHIFT);
        let hi = CTX_AW_48BIT | ((domain_id as u64) << CTX_DID_SHIFT);
        ContextEntry { lo, hi }
    }

    pub const fn is_present(&self) -> bool {
        (self.lo & CTX_PRESENT) != 0
    }

    pub const fn translation_type(&self) -> u64 {
        (self.lo & CTX_TT_MASK) >> CTX_TT_SHIFT
    }

    pub const fn address_space_root(&self) -> u64 {
        self.lo & CTX_ASR_MASK
    }

    pub const fn address_width(&self) -> u64 {
        self.hi & CTX_AW_MASK
    }

    pub const fn domain_id(&self) -> u16 {
        ((self.hi & CTX_DID_MASK) >> CTX_DID_SHIFT) as u16
    }
}

// ── Second-level PTE (§9.7) ──────────────────────────────────────
//
// 64 bits per entry, 512 per 4 KiB table — identical shape to host
// x86_64 PTEs except R/W are bits 0/1 (vs P/W in host PT).
//
//   [0]      R   Read permission
//   [1]      W   Write permission
//   [7]      Large page
//   [11]     SNP Snoop control
//   [12..52] Phys/Next-table addr (page-aligned)

pub const SL_PTE_READ: u64 = 1 << 0;
pub const SL_PTE_WRITE: u64 = 1 << 1;
pub const SL_PTE_LARGE: u64 = 1 << 7;
pub const SL_PTE_SNP: u64 = 1 << 11;
pub const SL_PTE_ADDR_MASK: u64 = VTD_PAGE_MASK & 0x000F_FFFF_FFFF_FFFF;

/// Build a leaf 4 KiB second-level PTE.
pub const fn sl_pte_leaf(phys: u64, read: bool, write: bool) -> u64 {
    let mut v = phys & SL_PTE_ADDR_MASK;
    if read {
        v |= SL_PTE_READ;
    }
    if write {
        v |= SL_PTE_WRITE;
    }
    v
}

/// Build a non-leaf (next-level pointer) PTE — same encoding but no
/// large-page bit and R/W permit walk-through.
pub const fn sl_pte_next(next_table: u64) -> u64 {
    (next_table & SL_PTE_ADDR_MASK) | SL_PTE_READ | SL_PTE_WRITE
}

pub const fn sl_pte_present(pte: u64) -> bool {
    (pte & (SL_PTE_READ | SL_PTE_WRITE)) != 0
}

pub const fn sl_pte_addr(pte: u64) -> u64 {
    pte & SL_PTE_ADDR_MASK
}

/// Slice an IOVA into the per-level index for a 48-bit / 4-level
/// walk. `level` 1 = lowest (4 KiB leaf), 4 = top.
pub const fn iova_level_index(iova: u64, level: u32) -> usize {
    let shift = VTD_PAGE_SHIFT + 9 * (level - 1);
    ((iova >> shift) & 0x1FF) as usize
}

// ── Invalidation queue descriptor encoders (§6.5) ────────────────
//
// QI descriptors are 128 bits (qw0, qw1). For boot we only need
// Context-Cache (CC) and IOTLB invalidates.
//
//   CC_TYPE = 1, IOTLB_TYPE = 2 (Linux QI_CC_TYPE / QI_IOTLB_TYPE).

pub const QI_CC_TYPE: u64 = 0x1;
pub const QI_IOTLB_TYPE: u64 = 0x2;
pub const QI_IEC_TYPE: u64 = 0x4;

/// Granularity field shared by CC and IOTLB descriptors:
///   1 = global (entire IOMMU)
///   2 = domain-selective
///   3 = device-selective (CC) / page-selective (IOTLB)
pub const QI_GRAN_GLOBAL: u64 = 1 << 4;
pub const QI_GRAN_DOMAIN: u64 = 2 << 4;
pub const QI_GRAN_PSI: u64 = 3 << 4;

/// 128-bit QI descriptor.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiDesc {
    pub qw0: u64,
    pub qw1: u64,
}

impl QiDesc {
    /// Context-cache invalidate. `gran` is one of `QI_GRAN_*`.
    /// `domain_id` is only meaningful for domain- or
    /// device-selective grans (high 16 bits of qw0 per §6.5.2.1).
    pub const fn cc_inv(gran: u64, domain_id: u16, source_id: u16) -> Self {
        let qw0 = QI_CC_TYPE
            | gran
            | ((domain_id as u64) << 16)
            | ((source_id as u64) << 32);
        QiDesc { qw0, qw1: 0 }
    }

    /// IOTLB invalidate. `gran` is one of `QI_GRAN_*`. `addr` is
    /// the page-selective IOVA (ignored for global / domain grans).
    pub const fn iotlb_inv(gran: u64, domain_id: u16, addr: u64) -> Self {
        let qw0 = QI_IOTLB_TYPE | gran | ((domain_id as u64) << 16);
        // qw1 holds Address / Address-Mask for page-selective grans.
        let qw1 = addr & VTD_PAGE_MASK;
        QiDesc { qw0, qw1 }
    }

    pub const fn ty(&self) -> u64 {
        self.qw0 & 0xF
    }

    pub const fn gran(&self) -> u64 {
        self.qw0 & 0x30
    }

    pub const fn domain_id(&self) -> u16 {
        ((self.qw0 >> 16) & 0xFFFF) as u16
    }
}

// ── IQA register encoding (§10.4.23) ─────────────────────────────
//
// IQA layout:
//   [0..3]   QS — queue size (entries = 256 << QS). 0 = 256 entries.
//   [11]     DW — 1 = 256-bit descriptors, 0 = 128-bit
//   [12..63] queue base (page-aligned)
pub const fn encode_iqa(base: u64, qs: u8, wide: bool) -> u64 {
    let mut v = base & VTD_PAGE_MASK;
    v |= (qs & 0x7) as u64;
    if wide {
        v |= 1 << 11;
    }
    v
}

pub const fn decode_iqa(iqa: u64) -> (u64, u8, bool) {
    let base = iqa & VTD_PAGE_MASK;
    let qs = (iqa & 0x7) as u8;
    let wide = (iqa & (1 << 11)) != 0;
    (base, qs, wide)
}

#[derive(Copy, Clone, Debug, Default)]
pub struct VtdCaps {
    pub version_major: u8,
    pub version_minor: u8,
    pub num_domains: u32,
    pub sagaw: u8,
    pub num_fault_regs: u16,
    pub queued_invalidation: bool,
    pub interrupt_remap: bool,
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
    unsafe {
        write_volatile((base + off) as *mut u32, v);
    }
}

unsafe fn w64(base: usize, off: usize, v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile((base + off) as *mut u64, v);
    }
}

/// Decode the read-only caps registers at `reg_base`.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of a VT-d
/// engine register block.
pub unsafe fn read_caps(reg_base: usize) -> VtdCaps {
    // SAFETY: caller-asserted.
    let ver = unsafe { r32(reg_base, VTD_VER) };
    let cap = unsafe { r64(reg_base, VTD_CAP) };
    let ecap = unsafe { r64(reg_base, VTD_ECAP) };
    decode_caps(ver, cap, ecap)
}

/// Pure-data decode helper — useful for tests that supply
/// synthetic register values.
pub fn decode_caps(ver: u32, cap: u64, ecap: u64) -> VtdCaps {
    let nd = (cap & 0x7) as u32;
    VtdCaps {
        version_major: ((ver >> 4) & 0xF) as u8,
        version_minor: (ver & 0xF) as u8,
        num_domains: 1 << (4 + 2 * nd), // SDM Vol 3 §10.4.2
        sagaw: ((cap >> 8) & 0x1F) as u8,
        num_fault_regs: (((cap >> 40) & 0xFF) + 1) as u16,
        queued_invalidation: (ecap & 0x2) != 0,
        interrupt_remap: (ecap & 0x8) != 0,
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
    unsafe {
        w32(reg_base, VTD_GCMD, bits);
    }
}

pub unsafe fn write_rtaddr(reg_base: usize, paddr: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, VTD_RTADDR, paddr);
    }
}
