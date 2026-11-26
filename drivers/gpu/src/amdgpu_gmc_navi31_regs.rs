//! Navi31/32/33 (GC 11.0.x, MMHUB 3.0.0) and Strix Point (GC 11.5.0,
//! MMHUB 3.0.1/3.0.2) GMC register tables.
//!
//! Every offset below is quoted from Linux 7.4-rc2:
//!
//! - GFX hub, GC 11.5.0 (Strix Point): `gc_11_5_0_offset.h`. Every
//!   GCMC/GCVM register is 0x4 above the 11.0.0 table except `FB_OFFSET`
//!   and the system-aperture defaults; see `GFX_11_5_0`.
//! - MM hub, MMHUB 3.0.2: `mmhub_3_0_2_offset.h`. The whole block sits
//!   0x80 below the 3.0.0/3.0.1 table; see `MM_3_0_2`.
//!
//! - GFX hub, GC 11.0.0 (Navi31) and 11.0.2 (Navi33, which Linux drives
//!   with the 11.0.0 function table — `gmc_v11_0_set_gfxhub_funcs` selects
//!   `gfxhub_v3_0_funcs` for both):
//!   `drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_offset.h`.
//! - GFX hub, GC 11.0.3 (Navi32): `gc_11_0_3_offset.h`. The whole GCMC/GCVM
//!   block sits 0x10 higher than on 11.0.0 (FB_LOCATION_BASE 0x1688 vs
//!   0x1678, CONTEXT0_CNTL 0x1698 vs 0x1688, PT_BASE 0x1703 vs 0x16f3);
//!   the L2/fault block sits 0x4 higher (L2_CNTL 0x15c0 vs 0x15bc). The
//!   FB_OFFSET register is 0x15a7 on both, and the per-engine/per-context
//!   strides agree (REQ/ACK/SEM 1, ADDR_RANGE 2, PT_BASE 2, CNTL 1).
//! - MM hub, MMHUB 3.0.0 (all three Navi3x dies —
//!   `amdgpu_platform::MMHUB_WINDOWS` attributes `mmhub_3_0_0_offset.h` to
//!   Navi3x, and `gmc_v11_0_set_mmhub_funcs` gives 3.0.0 the default
//!   `mmhub_v3_0_funcs` table):
//!   `drivers/gpu/drm/amd/include/asic_reg/mmhub/mmhub_3_0_0_offset.h`.
//!   Its offsets agree with NARF's `amdgpu_vmhub_regs::MMHUB_V3_0` table
//!   (Phoenix, MMHUB 3.0.1) — 3.0.0 and 3.0.1 differ only in BASE_IDX,
//!   which discovery's `bank()` resolves, not in offsets.
//!
//! `inv_*` name invalidation engine 17 (the GART/CPU engine);
//! `ctx` and the page-table registers name context 0. The shape mirrors
//! `amdgpu_gmc_navi22_regs::HubRegs` so the owner programs both hubs with
//! one `program()`.

#[derive(Clone, Copy, Debug)]
pub(super) struct HubRegs {
    pub fb_base: u32,
    /// MC_VM_FB_LOCATION_TOP: never consulted (Linux derives fb_end from
    /// MEMSIZE); kept so models can present a stale inherited value.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub fb_top: u32,
    /// MC_VM_FB_OFFSET: the VRAM-address offset added to a pool address.
    pub fb_offset: u32,
    pub agp_base: u32,
    pub agp_bot: u32,
    pub agp_top: u32,
    pub sys_low: u32,
    pub sys_high: u32,
    pub sys_default_lo: u32,
    pub sys_default_hi: u32,
    pub l1: u32,
    pub l2: u32,
    pub l2_2: u32,
    pub l2_3: u32,
    pub l2_4: u32,
    pub l2_5: u32,
    pub fault_lo: u32,
    pub fault_hi: u32,
    pub fault_cntl: u32,
    pub fault_cntl2: u32,
    /// `vm_l2_bank_select_reserved_cid2`: the register Linux's
    /// `gmc_v11_0_flush_gpu_tlb` reads back and sets bit 25
    /// (`RESERVED_CACHE_PRIVATE_INVALIDATION`) on after an MMHUB flush.
    /// Only the MMHUB assignment exists in Linux (`mmhub_v3_0.c:508`);
    /// the GFX value is the header's register, unused by the flush.
    pub l2_bank_select: u32,
    pub ctx: u32,
    pub pt_base: u32,
    pub pt_start: u32,
    pub pt_end: u32,
    pub identity_low: u32,
    pub identity_high: u32,
    pub identity_offset: u32,
    pub inv_req: u32,
    pub inv_ack: u32,
    pub inv_sem: u32,
    pub inv_range: u32,
    /// `hub->eng_addr_distance`: INVALIDATE_ENG1_ADDR_RANGE_LO32 -
    /// INVALIDATE_ENG0_ADDR_RANGE_LO32.
    pub eng_addr_distance: u32,
}

// linux-ctx: hdr=gc_11_0_0 seg=0
pub(super) const GFX: HubRegs = HubRegs {
    fb_base: 0x1678,         // linux: regGCMC_VM_FB_LOCATION_BASE
    fb_top: 0x1679,          // linux: regGCMC_VM_FB_LOCATION_TOP
    fb_offset: 0x15a7,       // linux: regGCMC_VM_FB_OFFSET
    agp_base: 0x167c,        // linux: regGCMC_VM_AGP_BASE
    agp_bot: 0x167b,         // linux: regGCMC_VM_AGP_BOT
    agp_top: 0x167a,         // linux: regGCMC_VM_AGP_TOP
    sys_low: 0x167d,         // linux: regGCMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x167e,        // linux: regGCMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x15a8,  // linux: regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x15a9,  // linux: regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x167f,              // linux: regGCMC_VM_MX_L1_TLB_CNTL
    l2: 0x15bc,              // linux: regGCVM_L2_CNTL
    l2_2: 0x15bd,            // linux: regGCVM_L2_CNTL2
    l2_3: 0x15be,            // linux: regGCVM_L2_CNTL3
    l2_4: 0x15d4,            // linux: regGCVM_L2_CNTL4
    l2_5: 0x15da,            // linux: regGCVM_L2_CNTL5
    fault_lo: 0x15cb,        // linux: regGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x15cc,        // linux: regGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x15c4,      // linux: regGCVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x15c5,     // linux: regGCVM_L2_PROTECTION_FAULT_CNTL2
    l2_bank_select: 0x15d7,  // linux: regGCVM_L2_BANK_SELECT_RESERVED_CID2
    ctx: 0x1688,             // linux: regGCVM_CONTEXT0_CNTL
    pt_base: 0x16f3,         // linux: regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x1713,        // linux: regGCVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x1733,          // linux: regGCVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x15ce,    // linux: regGCVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x15d0,   // linux: regGCVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x15d2, // linux: regGCVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x16bc,         // linux: regGCVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x16ce,         // linux: regGCVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x16aa,         // linux: regGCVM_INVALIDATE_ENG17_SEM
    inv_range: 0x16cf,       // linux: regGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
    eng_addr_distance: 2, // linux: regGCVM_INVALIDATE_ENG1_ADDR_RANGE_LO32 - regGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};

// linux-ctx: hdr=gc_11_0_3 seg=0
/// Navi32 (GC 11.0.3): the same table shifted 0x10 in the GCMC/GCVM
/// block and 0x4 in the L2/fault block. FB_OFFSET is 0x15a7 here too.
pub(super) const GFX_11_0_3: HubRegs = HubRegs {
    fb_base: 0x1688,         // linux: regGCMC_VM_FB_LOCATION_BASE
    fb_top: 0x1689,          // linux: regGCMC_VM_FB_LOCATION_TOP
    fb_offset: 0x15a7,       // linux: regGCMC_VM_FB_OFFSET
    agp_base: 0x168c,        // linux: regGCMC_VM_AGP_BASE
    agp_bot: 0x168b,         // linux: regGCMC_VM_AGP_BOT
    agp_top: 0x168a,         // linux: regGCMC_VM_AGP_TOP
    sys_low: 0x168d,         // linux: regGCMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x168e,        // linux: regGCMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x15a8,  // linux: regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x15a9,  // linux: regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x168f,              // linux: regGCMC_VM_MX_L1_TLB_CNTL
    l2: 0x15c0,              // linux: regGCVM_L2_CNTL
    l2_2: 0x15c1,            // linux: regGCVM_L2_CNTL2
    l2_3: 0x15c2,            // linux: regGCVM_L2_CNTL3
    l2_4: 0x15d8,            // linux: regGCVM_L2_CNTL4
    l2_5: 0x15de,            // linux: regGCVM_L2_CNTL5
    fault_lo: 0x15cf,        // linux: regGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x15d0,        // linux: regGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x15c8,      // linux: regGCVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x15c9,     // linux: regGCVM_L2_PROTECTION_FAULT_CNTL2
    l2_bank_select: 0x15db,  // linux: regGCVM_L2_BANK_SELECT_RESERVED_CID2
    ctx: 0x1698,             // linux: regGCVM_CONTEXT0_CNTL
    pt_base: 0x1703,         // linux: regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x1723,        // linux: regGCVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x1743,          // linux: regGCVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x15d2,    // linux: regGCVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x15d4,   // linux: regGCVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x15d6, // linux: regGCVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x16cc,         // linux: regGCVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x16de,         // linux: regGCVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x16ba,         // linux: regGCVM_INVALIDATE_ENG17_SEM
    inv_range: 0x16df,       // linux: regGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
    eng_addr_distance: 2, // linux: regGCVM_INVALIDATE_ENG1_ADDR_RANGE_LO32 - regGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};

// linux-ctx: hdr=mmhub_3_0_0 seg=0
/// MMHUB 3.0.0, shared by all three Navi3x dies. BASE_IDX 0 (Phoenix's
/// 3.0.1 puts the same offsets on BASE_IDX 1 — discovery's `bank()`
/// resolves the base, so the offsets are shared).
pub(super) const MM: HubRegs = HubRegs {
    fb_base: 0x08ec,         // linux: regMMMC_VM_FB_LOCATION_BASE
    fb_top: 0x08ed,          // linux: regMMMC_VM_FB_LOCATION_TOP
    fb_offset: 0x08d7,       // linux: regMMMC_VM_FB_OFFSET
    agp_base: 0x08f0,        // linux: regMMMC_VM_AGP_BASE
    agp_bot: 0x08ef,         // linux: regMMMC_VM_AGP_BOT
    agp_top: 0x08ee,         // linux: regMMMC_VM_AGP_TOP
    sys_low: 0x08f1,         // linux: regMMMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x08f2,        // linux: regMMMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x08d8,  // linux: regMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x08d9,  // linux: regMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x08f3,              // linux: regMMMC_VM_MX_L1_TLB_CNTL
    l2: 0x0700,              // linux: regMMVM_L2_CNTL
    l2_2: 0x0701,            // linux: regMMVM_L2_CNTL2
    l2_3: 0x0702,            // linux: regMMVM_L2_CNTL3
    l2_4: 0x0718,            // linux: regMMVM_L2_CNTL4
    l2_5: 0x071e,            // linux: regMMVM_L2_CNTL5
    fault_lo: 0x070f,        // linux: regMMVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x0710,        // linux: regMMVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x0708,      // linux: regMMVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x0709,     // linux: regMMVM_L2_PROTECTION_FAULT_CNTL2
    l2_bank_select: 0x071b,  // linux: regMMVM_L2_BANK_SELECT_RESERVED_CID2
    ctx: 0x0740,             // linux: regMMVM_CONTEXT0_CNTL
    pt_base: 0x07ab,         // linux: regMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x07cb,        // linux: regMMVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x07eb,          // linux: regMMVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x0712,    // linux: regMMVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x0714,   // linux: regMMVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x0716, // linux: regMMVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x0774,         // linux: regMMVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x0786,         // linux: regMMVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x0762,         // linux: regMMVM_INVALIDATE_ENG17_SEM
    inv_range: 0x0787,       // linux: regMMVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
    eng_addr_distance: 2, // linux: regMMVM_INVALIDATE_ENG1_ADDR_RANGE_LO32 - regMMVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};
// linux-ctx: hdr=gc_11_5_0 seg=0
/// Strix Point (GC 11.5.0): the same table as 11.0.0 with every GCMC/GCVM
/// register 0x4 higher (`gc_11_5_0_offset.h` vs `gc_11_0_0_offset.h`),
/// except `FB_OFFSET` (0x15a7) and the system-aperture defaults
/// (0x15a8/0x15a9), which do not move. The per-engine/per-context strides
/// agree (REQ/ACK/SEM 1, ADDR_RANGE 2, PT_BASE 2, CNTL 1), and every
/// field mask/shift/value `program()` uses agrees between
/// `gc_11_0_0_sh_mask.h` and `gc_11_5_0_sh_mask.h`, so the literals carry
/// over unchanged.
pub(super) const GFX_11_5_0: HubRegs = HubRegs {
    fb_base: 0x167c,         // linux: regGCMC_VM_FB_LOCATION_BASE
    fb_top: 0x167d,          // linux: regGCMC_VM_FB_LOCATION_TOP
    fb_offset: 0x15a7,       // linux: regGCMC_VM_FB_OFFSET
    agp_base: 0x1680,        // linux: regGCMC_VM_AGP_BASE
    agp_bot: 0x167f,         // linux: regGCMC_VM_AGP_BOT
    agp_top: 0x167e,         // linux: regGCMC_VM_AGP_TOP
    sys_low: 0x1681,         // linux: regGCMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x1682,        // linux: regGCMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x15a8,  // linux: regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x15a9,  // linux: regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x1683,              // linux: regGCMC_VM_MX_L1_TLB_CNTL
    l2: 0x15c0,              // linux: regGCVM_L2_CNTL
    l2_2: 0x15c1,            // linux: regGCVM_L2_CNTL2
    l2_3: 0x15c2,            // linux: regGCVM_L2_CNTL3
    l2_4: 0x15d8,            // linux: regGCVM_L2_CNTL4
    l2_5: 0x15de,            // linux: regGCVM_L2_CNTL5
    fault_lo: 0x15cf,        // linux: regGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x15d0,        // linux: regGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x15c8,      // linux: regGCVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x15c9,     // linux: regGCVM_L2_PROTECTION_FAULT_CNTL2
    l2_bank_select: 0x15db,  // linux: regGCVM_L2_BANK_SELECT_RESERVED_CID2
    ctx: 0x168c,             // linux: regGCVM_CONTEXT0_CNTL
    pt_base: 0x16f7,         // linux: regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x1717,        // linux: regGCVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x1737,          // linux: regGCVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x15d2,    // linux: regGCVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x15d4,   // linux: regGCVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x15d6, // linux: regGCVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x16c0,         // linux: regGCVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x16d2,         // linux: regGCVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x16ae,         // linux: regGCVM_INVALIDATE_ENG17_SEM
    inv_range: 0x16d3,       // linux: regGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
    eng_addr_distance: 2, // linux: regGCVM_INVALIDATE_ENG1_ADDR_RANGE_LO32 - regGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};

// linux-ctx: hdr=mmhub_3_0_2 seg=0
/// MMHUB 3.0.2: the whole block sits 0x80 lower than 3.0.0/3.0.1
/// (`mmhub_3_0_2_offset.h`), on BASE_IDX 0. The field masks/shifts/values
/// `program()` uses agree across `mmhub_3_0_0_sh_mask.h`,
/// `mmhub_3_0_1_sh_mask.h` and `mmhub_3_0_2_sh_mask.h`, and the L2
/// defaults agree in `mmhub_v3_0_2.c:33-35` (`mmhub_v3_0_1.c:33-35`),
/// so the literals carry over unchanged.
pub(super) const MM_3_0_2: HubRegs = HubRegs {
    fb_base: 0x086c,         // linux: regMMMC_VM_FB_LOCATION_BASE
    fb_top: 0x086d,          // linux: regMMMC_VM_FB_LOCATION_TOP
    fb_offset: 0x0857,       // linux: regMMMC_VM_FB_OFFSET
    agp_base: 0x0870,        // linux: regMMMC_VM_AGP_BASE
    agp_bot: 0x086f,         // linux: regMMMC_VM_AGP_BOT
    agp_top: 0x086e,         // linux: regMMMC_VM_AGP_TOP
    sys_low: 0x0871,         // linux: regMMMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x0872,        // linux: regMMMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x0858,  // linux: regMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x0859,  // linux: regMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x0873,              // linux: regMMMC_VM_MX_L1_TLB_CNTL
    l2: 0x0680,              // linux: regMMVM_L2_CNTL
    l2_2: 0x0681,            // linux: regMMVM_L2_CNTL2
    l2_3: 0x0682,            // linux: regMMVM_L2_CNTL3
    l2_4: 0x0698,            // linux: regMMVM_L2_CNTL4
    l2_5: 0x069e,            // linux: regMMVM_L2_CNTL5
    fault_lo: 0x068f,        // linux: regMMVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x0690,        // linux: regMMVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x0688,      // linux: regMMVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x0689,     // linux: regMMVM_L2_PROTECTION_FAULT_CNTL2
    l2_bank_select: 0x069b,  // linux: regMMVM_L2_BANK_SELECT_RESERVED_CID2
    ctx: 0x06c0,             // linux: regMMVM_CONTEXT0_CNTL
    pt_base: 0x072b,         // linux: regMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x074b,        // linux: regMMVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x076b,          // linux: regMMVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x0692,    // linux: regMMVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x0694,   // linux: regMMVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x0696, // linux: regMMVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x06f4,         // linux: regMMVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x0706,         // linux: regMMVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x06e2,         // linux: regMMVM_INVALIDATE_ENG17_SEM
    inv_range: 0x0707,       // linux: regMMVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
    eng_addr_distance: 2, // linux: regMMVM_INVALIDATE_ENG1_ADDR_RANGE_LO32 - regMMVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};
// linux-ctx: reset
