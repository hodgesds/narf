//! Linux gc_10_3_0 and mmhub_2_0_0 register headers, base index zero.
//! `inv_*` name invalidation engine 17 (the GART/CPU engine); `ctx` and the
//! page-table registers name context 0. Per-VMID strides match the hub init
//! functions: `ctx_distance` 1, `ctx_addr_distance` 2 (LO/HI pairs).
pub(super) const CTX_DISTANCE: u32 = 1; // linux: mmGCVM_CONTEXT1_CNTL@gc - mmGCVM_CONTEXT0_CNTL@gc
                                        // linux: mmGCVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32@gc - mmGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32@gc
pub(super) const CTX_ADDR_DISTANCE: u32 = 2;
#[derive(Clone, Copy, Debug)]
pub(super) struct HubRegs {
    pub fb_base: u32,
    /// MC_VM_FB_LOCATION_TOP: never consulted (Linux derives fb_end from
    /// MEMSIZE); kept so models can present a stale inherited value.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub fb_top: u32,
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
    pub fault_status: u32,
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
}
// linux-ctx: hdr=gc seg=0
pub(super) const GFX: HubRegs = HubRegs {
    fb_base: 0x16fc,         // linux: mmGCMC_VM_FB_LOCATION_BASE
    fb_top: 0x16fd,          // linux: mmGCMC_VM_FB_LOCATION_TOP
    agp_base: 0x1700,        // linux: mmGCMC_VM_AGP_BASE
    agp_bot: 0x16ff,         // linux: mmGCMC_VM_AGP_BOT
    agp_top: 0x16fe,         // linux: mmGCMC_VM_AGP_TOP
    sys_low: 0x1701,         // linux: mmGCMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x1702,        // linux: mmGCMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x16e8,  // linux: mmGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x16e9,  // linux: mmGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x1703,              // linux: mmGCMC_VM_MX_L1_TLB_CNTL
    l2: 0x15bc,              // linux: mmGCVM_L2_CNTL
    l2_2: 0x15bd,            // linux: mmGCVM_L2_CNTL2
    l2_3: 0x15be,            // linux: mmGCVM_L2_CNTL3
    l2_4: 0x15d4,            // linux: mmGCVM_L2_CNTL4
    l2_5: 0x15dc,            // linux: mmGCVM_L2_CNTL5
    fault_lo: 0x15cb,        // linux: mmGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x15cc,        // linux: mmGCVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x15c4,      // linux: mmGCVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x15c5,     // linux: mmGCVM_L2_PROTECTION_FAULT_CNTL2
    fault_status: 0x15c8,    // linux: mmGCVM_L2_PROTECTION_FAULT_STATUS
    ctx: 0x15fc,             // linux: mmGCVM_CONTEXT0_CNTL
    pt_base: 0x1667,         // linux: mmGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x1687,        // linux: mmGCVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x16a7,          // linux: mmGCVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x15ce,    // linux: mmGCVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x15d0,   // linux: mmGCVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x15d2, // linux: mmGCVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x1630,         // linux: mmGCVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x1642,         // linux: mmGCVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x161e,         // linux: mmGCVM_INVALIDATE_ENG17_SEM
    inv_range: 0x1643,       // linux: mmGCVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};
// linux-ctx: hdr=mmhub seg=0
pub(super) const MM: HubRegs = HubRegs {
    fb_base: 0x86c,         // linux: mmMMMC_VM_FB_LOCATION_BASE
    fb_top: 0x86d,          // linux: mmMMMC_VM_FB_LOCATION_TOP
    agp_base: 0x870,        // linux: mmMMMC_VM_AGP_BASE
    agp_bot: 0x86f,         // linux: mmMMMC_VM_AGP_BOT
    agp_top: 0x86e,         // linux: mmMMMC_VM_AGP_TOP
    sys_low: 0x871,         // linux: mmMMMC_VM_SYSTEM_APERTURE_LOW_ADDR
    sys_high: 0x872,        // linux: mmMMMC_VM_SYSTEM_APERTURE_HIGH_ADDR
    sys_default_lo: 0x858,  // linux: mmMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB
    sys_default_hi: 0x859,  // linux: mmMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB
    l1: 0x873,              // linux: mmMMMC_VM_MX_L1_TLB_CNTL
    l2: 0x680,              // linux: mmMMVM_L2_CNTL
    l2_2: 0x681,            // linux: mmMMVM_L2_CNTL2
    l2_3: 0x682,            // linux: mmMMVM_L2_CNTL3
    l2_4: 0x698,            // linux: mmMMVM_L2_CNTL4
    l2_5: 0x6a1,            // linux: mmMMVM_L2_CNTL5
    fault_lo: 0x68f,        // linux: mmMMVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_LO32
    fault_hi: 0x690,        // linux: mmMMVM_L2_PROTECTION_FAULT_DEFAULT_ADDR_HI32
    fault_cntl: 0x688,      // linux: mmMMVM_L2_PROTECTION_FAULT_CNTL
    fault_cntl2: 0x689,     // linux: mmMMVM_L2_PROTECTION_FAULT_CNTL2
    fault_status: 0x68c,    // linux: mmMMVM_L2_PROTECTION_FAULT_STATUS
    ctx: 0x6c0,             // linux: mmMMVM_CONTEXT0_CNTL
    pt_base: 0x72b,         // linux: mmMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32
    pt_start: 0x74b,        // linux: mmMMVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32
    pt_end: 0x76b,          // linux: mmMMVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32
    identity_low: 0x692,    // linux: mmMMVM_L2_CONTEXT1_IDENTITY_APERTURE_LOW_ADDR_LO32
    identity_high: 0x694,   // linux: mmMMVM_L2_CONTEXT1_IDENTITY_APERTURE_HIGH_ADDR_LO32
    identity_offset: 0x696, // linux: mmMMVM_L2_CONTEXT_IDENTITY_PHYSICAL_OFFSET_LO32
    inv_req: 0x6f4,         // linux: mmMMVM_INVALIDATE_ENG17_REQ
    inv_ack: 0x706,         // linux: mmMMVM_INVALIDATE_ENG17_ACK
    inv_sem: 0x6e2,         // linux: mmMMVM_INVALIDATE_ENG17_SEM
    inv_range: 0x707,       // linux: mmMMVM_INVALIDATE_ENG0_ADDR_RANGE_LO32
};
// linux-ctx: reset
