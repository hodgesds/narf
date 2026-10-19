//! GC 10.3.2 register offsets used by the Navi22 kernel queues. Linux
//! gfx_v10_0.c includes gc_10_1_0_offset.h plus its local `_Sienna_Cichlid`
//! overrides; sdma_v5_2.c includes gc_10_3_0_offset.h. Every value below was
//! resolved from those exact headers and matches gc_10_3_0 wherever both
//! define it. NBIO offsets are nbio_2_3_offset.h, BASE_IDX 2.
#![allow(dead_code)]
/// (GC BASE_IDX, dword offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reg(pub u8, pub u32);

// GRBM / CAM (gfx_v10_0_constants_init, setup_grbm_cam_remapping)
pub const GRBM_CNTL: Reg = Reg(0, 0x0da0); // linux: mmGRBM_CNTL@gc101
pub const GRBM_SOFT_RESET: Reg = Reg(0, 0x0da8); // linux: mmGRBM_SOFT_RESET@gc101
pub const GRBM_GFX_CNTL: Reg = Reg(0, 0x0dc2); // linux: mmGRBM_GFX_CNTL@gc101
pub const GRBM_GFX_INDEX: Reg = Reg(1, 0x2200); // linux: mmGRBM_GFX_INDEX@gc101
pub const GRBM_CAM_INDEX: Reg = Reg(1, 0x5a04); // linux: mmGRBM_CAM_INDEX@gc101
pub const GRBM_CAM_DATA: Reg = Reg(1, 0x5a05); // linux: mmGRBM_CAM_DATA@gc101
pub const GRBM_CAM_DATA_UPPER: Reg = Reg(1, 0x5a06); // linux: mmGRBM_CAM_DATA_UPPER@gc101
/// (UMD alias, Sienna_Cichlid target) in setup_grbm_cam_remapping order.
pub const CAM_REMAP: [(Reg, Reg); 7] = [
    // linux: mmVGT_TF_RING_SIZE_UMD@gc101; mmVGT_TF_RING_SIZE_Sienna_Cichlid@gc101
    (Reg(1, 0x224e), Reg(0, 0x0fc3)),
    // linux: mmVGT_TF_MEMORY_BASE_UMD@gc101; mmVGT_TF_MEMORY_BASE_Sienna_Cichlid@gc101
    (Reg(1, 0x2250), Reg(0, 0x0fc5)),
    // linux: mmVGT_TF_MEMORY_BASE_HI_UMD@gc101; mmVGT_TF_MEMORY_BASE_HI_Sienna_Cichlid@gc101
    (Reg(1, 0x2261), Reg(0, 0x0fc6)),
    // linux: mmVGT_HS_OFFCHIP_PARAM_UMD@gc101; mmVGT_HS_OFFCHIP_PARAM_Sienna_Cichlid@gc101
    (Reg(1, 0x224f), Reg(0, 0x0fc4)),
    // linux: mmVGT_ESGS_RING_SIZE_UMD@gc101; mmVGT_ESGS_RING_SIZE_Sienna_Cichlid@gc101
    (Reg(1, 0x2240), Reg(0, 0x0fc1)),
    // linux: mmVGT_GSVS_RING_SIZE_UMD@gc101; mmVGT_GSVS_RING_SIZE_Sienna_Cichlid@gc101
    (Reg(1, 0x2241), Reg(0, 0x0fc2)),
    // linux: mmSPI_CONFIG_CNTL_REMAP@gc101; mmSPI_CONFIG_CNTL_Sienna_Cichlid@gc101
    (Reg(1, 0x2440), Reg(0, 0x11ec)),
];
pub const VGT_ESGS_RING_SIZE_UMD: Reg = CAM_REMAP[4].0;
pub const VGT_ESGS_RING_SIZE: Reg = CAM_REMAP[4].1;

// Shader memory apertures and GDS (constants_init, init_compute/gds_vmid)
pub const SH_MEM_BASES: Reg = Reg(0, 0x10aa); // linux: mmSH_MEM_BASES@gc101
pub const SH_MEM_CONFIG: Reg = Reg(0, 0x10ad); // linux: mmSH_MEM_CONFIG@gc101
pub const GDS_VMID0_BASE: Reg = Reg(0, 0x20a0); // linux: mmGDS_VMID0_BASE@gc101
pub const GDS_VMID0_SIZE: Reg = Reg(0, 0x20a1); // linux: mmGDS_VMID0_SIZE@gc101
pub const GDS_GWS_VMID0: Reg = Reg(0, 0x20c0); // linux: mmGDS_GWS_VMID0@gc101
pub const GDS_OA_VMID0: Reg = Reg(0, 0x20d0); // linux: mmGDS_OA_VMID0@gc101
pub const SPI_GDBG_TRAP_CONFIG: Reg = Reg(0, 0x1f72); // linux: mmSPI_GDBG_TRAP_CONFIG@gc101
pub const SPI_GDBG_TRAP_MASK: Reg = Reg(0, 0x1f73); // linux: mmSPI_GDBG_TRAP_MASK@gc101
pub const SPI_GDBG_TRAP_DATA0: Reg = Reg(0, 0x1f78); // linux: mmSPI_GDBG_TRAP_DATA0@gc101
pub const SPI_GDBG_TRAP_DATA1: Reg = Reg(0, 0x1f79); // linux: mmSPI_GDBG_TRAP_DATA1@gc101

// RLC (rlc_resume with PSP autoload, kiq_setting)
pub const RLC_SPM_MC_CNTL: Reg = Reg(1, 0x4c71); // linux: mmRLC_SPM_MC_CNTL@gc101
pub const RLC_SRM_CNTL: Reg = Reg(1, 0x4c80); // linux: mmRLC_SRM_CNTL@gc101
                                              // linux: mmRLC_CP_SCHEDULERS_Sienna_Cichlid@gc101
pub const RLC_CP_SCHEDULERS: Reg = Reg(1, 0x4ca1);
pub const RLC_CSIB_ADDR_LO: Reg = Reg(1, 0x4ca2); // linux: mmRLC_CSIB_ADDR_LO@gc101
pub const RLC_CSIB_ADDR_HI: Reg = Reg(1, 0x4ca3); // linux: mmRLC_CSIB_ADDR_HI@gc101
pub const RLC_CSIB_LENGTH: Reg = Reg(1, 0x4ca4); // linux: mmRLC_CSIB_LENGTH@gc101
pub const RLC_RLCS_BOOTLOAD_STATUS: Reg = Reg(1, 0x4e8d); // linux: mmRLC_RLCS_BOOTLOAD_STATUS@gc101
pub const SCRATCH_REG0: Reg = Reg(1, 0x2040); // linux: mmSCRATCH_REG0@gc101

// CP gfx (cp_gfx_resume, cp_gfx_start, cp_gfx_set_doorbell)
pub const CP_STAT: Reg = Reg(0, 0x0f40); // linux: mmCP_STAT@gc101
pub const CP_MEC_CNTL: Reg = Reg(0, 0x0f55); // linux: mmCP_MEC_CNTL_Sienna_Cichlid@gc101
pub const CP_ME_CNTL: Reg = Reg(0, 0x0f56); // linux: mmCP_ME_CNTL@gc101
pub const CP_RB0_RPTR: Reg = Reg(0, 0x0f60); // linux: mmCP_RB0_RPTR@gc101
pub const CP_RB_WPTR_DELAY: Reg = Reg(0, 0x0f61); // linux: mmCP_RB_WPTR_DELAY@gc101
pub const CP_RB0_BASE: Reg = Reg(0, 0x1de0); // linux: mmCP_RB0_BASE@gc101
pub const CP_RB0_CNTL: Reg = Reg(0, 0x1de1); // linux: mmCP_RB0_CNTL@gc101
pub const CP_RB0_RPTR_ADDR: Reg = Reg(0, 0x1de3); // linux: mmCP_RB0_RPTR_ADDR@gc101
pub const CP_RB0_RPTR_ADDR_HI: Reg = Reg(0, 0x1de4); // linux: mmCP_RB0_RPTR_ADDR_HI@gc101
pub const CP_DEVICE_ID: Reg = Reg(0, 0x1deb); // linux: mmCP_DEVICE_ID@gc101
pub const CP_RB_VMID: Reg = Reg(0, 0x1df1); // linux: mmCP_RB_VMID@gc101
pub const CP_RB0_WPTR: Reg = Reg(0, 0x1df4); // linux: mmCP_RB0_WPTR@gc101
pub const CP_RB0_WPTR_HI: Reg = Reg(0, 0x1df5); // linux: mmCP_RB0_WPTR_HI@gc101
                                                // linux: mmCP_RB_DOORBELL_RANGE_LOWER@gc101
pub const CP_RB_DOORBELL_RANGE_LOWER: Reg = Reg(0, 0x1dfa);
// linux: mmCP_RB_DOORBELL_RANGE_UPPER@gc101
pub const CP_RB_DOORBELL_RANGE_UPPER: Reg = Reg(0, 0x1dfb);
// linux: mmCP_MEC_DOORBELL_RANGE_LOWER@gc101
pub const CP_MEC_DOORBELL_RANGE_LOWER: Reg = Reg(0, 0x1dfc);
// linux: mmCP_MEC_DOORBELL_RANGE_UPPER@gc101
pub const CP_MEC_DOORBELL_RANGE_UPPER: Reg = Reg(0, 0x1dfd);
pub const CP_INT_CNTL_RING0: Reg = Reg(0, 0x1e0a); // linux: mmCP_INT_CNTL_RING0@gc101
pub const CP_INT_CNTL_RING1: Reg = Reg(0, 0x1e0b); // linux: mmCP_INT_CNTL_RING1@gc101
pub const CP_ME1_PIPE0_INT_CNTL: Reg = Reg(0, 0x1e25); // linux: mmCP_ME1_PIPE0_INT_CNTL@gc101
pub const CP_MAX_CONTEXT: Reg = Reg(0, 0x1e4e); // linux: mmCP_MAX_CONTEXT@gc101
pub const CP_RB0_BASE_HI: Reg = Reg(0, 0x1e51); // linux: mmCP_RB0_BASE_HI@gc101
pub const CP_RB_WPTR_POLL_ADDR_LO: Reg = Reg(0, 0x1e8b); // linux: mmCP_RB_WPTR_POLL_ADDR_LO@gc101
pub const CP_RB_WPTR_POLL_ADDR_HI: Reg = Reg(0, 0x1e8c); // linux: mmCP_RB_WPTR_POLL_ADDR_HI@gc101
pub const CP_RB_DOORBELL_CONTROL: Reg = Reg(0, 0x1e8d); // linux: mmCP_RB_DOORBELL_CONTROL@gc101
pub const CP_RB_ACTIVE: Reg = Reg(0, 0x1f40); // linux: mmCP_RB_ACTIVE@gc101

// MEC HQD, GRBM-selected (kiq_init_register, compute_mqd_init)
pub const CP_PQ_WPTR_POLL_CNTL: Reg = Reg(0, 0x1e23); // linux: mmCP_PQ_WPTR_POLL_CNTL@gc101
pub const CP_PQ_STATUS: Reg = Reg(0, 0x1e58); // linux: mmCP_PQ_STATUS@gc101
pub const CP_MQD_BASE_ADDR: Reg = Reg(0, 0x1fa9); // linux: mmCP_MQD_BASE_ADDR@gc101
pub const CP_MQD_BASE_ADDR_HI: Reg = Reg(0, 0x1faa); // linux: mmCP_MQD_BASE_ADDR_HI@gc101
pub const CP_HQD_ACTIVE: Reg = Reg(0, 0x1fab); // linux: mmCP_HQD_ACTIVE@gc101
pub const CP_HQD_VMID: Reg = Reg(0, 0x1fac); // linux: mmCP_HQD_VMID@gc101
pub const CP_HQD_PERSISTENT_STATE: Reg = Reg(0, 0x1fad); // linux: mmCP_HQD_PERSISTENT_STATE@gc101
pub const CP_HQD_PQ_BASE: Reg = Reg(0, 0x1fb1); // linux: mmCP_HQD_PQ_BASE@gc101
pub const CP_HQD_PQ_BASE_HI: Reg = Reg(0, 0x1fb2); // linux: mmCP_HQD_PQ_BASE_HI@gc101
pub const CP_HQD_PQ_RPTR: Reg = Reg(0, 0x1fb3); // linux: mmCP_HQD_PQ_RPTR@gc101
                                                // linux: mmCP_HQD_PQ_RPTR_REPORT_ADDR@gc101
pub const CP_HQD_PQ_RPTR_REPORT_ADDR: Reg = Reg(0, 0x1fb4);
// linux: mmCP_HQD_PQ_RPTR_REPORT_ADDR_HI@gc101
pub const CP_HQD_PQ_RPTR_REPORT_ADDR_HI: Reg = Reg(0, 0x1fb5);
pub const CP_HQD_PQ_WPTR_POLL_ADDR: Reg = Reg(0, 0x1fb6); // linux: mmCP_HQD_PQ_WPTR_POLL_ADDR@gc101
                                                          // linux: mmCP_HQD_PQ_WPTR_POLL_ADDR_HI@gc101
pub const CP_HQD_PQ_WPTR_POLL_ADDR_HI: Reg = Reg(0, 0x1fb7);
// linux: mmCP_HQD_PQ_DOORBELL_CONTROL@gc101
pub const CP_HQD_PQ_DOORBELL_CONTROL: Reg = Reg(0, 0x1fb8);
pub const CP_HQD_PQ_CONTROL: Reg = Reg(0, 0x1fba); // linux: mmCP_HQD_PQ_CONTROL@gc101
pub const CP_HQD_IB_CONTROL: Reg = Reg(0, 0x1fbe); // linux: mmCP_HQD_IB_CONTROL@gc101
pub const CP_HQD_DEQUEUE_REQUEST: Reg = Reg(0, 0x1fc1); // linux: mmCP_HQD_DEQUEUE_REQUEST@gc101
pub const CP_MQD_CONTROL: Reg = Reg(0, 0x1fcb); // linux: mmCP_MQD_CONTROL@gc101
pub const CP_HQD_EOP_BASE_ADDR: Reg = Reg(0, 0x1fce); // linux: mmCP_HQD_EOP_BASE_ADDR@gc101
pub const CP_HQD_EOP_BASE_ADDR_HI: Reg = Reg(0, 0x1fcf); // linux: mmCP_HQD_EOP_BASE_ADDR_HI@gc101
pub const CP_HQD_EOP_CONTROL: Reg = Reg(0, 0x1fd0); // linux: mmCP_HQD_EOP_CONTROL@gc101
pub const CP_HQD_PQ_WPTR_LO: Reg = Reg(0, 0x1fdf); // linux: mmCP_HQD_PQ_WPTR_LO@gc101
pub const CP_HQD_PQ_WPTR_HI: Reg = Reg(0, 0x1fe0); // linux: mmCP_HQD_PQ_WPTR_HI@gc101

// SDMA 5.2 instance 0; sdma_v5_2_get_reg_offset adds SDMA1_REG_OFFSET.
pub const SDMA1_REG_OFFSET: u32 = 0x600; // linux: SDMA1_REG_OFFSET
pub const SDMA3_REG_OFFSET: u32 = 0x400; // linux: SDMA3_REG_OFFSET
pub const SDMA0_CNTL: Reg = Reg(0, 0x001c); // linux: mmSDMA0_CNTL@gc
                                            // linux: mmSDMA0_SEM_WAIT_FAIL_TIMER_CNTL@gc
pub const SDMA0_SEM_WAIT_FAIL_TIMER_CNTL: Reg = Reg(0, 0x0021);
pub const SDMA0_STATUS_REG: Reg = Reg(0, 0x0025); // linux: mmSDMA0_STATUS_REG@gc
pub const SDMA0_F32_CNTL: Reg = Reg(0, 0x002a); // linux: mmSDMA0_F32_CNTL@gc
pub const SDMA0_PHASE0_QUANTUM: Reg = Reg(0, 0x002c); // linux: mmSDMA0_PHASE0_QUANTUM@gc
pub const SDMA0_PHASE1_QUANTUM: Reg = Reg(0, 0x002d); // linux: mmSDMA0_PHASE1_QUANTUM@gc
pub const SDMA0_UTCL1_CNTL: Reg = Reg(0, 0x003c); // linux: mmSDMA0_UTCL1_CNTL@gc
pub const SDMA0_UTCL1_PAGE: Reg = Reg(0, 0x0048); // linux: mmSDMA0_UTCL1_PAGE@gc
pub const SDMA0_PHASE2_QUANTUM: Reg = Reg(0, 0x004f); // linux: mmSDMA0_PHASE2_QUANTUM@gc
pub const SDMA0_GFX_RB_CNTL: Reg = Reg(0, 0x0080); // linux: mmSDMA0_GFX_RB_CNTL@gc
pub const SDMA0_GFX_RB_BASE: Reg = Reg(0, 0x0081); // linux: mmSDMA0_GFX_RB_BASE@gc
pub const SDMA0_GFX_RB_BASE_HI: Reg = Reg(0, 0x0082); // linux: mmSDMA0_GFX_RB_BASE_HI@gc
pub const SDMA0_GFX_RB_RPTR: Reg = Reg(0, 0x0083); // linux: mmSDMA0_GFX_RB_RPTR@gc
pub const SDMA0_GFX_RB_RPTR_HI: Reg = Reg(0, 0x0084); // linux: mmSDMA0_GFX_RB_RPTR_HI@gc
pub const SDMA0_GFX_RB_WPTR: Reg = Reg(0, 0x0085); // linux: mmSDMA0_GFX_RB_WPTR@gc
pub const SDMA0_GFX_RB_WPTR_HI: Reg = Reg(0, 0x0086); // linux: mmSDMA0_GFX_RB_WPTR_HI@gc
                                                      // linux: mmSDMA0_GFX_RB_WPTR_POLL_CNTL@gc
pub const SDMA0_GFX_RB_WPTR_POLL_CNTL: Reg = Reg(0, 0x0087);
pub const SDMA0_GFX_RB_RPTR_ADDR_HI: Reg = Reg(0, 0x0088); // linux: mmSDMA0_GFX_RB_RPTR_ADDR_HI@gc
pub const SDMA0_GFX_RB_RPTR_ADDR_LO: Reg = Reg(0, 0x0089); // linux: mmSDMA0_GFX_RB_RPTR_ADDR_LO@gc
pub const SDMA0_GFX_IB_CNTL: Reg = Reg(0, 0x008a); // linux: mmSDMA0_GFX_IB_CNTL@gc
pub const SDMA0_GFX_DOORBELL: Reg = Reg(0, 0x0092); // linux: mmSDMA0_GFX_DOORBELL@gc
pub const SDMA0_GFX_DOORBELL_OFFSET: Reg = Reg(0, 0x00ab); // linux: mmSDMA0_GFX_DOORBELL_OFFSET@gc
                                                           // linux: mmSDMA0_GFX_RB_WPTR_POLL_ADDR_HI@gc
pub const SDMA0_GFX_RB_WPTR_POLL_ADDR_HI: Reg = Reg(0, 0x00b2);
// linux: mmSDMA0_GFX_RB_WPTR_POLL_ADDR_LO@gc
pub const SDMA0_GFX_RB_WPTR_POLL_ADDR_LO: Reg = Reg(0, 0x00b3);
// linux: mmSDMA0_GFX_MINOR_PTR_UPDATE@gc
pub const SDMA0_GFX_MINOR_PTR_UPDATE: Reg = Reg(0, 0x00b5);
/// Highest GC BASE_IDX 0 / 1 dword offsets touched (bank bound checks).
pub const LAST_GC0: u32 = 0x20df; // linux: mmGDS_OA_VMID15@gc101
pub const LAST_GC1: u32 = 0x5a06; // linux: mmGRBM_CAM_DATA_UPPER@gc101

// NBIO 2.3 BASE_IDX 2 (nbio_v2_3.c, nv.c)
// linux-ctx: hdr=nbio seg=2
pub const NBIO_DOORBELL_APER_EN: u32 = 0x00c0; // linux: mmRCC_DEV0_EPF0_RCC_DOORBELL_APER_EN
                                               // linux: mmBIF_BX_PF_DOORBELL_SELFRING_GPA_APER_BASE_HIGH
pub const NBIO_SELFRING_BASE_HIGH: u32 = 0x00f3;
// linux: mmBIF_BX_PF_DOORBELL_SELFRING_GPA_APER_BASE_LOW
pub const NBIO_SELFRING_BASE_LOW: u32 = 0x00f4;
pub const NBIO_SELFRING_CNTL: u32 = 0x00f5; // linux: mmBIF_BX_PF_DOORBELL_SELFRING_GPA_APER_CNTL
pub const NBIO_SDMA0_DOORBELL_RANGE: u32 = 0x01d0; // linux: mmBIF_SDMA0_DOORBELL_RANGE
pub const NBIO_SDMA1_DOORBELL_RANGE: u32 = 0x01d1; // linux: mmBIF_SDMA1_DOORBELL_RANGE
pub const NBIO_SDMA2_DOORBELL_RANGE: u32 = 0x01d6; // linux: mmBIF_SDMA2_DOORBELL_RANGE
pub const NBIO_SDMA3_DOORBELL_RANGE: u32 = 0x01d7; // linux: mmBIF_SDMA3_DOORBELL_RANGE
pub const NBIO_REMAP_HDP_MEM_FLUSH_CNTL: u32 = 0x012d; // linux: mmREMAP_HDP_MEM_FLUSH_CNTL
pub const LAST_NBIO: u32 = 0x01d1; // linux: mmBIF_SDMA1_DOORBELL_RANGE
                                   // linux-ctx: reset

// gfx_v10_3_set_power_brake_sequence (gc_10_3_0_offset.h, BASE_IDX 0;
// GC_THROTTLE_CTRL is gfx_v10_0.c's mmGC_THROTTLE_CTRL_Sienna_Cichlid).
pub const DIDT_IND_INDEX: Reg = Reg(0, 0x2020); // linux: mmDIDT_IND_INDEX@gc101
pub const DIDT_IND_DATA: Reg = Reg(0, 0x2021); // linux: mmDIDT_IND_DATA@gc101
pub const GC_THROTTLE_CTRL: Reg = Reg(0, 0x2030); // linux: mmGC_THROTTLE_CTRL_Sienna_Cichlid@gc101
pub const GC_CAC_IND_INDEX: Reg = Reg(0, 0x203c); // linux: mmGC_CAC_IND_INDEX@gc101
pub const GC_CAC_IND_DATA: Reg = Reg(0, 0x203d); // linux: mmGC_CAC_IND_DATA@gc101
/// Indirect ixPWRBRK_STALL_PATTERN_CTRL / ixDIDT_SQ_THROTTLE_CTRL.
pub const IX_PWRBRK_STALL_PATTERN_CTRL: u32 = 0x0001; // linux: ixPWRBRK_STALL_PATTERN_CTRL@gc101
pub const IX_DIDT_SQ_THROTTLE_CTRL: u32 = 0x001a; // linux: ixDIDT_SQ_THROTTLE_CTRL@gc101
/// PWRBRK_STEP_INTERVAL 1, BEGIN_STEP 0x12 (<<10), END_STEP 0x13 (<<15),
/// THROTTLE_PATTERN_BIT_NUMS 0xf (<<20).
// linux: (0x1 << PWRBRK_STALL_PATTERN_CTRL__PWRBRK_STEP_INTERVAL__SHIFT@gc101) | (0x12 << PWRBRK_STALL_PATTERN_CTRL__PWRBRK_BEGIN_STEP__SHIFT@gc101) | (0x13 << PWRBRK_STALL_PATTERN_CTRL__PWRBRK_END_STEP__SHIFT@gc101) | (0xf << PWRBRK_STALL_PATTERN_CTRL__PWRBRK_THROTTLE_PATTERN_BIT_NUMS__SHIFT@gc101)
pub const PWRBRK_STALL_PATTERN: u32 = 1 | (0x12 << 10) | (0x13 << 15) | (0xf << 20);
/// PWRBRK_STALL_EN (<<2), PATTERN_MODE (<<5), RELEASE_STEP_INTERVAL 5 (<<13).
// linux: (0x1 << GC_THROTTLE_CTRL__PWRBRK_STALL_EN__SHIFT@gc101) | (0x1 << GC_THROTTLE_CTRL__PATTERN_MODE__SHIFT@gc101) | (0x5 << GC_THROTTLE_CTRL__RELEASE_STEP_INTERVAL__SHIFT@gc101)
pub const PWRBRK_THROTTLE: u32 = (1 << 2) | (1 << 5) | (5 << 13);
/// DIDT_SQ_THROTTLE_CTRL.PWRBRK_STALL_EN (<<2).
// linux: 0x1 << DIDT_SQ_THROTTLE_CTRL__PWRBRK_STALL_EN__SHIFT@gc101
pub const PWRBRK_DIDT_SQ: u32 = 1 << 2;

/// golden_settings_gc_10_3_2: (register, and_mask, or_mask).
/// Compatibility view of the shared Navi22 sequence for existing model tests.
pub const GOLDEN: [(Reg, u32, u32); 42] = {
    let source = crate::amdgpu_rdna2::golden::NAVI22;
    assert!(source.len() == 42);
    let mut rows = [(Reg(0, 0), 0, 0); 42];
    let mut index = 0;
    while index < rows.len() {
        let row = source[index];
        rows[index] = (Reg(row.base_index, row.offset), row.and_mask, row.or_mask);
        index += 1;
    }
    rows
};
