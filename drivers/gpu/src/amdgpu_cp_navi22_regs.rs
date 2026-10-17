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
pub const GRBM_CNTL: Reg = Reg(0, 0x0da0);
pub const GRBM_SOFT_RESET: Reg = Reg(0, 0x0da8);
pub const GRBM_GFX_CNTL: Reg = Reg(0, 0x0dc2);
pub const GRBM_GFX_INDEX: Reg = Reg(1, 0x2200);
pub const GRBM_CAM_INDEX: Reg = Reg(1, 0x5a04);
pub const GRBM_CAM_DATA: Reg = Reg(1, 0x5a05);
pub const GRBM_CAM_DATA_UPPER: Reg = Reg(1, 0x5a06);
/// (UMD alias, Sienna_Cichlid target) in setup_grbm_cam_remapping order.
pub const CAM_REMAP: [(Reg, Reg); 7] = [
    (Reg(1, 0x224e), Reg(0, 0x0fc3)), // VGT_TF_RING_SIZE
    (Reg(1, 0x2250), Reg(0, 0x0fc5)), // VGT_TF_MEMORY_BASE
    (Reg(1, 0x2261), Reg(0, 0x0fc6)), // VGT_TF_MEMORY_BASE_HI
    (Reg(1, 0x224f), Reg(0, 0x0fc4)), // VGT_HS_OFFCHIP_PARAM
    (Reg(1, 0x2240), Reg(0, 0x0fc1)), // VGT_ESGS_RING_SIZE
    (Reg(1, 0x2241), Reg(0, 0x0fc2)), // VGT_GSVS_RING_SIZE
    (Reg(1, 0x2440), Reg(0, 0x11ec)), // SPI_CONFIG_CNTL
];
pub const VGT_ESGS_RING_SIZE_UMD: Reg = CAM_REMAP[4].0;
pub const VGT_ESGS_RING_SIZE: Reg = CAM_REMAP[4].1;

// Shader memory apertures and GDS (constants_init, init_compute/gds_vmid)
pub const SH_MEM_BASES: Reg = Reg(0, 0x10aa);
pub const SH_MEM_CONFIG: Reg = Reg(0, 0x10ad);
pub const GDS_VMID0_BASE: Reg = Reg(0, 0x20a0);
pub const GDS_VMID0_SIZE: Reg = Reg(0, 0x20a1);
pub const GDS_GWS_VMID0: Reg = Reg(0, 0x20c0);
pub const GDS_OA_VMID0: Reg = Reg(0, 0x20d0);
pub const SPI_GDBG_TRAP_CONFIG: Reg = Reg(0, 0x1f72);
pub const SPI_GDBG_TRAP_MASK: Reg = Reg(0, 0x1f73);
pub const SPI_GDBG_TRAP_DATA0: Reg = Reg(0, 0x1f78);
pub const SPI_GDBG_TRAP_DATA1: Reg = Reg(0, 0x1f79);

// RLC (rlc_resume with PSP autoload, kiq_setting)
pub const RLC_SPM_MC_CNTL: Reg = Reg(1, 0x4c71);
pub const RLC_SRM_CNTL: Reg = Reg(1, 0x4c80);
pub const RLC_CP_SCHEDULERS: Reg = Reg(1, 0x4ca1);
pub const RLC_CSIB_ADDR_LO: Reg = Reg(1, 0x4ca2);
pub const RLC_CSIB_ADDR_HI: Reg = Reg(1, 0x4ca3);
pub const RLC_CSIB_LENGTH: Reg = Reg(1, 0x4ca4);
pub const RLC_RLCS_BOOTLOAD_STATUS: Reg = Reg(1, 0x4e8d);
pub const SCRATCH_REG0: Reg = Reg(1, 0x2040);

// CP gfx (cp_gfx_resume, cp_gfx_start, cp_gfx_set_doorbell)
pub const CP_STAT: Reg = Reg(0, 0x0f40);
pub const CP_MEC_CNTL: Reg = Reg(0, 0x0f55); // _Sienna_Cichlid
pub const CP_ME_CNTL: Reg = Reg(0, 0x0f56);
pub const CP_RB0_RPTR: Reg = Reg(0, 0x0f60);
pub const CP_RB_WPTR_DELAY: Reg = Reg(0, 0x0f61);
pub const CP_RB0_BASE: Reg = Reg(0, 0x1de0);
pub const CP_RB0_CNTL: Reg = Reg(0, 0x1de1);
pub const CP_RB0_RPTR_ADDR: Reg = Reg(0, 0x1de3);
pub const CP_RB0_RPTR_ADDR_HI: Reg = Reg(0, 0x1de4);
pub const CP_DEVICE_ID: Reg = Reg(0, 0x1deb);
pub const CP_RB_VMID: Reg = Reg(0, 0x1df1);
pub const CP_RB0_WPTR: Reg = Reg(0, 0x1df4);
pub const CP_RB0_WPTR_HI: Reg = Reg(0, 0x1df5);
pub const CP_RB_DOORBELL_RANGE_LOWER: Reg = Reg(0, 0x1dfa);
pub const CP_RB_DOORBELL_RANGE_UPPER: Reg = Reg(0, 0x1dfb);
pub const CP_MEC_DOORBELL_RANGE_LOWER: Reg = Reg(0, 0x1dfc);
pub const CP_MEC_DOORBELL_RANGE_UPPER: Reg = Reg(0, 0x1dfd);
pub const CP_INT_CNTL_RING0: Reg = Reg(0, 0x1e0a);
pub const CP_INT_CNTL_RING1: Reg = Reg(0, 0x1e0b);
pub const CP_ME1_PIPE0_INT_CNTL: Reg = Reg(0, 0x1e25);
pub const CP_MAX_CONTEXT: Reg = Reg(0, 0x1e4e);
pub const CP_RB0_BASE_HI: Reg = Reg(0, 0x1e51);
pub const CP_RB_WPTR_POLL_ADDR_LO: Reg = Reg(0, 0x1e8b);
pub const CP_RB_WPTR_POLL_ADDR_HI: Reg = Reg(0, 0x1e8c);
pub const CP_RB_DOORBELL_CONTROL: Reg = Reg(0, 0x1e8d);
pub const CP_RB_ACTIVE: Reg = Reg(0, 0x1f40);

// MEC HQD, GRBM-selected (kiq_init_register, compute_mqd_init)
pub const CP_PQ_WPTR_POLL_CNTL: Reg = Reg(0, 0x1e23);
pub const CP_PQ_STATUS: Reg = Reg(0, 0x1e58);
pub const CP_MQD_BASE_ADDR: Reg = Reg(0, 0x1fa9);
pub const CP_MQD_BASE_ADDR_HI: Reg = Reg(0, 0x1faa);
pub const CP_HQD_ACTIVE: Reg = Reg(0, 0x1fab);
pub const CP_HQD_VMID: Reg = Reg(0, 0x1fac);
pub const CP_HQD_PERSISTENT_STATE: Reg = Reg(0, 0x1fad);
pub const CP_HQD_PQ_BASE: Reg = Reg(0, 0x1fb1);
pub const CP_HQD_PQ_BASE_HI: Reg = Reg(0, 0x1fb2);
pub const CP_HQD_PQ_RPTR: Reg = Reg(0, 0x1fb3);
pub const CP_HQD_PQ_RPTR_REPORT_ADDR: Reg = Reg(0, 0x1fb4);
pub const CP_HQD_PQ_RPTR_REPORT_ADDR_HI: Reg = Reg(0, 0x1fb5);
pub const CP_HQD_PQ_WPTR_POLL_ADDR: Reg = Reg(0, 0x1fb6);
pub const CP_HQD_PQ_WPTR_POLL_ADDR_HI: Reg = Reg(0, 0x1fb7);
pub const CP_HQD_PQ_DOORBELL_CONTROL: Reg = Reg(0, 0x1fb8);
pub const CP_HQD_PQ_CONTROL: Reg = Reg(0, 0x1fba);
pub const CP_HQD_IB_CONTROL: Reg = Reg(0, 0x1fbe);
pub const CP_HQD_DEQUEUE_REQUEST: Reg = Reg(0, 0x1fc1);
pub const CP_MQD_CONTROL: Reg = Reg(0, 0x1fcb);
pub const CP_HQD_EOP_BASE_ADDR: Reg = Reg(0, 0x1fce);
pub const CP_HQD_EOP_BASE_ADDR_HI: Reg = Reg(0, 0x1fcf);
pub const CP_HQD_EOP_CONTROL: Reg = Reg(0, 0x1fd0);
pub const CP_HQD_PQ_WPTR_LO: Reg = Reg(0, 0x1fdf);
pub const CP_HQD_PQ_WPTR_HI: Reg = Reg(0, 0x1fe0);

// SDMA 5.2 instance 0; sdma_v5_2_get_reg_offset adds SDMA1_REG_OFFSET.
pub const SDMA1_REG_OFFSET: u32 = 0x600;
pub const SDMA0_CNTL: Reg = Reg(0, 0x001c);
pub const SDMA0_SEM_WAIT_FAIL_TIMER_CNTL: Reg = Reg(0, 0x0021);
pub const SDMA0_STATUS_REG: Reg = Reg(0, 0x0025);
pub const SDMA0_F32_CNTL: Reg = Reg(0, 0x002a);
pub const SDMA0_PHASE0_QUANTUM: Reg = Reg(0, 0x002c);
pub const SDMA0_PHASE1_QUANTUM: Reg = Reg(0, 0x002d);
pub const SDMA0_UTCL1_CNTL: Reg = Reg(0, 0x003c);
pub const SDMA0_UTCL1_PAGE: Reg = Reg(0, 0x0048);
pub const SDMA0_PHASE2_QUANTUM: Reg = Reg(0, 0x004f);
pub const SDMA0_GFX_RB_CNTL: Reg = Reg(0, 0x0080);
pub const SDMA0_GFX_RB_BASE: Reg = Reg(0, 0x0081);
pub const SDMA0_GFX_RB_BASE_HI: Reg = Reg(0, 0x0082);
pub const SDMA0_GFX_RB_RPTR: Reg = Reg(0, 0x0083);
pub const SDMA0_GFX_RB_RPTR_HI: Reg = Reg(0, 0x0084);
pub const SDMA0_GFX_RB_WPTR: Reg = Reg(0, 0x0085);
pub const SDMA0_GFX_RB_WPTR_HI: Reg = Reg(0, 0x0086);
pub const SDMA0_GFX_RB_WPTR_POLL_CNTL: Reg = Reg(0, 0x0087);
pub const SDMA0_GFX_RB_RPTR_ADDR_HI: Reg = Reg(0, 0x0088);
pub const SDMA0_GFX_RB_RPTR_ADDR_LO: Reg = Reg(0, 0x0089);
pub const SDMA0_GFX_IB_CNTL: Reg = Reg(0, 0x008a);
pub const SDMA0_GFX_DOORBELL: Reg = Reg(0, 0x0092);
pub const SDMA0_GFX_DOORBELL_OFFSET: Reg = Reg(0, 0x00ab);
pub const SDMA0_GFX_RB_WPTR_POLL_ADDR_HI: Reg = Reg(0, 0x00b2);
pub const SDMA0_GFX_RB_WPTR_POLL_ADDR_LO: Reg = Reg(0, 0x00b3);
pub const SDMA0_GFX_MINOR_PTR_UPDATE: Reg = Reg(0, 0x00b5);
/// Highest GC BASE_IDX 0 / 1 dword offsets touched (bank bound checks).
pub const LAST_GC0: u32 = 0x20df; // GDS_OA_VMID15
pub const LAST_GC1: u32 = 0x5a06;

// NBIO 2.3 BASE_IDX 2 (nbio_v2_3.c, nv.c)
pub const NBIO_DOORBELL_APER_EN: u32 = 0x00c0; // RCC_DEV0_EPF0_RCC_DOORBELL_APER_EN
pub const NBIO_SELFRING_BASE_HIGH: u32 = 0x00f3;
pub const NBIO_SELFRING_BASE_LOW: u32 = 0x00f4;
pub const NBIO_SELFRING_CNTL: u32 = 0x00f5;
pub const NBIO_SDMA0_DOORBELL_RANGE: u32 = 0x01d0;
pub const NBIO_SDMA1_DOORBELL_RANGE: u32 = 0x01d1;
pub const NBIO_REMAP_HDP_MEM_FLUSH_CNTL: u32 = 0x012d;
pub const LAST_NBIO: u32 = 0x01d1;

// gfx_v10_3_set_power_brake_sequence (gc_10_3_0_offset.h, BASE_IDX 0;
// GC_THROTTLE_CTRL is gfx_v10_0.c's mmGC_THROTTLE_CTRL_Sienna_Cichlid).
pub const DIDT_IND_INDEX: Reg = Reg(0, 0x2020);
pub const DIDT_IND_DATA: Reg = Reg(0, 0x2021);
pub const GC_THROTTLE_CTRL: Reg = Reg(0, 0x2030);
pub const GC_CAC_IND_INDEX: Reg = Reg(0, 0x203c);
pub const GC_CAC_IND_DATA: Reg = Reg(0, 0x203d);
/// Indirect ixPWRBRK_STALL_PATTERN_CTRL / ixDIDT_SQ_THROTTLE_CTRL.
pub const IX_PWRBRK_STALL_PATTERN_CTRL: u32 = 0x0001;
pub const IX_DIDT_SQ_THROTTLE_CTRL: u32 = 0x001a;
/// PWRBRK_STEP_INTERVAL 1, BEGIN_STEP 0x12 (<<10), END_STEP 0x13 (<<15),
/// THROTTLE_PATTERN_BIT_NUMS 0xf (<<20).
pub const PWRBRK_STALL_PATTERN: u32 = 1 | (0x12 << 10) | (0x13 << 15) | (0xf << 20);
/// PWRBRK_STALL_EN (<<2), PATTERN_MODE (<<5), RELEASE_STEP_INTERVAL 5 (<<13).
pub const PWRBRK_THROTTLE: u32 = (1 << 2) | (1 << 5) | (5 << 13);
/// DIDT_SQ_THROTTLE_CTRL.PWRBRK_STALL_EN (<<2).
pub const PWRBRK_DIDT_SQ: u32 = 1 << 2;

/// golden_settings_gc_10_3_2: (register, and_mask, or_mask).
pub const GOLDEN: [(Reg, u32, u32); 42] = [
    (Reg(1, 0x507c), 0xff7f0fff, 0x78000100), // CGTT_SPI_CS_CLK_CTRL
    (Reg(1, 0x507d), 0xff7f0fff, 0x78000100), // CGTT_SPI_PS_CLK_CTRL
    (Reg(1, 0x507a), 0xff7f0fff, 0x30000100), // CGTT_SPI_RA0_CLK_CTRL
    (Reg(1, 0x507b), 0xff7f0fff, 0x7e000100), // CGTT_SPI_RA1_CLK_CTRL
    (Reg(0, 0x1f53), 0x0007ffff, 0x0000c000), // CPF_GCR_CNTL
    (Reg(0, 0x13ae), 0xffffffff, 0x00000280), // DB_DEBUG3
    (Reg(0, 0x13af), 0xffffffff, 0x00800000), // DB_DEBUG4
    (Reg(0, 0x13bf), 0x7fff0f1f, 0x00b80000), // DB_EXCEPTION_CONTROL
    (Reg(0, 0x1580), 0x1ff1ffff, 0x00000500), // GCR_GENERAL_CNTL_Sienna_Cichlid
    (Reg(0, 0x16f3), 0xffffffff, 0xff008080), // GCUTCL2_CGTT_CLK_CTRL_Sienna_Cichlid
    (Reg(0, 0x15db), 0xffff8fff, 0xff008080), // GCVM_L2_CGTT_CLK_CTRL_Sienna_Cichlid
    (Reg(0, 0x0fe5), 0x003fffff, 0x00280400), // GE_PC_CNTL
    (Reg(1, 0x2e21), 0xffffffff, 0xffffffcf), // GL2A_ADDR_MATCH_MASK
    (Reg(1, 0x2e03), 0xffffffff, 0xffffffcf), // GL2C_ADDR_MATCH_MASK
    (Reg(1, 0x2e08), 0xff8fff0f, 0x580f1008), // GL2C_CM_CTRL1
    (Reg(1, 0x2e0c), 0xf7ffffff, 0x00f80988), // GL2C_CTRL3
    (Reg(0, 0x1025), 0xf17fffff, 0x01200007), // PA_CL_ENHANCE
    (Reg(0, 0x1070), 0xffffffff, 0x00000800), // PA_SC_BINNER_TIMEOUT_COUNTER
    (Reg(0, 0x107c), 0xffffffbf, 0x00000820), // PA_SC_ENHANCE_2
    (Reg(0, 0x11ef), 0xffffffff, 0x00070104), // SPI_CONFIG_CNTL_1
    (Reg(0, 0x11db), 0x000000ff, 0x00000004), // SPI_START_PHASE
    (Reg(0, 0x10a0), 0xe07df47f, 0x00180070), // SQ_CONFIG
    (Reg(1, 0x39c0), 0xf0f001ff, 0),          // SQ_PERFCOUNTER0_SELECT
    (Reg(1, 0x39c1), 0xf0f001ff, 0),          // SQ_PERFCOUNTER1_SELECT
    (Reg(1, 0x39ca), 0xf0f001ff, 0),          // SQ_PERFCOUNTER10_SELECT
    (Reg(1, 0x39cb), 0xf0f001ff, 0),          // SQ_PERFCOUNTER11_SELECT
    (Reg(1, 0x39cc), 0xf0f001ff, 0),          // SQ_PERFCOUNTER12_SELECT
    (Reg(1, 0x39cd), 0xf0f001ff, 0),          // SQ_PERFCOUNTER13_SELECT
    (Reg(1, 0x39ce), 0xf0f001ff, 0),          // SQ_PERFCOUNTER14_SELECT
    (Reg(1, 0x39cf), 0xf0f001ff, 0),          // SQ_PERFCOUNTER15_SELECT
    (Reg(1, 0x39c2), 0xf0f001ff, 0),          // SQ_PERFCOUNTER2_SELECT
    (Reg(1, 0x39c3), 0xf0f001ff, 0),          // SQ_PERFCOUNTER3_SELECT
    (Reg(1, 0x39c4), 0xf0f001ff, 0),          // SQ_PERFCOUNTER4_SELECT
    (Reg(1, 0x39c5), 0xf0f001ff, 0),          // SQ_PERFCOUNTER5_SELECT
    (Reg(1, 0x39c6), 0xf0f001ff, 0),          // SQ_PERFCOUNTER6_SELECT
    (Reg(1, 0x39c7), 0xf0f001ff, 0),          // SQ_PERFCOUNTER7_SELECT
    (Reg(1, 0x39c8), 0xf0f001ff, 0),          // SQ_PERFCOUNTER8_SELECT
    (Reg(1, 0x39c9), 0xf0f001ff, 0),          // SQ_PERFCOUNTER9_SELECT
    (Reg(0, 0x12e2), 0xfff7ffff, 0x01030000), // TA_CNTL_AUX (gc_10_1_0 only)
    (Reg(0, 0x1588), 0xffbfffff, 0x00a00000), // UTCL1_CTRL
    (Reg(0, 0x1009), 0x00000fff, 0x000003ff), // VGT_GS_MAX_WAVE_ID
    (Reg(0, 0x10a2), 0x00000020, 0x00000020), // LDS_CONFIG (Navy Flounder hang fix)
];
