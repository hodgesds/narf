//! Navi22 VCN 3.0 media engines: both decode/encode instances and the JPEG
//! 3.0 decoder. Sources: Linux vcn_v3_0.c (`vcn_v3_0_start`, `_stop`,
//! `_mc_resume`, `_disable_clock_gating`, `_disable_static_power_gating`),
//! vcn_v2_0.c ring emitters reused by VCN 3.0, amdgpu_vcn.c (`sw_init`,
//! ring/IB tests), jpeg_v3_0.c, nbio_v2_3.c and vcn_3_0_0_{offset,sh_mask}.h.
//!
//! Power policy: Linux selects DPG (`AMD_PG_SUPPORT_VCN_DPG`) on GC 10.3.2,
//! which dynamically gates VCN tiles and needs PSP indirect-SRAM uploads.
//! NARF keeps media power gating disabled during bring-up, so this owner
//! runs Linux's static path with `AMD_PG_SUPPORT_VCN` clear (the
//! `amdgpu.pg_mask` configuration): every tile powered on through PGFSM and
//! never re-gated. Clock gating follows the default `AMD_CG_SUPPORT_VCN_MGCG`
//! programming of `vcn_v3_0_disable_clock_gating`. The SMU's MM_DPM_PG
//! feature is outside the boot policy, so Linux's `PowerUpVcn` message is
//! skipped exactly as `sienna_cichlid_dpm_set_vcn_enable` does; a board
//! where it runs is refused before any write. Firmware images come from the
//! PSP-loaded TMR (`AMDGPU_FW_LOAD_PSP`). Only VMID0 kernel rings exist.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_fence_navi22 as fence, amdgpu_vram::Pool,
    amdgpu_vram::Reservation,
};
use core::sync::atomic::{fence as barrier, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    DataMismatch,
    /// The VCPU never reported after Linux's ten reset retries.
    BootFailed(u8),
    /// The SMU runs MM_DPM_PG: Linux would send PowerUpVcn first.
    PowerGated,
    /// The discovery harvest table could not be trusted.
    Harvest(ip::DiscoveryError),
}

/// Register offsets as (SOC15 BASE_IDX, dword), vcn_3_0_0_offset.h. JPEG 3.0
/// shares the VCN instance-0 register space (`JPEG_HWIP = VCN_HWIP`).
pub(crate) mod regs {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Reg(pub u8, pub u32);
    pub const PGFSM_CONFIG: Reg = Reg(1, 0x000); // linux: mmUVD_PGFSM_CONFIG
    pub const PGFSM_STATUS: Reg = Reg(1, 0x001); // linux: mmUVD_PGFSM_STATUS
    pub const POWER_STATUS: Reg = Reg(1, 0x004); // linux: mmUVD_POWER_STATUS
    pub const CC_UVD_HARVESTING: Reg = Reg(1, 0x007); // linux: mmCC_UVD_HARVESTING
    pub const JPEG_POWER_STATUS: Reg = Reg(1, 0x00a); // linux: mmUVD_JPEG_POWER_STATUS
    pub const SCRATCH2: Reg = Reg(1, 0x016); // linux: mmUVD_SCRATCH2
    pub const SCRATCH9: Reg = Reg(1, 0x01d); // linux: mmUVD_SCRATCH9
    pub const GFX10_ADDR_CONFIG: Reg = Reg(1, 0x04a); // linux: mmUVD_GFX10_ADDR_CONFIG
    pub const STATUS: Reg = Reg(1, 0x080); // linux: mmUVD_STATUS
    pub const SOFT_RESET: Reg = Reg(1, 0x084); // linux: mmUVD_SOFT_RESET
    pub const CGC_GATE: Reg = Reg(1, 0x088); // linux: mmUVD_CGC_GATE
    pub const CGC_CTRL: Reg = Reg(1, 0x08a); // linux: mmUVD_CGC_CTRL
    pub const SUVD_CGC_GATE: Reg = Reg(1, 0x08c); // linux: mmUVD_SUVD_CGC_GATE
    pub const SUVD_CGC_CTRL: Reg = Reg(1, 0x08e); // linux: mmUVD_SUVD_CGC_CTRL
    pub const SUVD_CGC_GATE2: Reg = Reg(1, 0x0ff); // linux: mmUVD_SUVD_CGC_GATE2
    pub const MASTINT_EN: Reg = Reg(1, 0x0a1); // linux: mmUVD_MASTINT_EN
    /// Encode ring 0 (general purpose) and ring 1 (low latency).
    // linux: mmUVD_RB_BASE_LO; mmUVD_RB_BASE_LO2
    pub const RB_BASE_LO: [Reg; 2] = [Reg(1, 0x0aa), Reg(1, 0x0af)];
    // linux: mmUVD_RB_BASE_HI; mmUVD_RB_BASE_HI2
    pub const RB_BASE_HI: [Reg; 2] = [Reg(1, 0x0ab), Reg(1, 0x0b0)];
    // linux: mmUVD_RB_SIZE; mmUVD_RB_SIZE2
    pub const RB_SIZE: [Reg; 2] = [Reg(1, 0x0ac), Reg(1, 0x0b1)];
    // linux: mmUVD_RB_RPTR; mmUVD_RB_RPTR2
    pub const RB_RPTR: [Reg; 2] = [Reg(1, 0x0ad), Reg(1, 0x0b2)];
    // linux: mmUVD_RB_WPTR; mmUVD_RB_WPTR2
    pub const RB_WPTR: [Reg; 2] = [Reg(1, 0x0ae), Reg(1, 0x0b3)];
    pub const RB_ARB_CTRL: Reg = Reg(1, 0x0c6); // linux: mmUVD_RB_ARB_CTRL
    pub const VCPU_CACHE_OFFSET0: Reg = Reg(1, 0x140); // linux: mmUVD_VCPU_CACHE_OFFSET0
    pub const VCPU_CACHE_SIZE0: Reg = Reg(1, 0x141); // linux: mmUVD_VCPU_CACHE_SIZE0
    pub const VCPU_CACHE_OFFSET1: Reg = Reg(1, 0x142); // linux: mmUVD_VCPU_CACHE_OFFSET1
    pub const VCPU_CACHE_SIZE1: Reg = Reg(1, 0x143); // linux: mmUVD_VCPU_CACHE_SIZE1
    pub const VCPU_CACHE_OFFSET2: Reg = Reg(1, 0x144); // linux: mmUVD_VCPU_CACHE_OFFSET2
    pub const VCPU_CACHE_SIZE2: Reg = Reg(1, 0x145); // linux: mmUVD_VCPU_CACHE_SIZE2
    pub const VCPU_NONCACHE_OFFSET0: Reg = Reg(1, 0x152); // linux: mmUVD_VCPU_NONCACHE_OFFSET0
    pub const VCPU_NONCACHE_SIZE0: Reg = Reg(1, 0x153); // linux: mmUVD_VCPU_NONCACHE_SIZE0
    pub const VCPU_CNTL: Reg = Reg(1, 0x156); // linux: mmUVD_VCPU_CNTL
    pub const MPC_CNTL: Reg = Reg(1, 0x2cc); // linux: mmUVD_MPC_CNTL
    pub const MPC_SET_MUXA0: Reg = Reg(1, 0x2ce); // linux: mmUVD_MPC_SET_MUXA0
    pub const MPC_SET_MUXB0: Reg = Reg(1, 0x2d0); // linux: mmUVD_MPC_SET_MUXB0
    pub const MPC_SET_MUX: Reg = Reg(1, 0x2d2); // linux: mmUVD_MPC_SET_MUX
    pub const RBC_RB_CNTL: Reg = Reg(1, 0x2de); // linux: mmUVD_RBC_RB_CNTL
    pub const RBC_RB_RPTR: Reg = Reg(1, 0x2e0); // linux: mmUVD_RBC_RB_RPTR
    pub const RBC_RB_WPTR: Reg = Reg(1, 0x2e1); // linux: mmUVD_RBC_RB_WPTR
    pub const LMI_RBC_RB_BAR_LOW: Reg = Reg(1, 0x432); // linux: mmUVD_LMI_RBC_RB_64BIT_BAR_LOW
    pub const LMI_RBC_RB_BAR_HIGH: Reg = Reg(1, 0x433); // linux: mmUVD_LMI_RBC_RB_64BIT_BAR_HIGH
    pub const LMI_VCPU_NC0_BAR_LOW: Reg = Reg(1, 0x438); // linux: mmUVD_LMI_VCPU_NC0_64BIT_BAR_LOW
    /// linux: mmUVD_LMI_VCPU_NC0_64BIT_BAR_HIGH
    pub const LMI_VCPU_NC0_BAR_HIGH: Reg = Reg(1, 0x439);
    // linux: mmUVD_LMI_VCPU_CACHE_64BIT_BAR_LOW
    pub const LMI_VCPU_CACHE_BAR_LOW: Reg = Reg(1, 0x43c);
    // linux: mmUVD_LMI_VCPU_CACHE_64BIT_BAR_HIGH
    pub const LMI_VCPU_CACHE_BAR_HIGH: Reg = Reg(1, 0x43d);
    // linux: mmUVD_LMI_VCPU_CACHE1_64BIT_BAR_LOW
    pub const LMI_VCPU_CACHE1_BAR_LOW: Reg = Reg(1, 0x468);
    // linux: mmUVD_LMI_VCPU_CACHE1_64BIT_BAR_HIGH
    pub const LMI_VCPU_CACHE1_BAR_HIGH: Reg = Reg(1, 0x469);
    // linux: mmUVD_LMI_VCPU_CACHE2_64BIT_BAR_LOW
    pub const LMI_VCPU_CACHE2_BAR_LOW: Reg = Reg(1, 0x46c);
    // linux: mmUVD_LMI_VCPU_CACHE2_64BIT_BAR_HIGH
    pub const LMI_VCPU_CACHE2_BAR_HIGH: Reg = Reg(1, 0x46d);
    pub const LMI_CTRL2: Reg = Reg(1, 0x4a6); // linux: mmUVD_LMI_CTRL2
    pub const LMI_CTRL: Reg = Reg(1, 0x4a8); // linux: mmUVD_LMI_CTRL
    pub const LMI_STATUS: Reg = Reg(1, 0x4a9); // linux: mmUVD_LMI_STATUS
    pub const LMI_RBC_RB_VMID: Reg = Reg(1, 0x4b0); // linux: mmUVD_LMI_RBC_RB_VMID
    /// linux: mmUVD_LMI_RBC_RB_VMID
    pub const LAST1: u32 = 0x4b0;
    // JPEG 3.0, BASE_IDX 0 of VCN instance 0.
    pub const JPEG_PITCH: Reg = Reg(0, 0x09f); // linux: mmUVD_JPEG_PITCH
    /// linux: mmJPEG_DEC_GFX10_ADDR_CONFIG
    pub const JPEG_DEC_GFX10_ADDR_CONFIG: Reg = Reg(0, 0x0a6);
    // linux: mmJPEG_ENC_GFX10_ADDR_CONFIG
    pub const JPEG_ENC_GFX10_ADDR_CONFIG: Reg = Reg(0, 0x0ec);
    pub const JRBC_RB_WPTR: Reg = Reg(0, 0x100); // linux: mmUVD_JRBC_RB_WPTR
    pub const JRBC_RB_CNTL: Reg = Reg(0, 0x101); // linux: mmUVD_JRBC_RB_CNTL
    pub const JRBC_RB_RPTR: Reg = Reg(0, 0x10a); // linux: mmUVD_JRBC_RB_RPTR
    pub const JRBC_RB_SIZE: Reg = Reg(0, 0x113); // linux: mmUVD_JRBC_RB_SIZE
    pub const LMI_JRBC_RB_VMID: Reg = Reg(0, 0x150); // linux: mmUVD_LMI_JRBC_RB_VMID
    pub const LMI_JRBC_RB_BAR_LOW: Reg = Reg(0, 0x166); // linux: mmUVD_LMI_JRBC_RB_64BIT_BAR_LOW
    pub const LMI_JRBC_RB_BAR_HIGH: Reg = Reg(0, 0x167); // linux: mmUVD_LMI_JRBC_RB_64BIT_BAR_HIGH
    pub const JMI_CNTL: Reg = Reg(0, 0x192); // linux: mmUVD_JMI_CNTL
    pub const JPEG_SYS_INT_EN: Reg = Reg(0, 0x1c1); // linux: mmJPEG_SYS_INT_EN
    pub const JPEG_CGC_GATE: Reg = Reg(0, 0x1e0); // linux: mmJPEG_CGC_GATE
    pub const JPEG_CGC_CTRL: Reg = Reg(0, 0x1e1); // linux: mmJPEG_CGC_CTRL
    pub const LAST0: u32 = 0x1e1; // linux: mmJPEG_CGC_CTRL
    /// gc_10_3_0_offset.h mmGB_ADDR_CONFIG, GC BASE_IDX 0.
    // linux-ctx: hdr=gc seg=0
    pub const GB_ADDR_CONFIG: u32 = 0x13de; // linux: mmGB_ADDR_CONFIG
    /// nbio_2_3_offset.h / nbio_v2_3.c, NBIO BASE_IDX 2.
    // linux-ctx: hdr=nbio seg=2
    pub const NBIO_DOORBELL_APER_EN: u32 = 0x0c0; // linux: mmRCC_DEV0_EPF0_RCC_DOORBELL_APER_EN
    pub const NBIO_CONFIG_MEMSIZE: u32 = 0x0c3; // linux: mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
    /// linux: mmBIF_MMSCH0_DOORBELL_RANGE; mmBIF_MMSCH1_DOORBELL_RANGE
    pub const NBIO_MMSCH_DOORBELL_RANGE: [u32; 2] = [0x1d3, 0x1d8];
    pub const LAST_NBIO: u32 = 0x1d8; // linux: mmBIF_MMSCH1_DOORBELL_RANGE
}
// linux-ctx: reset
use regs::*;

/// Field values from vcn_3_0_0_sh_mask.h and amdgpu_vcn.h.
pub(crate) mod bits {
    // linux: n/a (literal `status & 2` in vcn_v3_0.c:vcn_v3_0_start)
    pub const VCPU_REPORT_BOOTED: u32 = 2;
    pub const STATUS_UVD_BUSY: u32 = 4; // linux: UVD_STATUS__UVD_BUSY
    /// `UVD_STATUS__IDLE` in the low three bits (stop path).
    pub const STATUS_IDLE: u32 = 2; // linux: UVD_STATUS__IDLE
    pub const VCPU_CLK_EN: u32 = 1 << 9; // linux: UVD_VCPU_CNTL__CLK_EN_MASK
    pub const VCPU_BLK_RST: u32 = 1 << 28; // linux: UVD_VCPU_CNTL__BLK_RST_MASK
    pub const MASTINT_VCPU_EN: u32 = 1 << 1; // linux: UVD_MASTINT_EN__VCPU_EN_MASK
    pub const LMI_CTRL2_STALL_ARB_UMC: u32 = 1 << 8; // linux: UVD_LMI_CTRL2__STALL_ARB_UMC_MASK
    pub const SOFT_RESET_LMI: u32 = 1 << 2; // linux: UVD_SOFT_RESET__LMI_SOFT_RESET_MASK
    pub const SOFT_RESET_LMI_UMC: u32 = 1 << 13; // linux: UVD_SOFT_RESET__LMI_UMC_SOFT_RESET_MASK
    pub const RB_ARB_VCPU_DIS: u32 = 1 << 3; // linux: UVD_RB_ARB_CTRL__VCPU_DIS_MASK
    /// WRITE_CLEAN_TIMER_EN | MASK_MC_URGENT | DATA_COHERENCY_EN |
    /// VCPU_DATA_COHERENCY_EN, OR-ed into UVD_LMI_CTRL.
    // linux: UVD_LMI_CTRL__WRITE_CLEAN_TIMER_EN_MASK | UVD_LMI_CTRL__MASK_MC_URGENT_MASK | UVD_LMI_CTRL__DATA_COHERENCY_EN_MASK | UVD_LMI_CTRL__VCPU_DATA_COHERENCY_EN_MASK
    pub const LMI_CTRL_SET: u32 = 0x0020_3100;
    pub const MPC_REPLACEMENT_MODE: u32 = 0x38; // linux: UVD_MPC_CNTL__REPLACEMENT_MODE_MASK
    /// VARA/VARB_1..4 = 1..4 and SET_0..2 = 0..2.
    // linux: (0x1 << UVD_MPC_SET_MUXA0__VARA_1__SHIFT) | (0x2 << UVD_MPC_SET_MUXA0__VARA_2__SHIFT) | (0x3 << UVD_MPC_SET_MUXA0__VARA_3__SHIFT) | (0x4 << UVD_MPC_SET_MUXA0__VARA_4__SHIFT)
    pub const MPC_MUX0: u32 = (1 << 6) | (2 << 12) | (3 << 18) | (4 << 24);
    // linux: (0x0 << UVD_MPC_SET_MUX__SET_0__SHIFT) | (0x1 << UVD_MPC_SET_MUX__SET_1__SHIFT) | (0x2 << UVD_MPC_SET_MUX__SET_2__SHIFT)
    pub const MPC_MUX: u32 = (1 << 3) | (2 << 6);
    /// Every PGFSM tile except UVDJ set to 1 (power on): the
    /// `!AMD_PG_SUPPORT_VCN` branch of `vcn_v3_0_disable_static_power_gating`.
    // linux: (1 << UVD_PGFSM_CONFIG__UVDM_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDU_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDF_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDC_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDB_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDIRL_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDLM_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDTD_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDTE_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDE_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDAB_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDATD_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDNA_PWR_CONFIG__SHIFT) | (1 << UVD_PGFSM_CONFIG__UVDNB_PWR_CONFIG__SHIFT)
    pub const PGFSM_ALL_ON: u32 = 0x1515_5555;
    // linux: n/a (literal 0x3F3FFFFF in vcn_v3_0_disable_static_power_gating)
    pub const PGFSM_STATUS_MASK: u32 = 0x3f3f_ffff;
    /// UVD_POWER_STATUS bits cleared with PG disabled (POWER_STATUS, PG_EN).
    // linux: UVD_POWER_STATUS__UVD_PG_EN_MASK | UVD_POWER_STATUS__UVD_POWER_STATUS_MASK
    pub const POWER_STATUS_CLEAR: u32 = 0x103;
    /// DYN_CLOCK_MODE (VCN_MGCG) | CLK_GATE_DLY_TIMER 1 | CLK_OFF_DELAY 4.
    // linux: (1 << UVD_CGC_CTRL__DYN_CLOCK_MODE__SHIFT) | (1 << UVD_CGC_CTRL__CLK_GATE_DLY_TIMER__SHIFT) | (4 << UVD_CGC_CTRL__CLK_OFF_DELAY__SHIFT)
    pub const CGC_CTRL_DYN: u32 = 1 | (1 << 2) | (4 << 6);
    /// SYS..MMSCH gates of UVD_CGC_GATE cleared.
    // linux: UVD_CGC_GATE__SYS_MASK | UVD_CGC_GATE__UDEC_MASK | UVD_CGC_GATE__MPEG2_MASK | UVD_CGC_GATE__REGS_MASK | UVD_CGC_GATE__RBC_MASK | UVD_CGC_GATE__LMI_MC_MASK | UVD_CGC_GATE__LMI_UMC_MASK | UVD_CGC_GATE__IDCT_MASK | UVD_CGC_GATE__MPRD_MASK | UVD_CGC_GATE__MPC_MASK | UVD_CGC_GATE__LBSI_MASK | UVD_CGC_GATE__LRBBM_MASK | UVD_CGC_GATE__UDEC_RE_MASK | UVD_CGC_GATE__UDEC_CM_MASK | UVD_CGC_GATE__UDEC_IT_MASK | UVD_CGC_GATE__UDEC_DB_MASK | UVD_CGC_GATE__UDEC_MP_MASK | UVD_CGC_GATE__WCB_MASK | UVD_CGC_GATE__VCPU_MASK | UVD_CGC_GATE__MMSCH_MASK
    pub const CGC_GATE_ALL: u32 = 0x0017_ffff;
    /// UDEC_RE..MMSCH mode bits of UVD_CGC_CTRL.
    // linux: UVD_CGC_CTRL__UDEC_RE_MODE_MASK | UVD_CGC_CTRL__UDEC_CM_MODE_MASK | UVD_CGC_CTRL__UDEC_IT_MODE_MASK | UVD_CGC_CTRL__UDEC_DB_MODE_MASK | UVD_CGC_CTRL__UDEC_MP_MODE_MASK | UVD_CGC_CTRL__SYS_MODE_MASK | UVD_CGC_CTRL__UDEC_MODE_MASK | UVD_CGC_CTRL__MPEG2_MODE_MASK | UVD_CGC_CTRL__REGS_MODE_MASK | UVD_CGC_CTRL__RBC_MODE_MASK | UVD_CGC_CTRL__LMI_MC_MODE_MASK | UVD_CGC_CTRL__LMI_UMC_MODE_MASK | UVD_CGC_CTRL__IDCT_MODE_MASK | UVD_CGC_CTRL__MPRD_MODE_MASK | UVD_CGC_CTRL__MPC_MODE_MASK | UVD_CGC_CTRL__LBSI_MODE_MASK | UVD_CGC_CTRL__LRBBM_MODE_MASK | UVD_CGC_CTRL__WCB_MODE_MASK | UVD_CGC_CTRL__VCPU_MODE_MASK | UVD_CGC_CTRL__MMSCH_MODE_MASK
    pub const CGC_CTRL_MODES: u32 = 0xbfff_f800;
    // linux: UVD_SUVD_CGC_GATE__SRE_MASK | UVD_SUVD_CGC_GATE__SIT_MASK | UVD_SUVD_CGC_GATE__SMP_MASK | UVD_SUVD_CGC_GATE__SCM_MASK | UVD_SUVD_CGC_GATE__SDB_MASK | UVD_SUVD_CGC_GATE__SRE_H264_MASK | UVD_SUVD_CGC_GATE__SRE_HEVC_MASK | UVD_SUVD_CGC_GATE__SIT_H264_MASK | UVD_SUVD_CGC_GATE__SIT_HEVC_MASK | UVD_SUVD_CGC_GATE__SCM_H264_MASK | UVD_SUVD_CGC_GATE__SCM_HEVC_MASK | UVD_SUVD_CGC_GATE__SDB_H264_MASK | UVD_SUVD_CGC_GATE__SDB_HEVC_MASK | UVD_SUVD_CGC_GATE__SCLR_MASK | UVD_SUVD_CGC_GATE__ENT_MASK | UVD_SUVD_CGC_GATE__IME_MASK | UVD_SUVD_CGC_GATE__SIT_HEVC_DEC_MASK | UVD_SUVD_CGC_GATE__SIT_HEVC_ENC_MASK | UVD_SUVD_CGC_GATE__SITE_MASK | UVD_SUVD_CGC_GATE__SRE_VP9_MASK | UVD_SUVD_CGC_GATE__SCM_VP9_MASK | UVD_SUVD_CGC_GATE__SIT_VP9_DEC_MASK | UVD_SUVD_CGC_GATE__SDB_VP9_MASK | UVD_SUVD_CGC_GATE__IME_HEVC_MASK | UVD_SUVD_CGC_GATE__EFC_MASK | UVD_SUVD_CGC_GATE__SAOE_MASK | UVD_SUVD_CGC_GATE__SRE_AV1_MASK | UVD_SUVD_CGC_GATE__FBC_PCLK_MASK | UVD_SUVD_CGC_GATE__FBC_CCLK_MASK | UVD_SUVD_CGC_GATE__SCM_AV1_MASK | UVD_SUVD_CGC_GATE__SMPA_MASK
    pub const SUVD_CGC_GATE_ALL: u32 = 0xffff_bfff;
    // linux: UVD_SUVD_CGC_GATE2__MPBE0_MASK | UVD_SUVD_CGC_GATE2__MPBE1_MASK | UVD_SUVD_CGC_GATE2__SIT_AV1_MASK | UVD_SUVD_CGC_GATE2__SDB_AV1_MASK | UVD_SUVD_CGC_GATE2__MPC1_MASK
    pub const SUVD_CGC_GATE2_ALL: u32 = 0x1f;
    // linux: UVD_SUVD_CGC_CTRL__SRE_MODE_MASK | UVD_SUVD_CGC_CTRL__SIT_MODE_MASK | UVD_SUVD_CGC_CTRL__SMP_MODE_MASK | UVD_SUVD_CGC_CTRL__SCM_MODE_MASK | UVD_SUVD_CGC_CTRL__SDB_MODE_MASK | UVD_SUVD_CGC_CTRL__SCLR_MODE_MASK | UVD_SUVD_CGC_CTRL__ENT_MODE_MASK | UVD_SUVD_CGC_CTRL__IME_MODE_MASK | UVD_SUVD_CGC_CTRL__SITE_MODE_MASK | UVD_SUVD_CGC_CTRL__EFC_MODE_MASK | UVD_SUVD_CGC_CTRL__SAOE_MODE_MASK | UVD_SUVD_CGC_CTRL__SMPA_MODE_MASK | UVD_SUVD_CGC_CTRL__MPBE0_MODE_MASK | UVD_SUVD_CGC_CTRL__MPBE1_MODE_MASK | UVD_SUVD_CGC_CTRL__SIT_AV1_MODE_MASK | UVD_SUVD_CGC_CTRL__SDB_AV1_MODE_MASK | UVD_SUVD_CGC_CTRL__MPC1_MODE_MASK | UVD_SUVD_CGC_CTRL__FBC_PCLK_MASK | UVD_SUVD_CGC_CTRL__FBC_CCLK_MASK
    pub const SUVD_CGC_CTRL_MODES: u32 = 0x3003_ffbf;
    /// VCPU_LMI_WRITE_CLEAN | READ_CLEAN | WRITE_CLEAN | WRITE_CLEAN_RAW.
    // linux: UVD_LMI_STATUS__VCPU_LMI_WRITE_CLEAN_MASK | UVD_LMI_STATUS__READ_CLEAN_MASK | UVD_LMI_STATUS__WRITE_CLEAN_MASK | UVD_LMI_STATUS__WRITE_CLEAN_RAW_MASK
    pub const LMI_STATUS_CLEAN: u32 = 0xf;
    /// UMC_READ_CLEAN_RAW | UMC_WRITE_CLEAN_RAW.
    // linux: UVD_LMI_STATUS__UMC_READ_CLEAN_RAW_MASK | UVD_LMI_STATUS__UMC_WRITE_CLEAN_RAW_MASK
    pub const LMI_STATUS_UMC_CLEAN: u32 = 0x240;
    /// RB_BUFSZ 12 | RB_BLKSZ 1 | RB_NO_FETCH | RB_NO_UPDATE | RB_RPTR_WR_EN.
    // linux: (12 << UVD_RBC_RB_CNTL__RB_BUFSZ__SHIFT) | (1 << UVD_RBC_RB_CNTL__RB_BLKSZ__SHIFT) | (1 << UVD_RBC_RB_CNTL__RB_NO_FETCH__SHIFT) | (1 << UVD_RBC_RB_CNTL__RB_NO_UPDATE__SHIFT) | (1 << UVD_RBC_RB_CNTL__RB_RPTR_WR_EN__SHIFT)
    pub const RBC_RB_CNTL_IDLE: u32 = 12 | (1 << 8) | (1 << 16) | (1 << 24) | (1 << 28);
    pub const CC_UVD_DISABLE: u32 = 1 << 1; // linux: CC_UVD_HARVESTING__UVD_DISABLE_MASK
    pub const PGFSM_UVDJ_ON: u32 = 1 << 22; // linux: 1 << UVD_PGFSM_CONFIG__UVDJ_PWR_CONFIG__SHIFT
    pub const PGFSM_UVDJ_STATUS: u32 = 0x00c0_0000; // linux: UVD_PGFSM_STATUS__UVDJ_PWR_STATUS_MASK
    /// linux: UVD_JPEG_POWER_STATUS__JPEG_POWER_STATUS_MASK
    pub const JPEG_POWER_STATUS_MASK: u32 = 1;
    pub const JPEG_PG_MODE: u32 = 1 << 4; // linux: UVD_JPEG_POWER_STATUS__JPEG_PG_MODE_MASK
    /// DYN_CLOCK_MODE (JPEG_MGCG) | CLK_GATE_DLY_TIMER 1 | CLK_OFF_DELAY 4.
    // linux: (1 << JPEG_CGC_CTRL__DYN_CLOCK_MODE__SHIFT) | (1 << JPEG_CGC_CTRL__CLK_GATE_DLY_TIMER__SHIFT) | (4 << JPEG_CGC_CTRL__CLK_OFF_DELAY__SHIFT)
    pub const JPEG_CGC_CTRL_DYN: u32 = 1 | (1 << 1) | (4 << 5);
    // linux: JPEG_CGC_GATE__JPEG_DEC_MASK | JPEG_CGC_GATE__JPEG2_DEC_MASK | JPEG_CGC_GATE__JPEG_ENC_MASK | JPEG_CGC_GATE__JMCIF_MASK | JPEG_CGC_GATE__JRBBM_MASK
    pub const JPEG_CGC_GATE_ALL: u32 = 0x1f;
    /// JPEG_DEC | JPEG2_DEC | JMCIF | JRBBM mode bits.
    // linux: JPEG_CGC_CTRL__JPEG_DEC_MODE_MASK | JPEG_CGC_CTRL__JPEG2_DEC_MODE_MASK | JPEG_CGC_CTRL__JMCIF_MODE_MASK | JPEG_CGC_CTRL__JRBBM_MODE_MASK
    pub const JPEG_CGC_CTRL_MODES: u32 = 0x001b_0000;
    pub const JMI_SOFT_RESET: u32 = 1; // linux: UVD_JMI_CNTL__SOFT_RESET_MASK
    pub const JPEG_SYS_INT_DJRBC: u32 = 1 << 1; // linux: JPEG_SYS_INT_EN__DJRBC_MASK
}
use bits::*;

/// VCN firmware command interface (amdgpu_vcn.h, vcn_v3_0.c internal regs).
pub(crate) mod cmd {
    /// `PACKET0(reg, 0)` (soc15d.h): type 0, one register.
    pub const fn packet0(reg: u32) -> u32 {
        reg & 0xffff // linux: n/a (PACKET0(reg, 0), soc15d.h)
    }
    pub const INTERNAL_CMD: u32 = 0x0f; // linux: mmUVD_GPCOM_VCPU_CMD_INTERNAL_OFFSET@vcn
    pub const INTERNAL_DATA0: u32 = 0x10; // linux: mmUVD_GPCOM_VCPU_DATA0_INTERNAL_OFFSET@vcn
    pub const INTERNAL_DATA1: u32 = 0x11; // linux: mmUVD_GPCOM_VCPU_DATA1_INTERNAL_OFFSET@vcn
    pub const INTERNAL_CONTEXT_ID: u32 = 0x27; // linux: mmUVD_CONTEXT_ID_INTERNAL_OFFSET@vcn
    pub const INTERNAL_NOP: u32 = 0x29; // linux: mmUVD_NO_OP_INTERNAL_OFFSET@vcn
    pub const INTERNAL_IB_SIZE: u32 = 0x25c; // linux: mmUVD_RBC_IB_SIZE_INTERNAL_OFFSET@vcn
    /// linux: mmUVD_LMI_RBC_IB_64BIT_BAR_LOW_INTERNAL_OFFSET@vcn
    pub const INTERNAL_IB_BAR_LOW: u32 = 0x3b4;
    // linux: mmUVD_LMI_RBC_IB_64BIT_BAR_HIGH_INTERNAL_OFFSET@vcn
    pub const INTERNAL_IB_BAR_HIGH: u32 = 0x3b5;
    pub const INTERNAL_IB_VMID: u32 = 0x431; // linux: mmUVD_LMI_RBC_IB_VMID_INTERNAL_OFFSET@vcn
    pub const INTERNAL_SCRATCH9: u32 = 0xc01d; // linux: mmUVD_SCRATCH9_INTERNAL_OFFSET@vcn
    pub const DEC_KMD: u32 = 0x8000_0000; // linux: VCN_DEC_KMD_CMD
    pub const DEC_FENCE: u32 = 0; // linux: VCN_DEC_CMD_FENCE
    pub const DEC_TRAP: u32 = 1; // linux: VCN_DEC_CMD_TRAP
    pub const DEC_PACKET_START: u32 = 0x0a; // linux: VCN_DEC_CMD_PACKET_START
    pub const DEC_PACKET_END: u32 = 0x0b; // linux: VCN_DEC_CMD_PACKET_END
    pub const ENC_NOP: u32 = 0; // linux: VCN_ENC_CMD_NO_OP
    pub const ENC_END: u32 = 1; // linux: VCN_ENC_CMD_END
    pub const ENC_IB: u32 = 2; // linux: VCN_ENC_CMD_IB
    pub const ENC_FENCE: u32 = 3; // linux: VCN_ENC_CMD_FENCE
    pub const ENC_TRAP: u32 = 4; // linux: VCN_ENC_CMD_TRAP
    /// jpeg_v3_0.c `mmUVD_JPEG_PITCH_INTERNAL_OFFSET`.
    pub const JPEG_INTERNAL_PITCH: u32 = 0x401f; // linux: mmUVD_JPEG_PITCH_INTERNAL_OFFSET@vcn
    /// `PACKETJ(0, 0, 0, PACKETJ_TYPE6)`, the JRBC NOP.
    pub const JPEG_NOP: u32 = 6 << 28; // linux: PACKETJ(0, 0, 0, PACKETJ_TYPE6)
}

/// `AMDGPU_NAVI10_DOORBELL64_VCN0_1 << 1`; vcn_v3_0_sw_init assigns the
/// decode ring `base + 8 * i` and encode ring j `base + 2 + j + 8 * i`, and
/// jpeg_v3_0_sw_init the JPEG ring `base + 1` (32-bit doorbells).
pub mod doorbell {
    pub const VCN_BASE: u32 = 0x188 << 1; // linux: AMDGPU_NAVI10_DOORBELL64_VCN0_1 << 1
    pub const fn dec(instance: u32) -> u32 {
        VCN_BASE + 8 * instance
    }
    pub const fn enc(instance: u32, ring: u32) -> u32 {
        VCN_BASE + 2 + ring + 8 * instance
    }
    pub const JPEG: u32 = VCN_BASE + 1;
    /// `BIF_MMSCH0_DOORBELL_RANGE.SIZE` programmed by vcn_doorbell_range.
    // linux: n/a (literal SIZE 8 in nbio_v2_3.c:nbio_v2_3_vcn_doorbell_range)
    pub const RANGE: u32 = 8;
}

// Per-instance VRAM: the VCPU BO (`amdgpu_vcn_sw_init` with PSP-loaded
// firmware: stack, context, then page-aligned fw_shared at the end), the
// three 512-dword rings (4 KiB with amdgpu_sched_hw_submission = 2),
// fence writeback and the IB-test buffers.
pub(crate) const STACK_SIZE: u32 = 128 << 10; // linux: AMDGPU_VCN_STACK_SIZE
pub(crate) const CONTEXT_SIZE: u32 = 512 << 10; // linux: AMDGPU_VCN_CONTEXT_SIZE
pub(crate) const STACK: u64 = 0; // linux: n/a (NARF BO layout; Linux PSP offset 0)
pub(crate) const CONTEXT: u64 = STACK + STACK_SIZE as u64;
pub(crate) const SHARED: u64 = CONTEXT + CONTEXT_SIZE as u64;
// linux: n/a (AMDGPU_GPU_PAGE_ALIGN(sizeof(struct amdgpu_fw_shared)) = 4096; struct not in probe)
pub(crate) const SHARED_SIZE: u32 = 4096;
pub(crate) const DEC_RING: u64 = SHARED + SHARED_SIZE as u64;
pub(crate) const ENC_RING: [u64; 2] = [DEC_RING + 4096, DEC_RING + 8192];
pub(crate) const WB: u64 = DEC_RING + 12288;
/// Fence slots: decode, encode 0, encode 1. Shadow wptrs follow.
pub(crate) const FENCE: [u64; 3] = [WB, WB + 8, WB + 16];
pub(crate) const WPTR: [u64; 3] = [WB + 64, WB + 72, WB + 80];
pub(crate) const IB: u64 = WB + 4096;
/// Decode create/destroy IBs, then encode create/destroy IBs.
pub(crate) const IBS: [u64; 4] = [IB, IB + 0x100, IB + 0x200, IB + 0x300];
pub(crate) const MSG: [u64; 2] = [IB + 4096, IB + 8192];
pub(crate) const SESSION: u64 = IB + 12288;
/// `amdgpu_vcn_enc_ring_test_ib`: 128 KiB + one page session buffer.
// linux: n/a ((128 << 10) + AMDGPU_GPU_PAGE_SIZE, amdgpu_vcn_enc_ring_test_ib)
pub(crate) const SESSION_SIZE: u64 = (128 << 10) + 4096;
pub(crate) const INSTANCE_BYTES: u64 = SESSION + SESSION_SIZE;
// linux: n/a (roundup_pow_of_two(512 * 4 * 2), amdgpu_ring_init)
pub(crate) const RING_BYTES: u64 = 4096;
pub(crate) const RING_DW: u32 = (RING_BYTES / 4) as u32;
/// JPEG ring plus one writeback page for its shadow wptr.
pub(crate) const JPEG_BYTES: u64 = 2 * RING_BYTES;
/// amdgpu_fw_shared byte offsets (natural C layout, not packed).
pub(crate) mod shared {
    pub const PRESENT_FLAG_0: u64 = 0; // linux: n/a (offsetof amdgpu_fw_shared.present_flag_0)
    pub const RB_WPTR: u64 = 52; // linux: n/a (offsetof amdgpu_fw_shared.rb.wptr = 52)
    /// Dword holding pad1 and the multi_queue decode/encode-GP/encode-LL
    /// mode bytes (offsets 57, 58, 59).
    pub const QUEUE_MODES: u64 = 56; // linux: n/a (offsetof amdgpu_fw_shared.pad1 = 56)
    /// SW_RING | MULTI_QUEUE | FW_SHARED_FLAG_0_RB | SMU_VERSION_INFO.
    // linux: AMDGPU_VCN_SW_RING_FLAG | AMDGPU_VCN_MULTI_QUEUE_FLAG | AMDGPU_VCN_FW_SHARED_FLAG_0_RB | AMDGPU_VCN_SMU_VERSION_INFO_FLAG
    pub const PRESENT: u32 = (1 << 9) | (1 << 8) | (1 << 6) | (1 << 11);
    pub const RING_RESET: u32 = 1; // linux: FW_QUEUE_RING_RESET
    /// linux: n/a (multi_queue.decode_queue_mode at fw_shared byte 57 = QUEUE_MODES + 1)
    pub const DECODE_SHIFT: u32 = 8;
    // linux: n/a (encode_generalpurpose/lowlatency_queue_mode at bytes 58/59)
    pub const ENCODE_SHIFT: [u32; 2] = [16, 24];
}

/// Harvested VCN instances (bit i = instance i), `adev->vcn.harvest_config`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Harvest(pub u8);
impl Harvest {
    /// Discovery harvest-table mask plus `amdgpu_discovery_harvest_config_quirk`:
    /// these Navy Flounder revisions ship a harvest table missing VCN1.
    pub fn navi22(table: u8, revision: u8) -> Self {
        // linux: n/a (revision literals in amdgpu_discovery.c:amdgpu_discovery_harvest_config_quirk)
        let quirk = matches!(revision, 0xc1 | 0xc2 | 0xc3 | 0xc5 | 0xc7 | 0xcf | 0xdf);
        Self(table | if quirk { 2 } else { 0 }) // linux-lit: 2=AMDGPU_VCN_HARVEST_VCN1
    }
    /// Read the harvest table from the discovery copy at the top of VRAM.
    ///
    /// # Safety
    /// Single-CPU boot, caller exclusively owns the GPU's BAR0/BAR5 mappings
    /// and the VRAM index latch (the same contract as probe's discovery read).
    pub unsafe fn read(
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        revision: u8,
    ) -> Result<Self, Error> {
        let offset = gpu
            .vram
            .size
            .checked_sub(ip::DISCOVERY_TMR_OFFSET)
            .ok_or(Error::Invalid)?;
        let mut blob = alloc::vec::Vec::new();
        blob.try_reserve_exact(ip::DISCOVERY_TMR_SIZE)
            .map_err(|_| Error::Allocation)?;
        blob.resize(ip::DISCOVERY_TMR_SIZE, 0);
        let (fb, regs, size) = (gpu.fb_bar, gpu.regs, gpu.vram.size);
        authority
            .invoke(Op(|| {
                // SAFETY: forwarded exclusive mapping/index-latch ownership.
                let mut reader = unsafe { crate::amdgpu_vram_access::MmioReader::new(&fb, &regs) };
                crate::amdgpu_vram_access::read(&mut reader, size, offset, &mut blob)
            }))
            .map_err(|_| Error::Revoked)?
            .map_err(|_| Error::DeviceGone)?;
        let table = ip::parse_vcn_harvest(&blob).map_err(Error::Harvest)?;
        Ok(if gpu.chip.did == crate::amdgpu::NAVI22 {
            Self::navi22(table, revision)
        } else {
            Self(table)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// BAR5 byte bases of VCN BASE_IDX 0 and 1 per discovered instance.
    pub vcn: [Option<[u64; 2]>; 2],
    pub gc: u64,
    pub nbio: u64,
    pub hdp: u64,
}
fn vcn_bases(gpu: &AmdGpu, instance: u8) -> Result<[u64; 2], Error> {
    let profile =
        crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did).ok_or(Error::Unsupported)?;
    let mut found = gpu
        .ip_blocks
        .iter()
        .filter(|b| b.hw_id == ip::HW_ID_VCN && b.instance == instance);
    let block = found.next().ok_or(Error::Unsupported)?;
    if found.next().is_some()
        || block.num_bases < 2
        || !profile
            .vcn_versions
            .contains(&(block.major, block.minor, block.revision))
    {
        return Err(Error::Unsupported);
    }
    let mut bases = [0; 2];
    for (index, last) in [(0, LAST0), (1, LAST1)] {
        let base = u64::from(block.base_addrs[index]) * 4;
        if base
            .checked_add((u64::from(last) + 1) * 4)
            .is_none_or(|end| end > gpu.regs.len)
        {
            return Err(Error::Invalid);
        }
        bases[index] = base;
    }
    Ok(bases)
}
impl Layout {
    /// Resolve the instances in `instances` (bit mask) plus GC/NBIO/HDP.
    pub(crate) fn resolve(gpu: &AmdGpu, instances: u8) -> Result<Self, Error> {
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        if gpu.regs.len < 0x7f004 || instances & !3 != 0 {
            return Err(Error::Unsupported);
        }
        let bank = |id, versions: &[(u8, u8, u8)], index, last| {
            crate::amdgpu_psp_ring::bank(gpu, id, versions, index, last)
                .map_err(|_| Error::Unsupported)
        };
        let mut vcn = [None; 2];
        for (i, slot) in vcn.iter_mut().enumerate() {
            if instances & (1 << i) != 0 {
                *slot = Some(vcn_bases(gpu, i as u8)?);
            }
        }
        Ok(Self {
            vcn,
            gc: bank(ip::HW_ID_GC, &[profile.gc_version], 0, GB_ADDR_CONFIG)?,
            nbio: bank(
                ip::HW_ID_NBIF,
                &[
                    (2, 3, 0),
                    (2, 3, 1),
                    (2, 3, 2),
                    (3, 3, 0),
                    (3, 3, 1),
                    (3, 3, 2),
                    (3, 3, 3),
                ],
                2,
                LAST_NBIO,
            )?,
            hdp: bank(
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,
                0xd1, // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
            )?,
        })
    }
    /// BAR5 byte address of `r` in VCN instance `i`. Instances are validated
    /// at construction; an unresolved instance maps to an unused zero base.
    pub(crate) fn reg(&self, i: usize, r: Reg) -> u64 {
        self.vcn[i].map_or(0, |b| b[r.0 as usize]) + u64::from(r.1) * 4
    }
    pub(crate) fn nbio(&self, reg: u32) -> u64 {
        self.nbio + u64::from(reg) * 4
    }
}

pub(crate) trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    /// Zero `len` bytes (dword multiple) at `offset` (`memset_io`).
    fn zero_memory(&mut self, map: MmioRegion, offset: u64, len: u64) {
        for at in (offset..offset + len).step_by(4) {
            self.write_memory(map, at, 0);
        }
    }
    /// 32-bit store to BAR2 dword `index` (`WDOORBELL32`).
    fn doorbell(&mut self, index: u32, value: u32);
}
#[derive(Debug)]
pub(crate) struct Mmio {
    regs: MmioRegion,
    doorbells: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds every VCN/GC/NBIO/HDP bank inside BAR5 and
        // this exclusive owner only calls this inside live PCI authority.
        let value = unsafe { self.regs.read32(address) };
        if value == u32::MAX {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: VCN MMIO {address:#x} returned all ones"
            );
        }
        value
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounded exclusive register mapping and authority.
        unsafe { self.regs.write32(address, value) };
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: offsets are bounded by the owner's permanent reservation.
        unsafe { map.read32(offset) }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: same retained reservation and dword-aligned bounded offset.
        unsafe { map.write32(offset, value) };
    }
    fn doorbell(&mut self, index: u32, value: u32) {
        let offset = u64::from(index) * 4;
        if offset + 4 <= self.doorbells.len {
            barrier(Ordering::SeqCst);
            // SAFETY: bounded inside the permanent UC doorbell page.
            unsafe { self.doorbells.write32(offset, value) };
            barrier(Ordering::SeqCst);
        }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
fn update<I: Io>(io: &mut I, address: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = checked(io.read(address))?;
    io.write(address, (old & !mask) | (value & mask));
    Ok(())
}
/// Linux uses WREG32_P for VCPU_CNTL, preserving all unselected bits even
/// when the register reads all ones. That control word alone cannot prove
/// removal: verify NBIO's memory-size and aperture registers before accepting
/// it. GC registers themselves can return all ones while GFXOFF is active.
fn update_vcpu<I: Io>(
    io: &mut I,
    layout: Layout,
    instance: usize,
    mask: u32,
    value: u32,
) -> Result<(), Error> {
    let address = layout.reg(instance, VCPU_CNTL);
    let old = io.read(address);
    if old == u32::MAX {
        if checked(io.read(layout.nbio(NBIO_CONFIG_MEMSIZE)))? == 0 {
            return Err(Error::Invalid);
        }
        if checked(io.read(layout.nbio(NBIO_DOORBELL_APER_EN)))? & 1 == 0 {
            return Err(Error::Invalid);
        }
    }
    io.write(address, (old & !mask) | (value & mask));
    Ok(())
}
async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
/// CPU VRAM writes leave the HDP write cache before an engine fetches them.
fn flush<I: Io>(io: &mut I, l: Layout) {
    barrier(Ordering::SeqCst);
    // linux: n/a (MMIO_REG_HOLE_OFFSET write, amdgpu_hdp_generic_flush)
    io.write(0x7f000, 0);
    io.read(l.nbio(NBIO_CONFIG_MEMSIZE));
    barrier(Ordering::SeqCst);
}
/// HDP read-cache invalidate before the CPU samples engine writes.
fn invalidate<I: Io>(io: &mut I, l: Layout) {
    io.write(l.hdp + 0xd1 * 4, 1); // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
    io.read(l.hdp + 0xd1 * 4); // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
    barrier(Ordering::SeqCst);
}
/// `adev->usec_timeout` (100 ms) for register waits and ring tests.
pub(crate) const REG_TIMEOUT_MS: u64 = 100; // linux: n/a (adev->usec_timeout)
/// `AMDGPU_IB_TEST_TIMEOUT` (1 s), used for multimedia rings on bare metal.
// linux: n/a (AMDGPU_IB_TEST_TIMEOUT = msecs_to_jiffies(1000))
pub(crate) const FENCE_TIMEOUT_MS: u64 = 1000;

/// `vcn_v3_0_start` VCPU boot loop bounds: 10 resets, 100 samples of
/// UVD_STATUS 10 ms apart per attempt, 10 ms around each BLK_RST toggle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timing {
    pub retries: u32,
    pub polls: u32,
    pub poll_us: u64,
    pub reset_us: u64,
}
// linux: n/a (loop literals in vcn_v3_0.c:vcn_v3_0_start)
pub(crate) const LINUX_TIMING: Timing = Timing {
    retries: 10,
    polls: 100,
    poll_us: 10_000,
    reset_us: 10_000,
};

#[derive(Debug)]
pub(crate) struct Hw<I: Io> {
    pub io: I,
    pub authority: Cap<BusDeviceCap, Write>,
    pub layout: Layout,
}
impl<I: Io> Hw<I> {
    pub(crate) fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (io, layout) = (&mut self.io, self.layout);
        self.authority
            .invoke(Op(|| f(io, layout)))
            .map_err(|_| Error::Revoked)?
    }
    async fn poll<T>(
        &mut self,
        engine: fence::Engine,
        timeout_ms: u64,
        mut f: impl FnMut(&mut I, Layout) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let deadline = narf_time::Deadline::after_ms(timeout_ms);
        fence::wait(engine, deadline, Error::Timeout, || {
            self.access(|io, l| f(io, l))
        })
        .await
    }
    /// `SOC15_WAIT_ON_RREG`: bounded wait for `(reg & mask) == value`.
    async fn wait_reg(
        &mut self,
        engine: fence::Engine,
        address: u64,
        value: u32,
        mask: u32,
    ) -> Result<(), Error> {
        self.poll(engine, REG_TIMEOUT_MS, |io, _| {
            Ok((checked(io.read(address))? & mask == value).then_some(()))
        })
        .await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Decode RBC: PACKET0 pairs, NOP pairs, 16-dword commit alignment.
    Dec,
    /// Encode: one-dword commands, VCN_ENC_CMD_NO_OP, 64-dword alignment.
    Enc,
    /// JRBC: PACKETJ NOP pairs, 16-dword alignment.
    Jpeg,
}
/// One 4 KiB kernel ring. `wptr` is a dword index wrapped by `ptr_mask`
/// exactly like `amdgpu_ring_write`.
#[derive(Debug)]
pub(crate) struct Ring {
    pub base: u64,
    pub kind: Kind,
    pub doorbell: u32,
    /// Writeback dword mirroring the last committed wptr (`wptr_cpu_addr`).
    pub shadow: u64,
    pub wptr: u32,
    pub seq: u32,
}
impl Ring {
    fn align(&self) -> u32 {
        if self.kind == Kind::Enc {
            64
        } else {
            16
        }
    }
    fn reset(&mut self) {
        self.wptr = 0;
    }
    /// Append one submission. The caller only submits to an idle ring, so
    /// the submission and its padding must fit without overtaking the engine.
    fn emit<I: Io>(&mut self, io: &mut I, map: MmioRegion, words: &[u32]) -> Result<(), Error> {
        if words.len() as u32 + self.align() > RING_DW {
            return Err(Error::Invalid);
        }
        for &word in words {
            io.write_memory(map, self.base + u64::from(self.wptr) * 4, word);
            self.wptr = (self.wptr + 1) % RING_DW;
        }
        Ok(())
    }
    /// `amdgpu_ring_commit`: pad with the ring's insert_nop, publish the
    /// shadow wptr, flush HDP and ring the 32-bit doorbell (`*_set_wptr`).
    fn commit<I: Io>(&mut self, io: &mut I, map: MmioRegion, l: Layout) {
        let align = self.align();
        let count = (align - (self.wptr % align)) % align;
        for i in 0..count {
            let word = match self.kind {
                Kind::Dec if i % 2 == 0 => cmd::packet0(cmd::INTERNAL_NOP),
                Kind::Jpeg if i % 2 == 0 => cmd::JPEG_NOP,
                Kind::Enc => cmd::ENC_NOP,
                // Second dword of a decode/JRBC NOP pair.
                _ => 0,
            };
            io.write_memory(map, self.base + u64::from(self.wptr) * 4, word);
            self.wptr = (self.wptr + 1) % RING_DW;
        }
        io.write_memory(map, self.shadow, self.wptr);
        flush(io, l);
        io.doorbell(self.doorbell, self.wptr);
    }
    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    /// Programming/booting this instance (cancellation leaves it here).
    Starting(u8),
    Running,
    Testing,
    Verified,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JpegState {
    Absent,
    Prepared,
    Starting,
    Verified,
    Stopped,
    Failed,
}
/// Evidence from the VCN and JPEG owners.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    /// Instances this owner programs (discovery minus harvest).
    pub instances: u8,
    /// VCPU boot attempt (1-based) that reported, per instance.
    pub booted: [u8; 2],
    pub dec_ring: [bool; 2],
    pub enc_ring: [[bool; 2]; 2],
    /// Last decode/encode IB-test fence sequence per instance.
    pub dec_ib: [u32; 2],
    pub enc_ib: [[u32; 2]; 2],
    pub jpeg_ring: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub jpeg: JpegState,
    pub proof: Proof,
}

#[derive(Debug)]
pub(crate) struct Instance {
    pub memory: Reservation,
    pub dec: Ring,
    pub enc: [Ring; 2],
    pub engine: fence::Engine,
}
impl Instance {
    pub(crate) fn new(pool: &Pool, i: u32) -> Result<Self, Error> {
        let memory = pool
            .reserve(INSTANCE_BYTES)
            .map_err(|_| Error::Allocation)?;
        // The decode fence takes only 40 address bits (`upper & 0xff`).
        if memory
            .address()
            .checked_add(INSTANCE_BYTES)
            .is_none_or(|end| end > 1 << 40)
        {
            return Err(Error::Unsupported);
        }
        let ring = |base, kind, doorbell, shadow| Ring {
            base,
            kind,
            doorbell,
            shadow,
            wptr: 0,
            seq: 0,
        };
        Ok(Self {
            memory,
            dec: ring(DEC_RING, Kind::Dec, doorbell::dec(i), WPTR[0]),
            enc: [
                ring(ENC_RING[0], Kind::Enc, doorbell::enc(i, 0), WPTR[1]),
                ring(ENC_RING[1], Kind::Enc, doorbell::enc(i, 1), WPTR[2]),
            ],
            engine: [fence::Engine::Vcn0, fence::Engine::Vcn1][i as usize],
        })
    }
    fn address(&self, offset: u64) -> u64 {
        self.memory.address() + offset
    }
}
#[derive(Debug)]
pub(crate) struct Jpeg {
    pub memory: Reservation,
    pub ring: Ring,
}
impl Jpeg {
    pub(crate) fn new(pool: &Pool) -> Result<Self, Error> {
        Ok(Self {
            memory: pool.reserve(JPEG_BYTES).map_err(|_| Error::Allocation)?,
            ring: Ring {
                base: 0,
                kind: Kind::Jpeg,
                doorbell: doorbell::JPEG,
                shadow: RING_BYTES,
                wptr: 0,
                seq: 0,
            },
        })
    }
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    enc_count: usize,
    pub hw: Hw<I>,
    pub vcn: [Option<Instance>; 2],
    pub jpeg: Option<Jpeg>,
    /// `adev->vcn.inst[i].fw->size`: the VCN container file length.
    pub firmware_bytes: u32,
    pub timing: Timing,
    pub state: State,
    pub jpeg_state: JpegState,
    pub proof: Proof,
}
/// `vcn_v2_0_dec_ring_emit_fence`: context_id = seq, fence then trap.
pub(crate) fn dec_fence(address: u64, seq: u32) -> [u32; 14] {
    use cmd::*;
    [
        packet0(INTERNAL_CONTEXT_ID),
        seq,
        packet0(INTERNAL_DATA0),
        address as u32,
        packet0(INTERNAL_DATA1),
        // linux: n/a (literal in vcn_v2_0.c:vcn_v2_0_dec_ring_emit_fence)
        (address >> 32) as u32 & 0xff,
        packet0(INTERNAL_CMD),
        DEC_KMD | (DEC_FENCE << 1),
        packet0(INTERNAL_DATA0),
        0,
        packet0(INTERNAL_DATA1),
        0,
        packet0(INTERNAL_CMD),
        DEC_KMD | (DEC_TRAP << 1),
    ]
}
/// `vcn_v2_0_dec_ring_insert_start`.
pub(crate) fn dec_start() -> [u32; 4] {
    use cmd::*;
    [
        packet0(INTERNAL_DATA0),
        0,
        packet0(INTERNAL_CMD),
        DEC_KMD | (DEC_PACKET_START << 1),
    ]
}
/// `vcn_v2_0_dec_ring_emit_ib`, VMID0.
fn dec_ib(address: u64, dwords: u32) -> [u32; 8] {
    use cmd::*;
    [
        packet0(INTERNAL_IB_VMID),
        0,
        packet0(INTERNAL_IB_BAR_LOW),
        address as u32,
        packet0(INTERNAL_IB_BAR_HIGH),
        (address >> 32) as u32,
        packet0(INTERNAL_IB_SIZE),
        dwords,
    ]
}
/// `vcn_v2_0_dec_ring_insert_end`.
pub(crate) fn dec_end() -> [u32; 2] {
    [
        cmd::packet0(cmd::INTERNAL_CMD),
        cmd::DEC_KMD | (cmd::DEC_PACKET_END << 1),
    ]
}
/// `amdgpu_vcn_dec_send_msg`: the 16-dword IB that hands a message to the
/// decoder (DATA0/DATA1 = message address, CMD 0, NOP padding).
fn dec_msg_ib(msg: u64) -> [u32; 16] {
    use cmd::*;
    let mut ib = [0; 16];
    ib[..6].copy_from_slice(&[
        packet0(INTERNAL_DATA0),
        msg as u32,
        packet0(INTERNAL_DATA1),
        (msg >> 32) as u32,
        packet0(INTERNAL_CMD),
        0,
    ]);
    for pair in ib[6..].chunks_exact_mut(2) {
        pair[0] = packet0(INTERNAL_NOP);
    }
    ib
}
/// `amdgpu_vcn_dec_get_create_msg` / `_destroy_msg`, handle 1. The rest of
/// the 1024-dword message is zero.
pub(crate) fn dec_msg(create: bool) -> [u32; 14] {
    if create {
        // linux: n/a (msg literals in amdgpu_vcn.c:amdgpu_vcn_dec_get_create_msg, handle 1)
        [0x28, 0x38, 1, 0, 1, 0, 1, 0x28, 0x10, 0, 7, 0, 0x780, 0x440]
    } else {
        // linux: n/a (msg literals in amdgpu_vcn.c:amdgpu_vcn_dec_get_destroy_msg, handle 1)
        [0x28, 0x18, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }
}
/// `amdgpu_vcn_enc_get_create_msg` / `_destroy_msg` IB (16 dwords, no
/// unified-queue header on VCN 3.0): session info, task info, op.
pub(crate) fn enc_msg_ib(session: u64, create: bool) -> [u32; 16] {
    let mut ib = [0; 16];
    // linux: n/a (IB literals in amdgpu_vcn.c:amdgpu_vcn_enc_get_create_msg/_destroy_msg)
    ib[..13].copy_from_slice(&[
        0x18,
        1,
        1,
        (session >> 32) as u32,
        session as u32,
        0,
        0x14,
        2,
        0x1c,
        0,
        0,
        8,
        if create { 0x0800_0001 } else { 0x0800_0002 },
    ]);
    ib
}

impl<I: Io> Engine<I> {
    fn active(&self) -> impl Iterator<Item = usize> + '_ {
        (0..2).filter(|&i| self.vcn[i].is_some())
    }
    /// `vcn_v3_0_hw_init` (non-SR-IOV): per unharvested instance, the NBIO
    /// MMSCH doorbell range, then `amdgpu_ring_test_helper` on the decode
    /// ring (whose begin_use runs `vcn_v3_0_start`) and both encode rings.
    pub(crate) async fn start(
        &mut self,
        firmware: crate::amdgpu_psp_ring::MediaFirmware,
        power: Option<crate::amdgpu_smu_navi22::PowerStatus>,
    ) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        let images = [firmware.vcn, firmware.vcn1];
        let missing = self.active().any(|i| images[i].is_none());
        // FEATURE_MM_DPM_PG_BIT (22): Linux would send PowerUpVcn here.
        // linux-lit: 22=FEATURE_MM_DPM_PG_BIT
        let gated = power.is_some_and(|p| p.enabled & (1 << 22) != 0);
        if self.vcn.iter().all(Option::is_none) || missing || gated {
            self.state = State::Failed;
            return Err(if gated {
                Error::PowerGated
            } else {
                Error::Invalid
            });
        }
        self.state = State::Starting(0);
        let result = self.start_inner(images).await;
        self.state = if result.is_ok() {
            State::Running
        } else {
            State::Failed
        };
        result
    }
    async fn start_inner(&mut self, images: [Option<u64>; 2]) -> Result<(), Error> {
        // gfx_v10_0_gpu_early_init: GC 10.3 reads GB_ADDR_CONFIG as-is.
        let gb_addr_config = self
            .hw
            .access(|io, l| checked(io.read(l.gc + u64::from(GB_ADDR_CONFIG) * 4)))?;
        for (i, image) in images.into_iter().enumerate() {
            let Some(firmware) = image else {
                continue;
            };
            if self.vcn[i].is_none() {
                continue;
            }
            self.state = State::Starting(i as u8);
            self.prepare_instance(i)?;
            self.start_instance(i, firmware, gb_addr_config).await?;
            self.test_dec_ring(i).await?;
            self.proof.dec_ring[i] = true;
            for j in 0..self.enc_count {
                self.test_enc_ring(i, j).await?;
                self.proof.enc_ring[i][j] = true;
            }
        }
        Ok(())
    }
    /// `amdgpu_vcn_resume` (PSP: zero the whole VCPU BO) and the fw_shared
    /// flags `vcn_v3_0_sw_init` sets, then the doorbell range.
    fn prepare_instance(&mut self, i: usize) -> Result<(), Error> {
        let instance = self.vcn[i].as_mut().ok_or(Error::Invalid)?;
        let map = instance.memory.mapping();
        let index = instance.dec.doorbell;
        self.hw.access(|io, l| {
            // linux-lit: 1=RCC_DEV0_EPF0_RCC_DOORBELL_APER_EN__BIF_DOORBELL_APER_EN_MASK
            if checked(io.read(l.nbio(NBIO_DOORBELL_APER_EN)))? & 1 == 0 {
                // Doorbells stage did not open the NBIF aperture.
                return Err(Error::Invalid);
            }
            io.zero_memory(map, 0, INSTANCE_BYTES);
            io.write_memory(map, SHARED + shared::PRESENT_FLAG_0, shared::PRESENT);
            flush(io, l);
            // nbio_v2_3_vcn_doorbell_range: OFFSET[11:2] = index, SIZE 8.
            update(
                io,
                l.nbio(NBIO_MMSCH_DOORBELL_RANGE[i]),
                // linux-lit: 0x001f_0ffc=BIF_MMSCH0_DOORBELL_RANGE__OFFSET_MASK | BIF_MMSCH0_DOORBELL_RANGE__SIZE_MASK
                0x001f_0ffc,
                // linux-lit: 2=BIF_MMSCH0_DOORBELL_RANGE__OFFSET__SHIFT; 0xffc=BIF_MMSCH0_DOORBELL_RANGE__OFFSET_MASK; 16=BIF_MMSCH0_DOORBELL_RANGE__SIZE__SHIFT
                ((index << 2) & 0xffc) | (doorbell::RANGE << 16),
            )
        })?;
        // Published before the VCPU can learn any of these addresses.
        instance.memory.publish();
        for ring in [&mut instance.dec]
            .into_iter()
            .chain(instance.enc.iter_mut())
        {
            ring.reset();
        }
        Ok(())
    }
    /// `vcn_v3_0_start`, static (non-DPG) path with VCN power gating off.
    async fn start_instance(
        &mut self,
        i: usize,
        firmware: u64,
        gb_addr_config: u32,
    ) -> Result<(), Error> {
        let instance = self.vcn[i].as_ref().ok_or(Error::Invalid)?;
        let (engine, base) = (instance.engine, instance.address(0));
        let shared_address = instance.address(SHARED);
        // linux: n/a (AMDGPU_GPU_PAGE_ALIGN(fw->size + 4), vcn_v3_0_mc_resume)
        let cache0 = (self.firmware_bytes + 4 + 4095) & !4095;
        let r = move |l: Layout, reg: Reg| l.reg(i, reg);
        // vcn_v3_0_disable_static_power_gating, !AMD_PG_SUPPORT_VCN branch.
        self.hw.access(|io, l| {
            // UVD_STATUS belongs to the gated domain. Like vcn_v3_0_start,
            // power the tiles first; GC and NBIO liveness were checked before
            // reaching here. A gated status read is not proof of device loss.
            io.write(r(l, PGFSM_CONFIG), PGFSM_ALL_ON);
            Ok(())
        })?;
        let status = self.hw.layout.reg(i, PGFSM_STATUS);
        self.hw
            .wait_reg(engine, status, 0, PGFSM_STATUS_MASK)
            .await?;
        self.hw.access(|io, l| {
            update(io, r(l, POWER_STATUS), POWER_STATUS_CLEAR, 0)?;
            // set VCN status busy
            update(io, r(l, STATUS), STATUS_UVD_BUSY, STATUS_UVD_BUSY)?;
            // vcn_v3_0_disable_clock_gating with AMD_CG_SUPPORT_VCN_MGCG
            let ctrl = checked(io.read(r(l, CGC_CTRL)))?;
            io.write(r(l, CGC_CTRL), ctrl | CGC_CTRL_DYN);
            update(io, r(l, CGC_GATE), CGC_GATE_ALL, 0)?;
            Ok(())
        })?;
        let gate = self.hw.layout.reg(i, CGC_GATE);
        self.hw.wait_reg(engine, gate, 0, u32::MAX).await?;
        self.hw.access(|io, l| {
            update(io, r(l, CGC_CTRL), CGC_CTRL_MODES, 0)?;
            update(
                io,
                r(l, SUVD_CGC_GATE),
                SUVD_CGC_GATE_ALL,
                SUVD_CGC_GATE_ALL,
            )?;
            update(
                io,
                r(l, SUVD_CGC_GATE2),
                SUVD_CGC_GATE2_ALL,
                SUVD_CGC_GATE2_ALL,
            )?;
            update(io, r(l, SUVD_CGC_CTRL), SUVD_CGC_CTRL_MODES, 0)?;
            // enable VCPU clock, disable master interrupt, LMI channels on
            update_vcpu(io, l, i, VCPU_CLK_EN, VCPU_CLK_EN)?;
            update(io, r(l, MASTINT_EN), MASTINT_VCPU_EN, 0)?;
            update(io, r(l, LMI_CTRL2), LMI_CTRL2_STALL_ARB_UMC, 0)?;
            update(io, r(l, SOFT_RESET), SOFT_RESET_LMI | SOFT_RESET_LMI_UMC, 0)?;
            let lmi = checked(io.read(r(l, LMI_CTRL)))?;
            io.write(r(l, LMI_CTRL), lmi | LMI_CTRL_SET);
            // linux-lit: 3=UVD_MPC_CNTL__REPLACEMENT_MODE__SHIFT
            update(io, r(l, MPC_CNTL), MPC_REPLACEMENT_MODE, 2 << 3)?;
            io.write(r(l, MPC_SET_MUXA0), MPC_MUX0);
            io.write(r(l, MPC_SET_MUXB0), MPC_MUX0);
            io.write(r(l, MPC_SET_MUX), MPC_MUX);
            // vcn_v3_0_mc_resume, AMDGPU_FW_LOAD_PSP: window 0 is the TMR copy
            for (low, high, value) in [
                (LMI_VCPU_CACHE_BAR_LOW, LMI_VCPU_CACHE_BAR_HIGH, firmware),
                (
                    LMI_VCPU_CACHE1_BAR_LOW,
                    LMI_VCPU_CACHE1_BAR_HIGH,
                    base + STACK,
                ),
                (
                    LMI_VCPU_CACHE2_BAR_LOW,
                    LMI_VCPU_CACHE2_BAR_HIGH,
                    base + CONTEXT,
                ),
                (LMI_VCPU_NC0_BAR_LOW, LMI_VCPU_NC0_BAR_HIGH, shared_address),
            ] {
                io.write(r(l, low), value as u32);
                io.write(r(l, high), (value >> 32) as u32);
                if low == LMI_VCPU_CACHE_BAR_LOW {
                    io.write(r(l, VCPU_CACHE_OFFSET0), 0);
                    io.write(r(l, VCPU_CACHE_SIZE0), cache0);
                }
            }
            io.write(r(l, VCPU_CACHE_OFFSET1), 0);
            io.write(r(l, VCPU_CACHE_SIZE1), STACK_SIZE);
            io.write(r(l, VCPU_CACHE_OFFSET2), 0);
            io.write(r(l, VCPU_CACHE_SIZE2), CONTEXT_SIZE);
            io.write(r(l, VCPU_NONCACHE_OFFSET0), 0);
            io.write(r(l, VCPU_NONCACHE_SIZE0), SHARED_SIZE);
            io.write(r(l, GFX10_ADDR_CONFIG), gb_addr_config);
            // unblock VCPU register access, release VCPU reset to boot
            update(io, r(l, RB_ARB_CTRL), RB_ARB_VCPU_DIS, 0)?;
            update_vcpu(io, l, i, VCPU_BLK_RST, 0)?;
            Ok(())
        })?;
        let attempt = self.boot_vcpu(i).await?;
        self.proof.booted[i] = attempt;
        self.program_rings(i)
    }
    /// The `for (j = 0; j < 10; ++j)` boot loop of `vcn_v3_0_start`.
    async fn boot_vcpu(&mut self, i: usize) -> Result<u8, Error> {
        let t = self.timing;
        for attempt in 1..=t.retries {
            for _ in 0..t.polls {
                let status = self.hw.access(|io, l| checked(io.read(l.reg(i, STATUS))))?;
                if status & VCPU_REPORT_BOOTED != 0 {
                    return Ok(attempt as u8);
                }
                delay(t.poll_us).await;
            }
            // "decode not responding, trying to reset the VCPU"
            self.hw
                .access(|io, l| update_vcpu(io, l, i, VCPU_BLK_RST, VCPU_BLK_RST))?;
            delay(t.reset_us).await;
            self.hw
                .access(|io, l| update_vcpu(io, l, i, VCPU_BLK_RST, 0))?;
            delay(t.reset_us).await;
        }
        Err(Error::BootFailed(i as u8))
    }
    /// Tail of `vcn_v3_0_start`: master interrupt, decode RBC and both
    /// encode rings, each bracketed by the fw_shared FW_QUEUE_RING_RESET.
    fn program_rings(&mut self, i: usize) -> Result<(), Error> {
        let enc_count = self.enc_count;
        let instance = self.vcn[i].as_mut().ok_or(Error::Invalid)?;
        let map = instance.memory.mapping();
        let dec = instance.address(DEC_RING);
        let enc = [instance.address(ENC_RING[0]), instance.address(ENC_RING[1])];
        let wptr = self.hw.access(|io, l| {
            let r = |reg: Reg| l.reg(i, reg);
            update(io, r(MASTINT_EN), MASTINT_VCPU_EN, MASTINT_VCPU_EN)?;
            // clear the busy bit of VCN_STATUS (2 << VCPU_REPORT__SHIFT)
            update(io, r(STATUS), STATUS_UVD_BUSY, 0)?;
            io.write(r(LMI_RBC_RB_VMID), 0);
            io.write(r(RBC_RB_CNTL), RBC_RB_CNTL_IDLE);
            let modes = |io: &mut I, value: u32| {
                io.write_memory(map, SHARED + shared::QUEUE_MODES, value);
                flush(io, l);
            };
            modes(io, shared::RING_RESET << shared::DECODE_SHIFT);
            io.write(r(LMI_RBC_RB_BAR_LOW), dec as u32);
            io.write(r(LMI_RBC_RB_BAR_HIGH), (dec >> 32) as u32);
            io.write(r(RBC_RB_RPTR), 0);
            io.write(r(SCRATCH2), 0);
            let wptr = checked(io.read(r(RBC_RB_RPTR)))?;
            io.write(r(RBC_RB_WPTR), wptr);
            io.write_memory(map, SHARED + shared::RB_WPTR, wptr);
            modes(io, 0);
            for j in 0..enc_count {
                modes(io, shared::RING_RESET << shared::ENCODE_SHIFT[j]);
                io.write(r(RB_RPTR[j]), 0);
                io.write(r(RB_WPTR[j]), 0);
                io.write(r(RB_BASE_LO[j]), enc[j] as u32);
                io.write(r(RB_BASE_HI[j]), (enc[j] >> 32) as u32);
                io.write(r(RB_SIZE[j]), RING_DW);
                modes(io, 0);
            }
            // Keeping one read-back to ensure all register writes are done.
            checked(io.read(r(STATUS)))?;
            Ok(wptr)
        })?;
        if wptr >= RING_DW {
            return Err(Error::Invalid);
        }
        instance.dec.wptr = wptr;
        Ok(())
    }
    /// `vcn_v2_0_dec_ring_test_ring` through UVD_SCRATCH9.
    async fn test_dec_ring(&mut self, i: usize) -> Result<(), Error> {
        let instance = self.vcn[i].as_mut().ok_or(Error::Invalid)?;
        let (map, engine) = (instance.memory.mapping(), instance.engine);
        let ring = &mut instance.dec;
        self.hw.access(|io, l| {
            // linux: n/a (literal in amdgpu_vcn_dec_ring_test_ring)
            io.write(l.reg(i, SCRATCH9), 0xcafe_dead);
            ring.emit(
                io,
                map,
                &[
                    cmd::packet0(cmd::INTERNAL_CMD),
                    cmd::DEC_KMD | (cmd::DEC_PACKET_START << 1),
                    cmd::packet0(cmd::INTERNAL_SCRATCH9),
                    0xdead_beef,
                ],
            )?;
            ring.commit(io, map, l);
            Ok(())
        })?;
        self.hw
            .poll(engine, REG_TIMEOUT_MS, |io, l| {
                Ok((checked(io.read(l.reg(i, SCRATCH9)))? == 0xdead_beef).then_some(()))
            })
            .await
    }
    /// `amdgpu_vcn_enc_ring_test_ring`: VCN_ENC_CMD_END must move the rptr.
    async fn test_enc_ring(&mut self, i: usize, j: usize) -> Result<(), Error> {
        let instance = self.vcn[i].as_mut().ok_or(Error::Invalid)?;
        let (map, engine) = (instance.memory.mapping(), instance.engine);
        let ring = &mut instance.enc[j];
        let rptr = self.hw.access(|io, l| {
            let rptr = checked(io.read(l.reg(i, RB_RPTR[j])))?;
            ring.emit(io, map, &[cmd::ENC_END])?;
            ring.commit(io, map, l);
            Ok(rptr)
        })?;
        self.hw
            .poll(engine, REG_TIMEOUT_MS, |io, l| {
                Ok((checked(io.read(l.reg(i, RB_RPTR[j])))? != rptr).then_some(()))
            })
            .await
    }
    /// `amdgpu_ib_ring_tests` for every VCN ring: the decoder create/destroy
    /// message pair and the encoder session initialize/close pair.
    pub(crate) async fn test_ib(&mut self) -> Result<(), Error> {
        if self.state != State::Running {
            return Err(Error::Busy);
        }
        self.state = State::Testing;
        let mut result = Ok(());
        let instances: alloc::vec::Vec<usize> = self.active().collect();
        for i in instances {
            result = self.test_dec_ib(i).await;
            for j in 0..self.enc_count {
                if result.is_ok() {
                    result = self.test_enc_ib(i, j).await;
                }
            }
            if result.is_err() {
                break;
            }
        }
        self.state = if result.is_ok() {
            State::Verified
        } else {
            State::Failed
        };
        result
    }
    async fn wait_fence(&mut self, i: usize, slot: usize, seq: u32) -> Result<(), Error> {
        let instance = self.vcn[i].as_ref().ok_or(Error::Invalid)?;
        let (map, engine) = (instance.memory.mapping(), instance.engine);
        self.hw
            .poll(engine, FENCE_TIMEOUT_MS, |io, l| {
                invalidate(io, l);
                let value = io.read_memory(map, FENCE[slot]);
                if value == u32::MAX {
                    // All-ones VRAM: a removed device also fails register reads.
                    checked(io.read(l.reg(i, STATUS)))?;
                }
                Ok(fence::signaled(value, seq).then_some(()))
            })
            .await
    }
    /// `amdgpu_vcn_dec_ring_test_ib`: create then destroy session 1, each a
    /// direct submission (`amdgpu_ib_schedule`: insert_start, IB, fence,
    /// insert_end); wait for the destroy fence.
    async fn test_dec_ib(&mut self, i: usize) -> Result<(), Error> {
        let instance = self.vcn[i].as_mut().ok_or(Error::Invalid)?;
        let map = instance.memory.mapping();
        let fence_address = instance.address(FENCE[0]);
        let mut last = 0;
        for (k, create) in [(0, true), (1, false)] {
            let msg = instance.address(MSG[k]);
            let ib = instance.address(IBS[k]);
            let ring = &mut instance.dec;
            let seq = ring.next_seq();
            last = seq;
            self.hw.access(|io, l| {
                checked(io.read(l.reg(i, STATUS)))?;
                let words = dec_msg(create);
                for at in 0..1024u64 {
                    let word = words.get(at as usize).copied().unwrap_or(0);
                    io.write_memory(map, MSG[k] + at * 4, word);
                }
                for (at, &word) in dec_msg_ib(msg).iter().enumerate() {
                    io.write_memory(map, IBS[k] + at as u64 * 4, word);
                }
                ring.emit(io, map, &dec_start())?;
                ring.emit(io, map, &dec_ib(ib, 16))?;
                ring.emit(io, map, &dec_fence(fence_address, seq))?;
                ring.emit(io, map, &dec_end())?;
                ring.commit(io, map, l);
                Ok(())
            })?;
        }
        self.wait_fence(i, 0, last).await?;
        self.proof.dec_ib[i] = last;
        Ok(())
    }
    /// `amdgpu_vcn_enc_ring_test_ib`: initialize then close session 1 on
    /// ring j (`vcn_v2_0_enc_ring_emit_ib/_fence`, insert_end).
    async fn test_enc_ib(&mut self, i: usize, j: usize) -> Result<(), Error> {
        let instance = self.vcn[i].as_mut().ok_or(Error::Invalid)?;
        let map = instance.memory.mapping();
        let fence_address = instance.address(FENCE[1 + j]);
        let session = instance.address(SESSION);
        let mut last = 0;
        for (k, create) in [(2, true), (3, false)] {
            let ib = instance.address(IBS[k]);
            let ring = &mut instance.enc[j];
            let seq = ring.next_seq();
            last = seq;
            self.hw.access(|io, l| {
                checked(io.read(l.reg(i, STATUS)))?;
                for (at, &word) in enc_msg_ib(session, create).iter().enumerate() {
                    io.write_memory(map, IBS[k] + at as u64 * 4, word);
                }
                ring.emit(io, map, &[cmd::ENC_IB, 0, ib as u32, (ib >> 32) as u32, 16])?;
                ring.emit(
                    io,
                    map,
                    &[
                        cmd::ENC_FENCE,
                        fence_address as u32,
                        (fence_address >> 32) as u32,
                        seq,
                        cmd::ENC_TRAP,
                    ],
                )?;
                ring.emit(io, map, &[cmd::ENC_END])?;
                ring.commit(io, map, l);
                Ok(())
            })?;
        }
        self.wait_fence(i, 1 + j, last).await?;
        self.proof.enc_ib[i][j] = last;
        Ok(())
    }
    /// `vcn_v3_0_stop` (non-DPG) for every started instance, and
    /// `jpeg_v3_0_stop` when JPEG runs. Power gating stays disabled, so the
    /// static PG re-enable steps are skipped; nothing is restarted.
    pub(crate) async fn stop(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Running | State::Verified) {
            return Err(Error::Busy);
        }
        self.state = State::Stopping;
        let result = self.stop_inner().await;
        self.state = if result.is_ok() {
            State::Stopped
        } else {
            State::Failed
        };
        result
    }
    async fn stop_inner(&mut self) -> Result<(), Error> {
        if self.jpeg_state == JpegState::Verified {
            self.hw.access(|io, l| {
                let r = |reg: Reg| l.reg(0, reg);
                update(io, r(JMI_CNTL), JMI_SOFT_RESET, JMI_SOFT_RESET)?;
                // jpeg_v3_0_enable_clock_gating; anti-hang on, no PGFSM.
                update(io, r(JPEG_CGC_GATE), JPEG_CGC_GATE_ALL, JPEG_CGC_GATE_ALL)?;
                update(io, r(JPEG_POWER_STATUS), JPEG_POWER_STATUS_MASK, 1)
            })?;
            self.jpeg_state = JpegState::Stopped;
        }
        let instances: alloc::vec::Vec<usize> = self.active().collect();
        for i in instances {
            let engine = self.vcn[i].as_ref().ok_or(Error::Invalid)?.engine;
            let reg = |l: Layout, r: Reg| l.reg(i, r);
            let (status, lmi) = (reg(self.hw.layout, STATUS), reg(self.hw.layout, LMI_STATUS));
            // linux: n/a (literal 0x7, vcn_v3_0_stop)
            self.hw.wait_reg(engine, status, STATUS_IDLE, 0x7).await?;
            self.hw
                .wait_reg(engine, lmi, LMI_STATUS_CLEAN, LMI_STATUS_CLEAN)
                .await?;
            self.hw.access(|io, l| {
                update(
                    io,
                    reg(l, LMI_CTRL2),
                    LMI_CTRL2_STALL_ARB_UMC,
                    LMI_CTRL2_STALL_ARB_UMC,
                )
            })?;
            self.hw
                .wait_reg(engine, lmi, LMI_STATUS_UMC_CLEAN, LMI_STATUS_UMC_CLEAN)
                .await?;
            self.hw.access(|io, l| {
                let r = |x: Reg| reg(l, x);
                update(io, r(RB_ARB_CTRL), RB_ARB_VCPU_DIS, RB_ARB_VCPU_DIS)?;
                update_vcpu(io, l, i, VCPU_BLK_RST, VCPU_BLK_RST)?;
                update_vcpu(io, l, i, VCPU_CLK_EN, 0)?;
                update(io, r(SOFT_RESET), SOFT_RESET_LMI_UMC, SOFT_RESET_LMI_UMC)?;
                update(io, r(SOFT_RESET), SOFT_RESET_LMI, SOFT_RESET_LMI)?;
                io.write(r(STATUS), 0);
                // vcn_v3_0_enable_clock_gating
                let ctrl = checked(io.read(r(CGC_CTRL)))?;
                io.write(r(CGC_CTRL), ctrl | CGC_CTRL_DYN);
                update(io, r(CGC_CTRL), CGC_CTRL_MODES, CGC_CTRL_MODES)?;
                update(
                    io,
                    r(SUVD_CGC_CTRL),
                    SUVD_CGC_CTRL_MODES,
                    SUVD_CGC_CTRL_MODES,
                )?;
                checked(io.read(r(STATUS)))?;
                Ok(())
            })?;
        }
        Ok(())
    }
    /// `jpeg_v3_0_early_init` harvest check, `jpeg_v3_0_hw_init` (doorbell
    /// range) and `amdgpu_jpeg_dec_ring_test_ring`, whose begin_use runs
    /// `jpeg_v3_0_start` with JPEG power gating disabled.
    pub(crate) async fn start_jpeg(&mut self) -> Result<(), Error> {
        if self.jpeg_state != JpegState::Prepared {
            return Err(Error::Busy);
        }
        self.jpeg_state = JpegState::Starting;
        let result = self.start_jpeg_inner().await;
        self.jpeg_state = match result {
            Ok(true) => JpegState::Verified,
            Ok(false) => JpegState::Absent,
            Err(_) => JpegState::Failed,
        };
        result.map(|_| ())
    }
    async fn start_jpeg_inner(&mut self) -> Result<bool, Error> {
        let jpeg = self.jpeg.as_mut().ok_or(Error::Invalid)?;
        let (map, address) = (jpeg.memory.mapping(), jpeg.memory.address());
        let r = |l: Layout, reg: Reg| l.reg(0, reg);
        let present = self.hw.access(|io, l| {
            let harvest = checked(io.read(r(l, CC_UVD_HARVESTING)))?;
            if harvest & CC_UVD_DISABLE != 0 {
                return Ok(false);
            }
            // linux-lit: 1=RCC_DEV0_EPF0_RCC_DOORBELL_APER_EN__BIF_DOORBELL_APER_EN_MASK
            if checked(io.read(l.nbio(NBIO_DOORBELL_APER_EN)))? & 1 == 0 {
                return Err(Error::Invalid);
            }
            io.zero_memory(map, 0, JPEG_BYTES);
            flush(io, l);
            // jpeg_v3_0_hw_init: MMSCH0 range starts at the VCN0 ring base.
            update(
                io,
                l.nbio(NBIO_MMSCH_DOORBELL_RANGE[0]),
                // linux-lit: 0x001f_0ffc=BIF_MMSCH0_DOORBELL_RANGE__OFFSET_MASK | BIF_MMSCH0_DOORBELL_RANGE__SIZE_MASK
                0x001f_0ffc,
                // linux-lit: 2=BIF_MMSCH0_DOORBELL_RANGE__OFFSET__SHIFT; 0xffc=BIF_MMSCH0_DOORBELL_RANGE__OFFSET_MASK; 16=BIF_MMSCH0_DOORBELL_RANGE__SIZE__SHIFT
                ((doorbell::VCN_BASE << 2) & 0xffc) | (doorbell::RANGE << 16),
            )?;
            // jpeg_v3_0_disable_static_power_gating: power UVDJ on
            io.write(r(l, PGFSM_CONFIG), PGFSM_UVDJ_ON);
            Ok(true)
        })?;
        if !present {
            return Ok(false);
        }
        jpeg.memory.publish();
        let status = self.hw.layout.reg(0, PGFSM_STATUS);
        self.hw
            .wait_reg(fence::Engine::Jpeg, status, 0, PGFSM_UVDJ_STATUS)
            .await?;
        let jpeg = self.jpeg.as_mut().ok_or(Error::Invalid)?;
        let ring = &mut jpeg.ring;
        ring.reset();
        self.hw.access(|io, l| {
            // anti-hang off, static PG mode
            update(io, r(l, JPEG_POWER_STATUS), JPEG_POWER_STATUS_MASK, 0)?;
            update(io, r(l, JPEG_POWER_STATUS), JPEG_PG_MODE, 0)?;
            // jpeg_v3_0_disable_clock_gating with AMD_CG_SUPPORT_JPEG_MGCG
            let ctrl = checked(io.read(r(l, JPEG_CGC_CTRL)))?;
            io.write(r(l, JPEG_CGC_CTRL), ctrl | JPEG_CGC_CTRL_DYN);
            update(io, r(l, JPEG_CGC_GATE), JPEG_CGC_GATE_ALL, 0)?;
            update(io, r(l, JPEG_CGC_CTRL), JPEG_CGC_CTRL_MODES, 0)?;
            let gb = checked(io.read(l.gc + u64::from(GB_ADDR_CONFIG) * 4))?;
            io.write(r(l, JPEG_DEC_GFX10_ADDR_CONFIG), gb);
            io.write(r(l, JPEG_ENC_GFX10_ADDR_CONFIG), gb);
            update(io, r(l, JMI_CNTL), JMI_SOFT_RESET, 0)?;
            update(
                io,
                r(l, JPEG_SYS_INT_EN),
                JPEG_SYS_INT_DJRBC,
                JPEG_SYS_INT_DJRBC,
            )?;
            io.write(r(l, LMI_JRBC_RB_VMID), 0);
            // linux-lit: 3=UVD_JRBC_RB_CNTL__RB_NO_FETCH_MASK | UVD_JRBC_RB_CNTL__RB_RPTR_WR_EN_MASK
            io.write(r(l, JRBC_RB_CNTL), 3);
            io.write(r(l, LMI_JRBC_RB_BAR_LOW), address as u32);
            io.write(r(l, LMI_JRBC_RB_BAR_HIGH), (address >> 32) as u32);
            io.write(r(l, JRBC_RB_RPTR), 0);
            io.write(r(l, JRBC_RB_WPTR), 0);
            io.write(r(l, JRBC_RB_CNTL), 2); // linux-lit: 2=UVD_JRBC_RB_CNTL__RB_RPTR_WR_EN_MASK
            io.write(r(l, JRBC_RB_SIZE), RING_DW);
            let wptr = checked(io.read(r(l, JRBC_RB_WPTR)))?;
            if wptr >= RING_DW {
                return Err(Error::Invalid);
            }
            ring.wptr = wptr;
            // amdgpu_jpeg_dec_ring_test_ring
            // linux: n/a (literal in amdgpu_jpeg_dec_ring_test_ring)
            io.write(r(l, JPEG_PITCH), 0xcafe_dead);
            checked(io.read(r(l, JPEG_PITCH)))?;
            ring.emit(
                io,
                map,
                &[cmd::packet0(cmd::JPEG_INTERNAL_PITCH), 0xabad_cafe],
            )?;
            ring.commit(io, map, l);
            Ok(())
        })?;
        self.hw
            .poll(fence::Engine::Jpeg, REG_TIMEOUT_MS, |io, l| {
                Ok((checked(io.read(r(l, JPEG_PITCH)))? == 0xabad_cafe).then_some(()))
            })
            .await?;
        self.proof.jpeg_ring = true;
        Ok(true)
    }
}

/// Kernel queue a VCN/JPEG trap completed (`vcn_v3_0_process_interrupt`,
/// `jpeg_v3_0_process_interrupt`). One fence slot per VCN instance.
pub fn fence_engine(iv: &crate::amdgpu_ih_navi22::Iv) -> Option<fence::Engine> {
    use crate::amdgpu_ih_navi22::{source, Source};
    let from = Source {
        client: iv.client,
        src: iv.src,
    };
    if from == source::JPEG_DEC {
        return Some(fence::Engine::Jpeg);
    }
    if from == source::VCN0_DEC || source::VCN0_ENC.contains(&from) {
        return Some(fence::Engine::Vcn0);
    }
    (from == source::VCN1_DEC || source::VCN1_ENC.contains(&from)).then_some(fence::Engine::Vcn1)
}
/// IH sources the started engines raise. VCN traps need no arming:
/// `vcn_v3_0_set_interrupt_state` is empty and UVD_MASTINT_EN is set by start.
pub fn interrupt_sources(status: Status) -> alloc::vec::Vec<crate::amdgpu_ih_navi22::Source> {
    use crate::amdgpu_ih_navi22::source;
    let mut sources = alloc::vec::Vec::new();
    for (i, (dec, enc)) in [
        (source::VCN0_DEC, source::VCN0_ENC),
        (source::VCN1_DEC, source::VCN1_ENC),
    ]
    .into_iter()
    .enumerate()
    {
        if status.proof.dec_ring[i] {
            sources.push(dec);
            sources.extend_from_slice(&enc);
        }
    }
    if status.jpeg == JpegState::Verified {
        sources.push(source::JPEG_DEC);
    }
    sources
}
/// Forward VCN/JPEG traps to fence waiters, one task per source, like the
/// kernel-queue router. Waits keep polling; interrupts only shorten them.
pub fn route_interrupts(
    ih: &crate::amdgpu_ih_navi22::Handle,
    status: Status,
) -> Result<(), crate::amdgpu_ih_navi22::Error> {
    let mut subscriptions = alloc::vec::Vec::new();
    for from in interrupt_sources(status) {
        subscriptions.push(ih.subscribe(from)?);
    }
    for mut subscription in subscriptions {
        narf_scheduler::spawn(async move {
            loop {
                match subscription.wait().await {
                    Ok(iv) => {
                        if let Some(engine) = fence_engine(&iv) {
                            fence::notify(engine);
                        }
                    }
                    Err(_) => {
                        fence::notify_all();
                        return;
                    }
                }
            }
        });
    }
    Ok(())
}

/// Owner of the Navi22 VCN 3.0 instances and JPEG 3.0 kernel rings.
#[derive(Debug)]
pub struct Media {
    engine: Engine<Mmio>,
    /// Client submission (None: MMHUB unresolved, media stays kernel-only).
    client: Option<Client>,
}
impl Media {
    /// Reserve per-instance VCPU/ring/IB storage without device I/O.
    /// `instances` is the unharvested VCN mask whose firmware PSP loads;
    /// JPEG exists when instance 0 does (`num_jpeg_inst = 1`).
    ///
    /// # Safety
    /// Caller exclusively owns this physical Navi22 GPU's VCN/JPEG blocks,
    /// the NBIF MMSCH doorbell ranges, HDP, the BAR2 doorbell page and the
    /// permanent VRAM pool. No other VCN owner may exist. The firmware TMR
    /// that PSP fills must stay alive for as long as this owner.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: crate::amdgpu_cp_navi22::Doorbells,
        instances: u8,
        firmware_bytes: usize,
    ) -> Result<Self, Error> {
        let firmware_bytes = u32::try_from(firmware_bytes).map_err(|_| Error::Invalid)?;
        if firmware_bytes == 0 || firmware_bytes > 4 << 20 {
            return Err(Error::Invalid);
        }
        let layout = Layout::resolve(gpu, instances)?;
        let mut vcn = [None, None];
        for (i, slot) in vcn.iter_mut().enumerate() {
            if instances & (1 << i) != 0 {
                *slot = Some(Instance::new(pool, i as u32)?);
            }
        }
        let jpeg = if instances & 1 != 0 {
            Some(Jpeg::new(pool)?)
        } else {
            None
        };
        let client = Client::new(gpu, pool, instances, jpeg.is_some());
        Ok(Self {
            client,
            engine: Engine {
                enc_count: if crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
                    .is_some_and(|p| p.asic == "navi24")
                {
                    0
                } else {
                    2
                },
                hw: Hw {
                    io: Mmio {
                        regs: gpu.regs,
                        doorbells: doorbells.region(),
                    },
                    authority,
                    layout,
                },
                vcn,
                jpeg_state: if jpeg.is_some() {
                    JpegState::Prepared
                } else {
                    JpegState::Absent
                },
                jpeg,
                firmware_bytes,
                timing: LINUX_TIMING,
                state: State::Prepared,
                proof: Proof {
                    instances,
                    ..Proof::default()
                },
            },
        })
    }
    /// Power, clock, boot and ring-test every owned VCN instance once.
    ///
    /// # Safety
    /// PSP loaded the VCN images reported in `firmware` into the retained
    /// TMR, both hubs' VMID0 are ready, NBIF doorbells are enabled, and
    /// `new`'s contract still holds. `power` is the SMU's enabled features.
    /// Failure or cancellation leaves the owner unusable until device reset.
    pub async unsafe fn start(
        &mut self,
        firmware: crate::amdgpu_psp_ring::MediaFirmware,
        power: Option<crate::amdgpu_smu_navi22::PowerStatus>,
    ) -> Result<(), Error> {
        self.engine.start(firmware, power).await
    }
    /// Start JPEG and ring-test it once (instance 0 register space).
    ///
    /// # Safety
    /// Same contract as `start`; JPEG shares instance 0's power controller.
    pub async unsafe fn start_jpeg(&mut self) -> Result<(), Error> {
        self.engine.start_jpeg().await
    }
    /// Decode and encode IB tests with fences on every started ring.
    pub async fn test_ib(&mut self) -> Result<(), Error> {
        self.engine.test_ib().await
    }
    /// Quiesce and halt every started engine (no restart support).
    ///
    /// # Safety
    /// No other client may have work outstanding on these engines.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        self.engine.stop().await
    }
    pub fn status(&self) -> Status {
        Status {
            state: self.engine.state,
            jpeg: self.engine.jpeg_state,
            proof: self.engine.proof,
        }
    }
}

// ── Client submission (append-only) ─────────────────────────────────────
//
// User jobs on instance 0's decode ring, both encode rings and the JPEG
// ring, framed by `amdgpu_navi22_submit::encode_media` under the client's
// VMID on MMHUB. They continue each kernel ring's fence sequence (the IB
// tests' last value) and complete through the same IH VCN/JPEG traps
// (`route_interrupts`). Instance 1 takes no client work: Linux's
// `vcn_v3_0_limit_sched` would move every non-H.264/HEVC/VP9 decode to
// instance 0 anyway, and on this card VCN1 is harvested.
use crate::amdgpu_navi22_submit::{self as submit, Ib, MediaRing, VmRef};

/// One kernel copy slot of a JPEG job's IBs (`amdgpu_jpeg_dec_parse_cs`
/// validates a copy executed at VMID 0); one slot per outstanding job.
pub(crate) const JPEG_IB_SLOT: u64 = 64 << 10; // linux: n/a (NARF bound on one JPEG job's IB bytes)
/// The JPEG ring's fence dword, after its wptr shadow.
pub(crate) const JPEG_FENCE: u64 = RING_BYTES + 64; // linux: n/a (NARF layout)

/// Client-submission state of the media owner.
#[derive(Debug)]
pub(crate) struct Client {
    /// MMHUB segment-0 dword base, for the ring-side VM flush.
    pub mmhub: u32,
    /// OSSSYS segment-0 dword base, for the MMHUB IH VMID LUT.
    pub oss: u32,
    /// Unharvested VCN instances (MMHUB invalidation-engine order).
    pub instances: u8,
    /// JPEG IB copies: `HW_SUBMISSIONS` slots of `JPEG_IB_SLOT` bytes.
    pub jpeg_ibs: Option<Reservation>,
}
impl Client {
    fn new(gpu: &AmdGpu, pool: &Pool, instances: u8, jpeg: bool) -> Option<Self> {
        // linux: n/a (MMHUB 2.1.0 discovery version)
        let base = crate::amdgpu_psp_ring::bank(
            gpu,
            ip::HW_ID_MMHUB,
            crate::amdgpu_rdna2::GMC_MMHUB_VERSIONS,
            0,
            submit::MM_PTB_HI,
        )
        .ok()?;
        // linux: n/a (OSSSYS 5.0.3 discovery version)
        let oss = crate::amdgpu_psp_ring::bank(
            gpu,
            ip::HW_ID_OSSSYS,
            crate::amdgpu_rdna2::IH_OSSSYS_VERSIONS,
            0,
            submit::IH_VMID_LUT_LAST,
        )
        .ok()?;
        let jpeg_ibs = if jpeg {
            pool.reserve(JPEG_IB_SLOT * u64::from(submit::HW_SUBMISSIONS))
                .ok()
                .map(|mut r| {
                    // Fetched by JPEG once a job uses it; never recycled.
                    r.publish();
                    r
                })
        } else {
            None
        };
        Some(Self {
            mmhub: u32::try_from(base / 4).ok()?,
            oss: u32::try_from(oss / 4).ok()?,
            instances,
            jpeg_ibs,
        })
    }
}

/// Lock-free reader of the client media rings' fences (dec, enc0, enc1,
/// JPEG), sampled after an HDP read-cache invalidate like `FenceReader`.
#[derive(Clone, Copy, Debug)]
pub struct MediaFenceReader {
    regs: MmioRegion,
    hdp_invalidate: u64,
    slots: [Option<(MmioRegion, u64)>; 4],
    authority: Cap<BusDeviceCap, Write>,
}
impl MediaFenceReader {
    /// The last sequence `ring` wrote; None when it takes no client work.
    pub fn completed(&self, ring: MediaRing) -> Result<Option<u32>, Error> {
        let Some((slot, offset)) = self.slots[ring.index()] else {
            return Ok(None);
        };
        let (regs, hdp) = (self.regs, self.hdp_invalidate);
        self.authority
            .invoke(Op(|| {
                // SAFETY: the HDP register lies in the BAR5 bank Layout
                // bounded; the slot is a published, permanent ring
                // reservation whose fence dword is in bounds.
                unsafe {
                    regs.write32(hdp, 1);
                    checked(regs.read32(hdp))?;
                    barrier(Ordering::SeqCst);
                    Ok(Some(slot.read32(offset)))
                }
            }))
            .map_err(|_| Error::Revoked)?
    }
}

impl<I: Io> Engine<I> {
    /// Whether `ring` passed its kernel ring and IB tests.
    pub(crate) fn client_ready(&self, ring: MediaRing) -> bool {
        match ring {
            MediaRing::Jpeg => self.jpeg_state == JpegState::Verified,
            MediaRing::Dec => self.state == State::Verified && self.proof.dec_ring[0],
            MediaRing::Enc(j) => {
                self.state == State::Verified && self.proof.enc_ring[0][usize::from(j & 1)]
            }
        }
    }
    /// The ring, its reservation's mapping and MC address, and the ring's
    /// fence offset in it.
    fn client_ring(&mut self, ring: MediaRing) -> Result<(&mut Ring, MmioRegion, u64, u64), Error> {
        if !self.client_ready(ring) {
            return Err(Error::Busy);
        }
        client_ring(&mut self.vcn[0], &mut self.jpeg, ring)
    }
    /// (last completed, throttle) sequences of client ring `ring`.
    pub(crate) fn client_fences(&mut self, ring: MediaRing) -> Result<(u32, u32), Error> {
        let (r, map, _, fence_at) = self.client_ring(ring)?;
        let throttle = r.seq.wrapping_sub(submit::HW_SUBMISSIONS - 1);
        let completed = self.hw.access(|io, l| {
            invalidate(io, l);
            checked(io.read(l.hdp + 0xd1 * 4))?;
            Ok(io.read_memory(map, fence_at))
        })?;
        Ok((completed, throttle))
    }
    /// Queue one client job on `ring` (see `amdgpu_navi22_submit`'s media
    /// section). JPEG IBs arrive as validated copies (`copies`, one per IB),
    /// written to a kernel slot and fetched at VMID 0; VCN IBs run from the
    /// client's VA. `vm` is the job's MMHUB grant (`media_grant`). `Busy`:
    /// two jobs outstanding — wait for the throttle sequence of
    /// [`Engine::client_fences`] and retry.
    pub(crate) fn submit_client(
        &mut self,
        client: &Client,
        ring: MediaRing,
        vm: VmRef,
        ibs: &[Ib],
        copies: &[alloc::vec::Vec<u32>],
    ) -> Result<u32, Error> {
        submit::validate_media(vm, ibs).map_err(|_| Error::Invalid)?;
        let jpeg_slot = if ring == MediaRing::Jpeg {
            let pool = client.jpeg_ibs.as_ref().ok_or(Error::Unsupported)?;
            let bytes: u64 = copies.iter().map(|c| c.len() as u64 * 4).sum();
            if copies.len() != ibs.len()
                || copies
                    .iter()
                    .zip(ibs)
                    .any(|(c, ib)| c.len() != ib.dwords as usize)
                || bytes > JPEG_IB_SLOT
            {
                return Err(Error::Invalid);
            }
            Some((pool.mapping(), pool.address()))
        } else {
            if !copies.is_empty() {
                return Err(Error::Invalid);
            }
            None
        };
        let (completed, throttle) = self.client_fences(ring)?;
        if !fence::signaled(completed, throttle) {
            return Err(Error::Busy);
        }
        let engine = ring.inv_engine_for(client.instances, self.enc_count as u8);
        let (r, map, base, fence_at) = client_ring(&mut self.vcn[0], &mut self.jpeg, ring)?;
        let (fence_address, ring_base) = (base + fence_at, base + r.base);
        let seq = r.next_seq();
        // JPEG copies go to slot `seq % HW_SUBMISSIONS`, free once the job
        // two behind (the throttle fence) completed.
        let mut kernel_ibs = alloc::vec::Vec::new();
        let mut placed = alloc::vec::Vec::new();
        if let Some((pool_map, pool_mc)) = jpeg_slot {
            let mut at = u64::from(seq % submit::HW_SUBMISSIONS) * JPEG_IB_SLOT;
            for copy in copies {
                kernel_ibs.push(Ib {
                    va: pool_mc + at,
                    dwords: copy.len() as u32,
                });
                placed.push((pool_map, at, copy));
                at += copy.len() as u64 * 4;
            }
        }
        let frame = submit::MediaFrame {
            ring,
            mmhub: client.mmhub,
            engine,
            flush: vm.flush.then_some(vm),
            pasid_map: (vm.flush && vm.map_pasid).then_some((
                client.oss + submit::IH_VMID_0_LUT_MM + u32::from(vm.vmid),
                vm.pasid,
            )),
            vmid: vm.vmid,
            ibs: if jpeg_slot.is_some() {
                &kernel_ibs
            } else {
                ibs
            },
            fence: fence_address,
            seq,
            ring_base,
        };
        let words = submit::encode_media(&frame);
        let fits = words.len() as u32 + r.align() <= RING_DW / submit::HW_SUBMISSIONS;
        let result = if fits {
            self.hw.access(|io, l| {
                for (pool_map, at, copy) in &placed {
                    for (k, &word) in copy.iter().enumerate() {
                        io.write_memory(*pool_map, at + k as u64 * 4, word);
                    }
                }
                r.emit(io, map, &words)?;
                // Pads, publishes the shadow wptr, flushes HDP (which also
                // carries the JPEG copies out), rings the doorbell.
                r.commit(io, map, l);
                Ok(())
            })
        } else {
            Err(Error::Invalid)
        };
        if result.is_err() {
            // Nothing reached the engine: return the sequence.
            r.seq = seq.wrapping_sub(1);
        }
        result?;
        Ok(seq)
    }
}

/// [`Engine::client_ring`] over the split-borrowed owners.
fn client_ring<'a>(
    vcn0: &'a mut Option<Instance>,
    jpeg: &'a mut Option<Jpeg>,
    ring: MediaRing,
) -> Result<(&'a mut Ring, MmioRegion, u64, u64), Error> {
    Ok(match ring {
        MediaRing::Jpeg => {
            let jpeg = jpeg.as_mut().ok_or(Error::Invalid)?;
            let (map, base) = (jpeg.memory.mapping(), jpeg.memory.address());
            (&mut jpeg.ring, map, base, JPEG_FENCE)
        }
        MediaRing::Dec => {
            let i = vcn0.as_mut().ok_or(Error::Invalid)?;
            let (map, base) = (i.memory.mapping(), i.memory.address());
            (&mut i.dec, map, base, FENCE[0])
        }
        MediaRing::Enc(j) => {
            let i = vcn0.as_mut().ok_or(Error::Invalid)?;
            let (map, base) = (i.memory.mapping(), i.memory.address());
            let j = usize::from(j & 1);
            (&mut i.enc[j], map, base, FENCE[1 + j])
        }
    })
}

impl Media {
    /// Bit `MediaRing::index()` per ring that accepts client jobs.
    pub fn client_rings(&self) -> u8 {
        let Some(client) = self.client.as_ref() else {
            return 0;
        };
        MediaRing::ALL
            .iter()
            .filter(|&&r| self.engine.client_ready(r))
            .filter(|&&r| r != MediaRing::Jpeg || client.jpeg_ibs.is_some())
            .fold(0, |m, r| m | 1 << r.index())
    }
    /// Lock-free fence reader over the client rings.
    pub fn fence_reader(&self) -> MediaFenceReader {
        let rings = self.client_rings();
        let mut slots = [None; 4];
        if let Some(i) = self.engine.vcn[0].as_ref() {
            for (k, at) in FENCE.iter().enumerate() {
                if rings & (1 << k) != 0 {
                    slots[k] = Some((i.memory.mapping(), *at));
                }
            }
        }
        if let Some(j) = self.engine.jpeg.as_ref() {
            if rings & (1 << MediaRing::Jpeg.index()) != 0 {
                slots[3] = Some((j.memory.mapping(), JPEG_FENCE));
            }
        }
        MediaFenceReader {
            regs: self.engine.hw.io.regs,
            hdp_invalidate: self.engine.hw.layout.hdp + 0xd1 * 4, // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
            slots,
            authority: self.engine.hw.authority,
        }
    }
    /// Queue a client job (`Engine::submit_client`).
    pub fn submit(
        &mut self,
        ring: MediaRing,
        vm: VmRef,
        ibs: &[Ib],
        copies: &[alloc::vec::Vec<u32>],
    ) -> Result<u32, Error> {
        if self.client_rings() & (1 << ring.index()) == 0 {
            return Err(Error::Busy);
        }
        let client = self.client.as_ref().ok_or(Error::Unsupported)?;
        self.engine.submit_client(client, ring, vm, ibs, copies)
    }
    /// (last completed, throttle) sequences of client ring `ring`.
    pub fn client_fences(&mut self, ring: MediaRing) -> Result<(u32, u32), Error> {
        self.engine.client_fences(ring)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vcn_navi22_tests.rs"]
pub(crate) mod tests;
