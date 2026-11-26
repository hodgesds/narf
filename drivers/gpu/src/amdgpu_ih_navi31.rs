//! Navi31/32/33 OSSSYS 6.0.0 interrupt handler rings, host delivery and
//! SOC21 IV dispatch. Linux ih_v6_0.c, amdgpu_ih.c, amdgpu_irq.c,
//! nbio_v4_3.c / nbif_v6_3_1.c / nbio_v6_3_2.c / nbio_v7_7.c /
//! nbif_v7_10.c / nbio_v7_11_5.c (ih_control); osssys_6_0_0_{offset,sh_mask}.h.
//! Ring 0 is the general IV ring, ring 1 the retry-fault ring Linux redirects
//! GFX UTCL2 faults to; ring 2 was removed in IH 6.0 and there is no soft
//! ring in this owner (the Navi22 precedent skips it too). No KFD forwarding.
//!
//! Deliberate differences from Linux, each forced by the current NARF state:
//! - Both 256 KiB rings and the ring-0 wptr writeback live in owned VRAM,
//!   addressed with MC_SPACE=4 through the VMID0 system aperture the GMC v11
//!   owner programs. Linux uses GTT, but NARF VMID0 has no system-memory PTEs
//!   yet. CPU reads go through BAR0 after an HDP flush (the 0x7f000 write plus
//!   the NBIO MEMSIZE read, as the Navi48 owner does).
//! - The rptrs are written through IH_RB_RPTR / IH_RB_RPTR_RING1 with the IH
//!   doorbells disabled (the use_doorbell=false branch of
//!   ih_v6_0_doorbell_rptr / ih_v6_0_set_rptr): this owner has no BAR2 mapping.
//!   Linux's doorbell indices would be AMDGPU_NAVI10_DOORBELL_IH << 1 = 0x2f0
//!   (ring 0), 0x2f2 (ring 1) and 0x2f4 (retry CAM). The retry-CAM doorbell
//!   register is still programmed exactly as Linux programs it; the
//!   GDC0/S2A ih_doorbell_range write is not, because its register lives
//!   outside the MMIO bank model (PCIE_PORT on NBIO 7.7, S2A entry 1 on the
//!   others) and only gates doorbells this owner leaves disabled. A later
//!   lane that enables IH doorbells must program the range first.
//! - No IH_CHICKEN write: Linux sets MC_SPACE_GPA_ENABLE only for direct or
//!   RLC-backdoor firmware load; NARF loads firmware through the PSP.
//! - Ring 1's wptr is read from IH_RB_WPTR_RING1 directly. Linux delivers it
//!   through a self-IV (client IH, source 0, ring_id 1) that updates a
//!   software wptr_cpu shadow and schedules ih1 work; this owner needs no
//!   shadow and no work item, so it skips the self-IV work scheduling. The
//!   self-IV source is still exposed for subscribers.
//! - Delivery is MSI-X entry 0, then MSI, then observable polling. Probe has
//!   set INTX_DISABLE, so there is no legacy INTx route.
//! - No suspend/resume/rearm surface yet: the platform reset and s0ix paths
//!   that the Navi22 owner carries are a follow-up once the platform calls
//!   for them; `initialize` always takes a fresh route.
//! - No typed GMC gate: `initialize` carries the same safety contract the
//!   Navi22 owner does (GMC VMID0 must be ready) instead of taking lane 3's
//!   `Gmc`, which does not exist on this branch yet. A typed gate like the
//!   Navi48 owner's is a follow-up once the GMC owner lands.
//!
//! The IRQ handler only records the event; IVs are decoded and dispatched by
//! task-context drains driven by subscribers (interrupt wake or watchdog).
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::{bank, bank_for, RegWindow},
    amdgpu_vram::{Pool, Reservation},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{fence, AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

/// linux: IH_RING_SIZE (both v6 rings; ring 1 is a real 256 KiB retry ring,
/// not the disabled stub the Navi22 owner leaves behind).
const RING: u64 = 256 * 1024;
/// Ring 0, then ring 1, then one writeback page (ring 0 only: v6 programs no
/// wptr address for ring 1, see `ih_v6_0_enable_ring`).
const BYTES: u64 = 2 * RING + 4096;
const WPTR_WB: u64 = 2 * RING;
const MASK: u32 = (RING - 1) as u32;
const RB_SIZE: u32 = 16; // linux: n/a (order_base_2(IH_RING_SIZE / 4), amdgpu_ih_ring_init)
const BATCH: usize = 32; // linux: AMDGPU_IH_MAX_NUM_IVS
const ROUNDS: usize = 8; // linux: n/a (NARF drain policy)
const RESTARTS: usize = 16; // linux: n/a (NARF drain policy)
const QUEUE: usize = 64; // linux: n/a (NARF mailbox depth)
const SLOTS: usize = 64; // linux: n/a (NARF subscriber slots)
const CLIENTS: u8 = 0x20; // linux: SOC15_IH_CLIENTID_MAX
const NO_VECTOR: u16 = 0x100; // linux: n/a (NARF sentinel)

// OSSSYS 6.0.0 offsets, BASE_IDX 0. WPTR_ADDR_HI/LO are reversed vs OSSSYS 4.0
// (0x85 is HI, 0x86 is LO), as on v4/v5. The v6 layout matches v4/v5 (BASE
// 0x81, RPTR 0x83, WPTR 0x84); v7 reordered them, so do not copy ih7's indices.
// linux-ctx: hdr=osssys seg=0
const RB_CNTL: u32 = 0x80; // linux: mmIH_RB_CNTL
const RB_BASE: u32 = 0x81; // linux: mmIH_RB_BASE
const RB_BASE_HI: u32 = 0x82; // linux: mmIH_RB_BASE_HI
const RB_RPTR: u32 = 0x83; // linux: mmIH_RB_RPTR
const RB_WPTR: u32 = 0x84; // linux: mmIH_RB_WPTR
const WPTR_ADDR_HI: u32 = 0x85; // linux: mmIH_RB_WPTR_ADDR_HI
const WPTR_ADDR_LO: u32 = 0x86; // linux: mmIH_RB_WPTR_ADDR_LO
const DOORBELL_RPTR: u32 = 0x87; // linux: mmIH_DOORBELL_RPTR
const DOORBELL_RETRY_CAM: u32 = 0x88; // linux: mmIH_DOORBELL_RETRY_CAM
const RB_CNTL_RING1: u32 = 0x8c; // linux: mmIH_RB_CNTL_RING1
const RB_BASE_RING1: u32 = 0x8d; // linux: mmIH_RB_BASE_RING1
const RB_BASE_HI_RING1: u32 = 0x8e; // linux: mmIH_RB_BASE_HI_RING1
const RB_RPTR_RING1: u32 = 0x8f; // linux: mmIH_RB_RPTR_RING1
const RB_WPTR_RING1: u32 = 0x90; // linux: mmIH_RB_WPTR_RING1
const DOORBELL_RPTR_RING1: u32 = 0x93; // linux: mmIH_DOORBELL_RPTR_RING1
/// linux: mmIH_CNTL2
const IH_CNTL2: u32 = 0xc1;
/// linux: mmIH_STATUS
const IH_STATUS: u32 = 0xc2;
/// linux: mmIH_INT_FLOOD_CNTL
const IH_INT_FLOOD_CNTL: u32 = 0xd5;
/// linux: mmIH_STORM_CLIENT_LIST_CNTL
const IH_STORM_CLIENT_LIST_CNTL: u32 = 0xda;
/// linux: mmIH_RETRY_INT_CAM_CNTL
const IH_RETRY_INT_CAM_CNTL: u32 = 0xef;
/// linux: mmIH_MSI_STORM_CTRL
const IH_MSI_STORM_CTRL: u32 = 0xf1;
/// linux: mmIH_RING1_CLIENT_CFG_INDEX
const IH_RING1_CLIENT_CFG_INDEX: u32 = 0x185;
/// linux: mmIH_RING1_CLIENT_CFG_DATA
const IH_RING1_CLIENT_CFG_DATA: u32 = 0x186;
// IH_CHICKEN is 0x18d (mmIH_CHICKEN) but is never written: Linux sets
// MC_SPACE_GPA_ENABLE only for direct or RLC-backdoor firmware load, and
// NARF loads firmware through the PSP.
// NBIO offsets, BASE_IDX 2 unless the version table says otherwise.
// linux-ctx: hdr=nbio seg=2
const REMAP_HDP_FLUSH: u32 = 0x12d; // linux: mmREMAP_HDP_MEM_FLUSH_CNTL
/// linux: mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE (the drain-flush read)
const NBIO_MEMSIZE: u32 = 0xc3;

// linux-ctx: reset
// IH_RB_CNTL fields (osssys_6_0_0_sh_mask.h). Note WPTR_OVERFLOW_CLEAR is bit
// 31 on v6; the shared amdgpu_ih.rs value (bit 16) is v4's.
const ENABLE: u32 = 1; // linux: IH_RB_CNTL__RB_ENABLE_MASK
const WRITEBACK: u32 = 1 << 8; // linux: IH_RB_CNTL__WPTR_WRITEBACK_ENABLE_MASK
const FULL_DRAIN: u32 = 1 << 9; // linux: IH_RB_CNTL__RB_FULL_DRAIN_ENABLE_MASK
const OVERFLOW_ENABLE: u32 = 1 << 16; // linux: IH_RB_CNTL__WPTR_OVERFLOW_ENABLE_MASK
const ENABLE_INTR: u32 = 1 << 17; // linux: IH_RB_CNTL__ENABLE_INTR_MASK
const MC_SNOOP: u32 = 1 << 20; // linux: IH_RB_CNTL__MC_SNOOP_MASK
const RPTR_REARM: u32 = 1 << 21; // linux: IH_RB_CNTL__RPTR_REARM_MASK
const MC_RO: u32 = 1 << 22; // linux: IH_RB_CNTL__MC_RO_MASK
const MC_VMID: u32 = 0xf << 24; // linux: IH_RB_CNTL__MC_VMID_MASK
const MC_SPACE: u32 = 7 << 28; // linux: IH_RB_CNTL__MC_SPACE_MASK
const OVERFLOW_CLEAR: u32 = 1 << 31; // linux: IH_RB_CNTL__WPTR_OVERFLOW_CLEAR_MASK
const SIZE_MASK: u32 = 0x3e; // linux: IH_RB_CNTL__RB_SIZE_MASK
const THRESHOLD: u32 = 0xf000; // linux: IH_RB_CNTL_RING1__RB_USED_INT_THRESHOLD_MASK
const RB_OVERFLOW: u32 = 1; // linux: IH_RB_WPTR__RB_OVERFLOW_MASK
                            // IH_CNTL2 SELF_IV_FORCE_WPTR_UPDATE_{TIMEOUT,ENABLE}.
const FORCE_TIMEOUT: u32 = 0x1f; // linux: IH_CNTL2__SELF_IV_FORCE_WPTR_UPDATE_TIMEOUT_MASK
/// linux: IH_CNTL2__SELF_IV_FORCE_WPTR_UPDATE_ENABLE_MASK
const FORCE_ENABLE: u32 = 1 << 8;
/// IH_STATUS idle bits: IDLE | BUFFER_IDLE | MC_WR_IDLE.
const IDLE_MASK: u32 = 0x45; // linux: IH_STATUS__IDLE_MASK | BUFFER_IDLE | MC_WR_IDLE
                             // INTERRUPT_CNTL IH_DUMMY_RD_OVERRIDE / IH_REQ_NONSNOOP_EN.
const DUMMY_RD_OVERRIDE: u32 = 1; // linux: INTERRUPT_CNTL__IH_DUMMY_RD_OVERRIDE_MASK
const REQ_NONSNOOP: u32 = 1 << 3; // linux: INTERRUPT_CNTL__IH_REQ_NONSNOOP_EN_MASK
                                  // IH storm control (ih_v6_0_irq_init).
const STORM_CLIENT18: u32 = 1 << 18; // linux: IH_STORM_CLIENT_LIST_CNTL__CLIENT18_IS_STORM_CLIENT_MASK
const FLOOD_ENABLE: u32 = 1 << 3; // linux: IH_INT_FLOOD_CNTL__FLOOD_CNTL_ENABLE_MASK
const MSI_STORM_DELAY_MASK: u32 = 0xfff; // linux: IH_MSI_STORM_CTRL__DELAY_MASK
const MSI_STORM_DELAY: u32 = 3; // linux: ih_v6_0_irq_init DELAY
const RING1_CFG_INDEX_MASK: u32 = 0x7; // linux: IH_RING1_CLIENT_CFG_INDEX__INDEX_MASK
const RING1_CFG_CLIENT_MASK: u32 = 0xff; // linux: IH_RING1_CLIENT_CFG_DATA__CLIENT_ID_MASK
const RING1_CFG_SOURCE_MASK: u32 = 0xff << 8; // linux: IH_RING1_CLIENT_CFG_DATA__SOURCE_ID_MASK
const RING1_CFG_MATCH: u32 = 1 << 16; // linux: IH_RING1_CLIENT_CFG_DATA__SOURCE_ID_MATCH_ENABLE_MASK
                                      // IH retry CAM (dGPU only; all three RDNA3 dies are discrete).
const RETRY_CAM_ENABLE: u32 = 1 << 16; // linux: IH_RETRY_INT_CAM_CNTL__ENABLE_MASK
const RETRY_CAM_SIZE_MASK: u32 = 0x1f; // linux: IH_RETRY_INT_CAM_CNTL__CAM_SIZE_MASK
const RETRY_CAM_SIZE: u32 = 0xf; // linux: ih_v6_0_irq_init CAM_SIZE
const DOORBELL_OFFSET_MASK: u32 = 0x3ff_ffff; // linux: IH_DOORBELL_RPTR__OFFSET_MASK
const DOORBELL_ENABLE: u32 = 1 << 28; // linux: IH_DOORBELL_RPTR__ENABLE_MASK
/// linux: AMDGPU_NAVI10_DOORBELL_IH (soc21.c sets doorbell_index.ih to it).
const DOORBELL_IH: u32 = 0x178;
/// Ring 0's doorbell index is `(ih) << 1` = 0x2f0, ring 1's `(ih + 1) << 1` =
/// 0x2f2; both stay disabled (no BAR2), so only the retry-CAM index below is
/// programmed. The retry-CAM doorbell is `(ih + 2) << 1` = 0x2f4.
const DOORBELL_RETRY_CAM_INDEX: u32 = (DOORBELL_IH + 2) << 1;

/// The RDNA3 die, selected by discovered GC version. The pairing is lane 1's
/// correction of the programme record's swap (Ubuntu LP#2034103, the Gentoo
/// firmware table, Mesa's navi33 external_rev): Navi31 GC 11.0.0, Navi32 GC
/// 11.0.3, Navi33 GC 11.0.2. IH 6.0.0 is identical on all three dies, so no
/// per-die IH parameter exists; the die is carried so the DCN and platform
/// owners can ask this owner which die it bound. A local enum duplicates
/// lane 1's `Rdna3Chip` the way lane 3's `Navi31Die` does; dedupe against
/// `amdgpu_rdna3::Rdna3Chip` once #2459 merges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Die {
    Navi31,
    Navi32,
    Navi33,
}
impl Die {
    pub const fn from_gc(major: u8, minor: u8, revision: u8) -> Option<Self> {
        match (major, minor, revision) {
            (11, 0, 0) => Some(Self::Navi31),
            (11, 0, 3) => Some(Self::Navi32),
            (11, 0, 2) => Some(Self::Navi33),
            _ => None,
        }
    }
    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            Self::Navi31 => (11, 0, 0),
            Self::Navi32 => (11, 0, 3),
            Self::Navi33 => (11, 0, 2),
        }
    }
    /// DCN version this die carries (lane 1's `IpVersions`, lane 5's DCN
    /// owner): 3.2.0 on Navi31/Navi32, 3.2.1 on Navi33. Both have 5 HPD
    /// connectors and 4 pipes, so the HPD and vblank bounds below do not vary
    /// by die; this is here for the DCN owner to consume.
    pub const fn dcn_version(self) -> (u8, u8, u8) {
        match self {
            Self::Navi31 | Self::Navi32 => (3, 2, 0),
            Self::Navi33 => (3, 2, 1),
        }
    }
}

/// SOC21 client and source ids. Clients: soc15_ih_clientid.h; sources from
/// the matching ivsrcid headers and the Linux IP handlers that register them.
/// The SOC21 GFX client (0x0a) is NOT the shared `CLIENT_ID_GFX` (0x14),
/// which is `SOC15_IH_CLIENTID_GRBM_CP`; lane 3 adds `CLIENT_ID_GFX_SOC21`
/// to amdgpu_ih.rs when #2463 merges, and this module will switch to it.
pub mod source {
    use super::Source;
    pub mod client {
        pub const IH: u8 = 0x00; // linux: SOC15_IH_CLIENTID_IH
        pub const ATHUB: u8 = 0x02; // linux: SOC15_IH_CLIENTID_ATHUB
        pub const BIF: u8 = 0x03; // linux: SOC15_IH_CLIENTID_BIF
        pub const DCE: u8 = 0x04; // linux: SOC15_IH_CLIENTID_DCE
        pub const ISP: u8 = 0x05; // linux: SOC15_IH_CLIENTID_ISP
        pub const MP3: u8 = 0x06; // linux: SOC15_IH_CLIENTID_MP3
        pub const RLC: u8 = 0x07; // linux: SOC15_IH_CLIENTID_RLC
        /// SOC21 GFX client (UTCL2 faults, SDMA, RLC_GC_FED). Lane 3's
        /// `CLIENT_ID_GFX_SOC21` once #2463 merges.
        pub const GFX: u8 = 0x0a; // linux: SOC15_IH_CLIENTID_GFX
        pub const IMU: u8 = 0x0b; // linux: SOC15_IH_CLIENTID_IMU
        pub const VCN1: u8 = 0x0e; // linux: SOC15_IH_CLIENTID_VCN1
        pub const THM: u8 = 0x0f; // linux: SOC15_IH_CLIENTID_THM
        pub const VCN: u8 = 0x10; // linux: SOC15_IH_CLIENTID_VCN
        pub const VPE1: u8 = 0x11; // linux: SOC15_IH_CLIENTID_VPE1
        pub const VMC: u8 = 0x12; // linux: SOC15_IH_CLIENTID_VMC
        pub const GRBM_CP: u8 = 0x14; // linux: SOC15_IH_CLIENTID_GRBM_CP
        pub const ROM_SMUIO: u8 = 0x16; // linux: SOC15_IH_CLIENTID_ROM_SMUIO
        pub const DF: u8 = 0x17; // linux: SOC15_IH_CLIENTID_DF
        pub const VPE: u8 = 0x18; // linux: SOC15_IH_CLIENTID_VPE
        pub const PWR: u8 = 0x19; // linux: SOC15_IH_CLIENTID_PWR
        pub const LSDMA: u8 = 0x1a; // linux: SOC15_IH_CLIENTID_LSDMA
        pub const UTCL2: u8 = 0x1b; // linux: SOC15_IH_CLIENTID_UTCL2
        pub const MP0: u8 = 0x1e; // linux: SOC15_IH_CLIENTID_MP0
        pub const MP1: u8 = 0x1f; // linux: SOC15_IH_CLIENTID_MP1
    }
    const fn s(client: u8, src: u8) -> Source {
        Source { client, src }
    }
    /// ih_v6_0_sw_init: the self-IRQ (client IH, source 0) whose ring_id 1
    /// entry carries ring 1's wptr in src_data[0]. This owner reads ring 1's
    /// wptr from its register instead, but the source is exposed so a
    /// subscriber can observe the self-IVs.
    // linux-lit: 0=SOC21_IH_CLIENTID_IH self-irq source
    pub const SELF_IV: Source = s(client::IH, 0);
    /// gfx_v11_0_sw_init: GFX_11_0__SRCID__CP_* on GRBM_CP. ring_id is the
    /// ME/pipe/queue, see [`super::Iv::cp_queue`] (the GFX11 layout matches
    /// GFX10's; me 3 is the MES pipe).
    // linux-lit: 181=GFX_11_0__SRCID__CP_EOP_INTERRUPT
    pub const GFX_EOP: Source = s(client::GRBM_CP, 181);
    // linux-lit: 183=GFX_11_0__SRCID__CP_BAD_OPCODE_ERROR
    pub const GFX_BAD_OPCODE: Source = s(client::GRBM_CP, 183);
    // linux-lit: 184=GFX_11_0__SRCID__CP_PRIV_REG_FAULT
    pub const GFX_PRIV_REG: Source = s(client::GRBM_CP, 184);
    // linux-lit: 185=GFX_11_0__SRCID__CP_PRIV_INSTR_FAULT
    pub const GFX_PRIV_INSTR: Source = s(client::GRBM_CP, 185);
    /// gfx_v11_0_sw_init: RLC_GC_FED on the GFX client.
    // linux-lit: 128=GFX_11_0__SRCID__RLC_GC_FED
    pub const GFX_RLC_FED: Source = s(client::GFX, 128);
    /// sdma_v6_0_sw_init: SDMA_TRAP and SDMA_FENCE on the GFX client (SDMA v6
    /// has no per-engine SOC21 clients); ring_id is the engine.
    // linux-lit: 49=SDMA_6_0__SRCID__SDMA_TRAP
    pub const SDMA_TRAP: Source = s(client::GFX, 49);
    // linux-lit: 67=SDMA_6_0__SRCID__SDMA_FENCE
    pub const SDMA_FENCE: Source = s(client::GFX, 67);
    /// vcn_v4_0_sw_init: per-instance decode/encode/trap/poison on the VCN
    /// clients; jpeg_v4_0_sw_init: JPEG decode/encode and JPEG poisons on the
    /// VCN client. The extra JPEG instance sources (JPEG1/3/4/5/6/7_DECODE)
    /// are not registered by any in-tree handler this lane grounds, so they
    /// are omitted here.
    // linux-lit: 114=VCN_4_0__SRCID__UVD_TRAP
    pub const VCN0_TRAP: Source = s(client::VCN, 114);
    // linux-lit: 124=VCN_4_0__SRCID__UVD_SYSTEM_MESSAGE_INTERRUPT
    pub const VCN0_DEC: Source = s(client::VCN, 124);
    // linux-lit: 119=VCN_4_0__SRCID__UVD_ENC_GENERAL_PURPOSE; 120=VCN_4_0__SRCID__UVD_ENC_LOW_LATENCY
    pub const VCN0_ENC: [Source; 2] = [s(client::VCN, 119), s(client::VCN, 120)];
    // linux-lit: 160=VCN_4_0__SRCID__UVD_POISON
    pub const VCN0_POISON: Source = s(client::VCN, 160);
    // linux-lit: 114=VCN_4_0__SRCID__UVD_TRAP
    pub const VCN1_TRAP: Source = s(client::VCN1, 114);
    // linux-lit: 124=VCN_4_0__SRCID__UVD_SYSTEM_MESSAGE_INTERRUPT
    pub const VCN1_DEC: Source = s(client::VCN1, 124);
    // linux-lit: 119=VCN_4_0__SRCID__UVD_ENC_GENERAL_PURPOSE; 120=VCN_4_0__SRCID__UVD_ENC_LOW_LATENCY
    pub const VCN1_ENC: [Source; 2] = [s(client::VCN1, 119), s(client::VCN1, 120)];
    // linux-lit: 160=VCN_4_0__SRCID__UVD_POISON
    pub const VCN1_POISON: Source = s(client::VCN1, 160);
    // linux-lit: 153=VCN_4_0__SRCID__JPEG_DECODE
    pub const JPEG_DEC: Source = s(client::VCN, 153);
    // linux-lit: 151=VCN_4_0__SRCID__JPEG_ENCODE
    pub const JPEG_ENC: Source = s(client::VCN, 151);
    // linux-lit: 161=VCN_4_0__SRCID__DJPEG0_POISON
    pub const JPEG_D_POISON: Source = s(client::VCN, 161);
    // linux-lit: 162=VCN_4_0__SRCID__EJPEG0_POISON
    pub const JPEG_E_POISON: Source = s(client::VCN, 162);
    /// gmc_v11_0_sw_init: VMC (MMHUB) faults on ring 0, UTCL2 (GFXHUB) faults
    /// on the GFX client, redirected to ring 1; DF ECC on the DF client.
    // linux-lit: 0=VMC_1_0__SRCID__VM_FAULT
    pub const VMC_FAULT: Source = s(client::VMC, 0);
    // linux-lit: 0=UTCL2_1_0__SRCID__FAULT
    pub const UTCL2_FAULT: Source = s(client::GFX, 0);
    // linux-lit: 0=DF_4_3__SRCID__ECC (gmc_v11_0_process_interrupt DF path)
    pub const DF_ECC: Source = s(client::DF, 0);
    /// DCN_1_0__SRCID__DC_HPD1_INT is shared by every HPD and HPD-RX line;
    /// src_data[0] is the context id, see [`super::Iv::hpd`]. DCN 3.2
    /// installs only HPD1..5 and HPD1RX..5RX (5 connectors, not the 6 the
    /// shared amdgpu_ih.rs HPD table carries for DCN 3.1.4).
    // linux-lit: 9=DCN_1_0__SRCID__DC_HPD1_INT
    pub const DCN_HPD: Source = s(client::DCE, 9);
    // linux-lit: 0x68=DCN_1_0__SRCID__DMCUB_OUTBOX_LOW_PRIORITY_READY_INT
    pub const DCN_DMUB_OUTBOX: Source = s(client::DCE, 0x68);
    /// Thermal / SMU sources are ungrounded for SMU 13.0.0 (no smu_v13_0_0
    /// or THM header in the ref set); lane 11 (thermal) owns them. Deliberately
    /// absent here rather than guessed.
    /// Vblank as amdgpu_dm uses it on DCN: OTG VSTARTUP (DC_D1_OTG_VSTARTUP + n).
    /// DCN 3.2 has 4 pipes, so only 0..3 are installed.
    pub const fn vblank(otg: u8) -> Option<Source> {
        if otg < 4 {
            // linux-lit: 0x3c=DCN_1_0__SRCID__DC_D1_OTG_VSTARTUP
            Some(s(client::DCE, 0x3c + otg))
        } else {
            None
        }
    }
    /// OTGn_IHC_V_UPDATE_NO_LOCK_INTERRUPT, n starting at OTG0 (0x57).
    /// DCN 3.2 has 4 OTGs.
    pub const fn vupdate(otg: u8) -> Option<Source> {
        if otg < 4 {
            // linux-lit: 0x57=DCN_1_0__SRCID__OTG0_IHC_V_UPDATE_NO_LOCK_INTERRUPT
            Some(s(client::DCE, 0x57 + otg))
        } else {
            None
        }
    }
    /// HUBPn_FLIP_INTERRUPT (0x4f + n). DCN 3.2 has 4 HUBPs.
    pub const fn pflip(hubp: u8) -> Option<Source> {
        if hubp < 4 {
            // linux-lit: 0x4f=DCN_1_0__SRCID__HUBP0_FLIP_INTERRUPT
            Some(s(client::DCE, 0x4f + hubp))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    /// The engine asked to raise the event did not submit it.
    Source,
    Closed(Closed),
}
/// Terminal outcome delivered to every waiter instead of a hang.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// This subscription was revoked or replaced by a newer generation.
    Revoked,
    Disabled,
    DeviceLost,
    AuthorityRevoked,
    /// Ring programming failed; no interrupts will be delivered.
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Enabled,
    Disabled,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Pending,
    MsiX { vector: u8 },
    Msi { vector: u8 },
    Polling,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    pub client: u8,
    pub src: u8,
}
/// Decoded 32-byte SOC15 IV (amdgpu_ih_decode_iv_helper).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Iv {
    pub client: u8,
    pub src: u8,
    pub ring_id: u8,
    pub vmid: u8,
    pub vmid_src: bool,
    pub timestamp: u64,
    pub timestamp_src: bool,
    pub pasid: u16,
    pub node_id: u8,
    pub src_data: [u32; 4],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpQueue {
    pub me: u8,
    pub pipe: u8,
    pub queue: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFault {
    /// true for MMHUB (VMC client), false for GFXHUB (UTCL2 on the GFX client).
    pub mmhub: bool,
    pub address: u64,
    pub retry: bool,
    pub write: bool,
    /// Retry-CAM index from src_data[2], for the VM-fault consumer to ACK the
    /// CAM entry. 0 when the fault is not a retry fault.
    pub cam_index: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpd {
    pub instance: u8,
    pub rx: bool,
}
impl Iv {
    // linux: n/a (dword layout literals in amdgpu_ih.c:amdgpu_ih_decode_iv_helper)
    pub const fn decode(dw: [u32; 8]) -> Self {
        Self {
            client: dw[0] as u8,
            src: (dw[0] >> 8) as u8,
            ring_id: (dw[0] >> 16) as u8,
            vmid: ((dw[0] >> 24) & 0xf) as u8,
            vmid_src: dw[0] >> 31 != 0,
            timestamp: dw[1] as u64 | (((dw[2] & 0xffff) as u64) << 32),
            timestamp_src: dw[2] >> 31 != 0,
            pasid: dw[3] as u16,
            node_id: (dw[3] >> 16) as u8,
            src_data: [dw[4], dw[5], dw[6], dw[7]],
        }
    }
    pub const fn source(&self) -> Source {
        Source {
            client: self.client,
            src: self.src,
        }
    }
    /// gfx_v11_0_eop_irq ring_id layout (same as GFX10's).
    pub const fn cp_queue(&self) -> CpQueue {
        CpQueue {
            // linux: n/a (ring_id literals in gfx_v11_0.c:gfx_v11_0_eop_irq)
            me: (self.ring_id & 0x0c) >> 2,
            pipe: self.ring_id & 3,
            queue: (self.ring_id & 0x70) >> 4,
        }
    }
    /// gmc_v11_0_process_interrupt address/flag decode. GFXHUB faults arrive
    /// on the GFX client (redirected to ring 1), MMHUB faults on VMC (ring 0).
    pub const fn page_fault(&self) -> Option<PageFault> {
        if self.src != 0
            || (self.client != source::client::VMC && self.client != source::client::GFX)
        {
            return None;
        }
        Some(PageFault {
            mmhub: self.client == source::client::VMC,
            // linux: n/a (literals in gmc_v11_0.c:gmc_v11_0_process_interrupt)
            address: ((self.src_data[0] as u64) << 12) | (((self.src_data[1] & 0xf) as u64) << 44),
            // linux-lit: 0x80=AMDGPU_GMC9_FAULT_SOURCE_DATA_RETRY
            retry: self.src_data[1] & 0x80 != 0,
            // linux-lit: 0x20=AMDGPU_GMC9_FAULT_SOURCE_DATA_WRITE
            write: self.src_data[1] & 0x20 != 0,
            // linux: n/a (cam_index = src_data[2] & 0x3ff, gmc_v11_0.c)
            cam_index: (self.src_data[2] & 0x3ff) as u16,
        })
    }
    /// irq_service_dcn32 HPD context ids: 0..4 HPDn, 6..10 HPDn_RX. Contexts
    /// 5 (HPD6) and 11 (HPD6RX) are never installed on DCN 3.2 and are
    /// rejected here, not decoded as a phantom sixth connector.
    pub const fn hpd(&self) -> Option<Hpd> {
        // linux-lit: 9=DCN_1_0__SRCID__DC_HPD1_INT; 5=DCN_1_0__CTXID__DC_HPD6_INT (uninstalled)
        if self.client != source::client::DCE
            || self.src != 9
            || self.src_data[0] > 10
            || self.src_data[0] == 5
        {
            return None;
        }
        let context = self.src_data[0] as u8;
        Some(Hpd {
            instance: context % 6, // linux-lit: 6=DCN_1_0__CTXID__DC_HPD1_RX_INT
            rx: context >= 6,      // linux-lit: 6=DCN_1_0__CTXID__DC_HPD1_RX_INT
        })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub interrupts: u64,
    pub drained: u64,
    pub unhandled: u64,
    pub malformed: u64,
    pub overflows: u64,
    /// IVs a full subscriber mailbox discarded (oldest first).
    pub dropped: u64,
    /// Drains that found IVs with no interrupt recorded since the last drain.
    pub unsignalled: u64,
    pub watchdog: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub iv: Iv,
    /// The host vector fired between submission and observation.
    pub interrupt: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub delivery: Delivery,
    /// The previous owner left ring 0 enabled; it was disabled before
    /// reprogramming.
    pub inherited: bool,
    pub proof: Option<Result<Proof, Error>>,
    pub stats: Stats,
}

/// One NBIO version's IH-control window. Sibling NBIOs agree on neither
/// their segment nor their offsets: NBIO 7.7 puts INTERRUPT_CNTL on BX1 at
/// segment 5 (0x8e11), while 4.3, 6.3.1, 6.3.2, 7.10, 7.11.4 and 7.11.5 keep
/// it on BX0/BX1 at segment 2 (0xf1) — 7.11.5's "BX1" lives at segment 2,
/// so the table keys on the full discovery version, never the major alone.
/// Each row's `last` is its INTERRUPT_CNTL2 dword, bounding the bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NbioWindow {
    version: (u8, u8, u8),
    base_idx: usize,
    cntl: u32,
    cntl2: u32,
}
impl RegWindow for NbioWindow {
    fn version(&self) -> (u8, u8, u8) {
        self.version
    }
    fn base_idx(&self) -> usize {
        self.base_idx
    }
    fn last(&self) -> u32 {
        self.cntl2
    }
}
/// Every NBIO version amdgpu_discovery.c assigns to SOC21
/// (nbio_v4_3 / nbif_v6_3_1 / nbio_v6_3_2 / nbio_v7_7 / nbif_v7_10 /
/// nbio_v7_11_5). Each row's segment and dwords were checked against its own
/// `*_offset.h` and `*_ih_control` in Linux 7.4-rc2.
const NBIO_WINDOWS: &[NbioWindow] = &[
    NbioWindow {
        version: (4, 3, 0),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
    NbioWindow {
        version: (4, 3, 1),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
    NbioWindow {
        version: (6, 3, 1),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
    NbioWindow {
        version: (6, 3, 2),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
    NbioWindow {
        version: (7, 7, 0),
        base_idx: 5,
        cntl: 0x8e11,
        cntl2: 0x8e12,
    },
    NbioWindow {
        version: (7, 7, 1),
        base_idx: 5,
        cntl: 0x8e11,
        cntl2: 0x8e12,
    },
    NbioWindow {
        version: (7, 10, 0),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
    NbioWindow {
        version: (7, 11, 4),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
    NbioWindow {
        version: (7, 11, 5),
        base_idx: 2,
        cntl: 0xf1,
        cntl2: 0xf2,
    },
];
const NBIO_VERSIONS: &[(u8, u8, u8)] = &[
    (4, 3, 0),
    (4, 3, 1),
    (6, 3, 1),
    (6, 3, 2),
    (7, 7, 0),
    (7, 7, 1),
    (7, 10, 0),
    (7, 11, 4),
    (7, 11, 5),
];

#[derive(Clone, Copy, Debug)]
struct Layout {
    die: Die,
    oss: u64,
    /// NBIO segment 2, bounded through the HDP remap (0x12d): the preflight
    /// remap check and the drain-flush MEMSIZE read. The remap dword is
    /// 0x12d at segment 2 on every SOC21 NBIO (BX1's remap on 7.11.5 is
    /// 0x12d at segment 2 too).
    nbio: u64,
    /// The version-resolved IH-control bank (segment 2 or 5 per the table).
    nbio_ctl: u64,
    nbio_cntl: u32,
    nbio_cntl2: u32,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        // The die is selected by discovered GC version, not PCI DID: lane 0's
        // DID table (#2460) is not on this branch yet, and GC is the selector
        // lane 1 grounded.
        let gc = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_GC, 0).ok_or(Error::Unsupported)?;
        let die = Die::from_gc(gc.major, gc.minor, gc.revision).ok_or(Error::Unsupported)?;
        let resolve = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        let (nbio_ctl, window) =
            bank_for(gpu, ip::HW_ID_NBIF, NBIO_WINDOWS).map_err(|_| Error::Unsupported)?;
        Ok(Self {
            die,
            oss: resolve(ip::HW_ID_OSSSYS, &[(6, 0, 0)], 0, IH_CNTL2)?,
            nbio: resolve(ip::HW_ID_NBIF, NBIO_VERSIONS, 2, REMAP_HDP_FLUSH)?,
            nbio_ctl,
            nbio_cntl: window.cntl,
            nbio_cntl2: window.cntl2,
        })
    }
}
trait Io: Send {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds OSSSYS/NBIO and the HDP remap. The
        // exclusive owner invokes every I/O batch under live PCI authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same validated register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: offsets are bounded by the retained BYTES ring allocation.
        unsafe { map.read32(offset) }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: same retained allocation and bounded dword offsets.
        unsafe { map.write32(offset, value) };
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
async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
#[derive(Clone, Copy, Debug, Default)]
struct Batch {
    count: usize,
    more: bool,
    overflow: bool,
    malformed: u64,
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    /// Bus address for NBIO's dummy read (Linux adev->dummy_page_addr).
    dummy: u64,
    state: State,
    rptr: [u32; 2],
    inherited: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (io, layout) = (&mut self.io, self.layout);
        self.authority
            .invoke(Op(|| f(io, layout)))
            .map_err(|_| Error::Revoked)?
    }
    fn reg(l: Layout, reg: u32) -> u64 {
        l.oss + u64::from(reg) * 4
    }
    fn nbio(l: Layout, reg: u32) -> u64 {
        l.nbio + u64::from(reg) * 4
    }
    fn nbio_ctl(l: Layout, reg: u32) -> u64 {
        l.nbio_ctl + u64::from(reg) * 4
    }
    const fn cntl_reg(ring: usize) -> u32 {
        if ring == 0 {
            RB_CNTL
        } else {
            RB_CNTL_RING1
        }
    }
    const fn base_reg(ring: usize) -> u32 {
        if ring == 0 {
            RB_BASE
        } else {
            RB_BASE_RING1
        }
    }
    const fn base_hi_reg(ring: usize) -> u32 {
        if ring == 0 {
            RB_BASE_HI
        } else {
            RB_BASE_HI_RING1
        }
    }
    const fn rptr_reg(ring: usize) -> u32 {
        if ring == 0 {
            RB_RPTR
        } else {
            RB_RPTR_RING1
        }
    }
    const fn wptr_reg(ring: usize) -> u32 {
        if ring == 0 {
            RB_WPTR
        } else {
            RB_WPTR_RING1
        }
    }
    const fn doorbell_reg(ring: usize) -> u32 {
        if ring == 0 {
            DOORBELL_RPTR
        } else {
            DOORBELL_RPTR_RING1
        }
    }
    fn update(io: &mut I, address: u64, mask: u32, value: u32) -> Result<u32, Error> {
        let next = (checked(io.read(address))? & !mask) | value;
        io.write(address, next);
        Ok(next)
    }
    /// Read-only checks; must succeed before any host routing or writes.
    /// The IH_STATUS idle check mirrors the Navi48 owner's preflight: a
    /// mid-flight IH fails closed instead of being reprogrammed under live
    /// interrupts.
    fn preflight(&mut self) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        let address = self.memory.address();
        if address % 256 != 0 || address.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
            return Err(Error::Invalid);
        }
        let inherited = self.access(|io, l| {
            // linux: n/a (MMIO_REG_HOLE_OFFSET = 0x80000 - PAGE_SIZE, nbio_v2_3.c)
            if checked(io.read(Self::nbio(l, REMAP_HDP_FLUSH)))? != 0x7f000 {
                return Err(Error::Invalid);
            }
            if checked(io.read(Self::reg(l, IH_STATUS)))? & IDLE_MASK != IDLE_MASK {
                return Err(Error::Invalid);
            }
            Ok(checked(io.read(Self::reg(l, RB_CNTL)))? & ENABLE != 0)
        })?;
        self.inherited = inherited;
        Ok(())
    }
    /// ih_v6_0_toggle_ring_interrupts(ring). Unlike the Navi22 toggle there
    /// is no GPU_TS bit on v6; the overflow-clear pulse (0 -> 1 -> 0) is
    /// part of the enable path, and ENABLE_INTR exists only on ring 0.
    fn toggle(io: &mut I, l: Layout, ring: usize, enable: bool) -> Result<(), Error> {
        let cntl = Self::reg(l, Self::cntl_reg(ring));
        let mut tmp = checked(io.read(cntl))?;
        tmp = (tmp & !(ENABLE | OVERFLOW_CLEAR)) | if enable { ENABLE } else { 0 };
        io.write(cntl, tmp);
        if enable {
            io.write(cntl, tmp | OVERFLOW_CLEAR);
            io.write(cntl, tmp);
        }
        if ring == 0 {
            let tmp = (tmp & !ENABLE_INTR) | if enable { ENABLE_INTR } else { 0 };
            io.write(cntl, tmp);
        }
        if !enable {
            io.write(Self::reg(l, Self::rptr_reg(ring)), 0);
            io.write(Self::reg(l, Self::wptr_reg(ring)), 0);
        }
        Ok(())
    }
    /// ih_v6_0_enable_ring(ring). Ring 1: OVERFLOW_ENABLE=0, FULL_DRAIN=1,
    /// and no wptr address (v6 has no IH_RB_WPTR_ADDR registers for ring 1,
    /// and Linux programs none); ring 0: RPTR_REARM only with MSI, and the
    /// wptr address is programmed whether writeback is enabled or not.
    fn enable_ring(
        io: &mut I,
        l: Layout,
        ring: usize,
        msi: bool,
        address: u64,
        writeback: u64,
    ) -> Result<(), Error> {
        io.write(Self::reg(l, Self::base_reg(ring)), (address >> 8) as u32);
        // linux: n/a (literals in ih_v6_0.c:ih_v6_0_enable_ring)
        io.write(
            Self::reg(l, Self::base_hi_reg(ring)),
            ((address >> 40) & 0xff) as u32,
        );
        if ring == 0 {
            Self::update(
                io,
                Self::reg(l, RB_CNTL),
                MC_SPACE
                    | OVERFLOW_CLEAR
                    | OVERFLOW_ENABLE
                    | SIZE_MASK
                    | WRITEBACK
                    | MC_SNOOP
                    | MC_RO
                    | MC_VMID
                    | RPTR_REARM,
                (4 << 28) // linux-lit: 28=IH_RB_CNTL__MC_SPACE__SHIFT
                    | OVERFLOW_CLEAR
                    | OVERFLOW_ENABLE
                    | (RB_SIZE << 1) // linux-lit: 1=IH_RB_CNTL__RB_SIZE__SHIFT
                    | WRITEBACK
                    | MC_SNOOP
                    | if msi { RPTR_REARM } else { 0 },
            )?;
            io.write(Self::reg(l, WPTR_ADDR_LO), writeback as u32 & !3);
            io.write(
                Self::reg(l, WPTR_ADDR_HI),
                // linux: n/a (literal in ih_v6_0.c:ih_v6_0_enable_ring)
                (writeback >> 32) as u32 & 0xffff,
            );
        } else {
            Self::update(
                io,
                Self::reg(l, RB_CNTL_RING1),
                MC_SPACE
                    | OVERFLOW_CLEAR
                    | OVERFLOW_ENABLE
                    | SIZE_MASK
                    | WRITEBACK
                    | MC_SNOOP
                    | MC_RO
                    | MC_VMID
                    | FULL_DRAIN,
                (4 << 28) | OVERFLOW_CLEAR | (RB_SIZE << 1) | WRITEBACK | MC_SNOOP | FULL_DRAIN,
            )?;
        }
        io.write(Self::reg(l, Self::wptr_reg(ring)), 0);
        io.write(Self::reg(l, Self::rptr_reg(ring)), 0);
        io.write(Self::reg(l, Self::doorbell_reg(ring)), 0);
        Ok(())
    }
    /// force_update_wptr_for_self_int(adev, 0, 8, enable). v6 calls it
    /// unconditionally (there is no 5.0.3 gate as on Navi22); only ring 1's
    /// threshold is touched, there is no ring 2.
    fn self_int(io: &mut I, l: Layout, enable: bool) -> Result<(), Error> {
        let cntl2 = checked(io.read(Self::reg(l, IH_CNTL2)))?;
        let cntl2 =
            // linux: n/a (timeout 8, ih_v6_0.c:ih_v6_0_irq_init)
            (cntl2 & !(FORCE_TIMEOUT | FORCE_ENABLE)) | 8 | if enable { FORCE_ENABLE } else { 0 };
        Self::update(io, Self::reg(l, RB_CNTL_RING1), THRESHOLD, 0)?;
        io.write(Self::reg(l, IH_CNTL2), cntl2);
        Ok(())
    }
    /// ih_v6_0_irq_init with the version-resolved nbio ih_control. No
    /// IH_CHICKEN write: Linux sets MC_SPACE_GPA only for direct firmware
    /// load. No ih_doorbell_range write: see the module header.
    fn program(&mut self, msi: bool) -> Result<(), Error> {
        self.state = State::Programming;
        let address = self.memory.address();
        let writeback = address + WPTR_WB;
        let dummy = self.dummy;
        let map = self.memory.mapping();
        self.access(|io, l| {
            for offset in (0..BYTES).step_by(4) {
                io.write_memory(map, offset, 0);
            }
            fence(Ordering::SeqCst);
            // linux: n/a (MMIO_REG_HOLE_OFFSET write, amdgpu_hdp_generic_flush)
            io.write(0x7f000, 0);
            io.read(Self::nbio(l, NBIO_MEMSIZE));
            fence(Ordering::SeqCst);
            Ok(())
        })?;
        // Publish before IH can retain the ring/writeback address.
        self.memory.publish();
        self.access(|io, l| {
            Self::toggle(io, l, 0, false)?;
            Self::toggle(io, l, 1, false)?;
            // linux: n/a (dummy_page_addr >> 8, nbio_*_ih_control)
            io.write(Self::nbio_ctl(l, l.nbio_cntl2), (dummy >> 8) as u32);
            // Dummy read off with MSI, on without. NONSNOOP stays 0 as Linux.
            Self::update(
                io,
                Self::nbio_ctl(l, l.nbio_cntl),
                DUMMY_RD_OVERRIDE | REQ_NONSNOOP,
                0,
            )?;
            Self::enable_ring(io, l, 0, msi, address, writeback)?;
            Self::enable_ring(io, l, 1, msi, address + RING, writeback)?;
            // Storm control. The doorbell-range write Linux does between the
            // ring enables and this block is skipped (module header).
            Self::update(
                io,
                Self::reg(l, IH_STORM_CLIENT_LIST_CNTL),
                STORM_CLIENT18,
                STORM_CLIENT18,
            )?;
            Self::update(
                io,
                Self::reg(l, IH_INT_FLOOD_CNTL),
                FLOOD_ENABLE,
                FLOOD_ENABLE,
            )?;
            Self::update(
                io,
                Self::reg(l, IH_MSI_STORM_CTRL),
                MSI_STORM_DELAY_MASK,
                MSI_STORM_DELAY,
            )?;
            // Redirect GFX UTCL2 faults (client 0x0a, source 0) to ring 1.
            Self::update(
                io,
                Self::reg(l, IH_RING1_CLIENT_CFG_INDEX),
                RING1_CFG_INDEX_MASK,
                0,
            )?;
            Self::update(
                io,
                Self::reg(l, IH_RING1_CLIENT_CFG_DATA),
                RING1_CFG_CLIENT_MASK | RING1_CFG_SOURCE_MASK | RING1_CFG_MATCH,
                u32::from(source::client::GFX) | RING1_CFG_MATCH,
            )?;
            // Retry CAM, dGPU only: the doorbell register, then ENABLE and
            // CAM_SIZE. The CAM ACK path (which entry the VM-fault consumer
            // retires via `PageFault::cam_index`) is the GMC lane's work;
            // ring-1 delivery does not depend on it.
            io.write(
                Self::reg(l, DOORBELL_RETRY_CAM),
                (DOORBELL_RETRY_CAM_INDEX & DOORBELL_OFFSET_MASK) | DOORBELL_ENABLE,
            );
            Self::update(
                io,
                Self::reg(l, IH_RETRY_INT_CAM_CNTL),
                RETRY_CAM_ENABLE | RETRY_CAM_SIZE_MASK,
                RETRY_CAM_ENABLE | RETRY_CAM_SIZE,
            )?;
            Self::toggle(io, l, 0, true)?;
            Self::toggle(io, l, 1, true)?;
            Self::self_int(io, l, true)
        })?;
        self.rptr = [0, 0];
        self.state = State::Enabled;
        Ok(())
    }
    /// `IH_RB_CNTL.RPTR_REARM`, set only with MSI (`ih_v6_0_enable_ring`).
    /// Ring 1 has no RPTR_REARM field.
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    fn rearm(&mut self, msi: bool) -> Result<(), Error> {
        if self.state != State::Enabled {
            return Ok(());
        }
        let value = if msi { RPTR_REARM } else { 0 };
        self.access(|io, l| Self::update(io, Self::reg(l, RB_CNTL), RPTR_REARM, value).map(drop))
    }
    /// ih_v6_0_get_wptr for one ring. Ring 0 reads the writeback page first
    /// and the register only on overflow; ring 1 has no writeback address
    /// and always reads IH_RB_WPTR_RING1 (Linux's self-IV shadow is not used).
    fn wptr(
        io: &mut I,
        l: Layout,
        ring: usize,
        map: MmioRegion,
        rptr: &mut u32,
    ) -> Result<(u32, bool), Error> {
        if ring == 0 {
            let writeback = io.read_memory(map, WPTR_WB);
            if writeback & RB_OVERFLOW == 0 {
                return Ok((writeback & MASK, false));
            }
        }
        let wptr = checked(io.read(Self::reg(l, Self::wptr_reg(ring))))?;
        if wptr & RB_OVERFLOW == 0 {
            return Ok((wptr & MASK, false));
        }
        let wptr = wptr & !RB_OVERFLOW;
        // Resume from the oldest vector not yet overwritten.
        // linux: n/a (wptr + 32, ih_v6_0.c:ih_v6_0_get_wptr)
        *rptr = wptr.wrapping_add(32) & MASK;
        let cntl = Self::update(
            io,
            Self::reg(l, Self::cntl_reg(ring)),
            OVERFLOW_CLEAR,
            OVERFLOW_CLEAR,
        )?;
        io.write(Self::reg(l, Self::cntl_reg(ring)), cntl & !OVERFLOW_CLEAR);
        Ok((wptr & MASK, true))
    }
    /// One ring's share of a bounded amdgpu_ih_process pass; always writes
    /// back the ring's rptr. `out` is the still-empty tail of the batch.
    fn collect_ring(
        io: &mut I,
        l: Layout,
        ring: usize,
        map: MmioRegion,
        rptr: &mut u32,
        out: &mut [Iv],
    ) -> Result<(usize, bool, bool, u64), Error> {
        let (wptr, overflow) = Self::wptr(io, l, ring, map, rptr)?;
        let mut count = 0;
        let mut malformed = 0;
        // IVs are 32 bytes; a misaligned pointer cannot be followed.
        if wptr % 32 != 0 {
            malformed += 1;
        }
        let wptr = wptr & !31;
        *rptr &= !31;
        let base = if ring == 0 { 0 } else { RING };
        while *rptr != wptr && count < out.len() {
            let mut dw = [0; 8];
            for (index, word) in dw.iter_mut().enumerate() {
                *word = io.read_memory(map, base + u64::from(*rptr) + index as u64 * 4);
            }
            *rptr = (*rptr + 32) & MASK;
            if dw[0] == u32::MAX {
                checked(io.read(Self::reg(l, Self::cntl_reg(ring))))?;
            }
            let iv = Iv::decode(dw);
            if dw[0] == u32::MAX || iv.client >= CLIENTS {
                malformed += 1;
                continue;
            }
            out[count] = iv;
            count += 1;
        }
        let more = *rptr != wptr;
        io.write(Self::reg(l, Self::rptr_reg(ring)), *rptr);
        Ok((count, more, overflow, malformed))
    }
    /// One bounded amdgpu_ih_process pass over both rings, ring 0 first.
    /// Always writes back both rptrs.
    fn collect(&mut self, out: &mut [Iv; BATCH]) -> Result<Batch, Error> {
        let map = self.memory.mapping();
        let mut rptrs = self.rptr;
        let batch = self.access(|io, l| {
            // HDP flush before CPU reads of ring memory (Navi48 pattern).
            fence(Ordering::SeqCst);
            io.write(0x7f000, 0);
            io.read(Self::nbio(l, NBIO_MEMSIZE));
            fence(Ordering::SeqCst);
            let mut batch = Batch::default();
            for (ring, rptr) in rptrs.iter_mut().enumerate() {
                let (count, more, overflow, malformed) =
                    Self::collect_ring(io, l, ring, map, rptr, &mut out[batch.count..])?;
                batch.count += count;
                batch.more |= more;
                batch.overflow |= overflow;
                batch.malformed += malformed;
                if batch.count == BATCH {
                    break;
                }
            }
            Ok(batch)
        });
        self.rptr = rptrs;
        batch
    }
    /// ih_v6_0_irq_disable register writes; the caller waits 1 ms.
    fn disable(&mut self) -> Result<(), Error> {
        if self.state != State::Enabled {
            return Err(Error::Busy);
        }
        self.state = State::Disabled;
        self.access(|io, l| {
            Self::self_int(io, l, false)?;
            Self::toggle(io, l, 0, false)?;
            Self::toggle(io, l, 1, false)
        })?;
        self.rptr = [0, 0];
        Ok(())
    }
}

#[derive(Debug)]
struct Slot {
    source: Source,
    generation: u64,
    queue: VecDeque<Iv>,
    waker: Option<Waker>,
    lost: u64,
}
#[derive(Debug, Default)]
struct Table {
    next: u64,
    slots: Vec<Slot>,
}
/// IRQ-visible state. The IRQ handler touches only atomics here.
struct Hub {
    table: IrqSafeSpinLock<Table>,
    closed: AtomicU8,
    pending: AtomicBool,
    vector: AtomicU16,
    delivery: AtomicU8,
    interrupts: AtomicU64,
    drained: AtomicU64,
    unhandled: AtomicU64,
    malformed: AtomicU64,
    overflows: AtomicU64,
    dropped: AtomicU64,
    unsignalled: AtomicU64,
    watchdog: AtomicU64,
}
fn closed_code(reason: Closed) -> u8 {
    match reason {
        Closed::Revoked => 1,
        Closed::Disabled => 2,
        Closed::DeviceLost => 3,
        Closed::AuthorityRevoked => 4,
        Closed::Failed => 5,
    }
}
impl Hub {
    fn new() -> Self {
        Self {
            table: IrqSafeSpinLock::new(Table::default()),
            closed: AtomicU8::new(0),
            pending: AtomicBool::new(false),
            vector: AtomicU16::new(NO_VECTOR),
            delivery: AtomicU8::new(0),
            interrupts: AtomicU64::new(0),
            drained: AtomicU64::new(0),
            unhandled: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            unsignalled: AtomicU64::new(0),
            watchdog: AtomicU64::new(0),
        }
    }
    /// Minimal IRQ-context work: record and leave decoding to task context.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    fn record_interrupt(&self) {
        self.interrupts.fetch_add(1, Ordering::Relaxed);
        self.pending.store(true, Ordering::Release);
    }
    fn closed(&self) -> Result<(), Closed> {
        match self.closed.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(Closed::Revoked),
            2 => Err(Closed::Disabled),
            3 => Err(Closed::DeviceLost),
            4 => Err(Closed::AuthorityRevoked),
            _ => Err(Closed::Failed),
        }
    }
    /// Wake every parked waiter without closing (their next poll drains).
    fn kick(&self) {
        let wakers: Vec<Waker> = {
            let mut table = self.table.lock();
            table
                .slots
                .iter_mut()
                .filter_map(|s| s.waker.take())
                .collect()
        };
        wakers.into_iter().for_each(Waker::wake);
    }
    /// First terminal reason wins; every parked waiter is woken.
    fn close(&self, reason: Closed) {
        let _ = self.closed.compare_exchange(
            0,
            closed_code(reason),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let wakers: Vec<Waker> = {
            let mut table = self.table.lock();
            table
                .slots
                .iter_mut()
                .filter_map(|s| s.waker.take())
                .collect()
        };
        wakers.into_iter().for_each(Waker::wake);
    }
    fn delivery(&self) -> Delivery {
        let vector = self.vector.load(Ordering::Acquire) as u8;
        match self.delivery.load(Ordering::Acquire) {
            1 => Delivery::MsiX { vector },
            2 => Delivery::Msi { vector },
            3 => Delivery::Polling,
            _ => Delivery::Pending,
        }
    }
    fn set_delivery(&self, delivery: Delivery) {
        let (kind, vector) = match delivery {
            Delivery::Pending => (0, NO_VECTOR),
            Delivery::MsiX { vector } => (1, u16::from(vector)),
            Delivery::Msi { vector } => (2, u16::from(vector)),
            Delivery::Polling => (3, NO_VECTOR),
        };
        self.vector.store(vector, Ordering::Release);
        self.delivery.store(kind, Ordering::Release);
    }
    fn vector(&self) -> Option<u8> {
        let vector = self.vector.load(Ordering::Acquire);
        (vector != NO_VECTOR).then_some(vector as u8)
    }
    /// Ring sampling period for deliveries with no interrupt: polling mode
    /// samples every millisecond, a ring not yet routed every 10 ms. MSI and
    /// MSI-X need none (Linux `ih_v6_0` has no IH timer).
    fn watchdog_us(&self) -> Option<u64> {
        match self.delivery() {
            Delivery::Polling => Some(1000),
            Delivery::Pending => Some(10_000),
            Delivery::MsiX { .. } | Delivery::Msi { .. } => None,
        }
    }
    fn dispatch(&self, ivs: &[Iv]) {
        let mut wakers = Vec::new();
        {
            let mut table = self.table.lock();
            for iv in ivs {
                let Some(slot) = table.slots.iter_mut().find(|s| s.source == iv.source()) else {
                    self.unhandled.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if slot.queue.len() >= QUEUE {
                    slot.queue.pop_front();
                    slot.lost += 1;
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                slot.queue.push_back(*iv);
                if let Some(waker) = slot.waker.take() {
                    wakers.push(waker);
                }
            }
        }
        wakers.into_iter().for_each(Waker::wake);
    }
    fn stats(&self) -> Stats {
        let load = |v: &AtomicU64| v.load(Ordering::Relaxed);
        Stats {
            interrupts: load(&self.interrupts),
            drained: load(&self.drained),
            unhandled: load(&self.unhandled),
            malformed: load(&self.malformed),
            overflows: load(&self.overflows),
            dropped: load(&self.dropped),
            unsignalled: load(&self.unsignalled),
            watchdog: load(&self.watchdog),
        }
    }
}
trait Port: Send + Sync {
    fn hub(&self) -> &Hub;
    fn drain(&self) -> Result<usize, Closed>;
}
struct Shared<I: Io> {
    hub: Hub,
    engine: Mutex<Engine<I>>,
}
impl<I: Io> Port for Shared<I> {
    fn hub(&self) -> &Hub {
        &self.hub
    }
    fn drain(&self) -> Result<usize, Closed> {
        let mut total = 0;
        for _ in 0..RESTARTS {
            // A busy engine: its holder re-checks `pending` once it lets go
            // (`redrain_if_pending`), so this waiter can park.
            let Some((n, more)) = self.drain_once()? else {
                return Ok(total);
            };
            total += n;
            if more {
                // The pass used its whole budget: what is left is drained by
                // the subscribers' next waits, which this wakes, rather than
                // by holding the CPU here.
                self.hub.kick();
                return Ok(total);
            }
            // An interrupt that arrived while the engine was held found the
            // drain busy and left only `pending` behind: drain again now the
            // engine is free (Linux `amdgpu_ih_process` re-reads the write
            // pointer and restarts).
            if !self.pending_after_release() {
                return Ok(total);
            }
        }
        self.hub.kick();
        Ok(total)
    }
}

impl<I: Io> Shared<I> {
    /// One budgeted pass over both rings under the engine lock: IVs drained
    /// and whether more remain; `None` if another owner holds the engine.
    fn drain_once(&self) -> Result<Option<(usize, bool)>, Closed> {
        self.hub.closed()?;
        let Some(mut engine) = self.engine.try_lock() else {
            return Ok(None);
        };
        let signalled = self.hub.pending.swap(false, Ordering::SeqCst);
        if engine.state != State::Enabled {
            return Ok(Some((0, false)));
        }
        let mut total = 0;
        let mut more = false;
        for _ in 0..ROUNDS {
            let mut ivs = [Iv::default(); BATCH];
            let batch = match engine.collect(&mut ivs) {
                Ok(batch) => batch,
                Err(error) => {
                    engine.state = State::Failed;
                    let reason = if error == Error::Revoked {
                        Closed::AuthorityRevoked
                    } else {
                        Closed::DeviceLost
                    };
                    drop(engine);
                    self.hub.close(reason);
                    return Err(reason);
                }
            };
            let hub = &self.hub;
            hub.malformed.fetch_add(batch.malformed, Ordering::Relaxed);
            hub.overflows
                .fetch_add(u64::from(batch.overflow), Ordering::Relaxed);
            hub.drained.fetch_add(batch.count as u64, Ordering::Relaxed);
            hub.dispatch(&ivs[..batch.count]);
            total += batch.count;
            more = batch.more;
            if !more {
                break;
            }
        }
        if total != 0 && !signalled {
            self.hub.unsignalled.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Some((total, more)))
    }

    /// After letting go of the engine: whether an interrupt left IVs behind.
    fn pending_after_release(&self) -> bool {
        fence(Ordering::SeqCst);
        self.hub.pending.load(Ordering::SeqCst)
    }

    /// Every engine holder other than a drain calls this once it lets go: an
    /// interrupt that found the engine busy left its IVs behind for the
    /// holder to drain.
    fn redrain_if_pending(&self) {
        if self.pending_after_release() {
            let _ = Port::drain(self);
        }
    }

    /// The trap round trip that proves the route ([`prove`]). With MSI or
    /// MSI-X delivery nothing but the vector wakes a waiter (Linux
    /// `amdgpu_irq_handler` → `amdgpu_ih_process`; no IH timer), so a trap
    /// whose IV reached the ring with no interrupt for it shows the route
    /// delivers nothing and every later IV would wait forever. The ring is
    /// then sampled instead, as for a route that could not be programmed.
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    async fn prove_route(
        &self,
        waiter: &mut Subscription,
        context: u32,
        interrupts: u64,
    ) -> Result<Proof, Error> {
        let result = prove(&self.hub, waiter, context, interrupts).await;
        if matches!(
            result,
            Ok(Proof {
                interrupt: false,
                ..
            })
        ) && matches!(
            self.hub.delivery(),
            Delivery::Msi { .. } | Delivery::MsiX { .. }
        ) {
            self.sample_ring().await;
        }
        result
    }

    /// Fall back to `Delivery::Polling`: `RPTR_REARM` clear as
    /// `program(false)` leaves it (`ih_v6_0_enable_ring` sets it only with
    /// MSI), and the waiters parked on the vector alone re-plan onto the
    /// polling timer.
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    async fn sample_ring(&self) {
        self.hub.set_delivery(Delivery::Polling);
        let _ = self.engine.lock().await.rearm(false);
        self.hub.kick();
    }
}

/// Cloneable dispatch endpoint for other Navi31 owners (rings, VM, DCN).
#[derive(Clone)]
pub struct Handle(Arc<dyn Port>);
impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handle")
            .field("delivery", &self.delivery())
            .finish_non_exhaustive()
    }
}
impl Handle {
    /// Claim the only route for `source`. Subscribing before IH enable is
    /// allowed; a second live owner is `Busy`.
    pub fn subscribe(&self, source: Source) -> Result<Subscription, Error> {
        let hub = self.0.hub();
        hub.closed().map_err(Error::Closed)?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(QUEUE)
            .map_err(|_| Error::Allocation)?;
        let mut table = hub.table.lock();
        if table.slots.iter().any(|s| s.source == source) {
            return Err(Error::Busy);
        }
        if table.slots.len() >= SLOTS || table.slots.try_reserve(1).is_err() {
            return Err(Error::Allocation);
        }
        table.next += 1;
        let generation = table.next;
        table.slots.push(Slot {
            source,
            generation,
            queue,
            waker: None,
            lost: 0,
        });
        drop(table);
        Ok(Subscription {
            port: self.0.clone(),
            source,
            generation,
        })
    }
    /// Revoke the current owner of `source`; its waiter observes
    /// `Closed::Revoked` and never receives a later owner's IVs.
    pub fn revoke(&self, source: Source) -> bool {
        let waker = {
            let mut table = self.0.hub().table.lock();
            let Some(index) = table.slots.iter().position(|s| s.source == source) else {
                return false;
            };
            table.slots.swap_remove(index).waker
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }
    /// Drain both rings in task context. Never call from an IRQ handler.
    pub fn drain(&self) -> Result<usize, Closed> {
        self.0.drain()
    }
    /// Report device loss (e.g. from PCIe recovery); every waiter terminates.
    pub fn close(&self, reason: Closed) {
        self.0.hub().close(reason);
    }
    pub fn delivery(&self) -> Delivery {
        self.0.hub().delivery()
    }
    pub fn stats(&self) -> Stats {
        self.0.hub().stats()
    }
}

/// Generation-tagged ownership of one (client, src) route.
pub struct Subscription {
    port: Arc<dyn Port>,
    source: Source,
    generation: u64,
}
impl core::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Subscription")
            .field("source", &self.source)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl Subscription {
    pub fn source(&self) -> Source {
        self.source
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// IVs dropped from this mailbox because it was full.
    pub fn lost(&self) -> u64 {
        let table = self.port.hub().table.lock();
        table
            .slots
            .iter()
            .find(|s| s.generation == self.generation)
            .map_or(0, |s| s.lost)
    }
    fn pop(&self, waker: Option<&Waker>) -> Result<Option<Iv>, Closed> {
        let mut table = self.port.hub().table.lock();
        let slot = table
            .slots
            .iter_mut()
            .find(|s| s.generation == self.generation)
            .ok_or(Closed::Revoked)?;
        if let Some(iv) = slot.queue.pop_front() {
            return Ok(Some(iv));
        }
        if let Some(waker) = waker {
            slot.waker = Some(waker.clone());
        }
        Ok(None)
    }
    /// Queued IVs are delivered before a terminal error.
    pub fn try_next(&mut self) -> Result<Option<Iv>, Closed> {
        if let Some(iv) = self.pop(None)? {
            return Ok(Some(iv));
        }
        self.port.hub().closed()?;
        let drained = self.port.drain();
        if let Some(iv) = self.pop(None)? {
            return Ok(Some(iv));
        }
        drained?;
        self.port.hub().closed()?;
        Ok(None)
    }
    /// Wait for the next IV. Woken by dispatch, the host vector, or the
    /// watchdog; cancellation only drops this waiter's registrations.
    pub fn wait(&mut self) -> Next<'_> {
        Next {
            subscription: self,
            timer: None,
            vector: None,
        }
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let mut table = self.port.hub().table.lock();
        table.slots.retain(|s| s.generation != self.generation);
    }
}
#[must_use = "futures do nothing unless polled"]
pub struct Next<'a> {
    subscription: &'a mut Subscription,
    timer: Option<narf_time::SleepUntil>,
    vector: Option<(u8, Waker)>,
}
impl core::fmt::Debug for Next<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Next")
            .field("subscription", &self.subscription)
            .finish_non_exhaustive()
    }
}
impl Future for Next<'_> {
    type Output = Result<Iv, Closed>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            // Register for the host vector BEFORE draining: an interrupt from
            // here on wakes this waiter, and every IV the device posted
            // before it (the IV write precedes its MSI) is in the ring the
            // drain below reads, so no IV can fall between the two.
            let vector = this.subscription.port.hub().vector();
            if let Some((old, waker)) = this.vector.take_if(|(old, _)| Some(*old) != vector) {
                narf_interrupts::dispatch::clear_waker(old, &waker);
            }
            if let Some(vector) = vector {
                narf_interrupts::dispatch::set_waker(vector, cx.waker().clone());
                this.vector = Some((vector, cx.waker().clone()));
            }
            match this.subscription.try_next() {
                Ok(Some(iv)) => return Poll::Ready(Ok(iv)),
                Err(reason) => return Poll::Ready(Err(reason)),
                Ok(None) => {}
            }
            // Park under the table lock so a concurrent dispatch/close cannot
            // be missed, then recheck termination.
            match this.subscription.pop(Some(cx.waker())) {
                Ok(Some(iv)) => return Poll::Ready(Ok(iv)),
                Err(reason) => return Poll::Ready(Err(reason)),
                Ok(None) => {}
            }
            let hub = this.subscription.port.hub();
            if let Err(reason) = hub.closed() {
                return Poll::Ready(Err(reason));
            }
            let Some(period) = hub.watchdog_us() else {
                // Interrupt-driven: the vector waker registered above wakes
                // this waiter for every IV posted after the drain.
                return Poll::Pending;
            };
            let timer = this.timer.get_or_insert_with(|| {
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(period).as_instant())
            });
            if Pin::new(timer).poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.timer = None;
            hub.watchdog.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for Next<'_> {
    fn drop(&mut self) {
        if let Some((vector, waker)) = self.vector.take() {
            narf_interrupts::dispatch::clear_waker(vector, &waker);
        }
    }
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn interrupt(cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: the cookie is a Hub inside an Arc whose clone was leaked when
    // the handler was installed; it is never freed.
    let hub = unsafe { &*(cookie as *const Hub) };
    hub.record_interrupt();
    narf_interrupts::IrqStatus::Handled
}

#[derive(Debug)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
enum Route {
    None,
    MsiX(narf_bus::MsixTable),
    // Integration remainder: read by `unroute`, which is first called when
    // the RDNA3 platform skeleton wires this IH stage in.
    Msi(#[allow(dead_code)] narf_bus::msi::MsiConfig),
}

/// Exclusive IH ring owner.
pub struct Ih {
    shared: Arc<Shared<Mmio>>,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    device: BusDevice,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    authority: Cap<BusDeviceCap, Write>,
    // Never freed: NBIO may hold its address until reset.
    _dummy: core::mem::ManuallyDrop<narf_io::DmaBuffer>,
    route: Route,
    state: State,
    die: Die,
    proof: Option<Result<Proof, Error>>,
}
impl core::fmt::Debug for Ih {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ih")
            .field("state", &self.state)
            .field("die", &self.die)
            .field("route", &self.route)
            .field("proof", &self.proof)
            .finish_non_exhaustive()
    }
}
impl Ih {
    /// Reserve the VRAM rings/writeback and NBIO dummy page without I/O.
    /// # Safety
    /// Caller owns this physical Navi31/32/33 GPU, OSSSYS/NBIO, its PCI
    /// interrupt capabilities and the matching permanent VRAM pool exclusively.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        device: BusDevice,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        Self::with_layout(gpu, authority, pool, device, layout)
    }
    fn with_layout(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        device: BusDevice,
        layout: Layout,
    ) -> Result<Self, Error> {
        let memory = pool.reserve(BYTES).map_err(|_| Error::Allocation)?;
        let dummy = narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| Error::Allocation)?;
        // SAFETY: freshly allocated, exclusively owned 4 KiB page.
        unsafe { core::ptr::write_bytes(dummy.cpu_mut_ptr::<u8>(), 0, 4096) };
        let engine = Engine {
            io: Mmio(gpu.regs),
            authority,
            layout,
            memory,
            dummy: dummy.dma_addr().raw(),
            state: State::Prepared,
            rptr: [0, 0],
            inherited: false,
        };
        Ok(Self {
            shared: Arc::new(Shared {
                hub: Hub::new(),
                engine: Mutex::new(engine),
            }),
            device,
            authority,
            _dummy: core::mem::ManuallyDrop::new(dummy),
            route: Route::None,
            state: State::Prepared,
            die: layout.die,
            proof: None,
        })
    }
    /// The die this owner bound, by discovered GC version.
    pub fn die(&self) -> Die {
        self.die
    }
    pub fn handle(&self) -> Handle {
        Handle(self.shared.clone())
    }
    /// amdgpu_irq_init then ih_v6_0_hw_init: route one host vector, then
    /// program and enable both rings. Routing failure degrades to polling.
    /// # Safety
    /// GMC VMID0 is ready (the rings are reached through its system
    /// aperture), and `new`'s ownership contract still holds. No second
    /// owner after failure or cancellation. This is the Navi22 owner's
    /// contract, not a typed gate: lane 3's `Gmc` does not exist on this
    /// branch yet, so the platform must call this only after the GMC
    /// owner reports `vmid0_ready()`.
    pub async unsafe fn initialize(&mut self) -> Result<Delivery, Error> {
        let shared = self.shared.clone();
        let result = {
            let mut engine = shared.engine.lock().await;
            match engine.preflight() {
                Ok(()) => {
                    // SAFETY: forwarded exclusive PCI function ownership.
                    let delivery = unsafe { self.route() };
                    self.shared.hub.set_delivery(delivery);
                    let msi = !matches!(delivery, Delivery::Polling);
                    engine.program(msi).map(|()| delivery).inspect_err(|_| {
                        engine.state = State::Failed;
                    })
                }
                Err(Error::Busy) => Err(Error::Busy),
                Err(error) => {
                    engine.state = State::Failed;
                    Err(error)
                }
            }
        };
        match result {
            Ok(_) => {
                self.state = State::Enabled;
                // An interrupt raised while the rings were being enabled
                // found the engine held.
                self.shared.redrain_if_pending();
            }
            Err(Error::Busy) => {}
            Err(_) => {
                self.state = State::Failed;
                self.shared.hub.close(Closed::Failed);
            }
        }
        result
    }
    /// # Safety
    /// Caller owns the PCI function's config space and MSI-X table.
    unsafe fn route(&mut self) -> Delivery {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_interrupts::{dispatch, vector};
            let (cap, device) = (&self.authority, &self.device);
            if narf_bus::pci::set_command(cap, device, narf_bus::pci::cmd::BUS_MASTER).is_err() {
                return Delivery::Polling;
            }
            let cookie = &self.shared.hub as *const Hub as u64;
            // SAFETY: APIC initialization precedes device initcalls.
            let target = unsafe { narf_interrupts::current_cpu_target_id() };
            if target > 255 {
                return Delivery::Polling;
            }
            let Ok(vector) = vector::alloc() else {
                return Delivery::Polling;
            };
            // The handler's Hub must outlive every possible delivery.
            core::mem::forget(self.shared.clone());
            dispatch::install_handler_named(vector, "amdgpu-navi31-ih", cookie, interrupt);
            if let Ok(mut table) = narf_bus::enable_msix(cap, device) {
                // SAFETY: owned function; IH sources are still disabled.
                unsafe { table.disable() };
                if table.alloc_vector().is_some()
                    // SAFETY: one owned vector, installed handler, valid target.
                    && unsafe { table.program_vector(0, target, vector) }.is_ok()
                    // SAFETY: same owned config space.
                    && unsafe { table.enable() }.is_ok()
                {
                    self.route = Route::MsiX(table);
                    return Delivery::MsiX { vector };
                }
                // SAFETY: nothing was delivered through this table.
                unsafe { table.disable() };
            }
            if let Ok(mut cfg) = narf_bus::msi::enable_msi(cap, device, 1) {
                // SAFETY: owned config space; vector and handler installed.
                if unsafe { narf_bus::msi::program_msi(&mut cfg, target, vector) }.is_ok()
                    // SAFETY: same.
                    && unsafe { narf_bus::msi::enable(&cfg) }.is_ok()
                {
                    self.route = Route::Msi(cfg);
                    return Delivery::Msi { vector };
                }
            }
            dispatch::remove_handler(vector, "amdgpu-navi31-ih", cookie);
            dispatch::synchronize_irq(vector);
            let _ = vector::free(vector);
            Delivery::Polling
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Delivery::Polling
        }
    }
    /// Bounded ih_v6_0_irq_disable; every waiter receives `Disabled`.
    /// Both rings stay quarantined and the vector stays reserved.
    /// # Safety
    /// Same ownership as `new`; consumers no longer depend on IH delivery.
    pub async unsafe fn disable(&mut self) -> Result<(), Error> {
        let result = self.shared.engine.lock().await.disable();
        if result != Err(Error::Busy) {
            delay(1000).await;
            self.state = State::Disabled;
            #[cfg(target_arch = "x86_64")]
            if let Some(vector) = self.shared.hub.vector() {
                match &mut self.route {
                    // SAFETY: IH has stopped raising interrupts.
                    Route::MsiX(table) => unsafe { table.disable() },
                    Route::Msi(_) | Route::None => {}
                }
                narf_interrupts::dispatch::disable_irq(vector);
                narf_interrupts::dispatch::synchronize_irq(vector);
            }
            self.shared.hub.close(Closed::Disabled);
        }
        result
    }
    /// Bounded (100 ms) round trip for an event the caller just raised.
    /// The result is retained in `status()`.
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    pub(crate) async fn prove(
        &mut self,
        waiter: &mut Subscription,
        context: u32,
        interrupts: u64,
    ) -> Result<Proof, Error> {
        let vector = self.shared.hub.vector();
        let result = self.shared.prove_route(waiter, context, interrupts).await;
        if let Some(vector) = vector.filter(|_| self.shared.hub.vector().is_none()) {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::PriorityWriter::<4>,
                "amdgpu: navi31 IH vector {vector} raised no interrupt for its trap; sampling the ring"
            );
            // SAFETY: `new`'s exclusive ownership of the PCI function and
            // its interrupt capabilities still holds.
            unsafe { self.unroute(vector) };
        }
        self.proof = Some(result);
        result
    }
    /// Undo `route` for a vector the proof showed silent: the teardown
    /// `route` runs when programming fails.
    /// # Safety
    /// Caller owns the PCI function's config space and MSI-X table.
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    unsafe fn unroute(&mut self, vector: u8) {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_interrupts::{dispatch, vector as vectors};
            match core::mem::replace(&mut self.route, Route::None) {
                // SAFETY: the IH's own table; caller-owned function.
                Route::MsiX(mut table) => unsafe { table.disable() },
                Route::Msi(cfg) => {
                    // SAFETY: same owned config space.
                    let _ = unsafe { narf_bus::msi::disable(&cfg) };
                }
                Route::None => {}
            }
            let cookie = &self.shared.hub as *const Hub as u64;
            dispatch::remove_handler(vector, "amdgpu-navi31-ih", cookie);
            dispatch::synchronize_irq(vector);
            let _ = vectors::free(vector);
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = vector;
    }
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    pub(crate) fn interrupts(&self) -> u64 {
        self.shared.hub.interrupts.load(Ordering::Acquire)
    }
    // Integration remainder: first called when the RDNA3 platform skeleton
    // wires this IH stage in (no platform caller on this branch yet).
    #[allow(dead_code)]
    pub(crate) fn record_proof(&mut self, error: Error) {
        self.proof = Some(Err(error));
    }
    pub fn state(&self) -> State {
        let Some(engine) = self.shared.engine.try_lock() else {
            return self.state;
        };
        let state = engine.state;
        drop(engine);
        self.shared.redrain_if_pending();
        state
    }
    pub fn status(&self) -> Status {
        // One engine hold, then the redrain every non-drain holder owes
        // (`redrain_if_pending`): an interrupt that found it held left its
        // IVs for this holder.
        let (state, inherited) = match self.shared.engine.try_lock() {
            Some(engine) => {
                let read = (engine.state, engine.inherited);
                drop(engine);
                self.shared.redrain_if_pending();
                read
            }
            None => (self.state, false),
        };
        Status {
            state,
            delivery: self.shared.hub.delivery(),
            inherited,
            proof: self.proof,
            stats: self.shared.hub.stats(),
        }
    }
}
// Integration remainder: first called when the RDNA3 platform skeleton
// wires this IH stage in (no platform caller on this branch yet). The
// fixture tests call it under `kernel-test`; the plain lib build does not.
#[allow(dead_code)]
async fn prove(
    hub: &Hub,
    waiter: &mut Subscription,
    context: u32,
    interrupts: u64,
) -> Result<Proof, Error> {
    let deadline = narf_time::Deadline::after_ms(100);
    loop {
        if let Some(iv) = waiter.try_next().map_err(Error::Closed)? {
            // linux-lit: 0x0fff_ffff=SDMA_PKT_TRAP_INT_CONTEXT_int_context_mask
            if iv.ring_id == 0 && iv.src_data[0] & 0x0fff_ffff == context {
                // Allow the MSI write a further 10 ms to be observed.
                let late = narf_time::Deadline::after_ms(10);
                while hub.interrupts.load(Ordering::Acquire) == interrupts
                    && hub.vector().is_some()
                    && !late.expired()
                {
                    delay(500).await;
                }
                return Ok(Proof {
                    iv,
                    interrupt: hub.interrupts.load(Ordering::Acquire) != interrupts,
                });
            }
            continue;
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        delay(1000).await;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_ih_navi31_tests.rs"]
mod tests;
