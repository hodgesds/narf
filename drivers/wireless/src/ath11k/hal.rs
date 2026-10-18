//! HAL SRNG core — the hardware-managed rings every ath11k transport
//! (Copy Engines, data path) is built from.
//!
//! A port of Linux `drivers/net/wireless/ath/ath11k/hal.c` (SRNG part)
//! and `hal.h`:
//!
//! - [`SRNG_CONFIG_TEMPLATE`] = `hw_srng_config_template[]`;
//!   [`create_config`] = `ath11k_hal_srng_create_config` (per-chip
//!   register bases from [`HalRegs`], `ATH11K_CE_OFFSET` = 0 on PCI).
//! - [`Hal::new`] = `ath11k_hal_srng_init` (+ the shadow-register
//!   assignment `ath11k_ce_get_shadow_config` performs at probe).
//! - [`Hal::srng_setup`] = `ath11k_hal_srng_setup` with
//!   `ath11k_hal_srng_src_hw_init` / `dst_hw_init` and, for CE
//!   destination rings, `ath11k_hal_ce_dst_setup`.
//! - Ring access: `access_begin` / `access_end`, `src_get_next_entry`,
//!   `src_reap_next`, `src_get_next_reaped`, `src_peek`,
//!   `src_next_peek`, `dst_get_next_entry`, `dst_peek`, `src_num_free`,
//!   `dst_num_free`.
//! - Shadow registers v2: [`ShadowConfig`] (`ath11k_hal_srng_shadow_config`,
//!   `ath11k_hal_srng_update_shadow_config`,
//!   `ath11k_hal_srng_get_shadow_config`), [`shadow_reg`]
//!   (`HAL_SHADOW_REG`), [`Hal::shadow_update_hp_tp`].
//! - CE descriptor helpers: `ath11k_hal_ce_src_set_desc`,
//!   `ath11k_hal_ce_dst_set_desc`, `ath11k_hal_ce_dst_status_get_length`,
//!   `ath11k_hal_ce_get_desc_size`.
//!
//! [`shadow_reg_v2`] is the list QMI `wlan_cfg` carries
//! (`ath11k_pci_init_qmi_ce_config` → `ath11k_ce_get_shadow_config`).
//!
//! Register I/O goes through [`ChipIo`] (Linux `ath11k_hif_read32` /
//! `write32`): direct BAR0 below `ATH11K_PCI_WINDOW_START`, the sliding
//! window above it — the SRNG R0/R2 blocks are windowed, the shadow
//! registers (`0x8fc + 4 * n`) are direct.
//!
//! Units follow Linux: `entry_size`, `ring_size`, `hp`, `tp` are in
//! 32-bit words.
//!
//! Not ported: the REO command / queue-descriptor helpers, the WBM
//! idle-list scatter setup, `dump_srng_stats`, big-endian swap flags
//! (NARF hosts are little-endian).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, fence, Ordering};

use narf_io::DmaBuffer;
use narf_lib::id::DomainId;

use super::ce::CeAttr;
use super::dp;
use super::hw::{HalRegs, HwParams};
use super::power::ChipIo;

// ── errors / diag ─────────────────────────────────────────────────

/// Failing-step codes latched through `narf_memory::diag` (HAL 80–89,
/// CE 90–99; MHI uses 10–35, PCI 1–5).
pub mod step {
    /// Coherent DMA allocation failed (detail = bytes).
    pub const NO_DMA_MEMORY: u32 = 80;
    /// `ring_num >= max_rings` (detail = type << 16 | ring_num).
    pub const BAD_RING_NUM: u32 = 81;
    /// Computed ring id beyond `HAL_SRNG_RING_ID_MAX` (detail = id).
    pub const RING_ID_RANGE: u32 = 82;
    /// All `HAL_SHADOW_NUM_REGS` shadow registers are taken (detail =
    /// type << 16 | ring_num).
    pub const SHADOW_FULL: u32 = 83;
    /// Shadow registers in use but this ring got none (detail = ring id).
    pub const NO_SHADOW_REG: u32 = 84;
    /// `entry_size * num_entries` exceeds the ring type's `max_size`, or
    /// zero entries (detail = type << 16 | entries, truncated).
    pub const BAD_RING_SIZE: u32 = 85;
    /// No HAL register map for this hardware revision.
    pub const NO_REGS: u32 = 86;
    /// The ring memory is smaller than `entry_size * num_entries`.
    pub const RING_MEM_SIZE: u32 = 87;
    /// Ring id already set up (detail = ring id).
    pub const RING_IN_USE: u32 = 88;
}

/// Linux errno values (positive).
pub mod errno {
    pub const EIO: i32 = 5;
    pub const ENOMEM: i32 = 12;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const ENOBUFS: i32 = 105;
    pub const ESHUTDOWN: i32 = 108;
}

/// A HAL / CE failure: the diag step + detail it latches, and the
/// errno Linux returns for the same condition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    pub step: u32,
    pub detail: u32,
    pub errno: i32,
}

impl TransportError {
    pub const fn new(step: u32, detail: u32, errno: i32) -> Self {
        TransportError {
            step,
            detail,
            errno,
        }
    }

    /// Latch into the framebuffer diag line and print to the console.
    pub fn report(&self, what: &str) {
        use core::fmt::Write as _;
        narf_memory::diag::latch_wifi_error(self.step, self.detail);
        let _ = writeln!(
            narf_console::Writer,
            "  ath11k: {} failed: step {} detail {:#x} (-{})",
            what,
            self.step,
            self.detail,
            self.errno
        );
    }
}

// ── constants (hal.h) ─────────────────────────────────────────────

pub const HAL_SHADOW_NUM_REGS: usize = 36;
pub const HAL_HP_OFFSET_IN_REG_START: usize = 1;
pub const HAL_OFFSET_FROM_HP_TO_TP: u32 = 4;

pub const HAL_SEQ_WCSS_UMAC_OFFSET: u32 = 0x00a0_0000;
pub const HAL_SEQ_WCSS_UMAC_REO_REG: u32 = 0x00a3_8000;
pub const HAL_SEQ_WCSS_UMAC_TCL_REG: u32 = 0x00a4_4000;
pub const HAL_SEQ_WCSS_UMAC_WBM_REG: u32 = 0x00a3_4000;

/// `ATH11K_CE_OFFSET(ab)` = `ab->mem_ce - ab->mem` = 0 on PCI.
pub const ATH11K_CE_OFFSET_PCI: u32 = 0;

// SW2TCL R2
pub const HAL_TCL1_RING_HP: u32 = 0x0000_2000;
pub const HAL_TCL1_RING_TP: u32 = 0x0000_2004;
pub const HAL_TCL2_RING_HP: u32 = 0x0000_2008;
pub const HAL_TCL_RING_HP: u32 = 0x0000_2018;
pub const HAL_TCL1_RING_TP_OFFSET: u32 = HAL_TCL1_RING_TP - HAL_TCL1_RING_HP;
pub const HAL_TCL_STATUS_RING_HP: u32 = 0x0000_2030;

// CE R0 / R2
pub const HAL_CE_DST_RING_BASE_LSB: u32 = 0x0000_0000;
pub const HAL_CE_DST_STATUS_RING_BASE_LSB: u32 = 0x0000_0058;
pub const HAL_CE_DST_RING_CTRL: u32 = 0x0000_00b0;
pub const HAL_CE_DST_RING_HP: u32 = 0x0000_0400;
pub const HAL_CE_DST_STATUS_RING_HP: u32 = 0x0000_0408;

// WBM R2
pub const HAL_WBM_IDLE_LINK_RING_HP: u32 = 0x0000_30b0;
pub const HAL_WBM_RELEASE_RING_HP: u32 = 0x0000_3018;
pub const HAL_WBM0_RELEASE_RING_HP: u32 = 0x0000_30c0;
pub const HAL_WBM1_RELEASE_RING_HP: u32 = 0x0000_30c8;

// TCL ring fields
pub const HAL_TCL1_RING_BASE_MSB_RING_SIZE: u32 = genmask(27, 8);
pub const HAL_TCL1_RING_BASE_MSB_RING_BASE_ADDR_MSB: u32 = genmask(7, 0);
pub const HAL_TCL1_RING_ID_ENTRY_SIZE: u32 = genmask(7, 0);
pub const HAL_TCL1_RING_MISC_MSI_LOOPCNT_DISABLE: u32 = 1 << 1;
pub const HAL_TCL1_RING_MISC_MSI_SWAP: u32 = 1 << 3;
pub const HAL_TCL1_RING_MISC_HOST_FW_SWAP: u32 = 1 << 4;
pub const HAL_TCL1_RING_MISC_DATA_TLV_SWAP: u32 = 1 << 5;
pub const HAL_TCL1_RING_MISC_SRNG_ENABLE: u32 = 1 << 6;
pub const HAL_TCL1_RING_CONSR_INT_SETUP_IX0_INTR_TMR_THOLD: u32 = genmask(31, 16);
pub const HAL_TCL1_RING_CONSR_INT_SETUP_IX0_BATCH_COUNTER_THOLD: u32 = genmask(14, 0);
pub const HAL_TCL1_RING_CONSR_INT_SETUP_IX1_LOW_THOLD: u32 = genmask(15, 0);
pub const HAL_TCL1_RING_MSI1_BASE_MSB_MSI1_ENABLE: u32 = 1 << 8;
pub const HAL_TCL1_RING_MSI1_BASE_MSB_ADDR: u32 = genmask(7, 0);

// REO ring fields
pub const HAL_REO1_RING_BASE_MSB_RING_SIZE: u32 = genmask(27, 8);
pub const HAL_REO1_RING_BASE_MSB_RING_BASE_ADDR_MSB: u32 = genmask(7, 0);
pub const HAL_REO1_RING_ID_RING_ID: u32 = genmask(15, 8);
pub const HAL_REO1_RING_ID_ENTRY_SIZE: u32 = genmask(7, 0);
pub const HAL_REO1_RING_MISC_MSI_SWAP: u32 = 1 << 3;
pub const HAL_REO1_RING_MISC_HOST_FW_SWAP: u32 = 1 << 4;
pub const HAL_REO1_RING_MISC_DATA_TLV_SWAP: u32 = 1 << 5;
pub const HAL_REO1_RING_MISC_SRNG_ENABLE: u32 = 1 << 6;
pub const HAL_REO1_RING_PRDR_INT_SETUP_INTR_TMR_THOLD: u32 = genmask(31, 16);
pub const HAL_REO1_RING_PRDR_INT_SETUP_BATCH_COUNTER_THOLD: u32 = genmask(14, 0);
pub const HAL_REO1_RING_MSI1_BASE_MSB_MSI1_ENABLE: u32 = 1 << 8;
pub const HAL_REO1_RING_MSI1_BASE_MSB_ADDR: u32 = genmask(7, 0);

// CE ring fields
pub const HAL_CE_DST_R0_DEST_CTRL_MAX_LEN: u32 = genmask(15, 0);

pub const HAL_ADDR_LSB_REG_MASK: u64 = 0xffff_ffff;
pub const HAL_ADDR_MSB_REG_SHIFT: u32 = 32;

// max ring sizes (`*_RING_BASE_MSB_RING_SIZE`), in words
pub const HAL_REO_REO2SW1_RING_BASE_MSB_RING_SIZE: u32 = 0x000f_ffff;
pub const HAL_REO_REO2TCL_RING_BASE_MSB_RING_SIZE: u32 = 0x000f_ffff;
pub const HAL_REO_SW2REO_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_REO_CMD_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_REO_STATUS_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_SW2TCL1_RING_BASE_MSB_RING_SIZE: u32 = 0x000f_ffff;
pub const HAL_SW2TCL1_CMD_RING_BASE_MSB_RING_SIZE: u32 = 0x000f_ffff;
pub const HAL_TCL_STATUS_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_CE_SRC_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_CE_DST_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_CE_DST_STATUS_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_WBM_IDLE_LINK_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_SW2WBM_RELEASE_RING_BASE_MSB_RING_SIZE: u32 = 0x0000_ffff;
pub const HAL_WBM2SW_RELEASE_RING_BASE_MSB_RING_SIZE: u32 = 0x000f_ffff;
pub const HAL_RXDMA_RING_MAX_SIZE: u32 = 0x0000_ffff;

/// srng flags (`HAL_SRNG_FLAGS_*`).
pub mod flags {
    pub const MSI_SWAP: u32 = 0x0000_0008;
    pub const RING_PTR_SWAP: u32 = 0x0000_0010;
    pub const DATA_TLV_SWAP: u32 = 0x0000_0020;
    pub const LOW_THRESH_INTR_EN: u32 = 0x0001_0000;
    pub const MSI_INTR: u32 = 0x0002_0000;
    pub const CACHED: u32 = 0x2000_0000;
    pub const LMAC_RING: u32 = 0x8000_0000;
    pub const REMAP_CE_RING: u32 = 0x1000_0000;
}

/// Interrupt mitigation defaults (`HAL_SRNG_INT_*`).
pub const HAL_SRNG_INT_BATCH_THRESHOLD_TX: u32 = 256;
pub const HAL_SRNG_INT_BATCH_THRESHOLD_RX: u32 = 128;
pub const HAL_SRNG_INT_BATCH_THRESHOLD_OTHER: u32 = 1;
pub const HAL_SRNG_INT_TIMER_THRESHOLD_TX: u32 = 1000;
pub const HAL_SRNG_INT_TIMER_THRESHOLD_RX: u32 = 500;
pub const HAL_SRNG_INT_TIMER_THRESHOLD_OTHER: u32 = 256;

/// `HAL_RING_BASE_ALIGN`.
pub const HAL_RING_BASE_ALIGN: usize = 8;

/// `GENMASK(h, l)` for 32-bit fields.
pub const fn genmask(h: u32, l: u32) -> u32 {
    (u32::MAX << l) & (u32::MAX >> (31 - h))
}

/// `FIELD_PREP(mask, v)` (value truncated to the field, as the hardware
/// sees it).
pub const fn field_prep(mask: u32, v: u32) -> u32 {
    (v << mask.trailing_zeros()) & mask
}

/// `FIELD_GET(mask, reg)`.
pub const fn field_get(mask: u32, reg: u32) -> u32 {
    (reg & mask) >> mask.trailing_zeros()
}

// ── ring ids (`enum hal_srng_ring_id`) ────────────────────────────

pub mod ring_id {
    pub const REO2SW1: u32 = 0;
    pub const REO2SW2: u32 = 1;
    pub const REO2SW3: u32 = 2;
    pub const REO2SW4: u32 = 3;
    pub const REO2TCL: u32 = 4;
    pub const SW2REO: u32 = 5;
    pub const REO_CMD: u32 = 8;
    pub const REO_STATUS: u32 = 9;
    pub const SW2TCL1: u32 = 16;
    pub const SW2TCL2: u32 = 17;
    pub const SW2TCL3: u32 = 18;
    pub const SW2TCL4: u32 = 19;
    pub const SW2TCL_CMD: u32 = 24;
    pub const TCL_STATUS: u32 = 25;
    pub const CE0_SRC: u32 = 32;
    pub const CE0_DST: u32 = 56;
    pub const CE0_DST_STATUS: u32 = 80;
    pub const WBM_IDLE_LINK: u32 = 104;
    pub const WBM_SW_RELEASE: u32 = 105;
    pub const WBM2SW0_RELEASE: u32 = 106;
    pub const WBM2SW1_RELEASE: u32 = 107;
    pub const WBM2SW2_RELEASE: u32 = 108;
    pub const WBM2SW3_RELEASE: u32 = 109;
    pub const WBM2SW4_RELEASE: u32 = 110;
    pub const UMAC_ID_END: u32 = 127;
    pub const LMAC1_ID_START: u32 = 128;
    pub const WMAC1_SW2RXDMA0_BUF: u32 = LMAC1_ID_START;
    pub const WMAC1_SW2RXDMA1_BUF: u32 = 129;
    pub const WMAC1_SW2RXDMA2_BUF: u32 = 130;
    pub const WMAC1_SW2RXDMA0_STATBUF: u32 = 131;
    pub const WMAC1_SW2RXDMA1_STATBUF: u32 = 132;
    pub const WMAC1_RXDMA2SW0: u32 = 133;
    pub const WMAC1_RXDMA2SW1: u32 = 134;
    pub const WMAC1_SW2RXDMA1_DESC: u32 = 135;
    pub const RXDMA_DIR_BUF: u32 = 136;
    pub const LMAC1_ID_END: u32 = 143;
}

pub const HAL_SRNG_NUM_LMACS: u32 = 3;
pub const HAL_SRNG_RINGS_PER_LMAC: u32 = ring_id::LMAC1_ID_END - ring_id::LMAC1_ID_START;
pub const HAL_SRNG_NUM_LMAC_RINGS: u32 = HAL_SRNG_NUM_LMACS * HAL_SRNG_RINGS_PER_LMAC;
/// `HAL_SRNG_RING_ID_MAX` = 127 + 3 * 15 = 172.
pub const HAL_SRNG_RING_ID_MAX: u32 = ring_id::UMAC_ID_END + HAL_SRNG_NUM_LMAC_RINGS;

pub const HAL_SRNG_REG_GRP_R0: usize = 0;
pub const HAL_SRNG_REG_GRP_R2: usize = 1;
pub const HAL_SRNG_NUM_REG_GRP: usize = 2;

// ── ring types / config template ──────────────────────────────────

/// `enum hal_ring_type`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HalRingType {
    ReoDst = 0,
    ReoException = 1,
    ReoReinject = 2,
    ReoCmd = 3,
    ReoStatus = 4,
    TclData = 5,
    TclCmd = 6,
    TclStatus = 7,
    CeSrc = 8,
    CeDst = 9,
    CeDstStatus = 10,
    WbmIdleLink = 11,
    Sw2WbmRelease = 12,
    Wbm2SwRelease = 13,
    RxdmaBuf = 14,
    RxdmaDst = 15,
    RxdmaMonitorBuf = 16,
    RxdmaMonitorStatus = 17,
    RxdmaMonitorDst = 18,
    RxdmaMonitorDesc = 19,
    RxdmaDirBuf = 20,
}

/// `HAL_MAX_RING_TYPES`.
pub const HAL_MAX_RING_TYPES: usize = 21;

impl HalRingType {
    /// Every type in enum order (the loop order of
    /// `ath11k_hal_srng_shadow_config`).
    pub const ALL: [HalRingType; HAL_MAX_RING_TYPES] = [
        HalRingType::ReoDst,
        HalRingType::ReoException,
        HalRingType::ReoReinject,
        HalRingType::ReoCmd,
        HalRingType::ReoStatus,
        HalRingType::TclData,
        HalRingType::TclCmd,
        HalRingType::TclStatus,
        HalRingType::CeSrc,
        HalRingType::CeDst,
        HalRingType::CeDstStatus,
        HalRingType::WbmIdleLink,
        HalRingType::Sw2WbmRelease,
        HalRingType::Wbm2SwRelease,
        HalRingType::RxdmaBuf,
        HalRingType::RxdmaDst,
        HalRingType::RxdmaMonitorBuf,
        HalRingType::RxdmaMonitorStatus,
        HalRingType::RxdmaMonitorDst,
        HalRingType::RxdmaMonitorDesc,
        HalRingType::RxdmaDirBuf,
    ];

    pub const fn idx(self) -> usize {
        self as usize
    }
}

/// `enum hal_srng_dir`, from the host's point of view: SRC = host
/// produces, DST = hardware produces.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SrngDir {
    Src,
    Dst,
}

/// `struct hal_srng_config`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SrngConfig {
    pub start_ring_id: u32,
    pub max_rings: u16,
    /// Entry size in 32-bit words.
    pub entry_size: u16,
    pub reg_start: [u32; HAL_SRNG_NUM_REG_GRP],
    pub reg_size: [u16; HAL_SRNG_NUM_REG_GRP],
    pub lmac_ring: bool,
    pub ring_dir: SrngDir,
    /// `*_RING_BASE_MSB_RING_SIZE`, in words.
    pub max_size: u32,
}

const fn words(bytes: usize) -> u16 {
    (bytes >> 2) as u16
}

const fn tmpl(
    start_ring_id: u32,
    max_rings: u16,
    entry_size: u16,
    lmac_ring: bool,
    ring_dir: SrngDir,
    max_size: u32,
) -> SrngConfig {
    SrngConfig {
        start_ring_id,
        max_rings,
        entry_size,
        reg_start: [0; 2],
        reg_size: [0; 2],
        lmac_ring,
        ring_dir,
        max_size,
    }
}

use core::mem::size_of;
use SrngDir::{Dst, Src};

/// `hw_srng_config_template[]` (entry sizes from the `dp` descriptor
/// layouts, exactly as Linux computes them with `sizeof`).
pub const SRNG_CONFIG_TEMPLATE: [SrngConfig; HAL_MAX_RING_TYPES] = [
    // REO_DST
    tmpl(
        ring_id::REO2SW1,
        4,
        words(size_of::<dp::HalReoDestRing>()),
        false,
        Dst,
        HAL_REO_REO2SW1_RING_BASE_MSB_RING_SIZE,
    ),
    // REO_EXCEPTION (REO2TCL used as the exception ring)
    tmpl(
        ring_id::REO2TCL,
        1,
        words(size_of::<dp::HalReoDestRing>()),
        false,
        Dst,
        HAL_REO_REO2TCL_RING_BASE_MSB_RING_SIZE,
    ),
    // REO_REINJECT
    tmpl(
        ring_id::SW2REO,
        1,
        words(size_of::<dp::HalReoEntranceRing>()),
        false,
        Src,
        HAL_REO_SW2REO_RING_BASE_MSB_RING_SIZE,
    ),
    // REO_CMD
    tmpl(
        ring_id::REO_CMD,
        1,
        words(size_of::<dp::HalTlvHdr>() + dp::HAL_REO_GET_QUEUE_STATS_SIZE),
        false,
        Src,
        HAL_REO_CMD_RING_BASE_MSB_RING_SIZE,
    ),
    // REO_STATUS
    tmpl(
        ring_id::REO_STATUS,
        1,
        words(size_of::<dp::HalTlvHdr>() + dp::HAL_REO_GET_QUEUE_STATS_STATUS_SIZE),
        false,
        Dst,
        HAL_REO_STATUS_RING_BASE_MSB_RING_SIZE,
    ),
    // TCL_DATA
    tmpl(
        ring_id::SW2TCL1,
        3,
        words(size_of::<dp::HalTlvHdr>() + size_of::<dp::HalTclDataCmd>()),
        false,
        Src,
        HAL_SW2TCL1_RING_BASE_MSB_RING_SIZE,
    ),
    // TCL_CMD
    tmpl(
        ring_id::SW2TCL_CMD,
        1,
        words(size_of::<dp::HalTlvHdr>() + dp::HAL_TCL_GSE_CMD_SIZE),
        false,
        Src,
        HAL_SW2TCL1_CMD_RING_BASE_MSB_RING_SIZE,
    ),
    // TCL_STATUS
    tmpl(
        ring_id::TCL_STATUS,
        1,
        words(size_of::<dp::HalTlvHdr>() + size_of::<dp::HalTclStatusRing>()),
        false,
        Dst,
        HAL_TCL_STATUS_RING_BASE_MSB_RING_SIZE,
    ),
    // CE_SRC
    tmpl(
        ring_id::CE0_SRC,
        12,
        words(size_of::<HalCeSrngSrcDesc>()),
        false,
        Src,
        HAL_CE_SRC_RING_BASE_MSB_RING_SIZE,
    ),
    // CE_DST — the host *produces* destination buffers: a SRC ring.
    tmpl(
        ring_id::CE0_DST,
        12,
        words(size_of::<HalCeSrngDestDesc>()),
        false,
        Src,
        HAL_CE_DST_RING_BASE_MSB_RING_SIZE,
    ),
    // CE_DST_STATUS
    tmpl(
        ring_id::CE0_DST_STATUS,
        12,
        words(size_of::<HalCeSrngDstStatusDesc>()),
        false,
        Dst,
        HAL_CE_DST_STATUS_RING_BASE_MSB_RING_SIZE,
    ),
    // WBM_IDLE_LINK
    tmpl(
        ring_id::WBM_IDLE_LINK,
        1,
        words(size_of::<dp::HalWbmLinkDesc>()),
        false,
        Src,
        HAL_WBM_IDLE_LINK_RING_BASE_MSB_RING_SIZE,
    ),
    // SW2WBM_RELEASE
    tmpl(
        ring_id::WBM_SW_RELEASE,
        1,
        words(size_of::<dp::HalWbmReleaseRing>()),
        false,
        Src,
        HAL_SW2WBM_RELEASE_RING_BASE_MSB_RING_SIZE,
    ),
    // WBM2SW_RELEASE
    tmpl(
        ring_id::WBM2SW0_RELEASE,
        5,
        words(size_of::<dp::HalWbmReleaseRing>()),
        false,
        Dst,
        HAL_WBM2SW_RELEASE_RING_BASE_MSB_RING_SIZE,
    ),
    // RXDMA_BUF
    tmpl(
        ring_id::WMAC1_SW2RXDMA0_BUF,
        2,
        words(size_of::<dp::HalWbmBufferRing>()),
        true,
        Src,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
    // RXDMA_DST
    tmpl(
        ring_id::WMAC1_RXDMA2SW0,
        1,
        words(size_of::<dp::HalReoEntranceRing>()),
        true,
        Dst,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
    // RXDMA_MONITOR_BUF
    tmpl(
        ring_id::WMAC1_SW2RXDMA2_BUF,
        1,
        words(size_of::<dp::HalWbmBufferRing>()),
        true,
        Src,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
    // RXDMA_MONITOR_STATUS
    tmpl(
        ring_id::WMAC1_SW2RXDMA1_STATBUF,
        1,
        words(size_of::<dp::HalWbmBufferRing>()),
        true,
        Src,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
    // RXDMA_MONITOR_DST
    tmpl(
        ring_id::WMAC1_RXDMA2SW1,
        1,
        words(size_of::<dp::HalReoEntranceRing>()),
        true,
        Dst,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
    // RXDMA_MONITOR_DESC
    tmpl(
        ring_id::WMAC1_SW2RXDMA1_DESC,
        1,
        words(size_of::<dp::HalWbmBufferRing>()),
        true,
        Src,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
    // RXDMA DIR BUF ("8 >> 2", no struct in Linux)
    tmpl(
        ring_id::RXDMA_DIR_BUF,
        2,
        8 >> 2,
        true,
        Src,
        HAL_RXDMA_RING_MAX_SIZE,
    ),
];

/// Linux `ath11k_hal_srng_create_config`: the template plus each
/// ring type's R0 / R2 register bases and per-ring strides.
pub fn create_config(r: &HalRegs) -> [SrngConfig; HAL_MAX_RING_TYPES] {
    use HalRingType as T;
    let mut c = SRNG_CONFIG_TEMPLATE;
    let reo = HAL_SEQ_WCSS_UMAC_REO_REG;
    let tcl = HAL_SEQ_WCSS_UMAC_TCL_REG;
    let wbm = HAL_SEQ_WCSS_UMAC_WBM_REG;
    let ce_off = ATH11K_CE_OFFSET_PCI;

    let s = &mut c[T::ReoDst.idx()];
    s.reg_start = [reo + r.hal_reo1_ring_base_lsb, reo + r.hal_reo1_ring_hp];
    s.reg_size = [
        (r.hal_reo2_ring_base_lsb - r.hal_reo1_ring_base_lsb) as u16,
        (r.hal_reo2_ring_hp - r.hal_reo1_ring_hp) as u16,
    ];

    c[T::ReoException.idx()].reg_start = [
        reo + r.hal_reo_tcl_ring_base_lsb,
        reo + r.hal_reo_tcl_ring_hp,
    ];
    c[T::ReoReinject.idx()].reg_start =
        [reo + r.hal_sw2reo_ring_base_lsb, reo + r.hal_sw2reo_ring_hp];
    c[T::ReoCmd.idx()].reg_start = [
        reo + r.hal_reo_cmd_ring_base_lsb,
        reo + r.hal_reo_cmd_ring_hp,
    ];
    c[T::ReoStatus.idx()].reg_start = [
        reo + r.hal_reo_status_ring_base_lsb,
        reo + r.hal_reo_status_hp,
    ];

    let s = &mut c[T::TclData.idx()];
    s.reg_start = [tcl + r.hal_tcl1_ring_base_lsb, tcl + HAL_TCL1_RING_HP];
    s.reg_size = [
        (r.hal_tcl2_ring_base_lsb - r.hal_tcl1_ring_base_lsb) as u16,
        (HAL_TCL2_RING_HP - HAL_TCL1_RING_HP) as u16,
    ];

    c[T::TclCmd.idx()].reg_start = [tcl + r.hal_tcl_ring_base_lsb, tcl + HAL_TCL_RING_HP];
    c[T::TclStatus.idx()].reg_start = [
        tcl + r.hal_tcl_status_ring_base_lsb,
        tcl + HAL_TCL_STATUS_RING_HP,
    ];

    let src_stride = (r.hal_seq_wcss_umac_ce1_src_reg - r.hal_seq_wcss_umac_ce0_src_reg) as u16;
    let dst_stride = (r.hal_seq_wcss_umac_ce1_dst_reg - r.hal_seq_wcss_umac_ce0_dst_reg) as u16;

    // Linux uses the *DST* R0/R2 offsets for the CE source ring too
    // (both are 0x0 / 0x400).
    let s = &mut c[T::CeSrc.idx()];
    s.reg_start = [
        r.hal_seq_wcss_umac_ce0_src_reg + HAL_CE_DST_RING_BASE_LSB + ce_off,
        r.hal_seq_wcss_umac_ce0_src_reg + HAL_CE_DST_RING_HP + ce_off,
    ];
    s.reg_size = [src_stride, src_stride];

    let s = &mut c[T::CeDst.idx()];
    s.reg_start = [
        r.hal_seq_wcss_umac_ce0_dst_reg + HAL_CE_DST_RING_BASE_LSB + ce_off,
        r.hal_seq_wcss_umac_ce0_dst_reg + HAL_CE_DST_RING_HP + ce_off,
    ];
    s.reg_size = [dst_stride, dst_stride];

    let s = &mut c[T::CeDstStatus.idx()];
    s.reg_start = [
        r.hal_seq_wcss_umac_ce0_dst_reg + HAL_CE_DST_STATUS_RING_BASE_LSB + ce_off,
        r.hal_seq_wcss_umac_ce0_dst_reg + HAL_CE_DST_STATUS_RING_HP + ce_off,
    ];
    s.reg_size = [dst_stride, dst_stride];

    c[T::WbmIdleLink.idx()].reg_start = [
        wbm + r.hal_wbm_idle_link_ring_base_lsb,
        wbm + HAL_WBM_IDLE_LINK_RING_HP,
    ];
    c[T::Sw2WbmRelease.idx()].reg_start = [
        wbm + r.hal_wbm_release_ring_base_lsb,
        wbm + HAL_WBM_RELEASE_RING_HP,
    ];

    let s = &mut c[T::Wbm2SwRelease.idx()];
    s.reg_start = [
        wbm + r.hal_wbm0_release_ring_base_lsb,
        wbm + HAL_WBM0_RELEASE_RING_HP,
    ];
    s.reg_size = [
        (r.hal_wbm1_release_ring_base_lsb - r.hal_wbm0_release_ring_base_lsb) as u16,
        (HAL_WBM1_RELEASE_RING_HP - HAL_WBM0_RELEASE_RING_HP) as u16,
    ];
    c
}

/// R0-relative offsets of the SRC (`HAL_TCL1_RING_*`) and DST
/// (`HAL_REO1_RING_*`) per-ring configuration registers — the
/// `*_OFFSET(ab)` macros of hal.h.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingRegOffsets {
    pub tcl_msi1_base_lsb: u32,
    pub tcl_msi1_base_msb: u32,
    pub tcl_msi1_data: u32,
    pub tcl_base_msb: u32,
    pub tcl_id: u32,
    pub tcl_consr_int_setup_ix0: u32,
    pub tcl_consr_int_setup_ix1: u32,
    pub tcl_tp_addr_lsb: u32,
    pub tcl_tp_addr_msb: u32,
    pub tcl_misc: u32,
    pub reo_msi1_base_lsb: u32,
    pub reo_msi1_base_msb: u32,
    pub reo_msi1_data: u32,
    pub reo_base_msb: u32,
    pub reo_id: u32,
    pub reo_producer_int_setup: u32,
    pub reo_hp_addr_lsb: u32,
    pub reo_hp_addr_msb: u32,
    pub reo_misc: u32,
    /// `HAL_REO1_RING_TP_OFFSET(ab)` (R2).
    pub reo_tp: u32,
}

impl RingRegOffsets {
    pub const fn new(r: &HalRegs) -> Self {
        let t = r.hal_tcl1_ring_base_lsb;
        let o = r.hal_reo1_ring_base_lsb;
        RingRegOffsets {
            tcl_msi1_base_lsb: r.hal_tcl1_ring_msi1_base_lsb - t,
            tcl_msi1_base_msb: r.hal_tcl1_ring_msi1_base_msb - t,
            tcl_msi1_data: r.hal_tcl1_ring_msi1_data - t,
            tcl_base_msb: r.hal_tcl1_ring_base_msb - t,
            tcl_id: r.hal_tcl1_ring_id - t,
            tcl_consr_int_setup_ix0: r.hal_tcl1_ring_consumer_int_setup_ix0 - t,
            tcl_consr_int_setup_ix1: r.hal_tcl1_ring_consumer_int_setup_ix1 - t,
            tcl_tp_addr_lsb: r.hal_tcl1_ring_tp_addr_lsb - t,
            tcl_tp_addr_msb: r.hal_tcl1_ring_tp_addr_msb - t,
            tcl_misc: r.hal_tcl1_ring_misc - t,
            reo_msi1_base_lsb: r.hal_reo1_ring_msi1_base_lsb - o,
            reo_msi1_base_msb: r.hal_reo1_ring_msi1_base_msb - o,
            reo_msi1_data: r.hal_reo1_ring_msi1_data - o,
            reo_base_msb: r.hal_reo1_ring_base_msb - o,
            reo_id: r.hal_reo1_ring_id - o,
            reo_producer_int_setup: r.hal_reo1_ring_producer_int_setup - o,
            reo_hp_addr_lsb: r.hal_reo1_ring_hp_addr_lsb - o,
            reo_hp_addr_msb: r.hal_reo1_ring_hp_addr_msb - o,
            reo_misc: r.hal_reo1_ring_misc - o,
            reo_tp: r.hal_reo1_ring_tp - r.hal_reo1_ring_hp,
        }
    }
}

/// Linux `ath11k_hal_srng_get_ring_id`.
pub fn get_ring_id(
    config: &[SrngConfig; HAL_MAX_RING_TYPES],
    ty: HalRingType,
    ring_num: u32,
    mac_id: u32,
) -> Result<u32, TransportError> {
    let c = &config[ty.idx()];
    if ring_num >= c.max_rings as u32 {
        return Err(TransportError::new(
            step::BAD_RING_NUM,
            ((ty as u32) << 16) | (ring_num & 0xffff),
            errno::EINVAL,
        ));
    }
    let mut id = c.start_ring_id + ring_num;
    if c.lmac_ring {
        id += mac_id * HAL_SRNG_RINGS_PER_LMAC;
    }
    if id >= HAL_SRNG_RING_ID_MAX {
        return Err(TransportError::new(step::RING_ID_RANGE, id, errno::EINVAL));
    }
    Ok(id)
}

// ── shadow registers v2 ───────────────────────────────────────────

/// `HAL_SHADOW_REG(ab, x)`: BAR0 offset of shadow register `x`.
pub const fn shadow_reg(regs: &HalRegs, idx: u32) -> u32 {
    regs.hal_shadow_base_addr + 4 * idx
}

/// The shadow-register v2 table: `hal->shadow_reg_addr[]` +
/// `num_shadow_reg_configured`, plus which ring each slot shadows.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShadowConfig {
    addr: [u32; HAL_SHADOW_NUM_REGS],
    ring: [(HalRingType, u32); HAL_SHADOW_NUM_REGS],
    len: usize,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        ShadowConfig {
            addr: [0; HAL_SHADOW_NUM_REGS],
            ring: [(HalRingType::ReoDst, 0); HAL_SHADOW_NUM_REGS],
            len: 0,
        }
    }
}

impl ShadowConfig {
    /// Linux `ath11k_hal_srng_update_shadow_config`: take the next
    /// shadow register for `(ty, ring_num)`; it shadows the ring's HP
    /// register (SRC) or TP register (DST). Returns the slot.
    pub fn update(
        &mut self,
        config: &[SrngConfig; HAL_MAX_RING_TYPES],
        ty: HalRingType,
        ring_num: u32,
    ) -> Result<usize, TransportError> {
        let idx = self.len;
        if idx >= HAL_SHADOW_NUM_REGS {
            return Err(TransportError::new(
                step::SHADOW_FULL,
                ((ty as u32) << 16) | (ring_num & 0xffff),
                errno::EINVAL,
            ));
        }
        self.len += 1;
        let c = &config[ty.idx()];
        let mut target = c.reg_start[HAL_HP_OFFSET_IN_REG_START];
        target += c.reg_size[HAL_HP_OFFSET_IN_REG_START] as u32 * ring_num;
        if c.ring_dir == SrngDir::Dst {
            target += HAL_OFFSET_FROM_HP_TO_TP;
        }
        self.addr[idx] = target;
        self.ring[idx] = (ty, ring_num);
        Ok(idx)
    }

    /// Linux `ath11k_hal_srng_shadow_config`: every non-CE, non-LMAC
    /// ring, in ring-type then ring-number order. Errors (table full)
    /// are ignored, as in Linux.
    pub fn hal_srng_shadow_config(&mut self, config: &[SrngConfig; HAL_MAX_RING_TYPES]) {
        for ty in HalRingType::ALL {
            if matches!(
                ty,
                HalRingType::CeSrc | HalRingType::CeDst | HalRingType::CeDstStatus
            ) {
                continue;
            }
            let c = &config[ty.idx()];
            if c.lmac_ring {
                continue;
            }
            for ring_num in 0..c.max_rings as u32 {
                let _ = self.update(config, ty, ring_num);
            }
        }
    }

    /// Linux `ath11k_ce_shadow_config` (ce.c): per CE, the source ring
    /// if it has one, then the destination + status rings.
    pub fn ce_shadow_config(
        &mut self,
        config: &[SrngConfig; HAL_MAX_RING_TYPES],
        host_ce_config: &[CeAttr],
    ) {
        for (i, attr) in host_ce_config.iter().enumerate() {
            if attr.src_nentries != 0 {
                let _ = self.update(config, HalRingType::CeSrc, i as u32);
            }
            if attr.dest_nentries != 0 {
                let _ = self.update(config, HalRingType::CeDst, i as u32);
                let _ = self.update(config, HalRingType::CeDstStatus, i as u32);
            }
        }
    }

    /// Linux `ath11k_hal_srng_get_shadow_config`: the target register
    /// addresses, in shadow-register order.
    pub fn as_slice(&self) -> &[u32] {
        &self.addr[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The shadow slot assigned to `(ty, ring_num)`, if any.
    pub fn slot_of(&self, ty: HalRingType, ring_num: u32) -> Option<usize> {
        self.ring[..self.len]
            .iter()
            .position(|&(t, n)| t == ty && n == ring_num)
    }

    /// `(ring type, ring number)` behind slot `idx`.
    pub fn ring_of(&self, idx: usize) -> Option<(HalRingType, u32)> {
        (idx < self.len).then(|| self.ring[idx])
    }
}

/// Linux `ath11k_ce_get_shadow_config` on a fresh HAL: the shadow
/// register v2 list the host sends in QMI `WLAN_CFG`
/// (`wlfw_wlan_cfg_req_msg_v01.shadow_reg_v2`), i.e. the HP/TP register
/// address each shadow register `0..len` mirrors. Non-CE rings first
/// (`ath11k_hal_srng_shadow_config`), then the CE rings of
/// `host_ce_config` (`ath11k_ce_shadow_config`).
///
/// `None` when the part does not use shadow registers
/// (`!supports_shadow_regs`: Linux leaves the list empty and sends
/// `shadow_reg_v2_valid = 0`) or has no HAL register map.
///
/// For WCN6855 HW2.1 this is the 30-entry list pinned in `hal_tests.rs`
/// (20 DP rings, then CE0 src, CE1 dst/status, CE2 dst/status, CE3 src,
/// CE4 src, CE5 dst/status, CE7 src).
pub fn shadow_reg_v2(hw: &HwParams) -> Option<ShadowConfig> {
    if !hw.supports_shadow_regs {
        return None;
    }
    let config = create_config(hw.regs?);
    let mut s = ShadowConfig::default();
    s.hal_srng_shadow_config(&config);
    s.ce_shadow_config(&config, hw.host_ce_config);
    Some(s)
}

// ── CE descriptors (hal_desc.h) ───────────────────────────────────

pub const HAL_CE_SRC_DESC_ADDR_INFO_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_CE_SRC_DESC_ADDR_INFO_HASH_EN: u32 = 1 << 8;
pub const HAL_CE_SRC_DESC_ADDR_INFO_BYTE_SWAP: u32 = 1 << 9;
pub const HAL_CE_SRC_DESC_ADDR_INFO_DEST_SWAP: u32 = 1 << 10;
pub const HAL_CE_SRC_DESC_ADDR_INFO_GATHER: u32 = 1 << 11;
pub const HAL_CE_SRC_DESC_ADDR_INFO_LEN: u32 = genmask(31, 16);
pub const HAL_CE_SRC_DESC_META_INFO_DATA: u32 = genmask(15, 0);
pub const HAL_CE_SRC_DESC_FLAGS_RING_ID: u32 = genmask(27, 20);
/// `HAL_SRNG_DESC_LOOP_CNT`.
pub const HAL_SRNG_DESC_LOOP_CNT: u32 = 0xf000_0000;
pub const HAL_CE_SRC_DESC_FLAGS_LOOP_CNT: u32 = HAL_SRNG_DESC_LOOP_CNT;

pub const HAL_CE_DEST_DESC_ADDR_INFO_ADDR_HI: u32 = genmask(7, 0);
pub const HAL_CE_DEST_DESC_ADDR_INFO_RING_ID: u32 = genmask(27, 20);
pub const HAL_CE_DEST_DESC_ADDR_INFO_LOOP_CNT: u32 = HAL_SRNG_DESC_LOOP_CNT;

pub const HAL_CE_DST_STATUS_DESC_FLAGS_HASH_EN: u32 = 1 << 8;
pub const HAL_CE_DST_STATUS_DESC_FLAGS_BYTE_SWAP: u32 = 1 << 9;
pub const HAL_CE_DST_STATUS_DESC_FLAGS_DEST_SWAP: u32 = 1 << 10;
pub const HAL_CE_DST_STATUS_DESC_FLAGS_GATHER: u32 = 1 << 11;
pub const HAL_CE_DST_STATUS_DESC_FLAGS_LEN: u32 = genmask(31, 16);
pub const HAL_CE_DST_STATUS_DESC_META_INFO_DATA: u32 = genmask(15, 0);
pub const HAL_CE_DST_STATUS_DESC_META_INFO_RING_ID: u32 = genmask(27, 20);
pub const HAL_CE_DST_STATUS_DESC_META_INFO_LOOP_CNT: u32 = HAL_SRNG_DESC_LOOP_CNT;

/// `struct hal_ce_srng_src_desc` (16 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalCeSrngSrcDesc {
    pub buffer_addr_low: u32,
    pub buffer_addr_info: u32,
    pub meta_info: u32,
    pub flags: u32,
}

/// `struct hal_ce_srng_dest_desc` (8 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalCeSrngDestDesc {
    pub buffer_addr_low: u32,
    pub buffer_addr_info: u32,
}

/// `struct hal_ce_srng_dst_status_desc` (16 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HalCeSrngDstStatusDesc {
    pub flags: u32,
    pub toeplitz_hash0: u32,
    pub toeplitz_hash1: u32,
    pub meta_info: u32,
}

const _: () = assert!(size_of::<HalCeSrngSrcDesc>() == 16);
const _: () = assert!(size_of::<HalCeSrngDestDesc>() == 8);
const _: () = assert!(size_of::<HalCeSrngDstStatusDesc>() == 16);

/// `enum hal_ce_desc`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HalCeDesc {
    Src,
    Dst,
    DstStatus,
}

/// Linux `ath11k_hal_ce_get_desc_size` (bytes).
pub const fn ce_get_desc_size(ty: HalCeDesc) -> usize {
    match ty {
        HalCeDesc::Src => size_of::<HalCeSrngSrcDesc>(),
        HalCeDesc::Dst => size_of::<HalCeSrngDestDesc>(),
        HalCeDesc::DstStatus => size_of::<HalCeSrngDstStatusDesc>(),
    }
}

/// The three words `ath11k_hal_ce_src_set_desc` writes
/// (`buffer_addr_low`, `buffer_addr_info`, `meta_info`; `flags` is left
/// as is).
pub const fn ce_src_desc_words(paddr: u64, len: u32, id: u32, byte_swap_data: u8) -> [u32; 3] {
    [
        (paddr & HAL_ADDR_LSB_REG_MASK) as u32,
        field_prep(
            HAL_CE_SRC_DESC_ADDR_INFO_ADDR_HI,
            (paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        ) | field_prep(HAL_CE_SRC_DESC_ADDR_INFO_BYTE_SWAP, byte_swap_data as u32)
            | field_prep(HAL_CE_SRC_DESC_ADDR_INFO_GATHER, 0)
            | field_prep(HAL_CE_SRC_DESC_ADDR_INFO_LEN, len),
        field_prep(HAL_CE_SRC_DESC_META_INFO_DATA, id),
    ]
}

/// The two words `ath11k_hal_ce_dst_set_desc` writes.
pub const fn ce_dst_desc_words(paddr: u64) -> [u32; 2] {
    [
        (paddr & HAL_ADDR_LSB_REG_MASK) as u32,
        field_prep(
            HAL_CE_DEST_DESC_ADDR_INFO_ADDR_HI,
            (paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        ),
    ]
}

// ── DMA memory ────────────────────────────────────────────────────

/// `ATH11K_PCI_COHERENT_DMA_MASK` = `DMA_BIT_MASK(32)`.
pub const ATH11K_COHERENT_DMA_MASK: u64 = 0xffff_ffff;
const DMA_DOMAIN: DomainId = DomainId::DRIVER_0;

/// A coherent DMA32 region with volatile little-endian word access;
/// `paddr()` is aligned to the requested alignment
/// (`PTR_ALIGN` / `ALIGN` in `ath11k_ce_alloc_ring`).
#[derive(Debug)]
pub struct DmaMem {
    buf: DmaBuffer,
    off: usize,
    len: usize,
}

impl DmaMem {
    /// `dma_alloc_coherent(len + align)` then align, as Linux does.
    pub fn alloc(len: usize, align: usize) -> Result<DmaMem, TransportError> {
        let align = align.max(1);
        let total = len + if align > 1 { align } else { 0 };
        let buf =
            narf_io::alloc_coherent_masked(total.max(1), DMA_DOMAIN, ATH11K_COHERENT_DMA_MASK)
                .map_err(|_| {
                    TransportError::new(step::NO_DMA_MEMORY, total as u32, errno::ENOMEM)
                })?;
        let raw = buf.dma_addr().raw();
        let aligned = (raw + (align as u64 - 1)) & !(align as u64 - 1);
        let off = (aligned - raw) as usize;
        let mem = DmaMem { buf, off, len };
        mem.zero();
        Ok(mem)
    }

    /// Device address of the (aligned) start.
    pub fn paddr(&self) -> u64 {
        self.buf.dma_addr().raw() + self.off as u64
    }

    /// Usable length in bytes (after alignment).
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read word `idx` (volatile, little-endian).
    pub fn rd32(&self, idx: usize) -> u32 {
        let off = self.off + idx * 4;
        assert!(idx * 4 + 4 <= self.len, "ath11k DmaMem read out of range");
        // SAFETY: in bounds (asserted) and 4-aligned (the buffer is
        // page aligned and `off` a multiple of the 8-byte alignment);
        // the buffer is a live kernel-mapped coherent allocation owned
        // by `self`.
        u32::from_le(unsafe { core::ptr::read_volatile(self.buf.cpu_ptr_at::<u32>(off as u64)) })
    }

    /// Write word `idx` (volatile, little-endian).
    pub fn wr32(&self, idx: usize, v: u32) {
        let off = self.off + idx * 4;
        assert!(idx * 4 + 4 <= self.len, "ath11k DmaMem write out of range");
        // SAFETY: as `rd32`; concurrent device access to coherent memory
        // is word-atomic and the protocol never has both sides write the
        // same word.
        unsafe { core::ptr::write_volatile(self.buf.cpu_mut_ptr_at::<u32>(off as u64), v.to_le()) }
    }

    /// Copy `dst.len()` bytes starting at byte `off`.
    pub fn read_bytes(&self, off: usize, dst: &mut [u8]) {
        assert!(
            off + dst.len() <= self.len,
            "ath11k DmaMem read out of range"
        );
        dst.copy_from_slice(&self.buf.as_slice()[self.off + off..self.off + off + dst.len()]);
    }

    /// Copy `src` in at byte `off`.
    pub fn write_bytes(&mut self, off: usize, src: &[u8]) {
        assert!(
            off + src.len() <= self.len,
            "ath11k DmaMem write out of range"
        );
        let o = self.off + off;
        self.buf.as_mut_slice()[o..o + src.len()].copy_from_slice(src);
    }

    /// `memset(.., 0, len)`.
    pub fn zero(&self) {
        for i in 0..self.len / 4 {
            self.wr32(i, 0);
        }
    }
}

/// `dma_rmb()`.
pub fn dma_rmb() {
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::Acquire);
    compiler_fence(Ordering::SeqCst);
}

/// `dma_wmb()`.
pub fn dma_wmb() {
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::Release);
    compiler_fence(Ordering::SeqCst);
}

/// `mb()` / `dma_mb()`.
pub fn dma_mb() {
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

// ── SRNG state ────────────────────────────────────────────────────

/// `struct hal_srng_params`.
#[derive(Debug)]
pub struct SrngParams {
    /// Ring memory (`ring_base_paddr` / `ring_base_vaddr`).
    pub ring: DmaMem,
    pub num_entries: u32,
    pub intr_batch_cntr_thres_entries: u32,
    pub intr_timer_thres_us: u32,
    pub flags: u32,
    pub max_buffer_len: u32,
    pub low_threshold: u32,
    pub msi_addr: u64,
    pub msi_data: u32,
}

impl SrngParams {
    pub fn new(ring: DmaMem, num_entries: u32) -> Self {
        SrngParams {
            ring,
            num_entries,
            intr_batch_cntr_thres_entries: 0,
            intr_timer_thres_us: 0,
            flags: 0,
            max_buffer_len: 0,
            low_threshold: 0,
            msi_addr: 0,
            msi_data: 0,
        }
    }
}

/// Where software publishes its ring pointer (SRC: HP, DST: TP) —
/// `srng->u.*.hp_addr` / `tp_addr` on the host-written side.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SwPtr {
    /// A BAR0 register: the ring's own R2 register, or its shadow.
    Reg(u32),
    /// LMAC ring: word index into the `wrp` area firmware reads.
    Wrp(u32),
}

/// `struct hal_srng`.
#[derive(Debug)]
pub struct Srng {
    pub ring_id: u32,
    pub ring_type: HalRingType,
    pub ring_num: u32,
    pub ring_dir: SrngDir,
    mem: DmaMem,
    pub ring_base_paddr: u64,
    pub num_entries: u32,
    /// Words.
    pub ring_size: u32,
    /// Words.
    pub entry_size: u32,
    pub intr_timer_thres_us: u32,
    pub intr_batch_cntr_thres_entries: u32,
    pub msi_addr: u64,
    pub msi_data: u32,
    pub flags: u32,
    pub hwreg_base: [u32; HAL_SRNG_NUM_REG_GRP],
    // src_ring
    pub hp: u32,
    pub reap_hp: u32,
    pub cached_tp: u32,
    /// Words (`params->low_threshold * entry_size`).
    pub low_threshold: u32,
    pub last_tp: u32,
    // dst_ring
    pub tp: u32,
    pub cached_hp: u32,
    pub loop_cnt: u32,
    pub max_buffer_length: u16,
    pub last_hp: u32,
    /// `rdp` word holding the hardware-written pointer (SRC: TP, DST:
    /// HP): `rdp.vaddr + ring_id`.
    pub hw_ptr_idx: u32,
    /// Software-written pointer location.
    pub sw_ptr: SwPtr,
    /// `access_end` calls (Linux `srng->timestamp`, as a count).
    pub access_ends: u64,
}

impl Srng {
    /// Byte offset of word `off` in the ring.
    pub fn desc_paddr(&self, off: u32) -> u64 {
        self.ring_base_paddr + off as u64 * 4
    }
}

/// HAL context: `struct ath11k_hal`.
#[derive(Debug)]
pub struct Hal {
    pub regs: &'static HalRegs,
    pub offs: RingRegOffsets,
    pub config: [SrngConfig; HAL_MAX_RING_TYPES],
    /// Remote pointer memory for HW/FW updates (`HAL_SRNG_RING_ID_MAX`
    /// words).
    pub rdp: DmaMem,
    /// Host → FW pointer memory for LMAC rings
    /// (`HAL_SRNG_NUM_LMAC_RINGS` words).
    pub wrp: DmaMem,
    srngs: Vec<Option<Srng>>,
    pub shadow: ShadowConfig,
    pub supports_shadow_regs: bool,
}

impl Hal {
    /// Linux `ath11k_hal_srng_init` (+ `ath11k_ce_get_shadow_config`
    /// when the part uses shadow registers, so ring setup finds each
    /// ring's shadow HP/TP register — Linux does both at probe).
    pub fn new(hw: &HwParams) -> Result<Hal, TransportError> {
        let regs = hw
            .regs
            .ok_or(TransportError::new(step::NO_REGS, 0, errno::EINVAL))?;
        let config = create_config(regs);
        let rdp = DmaMem::alloc(4 * HAL_SRNG_RING_ID_MAX as usize, 1)?;
        let wrp = DmaMem::alloc(4 * HAL_SRNG_NUM_LMAC_RINGS as usize, 1)?;
        let mut srngs = Vec::new();
        srngs.resize_with(HAL_SRNG_RING_ID_MAX as usize, || None);
        let shadow = shadow_reg_v2(hw).unwrap_or_default();
        Ok(Hal {
            regs,
            offs: RingRegOffsets::new(regs),
            config,
            rdp,
            wrp,
            srngs,
            shadow,
            supports_shadow_regs: hw.supports_shadow_regs,
        })
    }

    /// Linux `ath11k_hal_srng_get_shadow_config`.
    pub fn shadow_reg_v2(&self) -> &[u32] {
        self.shadow.as_slice()
    }

    /// Linux `ath11k_hal_srng_get_entrysize` (bytes).
    pub fn entry_size_bytes(&self, ty: HalRingType) -> u32 {
        (self.config[ty.idx()].entry_size as u32) << 2
    }

    /// Linux `ath11k_hal_srng_get_max_entries`.
    pub fn max_entries(&self, ty: HalRingType) -> u32 {
        let c = &self.config[ty.idx()];
        c.max_size / c.entry_size as u32
    }

    pub fn srng(&self, id: u32) -> Option<&Srng> {
        self.srngs.get(id as usize).and_then(|s| s.as_ref())
    }

    /// Ring memory of `id` (for descriptor access).
    pub fn ring_mem(&self, id: u32) -> Option<&DmaMem> {
        self.srng(id).map(|s| &s.mem)
    }

    /// Ids of the rings set up now.
    pub fn srng_ids(&self) -> Vec<u32> {
        self.srngs
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i as u32)
            .collect()
    }

    /// The ring's owner gives it up (`ath11k_dp_srng_cleanup` frees the
    /// memory; a CE keeps it for the next `ath11k_ce_init_ring`): the ring
    /// leaves the HAL and its memory goes back to the caller. The ring
    /// registers are not touched (Linux's cleanup does not either); only
    /// call this once the hardware no longer uses the ring — after a
    /// device reset, or before the ring was ever handed to the firmware.
    pub fn srng_free(&mut self, id: u32) -> Option<DmaMem> {
        self.srngs.get_mut(id as usize)?.take().map(|s| s.mem)
    }

    /// Linux `ath11k_hal_srng_clear` (crash recovery): forget every ring so
    /// each can be set up again. Memory of rings still listed is dropped
    /// (their owners released theirs first: DP with [`Self::srng_free`],
    /// CE with `Ce::cleanup_pipes`). As Linux, the `rdp` / `wrp` words are
    /// not cleared (ring setup zeroes each one) and the shadow register
    /// list is kept (`ath11k_ce_get_shadow_config` rebuilds the same one).
    pub fn srng_clear(&mut self) -> usize {
        let mut n = 0;
        for s in self.srngs.iter_mut() {
            if s.take().is_some() {
                n += 1;
            }
        }
        n
    }

    fn srng_mut(&mut self, id: u32) -> Option<&mut Srng> {
        self.srngs.get_mut(id as usize).and_then(|s| s.as_mut())
    }

    /// Shadow register offset `update_hp_tp_addr` gave this ring.
    fn shadow_ptr(&self, ty: HalRingType, ring_num: u32) -> Option<u32> {
        self.shadow
            .slot_of(ty, ring_num)
            .map(|i| shadow_reg(self.regs, i as u32))
    }

    /// Linux `ath11k_hal_srng_setup`. Takes ownership of the ring
    /// memory; returns the ring id.
    ///
    /// NARF-stricter than Linux: rejects a ring whose memory is smaller
    /// than `entry_size * num_entries`, zero entries or more than the
    /// type's `max_size`, a second setup of the same ring id, and a
    /// shadow-register part where this ring got no shadow register
    /// (Linux would dereference NULL).
    pub fn srng_setup(
        &mut self,
        io: &impl ChipIo,
        ty: HalRingType,
        ring_num: u32,
        mac_id: u32,
        params: SrngParams,
    ) -> Result<u32, TransportError> {
        let cfg = self.config[ty.idx()];
        let id = get_ring_id(&self.config, ty, ring_num, mac_id)?;
        let entry_size = cfg.entry_size as u32;
        let ring_size = entry_size.saturating_mul(params.num_entries);
        if params.num_entries == 0 || ring_size > cfg.max_size {
            return Err(TransportError::new(
                step::BAD_RING_SIZE,
                ((ty as u32) << 16) | (params.num_entries & 0xffff),
                errno::EINVAL,
            ));
        }
        if (params.ring.len() as u64) < ring_size as u64 * 4 {
            return Err(TransportError::new(step::RING_MEM_SIZE, id, errno::EINVAL));
        }
        if self.srng(id).is_some() {
            return Err(TransportError::new(step::RING_IN_USE, id, errno::EINVAL));
        }

        let mut hwreg_base = [0u32; HAL_SRNG_NUM_REG_GRP];
        for (i, b) in hwreg_base.iter_mut().enumerate() {
            *b = cfg.reg_start[i] + ring_num * cfg.reg_size[i] as u32;
        }
        let r2 = hwreg_base[HAL_SRNG_REG_GRP_R2];
        let mut srng_flags = params.flags;

        let sw_ptr = if cfg.lmac_ring {
            srng_flags |= flags::LMAC_RING;
            SwPtr::Wrp(id - ring_id::LMAC1_ID_START)
        } else if !self.supports_shadow_regs {
            match cfg.ring_dir {
                SrngDir::Src => SwPtr::Reg(r2),
                SrngDir::Dst => SwPtr::Reg(r2 + self.offs.reo_tp),
            }
        } else {
            match self.shadow_ptr(ty, ring_num) {
                Some(reg) => SwPtr::Reg(reg),
                None => return Err(TransportError::new(step::NO_SHADOW_REG, id, errno::EINVAL)),
            }
        };

        // memset(ring_base_vaddr, 0, entry_size * num_entries * 4)
        for i in 0..ring_size as usize {
            params.ring.wr32(i, 0);
        }

        let ring_base_paddr = params.ring.paddr();
        let srng = Srng {
            ring_id: id,
            ring_type: ty,
            ring_num,
            ring_dir: cfg.ring_dir,
            mem: params.ring,
            ring_base_paddr,
            num_entries: params.num_entries,
            ring_size,
            entry_size,
            intr_timer_thres_us: params.intr_timer_thres_us,
            intr_batch_cntr_thres_entries: params.intr_batch_cntr_thres_entries,
            msi_addr: params.msi_addr,
            msi_data: params.msi_data,
            flags: srng_flags,
            hwreg_base,
            hp: 0,
            reap_hp: ring_size - entry_size,
            cached_tp: 0,
            low_threshold: params.low_threshold * entry_size,
            last_tp: 0,
            tp: 0,
            cached_hp: 0,
            loop_cnt: 1,
            max_buffer_length: 0,
            last_hp: 0,
            hw_ptr_idx: id,
            sw_ptr,
            access_ends: 0,
        };
        self.srngs[id as usize] = Some(srng);

        if cfg.lmac_ring {
            return Ok(id);
        }

        self.hw_init(io, id);

        if ty == HalRingType::CeDst {
            if let Some(s) = self.srng_mut(id) {
                s.max_buffer_length = params.max_buffer_len as u16;
            }
            self.ce_dst_setup(io, ring_num, params.max_buffer_len as u16);
        }
        Ok(id)
    }

    /// Linux `ath11k_hal_srng_hw_init`.
    fn hw_init(&mut self, io: &impl ChipIo, id: u32) {
        let dir = match self.srng(id) {
            Some(s) => s.ring_dir,
            None => return,
        };
        match dir {
            SrngDir::Src => self.src_hw_init(io, id),
            SrngDir::Dst => self.dst_hw_init(io, id),
        }
    }

    /// Linux `ath11k_hal_srng_src_hw_init`.
    fn src_hw_init(&mut self, io: &impl ChipIo, id: u32) {
        let o = self.offs;
        let rdp_paddr = self.rdp.paddr();
        let Some(s) = self.srng(id) else { return };
        let reg_base = s.hwreg_base[HAL_SRNG_REG_GRP_R0];

        if s.flags & flags::MSI_INTR != 0 {
            io.write32(reg_base + o.tcl_msi1_base_lsb, s.msi_addr as u32);
            let val = field_prep(
                HAL_TCL1_RING_MSI1_BASE_MSB_ADDR,
                (s.msi_addr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
            ) | HAL_TCL1_RING_MSI1_BASE_MSB_MSI1_ENABLE;
            io.write32(reg_base + o.tcl_msi1_base_msb, val);
            io.write32(reg_base + o.tcl_msi1_data, s.msi_data);
        }

        io.write32(reg_base, s.ring_base_paddr as u32);
        let base_msb = field_prep(
            HAL_TCL1_RING_BASE_MSB_RING_BASE_ADDR_MSB,
            (s.ring_base_paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        ) | field_prep(
            HAL_TCL1_RING_BASE_MSB_RING_SIZE,
            s.entry_size * s.num_entries,
        );
        io.write32(reg_base + o.tcl_base_msb, base_msb);

        io.write32(
            reg_base + o.tcl_id,
            field_prep(HAL_REO1_RING_ID_ENTRY_SIZE, s.entry_size),
        );

        if s.ring_id == ring_id::WBM_IDLE_LINK {
            io.write32(reg_base, s.ring_base_paddr as u32);
            io.write32(reg_base + o.tcl_base_msb, base_msb);
        }

        // interrupt setup (timer threshold in µs, not >> 3, for SRC rings)
        let val = field_prep(
            HAL_TCL1_RING_CONSR_INT_SETUP_IX0_INTR_TMR_THOLD,
            s.intr_timer_thres_us,
        ) | field_prep(
            HAL_TCL1_RING_CONSR_INT_SETUP_IX0_BATCH_COUNTER_THOLD,
            s.intr_batch_cntr_thres_entries * s.entry_size,
        );
        io.write32(reg_base + o.tcl_consr_int_setup_ix0, val);

        let mut val = 0;
        if s.flags & flags::LOW_THRESH_INTR_EN != 0 {
            val |= field_prep(HAL_TCL1_RING_CONSR_INT_SETUP_IX1_LOW_THOLD, s.low_threshold);
        }
        io.write32(reg_base + o.tcl_consr_int_setup_ix1, val);

        if s.ring_id != ring_id::WBM_IDLE_LINK {
            let tp_addr = rdp_paddr + s.hw_ptr_idx as u64 * 4;
            io.write32(
                reg_base + o.tcl_tp_addr_lsb,
                (tp_addr & HAL_ADDR_LSB_REG_MASK) as u32,
            );
            io.write32(
                reg_base + o.tcl_tp_addr_msb,
                (tp_addr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
            );
        }

        // Initialise head and tail pointers to indicate an empty ring.
        let r2 = s.hwreg_base[HAL_SRNG_REG_GRP_R2];
        io.write32(r2, 0);
        io.write32(r2 + HAL_TCL1_RING_TP_OFFSET, 0);
        self.rdp.wr32(s.hw_ptr_idx as usize, 0);

        let mut val = 0;
        if s.flags & flags::DATA_TLV_SWAP != 0 {
            val |= HAL_TCL1_RING_MISC_DATA_TLV_SWAP;
        }
        if s.flags & flags::RING_PTR_SWAP != 0 {
            val |= HAL_TCL1_RING_MISC_HOST_FW_SWAP;
        }
        if s.flags & flags::MSI_SWAP != 0 {
            val |= HAL_TCL1_RING_MISC_MSI_SWAP;
        }
        // Loop count is not used for SRC rings.
        val |= HAL_TCL1_RING_MISC_MSI_LOOPCNT_DISABLE;
        val |= HAL_TCL1_RING_MISC_SRNG_ENABLE;
        io.write32(reg_base + o.tcl_misc, val);
    }

    /// Linux `ath11k_hal_srng_dst_hw_init`.
    fn dst_hw_init(&mut self, io: &impl ChipIo, id: u32) {
        let o = self.offs;
        let rdp_paddr = self.rdp.paddr();
        let Some(s) = self.srng(id) else { return };
        let reg_base = s.hwreg_base[HAL_SRNG_REG_GRP_R0];

        if s.flags & flags::MSI_INTR != 0 {
            io.write32(reg_base + o.reo_msi1_base_lsb, s.msi_addr as u32);
            let val = field_prep(
                HAL_REO1_RING_MSI1_BASE_MSB_ADDR,
                (s.msi_addr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
            ) | HAL_REO1_RING_MSI1_BASE_MSB_MSI1_ENABLE;
            io.write32(reg_base + o.reo_msi1_base_msb, val);
            io.write32(reg_base + o.reo_msi1_data, s.msi_data);
        }

        io.write32(reg_base, s.ring_base_paddr as u32);
        let val = field_prep(
            HAL_REO1_RING_BASE_MSB_RING_BASE_ADDR_MSB,
            (s.ring_base_paddr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        ) | field_prep(
            HAL_REO1_RING_BASE_MSB_RING_SIZE,
            s.entry_size * s.num_entries,
        );
        io.write32(reg_base + o.reo_base_msb, val);

        let val = field_prep(HAL_REO1_RING_ID_RING_ID, s.ring_id)
            | field_prep(HAL_REO1_RING_ID_ENTRY_SIZE, s.entry_size);
        io.write32(reg_base + o.reo_id, val);

        // interrupt setup: DST timer threshold in units of 8 µs
        let val = field_prep(
            HAL_REO1_RING_PRDR_INT_SETUP_INTR_TMR_THOLD,
            s.intr_timer_thres_us >> 3,
        ) | field_prep(
            HAL_REO1_RING_PRDR_INT_SETUP_BATCH_COUNTER_THOLD,
            s.intr_batch_cntr_thres_entries * s.entry_size,
        );
        io.write32(reg_base + o.reo_producer_int_setup, val);

        let hp_addr = rdp_paddr + s.hw_ptr_idx as u64 * 4;
        io.write32(
            reg_base + o.reo_hp_addr_lsb,
            (hp_addr & HAL_ADDR_LSB_REG_MASK) as u32,
        );
        io.write32(
            reg_base + o.reo_hp_addr_msb,
            (hp_addr >> HAL_ADDR_MSB_REG_SHIFT) as u32,
        );

        // Initialise head and tail pointers to indicate an empty ring.
        let r2 = s.hwreg_base[HAL_SRNG_REG_GRP_R2];
        io.write32(r2, 0);
        io.write32(r2 + o.reo_tp, 0);
        self.rdp.wr32(s.hw_ptr_idx as usize, 0);

        let mut val = 0;
        if s.flags & flags::DATA_TLV_SWAP != 0 {
            val |= HAL_REO1_RING_MISC_DATA_TLV_SWAP;
        }
        if s.flags & flags::RING_PTR_SWAP != 0 {
            val |= HAL_REO1_RING_MISC_HOST_FW_SWAP;
        }
        if s.flags & flags::MSI_SWAP != 0 {
            val |= HAL_REO1_RING_MISC_MSI_SWAP;
        }
        val |= HAL_REO1_RING_MISC_SRNG_ENABLE;
        io.write32(reg_base + o.reo_misc, val);
    }

    /// Linux `ath11k_hal_ce_dst_setup`: program the destination ring's
    /// maximum buffer length (read-modify-write of `DEST_CTRL`).
    fn ce_dst_setup(&self, io: &impl ChipIo, ring_num: u32, max_buffer_length: u16) {
        let c = &self.config[HalRingType::CeDst.idx()];
        let addr = HAL_CE_DST_RING_CTRL
            + c.reg_start[HAL_SRNG_REG_GRP_R0]
            + ring_num * c.reg_size[HAL_SRNG_REG_GRP_R0] as u32;
        let mut val = io.read32(addr);
        val &= !HAL_CE_DST_R0_DEST_CTRL_MAX_LEN;
        val |= field_prep(HAL_CE_DST_R0_DEST_CTRL_MAX_LEN, max_buffer_length as u32);
        io.write32(addr, val);
    }

    // ── ring access ───────────────────────────────────────────────

    /// Linux `ath11k_hal_srng_access_begin`.
    pub fn access_begin(&mut self, id: u32) {
        let hw = match self.srng(id) {
            Some(s) => self.rdp.rd32(s.hw_ptr_idx as usize),
            None => return,
        };
        let Some(s) = self.srng_mut(id) else { return };
        match s.ring_dir {
            SrngDir::Src => s.cached_tp = hw,
            SrngDir::Dst => {
                if hw != s.cached_hp {
                    s.cached_hp = hw;
                    // Read descriptors only after the head pointer.
                    dma_rmb();
                }
            }
        }
    }

    /// Linux `ath11k_hal_srng_access_end`: publish the cached
    /// HP (SRC) / TP (DST) to the hardware (register / shadow) or, for
    /// LMAC rings, to firmware through `wrp`.
    pub fn access_end(&mut self, io: &impl ChipIo, id: u32) {
        let hw = match self.srng(id) {
            Some(s) => self.rdp.rd32(s.hw_ptr_idx as usize),
            None => return,
        };
        let Some(s) = self.srngs.get_mut(id as usize).and_then(|s| s.as_mut()) else {
            return;
        };
        let (val, dir) = match s.ring_dir {
            SrngDir::Src => {
                s.last_tp = hw;
                (s.hp, SrngDir::Src)
            }
            SrngDir::Dst => {
                s.last_hp = hw;
                (s.tp, SrngDir::Dst)
            }
        };
        s.access_ends += 1;
        match (s.sw_ptr, dir) {
            (SwPtr::Wrp(idx), SrngDir::Src) => {
                // Descriptor written before the head pointer.
                dma_wmb();
                self.wrp.wr32(idx as usize, val);
            }
            (SwPtr::Wrp(idx), SrngDir::Dst) => {
                dma_mb();
                self.wrp.wr32(idx as usize, val);
            }
            (SwPtr::Reg(reg), SrngDir::Src) => {
                // The MMIO write accessor orders the descriptor writes.
                dma_wmb();
                io.write32(reg, val);
            }
            (SwPtr::Reg(reg), SrngDir::Dst) => {
                // Descriptor read before the tail pointer moves.
                dma_mb();
                io.write32(reg, val);
            }
        }
    }

    /// Linux `ath11k_hal_srng_src_num_free`.
    pub fn src_num_free(&mut self, id: u32, sync_hw_ptr: bool) -> u32 {
        let hw = match self.srng(id) {
            Some(s) => self.rdp.rd32(s.hw_ptr_idx as usize),
            None => return 0,
        };
        let Some(s) = self.srng_mut(id) else { return 0 };
        let hp = s.hp;
        let tp = if sync_hw_ptr {
            s.cached_tp = hw;
            hw
        } else {
            s.cached_tp
        };
        // Linux computes this in `int`; a TP that is not a multiple of
        // entry_size cannot come from the hardware.
        let n = if tp > hp {
            (tp - hp) / s.entry_size
        } else {
            (s.ring_size - hp + tp) / s.entry_size
        };
        n.saturating_sub(1)
    }

    /// Linux `ath11k_hal_srng_dst_num_free` (entries ready to consume).
    pub fn dst_num_free(&mut self, id: u32, sync_hw_ptr: bool) -> u32 {
        let hw = match self.srng(id) {
            Some(s) => self.rdp.rd32(s.hw_ptr_idx as usize),
            None => return 0,
        };
        let Some(s) = self.srng_mut(id) else { return 0 };
        let tp = s.tp;
        let hp = if sync_hw_ptr {
            s.cached_hp = hw;
            hw
        } else {
            s.cached_hp
        };
        if hp >= tp {
            (hp - tp) / s.entry_size
        } else {
            (s.ring_size - tp + hp) / s.entry_size
        }
    }

    /// Linux `ath11k_hal_srng_src_get_next_entry`: word offset of the
    /// next free entry, advancing HP (and `reap_hp`).
    pub fn src_get_next_entry(&mut self, id: u32) -> Option<u32> {
        let s = self.srng_mut(id)?;
        let next_hp = (s.hp + s.entry_size) % s.ring_size;
        if next_hp == s.cached_tp {
            return None;
        }
        let desc = s.hp;
        s.hp = next_hp;
        s.reap_hp = next_hp;
        Some(desc)
    }

    /// Linux `ath11k_hal_srng_src_reap_next`.
    pub fn src_reap_next(&mut self, id: u32) -> Option<u32> {
        let s = self.srng_mut(id)?;
        let next_reap_hp = (s.reap_hp + s.entry_size) % s.ring_size;
        if next_reap_hp == s.cached_tp {
            return None;
        }
        s.reap_hp = next_reap_hp;
        Some(next_reap_hp)
    }

    /// Linux `ath11k_hal_srng_src_get_next_reaped`.
    pub fn src_get_next_reaped(&mut self, id: u32) -> Option<u32> {
        let s = self.srng_mut(id)?;
        if s.hp == s.reap_hp {
            return None;
        }
        let desc = s.hp;
        s.hp = (s.hp + s.entry_size) % s.ring_size;
        Some(desc)
    }

    /// Linux `ath11k_hal_srng_src_next_peek`.
    pub fn src_next_peek(&self, id: u32) -> Option<u32> {
        let s = self.srng(id)?;
        let next_hp = (s.hp + s.entry_size) % s.ring_size;
        (next_hp != s.cached_tp).then_some(next_hp)
    }

    /// Linux `ath11k_hal_srng_src_peek`.
    pub fn src_peek(&self, id: u32) -> Option<u32> {
        let s = self.srng(id)?;
        if (s.hp + s.entry_size) % s.ring_size == s.cached_tp {
            return None;
        }
        Some(s.hp)
    }

    /// Linux `ath11k_hal_srng_dst_peek`.
    pub fn dst_peek(&self, id: u32) -> Option<u32> {
        let s = self.srng(id)?;
        (s.tp != s.cached_hp).then_some(s.tp)
    }

    /// Linux `ath11k_hal_srng_dst_get_next_entry`.
    pub fn dst_get_next_entry(&mut self, id: u32) -> Option<u32> {
        let s = self.srng_mut(id)?;
        if s.tp == s.cached_hp {
            return None;
        }
        let desc = s.tp;
        s.tp += s.entry_size;
        if s.tp == s.ring_size {
            s.tp = 0;
        }
        Some(desc)
    }

    /// Read descriptor word `i` of the entry at word offset `off`.
    pub fn desc_rd(&self, id: u32, off: u32, i: u32) -> u32 {
        match self.srng(id) {
            Some(s) => s.mem.rd32((off + i) as usize),
            None => 0,
        }
    }

    /// Write descriptor words starting at entry word offset `off`.
    pub fn desc_wr(&self, id: u32, off: u32, words: &[u32]) {
        if let Some(s) = self.srng(id) {
            for (i, &w) in words.iter().enumerate() {
                s.mem.wr32(off as usize + i, w);
            }
        }
    }

    /// Linux `ath11k_hal_ce_src_set_desc` on the entry at `off`.
    pub fn ce_src_set_desc(
        &self,
        id: u32,
        off: u32,
        paddr: u64,
        len: u32,
        transfer_id: u32,
        byte_swap_data: u8,
    ) {
        self.desc_wr(
            id,
            off,
            &ce_src_desc_words(paddr, len, transfer_id, byte_swap_data),
        );
    }

    /// Linux `ath11k_hal_ce_dst_set_desc` on the entry at `off`.
    pub fn ce_dst_set_desc(&self, id: u32, off: u32, paddr: u64) {
        self.desc_wr(id, off, &ce_dst_desc_words(paddr));
    }

    /// Linux `ath11k_hal_ce_dst_status_get_length`: the length field,
    /// cleared in the descriptor afterwards (so a stale entry reads 0).
    pub fn ce_dst_status_get_length(&self, id: u32, off: u32) -> u32 {
        let flags = self.desc_rd(id, off, 0);
        let len = field_get(HAL_CE_DST_STATUS_DESC_FLAGS_LEN, flags);
        self.desc_wr(id, off, &[flags & !HAL_CE_DST_STATUS_DESC_FLAGS_LEN]);
        len
    }

    /// Linux `ath11k_hal_srng_shadow_update_hp_tp`: re-publish a SRC
    /// ring's HP if the hardware has not consumed up to it.
    pub fn shadow_update_hp_tp(&mut self, io: &impl ChipIo, id: u32) {
        let pending = match self.srng(id) {
            Some(s) => s.ring_dir == SrngDir::Src && self.rdp.rd32(s.hw_ptr_idx as usize) != s.hp,
            None => false,
        };
        if pending {
            self.access_end(io, id);
        }
    }

    /// Linux `ath11k_hal_srng_get_hp_addr` (LMAC rings only, else 0).
    pub fn get_hp_addr(&self, id: u32) -> u64 {
        let Some(s) = self.srng(id) else { return 0 };
        if s.flags & flags::LMAC_RING == 0 {
            return 0;
        }
        match (s.ring_dir, s.sw_ptr) {
            (SrngDir::Src, SwPtr::Wrp(i)) => self.wrp.paddr() + i as u64 * 4,
            (SrngDir::Dst, _) => self.rdp.paddr() + s.hw_ptr_idx as u64 * 4,
            _ => 0,
        }
    }

    /// Linux `ath11k_hal_srng_get_tp_addr` (LMAC rings only, else 0).
    pub fn get_tp_addr(&self, id: u32) -> u64 {
        let Some(s) = self.srng(id) else { return 0 };
        if s.flags & flags::LMAC_RING == 0 {
            return 0;
        }
        match (s.ring_dir, s.sw_ptr) {
            (SrngDir::Src, _) => self.rdp.paddr() + s.hw_ptr_idx as u64 * 4,
            (SrngDir::Dst, SwPtr::Wrp(i)) => self.wrp.paddr() + i as u64 * 4,
            _ => 0,
        }
    }
}
