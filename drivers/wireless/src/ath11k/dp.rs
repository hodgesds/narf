//! Data Path — REO / TQM / TCL ring descriptor scaffolding.
//!
//! ath11k's data plane sits on top of three families of
//! Hardware-managed Software Ring (HAL_SRNG):
//!
//! - **TCL** (Transmit Classifier) — host pushes packets onto a
//!   TCL_DATA ring; a hardware classifier scatter-gathers them
//!   into per-AC buffers and emits completion status on a
//!   TCL_STATUS ring.
//! - **REO** (Reorder Engine) — receive-side: hardware reorders
//!   incoming MSDUs and emits them on per-flow REO_DST rings.
//! - **TQM/WBM** (Transmit Queue Manager / Wireless Buffer
//!   Manager) — buffer accounting + reinjection (errors get
//!   recycled through WBM_RELEASE rings).
//!
//! Linux's `dp.h` enumerates the ring sizes + descriptor formats;
//! this file translates the pure-data parts (sizes, descriptor
//! `repr(C)` layouts, ring-id enums) so the bring-up code can
//! reference them once Stage-2 wires the actual HAL_SRNG MMIO.
//!
//! Linux references (BSD-3 / dual GPL):
//! - `drivers/net/wireless/ath/ath11k/dp.h` — ring sizes + struct
//!   `dp_srng`.
//! - `drivers/net/wireless/ath/ath11k/hal_desc.h` — TCL data cmd
//!   descriptor + REO DST descriptor field layouts.
//! - `drivers/net/wireless/ath/ath11k/dp_tx.c` /
//!   `drivers/net/wireless/ath/ath11k/dp_rx.c` — descriptor
//!   producer/consumer paths.

#![allow(dead_code)]

// ── Ring-size constants ────────────────────────────────────────────
// Verbatim from `dp.h` — keeping the same names makes cross-
// references with the Linux source mechanical.

pub const DP_TCL_NUM_RING_MAX: usize = 3;
pub const DP_TCL_DATA_RING_SIZE: u32 = 512;
pub const DP_TCL_DATA_RING_SIZE_WCN6750: u32 = 2048;
pub const DP_TCL_CMD_RING_SIZE: u32 = 32;
pub const DP_TCL_STATUS_RING_SIZE: u32 = 32;

pub const DP_REO_DST_RING_MAX: usize = 4;
pub const DP_REO_DST_RING_SIZE: u32 = 2048;
pub const DP_REO_REINJECT_RING_SIZE: u32 = 32;
pub const DP_REO_EXCEPTION_RING_SIZE: u32 = 128;
pub const DP_REO_CMD_RING_SIZE: u32 = 256;
pub const DP_REO_STATUS_RING_SIZE: u32 = 2048;

pub const DP_WBM_RELEASE_RING_SIZE: u32 = 64;

pub const DP_RXDMA_BUF_RING_SIZE: u32 = 4096;
pub const DP_RXDMA_REFILL_RING_SIZE: u32 = 2048;
pub const DP_RXDMA_ERR_DST_RING_SIZE: u32 = 1024;
pub const DP_RXDMA_MON_STATUS_RING_SIZE: u32 = 1024;
pub const DP_RXDMA_MONITOR_BUF_RING_SIZE: u32 = 4096;
pub const DP_RXDMA_MONITOR_DST_RING_SIZE: u32 = 2048;
pub const DP_RXDMA_MONITOR_DESC_RING_SIZE: u32 = 4096;

// ── HAL_SRNG ring-type enum ────────────────────────────────────────
//
// Mirrors `enum hal_ring_type` in Linux's `hal.h`. Concrete IDs
// are baked into hardware tables; do not renumber.

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
    SwToHwRelease = 12,
    HwToSwRelease = 13,
    WbmIdleListEnd,
}

/// Direction of a HAL ring from the host's perspective.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HalRingDir {
    /// Host produces, hardware consumes (TCL_DATA, TCL_CMD,
    /// WBM_IDLE_LINK).
    SrcRing,
    /// Hardware produces, host consumes (REO_DST, REO_STATUS,
    /// TCL_STATUS).
    DstRing,
}

impl HalRingType {
    /// Default direction the ring runs in (the few
    /// bidirectional special-purpose rings get overridden at
    /// allocation time).
    pub fn default_dir(self) -> HalRingDir {
        match self {
            HalRingType::TclData
            | HalRingType::TclCmd
            | HalRingType::ReoReinject
            | HalRingType::ReoCmd
            | HalRingType::CeSrc
            | HalRingType::WbmIdleLink
            | HalRingType::SwToHwRelease => HalRingDir::SrcRing,
            HalRingType::ReoDst
            | HalRingType::ReoException
            | HalRingType::ReoStatus
            | HalRingType::TclStatus
            | HalRingType::CeDst
            | HalRingType::CeDstStatus
            | HalRingType::HwToSwRelease
            | HalRingType::WbmIdleListEnd => HalRingDir::DstRing,
        }
    }
}

// ── TCL_DATA descriptor ────────────────────────────────────────────
//
// Layout of a TCL data ring entry — 8 × u32 = 32 bytes — per
// `struct hal_tcl_data_cmd` in `hal_desc.h`. Field offsets are
// stable across chips; only the bitfield interpretation of
// `info0..info4` varies slightly with HW major.

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct HalTclDataCmd {
    /// DMA address of the MSDU buffer (low 32 bits).
    pub buf_addr_lo: u32,
    /// info0[7:0] = buffer addr high; info0[31:8] = buffer info.
    pub info0: u32,
    /// info1[15:0]  = data length;
    /// info1[20:16] = encap type; info1[28:24] = encrypt type.
    pub info1: u32,
    /// info2[15:0]  = packet offset; info2[31:16] = host buffer ring idx.
    pub info2: u32,
    /// info3[15:0]  = TCL command number;
    /// info3[31:16] = search type.
    pub info3: u32,
    /// info4[15:0]  = peer id; info4[31:16] = reserved.
    pub info4: u32,
    /// info5 — search index / spare.
    pub info5: u32,
    /// info6 — DSCP_TID table override.
    pub info6: u32,
}

impl HalTclDataCmd {
    pub const SIZE: usize = 32;

    /// Pack the high 8 bits of the buffer DMA address into the
    /// canonical `info0[7:0]` slot.
    pub fn set_buf_addr_hi(&mut self, hi: u8) {
        self.info0 = (self.info0 & 0xFFFF_FF00) | hi as u32;
    }

    pub fn set_data_len(&mut self, len: u16) {
        self.info1 = (self.info1 & 0xFFFF_0000) | len as u32;
    }

    pub fn set_buf_dma(&mut self, dma: u64) {
        self.buf_addr_lo = dma as u32;
        self.set_buf_addr_hi(((dma >> 32) & 0xFF) as u8);
    }
}

// ── REO_DST descriptor ─────────────────────────────────────────────
//
// 32-byte receive-direction descriptor produced by the REO. Field
// layout per `struct hal_reo_dst_desc` in `hal_desc.h`.

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct HalReoDstDesc {
    /// MSDU link descriptor (low 32 bits of DMA address).
    pub link_desc_lo: u32,
    /// info0[7:0]  = link desc high; info0[31:8] = MSDU count.
    pub info0: u32,
    /// info1 — buffer manager source + buffer cookie.
    pub info1: u32,
    /// info2 — RX status flags / sequence number.
    pub info2: u32,
    /// info3 — buffer source MSDU + queue desc addr 39:32.
    pub info3: u32,
    /// info4 — receive queue number.
    pub info4: u32,
    /// info5 — soundings + PPDU ID.
    pub info5: u32,
    /// info6 — RX rate / NSS / GI / BW.
    pub info6: u32,
}

impl HalReoDstDesc {
    pub const SIZE: usize = 32;

    pub fn link_desc_dma(&self) -> u64 {
        let hi = (self.info0 & 0xFF) as u64;
        (self.link_desc_lo as u64) | (hi << 32)
    }

    pub fn msdu_count(&self) -> u32 {
        (self.info0 >> 8) & 0x0000_00FF
    }
}

// ── TCL_STATUS / WBM_RELEASE common header ─────────────────────────

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct HalReleaseRingHdr {
    pub buf_addr_lo: u32,
    pub info0: u32,
    pub info1: u32,
    pub info2: u32,
    pub info3: u32,
    pub info4: u32,
    pub info5: u32,
    pub info6: u32,
}

impl HalReleaseRingHdr {
    pub const SIZE: usize = 32;
}

// ── Ring sizing helpers ────────────────────────────────────────────

/// Return the canonical size (in entries) of the named ring type.
/// Linux's `dp.h` picks these up at static time; collapsing them
/// into a function lets the test suite check the table is stable
/// without dragging in the full chip-cfg machinery.
pub fn default_ring_size(kind: HalRingType) -> u32 {
    match kind {
        HalRingType::TclData => DP_TCL_DATA_RING_SIZE,
        HalRingType::TclCmd => DP_TCL_CMD_RING_SIZE,
        HalRingType::TclStatus => DP_TCL_STATUS_RING_SIZE,
        HalRingType::ReoDst => DP_REO_DST_RING_SIZE,
        HalRingType::ReoException => DP_REO_EXCEPTION_RING_SIZE,
        HalRingType::ReoReinject => DP_REO_REINJECT_RING_SIZE,
        HalRingType::ReoCmd => DP_REO_CMD_RING_SIZE,
        HalRingType::ReoStatus => DP_REO_STATUS_RING_SIZE,
        HalRingType::WbmIdleLink | HalRingType::SwToHwRelease | HalRingType::HwToSwRelease => {
            DP_WBM_RELEASE_RING_SIZE
        }
        HalRingType::CeSrc | HalRingType::CeDst | HalRingType::CeDstStatus => 32,
        HalRingType::WbmIdleListEnd => 0,
    }
}

/// Total descriptor bytes for a ring of the named type, assuming
/// the default size. Useful for the DMA allocator's bookkeeping.
pub fn default_ring_bytes(kind: HalRingType) -> usize {
    let n = default_ring_size(kind) as usize;
    let entry_size = match kind {
        HalRingType::TclData
        | HalRingType::TclCmd
        | HalRingType::TclStatus
        | HalRingType::WbmIdleLink
        | HalRingType::SwToHwRelease
        | HalRingType::HwToSwRelease => HalTclDataCmd::SIZE,
        HalRingType::ReoDst
        | HalRingType::ReoException
        | HalRingType::ReoReinject
        | HalRingType::ReoCmd
        | HalRingType::ReoStatus => HalReoDstDesc::SIZE,
        HalRingType::CeSrc | HalRingType::CeDst | HalRingType::CeDstStatus => 16,
        HalRingType::WbmIdleListEnd => 0,
    };
    n * entry_size
}
