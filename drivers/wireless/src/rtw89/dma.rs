//! RTW89 PCI DMA-ring address tables and ring bookkeeping — Stage-2.
//!
//! Per-ring registers come in three "address sets":
//!
//! - **AX baseline** (8852A / 8852B / 8851B): 13 TX channels + 2 RX
//!   rings, doorbells in the `R_AX_*_TXBD_IDX` / `R_AX_*_RXBD_IDX`
//!   page (`pci.h:535..550`); descriptor-base regs in the
//!   `R_AX_*_TXBD_DESA_{L,H}` page (`pci.h:557..586`).
//! - **AX v1** (8852C): same channels, regs shifted to the `_V1`
//!   page (`pci.h:550..616`).
//! - **BE** (8922A): same channels, BE-specific offsets used by
//!   `mac_be.c`; we keep them under a `_V1` alias here because the
//!   physical offsets coincide for the registers we drive.
//!
//! For each ring we encode the doorbell + descriptor base + ring-size
//! registers as a single struct. Linux uses
//! `rtw89_pci_ch_dma_addr_set` (`pci.h:1311`) for the same purpose.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `pci.h:1311..1322` — `struct rtw89_pci_ch_dma_addr` and
//!   the `_set` aggregate.
//! - Linux `pci.c:1093..1183` — the three concrete address-set
//!   instances `rtw89_pci_ch_dma_addr_set{,_v1,_be}`.
//! - Linux `txrx.h:659..685` — `enum rtw89_tx_channel` /
//!   `enum rtw89_rx_channel` (13 TX + 2 RX).
//! - Linux `pci.h:617..667` — `B_AX_DESC_NUM_MSK` + BDRAM bit masks.

#![allow(dead_code)]

use super::mac::ChipGeneration;

// ── TX-channel enumeration ──────────────────────────────────────────
//
// Same numeric values as `enum rtw89_tx_channel` (`txrx.h:659`). The
// names follow the kernel exactly: ACH0..ACH7 are the per-band access
// queues (BE/BK/VI/VO per band × 2 bands), CH8..CH11 carry management
// + high-priority traffic, CH12 carries firmware commands.

/// Band-0 BE (best-effort). `RTW89_TXCH_ACH0`.
pub const TXCH_ACH0: u8 = 0;
/// Band-0 BK (background). `RTW89_TXCH_ACH1`.
pub const TXCH_ACH1: u8 = 1;
/// Band-0 VI (video). `RTW89_TXCH_ACH2`.
pub const TXCH_ACH2: u8 = 2;
/// Band-0 VO (voice). `RTW89_TXCH_ACH3`.
pub const TXCH_ACH3: u8 = 3;
/// Band-1 BE. `RTW89_TXCH_ACH4`.
pub const TXCH_ACH4: u8 = 4;
/// Band-1 BK. `RTW89_TXCH_ACH5`.
pub const TXCH_ACH5: u8 = 5;
/// Band-1 VI. `RTW89_TXCH_ACH6`.
pub const TXCH_ACH6: u8 = 6;
/// Band-1 VO. `RTW89_TXCH_ACH7`.
pub const TXCH_ACH7: u8 = 7;
/// Management, band 0. `RTW89_TXCH_CH8`.
pub const TXCH_CH8: u8 = 8;
/// High-priority, band 0. `RTW89_TXCH_CH9`.
pub const TXCH_CH9: u8 = 9;
/// Management, band 1. `RTW89_TXCH_CH10`.
pub const TXCH_CH10: u8 = 10;
/// High-priority, band 1. `RTW89_TXCH_CH11`.
pub const TXCH_CH11: u8 = 11;
/// Firmware command. `RTW89_TXCH_CH12`.
pub const TXCH_CH12: u8 = 12;

/// Number of TX channels (`RTW89_TXCH_NUM`). `txrx.h:675`.
pub const TXCH_NUM: usize = 13;

/// RX data queue. `RTW89_RXCH_RXQ`.
pub const RXCH_RXQ: u8 = 0;
/// RX report queue (TX completion reports). `RTW89_RXCH_RPQ`.
pub const RXCH_RPQ: u8 = 1;

/// Number of RX channels (`RTW89_RXCH_NUM`). `txrx.h:684`.
pub const RXCH_NUM: usize = 2;

// ── Per-ring register set ───────────────────────────────────────────

/// One TX ring's MMIO register quadruple.
///
/// Mirrors `struct rtw89_pci_ch_dma_addr` (`pci.h:1311`). All four
/// offsets are absolute BAR2 offsets, ready to feed to
/// `MmioRegion::write{16,32}`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxRingRegs {
    /// `*_TXBD_IDX` — write to advance the host's write-pointer
    /// ("doorbell"). 32-bit reg, low 12 bits = HW-pointer, high 16 =
    /// host-pointer; mask via `B_AX_DESC_NUM_MSK`. `pci.h:537..549`.
    pub idx: u64,
    /// `*_TXBD_DESA_L` — low 32 bits of the ring's physical base.
    /// `pci.h:557..582`.
    pub desa_l: u64,
    /// `*_TXBD_DESA_H` — high 32 bits of the ring's physical base.
    /// `pci.h:558..582`.
    pub desa_h: u64,
    /// `*_TXBD_NUM` — 16-bit ring slot count. `pci.h:621..637`.
    pub num: u64,
    /// `*_BDRAM_CTRL` — BDRAM slot config (SIDX/MAX/MIN packed).
    /// `pci.h:639..664`.
    pub bdram: u64,
}

/// One RX ring's MMIO register quadruple. Same shape as
/// [`TxRingRegs`] minus the BDRAM-CTRL (RX rings use a separate
/// reorder buffer not parameterised the same way).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxRingRegs {
    /// `*_RXBD_IDX` — doorbell. `pci.h:535..554`.
    pub idx: u64,
    /// `*_RXBD_DESA_L`. `pci.h:583..590`.
    pub desa_l: u64,
    /// `*_RXBD_DESA_H`. `pci.h:584..590`.
    pub desa_h: u64,
    /// `*_RXBD_NUM` — 16-bit ring slot count. `pci.h:619..637`.
    pub num: u64,
}

/// Aggregate of every TX + RX ring's register set, one of which is
/// selected at probe-time by chip-generation. Mirrors
/// `struct rtw89_pci_ch_dma_addr_set` (`pci.h:1319`).
#[derive(Copy, Clone, Debug)]
pub struct DmaAddrSet {
    pub tx: [TxRingRegs; TXCH_NUM],
    pub rx: [RxRingRegs; RXCH_NUM],
}

// ── Concrete AX address-set ─────────────────────────────────────────
//
// Mirrors `rtw89_pci_ch_dma_addr_set` (`pci.c:1093..1113`) byte-for-byte.
// The DEF_TXCHADDRS macros expand to a `(idx, desa_l, desa_h, num,
// bdram)` quintuple per channel; we transcribe the raw values from
// `pci.h:535..664`.

const fn txring_ax(idx: u64, desa_l: u64, desa_h: u64, num: u64, bdram: u64) -> TxRingRegs {
    TxRingRegs { idx, desa_l, desa_h, num, bdram }
}

const fn rxring_ax(idx: u64, desa_l: u64, desa_h: u64, num: u64) -> RxRingRegs {
    RxRingRegs { idx, desa_l, desa_h, num }
}

/// AX baseline ring addresses (`rtw89_pci_ch_dma_addr_set`,
/// `pci.c:1093`). Use for 8852A / 8852B / 8851B.
pub const AX_DMA_ADDR_SET: DmaAddrSet = DmaAddrSet {
    tx: [
        // ACH0: BE, band 0.
        txring_ax(0x1058, 0x1110, 0x1114, 0x1024, 0x1200),
        // ACH1: BK, band 0.
        txring_ax(0x105C, 0x1118, 0x111C, 0x1026, 0x1204),
        // ACH2: VI, band 0.
        txring_ax(0x1060, 0x1120, 0x1124, 0x1028, 0x1208),
        // ACH3: VO, band 0.
        txring_ax(0x1064, 0x1128, 0x112C, 0x102A, 0x120C),
        // ACH4: BE, band 1.
        txring_ax(0x1068, 0x1130, 0x1134, 0x102C, 0x1210),
        // ACH5: BK, band 1.
        txring_ax(0x106C, 0x1138, 0x113C, 0x102E, 0x1214),
        // ACH6: VI, band 1.
        txring_ax(0x1070, 0x1140, 0x1144, 0x1030, 0x1218),
        // ACH7: VO, band 1.
        txring_ax(0x1074, 0x1148, 0x114C, 0x1032, 0x121C),
        // CH8: MGMT band 0.
        txring_ax(0x1078, 0x1150, 0x1154, 0x1034, 0x1220),
        // CH9: HI band 0.
        txring_ax(0x107C, 0x1158, 0x115C, 0x1036, 0x1224),
        // CH10: MGMT band 1 (Type-1 BDRAM at distinct offset).
        txring_ax(0x137C, 0x1358, 0x135C, 0x1338, 0x1320),
        // CH11: HI band 1 (Type-1 BDRAM).
        txring_ax(0x1380, 0x1360, 0x1364, 0x133A, 0x1324),
        // CH12: FW command.
        txring_ax(0x1080, 0x1160, 0x1164, 0x1038, 0x1228),
    ],
    rx: [
        // RXQ — main data RX.
        rxring_ax(0x1050, 0x1100, 0x1104, 0x1020),
        // RPQ — TX-completion reports.
        rxring_ax(0x1054, 0x1108, 0x110C, 0x1022),
    ],
};

/// AX V1 ring addresses (`rtw89_pci_ch_dma_addr_set_v1`,
/// `pci.c:1116`). Use for 8852C.
pub const AX_V1_DMA_ADDR_SET: DmaAddrSet = DmaAddrSet {
    tx: [
        // ACH0..ACH7: contiguous `_V1` block starting at 0x1230 base.
        txring_ax(0x1058, 0x1230, 0x1234, 0x1024, 0x1300),
        txring_ax(0x105C, 0x1238, 0x123C, 0x1026, 0x1304),
        txring_ax(0x1060, 0x1240, 0x1244, 0x1028, 0x1308),
        txring_ax(0x1064, 0x1248, 0x124C, 0x102A, 0x130C),
        txring_ax(0x1068, 0x1250, 0x1254, 0x102C, 0x1310),
        txring_ax(0x106C, 0x1258, 0x125C, 0x102E, 0x1314),
        txring_ax(0x1070, 0x1260, 0x1264, 0x1030, 0x1318),
        txring_ax(0x1074, 0x1268, 0x126C, 0x1032, 0x131C),
        // CH8 / CH9
        txring_ax(0x1078, 0x1270, 0x1274, 0x1034, 0x1320),
        txring_ax(0x107C, 0x1278, 0x127C, 0x1036, 0x1324),
        // CH10 / CH11 (Type-1 BDRAM, V1 offsets).
        txring_ax(0x11D0, 0x1458, 0x145C, 0x1438, 0x1420),
        txring_ax(0x11D4, 0x1460, 0x1464, 0x143A, 0x1424),
        // CH12 (V1).
        txring_ax(0x1080, 0x1280, 0x1284, 0x1038, 0x1328),
    ],
    rx: [
        // RXQ / RPQ — V1 addresses.
        rxring_ax(0x1218, 0x1220, 0x1224, 0x1210),
        rxring_ax(0x121C, 0x1228, 0x122C, 0x1212),
    ],
};

/// Pick the ring address-set for the given chip generation.
/// Mirrors `chip->pci_info.dma_addr_set` resolution in
/// `rtw89_chip_setup`.
pub const fn addr_set_for(gen: ChipGeneration) -> &'static DmaAddrSet {
    match gen {
        // AX baseline catches 8852A / 8852B / 8851B. 8852C uses the
        // V1 set in Linux but we keep that mapping out of the
        // generation-only enum because the chip-id is what drives the
        // choice; callers that need V1 should branch on chip_id.
        ChipGeneration::Ax => &AX_DMA_ADDR_SET,
        // 8922A (BE) uses the V1 layout for the registers we drive.
        ChipGeneration::Be => &AX_V1_DMA_ADDR_SET,
    }
}

/// Pick the ring address-set for a given chip-id. Use this when you
/// actually have a chip-id — it picks V1 for 8852C separately from
/// the rest of the AX family.
pub const fn addr_set_for_chip(chip: super::mac::ChipId) -> &'static DmaAddrSet {
    use super::mac::ChipId;
    match chip {
        // 8852A / 8852B / 8851B use the AX baseline.
        ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8851B => &AX_DMA_ADDR_SET,
        // 8852C uses the AX V1 layout.
        ChipId::Rtl8852C => &AX_V1_DMA_ADDR_SET,
        // 8922A (BE) reuses the V1 layout for our purposes.
        ChipId::Rtl8922A => &AX_V1_DMA_ADDR_SET,
    }
}

// ── Ring-slot bookkeeping ───────────────────────────────────────────
//
// A `RingState` tracks the host-side write pointer and the last-known
// HW-side read pointer for one TX or RX ring. The driver maintains
// `wp`, advances it on every submit, and reads `rp` back from the
// chip's index register; the available-slot calculation is the same
// as Linux's `rtw89_pci_get_avail_txbd_num` (`pci.c:1222`).

/// Default slot count for the AX data TX rings. Linux uses 256 for
/// ACH0..7 in `rtw89_pci_ops_alloc` (`pci.c:3275`); the FW-command
/// ring (CH12) gets a smaller 64. We pin the AX default at 256.
pub const DEFAULT_TXBD_NUM: u16 = 256;

/// Default slot count for the AX RX rings (`RTW89_RXBD_NUM`).
/// Linux defines `RTW89_RXBD_NUM_MAX` as 256 in `pci.h`.
pub const DEFAULT_RXBD_NUM: u16 = 256;

/// One ring's host-side bookkeeping. Tracks the doorbell write index
/// (`wp`), the last-known HW read index (`rp`), and the ring depth.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingState {
    /// Host-side write pointer. Advances on every submit; visible to
    /// the chip via the index doorbell.
    pub wp: u16,
    /// Hardware-side read pointer. Cached from the index register;
    /// re-read whenever the host wants to know how many slots are
    /// free.
    pub rp: u16,
    /// Total ring depth.
    pub len: u16,
}

impl RingState {
    /// Empty ring of the given depth.
    pub const fn new(len: u16) -> Self {
        Self { wp: 0, rp: 0, len }
    }

    /// Number of free slots in the ring. Mirrors
    /// `rtw89_pci_get_avail_txbd_num` (`pci.c:1222`) — the bookkeeping
    /// reserves one slot to distinguish "full" from "empty."
    pub const fn avail(&self) -> u16 {
        if self.rp > self.wp {
            // wrapped: rp ahead.
            self.rp - self.wp - 1
        } else {
            // not wrapped: rp behind.
            self.len - (self.wp - self.rp) - 1
        }
    }

    /// `true` when no slots are available.
    pub const fn is_full(&self) -> bool {
        self.avail() == 0
    }

    /// Advance the host write pointer by `count`, wrapping at `len`.
    pub fn advance_wp(&mut self, count: u16) {
        let next = (self.wp as u32 + count as u32) % self.len as u32;
        self.wp = next as u16;
    }

    /// Record an updated HW read pointer (typically polled out of the
    /// `*_TXBD_IDX` register's low 12 bits).
    pub fn set_rp(&mut self, rp: u16) {
        self.rp = rp;
    }
}

/// One TX BD descriptor (§11.x). 8 bytes.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TxBd {
    pub length: u16,
    pub opt: u16,
    pub dma: u32,
}

pub const TXBD_OPT_LS: u16 = 1 << 14; // Last segment
pub const TXBD_OPT_DMA_HI_MASK: u16 = 0x3FC0; // bits 13:6

impl TxBd {
    pub fn set_phys(&mut self, phys: u64) {
        self.dma = (phys & 0xFFFFFFFF) as u32;
        let hi = (phys >> 32) as u16;
        self.opt = (self.opt & !TXBD_OPT_DMA_HI_MASK) | ((hi << 6) & TXBD_OPT_DMA_HI_MASK);
    }
}

/// One RX BD descriptor. 8 bytes.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RxBd {
    pub buf_size: u16,
    pub opt: u16,
    pub dma: u32,
}

pub const RXBD_OPT_DMA_HI_MASK: u16 = 0x3FC0; // bits 13:6

impl RxBd {
    pub fn set_phys(&mut self, phys: u64) {
        self.dma = (phys & 0xFFFFFFFF) as u32;
        let hi = (phys >> 32) as u16;
        self.opt = (self.opt & !RXBD_OPT_DMA_HI_MASK) | ((hi << 6) & RXBD_OPT_DMA_HI_MASK);
    }
}

/// Size of one TX BD descriptor (8 bytes). Matches Linux's
/// `struct rtw89_pci_tx_bd_32` (`pci.h:1283`).
pub const TX_BD_SIZE: usize = 8;

/// Size of one RX BD descriptor (8 bytes). Matches Linux's
/// `struct rtw89_pci_rx_bd_32` (`pci.h:1289`).
pub const RX_BD_SIZE: usize = 8;

/// Total bytes for a TX BD ring of `slots` entries.
pub const fn tx_ring_bytes(slots: u16) -> usize {
    slots as usize * TX_BD_SIZE
}

/// Total bytes for an RX BD ring of `slots` entries.
pub const fn rx_ring_bytes(slots: u16) -> usize {
    slots as usize * RX_BD_SIZE
}

/// `RING_IDX` mask: lower 12 bits of the index register hold the
/// HW-side read pointer; upper 16 hold the host-write pointer.
/// `pci.h:617` (`B_AX_DESC_NUM_MSK = GENMASK(11,0)`).
pub const RING_IDX_HW_MASK: u32 = 0x0000_0FFF;
pub const RING_IDX_HOST_SHIFT: u32 = 16;

/// Decompose an index-register value into (hw_rp, host_wp).
pub const fn split_idx(value: u32) -> (u16, u16) {
    let hw = (value & RING_IDX_HW_MASK) as u16;
    let host = ((value >> RING_IDX_HOST_SHIFT) & 0xFFFF) as u16;
    (hw, host)
}

/// Pack a (hw_rp, host_wp) pair into an index-register value.
pub const fn pack_idx(hw: u16, host: u16) -> u32 {
    (hw as u32 & RING_IDX_HW_MASK) | ((host as u32) << RING_IDX_HOST_SHIFT)
}
