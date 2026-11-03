// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE "new TRX flow" descriptors (`rtl8192ee/trx.{c,h}`, `pci.h`,
//! `pci.c` with `use_new_trx_flow`).
//!
//! Unlike the linked rings of RTL8188EE/RTL8821AE, each TX queue has two
//! parallel arrays: a ring of 64-byte *buffer descriptors* (`struct
//! rtl_tx_buffer_desc`, four 16-byte segments for `RTL8192EE_SEG_NUM = 1`),
//! whose base the MAC is given in `REG_*_DESA`, and a ring of 64-byte TX
//! descriptors (`struct rtl_tx_desc`, 40 used bytes) that segment 0 of the
//! matching buffer descriptor points at. Segment 1 points at the frame.
//! Ownership is not a descriptor bit: the driver advances the queue's write
//! index in `REG_*_TXBD_IDX[11:0]` and the device reports its read index in
//! `[27:16]`. The beacon queue alone uses the buffer descriptor OWN bit.
//!
//! RX uses a ring of 16-byte buffer descriptors (`struct
//! rtl_rx_buffer_desc`) pointing at receive buffers whose first 24 bytes
//! are the RX status ("wifi info") written by the device; the payload
//! follows at `24 + drvinfo + shift`. Progress is the
//! `REG_RXQ_TXBD_IDX` read/write pointer pair; the driver acknowledges by
//! writing the next read pointer to `0x3b4`.

/// `TX_DESC_SIZE` (ring entry, `struct rtl_tx_desc`).
pub const TX_DESC_SIZE: usize = 64;
/// Used TX descriptor bytes (`desc_size = 40` in `rtl92ee_pre_fill_tx_bd_desc`).
pub const TX_DESC_USED: usize = 40;
/// `RTL8192EE_SEG_NUM` (= `BUFDESC_SEG_NUM`, 1: four segments).
pub const SEG_NUM: u16 = 1;
/// Segments per TX buffer descriptor.
pub const SEGMENTS: usize = 1 << (SEG_NUM + 1);
/// `sizeof(struct rtl_tx_buffer_desc)`.
pub const TX_BD_SIZE: usize = 16 * SEGMENTS;
/// `sizeof(struct rtl_rx_buffer_desc)`.
pub const RX_BD_SIZE: usize = 16;
/// `RX_DESC_SIZE` (RX status at the start of every receive buffer).
pub const RX_DESC_SIZE: usize = 24;
/// `MAX_RECEIVE_BUFFER_SIZE`.
pub const MAX_RECEIVE_BUFFER_SIZE: u32 = 8192;
/// `RX_DRV_INFO_SIZE_UNIT`.
pub const RX_DRV_INFO_SIZE_UNIT: usize = 8;
/// `USB_HWDESC_HEADER_LEN` — TX `offset` without early mode.
pub const HWDESC_HEADER_LEN: u32 = 40;
/// `TX_DESC_NUM_92E` / `RX_DESC_NUM_92E` / `RTL_PCI_MAX_RX_COUNT`.
pub const TX_DESC_NUM: u16 = 512;
pub const RX_DESC_NUM: u16 = 512;
/// `txringcount[BEACON_QUEUE]`.
pub const BEACON_DESC_NUM: u16 = 2;
/// `rtl92ee_pre_fill_tx_bd_desc` `tx_page_size * 128`.
const PAGE_BYTES: u32 = 2 * 128;

/// `QSLT_*` firmware queue selectors (`rtl8192ee/def.h`).
pub const QSLT_BK: u8 = 0x2;
pub const QSLT_BE: u8 = 0x0;
pub const QSLT_VI: u8 = 0x5;
pub const QSLT_VO: u8 = 0x7;
pub const QSLT_BEACON: u8 = 0x10;
pub const QSLT_HIGH: u8 = 0x11;
pub const QSLT_MGNT: u8 = 0x12;
pub const QSLT_CMD: u8 = 0x13;

/// `DESC_RATE*` (`rtlwifi/wifi.h`).
pub const DESC_RATE1M: u8 = 0x00;
pub const DESC_RATE11M: u8 = 0x03;
pub const DESC_RATE24M: u8 = 0x08;
pub const DESC_RATE54M: u8 = 0x0b;
pub const DESC_RATEMCS0: u8 = 0x0c;
pub const DESC_RATEMCS15: u8 = 0x1b;

/// Per-queue index registers (`get_desc_addr_fr_q_idx`).
pub const REG_VOQ_TXBD_IDX: u16 = 0x03a0;
pub const REG_VIQ_TXBD_IDX: u16 = 0x03a4;
pub const REG_BEQ_TXBD_IDX: u16 = 0x03a8;
pub const REG_BKQ_TXBD_IDX: u16 = 0x03ac;
pub const REG_MGQ_TXBD_IDX: u16 = 0x03b0;
pub const REG_RXQ_TXBD_IDX: u16 = 0x03b4;
pub const REG_HI0Q_TXBD_IDX: u16 = 0x03b8;

/// rtlwifi `enum rtl_txq` order used by Linux for `tx_ring[]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Queue {
    Bk = 0,
    Be = 1,
    Vi = 2,
    Vo = 3,
    Beacon = 4,
    TxCmd = 5,
    Mgnt = 6,
    High = 7,
    Hcca = 8,
}

impl Queue {
    /// `get_desc_addr_fr_q_idx`: BEACON/TXCMD/HCCA alias the BE index.
    pub const fn index_register(self) -> u16 {
        match self {
            Self::Bk => REG_BKQ_TXBD_IDX,
            Self::Be | Self::Beacon | Self::TxCmd | Self::Hcca => REG_BEQ_TXBD_IDX,
            Self::Vi => REG_VIQ_TXBD_IDX,
            Self::Vo => REG_VOQ_TXBD_IDX,
            Self::Mgnt => REG_MGQ_TXBD_IDX,
            Self::High => REG_HI0Q_TXBD_IDX,
        }
    }

    /// `txringcount[]` for the new TRX flow.
    pub const fn entries(self) -> u16 {
        match self {
            Self::Beacon => BEACON_DESC_NUM,
            _ => TX_DESC_NUM,
        }
    }
}

#[inline]
fn put(dw: &mut u32, value: u32, lo: u32, width: u32) {
    let mask = if width == 32 {
        u32::MAX
    } else {
        ((1u32 << width) - 1) << lo
    };
    *dw = (*dw & !mask) | ((value << lo) & mask);
}

#[inline]
fn get(dw: u32, lo: u32, width: u32) -> u32 {
    (dw >> lo)
        & if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        }
}

/// `calc_fifo_space` (`pci.h`).
pub const fn fifo_space(rp: u16, wp: u16, size: u16) -> u16 {
    if rp <= wp {
        size - 1 + rp - wp
    } else {
        rp - wp - 1
    }
}

/// `REG_*_TXBD_IDX` decode: (read point `[27:16]`, write point `[11:0]`).
pub const fn tx_points(value: u32) -> (u16, u16) {
    (((value >> 16) & 0x0fff) as u16, (value & 0x0fff) as u16)
}

/// `REG_RXQ_TXBD_IDX` decode: (read point `[26:16]`, write point `[10:0]`).
pub const fn rx_points(value: u32) -> (u16, u16) {
    (((value >> 16) & 0x7ff) as u16, (value & 0x7ff) as u16)
}

/// `rtl92ee_get_available_desc` for one queue's index register value.
pub const fn available(value: u32) -> u16 {
    let (rp, wp) = tx_points(value);
    fifo_space(rp, wp, TX_DESC_NUM)
}

/// `rtl92ee_is_tx_desc_closed` for a non-beacon queue, given the device read
/// point and the driver's write point. (The unload / RF-off overrides are
/// the caller's.)
pub const fn tx_desc_closed(read_point: u16, write_point: u16, index: u16) -> bool {
    if write_point > read_point {
        !(index < write_point && index >= read_point)
    } else if write_point < read_point {
        index > write_point && index < read_point
    } else {
        index != read_point
    }
}

/// 64-byte TX buffer descriptor (four segments; DMA32, high words 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxBufferDesc {
    pub dw: [u32; 16],
}

impl TxBufferDesc {
    /// `rtl92ee_pre_fill_tx_bd_desc` without early mode and with
    /// `dma64 == false`: segment 0 is the 40-byte TX descriptor at
    /// `desc_addr` with the PSB page count, segment 1 the frame. All other
    /// segments are zero; OWN is clear.
    pub fn fill(desc_addr: u32, frame_addr: u32, pkt_len: u16) -> Self {
        let mut d = Self::default();
        let total = TX_DESC_USED as u32 + u32::from(pkt_len);
        let mut psb = (u32::from(pkt_len) + 0x28) / PAGE_BYTES;
        if psb * PAGE_BYTES < total {
            psb += 1;
        }
        put(&mut d.dw[0], TX_DESC_USED as u32, 0, 14);
        put(&mut d.dw[0], psb, 16, 15);
        d.dw[1] = desc_addr;
        put(&mut d.dw[4], u32::from(pkt_len), 0, 16);
        d.dw[5] = frame_addr;
        d
    }

    /// `HW_DESC_OWN` for `BEACON_QUEUE`: `set_tx_buff_desc_own(1)`.
    pub fn set_own(&mut self) {
        put(&mut self.dw[0], 1, 31, 1);
    }

    pub fn own(&self) -> bool {
        get(self.dw[0], 31, 1) != 0
    }

    pub fn psb(&self) -> u32 {
        get(self.dw[0], 16, 15)
    }

    /// `HW_DESC_TXBUFF_ADDR` (segment 1 low).
    pub fn frame_addr(&self) -> u32 {
        self.dw[5]
    }

    pub fn to_le_bytes(&self) -> [u8; TX_BD_SIZE] {
        let mut out = [0; TX_BD_SIZE];
        for (i, w) in self.dw.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Inputs for the first+last segment path of `rtl92ee_tx_fill_desc`
/// (no early mode, single-buffer MPDU, DMA32).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxParams {
    pub pkt_size: u16,
    pub queue_sel: u8,
    pub macid: u8,
    pub rate_id: u8,
    /// `ptcb_desc->hw_rate` (`DESC_RATE*`).
    pub hw_rate: u8,
    pub use_driver_rate: bool,
    pub disable_fallback: bool,
    /// `data_bw` / `tx_sub_carrier` (`bw_40` station: 1/3 for a 40 MHz
    /// packet, 0/`cur_40_prime_sc` otherwise; 0/0 on a 20 MHz link).
    pub data_bw: u8,
    pub sub_carrier: u8,
    /// `IEEE80211_TX_CTL_AMPDU`: AGG_EN with `max_agg_num = 0x14`.
    pub ampdu: bool,
    pub ampdu_density: u8,
    /// 0 none, 1 WEP/TKIP, 3 CCMP (`info->control.hw_key`).
    pub sec_type: u8,
    pub seq: u16,
    pub multicast: bool,
    /// 0 none, 1 RTS/CTS, 2 CTS-to-self (`rts_rate`, `rts_sc`, long preamble).
    pub protection: u8,
    pub rts_rate: u8,
    /// `rtl_set_tx_report`: SPE_RPT + SW_DEFINE sequence.
    pub tx_report: Option<u16>,
    pub buffer_addr: u32,
}

/// 64-byte TX descriptor (40 used bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    pub dw: [u32; 16],
}

impl TxDesc {
    /// `rtl92ee_tx_fill_desc` (after `clear_pci_tx_desc_content` and the
    /// `pre_fill_tx_bd_desc` PKT_SIZE / TX_BUFFER_SIZE) for a first+last
    /// segment frame. No descriptor OWN exists on this chip.
    pub fn fill(p: &TxParams) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], u32::from(p.pkt_size), 0, 16);
        put(&mut dw[7], u32::from(p.pkt_size), 0, 16);
        put(&mut dw[0], HWDESC_HEADER_LEN, 16, 8);
        put(&mut dw[4], u32::from(p.hw_rate), 0, 7);
        if p.ampdu {
            put(&mut dw[2], 1, 12, 1);
            put(&mut dw[3], 0x14, 17, 5);
        }
        put(&mut dw[9], u32::from(p.seq), 12, 12);
        put(&mut dw[3], u32::from(p.protection == 1), 12, 1);
        put(&mut dw[3], 0, 13, 1);
        put(&mut dw[3], u32::from(p.protection == 2), 11, 1);
        if p.protection != 0 {
            put(&mut dw[4], u32::from(p.rts_rate), 24, 5);
        }
        put(&mut dw[4], u32::from(p.data_bw), 5, 2);
        put(&mut dw[5], u32::from(p.sub_carrier), 0, 4);
        put(&mut dw[2], u32::from(p.ampdu_density), 20, 3);
        put(&mut dw[1], u32::from(p.sec_type), 22, 2);
        put(&mut dw[1], u32::from(p.queue_sel), 8, 5);
        put(&mut dw[4], 0x1f, 8, 5);
        put(&mut dw[4], 0xf, 13, 4);
        put(&mut dw[3], p.disable_fallback as u32, 10, 1);
        put(&mut dw[3], p.use_driver_rate as u32, 8, 1);
        if let Some(sn) = p.tx_report {
            // SET_TX_DESC_SPE_RPT (dword 2 BIT19) / SW_DEFINE (dword 6 [11:0]).
            put(&mut dw[2], 1, 19, 1);
            put(&mut dw[6], u32::from(sn), 0, 12);
        }
        put(&mut dw[0], 1, 27, 1);
        put(&mut dw[0], 1, 26, 1);
        dw[10] = p.buffer_addr;
        put(&mut dw[1], u32::from(p.rate_id), 16, 5);
        put(&mut dw[1], u32::from(p.macid), 0, 7);
        if p.multicast {
            put(&mut dw[0], 1, 24, 1);
        }
        d
    }

    /// `rtl92ee_tx_fill_cmddesc` (reserved-page upload on the beacon queue).
    pub fn command(len: u16, buffer_addr: u32) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], 40, 16, 8);
        put(&mut dw[4], u32::from(DESC_RATE1M), 0, 7);
        put(&mut dw[1], u32::from(QSLT_BEACON), 8, 5);
        put(&mut dw[0], 1, 27, 1);
        put(&mut dw[0], 1, 26, 1);
        put(&mut dw[7], u32::from(len), 0, 16);
        dw[10] = buffer_addr;
        put(&mut dw[1], 7, 16, 5);
        // set_tx_desc_own(1): the bit exists in the 92E layout and Linux sets it.
        put(&mut dw[0], 1, 31, 1);
        put(&mut dw[0], u32::from(len), 0, 16);
        put(&mut dw[3], 1, 8, 1);
        d
    }

    pub fn to_le_bytes(&self) -> [u8; TX_DESC_SIZE] {
        let mut out = [0; TX_DESC_SIZE];
        for (i, w) in self.dw.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// 16-byte RX buffer descriptor (DMA32).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxBufferDesc {
    pub dw: [u32; 4],
}

impl RxBufferDesc {
    /// `HW_DESC_RX_PREPARE`: LS/FS/total length cleared, data length
    /// `MAX_RECEIVE_BUFFER_SIZE + RX_DESC_SIZE`, buffer address.
    pub fn prepare(buffer_addr: u32) -> Self {
        let mut d = Self::default();
        put(
            &mut d.dw[0],
            MAX_RECEIVE_BUFFER_SIZE + RX_DESC_SIZE as u32,
            0,
            14,
        );
        d.dw[1] = buffer_addr;
        d
    }

    pub fn from_words(dw: [u32; 4]) -> Self {
        Self { dw }
    }

    pub fn first_segment(&self) -> bool {
        get(self.dw[0], 16, 1) != 0
    }

    pub fn last_segment(&self) -> bool {
        get(self.dw[0], 15, 1) != 0
    }

    pub fn total_length(&self) -> u32 {
        get(self.dw[0], 16, 15)
    }

    /// `rtl92ee_rx_check_dma_ok`'s completion predicate (any of total
    /// length, FS, LS set).
    pub fn dma_done(&self) -> bool {
        self.total_length() != 0 || self.first_segment() || self.last_segment()
    }

    pub fn to_le_bytes(&self) -> [u8; RX_BD_SIZE] {
        let mut out = [0; RX_BD_SIZE];
        for (i, w) in self.dw.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Decoded RX status (`rtl92ee_rx_query_desc`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxStatus {
    pub pkt_len: u16,
    pub crc: bool,
    pub icv: bool,
    pub drvinfo: usize,
    pub shift: usize,
    pub physt: bool,
    /// `!SWDEC`.
    pub decrypted: bool,
    pub macid: u8,
    pub ampdu: bool,
    /// `rpt_sel`: C2H packet instead of a frame.
    pub c2h: bool,
    pub rate: u8,
    pub tsfl: u32,
    /// `wake_match` (pattern BIT2, magic BIT1, unicast BIT0).
    pub wake_match: u8,
}

impl RxStatus {
    /// Decode the 24-byte RX status at the start of a receive buffer.
    pub fn decode(b: &[u8; RX_DESC_SIZE]) -> Self {
        let w = |i: usize| u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        let (d0, d1, d2, d3) = (w(0), w(1), w(2), w(3));
        let wake_match = if get(d3, 29, 1) != 0 {
            1 << 2
        } else if get(d3, 31, 1) != 0 {
            1 << 1
        } else if get(d3, 30, 1) != 0 {
            1
        } else {
            0
        };
        Self {
            pkt_len: get(d0, 0, 14) as u16,
            crc: get(d0, 14, 1) != 0,
            icv: get(d0, 15, 1) != 0,
            drvinfo: get(d0, 16, 4) as usize * RX_DRV_INFO_SIZE_UNIT,
            shift: get(d0, 24, 2) as usize,
            physt: get(d0, 26, 1) != 0,
            decrypted: get(d0, 27, 1) == 0,
            macid: get(d1, 0, 7) as u8,
            ampdu: get(d1, 15, 1) != 0,
            c2h: get(d2, 28, 1) != 0,
            rate: get(d3, 0, 7) as u8,
            tsfl: w(5),
            wake_match,
        }
    }

    /// Payload offset inside the receive buffer
    /// (`skb_reserve(drvinfo + shift + 24)`).
    pub fn payload_offset(&self) -> usize {
        RX_DESC_SIZE + self.drvinfo + self.shift
    }
}
