// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE PCI TX/RX descriptors (`rtl8723be/trx.{c,h}`).
//!
//! The layout is the RTL8821AE one (`rtl8821ae/trx.h`) bit for bit, except
//! that the RTL8723BE TX descriptor has no `tx_ant` field and its RX
//! descriptor carries `rxht` (dword 3 BIT6): a 40-byte TX descriptor in a
//! 64-byte ring entry with the buffer address at dword 10 and
//! `next_desc_address` at dword 12, and a 32-byte RX status descriptor with
//! the buffer address at dword 6. The fill below follows
//! `rtl8723be_tx_fill_desc` (not the RTL8821AE fill: `max_agg_num` is
//! `0x14`, the RTS rate/short/sub-carrier come from the TCB, short GI only
//! for `hw_rate > DESC92C_RATEMCS0`, and the 40 MHz sub-carrier is 3 for a
//! 40 MHz packet, else `cur_40_prime_sc`).

pub use crate::rtlwifi::rtl8821ae::trx::{
    HWDESC_HEADER_LEN, QSLT_BE, QSLT_BEACON, QSLT_BK, QSLT_CMD, QSLT_HIGH, QSLT_MGNT, QSLT_VI,
    QSLT_VO, RX_DESC_SIZE, RX_DRV_INFO_SIZE_UNIT, TX_DESC_SIZE, TX_RING_ENTRY,
};

/// `TX_DESC_NEXT_DESC_OFFSET` is 40 in `trx.h`, but the link Linux writes
/// (`set_tx_desc_next_desc_address`) is dword 12: the ring profile's
/// next-link byte offset.
pub const NEXT_DESC_BYTE: usize = 48;
/// `DESC92C_RATE1M`, `DESC92C_RATE54M`, `DESC92C_RATEMCS0`,
/// `DESC92C_RATEMCS7` (`def.h`).
pub const DESC_RATE1M: u8 = 0x00;
pub const DESC_RATE54M: u8 = 0x0b;
pub const DESC_RATEMCS0: u8 = 0x0c;
pub const DESC_RATEMCS7: u8 = 0x13;

#[inline]
fn put(dw: &mut u32, value: u32, lo: u32, width: u32) {
    let mask = ((1u32 << width) - 1) << lo;
    *dw = (*dw & !mask) | ((value << lo) & mask);
}

#[inline]
fn get(dw: u32, lo: u32, width: u32) -> u32 {
    (dw >> lo) & ((1u32 << width) - 1)
}

/// 64-byte TX ring entry (`struct tx_desc_8723be` plus link words).
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    pub dw: [u32; 16],
}

/// Inputs for the single-buffer, non-early-mode path of
/// `rtl8723be_tx_fill_desc`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxParams {
    pub pkt_size: u16,
    pub queue_sel: u8,
    pub macid: u8,
    /// `ptcb_desc->ratr_index` (`dm.useramask` branch, `if (1)`).
    pub rate_id: u8,
    /// `ptcb_desc->hw_rate`.
    pub hw_rate: u8,
    pub use_driver_rate: bool,
    pub disable_fallback: bool,
    pub use_shortgi: bool,
    pub use_shortpreamble: bool,
    /// `mac->bw_40` (station).
    pub bw_40: bool,
    /// `ptcb_desc->packet_bw == HT_CHANNEL_WIDTH_20_40`.
    pub packet_bw_40: bool,
    /// `mac->cur_40_prime_sc`.
    pub cur_40_prime_sc: u8,
    pub ampdu: bool,
    pub ampdu_density: u8,
    /// 0 none, 1 WEP/TKIP, 3 CCMP.
    pub sec_type: u8,
    pub qos_data: bool,
    pub seq: u16,
    pub multicast: bool,
    pub rts_enable: bool,
    pub cts_enable: bool,
    pub rts_rate: u8,
    pub rts_sc: u8,
    pub rts_use_shortpreamble: bool,
    pub rts_use_shortgi: bool,
    /// `rtl_set_tx_report`: request a C2H TX report carrying `sw_define`.
    pub tx_report: Option<u16>,
    pub buffer_len: u16,
    pub buffer_addr: u32,
}

impl TxDesc {
    /// `rtl8723be_tx_fill_desc` for a first+last segment frame, OWN clear.
    pub fn fill(p: &TxParams) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], HWDESC_HEADER_LEN, 16, 8);
        put(&mut dw[4], u32::from(p.hw_rate), 0, 7);
        let short = if p.hw_rate > DESC_RATEMCS0 {
            p.use_shortgi
        } else {
            p.use_shortpreamble
        };
        put(&mut dw[5], short as u32, 4, 1);
        if p.ampdu {
            put(&mut dw[2], 1, 12, 1);
            put(&mut dw[3], 0x14, 17, 5);
        }
        put(&mut dw[9], u32::from(p.seq), 12, 12);
        put(&mut dw[3], (p.rts_enable && !p.cts_enable) as u32, 12, 1);
        put(&mut dw[3], 0, 13, 1);
        put(&mut dw[3], p.cts_enable as u32, 11, 1);
        put(&mut dw[4], u32::from(p.rts_rate), 24, 5);
        put(&mut dw[5], u32::from(p.rts_sc), 13, 4);
        let rts_short = if p.rts_rate <= DESC_RATE54M {
            p.rts_use_shortpreamble
        } else {
            p.rts_use_shortgi
        };
        put(&mut dw[5], rts_short as u32, 12, 1);
        let (bw, sc) = match (p.bw_40, p.packet_bw_40) {
            (true, true) => (1, 3),
            (true, false) => (0, p.cur_40_prime_sc),
            (false, _) => (0, 0),
        };
        put(&mut dw[5], bw, 5, 2);
        put(&mut dw[5], u32::from(sc), 0, 4);
        put(&mut dw[0], 0, 28, 1);
        put(&mut dw[0], u32::from(p.pkt_size), 0, 16);
        put(&mut dw[2], u32::from(p.ampdu_density), 20, 3);
        put(&mut dw[1], u32::from(p.sec_type), 22, 2);
        put(&mut dw[1], u32::from(p.queue_sel), 8, 5);
        put(&mut dw[4], 0x1f, 8, 5);
        put(&mut dw[4], 0xf, 13, 4);
        put(&mut dw[3], p.disable_fallback as u32, 10, 1);
        put(&mut dw[3], p.use_driver_rate as u32, 8, 1);
        if let Some(sn) = p.tx_report {
            // SET_TX_DESC_SPE_RPT (byte 8 BIT19) / SW_DEFINE (byte 24 [11:0]).
            put(&mut dw[2], 1, 19, 1);
            put(&mut dw[6], u32::from(sn), 0, 12);
        }
        put(&mut dw[0], 1, 27, 1);
        put(&mut dw[0], 1, 26, 1);
        put(&mut dw[7], u32::from(p.buffer_len), 0, 16);
        dw[10] = p.buffer_addr;
        put(&mut dw[1], u32::from(p.rate_id), 16, 5);
        put(&mut dw[1], u32::from(p.macid), 0, 7);
        if !p.qos_data {
            put(&mut dw[8], 1, 15, 1);
            put(&mut dw[3], 0, 6, 2);
        }
        put(&mut dw[2], 0, 17, 1);
        if p.multicast {
            put(&mut dw[0], 1, 24, 1);
        }
        d
    }

    /// `rtl8723be_tx_fill_cmddesc` (beacon queue, 1M, driver rate). OWN is
    /// left to the caller, published after the buffer as for data frames.
    pub fn fill_cmd(len: u16, buffer_addr: u32) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], HWDESC_HEADER_LEN, 16, 8);
        put(&mut dw[4], u32::from(DESC_RATE1M), 0, 7);
        put(&mut dw[1], u32::from(QSLT_BEACON), 8, 5);
        put(&mut dw[0], 1, 27, 1);
        put(&mut dw[0], 1, 26, 1);
        put(&mut dw[7], u32::from(len), 0, 16);
        dw[10] = buffer_addr;
        put(&mut dw[0], u32::from(len), 0, 16);
        put(&mut dw[3], 1, 8, 1);
        d
    }

    pub fn set_own(&mut self, own: bool) {
        put(&mut self.dw[0], own as u32, 31, 1);
    }
    pub fn own(&self) -> bool {
        get(self.dw[0], 31, 1) != 0
    }
    pub fn set_next(&mut self, addr: u32) {
        self.dw[12] = addr;
    }
    pub fn pkt_size(&self) -> u16 {
        get(self.dw[0], 0, 16) as u16
    }
    pub fn queue_sel(&self) -> u8 {
        get(self.dw[1], 8, 5) as u8
    }
    pub fn macid(&self) -> u8 {
        get(self.dw[1], 0, 7) as u8
    }
    pub fn tx_rate(&self) -> u8 {
        get(self.dw[4], 0, 7) as u8
    }
    pub fn data_bw(&self) -> u8 {
        get(self.dw[5], 5, 2) as u8
    }
    pub fn sub_carrier(&self) -> u8 {
        get(self.dw[5], 0, 4) as u8
    }
}

/// Decoded `rtl8723be_rx_query_desc` status fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxStatus {
    pub length: u16,
    pub drvinfo_size: usize,
    pub shift: usize,
    pub crc: bool,
    pub icv: bool,
    pub decrypted: bool,
    pub physt: bool,
    pub rate: u8,
    pub short_preamble: bool,
    pub ampdu: bool,
    pub macid: u8,
    /// `get_rx_desc_bw`: 0 = 20, 1 = 40 MHz.
    pub bw: u8,
    /// `get_rx_desc_rxht`.
    pub is_ht: bool,
    pub tsfl: u32,
    /// `get_rx_status_desc_rpt_sel`: the buffer is a C2H packet.
    pub c2h: bool,
    pub pattern_match: bool,
    pub unicast_match: bool,
    pub magic_match: bool,
}

impl RxStatus {
    /// Decode a driver-owned RX status descriptor (`None` while OWN).
    pub fn parse(dw: &[u32; 8]) -> Option<Self> {
        if get(dw[0], 31, 1) != 0 {
            return None;
        }
        Some(Self {
            length: get(dw[0], 0, 14) as u16,
            crc: get(dw[0], 14, 1) != 0,
            icv: get(dw[0], 15, 1) != 0,
            drvinfo_size: get(dw[0], 16, 4) as usize * RX_DRV_INFO_SIZE_UNIT,
            shift: get(dw[0], 24, 2) as usize & 3,
            physt: get(dw[0], 26, 1) != 0,
            decrypted: get(dw[0], 27, 1) == 0,
            macid: get(dw[1], 0, 7) as u8,
            ampdu: get(dw[1], 15, 1) != 0,
            c2h: get(dw[2], 28, 1) != 0,
            rate: get(dw[3], 0, 7) as u8,
            is_ht: get(dw[3], 6, 1) != 0,
            pattern_match: get(dw[3], 29, 1) != 0,
            unicast_match: get(dw[3], 30, 1) != 0,
            magic_match: get(dw[3], 31, 1) != 0,
            short_preamble: get(dw[4], 0, 1) != 0,
            bw: get(dw[4], 4, 2) as u8,
            tsfl: dw[5],
        })
    }

    /// Byte offset of the 802.11 header / C2H payload in the RX buffer.
    pub fn payload_offset(&self) -> usize {
        RX_DESC_SIZE + self.drvinfo_size + self.shift
    }
    pub fn hw_error(&self) -> bool {
        self.crc || self.icv
    }
    /// `RX_HAL_IS_CCK_RATE`.
    pub const fn is_cck(&self) -> bool {
        self.rate <= 3
    }
}

/// Re-arm an RX descriptor (`rtl8723be_set_desc` HW_DESC_RXBUFF_ADDR /
/// RXPKT_LEN / RXOWN, plus EOR on the last entry).
pub fn rx_arm(dw: &mut [u32; 8], buffer: u32, len: u16, last: bool) {
    *dw = [0; 8];
    dw[6] = buffer;
    put(&mut dw[0], u32::from(len), 0, 14);
    put(&mut dw[0], last as u32, 30, 1);
    put(&mut dw[0], 1, 31, 1);
}
