// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE PCI TX/RX descriptors (`rtl8192de/trx.{c,h}` +
//! `rtl8192d/trx_common.{c,h}`).
//!
//! This layout is the 92D one, NOT the 8723BE/8821AE one: a 64-byte TX
//! descriptor in a 64-byte ring entry with the buffer address at dword
//! 8 and `next_desc_address` at dword 10 (byte 40, which is why
//! `clear_pci_tx_desc_content` clears only the first 40 bytes — the
//! ring link survives a fill), and a 32-byte RX status descriptor with
//! the buffer address at dword 6. Field positions below are the
//! `trx_common.h` setter macros, verified one by one; every value the
//! fill programs is one Linux sets on the same path.
//!
//! The fill covers the single-buffer, non-early-mode path of
//! `rtl92de_tx_fill_desc` for a first+last segment frame, including
//! the AMPDU flag + density, RDG + HTC for QoS data (behind
//! `rdg_en`, which upstream never sets — see [`super::h2c`]),
//! the LPS hardware-sequence rule, the TX-report request
//! (`spe_rpt` / `sw_define`), and rate-id / MAC-id. Early-mode
//! AMPDU headers, multi-segment frames and AMPDU aggregation beyond
//! the descriptor's own agg flag are remainders for the station
//! owner. Ring-slot allocation, descriptor-ring base programming,
//! the doorbell and OWN publication stay with the caller: this
//! module fills a caller-provided [`TxDesc`] (OWN left clear, as
//! Linux's data path leaves it for the ring owner — only the
//! command path publishes OWN itself, and this module leaves that
//! to the caller too) and the future `Prepared::Chip::Rtl8192de`
//! packet path owns the rings.

/// `TX_DESC_SIZE`.
pub const TX_DESC_SIZE: usize = 64;
/// `RX_DESC_SIZE`.
pub const RX_DESC_SIZE: usize = 32;
/// `USB_HWDESC_HEADER_LEN`: the descriptor offset without early mode.
pub const HWDESC_HEADER_LEN: u8 = 32;
/// `TX_DESC_NEXT_DESC_OFFSET`: the ring-link byte offset.
pub const NEXT_DESC_BYTE: usize = 40;
/// `RX_DRV_INFO_SIZE_UNIT`.
pub const RX_DRV_INFO_SIZE_UNIT: usize = 8;
/// `QSLT_BEACON` (firmware queue selector, `wifi.h`).
pub const QSLT_BEACON: u8 = 0x10;
/// `QSLT_MGNT`.
pub const QSLT_MGNT: u8 = 0x12;
/// `QSLT_BE`.
pub const QSLT_BE: u8 = 0;
/// `QSLT_BK`.
pub const QSLT_BK: u8 = 1;
/// `QSLT_VI`.
pub const QSLT_VI: u8 = 2;
/// `QSLT_VO`.
pub const QSLT_VO: u8 = 3;
/// `QSLT_HIGH`.
pub const QSLT_HIGH: u8 = 4;
/// `QSLT_CMD`.
pub const QSLT_CMD: u8 = 5;
/// `DESC_RATE1M`, `DESC_RATE6M`, `DESC_RATE54M`, `DESC_RATEMCS0`,
/// `DESC_RATEMCS7` (`wifi.h`).
pub const DESC_RATE1M: u8 = 0x00;
pub const DESC_RATE6M: u8 = 0x04;
pub const DESC_RATE54M: u8 = 0x0b;
pub const DESC_RATEMCS0: u8 = 0x0c;
pub const DESC_RATEMCS7: u8 = 0x13;
/// AMPDU `max_agg_num` programmed by the fill (`0x14`).
pub const MAX_AGG_NUM: u8 = 0x14;
/// Data / RTS rate fallback limits programmed by the fill.
pub const DATA_RATE_FB_LIMIT: u8 = 0x1f;
pub const RTS_RATE_FB_LIMIT: u8 = 0x0f;
/// RTS rate forced when the driver rate is not used (`0x08` = 24M).
pub const RTS_RATE_NO_DRIVER_RATE: u8 = 0x08;
/// Command-descriptor rate id / MAC id (`rtl92de_tx_fill_cmddesc`).
pub const CMD_RATE_ID: u8 = 7;
pub const CMD_MACID: u8 = 0;
/// LPS `pkt_id` for non-QoS frames under firmware LPS control.
pub const LPS_PKT_ID: u8 = 8;

#[inline]
fn put(dw: &mut u32, value: u32, lo: u32, width: u32) {
    let mask = ((1u32 << width) - 1) << lo;
    *dw = (*dw & !mask) | ((value << lo) & mask);
}

#[inline]
fn get(dw: u32, lo: u32, width: u32) -> u32 {
    (dw >> lo) & ((1u32 << width) - 1)
}

/// 64-byte TX ring entry (`struct tx_desc_92d` plus link words).
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    pub dw: [u32; 16],
}

/// Rate-id / MAC-id for a descriptor (`rtl92de_tx_fill_desc` tail:
/// `dm.useramask` selects `ratr_index` / `mac_id` directly, otherwise
/// rate id `0x0c + ratr_index` and MAC id `ratr_index`).
pub fn rate_id_macid(useramask: bool, ratr_index: u8, mac_id: u8) -> (u8, u8) {
    if useramask {
        (ratr_index, mac_id)
    } else {
        (0x0c + ratr_index, ratr_index)
    }
}

/// Inputs for the single-buffer, non-early-mode path of
/// `rtl92de_tx_fill_desc`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxParams {
    pub pkt_size: u16,
    pub queue_sel: u8,
    pub macid: u8,
    /// `ptcb_desc->ratr_index` after the `useramask` rule.
    pub rate_id: u8,
    /// `ptcb_desc->hw_rate`.
    pub hw_rate: u8,
    pub use_driver_rate: bool,
    pub disable_fallback: bool,
    pub use_shortgi: bool,
    pub use_shortpreamble: bool,
    /// `mac->bw_40` (station) or the peer's 40 MHz capability (AP /
    /// adhoc).
    pub bw_40: bool,
    /// `ptcb_desc->packet_bw == HT_CHANNEL_WIDTH_20_40`.
    pub packet_bw_40: bool,
    /// `mac->cur_40_prime_sc`.
    pub cur_40_prime_sc: u8,
    pub ampdu: bool,
    pub ampdu_density: u8,
    /// 0 none, 1 WEP/TKIP, 3 CCMP (key state selects; pass 1 uses 0).
    pub sec_type: u8,
    pub qos_data: bool,
    pub seq: u16,
    pub rts_enable: bool,
    pub cts_enable: bool,
    pub rts_rate: u8,
    pub rts_sc: u8,
    pub rts_stbc: bool,
    pub rts_use_shortpreamble: bool,
    pub rts_use_shortgi: bool,
    pub buffer_len: u16,
    pub buffer_addr: u32,
    /// `rtlhal->current_bandtype == BAND_ON_5G` (5 GHz has no CCK
    /// rate: data and RTS rates floor at 6M).
    pub band_5g: bool,
    /// `rtlhal->macphymode == DUALMAC_DUALPHY` (MCS7 forces
    /// short GI).
    pub dual_mac_dual_phy: bool,
    /// `ppsc->fwctrl_lps` (non-QoS frames take the LPS hwseq rule).
    pub fwctrl_lps: bool,
    /// `mac->rdg_en` (QoS data only).
    pub rdg_en: bool,
    /// `rtl_is_tx_report_skb` (EAPOL or nullfunc): the firmware
    /// reports this frame's TX status — `SET_TX_DESC_SPE_RPT`
    /// (dword 2 bit 19).
    pub spe_rpt: bool,
    /// Driver TX-report sequence for `SET_TX_DESC_SW_DEFINE`
    /// (dword 6 bits 11:0): `(sn & 0x3f) << 2` (bits 7:2 driver
    /// sequence; bits 11:8 reserved, bits 1:0 firmware). Bit 11 is
    /// shared with `max_agg_num`, but a report frame is never an
    /// AMPDU frame, so the two writes never meet.
    pub sw_define: u16,
}

impl TxDesc {
    /// `rtl92de_tx_fill_desc` for a first+last segment frame, OWN
    /// clear. Field order follows Linux, including the two
    /// order-sensitive rules: the RTS rate is set from the TCB and
    /// then overwritten with `0x08` when the driver rate is not used,
    /// and `pkt_id` is set to 0 and then overwritten with 8 by the
    /// LPS hwseq rule.
    pub fn fill(p: &TxParams) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], u32::from(HWDESC_HEADER_LEN), 16, 8);
        let mut hw_rate = p.hw_rate;
        if p.band_5g && hw_rate < DESC_RATE6M {
            hw_rate = DESC_RATE6M;
        }
        put(&mut dw[5], u32::from(hw_rate), 0, 6);
        let short = p.use_shortgi
            || p.use_shortpreamble
            || (p.dual_mac_dual_phy && hw_rate == DESC_RATEMCS7);
        put(&mut dw[5], short as u32, 6, 1);
        if p.ampdu {
            put(&mut dw[1], 1, 5, 1);
            put(&mut dw[6], u32::from(MAX_AGG_NUM), 11, 5);
        }
        put(&mut dw[3], u32::from(p.seq), 16, 12);
        put(&mut dw[4], (p.rts_enable && !p.cts_enable) as u32, 12, 1);
        put(&mut dw[4], (p.rts_enable || p.cts_enable) as u32, 13, 1);
        put(&mut dw[4], p.cts_enable as u32, 11, 1);
        put(&mut dw[4], p.rts_stbc as u32, 30, 2);
        let mut rts_rate = p.rts_rate;
        if p.band_5g && rts_rate < DESC_RATE6M {
            rts_rate = DESC_RATE6M;
        }
        put(&mut dw[4], u32::from(rts_rate), 0, 5);
        put(&mut dw[4], 0, 27, 1);
        put(&mut dw[4], u32::from(p.rts_sc), 28, 2);
        let rts_short = if rts_rate <= DESC_RATE54M {
            p.rts_use_shortpreamble
        } else {
            p.rts_use_shortgi
        };
        put(&mut dw[4], rts_short as u32, 26, 1);
        let (bw, sc) = match (p.bw_40, p.packet_bw_40) {
            (true, true) => (1, 3),
            (true, false) => (0, p.cur_40_prime_sc),
            (false, _) => (0, 0),
        };
        put(&mut dw[4], bw, 25, 1);
        put(&mut dw[4], u32::from(sc), 20, 2);
        put(&mut dw[0], 0, 28, 1);
        put(&mut dw[0], u32::from(p.pkt_size), 0, 16);
        put(&mut dw[2], u32::from(p.ampdu_density), 20, 3);
        put(&mut dw[1], u32::from(p.sec_type), 22, 2);
        put(&mut dw[3], 0, 28, 4);
        put(&mut dw[1], u32::from(p.queue_sel), 8, 5);
        put(&mut dw[5], u32::from(DATA_RATE_FB_LIMIT), 8, 5);
        put(&mut dw[5], u32::from(RTS_RATE_FB_LIMIT), 13, 4);
        put(&mut dw[4], p.disable_fallback as u32, 10, 1);
        put(&mut dw[4], p.use_driver_rate as u32, 8, 1);
        if !p.use_driver_rate {
            put(&mut dw[4], u32::from(RTS_RATE_NO_DRIVER_RATE), 0, 5);
        }
        if p.qos_data && p.rdg_en {
            put(&mut dw[1], 1, 7, 1);
            put(&mut dw[0], 1, 25, 1);
        }
        put(&mut dw[0], 1, 27, 1);
        put(&mut dw[0], 1, 26, 1);
        put(&mut dw[7], u32::from(p.buffer_len), 0, 16);
        dw[8] = p.buffer_addr;
        put(&mut dw[1], u32::from(p.rate_id), 16, 4);
        put(&mut dw[1], u32::from(p.macid), 0, 5);
        if p.qos_data {
            put(&mut dw[4], 1, 6, 1);
        }
        if !p.qos_data && p.fwctrl_lps {
            put(&mut dw[4], 1, 7, 1);
            put(&mut dw[3], u32::from(LPS_PKT_ID), 28, 4);
        }
        put(&mut dw[2], 0, 17, 1);
        if p.spe_rpt {
            put(&mut dw[2], 1, 19, 1);
            put(&mut dw[6], u32::from(p.sw_define), 0, 12);
        }
        // No `bmc` write: unlike its 92C siblings, the 92D fill path has
        // no `bmc` setter in `trx_common.h` and never programs the bit.
        d
    }

    /// `rtl92de_tx_fill_cmddesc`: beacon-queue command descriptor,
    /// OWN left clear for the caller (Linux publishes OWN itself at
    /// the end of this path; the ring owner publishes here).
    pub fn fill_cmd(len: u16, buffer_addr: u32, band_5g: bool, fwctrl_lps: bool) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], u32::from(HWDESC_HEADER_LEN), 16, 8);
        put(
            &mut dw[5],
            u32::from(if band_5g { DESC_RATE6M } else { DESC_RATE1M }),
            0,
            6,
        );
        put(&mut dw[3], 0, 16, 12);
        put(&mut dw[0], 0, 28, 1);
        put(&mut dw[1], u32::from(QSLT_BEACON), 8, 5);
        put(&mut dw[0], 1, 27, 1);
        put(&mut dw[0], 1, 26, 1);
        put(&mut dw[7], u32::from(len), 0, 16);
        dw[8] = buffer_addr;
        put(&mut dw[1], u32::from(CMD_RATE_ID), 16, 4);
        put(&mut dw[1], u32::from(CMD_MACID), 0, 5);
        put(&mut dw[0], u32::from(len), 0, 16);
        put(&mut dw[0], u32::from(HWDESC_HEADER_LEN), 16, 8);
        put(&mut dw[4], 1, 8, 1);
        if fwctrl_lps {
            put(&mut dw[4], 1, 7, 1);
            put(&mut dw[3], u32::from(LPS_PKT_ID), 28, 4);
        }
        d
    }

    /// `rtl92de_set_desc` `HW_DESC_OWN` (data path: the caller
    /// publishes after the payload buffer is visible).
    pub fn set_own(&mut self, own: bool) {
        put(&mut self.dw[0], own as u32, 31, 1);
    }

    /// `rtl92de_get_desc` `HW_DESC_OWN`.
    pub fn own(&self) -> bool {
        get(self.dw[0], 31, 1) != 0
    }

    /// `rtl92de_set_desc` `HW_DESC_TX_NEXTDESC_ADDR`.
    pub fn set_next(&mut self, addr: u32) {
        self.dw[10] = addr;
    }

    /// `rtl92de_get_desc` `HW_DESC_TXBUFF_ADDR`.
    pub fn buffer_addr(&self) -> u32 {
        self.dw[8]
    }

    /// Descriptor packet size.
    pub fn pkt_size(&self) -> u16 {
        get(self.dw[0], 0, 16) as u16
    }

    /// Firmware queue selector.
    pub fn queue_sel(&self) -> u8 {
        get(self.dw[1], 8, 5) as u8
    }

    /// MAC id.
    pub fn macid(&self) -> u8 {
        get(self.dw[1], 0, 5) as u8
    }

    /// Data rate code.
    pub fn tx_rate(&self) -> u8 {
        get(self.dw[5], 0, 6) as u8
    }

    /// Data bandwidth bit.
    pub fn data_bw(&self) -> u8 {
        get(self.dw[4], 25, 1) as u8
    }

    /// TX sub-carrier.
    pub fn sub_carrier(&self) -> u8 {
        get(self.dw[4], 20, 2) as u8
    }
}

/// Decoded RX status (`rtl92d_rx_query_desc` over `trx_common.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxStatus {
    pub length: u16,
    pub drvinfo_size: usize,
    pub shift: usize,
    pub crc: bool,
    pub icv: bool,
    pub decrypted: bool,
    pub physt: bool,
    /// `get_rx_desc_rxmcs` (6 bits).
    pub rate: u8,
    /// `get_rx_desc_splcp` (dword 3 bit 8).
    pub short_preamble: bool,
    pub ampdu: bool,
    /// `get_rx_desc_paggr && get_rx_desc_faggr`.
    pub first_ampdu: bool,
    /// `get_rx_desc_bw` (dword 3 bit 9): 0 = 20, 1 = 40 MHz.
    pub bw: u8,
    /// `get_rx_desc_rxht`.
    pub is_ht: bool,
    pub tsfl: u32,
}

impl RxStatus {
    /// Decode a driver-owned RX status descriptor (`None` while OWN).
    /// `decrypted` follows Linux exactly: not software-decrypted and
    /// the encryption type is not `RX_DESC_ENC_NONE` (0).
    pub fn parse(dw: &[u32; 8]) -> Option<Self> {
        if get(dw[0], 31, 1) != 0 {
            return None;
        }
        let paggr = get(dw[1], 14, 1) != 0;
        Some(Self {
            length: get(dw[0], 0, 14) as u16,
            crc: get(dw[0], 14, 1) != 0,
            icv: get(dw[0], 15, 1) != 0,
            drvinfo_size: get(dw[0], 16, 4) as usize * RX_DRV_INFO_SIZE_UNIT,
            shift: get(dw[0], 24, 2) as usize,
            physt: get(dw[0], 26, 1) != 0,
            decrypted: get(dw[0], 27, 1) == 0 && get(dw[0], 20, 3) != 0,
            rate: get(dw[3], 0, 6) as u8,
            short_preamble: get(dw[3], 8, 1) != 0,
            ampdu: paggr,
            first_ampdu: paggr && get(dw[1], 15, 1) != 0,
            bw: get(dw[3], 9, 1) as u8,
            is_ht: get(dw[3], 6, 1) != 0,
            tsfl: dw[5],
        })
    }

    /// Byte offset of the 802.11 header in the RX buffer.
    pub fn payload_offset(&self) -> usize {
        RX_DESC_SIZE + self.drvinfo_size + self.shift
    }

    /// `stats->hwerror = crc | icv`.
    pub fn hw_error(&self) -> bool {
        self.crc || self.icv
    }

    /// `RX_HAL_IS_CCK_RATE`.
    pub const fn is_cck(&self) -> bool {
        self.rate <= 3
    }
}

/// Re-arm an RX descriptor (`rtl92d_set_desc` `HW_DESC_RXBUFF_ADDR` /
/// `RXPKT_LEN` / `RXOWN`, plus EOR on the last entry).
pub fn rx_arm(dw: &mut [u32; 8], buffer: u32, len: u16, last: bool) {
    *dw = [0; 8];
    dw[6] = buffer;
    put(&mut dw[0], u32::from(len), 0, 14);
    put(&mut dw[0], last as u32, 30, 1);
    put(&mut dw[0], 1, 31, 1);
}
