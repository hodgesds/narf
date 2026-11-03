// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE PCI TX/RX descriptors (`rtl8821ae/trx.{c,h}`).
//!
//! The TX descriptor proper is `TX_DESC_SIZE` (40) bytes, followed in the
//! 64-byte ring entry by the buffer address (dword 10) and the next-descriptor
//! address (dword 12). The RX status descriptor is `RX_DESC_SIZE` (32) bytes
//! with the buffer address in dword 6.

/// `TX_DESC_SIZE`.
pub const TX_DESC_SIZE: usize = 40;
/// Ring entry size (`struct rtl_tx_desc`, 16 dwords).
pub const TX_RING_ENTRY: usize = 64;
/// `RX_DESC_SIZE`.
pub const RX_DESC_SIZE: usize = 32;
/// `RX_DRV_INFO_SIZE_UNIT`.
pub const RX_DRV_INFO_SIZE_UNIT: usize = 8;
/// `USB_HWDESC_HEADER_LEN` — TX `offset` field for non-early-mode frames.
pub const HWDESC_HEADER_LEN: u32 = 40;

/// `QSLT_*` firmware queue selectors (`rtl8821ae/def.h`).
pub const QSLT_BK: u8 = 0x2;
pub const QSLT_BE: u8 = 0x0;
pub const QSLT_VI: u8 = 0x5;
pub const QSLT_VO: u8 = 0x7;
pub const QSLT_BEACON: u8 = 0x10;
pub const QSLT_HIGH: u8 = 0x11;
pub const QSLT_MGNT: u8 = 0x12;
pub const QSLT_CMD: u8 = 0x13;

/// `DESC_RATE*` boundaries (`rtlwifi/wifi.h`).
pub const DESC_RATE54M: u8 = 0x0b;
pub const DESC_RATEMCS0: u8 = 0x0c;
pub const DESC_RATEVHT1SS_MCS0: u8 = 0x2c;
pub const DESC_RATEVHT1SS_MCS9: u8 = 0x35;
pub const DESC_RATEVHT2SS_MCS0: u8 = 0x36;
pub const DESC_RATEVHT2SS_MCS9: u8 = 0x3f;

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

/// 64-byte TX ring entry.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    pub dw: [u32; 16],
}

/// Inputs for the first-segment data/management path of
/// `rtl8821ae_tx_fill_desc` (non-early-mode, single-buffer MPDU).
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
    /// Short GI for HT/VHT rates, short preamble otherwise.
    pub short: bool,
    /// `rtl8821ae_bw_mapping`: 0 = 20, 1 = 40, 2 = 80 MHz.
    pub data_bw: u8,
    /// `rtl8821ae_sc_mapping` sub-carrier.
    pub sub_carrier: u8,
    pub ampdu: bool,
    pub ampdu_density: u8,
    /// 0 none, 1 WEP/TKIP, 3 CCMP.
    pub sec_type: u8,
    pub qos_data: bool,
    pub seq: u16,
    pub multicast: bool,
    /// `rtl_set_tx_report`: request a C2H TX report carrying `sw_define`.
    pub tx_report: Option<u16>,
    pub buffer_len: u16,
    pub buffer_addr: u32,
}

impl TxDesc {
    /// Fill the descriptor exactly as `rtl8821ae_tx_fill_desc` does for a
    /// first+last segment frame, leaving OWN clear. The caller publishes the
    /// buffer and then calls [`TxDesc::set_own`] after a write barrier.
    pub fn fill(p: &TxParams) -> Self {
        let mut d = Self::default();
        let dw = &mut d.dw;
        put(&mut dw[0], HWDESC_HEADER_LEN, 16, 8);
        put(&mut dw[4], u32::from(p.hw_rate), 0, 7);
        put(&mut dw[5], p.short as u32, 4, 1);
        if p.ampdu {
            put(&mut dw[2], 1, 12, 1);
            put(&mut dw[3], 0x1f, 17, 5);
        }
        put(&mut dw[9], u32::from(p.seq), 12, 12);
        put(&mut dw[5], u32::from(p.data_bw), 5, 2);
        put(&mut dw[5], u32::from(p.sub_carrier), 0, 4);
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
        if p.multicast {
            put(&mut dw[0], 1, 24, 1);
        }
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
    pub fn sw_define(&self) -> Option<u16> {
        (get(self.dw[2], 19, 1) != 0).then(|| get(self.dw[6], 0, 12) as u16)
    }
}

/// Decoded `rtl8821ae_rx_query_desc` status fields.
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
    /// 0 = 20, 1 = 40, 2 = 80 MHz.
    pub bw: u8,
    pub tsfl: u32,
    /// `get_rx_status_desc_rpt_sel`: the buffer is a C2H packet.
    pub c2h: bool,
    pub pattern_match: bool,
    pub unicast_match: bool,
    pub magic_match: bool,
}

impl RxStatus {
    /// Decode an RX status descriptor that the driver owns (OWN clear).
    /// Returns `None` while hardware still owns it.
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
    pub fn is_ht(&self) -> bool {
        (DESC_RATEMCS0..DESC_RATEVHT1SS_MCS0).contains(&self.rate)
    }
    pub fn is_vht(&self) -> bool {
        self.rate >= DESC_RATEVHT1SS_MCS0
    }
    /// `rtl8821ae_get_rx_vht_nss`.
    pub fn vht_nss(&self) -> u8 {
        match self.rate {
            DESC_RATEVHT1SS_MCS0..=DESC_RATEVHT1SS_MCS9 => 1,
            DESC_RATEVHT2SS_MCS0..=DESC_RATEVHT2SS_MCS9 => 2,
            _ => 0,
        }
    }
    /// `rtl8821ae_rx_query_desc` wake reason: pattern BIT2, magic BIT1,
    /// unicast BIT0.
    pub fn wake_match(&self) -> u8 {
        if self.pattern_match {
            1 << 2
        } else if self.magic_match {
            1 << 1
        } else if self.unicast_match {
            1
        } else {
            0
        }
    }
}

/// Bytes of the RX PHY status (`rx_fwinfo_8821ae` / `phy_status_rpt`
/// overlay) read for the station PWDB: `pwdb_all` (byte 4) and
/// `cfosho[0]` (byte 5, the CCK AGC report).
pub const PHY_STATUS_PWDB_BYTES: usize = 6;

/// `rtl8821ae/trx.c::query_rxphystatus` `rx_pwdb_all` for the RTL8821AE
/// (`hw_type != HARDWARE_TYPE_RTL8812AE`). `phy` starts at
/// `skb->data + rx_bufshift` (Linux's `p_drvinfo`); `cck` is
/// `RTL8821AE_RX_HAL_IS_CCK_RATE(rate)`.
///
/// CCK: `cck_agc_rpt = p_phystrpt->cfosho[0]`, LNA `[7:5]`, VGA `[4:0]`,
/// `pout = -6`; LNA 3, 6 and 7 have no case, so `rx_pwr_all` keeps its
/// initial 0 (percentage 100) exactly as Linux. The 8821 branch applies no
/// `cck_high_power` correction. OFDM/HT/VHT: `((pwdb_all >> 1) & 0x7f) - 110`.
/// Both go through `rtl_query_rxpwrpercentage`.
pub fn rx_pwdb(phy: &[u8; PHY_STATUS_PWDB_BYTES], cck: bool) -> u8 {
    use crate::rtlwifi::rate_adaptive::rx_power_percentage;
    if !cck {
        return rx_power_percentage(i32::from((phy[4] >> 1) & 0x7f) - 110);
    }
    let agc = phy[5];
    let vga = i32::from(agc & 0x1f);
    let pout = -6;
    let power = match (agc & 0xe0) >> 5 {
        5 => pout - 32 - 2 * vga,
        4 => pout - 24 - 2 * vga,
        2 => pout - 11 - 2 * vga,
        1 => pout + 5 - 2 * vga,
        0 => pout + 21 - 2 * vga,
        _ => 0,
    };
    rx_power_percentage(power)
}

/// `RTL8821AE_RX_HAL_IS_CCK_RATE`: `DESC_RATE1M..=DESC_RATE11M`.
pub const fn is_cck(rate: u8) -> bool {
    rate <= 3
}

/// Re-arm an RX descriptor (`rtl8821ae_set_desc` HW_DESC_RXBUFF_ADDR /
/// RXPKT_LEN / RXOWN, plus EOR on the last entry).
pub fn rx_arm(dw: &mut [u32; 8], buffer: u32, len: u16, last: bool) {
    *dw = [0; 8];
    dw[6] = buffer;
    put(&mut dw[0], u32::from(len), 0, 14);
    put(&mut dw[0], last as u32, 30, 1);
    put(&mut dw[0], 1, 31, 1);
}
