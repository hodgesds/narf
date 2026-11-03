// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE TX/RX descriptors (legacy linked-ring flow).
//!
//! Linux `rtl8192ce/trx.{c,h}`: 64-byte TX ring entries whose first 40
//! bytes (`clear_pci_tx_desc_content` bound, `TX_DESC_NEXT_DESC_OFFSET`)
//! are the hardware descriptor and whose dword 10 is the next-descriptor
//! link; 32-byte RX descriptors with the buffer at dword 6. The ring
//! geometry is therefore the RTL8188EE one (`prepare::Chip::Rtl8192ce`);
//! the field layout below is the 92C one.

/// `TX_DESC_SIZE`.
pub const TX_DESC_SIZE: usize = 64;
/// `TX_DESC_NEXT_DESC_OFFSET`: bytes cleared/filled per frame.
pub const TX_DESC_NEXT_DESC_OFFSET: usize = 40;
/// `RX_DESC_SIZE`.
pub const RX_DESC_SIZE: usize = 32;
/// `RX_DRV_INFO_SIZE_UNIT`.
pub const RX_DRV_INFO_SIZE_UNIT: usize = 8;
/// `USB_HWDESC_HEADER_LEN` (the TX descriptor offset written by the PCI
/// driver too).
pub const HWDESC_HEADER_LEN: u32 = 32;

/// `rtl_desc_qsel` (`def.h`).
pub const QSLT_BK: u8 = 0x2;
pub const QSLT_BE: u8 = 0x0;
pub const QSLT_VI: u8 = 0x5;
pub const QSLT_VO: u8 = 0x7;
pub const QSLT_BEACON: u8 = 0x10;
pub const QSLT_HIGH: u8 = 0x11;
pub const QSLT_MGNT: u8 = 0x12;
pub const QSLT_CMD: u8 = 0x13;

/// `rtl_desc92c_rate` (`def.h`).
pub const DESC_RATE1M: u8 = 0x00;
pub const DESC_RATE11M: u8 = 0x03;
pub const DESC_RATE24M: u8 = 0x08;
pub const DESC_RATE54M: u8 = 0x0b;
pub const DESC_RATEMCS0: u8 = 0x0c;
pub const DESC_RATEMCS15: u8 = 0x1b;

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

/// Inputs of the single-segment (first + last) `rtl92ce_tx_fill_desc` path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxParams {
    pub pkt_size: u16,
    /// `_rtl92ce_map_hwqueue_to_fwqueue`.
    pub queue_sel: u8,
    /// Descriptor `MACID` / `RATE_ID` exactly as written: with
    /// `dm.useramask` these are `tcb_desc->mac_id` / `ratr_index`, otherwise
    /// `ratr_index` / `0xc + ratr_index`.
    pub macid: u8,
    pub rate_id: u8,
    /// `tcb_desc->hw_rate` (`DESC_RATE*`).
    pub hw_rate: u8,
    pub use_driver_rate: bool,
    /// Short GI (HT) or short preamble (legacy).
    pub short: bool,
    /// 40 MHz association (`mac->bw_40`) and the frame's own bandwidth.
    pub bw_40: bool,
    pub packet_bw_40: bool,
    /// `mac->cur_40_prime_sc` for 20 MHz frames inside a 40 MHz BSS.
    pub prime_sc: u8,
    pub ampdu: bool,
    pub ampdu_density: u8,
    /// 0 none, 1 WEP/TKIP, 3 CCMP.
    pub sec_type: u8,
    pub qos_data: bool,
    /// `ppsc->fwctrl_lps` (hardware sequence for non-QoS frames).
    pub fwctrl_lps: bool,
    pub seq: u16,
    pub multicast: bool,
    /// `_rtl_query_protection_mode`: 0 none, 1 RTS/CTS, 2 CTS-to-self, both
    /// at `DESC_RATE24M` with long preamble.
    pub protection: u8,
    pub buffer_addr: u32,
}

/// The 40 hardware bytes of a 92C TX descriptor.
pub type TxWords = [u32; TX_DESC_NEXT_DESC_OFFSET / 4];

/// `rtl92ce_tx_fill_desc` for a first+last segment frame with OWN clear.
/// The caller keeps the ring's dword 10 link, publishes the buffer and sets
/// OWN ([`set_own`]) after a write barrier.
pub fn fill(p: &TxParams) -> TxWords {
    let mut dw = [0u32; 10];
    put(&mut dw[0], HWDESC_HEADER_LEN, 16, 8);
    put(&mut dw[5], u32::from(p.hw_rate), 0, 6);
    put(&mut dw[5], p.short as u32, 6, 1);
    if p.ampdu {
        put(&mut dw[1], 1, 5, 1);
        put(&mut dw[6], 0x14, 11, 5);
    }
    put(&mut dw[3], u32::from(p.seq), 16, 12);
    let (rts, cts) = (p.protection != 0, p.protection == 2);
    put(&mut dw[4], u32::from(rts && !cts), 12, 1);
    put(&mut dw[4], u32::from(rts || cts), 13, 1);
    put(&mut dw[4], u32::from(cts), 11, 1);
    put(&mut dw[4], 0, 30, 2);
    let rts_rate = if rts { DESC_RATE24M } else { 0 };
    put(&mut dw[4], u32::from(rts_rate), 0, 5);
    put(&mut dw[4], 0, 27, 1);
    put(&mut dw[4], 0, 28, 2);
    put(&mut dw[4], 0, 26, 1);
    if p.bw_40 {
        if p.packet_bw_40 {
            put(&mut dw[4], 1, 25, 1);
            put(&mut dw[4], 3, 20, 2);
        } else {
            put(&mut dw[4], u32::from(p.prime_sc), 20, 2);
        }
    }
    put(&mut dw[0], u32::from(p.pkt_size), 0, 16);
    put(&mut dw[2], u32::from(p.ampdu_density), 20, 3);
    put(&mut dw[1], u32::from(p.sec_type), 22, 2);
    put(&mut dw[1], u32::from(p.queue_sel), 8, 5);
    put(&mut dw[5], 0x1f, 8, 5);
    put(&mut dw[5], 0xf, 13, 4);
    put(&mut dw[4], p.use_driver_rate as u32, 8, 1);
    put(&mut dw[0], 1, 27, 1);
    put(&mut dw[0], 1, 26, 1);
    put(&mut dw[7], u32::from(p.pkt_size), 0, 16);
    dw[8] = p.buffer_addr;
    put(&mut dw[1], u32::from(p.rate_id), 16, 4);
    put(&mut dw[1], u32::from(p.macid), 0, 5);
    if !p.qos_data && p.fwctrl_lps {
        put(&mut dw[4], 1, 7, 1);
        put(&mut dw[3], 8, 28, 4);
    }
    if p.multicast {
        put(&mut dw[0], 1, 24, 1);
    }
    dw
}

/// `rtl92ce_tx_fill_cmddesc`: beacon-queue firmware packet (reserved page),
/// 1M, `RATE_ID 7`, MACID 0, driver rate, hardware sequence for non-QoS —
/// OWN set by Linux in the same fill (the caller writes it last).
pub fn fill_cmd(len: u16, buffer_addr: u32, qos_data: bool) -> TxWords {
    let mut dw = [0u32; 10];
    put(&mut dw[0], HWDESC_HEADER_LEN, 16, 8);
    put(&mut dw[5], u32::from(DESC_RATE1M), 0, 6);
    put(&mut dw[1], u32::from(QSLT_BEACON), 8, 5);
    put(&mut dw[0], 1, 27, 1);
    put(&mut dw[0], 1, 26, 1);
    put(&mut dw[7], u32::from(len), 0, 16);
    dw[8] = buffer_addr;
    put(&mut dw[1], 7, 16, 4);
    put(&mut dw[0], u32::from(len), 0, 16);
    put(&mut dw[4], 1, 8, 1);
    if !qos_data {
        put(&mut dw[4], 1, 7, 1);
        put(&mut dw[3], 8, 28, 4);
    }
    dw
}

/// `set_tx_desc_own`.
pub fn set_own(dw: &mut TxWords, own: bool) {
    put(&mut dw[0], own as u32, 31, 1);
}
/// `get_tx_desc_own` (`rtl92ce_is_tx_desc_closed` is `!own`).
pub fn own(dw0: u32) -> bool {
    get(dw0, 31, 1) != 0
}
pub fn pkt_size(dw: &TxWords) -> u16 {
    get(dw[0], 0, 16) as u16
}
pub fn queue_sel(dw: &TxWords) -> u8 {
    get(dw[1], 8, 5) as u8
}
pub fn tx_rate(dw: &TxWords) -> u8 {
    get(dw[5], 0, 6) as u8
}

/// Decoded `rtl92ce_rx_query_desc` status fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxStatus {
    pub length: u16,
    pub drvinfo_size: usize,
    pub shift: usize,
    pub crc: bool,
    pub icv: bool,
    pub decrypted: bool,
    pub physt: bool,
    /// `rxmcs` (`DESC_RATE*`).
    pub rate: u8,
    pub ht: bool,
    pub short_preamble: bool,
    pub ampdu: bool,
    pub first_ampdu: bool,
    pub bw_40: bool,
    pub tsfl: u32,
}

impl RxStatus {
    /// Decode a driver-owned RX descriptor; `None` while OWN is set.
    pub fn parse(dw: &[u32; 8]) -> Option<Self> {
        if get(dw[0], 31, 1) != 0 {
            return None;
        }
        let ampdu = get(dw[1], 14, 1) != 0;
        Some(Self {
            length: get(dw[0], 0, 14) as u16,
            crc: get(dw[0], 14, 1) != 0,
            icv: get(dw[0], 15, 1) != 0,
            drvinfo_size: get(dw[0], 16, 4) as usize * RX_DRV_INFO_SIZE_UNIT,
            shift: get(dw[0], 24, 2) as usize & 3,
            physt: get(dw[0], 26, 1) != 0,
            decrypted: get(dw[0], 27, 1) == 0,
            ampdu,
            first_ampdu: ampdu && get(dw[1], 15, 1) != 0,
            rate: get(dw[3], 0, 6) as u8,
            ht: get(dw[3], 6, 1) != 0,
            short_preamble: get(dw[3], 8, 1) != 0,
            bw_40: get(dw[3], 9, 1) != 0,
            tsfl: dw[5],
        })
    }
    /// Byte offset of the 802.11 header in the RX buffer (the 92CE RX
    /// descriptor is in the ring, not in front of the buffer).
    pub fn payload_offset(&self) -> usize {
        self.drvinfo_size + self.shift
    }
    pub fn hw_error(&self) -> bool {
        self.crc || self.icv
    }
    /// `RX_HAL_IS_CCK_RATE`.
    pub fn is_cck(&self) -> bool {
        self.rate <= DESC_RATE11M
    }
}

/// Re-arm an RX descriptor (`rtl92ce_set_desc` HW_DESC_RXBUFF_ADDR /
/// RXPKT_LEN / RXOWN, EOR on the last entry).
pub fn rx_arm(dw: &mut [u32; 8], buffer: u32, len: u16, last: bool) {
    *dw = [0; 8];
    dw[6] = buffer;
    put(&mut dw[0], u32::from(len), 0, 14);
    put(&mut dw[0], last as u32, 30, 1);
    put(&mut dw[0], 1, 31, 1);
}
