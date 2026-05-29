//! RTL8XXXU RX descriptor parsing.
//!
//! Each received bulk-IN URB starts with an RX descriptor that the
//! firmware fills in before handing the buffer to the host. There are
//! two on-the-wire variants:
//!
//! - **RxDesc16** (16 bytes) — used by 8188EU, 8192EU, 8723BU and other
//!   gen1 chips. Source: `rtl8xxxu.h::rtl8xxxu_rxdesc16` L135.
//! - **RxDesc24** (24 bytes) — used by 8821CU, 8822BU and other gen2
//!   chips. Source: `rtl8xxxu.h::rtl8xxxu_rxdesc24` L275.
//!
//! After the descriptor, the host data optionally contains a
//! `drvinfo_sz × 8` byte chunk of PHY status (RSSI / EVM / etc), then
//! the 802.11 frame body.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_parse_rxdesc16`
//!   (~L4660).
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_parse_rxdesc24`
//!   (~L4800).

#![allow(dead_code)]

use super::regs::*;

/// Decoded RX descriptor (16-byte variant).
#[derive(Copy, Clone, Debug, Default)]
pub struct RxDesc16Decoded {
    /// Raw 802.11 MPDU length in bytes (DW0 bits[13:0]).
    pub pktlen: u16,
    /// CRC error flag (DW0 bit 14).
    pub crc32_err: bool,
    /// ICV error flag (DW0 bit 15).
    pub icv_err: bool,
    /// Length of driver info section (DW0 bits[19:16], × 8 = byte count).
    pub drvinfo_sz_words: u8,
    /// Cipher suite (DW0 bits[22:20]).
    pub security: u8,
    /// Whether the frame has a QoS header (DW0 bit 23).
    pub qos: bool,
    /// PHY-statistics present (DW0 bit 26).
    pub phy_stats: bool,
    /// MACID (DW1 bits[4:0]).
    pub macid: u8,
    /// TID (DW1 bits[8:5]).
    pub tid: u8,
    /// Type bits (DW1 bits[30:29]).
    pub frame_type: u8,
    /// Sequence number (DW2 bits[11:0]).
    pub seq: u16,
    /// Receive rate index (DW3 bits[5:0]).
    pub rxmcs: u8,
    /// HT bit (DW3 bit 6).
    pub rxht: bool,
}

impl RxDesc16Decoded {
    pub const SIZE: usize = RXDESC_SIZE_16;

    /// Parse the 16-byte descriptor from the first 16 bytes of `bytes`.
    /// Returns `None` if the slice is short.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let dw0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let dw1 = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let dw2 = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let dw3 = u32::from_le_bytes(bytes[12..16].try_into().ok()?);

        Some(Self {
            pktlen: (dw0 & 0x3FFF) as u16,
            crc32_err: (dw0 & (1 << 14)) != 0,
            icv_err: (dw0 & (1 << 15)) != 0,
            drvinfo_sz_words: ((dw0 >> 16) & 0x0F) as u8,
            security: ((dw0 >> 20) & 0x07) as u8,
            qos: (dw0 & (1 << 23)) != 0,
            phy_stats: (dw0 & (1 << 26)) != 0,
            macid: (dw1 & 0x1F) as u8,
            tid: ((dw1 >> 5) & 0x0F) as u8,
            frame_type: ((dw1 >> 29) & 0x03) as u8,
            seq: (dw2 & 0x0FFF) as u16,
            rxmcs: (dw3 & 0x3F) as u8,
            rxht: (dw3 & (1 << 6)) != 0,
        })
    }

    /// Total bytes consumed by descriptor + drvinfo (no padding).
    pub fn header_len(&self) -> usize {
        Self::SIZE + (self.drvinfo_sz_words as usize) * 8
    }
}

/// Decoded RX descriptor (24-byte variant).
#[derive(Copy, Clone, Debug, Default)]
pub struct RxDesc24Decoded {
    /// MPDU length (DW0 bits[13:0]).
    pub pktlen: u16,
    /// CRC error.
    pub crc32_err: bool,
    /// ICV error.
    pub icv_err: bool,
    /// Driver info size in 8-byte words.
    pub drvinfo_sz_words: u8,
    /// QoS bit.
    pub qos: bool,
    /// MACID.
    pub macid: u8,
    /// Rate-id (DW3 bits[6:0]).
    pub rxrate: u8,
    /// HT bit.
    pub rxht: bool,
    /// VHT bit (only on rxdesc24).
    pub rxvht: bool,
    /// Sequence number.
    pub seq: u16,
}

impl RxDesc24Decoded {
    pub const SIZE: usize = RXDESC_SIZE_24;

    /// Parse the 24-byte descriptor.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let dw0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let dw1 = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let dw2 = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let dw3 = u32::from_le_bytes(bytes[12..16].try_into().ok()?);

        Some(Self {
            pktlen: (dw0 & 0x3FFF) as u16,
            crc32_err: (dw0 & (1 << 14)) != 0,
            icv_err: (dw0 & (1 << 15)) != 0,
            drvinfo_sz_words: ((dw0 >> 16) & 0x0F) as u8,
            qos: (dw0 & (1 << 23)) != 0,
            macid: (dw1 & 0x7F) as u8,
            rxrate: (dw3 & 0x7F) as u8,
            rxht: (dw3 & (1 << 7)) != 0,
            rxvht: (dw3 & (1 << 8)) != 0,
            seq: (dw2 & 0x0FFF) as u16,
        })
    }

    /// Bytes consumed by descriptor + drvinfo.
    pub fn header_len(&self) -> usize {
        Self::SIZE + (self.drvinfo_sz_words as usize) * 8
    }
}

/// Slice of an RX URB into (descriptor, drvinfo, mpdu).
pub struct RxFrame<'a> {
    pub drvinfo: &'a [u8],
    pub mpdu: &'a [u8],
}

/// Slice an URB buffer using a 16-byte descriptor.
pub fn slice_urb16<'a>(bytes: &'a [u8], desc: &RxDesc16Decoded) -> Option<RxFrame<'a>> {
    let hdr = desc.header_len();
    let total = hdr + desc.pktlen as usize;
    if bytes.len() < total {
        return None;
    }
    Some(RxFrame {
        drvinfo: &bytes[RxDesc16Decoded::SIZE..hdr],
        mpdu: &bytes[hdr..total],
    })
}

/// Slice an URB buffer using a 24-byte descriptor.
pub fn slice_urb24<'a>(bytes: &'a [u8], desc: &RxDesc24Decoded) -> Option<RxFrame<'a>> {
    let hdr = desc.header_len();
    let total = hdr + desc.pktlen as usize;
    if bytes.len() < total {
        return None;
    }
    Some(RxFrame {
        drvinfo: &bytes[RxDesc24Decoded::SIZE..hdr],
        mpdu: &bytes[hdr..total],
    })
}
