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
#[allow(missing_debug_implementations)] // TODO(narf): no Debug impl yet
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

// ──────────────────────────────────────────────────────────────────────
// RX ring dispatch
//
// Each USB transfer on the bulk-IN endpoint can contain zero, one, or
// many 802.11 MPDUs each prefixed with a 16-byte (gen1) or 24-byte
// (gen2) RxDesc and an optional drvinfo blob. `pump_rx` decodes the
// transfer into per-frame slices and dispatches each via the caller-
// supplied closure.
//
// Source: `core.c::rtl8xxxu_rx_complete` ~L4400 (gen1) — the Linux
// driver walks one URB at a time popping `pkt_len` + drvinfo +
// 8-byte alignment per frame.
// ──────────────────────────────────────────────────────────────────────

/// Generation flag: which RxDesc layout the chip uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxDescGen {
    /// 8188EU / 8192EU / 8723BU — 16-byte descriptor.
    Gen1,
    /// 8821CU / 8822BU — 24-byte descriptor.
    Gen2,
}

/// Align `n` up to the next multiple of 8 (USB-side per-MPDU padding).
const fn align_up8(n: usize) -> usize {
    (n + 7) & !7
}

/// Walk a bulk-IN transfer buffer and invoke `on_frame` once per
/// decoded MPDU. Returns the number of MPDUs dispatched.
///
/// Source: `core.c::rtl8xxxu_rx_complete` ~L4400 (16-byte path) and
/// ~L4800 (24-byte path). Linux uses 8-byte padding between MPDUs
/// inside a single URB.
pub fn pump_rx_buf<F>(gen: RxDescGen, buf: &[u8], mut on_frame: F) -> usize
where
    F: FnMut(&[u8]),
{
    let mut off = 0usize;
    let mut n_frames = 0usize;
    while off + descriptor_size(gen) <= buf.len() {
        let (header_len, pkt_len) = match gen {
            RxDescGen::Gen1 => {
                let desc = match RxDesc16Decoded::parse(&buf[off..]) {
                    Some(d) => d,
                    None => break,
                };
                (desc.header_len(), desc.pktlen as usize)
            }
            RxDescGen::Gen2 => {
                let desc = match RxDesc24Decoded::parse(&buf[off..]) {
                    Some(d) => d,
                    None => break,
                };
                (desc.header_len(), desc.pktlen as usize)
            }
        };
        // Trailing zero-pad / runt: a descriptor with pktlen == 0 ends
        // the URB regardless of what bytes follow.
        if pkt_len == 0 {
            break;
        }
        let total = header_len + pkt_len;
        if off + total > buf.len() {
            break;
        }
        on_frame(&buf[off + header_len..off + total]);
        n_frames += 1;
        // Linux advances by 8-byte-aligned MPDU end so the next desc
        // lands on an 8-byte boundary inside the URB.
        let advance = align_up8(total);
        if advance == 0 {
            break;
        }
        off += advance;
    }
    n_frames
}

const fn descriptor_size(gen: RxDescGen) -> usize {
    match gen {
        RxDescGen::Gen1 => RxDesc16Decoded::SIZE,
        RxDescGen::Gen2 => RxDesc24Decoded::SIZE,
    }
}

/// Build a synthetic gen1 RX URB containing one MPDU. Used by smokes
/// to drive `pump_rx_buf` without live hardware.
pub fn build_synthetic_gen1_urb(mpdu: &[u8]) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec::Vec::with_capacity(RxDesc16Decoded::SIZE + mpdu.len() + 8);
    let mut dw0 = (mpdu.len() as u32) & 0x3FFF;
    // drvinfo_sz_words = 0.
    let _ = &mut dw0;
    buf.extend_from_slice(&dw0.to_le_bytes()); // DW0
    buf.extend_from_slice(&0u32.to_le_bytes()); // DW1
    buf.extend_from_slice(&0u32.to_le_bytes()); // DW2
    buf.extend_from_slice(&0u32.to_le_bytes()); // DW3
    buf.extend_from_slice(mpdu);
    let pad = align_up8(buf.len()) - buf.len();
    buf.extend(core::iter::repeat_n(0u8, pad));
    buf
}

/// Build a synthetic gen1 URB with `count` MPDUs concatenated.
pub fn build_synthetic_gen1_urb_multi(mpdus: &[&[u8]]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    for m in mpdus {
        out.extend_from_slice(&build_synthetic_gen1_urb(m));
    }
    out
}

extern crate alloc;
