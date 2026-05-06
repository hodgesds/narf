//! Bluetooth Mesh — Network and Lower Transport layer codecs (clean-room).
//!
//! References (public-only):
//! - "Bluetooth Mesh Profile Specification, Version 1.1" (Sep 2023) —
//!   Bluetooth SIG. Public adopted document.
//!   §3.4.2 (Network PDU layout — IVI/NID + obfuscated header
//!   {CTL/TTL/SEQ/SRC} + encrypted DST+TransportPDU).
//!   §3.5.2.1 (Lower Transport — unsegmented Access PDU, AKF/AID).
//!   §3.5.2.2 (Lower Transport — segmented Access PDU: SegN/SegO/
//!   SeqZero packing).
//!   §3.7.3 (Access-layer Opcode encoding — 1/2/3 byte forms).
//! - "Bluetooth Mesh Model Specification, Version 1.1" — Bluetooth
//!   SIG. Public. Composition Data Page 0 layout (CID/PID/VID/CRPL/
//!   Features + per-element list).
//!
//! No GPL Linux source consulted.
//!
//! ## Network PDU header (§3.4.2)
//!
//! ```text
//!   byte 0:
//!     bit  7    = IVI (least-significant bit of IV Index)
//!     bits 6..0 = NID (Network Identifier)
//!   byte 1:
//!     bit  7    = CTL (1 = Control message, 0 = Access message)
//!     bits 6..0 = TTL (Time-To-Live, 0..127)
//!   bytes 2..4 = SEQ (24-bit big-endian sequence number)
//!   bytes 5..6 = SRC address (16-bit big-endian)
//! ```
//!
//! ## Lower Transport — segmented Access PDU (§3.5.2.2)
//!
//! ```text
//!   byte 0:
//!     bit  7    = SEG (1 = segmented)
//!     bit  6    = AKF (1 = Application Key flag)
//!     bits 5..0 = AID
//!   bytes 1..2 = bit15 (SZMIC) | bits14..0 (SeqZero — 13 bits)
//!                — actually: SZMIC at bit 23, SeqZero at bits 22..10,
//!                  SegO at bits 9..5, SegN at bits 4..0 (3-byte block).
//!   bytes 1..3 = SZMIC | SeqZero | SegO | SegN packed BE
//! ```
//!
//! ## Access-layer Opcode (§3.7.3)
//!
//! Variable-length opcode at the start of the Access PDU:
//!
//! ```text
//!   1 byte   form: top bit 0 → opcode = byte (0x00..0x7F).
//!                  byte 0x7F is reserved. Opcode 0x00 is also reserved.
//!   2 byte   form: byte 0 in 0x80..0xBF, top 2 bits = 0b10. opcode = 14 bits
//!                  packed as (byte0 & 0x3F) << 8 | byte1.
//!   3 byte   form: byte 0 in 0xC0..0xFF, top 2 bits = 0b11. opcode = 22 bits:
//!                  (byte0 & 0x3F) at bits 21..16, byte1 at 15..8, byte2 at 7..0.
//!                  These messages also carry a Vendor Company ID at bytes 1..2 LE
//!                  with the model-specific opcode in byte 0[5..0].
//! ```

use alloc::vec::Vec;

// ── Network PDU ────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MeshError {
    /// Buffer too short for the requested header / payload.
    Short,
    /// Reserved opcode value (0x00 or 0x7F).
    BadOpcode,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkHeader {
    /// Least-significant bit of the IV Index.
    pub ivi: u8,
    /// 7-bit Network ID (low 7 bits of byte 0).
    pub nid: u8,
    /// Control vs Access flag.
    pub ctl: bool,
    /// 7-bit Time-To-Live.
    pub ttl: u8,
    /// 24-bit Sequence Number.
    pub seq: u32,
    pub src: u16,
    pub dst: u16,
}

impl NetworkHeader {
    /// Encode the 9-byte cleartext network header. The IVI/NID byte
    /// is *not* obfuscated here — encryption is the caller's
    /// responsibility (Network Encryption Key + privacy mask, §3.8).
    pub fn encode(&self) -> [u8; 9] {
        [
            ((self.ivi & 0x01) << 7) | (self.nid & 0x7F),
            (if self.ctl { 0x80 } else { 0 }) | (self.ttl & 0x7F),
            ((self.seq >> 16) & 0xFF) as u8,
            ((self.seq >> 8) & 0xFF) as u8,
            (self.seq & 0xFF) as u8,
            (self.src >> 8) as u8,
            (self.src & 0xFF) as u8,
            (self.dst >> 8) as u8,
            (self.dst & 0xFF) as u8,
        ]
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MeshError> {
        if buf.len() < 9 {
            return Err(MeshError::Short);
        }
        Ok(Self {
            ivi: (buf[0] >> 7) & 0x01,
            nid: buf[0] & 0x7F,
            ctl: (buf[1] & 0x80) != 0,
            ttl: buf[1] & 0x7F,
            seq: ((buf[2] as u32) << 16) | ((buf[3] as u32) << 8) | (buf[4] as u32),
            src: u16::from_be_bytes([buf[5], buf[6]]),
            dst: u16::from_be_bytes([buf[7], buf[8]]),
        })
    }
}

// ── Lower Transport — segmented Access PDU (§3.5.2.2) ─────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SegmentedAccessHeader {
    /// SEG bit (always 1 for segmented). Surfaced for symmetry.
    pub seg: bool,
    /// Application Key Flag — 1 = AID identifies an AppKey.
    pub akf: bool,
    /// Application Identifier (6 bits).
    pub aid: u8,
    /// Size of the MIC field after reassembly: false = 32-bit, true = 64-bit.
    pub szmic: bool,
    /// SeqZero — low 13 bits of the SEQ at fragmentation time.
    pub seq_zero: u16,
    /// 5-bit Segment Offset.
    pub seg_o: u8,
    /// 5-bit final Segment Number (0..31). N+1 segments total.
    pub seg_n: u8,
}

impl SegmentedAccessHeader {
    /// Encode the 4-byte Lower Transport header.
    pub fn encode(&self) -> [u8; 4] {
        let b0 = (if self.seg { 0x80 } else { 0 })
            | (if self.akf { 0x40 } else { 0 })
            | (self.aid & 0x3F);
        let packed: u32 = ((self.szmic as u32) << 23)
            | (((self.seq_zero & 0x1FFF) as u32) << 10)
            | (((self.seg_o & 0x1F) as u32) << 5)
            | (self.seg_n & 0x1F) as u32;
        [
            b0,
            ((packed >> 16) & 0xFF) as u8,
            ((packed >> 8) & 0xFF) as u8,
            (packed & 0xFF) as u8,
        ]
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MeshError> {
        if buf.len() < 4 {
            return Err(MeshError::Short);
        }
        let b0 = buf[0];
        let packed = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        Ok(Self {
            seg: (b0 & 0x80) != 0,
            akf: (b0 & 0x40) != 0,
            aid: b0 & 0x3F,
            szmic: ((packed >> 23) & 1) != 0,
            seq_zero: ((packed >> 10) & 0x1FFF) as u16,
            seg_o: ((packed >> 5) & 0x1F) as u8,
            seg_n: (packed & 0x1F) as u8,
        })
    }
}

// ── Access-layer Opcode (§3.7.3) ───────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AccessOpcode {
    /// 1-byte opcode in 0x01..=0x7E (0x00 and 0x7F reserved).
    OneByte(u8),
    /// 2-byte opcode in 0b10_00_0000..=0b10_11_1111. 14-bit value.
    TwoByte(u16),
    /// 3-byte vendor opcode: high 6 bits of byte 0 + 16-bit Company ID.
    /// `op` carries the model-specific code (low 6 bits of byte 0);
    /// `company_id` is the Bluetooth-SIG-assigned vendor 16-bit value.
    Vendor { op: u8, company_id: u16 },
}

impl AccessOpcode {
    /// Encode the opcode bytes. Returns the prefix that goes at the
    /// start of an Access PDU.
    pub fn encode(self) -> Vec<u8> {
        match self {
            AccessOpcode::OneByte(op) => alloc::vec![op],
            AccessOpcode::TwoByte(v) => {
                alloc::vec![0x80 | ((v >> 8) & 0x3F) as u8, (v & 0xFF) as u8]
            }
            AccessOpcode::Vendor { op, company_id } => alloc::vec![
                0xC0 | (op & 0x3F),
                (company_id & 0xFF) as u8,
                (company_id >> 8) as u8,
            ],
        }
    }

    /// Decode a leading opcode and return (opcode, bytes_consumed).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), MeshError> {
        if buf.is_empty() {
            return Err(MeshError::Short);
        }
        let b0 = buf[0];
        match b0 & 0xC0 {
            0x80 => {
                if buf.len() < 2 {
                    return Err(MeshError::Short);
                }
                let v = (((b0 & 0x3F) as u16) << 8) | (buf[1] as u16);
                Ok((AccessOpcode::TwoByte(v), 2))
            }
            0xC0 => {
                if buf.len() < 3 {
                    return Err(MeshError::Short);
                }
                Ok((
                    AccessOpcode::Vendor {
                        op: b0 & 0x3F,
                        company_id: u16::from_le_bytes([buf[1], buf[2]]),
                    },
                    3,
                ))
            }
            _ => {
                if b0 == 0 || b0 == 0x7F {
                    return Err(MeshError::BadOpcode);
                }
                Ok((AccessOpcode::OneByte(b0), 1))
            }
        }
    }
}

// ── Composition Data Page 0 (Mesh Model Spec §4.2.1.1) ────────────

/// Mandatory composition-data fields a node returns when queried for
/// Page 0 of its composition data.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompositionHeader {
    /// 16-bit Company Identifier (assigned by the SIG).
    pub cid: u16,
    /// 16-bit Product Identifier (vendor-assigned).
    pub pid: u16,
    /// 16-bit Version Identifier.
    pub vid: u16,
    /// Capacity of the Replay Protection List (in number of entries).
    pub crpl: u16,
    /// 16-bit Features bitmap (bit 0 Relay, bit 1 Proxy, bit 2 Friend,
    /// bit 3 Low Power).
    pub features: u16,
}

impl CompositionHeader {
    pub const FEATURE_RELAY: u16 = 1 << 0;
    pub const FEATURE_PROXY: u16 = 1 << 1;
    pub const FEATURE_FRIEND: u16 = 1 << 2;
    pub const FEATURE_LOW_POWER: u16 = 1 << 3;

    pub fn encode(&self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0..2].copy_from_slice(&self.cid.to_le_bytes());
        out[2..4].copy_from_slice(&self.pid.to_le_bytes());
        out[4..6].copy_from_slice(&self.vid.to_le_bytes());
        out[6..8].copy_from_slice(&self.crpl.to_le_bytes());
        out[8..10].copy_from_slice(&self.features.to_le_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MeshError> {
        if buf.len() < 10 {
            return Err(MeshError::Short);
        }
        Ok(Self {
            cid: u16::from_le_bytes([buf[0], buf[1]]),
            pid: u16::from_le_bytes([buf[2], buf[3]]),
            vid: u16::from_le_bytes([buf[4], buf[5]]),
            crpl: u16::from_le_bytes([buf[6], buf[7]]),
            features: u16::from_le_bytes([buf[8], buf[9]]),
        })
    }
}
