//! HCI packet codec.
//!
//! Bluetooth Core Spec 5.3 Vol 4 Part E §5.4 lists four packet types,
//! each prefixed by a 1-byte indicator on the USB/UART transport:
//!
//! ```text
//!   0x01 — HCI Command
//!   0x02 — ACL Data
//!   0x03 — Synchronous Data (SCO/eSCO)
//!   0x04 — HCI Event
//!   0x05 — ISO Data (BLE)
//! ```
//!
//! Each carries a fixed-length header followed by a payload whose
//! length is encoded in the header's last byte (Command/Event) or
//! a little-endian u16 length (ACL/SCO/ISO).

use alloc::vec::Vec;

/// Packet-type indicators per Vol 4 Part B §2.2 and Part E §5.4.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Command = 0x01,
    AclData = 0x02,
    SyncData = 0x03,
    Event = 0x04,
    IsoData = 0x05,
}

impl PacketType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(PacketType::Command),
            0x02 => Some(PacketType::AclData),
            0x03 => Some(PacketType::SyncData),
            0x04 => Some(PacketType::Event),
            0x05 => Some(PacketType::IsoData),
            _ => None,
        }
    }
}

/// HCI Command packet (Vol 4 Part E §5.4.1).
///
/// Wire layout (after the 0x01 indicator byte):
///
/// ```text
///   0..2: u16 LE Opcode (OGF<<10 | OCF)
///   2:    u8     Parameter Total Length
///   3..N: parameters
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub opcode: u16,
    pub params: Vec<u8>,
}

impl Command {
    pub fn new(opcode: u16) -> Self {
        Self {
            opcode,
            params: Vec::new(),
        }
    }

    pub fn with_params(opcode: u16, params: &[u8]) -> Self {
        Self {
            opcode,
            params: params.to_vec(),
        }
    }

    /// Encode the command payload (excluding the leading 0x01 indicator).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.params.len());
        out.push((self.opcode & 0xFF) as u8);
        out.push((self.opcode >> 8) as u8);
        out.push(self.params.len() as u8);
        out.extend_from_slice(&self.params);
        out
    }
}

/// HCI Event packet (Vol 4 Part E §5.4.4).
///
/// Wire layout:
///
/// ```text
///   0:    u8 Event Code
///   1:    u8 Parameter Total Length
///   2..N: parameters
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub code: u8,
    pub params: Vec<u8>,
}

impl Event {
    /// Decode from a buffer that starts at the event code (i.e. the
    /// 0x04 indicator has already been stripped).
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        let code = buf[0];
        let plen = buf[1] as usize;
        if buf.len() < 2 + plen {
            return None;
        }
        Some(Self {
            code,
            params: buf[2..2 + plen].to_vec(),
        })
    }
}

/// HCI ACL Data packet (Vol 4 Part E §5.4.2).
///
/// Wire layout:
///
/// ```text
///   0..2: u16 LE handle (low 12) + flags (PB:2 BC:2 in high 4)
///   2..4: u16 LE Data Total Length
///   4..N: data
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclData {
    pub handle: u16,
    pub pb_flag: u8,
    pub bc_flag: u8,
    pub data: Vec<u8>,
}

impl AclData {
    pub fn encode(&self) -> Vec<u8> {
        let h = (self.handle & 0x0FFF)
            | (((self.pb_flag & 0x3) as u16) << 12)
            | (((self.bc_flag & 0x3) as u16) << 14);
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push((h & 0xFF) as u8);
        out.push((h >> 8) as u8);
        let len = self.data.len() as u16;
        out.push((len & 0xFF) as u8);
        out.push((len >> 8) as u8);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let h = u16::from_le_bytes([buf[0], buf[1]]);
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return None;
        }
        Some(Self {
            handle: h & 0x0FFF,
            pb_flag: ((h >> 12) & 0x3) as u8,
            bc_flag: ((h >> 14) & 0x3) as u8,
            data: buf[4..4 + len].to_vec(),
        })
    }
}

/// Compose an HCI Opcode from OGF (Opcode Group Field, 6 bits) +
/// OCF (Opcode Command Field, 10 bits). Vol 4 Part E §5.4.1.
#[inline]
pub const fn opcode(ogf: u8, ocf: u16) -> u16 {
    ((ogf as u16 & 0x3F) << 10) | (ocf & 0x03FF)
}

/// Decompose an opcode into `(ogf, ocf)`.
#[inline]
pub const fn split_opcode(opcode: u16) -> (u8, u16) {
    (((opcode >> 10) & 0x3F) as u8, opcode & 0x03FF)
}

/// HCI Synchronous (SCO/eSCO) Data packet (Vol 4 Part E §5.4.3).
///
/// Wire layout:
///
/// ```text
///   0..2: u16 LE handle (low 12) + flags (PS:2 RFU:2 in bits[12..16])
///   2:    u8  Data Total Length
///   3..N: data
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoData {
    pub handle: u16,
    /// Packet-Status flag (§5.4.3): 0 correct / 1 possible-invalid /
    /// 2 no-data / 3 partial-loss. Maps into bits 12..14 of the
    /// 16-bit handle field on the wire.
    pub packet_status: u8,
    pub data: Vec<u8>,
}

impl ScoData {
    pub fn encode(&self) -> Vec<u8> {
        let h = (self.handle & 0x0FFF) | (((self.packet_status & 0x3) as u16) << 12);
        let mut out = Vec::with_capacity(3 + self.data.len());
        out.push((h & 0xFF) as u8);
        out.push((h >> 8) as u8);
        out.push(self.data.len() as u8);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 3 {
            return None;
        }
        let h = u16::from_le_bytes([buf[0], buf[1]]);
        let len = buf[2] as usize;
        if buf.len() < 3 + len {
            return None;
        }
        Some(Self {
            handle: h & 0x0FFF,
            packet_status: ((h >> 12) & 0x3) as u8,
            data: buf[3..3 + len].to_vec(),
        })
    }
}

/// HCI Isochronous Data packet (Vol 4 Part E §5.4.5, BLE Audio).
///
/// Wire layout (the "ISO Data Load" can carry an optional Time-Stamp +
/// Packet-Sequence-Number + SDU header depending on PB flag):
///
/// ```text
///   0..2: u16 LE handle (low 12) + PB:2 + TS:1 + RFU:1
///   2..4: u16 LE Data_Total_Length
///   4..N: ISO Data Load
/// ```
///
/// PB flag values (§5.4.5):
///   0b00 — first fragment of fragmented SDU
///   0b01 — continuation fragment of fragmented SDU
///   0b10 — complete SDU
///   0b11 — last fragment of fragmented SDU
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsoData {
    /// Connection handle (low 12 bits).
    pub handle: u16,
    /// PB flag (§5.4.5).
    pub pb_flag: u8,
    /// TS flag — 1 if a Time-Stamp field is present in the data load.
    pub ts_flag: bool,
    /// Raw ISO Data Load (may include time-stamp + SDU header).
    pub data: Vec<u8>,
}

impl IsoData {
    pub fn encode(&self) -> Vec<u8> {
        let h = (self.handle & 0x0FFF)
            | (((self.pb_flag & 0x3) as u16) << 12)
            | (if self.ts_flag { 1u16 << 14 } else { 0 });
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push((h & 0xFF) as u8);
        out.push((h >> 8) as u8);
        let len = (self.data.len() as u16) & 0x3FFF;
        out.push((len & 0xFF) as u8);
        out.push((len >> 8) as u8);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let h = u16::from_le_bytes([buf[0], buf[1]]);
        let len = (u16::from_le_bytes([buf[2], buf[3]]) & 0x3FFF) as usize;
        if buf.len() < 4 + len {
            return None;
        }
        Some(Self {
            handle: h & 0x0FFF,
            pb_flag: ((h >> 12) & 0x3) as u8,
            ts_flag: (h & (1 << 14)) != 0,
            data: buf[4..4 + len].to_vec(),
        })
    }
}
