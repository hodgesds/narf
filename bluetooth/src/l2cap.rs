//! L2CAP — Logical Link Control and Adaptation Protocol.
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part A. Public
//! Bluetooth SIG document. No GPL Linux source consulted.
//!
//! L2CAP sits between HCI ACL data and every higher-layer protocol
//! (ATT for BLE, RFCOMM/SDP for BR/EDR, SMP for pairing). It carries
//! "channels" — multiplexed streams identified by 16-bit CIDs. Some
//! CIDs are reserved (§2.1):
//!
//!   0x0000 — Null identifier (forbidden in valid frames)
//!   0x0001 — Signalling channel (BR/EDR)
//!   0x0002 — Connectionless channel
//!   0x0003 — AMP Manager
//!   0x0004 — Attribute Protocol (BLE)
//!   0x0005 — LE Signalling channel
//!   0x0006 — Security Manager Protocol (BLE)
//!   0x0007 — BR/EDR Security Manager
//!   0x0040..0xFFFF — dynamic (BR/EDR) / 0x0040..0x007F (LE)
//!
//! ## Frame layout (§3.1)
//!
//! Every L2CAP B-frame on a channel:
//!
//!   0..2: u16 LE length (of payload only — excludes this header)
//!   2..4: u16 LE CID
//!   4..N: payload
//!
//! ACL HCI fragments these across multiple ACL packets; the
//! `Reassembler` here pulls them back together.

use alloc::vec::Vec;

// ── Reserved CIDs (§2.1) ───────────────────────────────────────────
pub const CID_NULL: u16 = 0x0000;
pub const CID_SIGNALLING: u16 = 0x0001;
pub const CID_CONNECTIONLESS: u16 = 0x0002;
pub const CID_AMP_MANAGER: u16 = 0x0003;
pub const CID_ATT: u16 = 0x0004;
pub const CID_LE_SIGNALLING: u16 = 0x0005;
pub const CID_SMP: u16 = 0x0006;
pub const CID_BREDR_SMP: u16 = 0x0007;

/// First dynamic CID value for BR/EDR (§2.1, table 2-1).
pub const CID_DYNAMIC_BREDR_FIRST: u16 = 0x0040;
/// Last dynamic CID value for BR/EDR (§2.1, table 2-1).
pub const CID_DYNAMIC_BREDR_LAST: u16 = 0xFFFF;
/// First dynamic CID value for LE (§2.1, table 2-2).
pub const CID_DYNAMIC_LE_FIRST: u16 = 0x0040;
/// Last dynamic CID value for LE (§2.1, table 2-2).
pub const CID_DYNAMIC_LE_LAST: u16 = 0x007F;

/// L2CAP B-frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BFrame {
    pub cid: u16,
    pub payload: Vec<u8>,
}

impl BFrame {
    pub fn new(cid: u16, payload: Vec<u8>) -> Self {
        Self { cid, payload }
    }

    /// Encode to wire bytes (length prefix + CID + payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.payload.len());
        let len = self.payload.len() as u16;
        out.push((len & 0xFF) as u8);
        out.push((len >> 8) as u8);
        out.push((self.cid & 0xFF) as u8);
        out.push((self.cid >> 8) as u8);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from a complete (i.e. already reassembled) buffer.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let cid = u16::from_le_bytes([buf[2], buf[3]]);
        if buf.len() < 4 + len {
            return None;
        }
        Some(Self {
            cid,
            payload: buf[4..4 + len].to_vec(),
        })
    }
}

// ── ACL fragmentation / recombination ──────────────────────────────
//
// Vol 4 Part E §5.4.2 PB flag values:
//   0b00 — first non-automatically-flushable, complete or fragment
//   0b01 — continuing fragment
//   0b10 — first automatically-flushable, complete or fragment
//   0b11 — complete L2CAP PDU (BLE, §5.4.2)
//
// A "Start" PB (00 or 10 for BR/EDR; 11 for BLE complete) opens a
// new reassembly window; subsequent 0b01 fragments append until the
// L2CAP length field is satisfied.

/// PB-flag classification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PbFlag {
    /// Continuation of an in-progress L2CAP PDU.
    Continuation,
    /// First / only fragment of a new L2CAP PDU (BR/EDR).
    StartBrEdr,
    /// Complete L2CAP PDU in one ACL packet (LE).
    CompleteLe,
}

impl PbFlag {
    pub fn from_bits(b: u8) -> Self {
        match b & 0x3 {
            0b01 => PbFlag::Continuation,
            0b11 => PbFlag::CompleteLe,
            _ => PbFlag::StartBrEdr,
        }
    }
}

/// Reassembler for one ACL connection. Calls `feed(pb_flag, data)`
/// with each ACL fragment and drains complete L2CAP frames from the
/// returned `Vec`.
#[derive(Debug, Default)]
pub struct Reassembler {
    /// In-progress accumulator. Empty when no Start has been seen.
    buffer: Vec<u8>,
    /// Total expected length once we've decoded the L2CAP header
    /// (4 + payload_len). 0 until we've buffered enough bytes.
    expected: usize,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one ACL fragment. Returns the list of L2CAP frames that
    /// completed on this call (typically 0 or 1; multiple is rare
    /// but legal if the firmware bundles fragments).
    pub fn feed(&mut self, pb: PbFlag, data: &[u8]) -> Vec<BFrame> {
        match pb {
            PbFlag::StartBrEdr | PbFlag::CompleteLe => {
                // New PDU. Drop any incomplete pending one — Vol 3
                // Part A §6.6.2 says continuing fragments lost when
                // a new Start is seen.
                self.buffer.clear();
                self.buffer.extend_from_slice(data);
                self.expected = 0;
            }
            PbFlag::Continuation => {
                self.buffer.extend_from_slice(data);
            }
        }

        // Resolve `expected` once we have at least the 4-byte header.
        if self.expected == 0 && self.buffer.len() >= 4 {
            let len = u16::from_le_bytes([self.buffer[0], self.buffer[1]]) as usize;
            self.expected = 4 + len;
        }

        let mut out = Vec::new();
        while self.expected != 0 && self.buffer.len() >= self.expected {
            let frame_bytes: Vec<u8> = self.buffer.drain(..self.expected).collect();
            if let Some(b) = BFrame::decode(&frame_bytes) {
                out.push(b);
            }
            // If more bytes remain it's a back-to-back PDU in the same
            // ACL fragment (rare); decode the next header.
            self.expected = if self.buffer.len() >= 4 {
                4 + u16::from_le_bytes([self.buffer[0], self.buffer[1]]) as usize
            } else {
                0
            };
        }
        out
    }

    /// Reset the reassembler — used on link reset.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.expected = 0;
    }
}

// ── Dynamic CID allocator ──────────────────────────────────────────

/// Allocator for dynamic L2CAP CIDs. Holds a bitmap of in-use CIDs;
/// `alloc_le()` and `alloc_bredr()` pick the lowest free value.
#[derive(Debug)]
pub struct CidAllocator {
    le_used: [u64; 1], // 64 bits cover 0x0040..=0x007F
    bredr_next: u16,
}

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CidAllocator {
    pub const fn new() -> Self {
        Self {
            le_used: [0],
            bredr_next: CID_DYNAMIC_BREDR_FIRST,
        }
    }

    /// Allocate a fresh LE dynamic CID. `None` when the pool is full.
    pub fn alloc_le(&mut self) -> Option<u16> {
        let used = self.le_used[0];
        for slot in 0..64u32 {
            if used & (1 << slot) == 0 {
                self.le_used[0] |= 1 << slot;
                return Some(CID_DYNAMIC_LE_FIRST + slot as u16);
            }
        }
        None
    }

    /// Free a previously-allocated LE CID. No-op for non-LE values.
    pub fn free_le(&mut self, cid: u16) {
        if cid >= CID_DYNAMIC_LE_FIRST && cid <= CID_DYNAMIC_LE_LAST {
            let slot = cid - CID_DYNAMIC_LE_FIRST;
            self.le_used[0] &= !(1u64 << slot);
        }
    }

    /// Allocate a fresh BR/EDR dynamic CID. The space is huge
    /// (0x0040..=0xFFFF) so we hand out monotonically-incrementing
    /// values; "free" is a no-op (slot is reused at wrap).
    pub fn alloc_bredr(&mut self) -> Option<u16> {
        let cid = self.bredr_next;
        if cid > CID_DYNAMIC_BREDR_LAST {
            return None;
        }
        self.bredr_next = self.bredr_next.saturating_add(1);
        Some(cid)
    }
}

// ── Signalling-channel commands (§4) ───────────────────────────────
//
// The signalling channel multiplexes "Command Reject", "Connection
// Request/Response", "Configure Request/Response",
// "Disconnect Request/Response", "Connection Parameter Update", etc.
// We define the codec for the wire format; routing to per-channel
// state machines lives in callers.

/// Signalling-channel command codes (§4, table 4-1). Subset.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignallingCode {
    CommandReject = 0x01,
    ConnectionRequest = 0x02,
    ConnectionResponse = 0x03,
    ConfigureRequest = 0x04,
    ConfigureResponse = 0x05,
    DisconnectionRequest = 0x06,
    DisconnectionResponse = 0x07,
    EchoRequest = 0x08,
    EchoResponse = 0x09,
    InformationRequest = 0x0A,
    InformationResponse = 0x0B,
    ConnectionParameterUpdateRequest = 0x12,
    ConnectionParameterUpdateResponse = 0x13,
    LeCreditBasedConnectionRequest = 0x14,
    LeCreditBasedConnectionResponse = 0x15,
    FlowControlCredit = 0x16,
}

impl SignallingCode {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::CommandReject,
            0x02 => Self::ConnectionRequest,
            0x03 => Self::ConnectionResponse,
            0x04 => Self::ConfigureRequest,
            0x05 => Self::ConfigureResponse,
            0x06 => Self::DisconnectionRequest,
            0x07 => Self::DisconnectionResponse,
            0x08 => Self::EchoRequest,
            0x09 => Self::EchoResponse,
            0x0A => Self::InformationRequest,
            0x0B => Self::InformationResponse,
            0x12 => Self::ConnectionParameterUpdateRequest,
            0x13 => Self::ConnectionParameterUpdateResponse,
            0x14 => Self::LeCreditBasedConnectionRequest,
            0x15 => Self::LeCreditBasedConnectionResponse,
            0x16 => Self::FlowControlCredit,
            _ => return None,
        })
    }
}

/// One signalling-channel command. The signalling channel can pack
/// several commands per L2CAP frame (§4) so consumers iterate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignallingCommand {
    pub code: u8,
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl SignallingCommand {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code);
        out.push(self.identifier);
        let len = self.data.len() as u16;
        out.push((len & 0xFF) as u8);
        out.push((len >> 8) as u8);
        out.extend_from_slice(&self.data);
    }

    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let code = buf[0];
        let identifier = buf[1];
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return None;
        }
        Some((
            Self {
                code,
                identifier,
                data: buf[4..4 + len].to_vec(),
            },
            4 + len,
        ))
    }
}

/// Iterate every signalling command packed into `payload`.
pub fn iter_signalling(payload: &[u8]) -> SignallingIter<'_> {
    SignallingIter { buf: payload }
}

#[derive(Clone, Debug)]
pub struct SignallingIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for SignallingIter<'a> {
    type Item = SignallingCommand;
    fn next(&mut self) -> Option<Self::Item> {
        let (cmd, n) = SignallingCommand::decode(self.buf)?;
        self.buf = &self.buf[n..];
        Some(cmd)
    }
}
