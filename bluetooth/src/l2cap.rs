//! L2CAP — Logical Link Control and Adaptation Protocol.
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part A. Public
//! Bluetooth SIG document. No GPL Linux source consulted.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
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

// ── ACL ⇄ L2CAP boundary ───────────────────────────────────────────
//
// Outbound: a complete L2CAP B-frame is fragmented into one or more
// ACL packets sized to the controller's ACL MTU. The first fragment
// uses PB=0b00 (BR/EDR) or PB=0b00/0b10/0b11 (LE); a Complete-LE PDU
// in a single ACL packet uses PB=0b11. Continuation fragments use
// PB=0b01.
//
// Inbound: the Reassembler above is per-connection. The `Dispatcher`
// below holds one Reassembler per ACL handle and dispatches the
// frames to per-CID sinks.

use crate::hci::AclData;

/// PB-flag wire encoding for an outbound first fragment of a non-LE
/// frame (PB=0b00) — first non-automatically-flushable.
pub const PB_FIRST_NON_FLUSHABLE: u8 = 0b00;
/// PB-flag wire encoding for outbound continuation (PB=0b01).
pub const PB_CONTINUATION: u8 = 0b01;
/// PB-flag wire encoding for outbound first automatically-flushable
/// fragment (PB=0b10). LE peripheral controllers typically use this
/// for the first ACL packet of an L2CAP PDU even when the entire PDU
/// fits, because BLE has no per-link flush concept.
pub const PB_FIRST_FLUSHABLE: u8 = 0b10;
/// PB-flag wire encoding for an LE complete PDU in one ACL packet
/// (PB=0b11).
pub const PB_COMPLETE_LE: u8 = 0b11;

/// Wrap one already-encoded B-frame (length+CID+payload) into a list
/// of ACL packets, each ≤ `acl_mtu` bytes of data, with the right
/// PB-flag progression. `bc_flag` is always 0 for point-to-point
/// links (§5.4.2 broadcast flag).
///
/// If the entire frame fits in a single ACL packet and `le` is true,
/// the packet uses PB=0b10 ("first automatically flushable") which is
/// the spec-required value for LE host-to-controller traffic
/// (Vol 4 Part E §5.4.2). For BR/EDR or fragmented LE the first
/// packet uses PB=0b00, continuation packets PB=0b01.
pub fn wrap_bframe_into_acl(
    connection_handle: u16,
    frame_bytes: &[u8],
    acl_mtu: u16,
    le: bool,
) -> Vec<AclData> {
    let mut out = Vec::new();
    if frame_bytes.is_empty() {
        return out;
    }
    let mtu = acl_mtu.max(1) as usize;
    let mut first = true;
    let mut idx = 0;
    while idx < frame_bytes.len() {
        let end = core::cmp::min(idx + mtu, frame_bytes.len());
        let pb = if first {
            if le {
                PB_FIRST_FLUSHABLE
            } else {
                PB_FIRST_NON_FLUSHABLE
            }
        } else {
            PB_CONTINUATION
        };
        out.push(AclData {
            handle: connection_handle & 0x0FFF,
            pb_flag: pb,
            bc_flag: 0,
            data: frame_bytes[idx..end].to_vec(),
        });
        first = false;
        idx = end;
    }
    out
}

/// Convenience: encode a `BFrame` and wrap it into ACL packets.
pub fn wrap_frame_into_acl(
    connection_handle: u16,
    frame: &BFrame,
    acl_mtu: u16,
    le: bool,
) -> Vec<AclData> {
    wrap_bframe_into_acl(connection_handle, &frame.encode(), acl_mtu, le)
}

/// Per-connection L2CAP dispatcher. Holds one `Reassembler` and
/// surfaces reassembled `BFrame`s grouped by CID.
///
/// Stage 1 wires a single dispatcher per ACL handle; the host's
/// connection table maps `(transport, handle)` → dispatcher.
#[derive(Debug, Default)]
pub struct Dispatcher {
    pub reassembler: Reassembler,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one inbound ACL packet (after the HCI ACL header has been
    /// stripped to a `pb_flag` + `data` pair). Returns the list of
    /// L2CAP frames that completed.
    pub fn feed_acl(&mut self, pb_flag: u8, data: &[u8]) -> Vec<BFrame> {
        self.reassembler.feed(PbFlag::from_bits(pb_flag), data)
    }

    /// Classify a frame by CID. The ATT fixed channel is the only one
    /// Stage 1 routes; the rest are returned for the caller to handle
    /// (LE signalling, SMP, dynamic channels) or drop.
    pub fn classify_cid(cid: u16) -> CidClass {
        match cid {
            CID_ATT => CidClass::Att,
            CID_LE_SIGNALLING => CidClass::LeSignalling,
            CID_SMP => CidClass::Smp,
            CID_SIGNALLING => CidClass::BrEdrSignalling,
            CID_NULL => CidClass::Invalid,
            c if (CID_DYNAMIC_LE_FIRST..=CID_DYNAMIC_LE_LAST).contains(&c) => CidClass::Dynamic,
            c if c >= CID_DYNAMIC_BREDR_FIRST => CidClass::Dynamic,
            _ => CidClass::Reserved,
        }
    }
}

/// CID classification produced by [`Dispatcher::classify_cid`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CidClass {
    /// 0x0000 — never valid in a real frame.
    Invalid,
    /// 0x0001 — BR/EDR signalling channel.
    BrEdrSignalling,
    /// 0x0004 — Attribute Protocol (BLE).
    Att,
    /// 0x0005 — LE signalling channel.
    LeSignalling,
    /// 0x0006 — Security Manager (BLE).
    Smp,
    /// Dynamically-allocated CID (BR/EDR ≥0x40, LE 0x40..=0x7F).
    Dynamic,
    /// Spec-reserved CID we don't handle here.
    Reserved,
}

// ── Well-known PSMs (Bluetooth Assigned Numbers) ───────────────────

/// SDP — Service Discovery Protocol.
pub const PSM_SDP: u16 = 0x0001;
/// RFCOMM — serial-port emulation.
pub const PSM_RFCOMM: u16 = 0x0003;
/// TCS-BIN — Telephony Control Specification.
pub const PSM_TCS_BIN: u16 = 0x0005;
/// BNEP — Bluetooth Network Encapsulation Protocol.
pub const PSM_BNEP: u16 = 0x000F;
/// HID Control channel.
pub const PSM_HID_CONTROL: u16 = 0x0011;
/// HID Interrupt channel.
pub const PSM_HID_INTERRUPT: u16 = 0x0013;
/// AVCTP — Audio/Video Control Transport (AVRCP carrier).
pub const PSM_AVCTP: u16 = 0x0017;
/// AVDTP — Audio/Video Distribution Transport (A2DP carrier).
pub const PSM_AVDTP: u16 = 0x0019;
/// AVCTP browsing channel.
pub const PSM_AVCTP_BROWSING: u16 = 0x001B;
/// ATT over BR/EDR (rare; LE uses fixed CID 0x0004 instead).
pub const PSM_ATT: u16 = 0x001F;

// ── L2CAP Signalling-command builders (§4.X) ───────────────────────

/// Build a Connection Request signalling command (§4.2). 4-byte data:
/// PSM (2 LE) + Source_CID (2 LE).
pub fn build_connection_request(identifier: u8, psm: u16, source_cid: u16) -> SignallingCommand {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&psm.to_le_bytes());
    data.extend_from_slice(&source_cid.to_le_bytes());
    SignallingCommand {
        code: SignallingCode::ConnectionRequest as u8,
        identifier,
        data,
    }
}

/// Connection-Response result codes (§4.3, table 4-5).
pub const CONN_RESULT_SUCCESS: u16 = 0x0000;
pub const CONN_RESULT_PENDING: u16 = 0x0001;
pub const CONN_RESULT_REFUSED_PSM_NOT_SUPPORTED: u16 = 0x0002;
pub const CONN_RESULT_REFUSED_SECURITY_BLOCK: u16 = 0x0003;
pub const CONN_RESULT_REFUSED_NO_RESOURCES: u16 = 0x0004;

/// Connection-Response status codes (§4.3, table 4-6).
pub const CONN_STATUS_NO_INFORMATION: u16 = 0x0000;
pub const CONN_STATUS_AUTHENTICATION_PENDING: u16 = 0x0001;
pub const CONN_STATUS_AUTHORISATION_PENDING: u16 = 0x0002;

/// Build a Connection Response (§4.3). 8-byte data: Dest_CID (2 LE) +
/// Source_CID (2 LE) + Result (2 LE) + Status (2 LE).
pub fn build_connection_response(
    identifier: u8,
    dest_cid: u16,
    source_cid: u16,
    result: u16,
    status: u16,
) -> SignallingCommand {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&dest_cid.to_le_bytes());
    data.extend_from_slice(&source_cid.to_le_bytes());
    data.extend_from_slice(&result.to_le_bytes());
    data.extend_from_slice(&status.to_le_bytes());
    SignallingCommand {
        code: SignallingCode::ConnectionResponse as u8,
        identifier,
        data,
    }
}

/// Build a Configuration Request (§4.4). 4-byte fixed header + options:
/// Dest_CID (2 LE) + Flags (2 LE) + options.
pub fn build_configure_request(
    identifier: u8,
    dest_cid: u16,
    continuation: bool,
    options: &[u8],
) -> SignallingCommand {
    let flags: u16 = if continuation { 1 } else { 0 };
    let mut data = Vec::with_capacity(4 + options.len());
    data.extend_from_slice(&dest_cid.to_le_bytes());
    data.extend_from_slice(&flags.to_le_bytes());
    data.extend_from_slice(options);
    SignallingCommand {
        code: SignallingCode::ConfigureRequest as u8,
        identifier,
        data,
    }
}

/// Build a Disconnection Request (§4.6). 4-byte data: Dest_CID (2 LE) +
/// Source_CID (2 LE).
pub fn build_disconnection_request(
    identifier: u8,
    dest_cid: u16,
    source_cid: u16,
) -> SignallingCommand {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&dest_cid.to_le_bytes());
    data.extend_from_slice(&source_cid.to_le_bytes());
    SignallingCommand {
        code: SignallingCode::DisconnectionRequest as u8,
        identifier,
        data,
    }
}

/// Build an Echo Request (§4.8). Variable-length data ping.
pub fn build_echo_request(identifier: u8, data: &[u8]) -> SignallingCommand {
    SignallingCommand {
        code: SignallingCode::EchoRequest as u8,
        identifier,
        data: data.to_vec(),
    }
}

/// Information-Request InfoType values (§4.10, table 4-13).
pub const INFO_TYPE_CONNECTIONLESS_MTU: u16 = 0x0001;
pub const INFO_TYPE_EXTENDED_FEATURES: u16 = 0x0002;
pub const INFO_TYPE_FIXED_CHANNELS: u16 = 0x0003;

/// Build an Information Request (§4.10). 2-byte data: InfoType (2 LE).
pub fn build_information_request(identifier: u8, info_type: u16) -> SignallingCommand {
    SignallingCommand {
        code: SignallingCode::InformationRequest as u8,
        identifier,
        data: info_type.to_le_bytes().to_vec(),
    }
}

// ── LE Credit-Based Connection (§4.22) ─────────────────────────────
//
// LE COC (Connection-Oriented Channel) is the BLE replacement for the
// classic BR/EDR configure-then-stream dance. Credits flow as a
// separate signalling command; each credit grants the peer permission
// to send one K-frame.

/// Build an LE Credit-Based Connection Request (§4.22). Data:
/// LE_PSM (2 LE) + Source_CID (2 LE) + MTU (2 LE) + MPS (2 LE) +
/// Initial_Credits (2 LE) = 10 bytes.
pub fn build_le_credit_based_connection_request(
    identifier: u8,
    le_psm: u16,
    source_cid: u16,
    mtu: u16,
    mps: u16,
    initial_credits: u16,
) -> SignallingCommand {
    let mut data = Vec::with_capacity(10);
    data.extend_from_slice(&le_psm.to_le_bytes());
    data.extend_from_slice(&source_cid.to_le_bytes());
    data.extend_from_slice(&mtu.to_le_bytes());
    data.extend_from_slice(&mps.to_le_bytes());
    data.extend_from_slice(&initial_credits.to_le_bytes());
    SignallingCommand {
        code: SignallingCode::LeCreditBasedConnectionRequest as u8,
        identifier,
        data,
    }
}

/// Build an LE Flow Control Credit signalling command (§4.24). Data:
/// CID (2 LE) + Credits (2 LE).
pub fn build_le_flow_control_credit(
    identifier: u8,
    cid: u16,
    credits: u16,
) -> SignallingCommand {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&cid.to_le_bytes());
    data.extend_from_slice(&credits.to_le_bytes());
    SignallingCommand {
        code: SignallingCode::FlowControlCredit as u8,
        identifier,
        data,
    }
}

// ── LE Connection Parameter Update Request (§4.20) ─────────────────

/// Build an LE Connection Parameter Update Request (§4.20).
/// Data: Interval_Min (2 LE) + Interval_Max (2 LE) + Latency (2 LE) +
/// Timeout (2 LE) = 8 bytes. Intervals are in 1.25 ms units; timeout
/// in 10 ms.
pub fn build_le_connection_parameter_update_request(
    identifier: u8,
    interval_min: u16,
    interval_max: u16,
    latency: u16,
    timeout: u16,
) -> SignallingCommand {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&interval_min.to_le_bytes());
    data.extend_from_slice(&interval_max.to_le_bytes());
    data.extend_from_slice(&latency.to_le_bytes());
    data.extend_from_slice(&timeout.to_le_bytes());
    SignallingCommand {
        code: SignallingCode::ConnectionParameterUpdateRequest as u8,
        identifier,
        data,
    }
}

// ── MTU-option encoder (§5.1) ──────────────────────────────────────

/// MTU configuration option type (§5.1, table 5-1).
pub const CONFIG_OPT_MTU: u8 = 0x01;

/// Encode the L2CAP MTU configuration option (§5.1). Format:
/// type(1) length(1=2) MTU (u16 LE).
pub fn config_option_mtu(mtu: u16) -> [u8; 4] {
    [
        CONFIG_OPT_MTU,
        2,
        (mtu & 0xFF) as u8,
        (mtu >> 8) as u8,
    ]
}
