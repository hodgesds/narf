//! H5 — Three-Wire UART HCI transport — clean-room.
//!
//! Reference: **Bluetooth Core Specification 5.3, Vol 4 Part D
//! "Three-Wire UART Transport Layer"** (Bluetooth SIG, public).
//! H5 is the link-layer-protected UART transport: every payload
//! is wrapped in a 4-byte header + optional CRC, then SLIP-
//! escaped between framing octets so the host can recover from
//! a missed byte.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## Frame structure (Vol 4 Part D §3)
//!
//! ```text
//!   0xC0          SLIP frame-start delimiter
//!   ┌───────────┐
//!   │ 4-byte    │   bits  3:0   sequence number  (sender's seq)
//!   │ link      │   bits  7:4   ack number       (peer's seq + 1)
//!   │ header    │   bit  8      data integrity check (CRC) present
//!   │           │   bit  9      reliable (ACK required)
//!   │           │   bits 11:10  packet type (0=ACK, 1=Cmd, 2=ACL,
//!   │           │                          3=Sync, 4=Event, 5=ISO,
//!   │           │                          14=Vendor, 15=Link Control)
//!   │           │   bits 23:12  payload length
//!   │           │   bits 31:24  header checksum
//!   └───────────┘
//!   payload …
//!   [optional 16-bit CRC]
//!   0xC0          SLIP frame-end delimiter
//! ```
//!
//! Header checksum (Vol 4 Part D §3.5): `byte0 + byte1 + byte2`
//! sum-modulo-256, then NOT, stored in `byte3`. Receiver
//! validates `byte0 + byte1 + byte2 + byte3 == 0xFF`.
//!
//! Optional CRC-CCITT-16 covers everything between the SLIP
//! delimiters — header + payload — using poly `0x1021`, initial
//! `0xFFFF`. The encoder appends it big-endian when bit 8 of
//! the header is set.
//!
//! ## SLIP escaping (Vol 4 Part D §4)
//!
//! ```text
//!   0xC0  →  0xDB 0xDC     (escape frame delimiter)
//!   0xDB  →  0xDB 0xDD     (escape escape byte)
//! ```
//!
//! ## Scope
//!
//! Wire-format codec — header packing, SLIP escape/unescape, CRC, and
//! the link-control message vocabulary (SYNC / CONFIG / WAKEUP ...,
//! plus the Configuration Field). The link-establishment state machine
//! (sliding window, sender's/receiver's sequence numbers,
//! retransmission) lives in [`crate::h5_transport::H5Transport`],
//! which drives this codec over a byte port.

use alloc::vec::Vec;

// ── SLIP delimiter / escape octets ───────────────────────────────

pub const SLIP_DELIM: u8 = 0xC0;
pub const SLIP_ESC: u8 = 0xDB;
pub const SLIP_ESC_DELIM: u8 = 0xDC;
pub const SLIP_ESC_ESC: u8 = 0xDD;

// ── Packet types (Vol 4 Part D §3.4) ─────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum H5PacketType {
    Ack = 0,
    HciCommand = 1,
    AclData = 2,
    SyncData = 3,
    HciEvent = 4,
    IsoData = 5,
    /// Vendor-specific packets (Vol 4 Part D §4.5 Table 4.1: 14).
    VendorSpecific = 14,
    /// Link-control packets — SYNC / CONFIG / WAKEUP / ... (§4.5
    /// Table 4.1: 15). An earlier revision of this codec mislabelled
    /// 15 as Vendor Specific; the spec assigns 14 to vendors.
    LinkControl = 15,
}

impl H5PacketType {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b & 0xF {
            0 => H5PacketType::Ack,
            1 => H5PacketType::HciCommand,
            2 => H5PacketType::AclData,
            3 => H5PacketType::SyncData,
            4 => H5PacketType::HciEvent,
            5 => H5PacketType::IsoData,
            14 => H5PacketType::VendorSpecific,
            15 => H5PacketType::LinkControl,
            _ => return None,
        })
    }
}

// ── Link-control messages (Vol 4 Part D §8, §9) ─────────────────────

// Link-control payloads are unreliable packets of type 15 (Link
// Control). Every payload's second octet is the first octet's low 7
// bits inverted, with the MSB set to ensure even parity (§8
// footnote [3]); the pairs below are the spec's literal values.
//
// There is no RST link message in Part D: a peer reset is signalled
// by a SYNC arriving while Active (§8.3), which restarts link
// establishment at the Uninitialized state.

/// SYNC (§8.4): sent periodically in the Uninitialized state.
pub const LINK_SYNC: [u8; 2] = [0x01, 0x7E];
/// SYNC RESPONSE (§8.5): reply to a SYNC.
pub const LINK_SYNC_RESP: [u8; 2] = [0x02, 0x7D];
/// CONFIG (§8.6): `0x03 0xFC` + Configuration Field (host sends the
/// field; the controller sends CONFIG without one, §8.8).
pub const LINK_CONFIG: [u8; 2] = [0x03, 0xFC];
/// CONFIG RESPONSE (§8.7): `0x04 0x7B` + Configuration Field
/// (controller sends the field; the host sends CONFIG RESPONSE
/// without one, §8.8).
pub const LINK_CONFIG_RESP: [u8; 2] = [0x04, 0x7B];
/// WAKEUP (§9.1): first message when the peer is believed asleep.
pub const LINK_WAKEUP: [u8; 2] = [0x05, 0xFA];
/// WOKEN (§9.2): mandatory reply to a WAKEUP.
pub const LINK_WOKEN: [u8; 2] = [0x06, 0xF9];
/// SLEEP (§9.3): notifies the peer this device is going to sleep.
pub const LINK_SLEEP: [u8; 2] = [0x07, 0x78];

/// Second octet of a link-control payload, computed from the first
/// octet by the §8 footnote [3] parity rule: invert the low 7 bits,
/// then set the MSB iff that leaves an odd number of 1-bits (so the
/// finished octet always has even parity).
pub fn link_second_octet(first: u8) -> u8 {
    let inv = !(first & 0x7F) & 0x7F;
    if inv.count_ones() % 2 == 0 {
        inv
    } else {
        inv | 0x80
    }
}

/// A link-control message, classified from its payload.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkControlKind {
    Sync,
    SyncResp,
    Config,
    ConfigResp,
    Wakeup,
    Woken,
    Sleep,
}

impl LinkControlKind {
    /// Classify a Link Control payload. Returns the kind plus the
    /// trailing bytes after the two-octet prefix — the Configuration
    /// Field for CONFIG / CONFIG RESPONSE (possibly empty, §8.8),
    /// empty for the rest. `None` for an unrecognised prefix.
    pub fn from_payload(payload: &[u8]) -> Option<(Self, &[u8])> {
        if payload.len() < 2 {
            return None;
        }
        let kind = match (payload[0], payload[1]) {
            (0x01, 0x7E) => LinkControlKind::Sync,
            (0x02, 0x7D) => LinkControlKind::SyncResp,
            (0x03, 0xFC) => LinkControlKind::Config,
            (0x04, 0x7B) => LinkControlKind::ConfigResp,
            (0x05, 0xFA) => LinkControlKind::Wakeup,
            (0x06, 0xF9) => LinkControlKind::Woken,
            (0x07, 0x78) => LinkControlKind::Sleep,
            _ => return None,
        };
        Some((kind, &payload[2..]))
    }

    /// The two-octet prefix for this message.
    pub fn prefix(self) -> [u8; 2] {
        match self {
            LinkControlKind::Sync => LINK_SYNC,
            LinkControlKind::SyncResp => LINK_SYNC_RESP,
            LinkControlKind::Config => LINK_CONFIG,
            LinkControlKind::ConfigResp => LINK_CONFIG_RESP,
            LinkControlKind::Wakeup => LINK_WAKEUP,
            LinkControlKind::Woken => LINK_WOKEN,
            LinkControlKind::Sleep => LINK_SLEEP,
        }
    }
}

/// The Configuration Field (Vol 4 Part D §8.8, Figure 8.6): a single
/// octet, LSB-first — bits 2:0 sliding window size (1..=7, §8.8.2),
/// bit 3 Out-Of-Frame software flow control (§8.8.4), bit 4
/// data-integrity-check type (0 = none, 1 = 16-bit CCITT-CRC,
/// §8.8.3), bits 7:5 version number (0 = v1.0, the only version this
/// spec defines, §8.8.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct H5Config {
    pub window: u8,
    pub oof_flow_control: bool,
    pub crc: bool,
    pub version: u8,
}

impl H5Config {
    pub fn encode(self) -> u8 {
        (self.window & 0x07)
            | (if self.oof_flow_control { 1 << 3 } else { 0 })
            | (if self.crc { 1 << 4 } else { 0 })
            | ((self.version & 0x07) << 5)
    }

    pub fn decode(b: u8) -> Self {
        Self {
            window: b & 0x07,
            oof_flow_control: b & (1 << 3) != 0,
            crc: b & (1 << 4) != 0,
            version: (b >> 5) & 0x07,
        }
    }

    /// Valid per §8.8.2/§8.8.5: window in 1..=7 and version 0 (v1.0).
    pub fn is_valid(self) -> bool {
        (1..=7).contains(&self.window) && self.version == 0
    }
}

// ── Decoded H5 frame ─────────────────────────────────────────────

/// Decoded header fields per Vol 4 Part D §3.5.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct H5Header {
    pub seq: u8,
    pub ack: u8,
    pub crc_present: bool,
    pub reliable: bool,
    pub ptype: H5PacketType,
    pub payload_len: u16,
}

impl H5Header {
    /// Pack into the 4-byte wire header. `byte3` (header
    /// checksum) is computed automatically.
    pub fn encode(&self) -> [u8; 4] {
        let b0 = (self.seq & 0x07)
            | ((self.ack & 0x07) << 3)
            | (if self.crc_present { 1 << 6 } else { 0 })
            | (if self.reliable { 1 << 7 } else { 0 });
        let ptype = self.ptype as u8;
        let len = self.payload_len & 0x0FFF;
        let b1 = (ptype & 0x0F) | ((len & 0x000F) << 4) as u8;
        let b2 = ((len >> 4) & 0xFF) as u8;
        // Per Bluetooth Core Vol 4 Part D §8.3 the three header
        // bytes plus this checksum must sum to 0xFF (byte
        // arithmetic). Two's complement ((~x)+1) would make the
        // sum 0, not 0xFF — we want one's complement.
        let cks = !(b0.wrapping_add(b1).wrapping_add(b2));
        [b0, b1, b2, cks]
    }

    /// Parse a 4-byte header. Validates the byte-sum checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, H5Error> {
        if bytes.len() < 4 {
            return Err(H5Error::ShortHeader);
        }
        let b0 = bytes[0];
        let b1 = bytes[1];
        let b2 = bytes[2];
        let b3 = bytes[3];
        // Header checksum: b0 + b1 + b2 + b3 == 0xFF (byte
        // arithmetic). Vol 4 Part D §3.5.
        let sum = (b0 as u16 + b1 as u16 + b2 as u16 + b3 as u16) & 0xFF;
        if sum != 0xFF {
            return Err(H5Error::BadHeaderChecksum);
        }
        let seq = b0 & 0x07;
        let ack = (b0 >> 3) & 0x07;
        let crc_present = b0 & (1 << 6) != 0;
        let reliable = b0 & (1 << 7) != 0;
        let ptype =
            H5PacketType::from_u8(b1 & 0x0F).ok_or(H5Error::UnknownPacketType(b1 & 0x0F))?;
        let payload_len = ((b1 as u16) >> 4) | ((b2 as u16) << 4);
        Ok(Self {
            seq,
            ack,
            crc_present,
            reliable,
            ptype,
            payload_len: payload_len & 0x0FFF,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum H5Error {
    ShortHeader,
    BadHeaderChecksum,
    UnknownPacketType(u8),
    /// Body is shorter than the header announces.
    Truncated,
    /// Optional CRC was set but didn't validate.
    BadCrc {
        got: u16,
        want: u16,
    },
    /// SLIP escape sequence was malformed.
    BadEscape(u8),
}

/// One decoded frame: header + (unescaped) payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H5Frame {
    pub header: H5Header,
    pub payload: Vec<u8>,
}

// ── SLIP escape / unescape ───────────────────────────────────────

/// SLIP-escape the input bytes. Does NOT add the framing
/// delimiters around the result.
pub fn slip_escape(bytes: &[u8], out: &mut Vec<u8>) {
    for &b in bytes {
        match b {
            SLIP_DELIM => {
                out.push(SLIP_ESC);
                out.push(SLIP_ESC_DELIM);
            }
            SLIP_ESC => {
                out.push(SLIP_ESC);
                out.push(SLIP_ESC_ESC);
            }
            other => out.push(other),
        }
    }
}

/// SLIP-unescape the input bytes. Does NOT consume framing
/// delimiters — the caller strips them first.
pub fn slip_unescape(bytes: &[u8]) -> Result<Vec<u8>, H5Error> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().copied();
    while let Some(b) = iter.next() {
        if b == SLIP_ESC {
            let n = iter.next().ok_or(H5Error::BadEscape(SLIP_ESC))?;
            match n {
                SLIP_ESC_DELIM => out.push(SLIP_DELIM),
                SLIP_ESC_ESC => out.push(SLIP_ESC),
                other => return Err(H5Error::BadEscape(other)),
            }
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

// ── CRC-CCITT-16 (poly 0x1021, init 0xFFFF) ──────────────────────

/// Compute the CRC-CCITT-16 covering `bytes`. Polynomial `0x1021`,
/// initial value `0xFFFF`, MSB-first. Vol 4 Part D §6.
pub fn crc_ccitt(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in bytes {
        let mut x = (crc >> 8) ^ (b as u16);
        x ^= x >> 4;
        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
    }
    crc
}

// ── Encoder ──────────────────────────────────────────────────────

/// Build the on-wire byte sequence for one H5 frame:
///
/// ```text
///   0xC0  SLIP-escaped(header || payload [ || crc16 ])  0xC0
/// ```
///
/// Returns `(framed_bytes, raw_crc)` so callers that want to
/// log the CRC can; raw_crc is `None` when `header.crc_present`
/// is false.
pub fn encode_frame(header: H5Header, payload: &[u8]) -> Vec<u8> {
    // Patch header.payload_len so the wire field always matches
    // the actual payload length.
    let mut hdr = header;
    hdr.payload_len = payload.len() as u16 & 0x0FFF;
    let header_bytes = hdr.encode();

    let mut body = Vec::with_capacity(4 + payload.len() + if hdr.crc_present { 2 } else { 0 });
    body.extend_from_slice(&header_bytes);
    body.extend_from_slice(payload);
    if hdr.crc_present {
        let crc = crc_ccitt(&body);
        body.push((crc >> 8) as u8); // big-endian
        body.push((crc & 0xFF) as u8);
    }

    let mut out = Vec::with_capacity(2 + body.len());
    out.push(SLIP_DELIM);
    slip_escape(&body, &mut out);
    out.push(SLIP_DELIM);
    out
}

// ── Decoder state machine ────────────────────────────────────────

/// Stream decoder. Feed bytes; on each completed `0xC0 .. 0xC0`
/// boundary, returns the decoded frame.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    in_frame: bool,
    max_frame: usize,
}

impl Decoder {
    pub fn new(max_frame: usize) -> Self {
        Self {
            buf: Vec::new(),
            in_frame: false,
            max_frame,
        }
    }

    /// Feed one byte; on a complete frame returns it (after
    /// SLIP-unescape + header validation + optional CRC check).
    pub fn feed(&mut self, b: u8) -> Result<Option<H5Frame>, H5Error> {
        if b == SLIP_DELIM {
            if !self.in_frame {
                self.in_frame = true;
                self.buf.clear();
                return Ok(None);
            }
            // Trailing delimiter — frame complete.
            self.in_frame = false;
            if self.buf.is_empty() {
                // Two delimiters back-to-back: idle. Spec allows
                // this and it's commonly used for line-sync.
                return Ok(None);
            }
            let raw = core::mem::take(&mut self.buf);
            return decode_frame(&raw).map(Some);
        }
        if !self.in_frame {
            // Pre-frame noise — drop quietly.
            return Ok(None);
        }
        if self.buf.len() >= self.max_frame {
            self.in_frame = false;
            self.buf.clear();
            return Err(H5Error::Truncated);
        }
        self.buf.push(b);
        Ok(None)
    }

    /// Feed a buffer of bytes; yield every completed frame.
    pub fn drain(&mut self, bytes: &[u8]) -> Result<Vec<H5Frame>, H5Error> {
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(f) = self.feed(b)? {
                out.push(f);
            }
        }
        Ok(out)
    }
}

/// Parse an unescaped frame body (header + payload + optional
/// CRC). Used by the decoder; exported for callers that want to
/// drive the parsing themselves.
pub fn decode_frame(escaped: &[u8]) -> Result<H5Frame, H5Error> {
    let unescaped = slip_unescape(escaped)?;
    if unescaped.len() < 4 {
        return Err(H5Error::ShortHeader);
    }
    let header = H5Header::decode(&unescaped[..4])?;
    let payload_end = 4 + header.payload_len as usize;
    if header.crc_present {
        if unescaped.len() < payload_end + 2 {
            return Err(H5Error::Truncated);
        }
        let payload = unescaped[4..payload_end].to_vec();
        let got = ((unescaped[payload_end] as u16) << 8) | (unescaped[payload_end + 1] as u16);
        let want = crc_ccitt(&unescaped[..payload_end]);
        if got != want {
            return Err(H5Error::BadCrc { got, want });
        }
        Ok(H5Frame { header, payload })
    } else {
        if unescaped.len() < payload_end {
            return Err(H5Error::Truncated);
        }
        let payload = unescaped[4..payload_end].to_vec();
        Ok(H5Frame { header, payload })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_slip_escape_round_trip() -> TestResult {
        let raw = [0x01, 0xC0, 0x02, 0xDB, 0x03];
        let mut esc = Vec::new();
        slip_escape(&raw, &mut esc);
        // Two escapable bytes → expect 7 escaped bytes.
        if esc.len() != 7 {
            return TestResult::Fail("escape length wrong");
        }
        let back = slip_unescape(&esc).expect("clean unescape");
        if back != raw {
            return TestResult::Fail("round trip lost bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_slip_escape_round_trip);

    fn smoke_header_checksum() -> TestResult {
        let h = H5Header {
            seq: 3,
            ack: 5,
            crc_present: true,
            reliable: true,
            ptype: H5PacketType::HciCommand,
            payload_len: 0x123,
        };
        let bytes = h.encode();
        // Header checksum: b0+b1+b2+b3 == 0xFF (mod 256).
        let sum: u16 =
            (bytes[0] as u16 + bytes[1] as u16 + bytes[2] as u16 + bytes[3] as u16) & 0xFF;
        if sum != 0xFF {
            return TestResult::Fail("header checksum byte-sum wrong");
        }
        let back = H5Header::decode(&bytes).expect("clean decode");
        if back != h {
            return TestResult::Fail("header round trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_header_checksum);

    fn smoke_header_rejects_bad_checksum() -> TestResult {
        let mut bytes = H5Header {
            seq: 0,
            ack: 0,
            crc_present: false,
            reliable: false,
            ptype: H5PacketType::Ack,
            payload_len: 0,
        }
        .encode();
        bytes[3] = bytes[3].wrapping_add(1);
        match H5Header::decode(&bytes) {
            Err(H5Error::BadHeaderChecksum) => TestResult::Pass,
            _ => TestResult::Fail("flipped checksum byte must be rejected"),
        }
    }
    kernel_test_in!("bluetooth/h5", smoke_header_rejects_bad_checksum);

    fn smoke_frame_round_trip_no_crc() -> TestResult {
        let header = H5Header {
            seq: 1,
            ack: 0,
            crc_present: false,
            reliable: true,
            ptype: H5PacketType::HciEvent,
            payload_len: 0, // patched at encode
        };
        let payload: Vec<u8> = (0..8).collect();
        let wire = encode_frame(header, &payload);
        // Must start and end with SLIP delimiter.
        if wire.first() != Some(&SLIP_DELIM) || wire.last() != Some(&SLIP_DELIM) {
            return TestResult::Fail("missing SLIP delimiters");
        }
        let mut dec = Decoder::new(1024);
        let frames = dec.drain(&wire).expect("clean decode");
        match &frames[..] {
            [f] if f.payload == payload && f.header.ptype == H5PacketType::HciEvent => {
                TestResult::Pass
            }
            _ => TestResult::Fail("payload did not round-trip"),
        }
    }
    kernel_test_in!("bluetooth/h5", smoke_frame_round_trip_no_crc);

    fn smoke_frame_round_trip_with_crc() -> TestResult {
        let header = H5Header {
            seq: 2,
            ack: 1,
            crc_present: true,
            reliable: true,
            ptype: H5PacketType::AclData,
            payload_len: 0,
        };
        // Include bytes that need SLIP escaping.
        let payload = alloc::vec![0xC0, 0xDB, 0xAA, 0x55];
        let wire = encode_frame(header, &payload);
        let mut dec = Decoder::new(1024);
        let frames = dec.drain(&wire).expect("clean decode");
        match &frames[..] {
            [f] if f.payload == payload && f.header.crc_present => TestResult::Pass,
            _ => TestResult::Fail("CRC frame did not round-trip"),
        }
    }
    kernel_test_in!("bluetooth/h5", smoke_frame_round_trip_with_crc);

    fn smoke_decoder_rejects_bad_crc() -> TestResult {
        let header = H5Header {
            seq: 0,
            ack: 0,
            crc_present: true,
            reliable: false,
            ptype: H5PacketType::HciCommand,
            payload_len: 0,
        };
        let payload = alloc::vec![1, 2, 3];
        let mut wire = encode_frame(header, &payload);
        // Corrupt one of the CRC bytes (avoid the SLIP delimiters
        // and any escape sequences — flip the second-to-last byte).
        let len = wire.len();
        wire[len - 2] ^= 0xFF;
        let mut dec = Decoder::new(1024);
        match dec.drain(&wire) {
            Err(H5Error::BadCrc { .. }) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("corrupted CRC must be rejected")
            }
        }
    }
    kernel_test_in!("bluetooth/h5", smoke_decoder_rejects_bad_crc);

    fn smoke_two_frames_back_to_back() -> TestResult {
        let h = H5Header {
            seq: 0,
            ack: 0,
            crc_present: false,
            reliable: false,
            ptype: H5PacketType::Ack,
            payload_len: 0,
        };
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_frame(h, &[]));
        wire.extend_from_slice(&encode_frame(h, &[]));
        let mut dec = Decoder::new(1024);
        let frames = dec.drain(&wire).expect("clean decode");
        if frames.len() != 2 {
            return TestResult::Fail("expected two frames");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_two_frames_back_to_back);

    fn smoke_crc_ccitt_known_vector() -> TestResult {
        // CRC-CCITT-FALSE("123456789") = 0x29B1.
        if crc_ccitt(b"123456789") != 0x29B1 {
            return TestResult::Fail("CRC-CCITT-FALSE vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_crc_ccitt_known_vector);

    fn smoke_link_second_octet_matches_spec_pairs() -> TestResult {
        // Vol 4 Part D §8.4–§8.7, §9.1–§9.3 literal pairs, each
        // reproduced by the §8 footnote [3] parity rule.
        let pairs = [
            LINK_SYNC,
            LINK_SYNC_RESP,
            LINK_CONFIG,
            LINK_CONFIG_RESP,
            LINK_WAKEUP,
            LINK_WOKEN,
            LINK_SLEEP,
        ];
        for [first, second] in pairs {
            if link_second_octet(first) != second {
                return TestResult::Fail("parity rule != spec pair");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_link_second_octet_matches_spec_pairs);

    fn smoke_link_control_kind_classifies_all() -> TestResult {
        let cases = [
            (&LINK_SYNC[..], LinkControlKind::Sync),
            (&LINK_SYNC_RESP[..], LinkControlKind::SyncResp),
            (&LINK_CONFIG[..], LinkControlKind::Config),
            (&LINK_CONFIG_RESP[..], LinkControlKind::ConfigResp),
            (&LINK_WAKEUP[..], LinkControlKind::Wakeup),
            (&LINK_WOKEN[..], LinkControlKind::Woken),
            (&LINK_SLEEP[..], LinkControlKind::Sleep),
        ];
        for (payload, want) in cases {
            match LinkControlKind::from_payload(payload) {
                Some((got, rest)) if got == want && rest.is_empty() => {}
                _ => return TestResult::Fail("link payload misclassified"),
            }
        }
        // A CONFIG carrying a Configuration Field exposes the field.
        let mut with_field = LINK_CONFIG.to_vec();
        with_field.push(0x14);
        match LinkControlKind::from_payload(&with_field) {
            Some((LinkControlKind::Config, field)) if field == [0x14] => {}
            _ => return TestResult::Fail("CONFIG field not exposed"),
        }
        // Unknown prefix / short payload rejected.
        if LinkControlKind::from_payload(&[0x09, 0x76]).is_some()
            || LinkControlKind::from_payload(&[0x01]).is_some()
        {
            return TestResult::Fail("bad link payload accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_link_control_kind_classifies_all);

    fn smoke_config_field_bit_layout() -> TestResult {
        // Figure 8.6: window bits 2:0, OOF bit 3, CRC bit 4, version
        // bits 7:5. Window 5 + CRC, version 0 → 0x15.
        let cfg = H5Config {
            window: 5,
            oof_flow_control: false,
            crc: true,
            version: 0,
        };
        if cfg.encode() != 0x15 {
            return TestResult::Fail("config octet bit layout wrong");
        }
        if H5Config::decode(0x15) != cfg {
            return TestResult::Fail("config octet decode wrong");
        }
        // OOF sets bit 3; version 0 is the only valid version.
        let oof = H5Config {
            window: 1,
            oof_flow_control: true,
            crc: false,
            version: 0,
        };
        if oof.encode() != 0x09 || !oof.is_valid() {
            return TestResult::Fail("OOF bit wrong");
        }
        let window_zero = H5Config {
            window: 0,
            oof_flow_control: false,
            crc: false,
            version: 0,
        };
        let version_one = H5Config {
            window: 4,
            oof_flow_control: false,
            crc: false,
            version: 1,
        };
        if cfg.is_valid() && !window_zero.is_valid() && !version_one.is_valid() {
            TestResult::Pass
        } else {
            TestResult::Fail("config validity rule wrong")
        }
    }
    kernel_test_in!("bluetooth/h5", smoke_config_field_bit_layout);

    fn smoke_packet_type_vendor_is_14_link_is_15() -> TestResult {
        // Vol 4 Part D §4.5 Table 4.1: Vendor Specific = 14, Link
        // Control = 15 (an earlier revision had these swapped).
        if H5PacketType::from_u8(14) != Some(H5PacketType::VendorSpecific)
            || H5PacketType::from_u8(15) != Some(H5PacketType::LinkControl)
            || H5PacketType::from_u8(6).is_some()
            || H5PacketType::from_u8(13).is_some()
        {
            return TestResult::Fail("packet-type values wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5", smoke_packet_type_vendor_is_14_link_is_15);
}
