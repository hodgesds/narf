//! H4 — UART HCI transport, single-stream framing — clean-room.
//!
//! Reference: **Bluetooth Core Specification 5.3, Vol 4 Part A
//! "UART Transport Layer"** (Bluetooth SIG, public). H4 is the
//! simpler of the two SIG-published UART transports — every
//! packet is prefixed by a single packet-indicator byte and
//! shares the same wire body as the USB transport.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## Wire format
//!
//! ```text
//!   1 byte   packet-type indicator (0x01 / 0x02 / 0x03 / 0x04 / 0x05)
//!   N bytes  packet payload as defined by the HCI codec
//! ```
//!
//! The payload's length is encoded *inside* its own header:
//!
//! - Command: 3-byte header (opcode lo, opcode hi, parameter length).
//! - ACL: 4-byte header (handle+flags lo+hi, data total length lo+hi).
//! - Synchronous: 3-byte header (handle+flags lo+hi, data total length).
//! - Event: 2-byte header (event code, parameter total length).
//! - ISO: 4-byte header (handle+flags lo+hi, ISO data load length lo+hi
//!   with timestamp bit in the high half).
//!
//! ## Scope
//!
//! Codec only — `encode_*` produces the `1 + N` byte stream; the
//! `Decoder` state machine consumes a continuous UART byte stream
//! and yields one decoded packet per `step` call. The actual UART
//! ISR / FIFO drainer lives in the per-platform driver and feeds
//! bytes to `Decoder::feed`.

use alloc::vec::Vec;

use crate::hci::{AclData, Command, Event, PacketType};

// ── Encoders ─────────────────────────────────────────────────────

/// Encode an HCI Command as an H4 frame: `0x01` indicator + the
/// encoded Command body.
pub fn encode_command(cmd: &Command) -> Vec<u8> {
    let body = cmd.encode();
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(PacketType::Command as u8);
    out.extend_from_slice(&body);
    out
}

/// Encode an HCI Event as an H4 frame.
pub fn encode_event(event_code: u8, params: &[u8]) -> Vec<u8> {
    if params.len() > u8::MAX as usize {
        // Spec caps Event parameter length at 255; trim defensively.
        return Vec::new();
    }
    let mut out = Vec::with_capacity(1 + 2 + params.len());
    out.push(PacketType::Event as u8);
    out.push(event_code);
    out.push(params.len() as u8);
    out.extend_from_slice(params);
    out
}

/// Encode an ACL Data packet as an H4 frame.
pub fn encode_acl(acl: &AclData) -> Vec<u8> {
    let body = acl.encode();
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(PacketType::AclData as u8);
    out.extend_from_slice(&body);
    out
}

// ── Decoder state machine ────────────────────────────────────────

/// Decoded H4 frame yielded by the [`Decoder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum H4Frame {
    Command(Command),
    AclData(AclData),
    SyncData {
        handle: u16,
        pb_flag: u8,
        data: Vec<u8>,
    },
    Event(Event),
    IsoData {
        handle: u16,
        pb_flag: u8,
        ts_present: bool,
        data: Vec<u8>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum H4Error {
    /// Indicator byte not in {1..=5}.
    BadIndicator(u8),
    /// Header read but body length too long for the supplied
    /// max-frame budget.
    BodyTooLong { announced: usize, limit: usize },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DecState {
    Indicator,
    Header {
        ptype: PacketType,
        header_len: usize,
    },
    Body {
        ptype: PacketType,
        body_len: usize,
    },
}

/// H4 byte-stream decoder. Feed bytes from the UART into it; pull
/// completed frames from `step`.
#[derive(Debug)]
pub struct Decoder {
    state: DecState,
    /// Bytes accumulated so far for the current packet (header +
    /// body, *not* including the indicator byte).
    accum: Vec<u8>,
    max_frame: usize,
}

impl Decoder {
    /// Build a decoder that rejects any frame whose header
    /// announces a body longer than `max_frame` bytes — a safety
    /// rail against a runaway controller flooding RAM.
    pub fn new(max_frame: usize) -> Self {
        Self {
            state: DecState::Indicator,
            accum: Vec::new(),
            max_frame,
        }
    }

    /// Feed one byte; on a complete frame, returns `Some(frame)`.
    /// On a malformed header, returns the error and resets the
    /// state machine so the next byte is treated as a fresh
    /// indicator.
    pub fn feed(&mut self, b: u8) -> Result<Option<H4Frame>, H4Error> {
        match self.state {
            DecState::Indicator => {
                let pt = PacketType::from_u8(b).ok_or(H4Error::BadIndicator(b))?;
                self.state = DecState::Header {
                    ptype: pt,
                    header_len: header_len(pt),
                };
                self.accum.clear();
                Ok(None)
            }
            DecState::Header { ptype, header_len } => {
                self.accum.push(b);
                if self.accum.len() == header_len {
                    // Header complete; read announced body length.
                    let announced = body_length_from_header(ptype, &self.accum);
                    if announced > self.max_frame {
                        let limit = self.max_frame;
                        self.reset();
                        return Err(H4Error::BodyTooLong { announced, limit });
                    }
                    if announced == 0 {
                        // Header-only packet → frame complete now.
                        let frame = self.finalize(ptype);
                        return Ok(Some(frame));
                    }
                    self.state = DecState::Body {
                        ptype,
                        body_len: announced,
                    };
                }
                Ok(None)
            }
            DecState::Body { ptype, body_len } => {
                self.accum.push(b);
                let header_len = header_len(ptype);
                if self.accum.len() == header_len + body_len {
                    let frame = self.finalize(ptype);
                    return Ok(Some(frame));
                }
                Ok(None)
            }
        }
    }

    /// Drive the decoder forward over a slice of bytes, yielding
    /// every complete frame in order.
    pub fn drain(&mut self, bytes: &[u8]) -> Result<Vec<H4Frame>, H4Error> {
        let mut frames = Vec::new();
        for &b in bytes {
            if let Some(f) = self.feed(b)? {
                frames.push(f);
            }
        }
        Ok(frames)
    }

    fn reset(&mut self) {
        self.state = DecState::Indicator;
        self.accum.clear();
    }

    fn finalize(&mut self, ptype: PacketType) -> H4Frame {
        let buf = core::mem::take(&mut self.accum);
        let frame = match ptype {
            PacketType::Command => {
                // `buf` already contains the Command's full wire
                // body (opcode lo, hi, plen, params); the header
                // decoder above guarantees `buf.len() == 3 + plen`.
                let opcode = u16::from_le_bytes([buf[0], buf[1]]);
                let params = buf[3..].to_vec();
                H4Frame::Command(Command { opcode, params })
            }
            PacketType::AclData => {
                let acl = AclData::decode(&buf).expect("validated by header decoder");
                H4Frame::AclData(acl)
            }
            PacketType::Event => {
                let ev = Event::decode(&buf).expect("validated by header decoder");
                H4Frame::Event(ev)
            }
            PacketType::SyncData => {
                let h = u16::from_le_bytes([buf[0], buf[1]]);
                let dlen = buf[2] as usize;
                H4Frame::SyncData {
                    handle: h & 0x0FFF,
                    pb_flag: ((h >> 12) & 0x3) as u8,
                    data: buf[3..3 + dlen].to_vec(),
                }
            }
            PacketType::IsoData => {
                let h = u16::from_le_bytes([buf[0], buf[1]]);
                let raw_len = u16::from_le_bytes([buf[2], buf[3]]);
                let dlen = (raw_len & 0x3FFF) as usize;
                let ts_present = (raw_len & 0x4000) != 0;
                H4Frame::IsoData {
                    handle: h & 0x0FFF,
                    pb_flag: ((h >> 12) & 0x3) as u8,
                    ts_present,
                    data: buf[4..4 + dlen].to_vec(),
                }
            }
        };
        self.reset();
        frame
    }
}

fn header_len(pt: PacketType) -> usize {
    match pt {
        PacketType::Command => 3,
        PacketType::Event => 2,
        PacketType::AclData => 4,
        PacketType::SyncData => 3,
        PacketType::IsoData => 4,
    }
}

fn body_length_from_header(pt: PacketType, header: &[u8]) -> usize {
    match pt {
        PacketType::Command => header[2] as usize,
        PacketType::Event => header[1] as usize,
        PacketType::AclData => u16::from_le_bytes([header[2], header[3]]) as usize,
        PacketType::SyncData => header[2] as usize,
        // ISO header: handle+flags (2 B) + length (low 14 bits of u16) + ts flag (bit 14).
        PacketType::IsoData => {
            let raw = u16::from_le_bytes([header[2], header[3]]);
            (raw & 0x3FFF) as usize
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_command_round_trip() -> TestResult {
        let cmd = Command::with_params(0x0C03, &[0xAA, 0x55]); // RESET-style
        let frame = encode_command(&cmd);
        if frame[0] != PacketType::Command as u8 {
            return TestResult::Fail("indicator byte missing");
        }
        let mut dec = Decoder::new(1024);
        let frames = dec.drain(&frame).expect("clean parse");
        if frames.len() != 1 {
            return TestResult::Fail("expected exactly one frame");
        }
        match &frames[0] {
            H4Frame::Command(c) if *c == cmd => TestResult::Pass,
            _ => TestResult::Fail("command did not round-trip"),
        }
    }
    kernel_test_in!("bluetooth/h4", smoke_command_round_trip);

    fn smoke_event_round_trip() -> TestResult {
        let frame = encode_event(0x0E, &[1, 2, 3, 4]);
        let mut dec = Decoder::new(1024);
        let frames = dec.drain(&frame).expect("clean parse");
        match &frames[..] {
            [H4Frame::Event(e)] if e.code == 0x0E && e.params == alloc::vec![1, 2, 3, 4] => {
                TestResult::Pass
            }
            _ => TestResult::Fail("event did not round-trip"),
        }
    }
    kernel_test_in!("bluetooth/h4", smoke_event_round_trip);

    fn smoke_byte_at_a_time() -> TestResult {
        let cmd = Command::with_params(0x1001, &[]);
        let frame = encode_command(&cmd);
        let mut dec = Decoder::new(1024);
        let mut out = None;
        for &b in &frame {
            if let Some(f) = dec.feed(b).expect("clean feed") {
                out = Some(f);
            }
        }
        match out {
            Some(H4Frame::Command(c)) if c == cmd => TestResult::Pass,
            _ => TestResult::Fail("byte-at-a-time decode failed"),
        }
    }
    kernel_test_in!("bluetooth/h4", smoke_byte_at_a_time);

    fn smoke_decoder_rejects_bad_indicator() -> TestResult {
        let mut dec = Decoder::new(1024);
        match dec.feed(0xFF) {
            Err(H4Error::BadIndicator(0xFF)) => TestResult::Pass,
            _ => TestResult::Fail("indicator 0xFF must be rejected"),
        }
    }
    kernel_test_in!("bluetooth/h4", smoke_decoder_rejects_bad_indicator);

    fn smoke_decoder_enforces_max_frame() -> TestResult {
        // Indicator = ACL (0x02). Header [handle lo, hi, len lo, hi].
        // Announce 4096 bytes, but cap at 64.
        let mut dec = Decoder::new(64);
        for &b in &[0x02u8, 0x40, 0x00] {
            assert!(dec.feed(b).expect("clean feed").is_none());
        }
        // Length lo=0x00, hi=0x10 → 4096 bytes announced.
        assert!(dec.feed(0x00).expect("clean feed").is_none());
        match dec.feed(0x10) {
            Err(H4Error::BodyTooLong {
                announced: 4096,
                limit: 64,
            }) => TestResult::Pass,
            _ => TestResult::Fail("oversize body must surface"),
        }
    }
    kernel_test_in!("bluetooth/h4", smoke_decoder_enforces_max_frame);

    fn smoke_two_frames_in_one_buffer() -> TestResult {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_event(0x05, &[0xAB]));
        bytes.extend_from_slice(&encode_event(0x06, &[0x12, 0x34]));
        let mut dec = Decoder::new(1024);
        let frames = dec.drain(&bytes).expect("clean parse");
        match &frames[..] {
            [H4Frame::Event(a), H4Frame::Event(b)] if a.code == 5 && b.code == 6 => {
                TestResult::Pass
            }
            _ => TestResult::Fail("expected two events"),
        }
    }
    kernel_test_in!("bluetooth/h4", smoke_two_frames_in_one_buffer);
}
