//! RFCOMM — Bluetooth serial-port emulation (clean-room).
//!
//! Spec sources (public-only):
//! - Bluetooth Core Specification 5.3, Vol 3 Part B (RFCOMM).
//!   §1 framing, §2 Multiplexer Control, §5.2 frame format,
//!   §5.3 frame-type codes, §5.1.1 address byte, §5.1.2 control
//!   byte, §5.1.3 length indicator, §5.1.4 FCS.
//! - ETSI TS 07.10 — the underlying multiplexed-serial protocol that
//!   RFCOMM adapts. Public ETSI document; only the byte layout is
//!   referenced here.
//!
//! No GPL Linux source consulted.
//!
//! ## Frame layout (§5.2)
//!
//! ```text
//!   byte 0           Address  (EA(1) | C/R(1) | DLCI(6))
//!   byte 1           Control  (frame type with optional P/F bit)
//!   byte 2..(1..2)   Length   (EA-coded: bit0 = "this is the only
//!                              length byte". 1 byte ⇒ payload up to
//!                              0..127, 2 bytes ⇒ payload up to 0..32767)
//!   payload          0..N bytes (only for UIH; control frames have none)
//!   FCS              1 byte (CRC8 over address+control[+length] for
//!                            SABM/UA/DM/DISC, and over address+control
//!                            only for UIH per §5.1.4)
//! ```
//!
//! ## Frame types (§5.3)
//!
//! - SABM (0x2F + P) — Set Asynchronous Balanced Mode (open DLC).
//! - UA   (0x63 + F) — Unnumbered Acknowledgement.
//! - DM   (0x0F + F) — Disconnected Mode.
//! - DISC (0x43 + P) — Disconnect.
//! - UIH  (0xEF + P/F) — Unnumbered Information with Header check.
//!
//! ## DLCI (§5.4)
//!
//! - DLCI 0 is the multiplexer-control channel.
//! - DLCI 1..=61 are user data link connections.
//! - The lower 5 bits of the DLCI encode the *server channel*
//!   (1..=30); the high bit selects "responder side" addressing.

use alloc::vec::Vec;

/// Frame-type byte values *with* the P/F bit cleared. Callers OR in
/// 0x10 to set it.
pub const FRAME_SABM: u8 = 0x2F;
pub const FRAME_UA: u8 = 0x63;
pub const FRAME_DM: u8 = 0x0F;
pub const FRAME_DISC: u8 = 0x43;
pub const FRAME_UIH: u8 = 0xEF;

/// P/F bit position in the control byte (§5.1.2).
pub const PF_BIT: u8 = 0x10;

/// Multiplexer-control channel (§5.4).
pub const DLCI_MUX: u8 = 0;

/// Errors from frame decode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RfcommError {
    /// Buffer too short for a minimal frame (3 bytes + FCS).
    Short,
    /// Length-indicator EA bit chain wasn't terminated.
    BadLength,
    /// FCS mismatch (CRC8 over the header bytes).
    BadFcs,
}

/// One decoded RFCOMM frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// 6-bit DLCI (Data Link Connection Identifier).
    pub dlci: u8,
    /// C/R flag (Command/Response, §5.1.1 bit 1 of address byte).
    pub cr: bool,
    /// Frame-type code with PF bit cleared (e.g. `FRAME_SABM`).
    pub frame_type: u8,
    /// Poll/Final bit value extracted from the control byte.
    pub pf: bool,
    /// Information field (UIH only).
    pub info: Vec<u8>,
}

impl Frame {
    /// Encode address byte (§5.1.1):
    /// `EA(1=1) | CR | DLCI(6)`. `direction` is the addressing-side
    /// bit per §5.4 ("initiator" or "responder").
    pub fn address_byte(dlci: u8, cr: bool) -> u8 {
        let ea: u8 = 0x01;
        let cr: u8 = if cr { 0x02 } else { 0x00 };
        let dlci_field: u8 = (dlci & 0x3F) << 2;
        ea | cr | dlci_field
    }

    /// Decode address byte → (dlci, cr).
    pub fn parse_address(b: u8) -> (u8, bool) {
        let dlci = (b >> 2) & 0x3F;
        let cr = (b & 0x02) != 0;
        (dlci, cr)
    }

    /// Encode this frame to wire bytes, appending the FCS.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.info.len() + 4);
        out.push(Self::address_byte(self.dlci, self.cr));
        let mut control = self.frame_type;
        if self.pf {
            control |= PF_BIT;
        }
        out.push(control);

        // Length: EA-coded. < 128 → 1 byte; 128..32768 → 2 bytes.
        let len = self.info.len();
        if len < 128 {
            out.push(((len as u8) << 1) | 0x01);
        } else {
            out.push(((len as u8) << 1) & 0xFE);
            out.push((len >> 7) as u8);
        }

        out.extend_from_slice(&self.info);

        // FCS coverage (§5.1.4):
        //   - SABM, UA, DM, DISC → over address + control + length
        //   - UIH                → over address + control only
        let cover_len = if self.frame_type == FRAME_UIH {
            2
        } else if len < 128 {
            3
        } else {
            4
        };
        let fcs = fcs8(&out[..cover_len]);
        out.push(fcs);
        out
    }

    /// Decode one frame from `buf`. Returns the decoded frame and
    /// the number of bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), RfcommError> {
        if buf.len() < 4 {
            return Err(RfcommError::Short);
        }
        let (dlci, cr) = Self::parse_address(buf[0]);
        let control = buf[1];
        let pf = (control & PF_BIT) != 0;
        let frame_type = control & !PF_BIT;

        // Length indicator — 1 or 2 bytes based on EA bit.
        let (info_len, length_bytes) = if (buf[2] & 0x01) != 0 {
            ((buf[2] >> 1) as usize, 1usize)
        } else {
            if buf.len() < 5 {
                return Err(RfcommError::Short);
            }
            let lo = (buf[2] >> 1) as usize;
            let hi = (buf[3] as usize) << 7;
            (lo | hi, 2usize)
        };

        let header_len = 2 + length_bytes;
        let fcs_pos = header_len + info_len;
        if buf.len() < fcs_pos + 1 {
            return Err(RfcommError::Short);
        }

        let cover_len = if frame_type == FRAME_UIH {
            2
        } else {
            header_len
        };
        let want_fcs = fcs8(&buf[..cover_len]);
        if want_fcs != buf[fcs_pos] {
            return Err(RfcommError::BadFcs);
        }

        let info = buf[header_len..fcs_pos].to_vec();
        Ok((
            Self {
                dlci,
                cr,
                frame_type,
                pf,
                info,
            },
            fcs_pos + 1,
        ))
    }

    pub fn sabm(dlci: u8, cr: bool) -> Self {
        Self {
            dlci,
            cr,
            frame_type: FRAME_SABM,
            pf: true,
            info: Vec::new(),
        }
    }
    pub fn ua(dlci: u8, cr: bool) -> Self {
        Self {
            dlci,
            cr,
            frame_type: FRAME_UA,
            pf: true,
            info: Vec::new(),
        }
    }
    pub fn dm(dlci: u8, cr: bool) -> Self {
        Self {
            dlci,
            cr,
            frame_type: FRAME_DM,
            pf: true,
            info: Vec::new(),
        }
    }
    pub fn disc(dlci: u8, cr: bool) -> Self {
        Self {
            dlci,
            cr,
            frame_type: FRAME_DISC,
            pf: true,
            info: Vec::new(),
        }
    }
    pub fn uih(dlci: u8, cr: bool, info: Vec<u8>) -> Self {
        Self {
            dlci,
            cr,
            frame_type: FRAME_UIH,
            pf: false,
            info,
        }
    }
}

/// 8-bit CRC used for the RFCOMM FCS (§5.1.4).
///
/// Polynomial x^8 + x^2 + x + 1 with input bits processed LSB-first
/// (a.k.a. reversed CRC-8/ITU). The spec states "the same as the
/// FCS used in TS 07.10 / Q.921" and includes the canonical 256-byte
/// lookup table. We compute on the fly to avoid a 256-byte literal.
pub fn fcs8(bytes: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for byte in bytes {
        let mut b = *byte;
        for _ in 0..8 {
            let mix = (crc ^ b) & 0x01;
            crc >>= 1;
            if mix != 0 {
                crc ^= 0xE0;
            }
            b >>= 1;
        }
    }
    !crc
}

// ── DLC state machine (one user channel) ───────────────────────────

/// State of one RFCOMM Data Link Connection (one DLCI).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DlcState {
    Closed,
    /// We sent SABM, waiting for UA.
    Connecting,
    Open,
    /// We sent DISC, waiting for UA.
    Disconnecting,
}

/// Minimal initiator-side state machine. `cr` flag tracks who is the
/// initiator: spec says the initiator sets C/R=1 in commands and the
/// responder sets C/R=0 in responses. Side-agnostic; the caller wires
/// this up.
#[derive(Debug)]
pub struct Dlc {
    pub dlci: u8,
    pub state: DlcState,
}

impl Dlc {
    pub const fn new(dlci: u8) -> Self {
        Self {
            dlci,
            state: DlcState::Closed,
        }
    }

    /// Build the frame to send to open the connection.
    pub fn connect(&mut self) -> Frame {
        self.state = DlcState::Connecting;
        Frame::sabm(self.dlci, true)
    }

    /// Build the frame to send to tear down the connection.
    pub fn disconnect(&mut self) -> Frame {
        self.state = DlcState::Disconnecting;
        Frame::disc(self.dlci, true)
    }

    /// Build a UIH data frame for an open connection. Returns None
    /// if the DLC isn't open.
    pub fn send(&self, info: Vec<u8>) -> Option<Frame> {
        if self.state != DlcState::Open {
            return None;
        }
        Some(Frame::uih(self.dlci, true, info))
    }

    /// Drive the state machine on a received frame. Returns the
    /// decoded info field if `rx` was a UIH on this DLC.
    pub fn feed(&mut self, rx: &Frame) -> Option<Vec<u8>> {
        if rx.dlci != self.dlci {
            return None;
        }
        match (self.state, rx.frame_type) {
            (DlcState::Connecting, FRAME_UA) => {
                self.state = DlcState::Open;
                None
            }
            (DlcState::Connecting, FRAME_DM) => {
                self.state = DlcState::Closed;
                None
            }
            (DlcState::Disconnecting, FRAME_UA) => {
                self.state = DlcState::Closed;
                None
            }
            (DlcState::Open, FRAME_UIH) => Some(rx.info.clone()),
            (DlcState::Open, FRAME_DISC) => {
                self.state = DlcState::Closed;
                None
            }
            _ => None,
        }
    }
}
