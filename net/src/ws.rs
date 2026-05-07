//! WebSocket framing — clean-room.
//!
//! References (public-only):
//! - RFC 6455 — The WebSocket Protocol (I. Fette & A. Melnikov, Dec
//!   2011). §5.2 (Base Framing Protocol — variable-length frame
//!   header with 7-bit / 16-bit / 64-bit payload-length encodings).
//!   §5.3 (Client-to-Server Masking — 4-byte masking key XORed with
//!   payload). §5.5 (Control Frames — Close / Ping / Pong with
//!   payloads ≤ 125 bytes). §7.4 (Status Codes).
//!
//! No GPL Linux source consulted.
//!
//! ## Frame layout (RFC 6455 §5.2)
//!
//! ```text
//!   byte 0:
//!     bit 7   FIN
//!     bits 6..4 RSV1 RSV2 RSV3 (extension-reserved, 0 unless negotiated)
//!     bits 3..0 Opcode
//!   byte 1:
//!     bit 7   MASK (always 1 from client → server, 0 server → client)
//!     bits 6..0 Payload Length:
//!       0..125     literal length
//!       126        next 2 bytes are big-endian u16 length
//!       127        next 8 bytes are big-endian u64 length (top bit MUST be 0)
//!   bytes …       extended length (if Length == 126 / 127)
//!   bytes …       4-byte masking key (only if MASK = 1)
//!   bytes …       payload (length bytes, XORed with the masking key when MASK = 1)
//! ```

extern crate alloc;

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WsError {
    Short,
    /// Length 127 with top bit set per RFC 6455 §5.2 — reserved.
    BadLength,
    /// Control frame > 125 bytes (RFC 6455 §5.5).
    ControlFrameTooLong,
}

// ── Opcodes (RFC 6455 §5.2) ────────────────────────────────────────

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Top-bit mask of opcode byte 0 (FIN flag).
pub const FIN_BIT: u8 = 0x80;
/// Top-bit mask of byte 1 (MASK flag).
pub const MASK_BIT: u8 = 0x80;

// ── Close-frame status codes (RFC 6455 §7.4) ──────────────────────

pub const STATUS_NORMAL_CLOSURE: u16 = 1000;
pub const STATUS_GOING_AWAY: u16 = 1001;
pub const STATUS_PROTOCOL_ERROR: u16 = 1002;
pub const STATUS_UNSUPPORTED_DATA: u16 = 1003;
pub const STATUS_NO_STATUS_RECEIVED: u16 = 1005;
pub const STATUS_ABNORMAL_CLOSURE: u16 = 1006;
pub const STATUS_INVALID_FRAME_PAYLOAD_DATA: u16 = 1007;
pub const STATUS_POLICY_VIOLATION: u16 = 1008;
pub const STATUS_MESSAGE_TOO_BIG: u16 = 1009;
pub const STATUS_MISSING_EXTENSION: u16 = 1010;
pub const STATUS_INTERNAL_ERROR: u16 = 1011;
pub const STATUS_TLS_HANDSHAKE: u16 = 1015;

// ── Frame ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: u8,
    /// 4-byte masking key (always set on client → server frames; the
    /// server side MUST send unmasked frames).
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Returns true for the four control opcodes (Close, Ping, Pong).
    pub fn is_control(&self) -> bool {
        (self.opcode & 0x08) != 0
    }

    /// Encode this frame to wire bytes (with masking applied if `mask`
    /// is Some).
    pub fn encode(&self) -> Result<Vec<u8>, WsError> {
        if self.is_control() && self.payload.len() > 125 {
            return Err(WsError::ControlFrameTooLong);
        }
        let mut out = Vec::with_capacity(2 + self.payload.len() + 12);
        let mut byte0 = self.opcode & 0x0F;
        if self.fin {
            byte0 |= FIN_BIT;
        }
        if self.rsv1 {
            byte0 |= 0x40;
        }
        if self.rsv2 {
            byte0 |= 0x20;
        }
        if self.rsv3 {
            byte0 |= 0x10;
        }
        out.push(byte0);

        let len = self.payload.len();
        let masked = self.mask.is_some();
        let mask_bit = if masked { MASK_BIT } else { 0 };
        if len <= 125 {
            out.push(mask_bit | (len as u8));
        } else if len <= 0xFFFF {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(key) = self.mask {
            out.extend_from_slice(&key);
            for (i, b) in self.payload.iter().enumerate() {
                out.push(b ^ key[i & 3]);
            }
        } else {
            out.extend_from_slice(&self.payload);
        }
        Ok(out)
    }

    /// Decode one frame from the start of `buf`. Returns the frame
    /// (with masking unwound) and the byte count consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), WsError> {
        if buf.len() < 2 {
            return Err(WsError::Short);
        }
        let byte0 = buf[0];
        let byte1 = buf[1];
        let fin = (byte0 & FIN_BIT) != 0;
        let rsv1 = (byte0 & 0x40) != 0;
        let rsv2 = (byte0 & 0x20) != 0;
        let rsv3 = (byte0 & 0x10) != 0;
        let opcode = byte0 & 0x0F;
        let masked = (byte1 & MASK_BIT) != 0;
        let len_field = byte1 & 0x7F;
        let mut p = 2;
        let length: usize = match len_field {
            0..=125 => len_field as usize,
            126 => {
                if buf.len() < p + 2 {
                    return Err(WsError::Short);
                }
                let n = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
                p += 2;
                n
            }
            127 => {
                if buf.len() < p + 8 {
                    return Err(WsError::Short);
                }
                let n = u64::from_be_bytes([
                    buf[p],
                    buf[p + 1],
                    buf[p + 2],
                    buf[p + 3],
                    buf[p + 4],
                    buf[p + 5],
                    buf[p + 6],
                    buf[p + 7],
                ]);
                if n & (1 << 63) != 0 {
                    return Err(WsError::BadLength);
                }
                p += 8;
                n as usize
            }
            _ => unreachable!(),
        };
        let mask = if masked {
            if buf.len() < p + 4 {
                return Err(WsError::Short);
            }
            let m = [buf[p], buf[p + 1], buf[p + 2], buf[p + 3]];
            p += 4;
            Some(m)
        } else {
            None
        };
        if buf.len() < p + length {
            return Err(WsError::Short);
        }
        let mut payload = buf[p..p + length].to_vec();
        if let Some(key) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= key[i & 3];
            }
        }
        if (opcode & 0x08) != 0 && length > 125 {
            return Err(WsError::ControlFrameTooLong);
        }
        Ok((
            Self {
                fin,
                rsv1,
                rsv2,
                rsv3,
                opcode,
                mask,
                payload,
            },
            p + length,
        ))
    }
}

// ── Convenience builders ───────────────────────────────────────────

/// Build an unmasked text frame (server-side direction).
pub fn text_frame(text: &str, fin: bool) -> Frame {
    Frame {
        fin,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OP_TEXT,
        mask: None,
        payload: text.as_bytes().to_vec(),
    }
}

/// Build an unmasked binary frame.
pub fn binary_frame(data: Vec<u8>, fin: bool) -> Frame {
    Frame {
        fin,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OP_BINARY,
        mask: None,
        payload: data,
    }
}

/// Build a Close frame. The 2-byte status code comes first; an
/// optional UTF-8 reason follows. RFC 6455 §5.5.1.
pub fn close_frame(status: u16, reason: &str) -> Frame {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&status.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OP_CLOSE,
        mask: None,
        payload,
    }
}

/// Build a Ping frame.
pub fn ping_frame(payload: Vec<u8>) -> Frame {
    Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OP_PING,
        mask: None,
        payload,
    }
}

/// Build a Pong frame.
pub fn pong_frame(payload: Vec<u8>) -> Frame {
    Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OP_PONG,
        mask: None,
        payload,
    }
}
