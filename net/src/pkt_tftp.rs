//! TFTP packet codec — clean-room.
//!
//! References (public-only):
//! - RFC 1350 — The TFTP Protocol (Revision 2) (K. Sollins, July
//!   1992). §5 Packet Formats. Opcodes RRQ (1), WRQ (2), DATA (3),
//!   ACK (4), ERROR (5).
//!   <https://datatracker.ietf.org/doc/html/rfc1350>
//! - RFC 2347 — TFTP Option Extension (G. Malkin & A. Harkin, May
//!   1998). OACK (opcode 6) packets carry server-acknowledged
//!   options (e.g. blksize, timeout, tsize, windowsize from
//!   RFCs 2348 / 2349 / 7440).
//!   <https://datatracker.ietf.org/doc/html/rfc2347>
//!
//! No GPL Linux source consulted.
//!
//! ## Packet shapes (RFC 1350 §5)
//!
//! Read / Write Request:
//! ```text
//!   bytes 0..1   Opcode (1 = RRQ, 2 = WRQ)
//!   filename     NUL-terminated ASCII
//!   mode         NUL-terminated ASCII (one of "netascii", "octet",
//!                                       "mail")
//! ```
//!
//! Data:
//! ```text
//!   bytes 0..1   Opcode = 3
//!   bytes 2..3   Block #
//!   bytes 4..N   Data (0..512 bytes; < 512 marks last block)
//! ```
//!
//! Ack:
//! ```text
//!   bytes 0..1   Opcode = 4
//!   bytes 2..3   Block #
//! ```
//!
//! Error:
//! ```text
//!   bytes 0..1   Opcode = 5
//!   bytes 2..3   ErrorCode
//!   ErrMsg       NUL-terminated ASCII
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ── Opcodes ───────────────────────────────────────────────────────

pub const OP_RRQ: u16 = 1;
pub const OP_WRQ: u16 = 2;
pub const OP_DATA: u16 = 3;
pub const OP_ACK: u16 = 4;
pub const OP_ERROR: u16 = 5;
pub const OP_OACK: u16 = 6;

// ── Standard transfer modes ───────────────────────────────────────

pub const MODE_NETASCII: &str = "netascii";
pub const MODE_OCTET: &str = "octet";
pub const MODE_MAIL: &str = "mail";

// ── Error codes (RFC 1350 §5 + RFC 2347) ──────────────────────────

pub const ERROR_NOT_DEFINED: u16 = 0;
pub const ERROR_FILE_NOT_FOUND: u16 = 1;
pub const ERROR_ACCESS_VIOLATION: u16 = 2;
pub const ERROR_DISK_FULL: u16 = 3;
pub const ERROR_ILLEGAL_OPERATION: u16 = 4;
pub const ERROR_UNKNOWN_TID: u16 = 5;
pub const ERROR_FILE_ALREADY_EXISTS: u16 = 6;
pub const ERROR_NO_SUCH_USER: u16 = 7;
pub const ERROR_TERMINATE_TRANSFER: u16 = 8; // RFC 2347

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TftpError {
    Short,
    /// NUL-terminated string ran past the buffer.
    Unterminated,
    BadOpcode(u16),
}

// ── Helpers ───────────────────────────────────────────────────────

fn read_nul_string(buf: &[u8], pos: &mut usize) -> Result<String, TftpError> {
    let start = *pos;
    while *pos < buf.len() && buf[*pos] != 0 {
        *pos += 1;
    }
    if *pos >= buf.len() {
        return Err(TftpError::Unterminated);
    }
    let s = core::str::from_utf8(&buf[start..*pos]).unwrap_or("").into();
    *pos += 1; // skip NUL
    Ok(s)
}

fn write_nul_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

// ── Packet enum ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// RRQ / WRQ (opcode 1 / 2). `options` is empty unless RFC 2347
    /// extensions are negotiated.
    Request {
        opcode: u16,
        filename: String,
        mode: String,
        options: Vec<(String, String)>,
    },
    Data {
        block: u16,
        data: Vec<u8>,
    },
    Ack {
        block: u16,
    },
    Error {
        code: u16,
        message: String,
    },
    /// OACK — server's response to RFC 2347 options.
    OAck {
        options: Vec<(String, String)>,
    },
}

impl Packet {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Packet::Request {
                opcode,
                filename,
                mode,
                options,
            } => {
                out.extend_from_slice(&opcode.to_be_bytes());
                write_nul_string(&mut out, filename);
                write_nul_string(&mut out, mode);
                for (k, v) in options {
                    write_nul_string(&mut out, k);
                    write_nul_string(&mut out, v);
                }
            }
            Packet::Data { block, data } => {
                out.extend_from_slice(&OP_DATA.to_be_bytes());
                out.extend_from_slice(&block.to_be_bytes());
                out.extend_from_slice(data);
            }
            Packet::Ack { block } => {
                out.extend_from_slice(&OP_ACK.to_be_bytes());
                out.extend_from_slice(&block.to_be_bytes());
            }
            Packet::Error { code, message } => {
                out.extend_from_slice(&OP_ERROR.to_be_bytes());
                out.extend_from_slice(&code.to_be_bytes());
                write_nul_string(&mut out, message);
            }
            Packet::OAck { options } => {
                out.extend_from_slice(&OP_OACK.to_be_bytes());
                for (k, v) in options {
                    write_nul_string(&mut out, k);
                    write_nul_string(&mut out, v);
                }
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, TftpError> {
        if buf.len() < 2 {
            return Err(TftpError::Short);
        }
        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let mut pos = 2;
        match opcode {
            OP_RRQ | OP_WRQ => {
                let filename = read_nul_string(buf, &mut pos)?;
                let mode = read_nul_string(buf, &mut pos)?;
                let mut options = Vec::new();
                while pos < buf.len() {
                    let k = read_nul_string(buf, &mut pos)?;
                    if k.is_empty() {
                        break;
                    }
                    let v = read_nul_string(buf, &mut pos)?;
                    options.push((k, v));
                }
                Ok(Packet::Request {
                    opcode,
                    filename,
                    mode,
                    options,
                })
            }
            OP_DATA => {
                if buf.len() < 4 {
                    return Err(TftpError::Short);
                }
                Ok(Packet::Data {
                    block: u16::from_be_bytes([buf[2], buf[3]]),
                    data: buf[4..].to_vec(),
                })
            }
            OP_ACK => {
                if buf.len() < 4 {
                    return Err(TftpError::Short);
                }
                Ok(Packet::Ack {
                    block: u16::from_be_bytes([buf[2], buf[3]]),
                })
            }
            OP_ERROR => {
                if buf.len() < 4 {
                    return Err(TftpError::Short);
                }
                let code = u16::from_be_bytes([buf[2], buf[3]]);
                pos = 4;
                let message = read_nul_string(buf, &mut pos)?;
                Ok(Packet::Error { code, message })
            }
            OP_OACK => {
                let mut options = Vec::new();
                while pos < buf.len() {
                    let k = read_nul_string(buf, &mut pos)?;
                    if k.is_empty() {
                        break;
                    }
                    let v = read_nul_string(buf, &mut pos)?;
                    options.push((k, v));
                }
                Ok(Packet::OAck { options })
            }
            other => Err(TftpError::BadOpcode(other)),
        }
    }
}
