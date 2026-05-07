//! TCP segment codec — clean-room.
//!
//! References (public-only):
//! - RFC 9293 — Transmission Control Protocol (W. Eddy, Aug 2022).
//!   §3.1 Header Format. §3.2 Terminology — control flags FIN/SYN/
//!   RST/PSH/ACK/URG/ECE/CWR. §3.7.2 Connection state machine.
//! - RFC 1071 — Computing the Internet Checksum. The 16-bit ones-
//!   complement sum we reuse for the TCP pseudo-header.
//! - RFC 7323 — TCP Extensions for High Performance (Window Scale
//!   option kind 3, Timestamps option kind 8).
//! - RFC 2018 — TCP Selective Acknowledgment Options (kind 4 SACK
//!   permitted; kind 5 SACK).
//!
//! No GPL Linux source consulted.
//!
//! ## Header (RFC 9293 §3.1)
//!
//! Minimum 20 bytes, options pad up to a 60-byte ceiling:
//!
//! ```text
//!   bytes 0..1   Source Port (BE)
//!   bytes 2..3   Destination Port (BE)
//!   bytes 4..7   Sequence Number (BE)
//!   bytes 8..11  Acknowledgement Number (BE)
//!   byte 12      Data Offset (4 bits, MSBs) | Reserved (3 bits) |
//!                bit 0 of Flags (NS — RFC 3540, surfaced as `cwr`
//!                bit at position 7 of byte 13 here for symmetry).
//!   byte 13      Control Flags: CWR | ECE | URG | ACK | PSH | RST | SYN | FIN
//!   bytes 14..15 Window Size (BE)
//!   bytes 16..17 Checksum (BE)
//!   bytes 18..19 Urgent Pointer (BE)
//!   bytes 20..N  Options (must be padded to 4-byte multiple)
//! ```

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::ip_checksum;

/// Minimum TCP header size (no options).
pub const TCP_HDR_MIN: usize = 20;
/// Maximum TCP header size (with the full 40 bytes of options).
pub const TCP_HDR_MAX: usize = 60;

// Control-flag bits (byte 13).
pub const FLAG_FIN: u8 = 1 << 0;
pub const FLAG_SYN: u8 = 1 << 1;
pub const FLAG_RST: u8 = 1 << 2;
pub const FLAG_PSH: u8 = 1 << 3;
pub const FLAG_ACK: u8 = 1 << 4;
pub const FLAG_URG: u8 = 1 << 5;
pub const FLAG_ECE: u8 = 1 << 6;
pub const FLAG_CWR: u8 = 1 << 7;

// Option Kinds (RFC 9293 §3.1, RFC 7323).
pub const OPT_END_OF_LIST: u8 = 0;
pub const OPT_NOP: u8 = 1;
pub const OPT_MSS: u8 = 2;
pub const OPT_WINDOW_SCALE: u8 = 3;
pub const OPT_SACK_PERMITTED: u8 = 4;
pub const OPT_SACK: u8 = 5;
pub const OPT_TIMESTAMPS: u8 = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpError {
    Short,
    /// Data Offset field claims more bytes than the buffer contains.
    BadDataOffset,
    /// Computed checksum mismatch.
    BadChecksum,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    /// Header length in bytes (multiple of 4, in 20..=60).
    pub header_len: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    /// Raw options bytes (header_len - 20). Caller decodes via
    /// `iter_options`.
    pub options: Vec<u8>,
}

impl TcpHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_len as usize);
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.acknowledgement.to_be_bytes());
        let data_offset = (self.header_len / 4) as u8;
        out.push(data_offset << 4);
        out.push(self.flags);
        out.extend_from_slice(&self.window.to_be_bytes());
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        out.extend_from_slice(&self.options);
        // Pad options to 4-byte boundary with NOPs / EOL.
        while out.len() % 4 != 0 {
            out.push(OPT_END_OF_LIST);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TcpError> {
        if buf.len() < TCP_HDR_MIN {
            return Err(TcpError::Short);
        }
        let data_offset = (buf[12] >> 4) & 0x0F;
        let header_len = (data_offset as usize) * 4;
        if !(TCP_HDR_MIN..=TCP_HDR_MAX).contains(&header_len) {
            return Err(TcpError::BadDataOffset);
        }
        if buf.len() < header_len {
            return Err(TcpError::Short);
        }
        let mut h = Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            sequence: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            acknowledgement: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            header_len: header_len as u8,
            flags: buf[13],
            window: u16::from_be_bytes([buf[14], buf[15]]),
            checksum: u16::from_be_bytes([buf[16], buf[17]]),
            urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
            options: Vec::new(),
        };
        h.options = buf[20..header_len].to_vec();
        Ok((h, header_len))
    }
}

// ── Options decoder ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpOption<'a> {
    Nop,
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Timestamps { tsval: u32, tsecr: u32 },
    /// Anything else — kind + payload bytes.
    Other { kind: u8, data: &'a [u8] },
}

/// Iterate options. Stops at end-of-list (kind 0) or when the buffer
/// is exhausted.
pub fn iter_options(mut buf: &[u8]) -> impl Iterator<Item = TcpOption<'_>> {
    core::iter::from_fn(move || {
        loop {
            let head = *buf.first()?;
            match head {
                OPT_END_OF_LIST => return None,
                OPT_NOP => {
                    buf = &buf[1..];
                    return Some(TcpOption::Nop);
                }
                _ => break,
            }
        }
        if buf.len() < 2 {
            return None;
        }
        let kind = buf[0];
        let len = buf[1] as usize;
        if len < 2 || len > buf.len() {
            return None;
        }
        let payload = &buf[2..len];
        let opt = match kind {
            OPT_MSS if payload.len() == 2 => {
                TcpOption::Mss(u16::from_be_bytes([payload[0], payload[1]]))
            }
            OPT_WINDOW_SCALE if payload.len() == 1 => TcpOption::WindowScale(payload[0]),
            OPT_SACK_PERMITTED => TcpOption::SackPermitted,
            OPT_TIMESTAMPS if payload.len() == 8 => TcpOption::Timestamps {
                tsval: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
                tsecr: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
            },
            _ => TcpOption::Other { kind, data: payload },
        };
        buf = &buf[len..];
        Some(opt)
    })
}

// ── Pseudo-header checksum ─────────────────────────────────────────

pub fn ipv4_pseudo_checksum(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len() + 1);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.push(0);
    buf.push(crate::pkt::IP_PROTO_TCP);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    ip_checksum(&buf)
}

/// Verify the TCP segment checksum against the IPv4 pseudo-header.
pub fn verify_ipv4(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> Result<(), TcpError> {
    if segment.len() < TCP_HDR_MIN {
        return Err(TcpError::Short);
    }
    let mut probe: Vec<u8> = segment.to_vec();
    probe[16] = 0;
    probe[17] = 0;
    let calc = ipv4_pseudo_checksum(src, dst, &probe);
    let on_wire = u16::from_be_bytes([segment[16], segment[17]]);
    if calc != on_wire {
        return Err(TcpError::BadChecksum);
    }
    Ok(())
}

// ── Common builders ────────────────────────────────────────────────

/// Build a SYN segment carrying common active-open options:
/// MSS + Window Scale + SACK Permitted + Timestamps.
pub fn build_syn(
    src_port: u16,
    dst_port: u16,
    isn: u32,
    window: u16,
    mss: u16,
    wscale: u8,
    tsval: u32,
) -> TcpHeader {
    let mut options = Vec::with_capacity(20);
    options.push(OPT_MSS);
    options.push(4);
    options.extend_from_slice(&mss.to_be_bytes());
    options.push(OPT_NOP);
    options.push(OPT_WINDOW_SCALE);
    options.push(3);
    options.push(wscale);
    options.push(OPT_SACK_PERMITTED);
    options.push(2);
    options.push(OPT_NOP);
    options.push(OPT_NOP);
    options.push(OPT_TIMESTAMPS);
    options.push(10);
    options.extend_from_slice(&tsval.to_be_bytes());
    options.extend_from_slice(&[0u8; 4]); // tsecr = 0 on initial SYN
    while options.len() % 4 != 0 {
        options.push(OPT_END_OF_LIST);
    }
    let header_len = (TCP_HDR_MIN + options.len()) as u8;
    TcpHeader {
        src_port,
        dst_port,
        sequence: isn,
        acknowledgement: 0,
        header_len,
        flags: FLAG_SYN,
        window,
        checksum: 0,
        urgent_ptr: 0,
        options,
    }
}

/// Build a bare RST segment (RFC 9293 §3.10.7.1).
pub fn build_rst(src_port: u16, dst_port: u16, sequence: u32) -> TcpHeader {
    TcpHeader {
        src_port,
        dst_port,
        sequence,
        acknowledgement: 0,
        header_len: TCP_HDR_MIN as u8,
        flags: FLAG_RST,
        window: 0,
        checksum: 0,
        urgent_ptr: 0,
        options: Vec::new(),
    }
}
