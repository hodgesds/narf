//! WireGuard packet codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **Jason A. Donenfeld, "WireGuard: Next Generation Kernel
//!   Network Tunnel"**, NDSS 2017.
//!   <https://www.wireguard.com/papers/wireguard.pdf>
//!   - §5 — message format.
//!   - §5.4 — handshake initiation / response message wire layout.
//!   - §5.5 — cookie-reply message.
//!   - §5.6 — transport-data message.
//! - **WireGuard Protocol & Cryptography** reference page.
//!   <https://www.wireguard.com/protocol/>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Wire-format codec for the four WireGuard message types: framing,
//! field offsets, type / reserved-byte validation. The actual
//! cryptography (Curve25519 ECDH, BLAKE2s-keyed MAC, ChaCha20-
//! Poly1305 AEAD) lives in `crypto/`; this module produces / parses
//! the byte layout into / out of which those operations slot.

extern crate alloc;
use alloc::vec::Vec;

/// Message Type (whitepaper §5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
}

impl MessageType {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::HandshakeInitiation,
            2 => Self::HandshakeResponse,
            3 => Self::CookieReply,
            4 => Self::TransportData,
            _ => return None,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WgError {
    Short,
    BadType,
    /// Reserved bytes 1..4 must be zero (§5.1).
    NonZeroReserved,
}

// ── Handshake Initiation (whitepaper §5.4.2) ─────────────────────
// Total: 148 bytes.
//   0:        u8  message_type = 1
//   1..4:     reserved [0; 3]
//   4..8:     u32 LE sender_index
//   8..40:    [u8; 32] unencrypted_ephemeral
//   40..88:   [u8; 32+16] encrypted_static (AEAD tag 16)
//   88..116:  [u8; 12+16] encrypted_timestamp (AEAD tag 16)
//   116..132: [u8; 16] mac1
//   132..148: [u8; 16] mac2

pub const HANDSHAKE_INITIATION_LEN: usize = 148;
pub const HANDSHAKE_RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
/// Transport-data minimum: 16-byte AEAD tag, no inner payload.
pub const TRANSPORT_DATA_MIN_LEN: usize = 32;

/// Decoded Handshake-Initiation header (referenced by slices into
/// the original buffer; no copies).
#[derive(Copy, Clone, Debug)]
pub struct HandshakeInitiation<'a> {
    pub sender_index: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_static: &'a [u8; 48],
    pub encrypted_timestamp: &'a [u8; 28],
    pub mac1: &'a [u8; 16],
    pub mac2: &'a [u8; 16],
}

pub fn build_handshake_initiation(
    sender_index: u32,
    unencrypted_ephemeral: &[u8; 32],
    encrypted_static: &[u8; 48],
    encrypted_timestamp: &[u8; 28],
    mac1: &[u8; 16],
    mac2: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HANDSHAKE_INITIATION_LEN);
    buf.push(MessageType::HandshakeInitiation as u8);
    buf.extend_from_slice(&[0, 0, 0]);
    buf.extend_from_slice(&sender_index.to_le_bytes());
    buf.extend_from_slice(unencrypted_ephemeral);
    buf.extend_from_slice(encrypted_static);
    buf.extend_from_slice(encrypted_timestamp);
    buf.extend_from_slice(mac1);
    buf.extend_from_slice(mac2);
    buf
}

pub fn decode_handshake_initiation(buf: &[u8]) -> Result<HandshakeInitiation<'_>, WgError> {
    if buf.len() < HANDSHAKE_INITIATION_LEN {
        return Err(WgError::Short);
    }
    if buf[0] != MessageType::HandshakeInitiation as u8 {
        return Err(WgError::BadType);
    }
    if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
        return Err(WgError::NonZeroReserved);
    }
    Ok(HandshakeInitiation {
        sender_index: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        unencrypted_ephemeral: (&buf[8..40]).try_into().unwrap(),
        encrypted_static: (&buf[40..88]).try_into().unwrap(),
        encrypted_timestamp: (&buf[88..116]).try_into().unwrap(),
        mac1: (&buf[116..132]).try_into().unwrap(),
        mac2: (&buf[132..148]).try_into().unwrap(),
    })
}

// ── Handshake Response (§5.4.3) ──────────────────────────────────
// Total: 92 bytes.
//   0:        u8 message_type = 2
//   1..4:     reserved [0; 3]
//   4..8:     u32 LE sender_index
//   8..12:    u32 LE receiver_index
//   12..44:   [u8; 32] unencrypted_ephemeral
//   44..60:   [u8; 0+16] encrypted_nothing (AEAD tag only)
//   60..76:   [u8; 16] mac1
//   76..92:   [u8; 16] mac2

#[derive(Copy, Clone, Debug)]
pub struct HandshakeResponse<'a> {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8; 16],
    pub mac1: &'a [u8; 16],
    pub mac2: &'a [u8; 16],
}

pub fn build_handshake_response(
    sender_index: u32,
    receiver_index: u32,
    unencrypted_ephemeral: &[u8; 32],
    encrypted_nothing: &[u8; 16],
    mac1: &[u8; 16],
    mac2: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HANDSHAKE_RESPONSE_LEN);
    buf.push(MessageType::HandshakeResponse as u8);
    buf.extend_from_slice(&[0, 0, 0]);
    buf.extend_from_slice(&sender_index.to_le_bytes());
    buf.extend_from_slice(&receiver_index.to_le_bytes());
    buf.extend_from_slice(unencrypted_ephemeral);
    buf.extend_from_slice(encrypted_nothing);
    buf.extend_from_slice(mac1);
    buf.extend_from_slice(mac2);
    buf
}

pub fn decode_handshake_response(buf: &[u8]) -> Result<HandshakeResponse<'_>, WgError> {
    if buf.len() < HANDSHAKE_RESPONSE_LEN {
        return Err(WgError::Short);
    }
    if buf[0] != MessageType::HandshakeResponse as u8 {
        return Err(WgError::BadType);
    }
    if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
        return Err(WgError::NonZeroReserved);
    }
    Ok(HandshakeResponse {
        sender_index: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        receiver_index: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        unencrypted_ephemeral: (&buf[12..44]).try_into().unwrap(),
        encrypted_nothing: (&buf[44..60]).try_into().unwrap(),
        mac1: (&buf[60..76]).try_into().unwrap(),
        mac2: (&buf[76..92]).try_into().unwrap(),
    })
}

// ── Cookie Reply (§5.5) ──────────────────────────────────────────
// Total: 64 bytes.
//   0:        u8 message_type = 3
//   1..4:     reserved [0; 3]
//   4..8:     u32 LE receiver_index
//   8..32:    [u8; 24] nonce
//   32..64:   [u8; 16+16] encrypted_cookie (16 bytes + 16 AEAD tag)

#[derive(Copy, Clone, Debug)]
pub struct CookieReply<'a> {
    pub receiver_index: u32,
    pub nonce: &'a [u8; 24],
    pub encrypted_cookie: &'a [u8; 32],
}

pub fn build_cookie_reply(
    receiver_index: u32,
    nonce: &[u8; 24],
    encrypted_cookie: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(COOKIE_REPLY_LEN);
    buf.push(MessageType::CookieReply as u8);
    buf.extend_from_slice(&[0, 0, 0]);
    buf.extend_from_slice(&receiver_index.to_le_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(encrypted_cookie);
    buf
}

pub fn decode_cookie_reply(buf: &[u8]) -> Result<CookieReply<'_>, WgError> {
    if buf.len() < COOKIE_REPLY_LEN {
        return Err(WgError::Short);
    }
    if buf[0] != MessageType::CookieReply as u8 {
        return Err(WgError::BadType);
    }
    if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
        return Err(WgError::NonZeroReserved);
    }
    Ok(CookieReply {
        receiver_index: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        nonce: (&buf[8..32]).try_into().unwrap(),
        encrypted_cookie: (&buf[32..64]).try_into().unwrap(),
    })
}

// ── Transport Data (§5.6) ────────────────────────────────────────
// Header is 16 bytes; encrypted payload follows + 16-byte AEAD tag.
//   0:        u8 message_type = 4
//   1..4:     reserved [0; 3]
//   4..8:     u32 LE receiver_index
//   8..16:    u64 LE counter
//   16..N:    encrypted payload (16 bytes minimum, for the AEAD tag)

#[derive(Copy, Clone, Debug)]
pub struct TransportHeader {
    pub receiver_index: u32,
    pub counter: u64,
}

pub fn build_transport_header(receiver_index: u32, counter: u64) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    hdr[0] = MessageType::TransportData as u8;
    hdr[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    hdr[8..16].copy_from_slice(&counter.to_le_bytes());
    hdr
}

pub fn decode_transport_header(buf: &[u8]) -> Result<TransportHeader, WgError> {
    if buf.len() < 16 {
        return Err(WgError::Short);
    }
    if buf[0] != MessageType::TransportData as u8 {
        return Err(WgError::BadType);
    }
    if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
        return Err(WgError::NonZeroReserved);
    }
    Ok(TransportHeader {
        receiver_index: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        counter: u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]),
    })
}

/// Anti-replay window — accept a packet whose counter is within
/// the last `WINDOW_SIZE` of the highest seen counter and not
/// previously seen. A fresh peer state starts with `highest = 0`
/// and `bitmap = 0` and rejects counter 0 (which is a Sentinel for
/// "uninitialised" per WireGuard's nonce-once-per-key semantics).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AntiReplay {
    pub highest: u64,
    pub bitmap: u128,
}

impl AntiReplay {
    pub const WINDOW_SIZE: u64 = 128;

    /// Accept-and-update. Returns `false` if the packet is too old
    /// or already seen.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter == 0 || counter > self.highest + (1 << 63) {
            // 0 is reserved; counter > highest + 2^63 is a sender
            // bug we don't accommodate.
            if counter == 0 {
                return false;
            }
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift >= Self::WINDOW_SIZE {
                self.bitmap = 1; // wipe; only the new packet remains
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = counter;
            return true;
        }
        let dist = self.highest - counter;
        if dist >= Self::WINDOW_SIZE {
            return false;
        }
        let bit = 1u128 << dist;
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }
}
