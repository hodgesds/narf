//! MQTT v5.0 fixed-header + CONNECT codec — clean-room.
//!
//! References (public-only):
//! - "MQTT Version 5.0" — OASIS Standard, 7 March 2019. Public.
//!   §2.1 (Fixed Header), §2.1.4 (Remaining Length variable-length
//!   integer with 7-bit per-byte continuation encoding), §3.1
//!   CONNECT Packet, §3.2 CONNACK, §3.3 PUBLISH, §3.8 SUBSCRIBE,
//!   §3.13 PINGREQ / PINGRESP, §3.14 DISCONNECT, §3.15 AUTH.
//!   <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
//! - "MQTT Version 3.1.1" — OASIS Standard, 29 October 2014. Public.
//!   Referenced for the protocol-name "MQTT" + level=4 vs v5 level=5.
//!   <https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html>
//!
//! No GPL Linux source consulted.
//!
//! ## Fixed header (MQTT 5.0 §2.1)
//!
//! ```text
//!   byte 0     packet type (high nibble) | flags (low nibble)
//!   bytes 1..N Remaining Length (variable-length integer, 1..4 bytes)
//! ```
//!
//! Remaining Length encodes 0..268_435_455 in big-endian-ish base-128
//! continuation form: each byte's high bit (continuation flag) is 1
//! if more bytes follow, low 7 bits carry data.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ── Packet types (MQTT 5.0 §2.1.2 table 2-1) ──────────────────────

pub const PT_CONNECT: u8 = 1;
pub const PT_CONNACK: u8 = 2;
pub const PT_PUBLISH: u8 = 3;
pub const PT_PUBACK: u8 = 4;
pub const PT_PUBREC: u8 = 5;
pub const PT_PUBREL: u8 = 6;
pub const PT_PUBCOMP: u8 = 7;
pub const PT_SUBSCRIBE: u8 = 8;
pub const PT_SUBACK: u8 = 9;
pub const PT_UNSUBSCRIBE: u8 = 10;
pub const PT_UNSUBACK: u8 = 11;
pub const PT_PINGREQ: u8 = 12;
pub const PT_PINGRESP: u8 = 13;
pub const PT_DISCONNECT: u8 = 14;
pub const PT_AUTH: u8 = 15;

// ── CONNECT flags (§3.1.2.3) ──────────────────────────────────────

pub const CONNECT_USERNAME: u8 = 1 << 7;
pub const CONNECT_PASSWORD: u8 = 1 << 6;
pub const CONNECT_WILL_RETAIN: u8 = 1 << 5;
pub const CONNECT_WILL_QOS_MASK: u8 = 0b11 << 3;
pub const CONNECT_WILL_FLAG: u8 = 1 << 2;
pub const CONNECT_CLEAN_START: u8 = 1 << 1;

// ── CONNACK reason codes (selected, §3.2.2.2) ─────────────────────

pub const REASON_SUCCESS: u8 = 0x00;
pub const REASON_UNSPECIFIED_ERROR: u8 = 0x80;
pub const REASON_MALFORMED_PACKET: u8 = 0x81;
pub const REASON_PROTOCOL_ERROR: u8 = 0x82;
pub const REASON_UNSUPPORTED_PROTOCOL_VERSION: u8 = 0x84;
pub const REASON_CLIENT_ID_NOT_VALID: u8 = 0x85;
pub const REASON_BAD_USER_NAME_OR_PASSWORD: u8 = 0x86;
pub const REASON_NOT_AUTHORIZED: u8 = 0x87;
pub const REASON_SERVER_BUSY: u8 = 0x89;
pub const REASON_BANNED: u8 = 0x8A;
pub const REASON_BAD_AUTHENTICATION_METHOD: u8 = 0x8C;
pub const REASON_TOPIC_NAME_INVALID: u8 = 0x90;

// Property identifiers (selected, §2.2.2.2 table 2-4).
pub const PROPERTY_SESSION_EXPIRY_INTERVAL: u8 = 0x11;
pub const PROPERTY_RECEIVE_MAXIMUM: u8 = 0x21;
pub const PROPERTY_MAXIMUM_QOS: u8 = 0x24;
pub const PROPERTY_RETAIN_AVAILABLE: u8 = 0x25;
pub const PROPERTY_MAXIMUM_PACKET_SIZE: u8 = 0x27;
pub const PROPERTY_ASSIGNED_CLIENT_IDENTIFIER: u8 = 0x12;
pub const PROPERTY_TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
pub const PROPERTY_REASON_STRING: u8 = 0x1F;
pub const PROPERTY_USER_PROPERTY: u8 = 0x26;
pub const PROPERTY_AUTHENTICATION_METHOD: u8 = 0x15;
pub const PROPERTY_AUTHENTICATION_DATA: u8 = 0x16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MqttError {
    Short,
    /// Remaining Length VarInt exceeded 4 bytes (§2.1.4).
    BadVarInt,
    Truncated,
}

// ── Remaining Length (§2.1.4) ─────────────────────────────────────

/// Encode a value 0..268_435_455 to its 1-4 byte VarInt form.
pub fn encode_var_int(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a VarInt from the start of `buf`. Returns (value, bytes
/// consumed).
pub fn decode_var_int(buf: &[u8]) -> Result<(u32, usize), MqttError> {
    let mut value: u32 = 0;
    let mut multiplier: u32 = 1;
    for i in 0..4 {
        if i >= buf.len() {
            return Err(MqttError::Short);
        }
        let b = buf[i];
        value += ((b & 0x7F) as u32) * multiplier;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        multiplier *= 128;
    }
    Err(MqttError::BadVarInt)
}

// ── Fixed header ──────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FixedHeader {
    pub packet_type: u8,
    pub flags: u8,
    pub remaining_length: u32,
}

impl FixedHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(((self.packet_type & 0x0F) << 4) | (self.flags & 0x0F));
        encode_var_int(out, self.remaining_length);
    }

    /// Decode the fixed header. Returns the parsed header + the byte
    /// count it consumed (1 + 1..4 VarInt bytes).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), MqttError> {
        if buf.is_empty() {
            return Err(MqttError::Short);
        }
        let packet_type = (buf[0] >> 4) & 0x0F;
        let flags = buf[0] & 0x0F;
        let (remaining_length, vlen) = decode_var_int(&buf[1..])?;
        Ok((
            Self {
                packet_type,
                flags,
                remaining_length,
            },
            1 + vlen,
        ))
    }
}

// ── UTF-8 string (§1.5.4) ─────────────────────────────────────────

/// Append an MQTT UTF-8 string: 2-byte BE length + bytes.
pub fn append_utf8_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Decode an MQTT UTF-8 string starting at `pos`. Returns
/// (string, bytes consumed).
pub fn decode_utf8_string(buf: &[u8], pos: usize) -> Result<(String, usize), MqttError> {
    if buf.len() < pos + 2 {
        return Err(MqttError::Short);
    }
    let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    if buf.len() < pos + 2 + len {
        return Err(MqttError::Truncated);
    }
    let s = core::str::from_utf8(&buf[pos + 2..pos + 2 + len])
        .unwrap_or("")
        .into();
    Ok((s, 2 + len))
}

// ── CONNECT (§3.1) ────────────────────────────────────────────────

/// Build a CONNECT packet for MQTT v5.
///
/// Fixed parts:
///   * Protocol Name: UTF-8 string "MQTT"
///   * Protocol Level: 5 (MQTT 5)
///   * Connect Flags: bitmap (set CLEAN_START as needed)
///   * Keep Alive: BE u16 in seconds
///   * Properties Length: VarInt (we emit 0 — no properties)
///   * Client Identifier: UTF-8 string (may be empty for server-assigned)
pub fn build_connect_v5(
    flags: u8,
    keep_alive_secs: u16,
    client_id: &str,
) -> Vec<u8> {
    // Variable header.
    let mut variable = Vec::with_capacity(64 + client_id.len());
    append_utf8_string(&mut variable, "MQTT");
    variable.push(5); // Protocol Level
    variable.push(flags);
    variable.extend_from_slice(&keep_alive_secs.to_be_bytes());
    encode_var_int(&mut variable, 0); // properties length

    // Payload.
    let mut payload = Vec::with_capacity(2 + client_id.len());
    append_utf8_string(&mut payload, client_id);

    let body_len = variable.len() + payload.len();
    let mut out = Vec::with_capacity(2 + body_len);
    let header = FixedHeader {
        packet_type: PT_CONNECT,
        flags: 0, // CONNECT reserved flags = 0
        remaining_length: body_len as u32,
    };
    header.encode(&mut out);
    out.extend_from_slice(&variable);
    out.extend_from_slice(&payload);
    out
}

/// Build a PUBLISH packet (§3.3). `qos` is 0..=2; `retain` and `dup`
/// go in fixed-header flags.
pub fn build_publish_v5(
    dup: bool,
    qos: u8,
    retain: bool,
    topic: &str,
    packet_id: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut flags = (qos & 0x03) << 1;
    if dup {
        flags |= 0x08;
    }
    if retain {
        flags |= 0x01;
    }
    let mut variable = Vec::with_capacity(2 + topic.len() + 2 + 1);
    append_utf8_string(&mut variable, topic);
    if let Some(id) = packet_id {
        variable.extend_from_slice(&id.to_be_bytes());
    }
    encode_var_int(&mut variable, 0); // no properties

    let body_len = variable.len() + payload.len();
    let mut out = Vec::with_capacity(2 + body_len);
    let header = FixedHeader {
        packet_type: PT_PUBLISH,
        flags,
        remaining_length: body_len as u32,
    };
    header.encode(&mut out);
    out.extend_from_slice(&variable);
    out.extend_from_slice(payload);
    out
}

/// Build a PINGREQ (no body).
pub fn build_pingreq() -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    let header = FixedHeader {
        packet_type: PT_PINGREQ,
        flags: 0,
        remaining_length: 0,
    };
    header.encode(&mut out);
    out
}

/// Build a DISCONNECT for v5 with the supplied reason code (§3.14).
pub fn build_disconnect_v5(reason_code: u8) -> Vec<u8> {
    let mut variable = Vec::with_capacity(2);
    variable.push(reason_code);
    encode_var_int(&mut variable, 0); // no properties
    let mut out = Vec::with_capacity(2 + variable.len());
    let header = FixedHeader {
        packet_type: PT_DISCONNECT,
        flags: 0,
        remaining_length: variable.len() as u32,
    };
    header.encode(&mut out);
    out.extend_from_slice(&variable);
    out
}
