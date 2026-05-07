//! ATT — Attribute Protocol.
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part F. Public
//! Bluetooth SIG document. No GPL Linux source consulted.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! ATT carries attribute reads/writes between client and server over
//! L2CAP fixed CID 0x0004 (BLE) — every BLE GATT operation is one or
//! more ATT PDUs underneath.
//!
//! ## PDU layout (§3.3)
//!
//!   0:    u8   Opcode (bit 7 = Authentication signature, bit 6 =
//!              Command/Request)
//!   1..N: parameters (opcode-specific)
//!
//! Opcodes are bucketed (§3.4):
//!
//!   0x01 Error Response
//!   0x02 Exchange MTU Request    0x03 Exchange MTU Response
//!   0x04 Find Information Req    0x05 Find Information Rsp
//!   0x06 Find By Type Value Req  0x07 Find By Type Value Rsp
//!   0x08 Read By Type Req        0x09 Read By Type Rsp
//!   0x0A Read Request            0x0B Read Response
//!   0x0C Read Blob Request       0x0D Read Blob Response
//!   0x0E Read Multiple Request   0x0F Read Multiple Response
//!   0x10 Read By Group Type Req  0x11 Read By Group Type Rsp
//!   0x12 Write Request           0x13 Write Response
//!   0x52 Write Command (no response)
//!   0x16 Prepare Write Request   0x17 Prepare Write Response
//!   0x18 Execute Write Request   0x19 Execute Write Response
//!   0x1B Handle Value Notification  0x1D Handle Value Indication
//!   0x1E Handle Value Confirmation
//!   0xD2 Signed Write Command

use alloc::vec::Vec;

// ── Opcodes (§3.4) ─────────────────────────────────────────────────
pub const ATT_ERROR_RSP: u8 = 0x01;
pub const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
pub const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
pub const ATT_FIND_INFORMATION_REQ: u8 = 0x04;
pub const ATT_FIND_INFORMATION_RSP: u8 = 0x05;
pub const ATT_FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
pub const ATT_FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
pub const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
pub const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
pub const ATT_READ_REQ: u8 = 0x0A;
pub const ATT_READ_RSP: u8 = 0x0B;
pub const ATT_READ_BLOB_REQ: u8 = 0x0C;
pub const ATT_READ_BLOB_RSP: u8 = 0x0D;
pub const ATT_READ_MULTIPLE_REQ: u8 = 0x0E;
pub const ATT_READ_MULTIPLE_RSP: u8 = 0x0F;
pub const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub const ATT_WRITE_REQ: u8 = 0x12;
pub const ATT_WRITE_RSP: u8 = 0x13;
pub const ATT_WRITE_CMD: u8 = 0x52;
pub const ATT_PREPARE_WRITE_REQ: u8 = 0x16;
pub const ATT_PREPARE_WRITE_RSP: u8 = 0x17;
pub const ATT_EXECUTE_WRITE_REQ: u8 = 0x18;
pub const ATT_EXECUTE_WRITE_RSP: u8 = 0x19;
pub const ATT_HANDLE_VALUE_NTF: u8 = 0x1B;
pub const ATT_HANDLE_VALUE_IND: u8 = 0x1D;
pub const ATT_HANDLE_VALUE_CFM: u8 = 0x1E;
pub const ATT_SIGNED_WRITE_CMD: u8 = 0xD2;

// ── ATT error codes (§3.4.1.1) ────────────────────────────────────
pub const ATT_ECODE_INVALID_HANDLE: u8 = 0x01;
pub const ATT_ECODE_READ_NOT_PERMITTED: u8 = 0x02;
pub const ATT_ECODE_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ATT_ECODE_INVALID_PDU: u8 = 0x04;
pub const ATT_ECODE_INSUFFICIENT_AUTH: u8 = 0x05;
pub const ATT_ECODE_REQUEST_NOT_SUPPORTED: u8 = 0x06;
pub const ATT_ECODE_INVALID_OFFSET: u8 = 0x07;
pub const ATT_ECODE_INSUFFICIENT_AUTHORIZATION: u8 = 0x08;
pub const ATT_ECODE_PREPARE_QUEUE_FULL: u8 = 0x09;
pub const ATT_ECODE_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
pub const ATT_ECODE_ATTRIBUTE_NOT_LONG: u8 = 0x0B;
pub const ATT_ECODE_INSUFFICIENT_KEY_SIZE: u8 = 0x0C;
pub const ATT_ECODE_INVALID_VALUE_LENGTH: u8 = 0x0D;
pub const ATT_ECODE_UNLIKELY: u8 = 0x0E;
pub const ATT_ECODE_INSUFFICIENT_ENC: u8 = 0x0F;
pub const ATT_ECODE_UNSUPPORTED_GROUP_TYPE: u8 = 0x10;
pub const ATT_ECODE_INSUFFICIENT_RESOURCES: u8 = 0x11;

/// Default ATT MTU on a fresh BLE link (§3.4.2). Either side may
/// initiate Exchange MTU to grow it.
pub const ATT_DEFAULT_MTU: u16 = 23;

/// Decoded ATT PDU. We keep parameters as a slice for zero-copy
/// dispatch; the per-opcode decoders below pull structured fields
/// out of `params`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    pub opcode: u8,
    pub params: Vec<u8>,
}

impl Pdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.params.len());
        out.push(self.opcode);
        out.extend_from_slice(&self.params);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        Some(Self {
            opcode: buf[0],
            params: buf[1..].to_vec(),
        })
    }

    /// `true` if this opcode expects a response from the peer
    /// (§3.3.2). Commands and notifications do not.
    pub fn expects_response(&self) -> bool {
        // Bit 7 of the opcode is the "Authentication Signature"
        // flag — strip it before classifying. Bit 6 is the
        // "Command Flag" — when set, no response is expected.
        let core = self.opcode & 0x7F;
        if core & 0x40 != 0 {
            return false;
        }
        !matches!(core, ATT_HANDLE_VALUE_NTF | ATT_HANDLE_VALUE_CFM)
    }
}

// ── Exchange MTU (§3.4.2) ─────────────────────────────────────────

/// Build an Exchange_MTU_Request with the client's preferred MTU.
pub fn build_exchange_mtu_request(client_rx_mtu: u16) -> Pdu {
    let mut p = Vec::with_capacity(2);
    p.push((client_rx_mtu & 0xFF) as u8);
    p.push((client_rx_mtu >> 8) as u8);
    Pdu {
        opcode: ATT_EXCHANGE_MTU_REQ,
        params: p,
    }
}

/// Build an Exchange_MTU_Response with the server's preferred MTU.
pub fn build_exchange_mtu_response(server_rx_mtu: u16) -> Pdu {
    let mut p = Vec::with_capacity(2);
    p.push((server_rx_mtu & 0xFF) as u8);
    p.push((server_rx_mtu >> 8) as u8);
    Pdu {
        opcode: ATT_EXCHANGE_MTU_RSP,
        params: p,
    }
}

/// Decode an Exchange MTU request/response payload (both shapes are
/// a single u16 per §3.4.2).
pub fn decode_exchange_mtu(p: &Pdu) -> Option<u16> {
    if p.opcode != ATT_EXCHANGE_MTU_REQ && p.opcode != ATT_EXCHANGE_MTU_RSP {
        return None;
    }
    if p.params.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([p.params[0], p.params[1]]))
}

// ── Read (§3.4.4) ─────────────────────────────────────────────────

pub fn build_read_request(handle: u16) -> Pdu {
    let mut p = Vec::with_capacity(2);
    p.push((handle & 0xFF) as u8);
    p.push((handle >> 8) as u8);
    Pdu {
        opcode: ATT_READ_REQ,
        params: p,
    }
}

pub fn build_read_response(value: &[u8]) -> Pdu {
    Pdu {
        opcode: ATT_READ_RSP,
        params: value.to_vec(),
    }
}

pub fn decode_read_request(p: &Pdu) -> Option<u16> {
    if p.opcode != ATT_READ_REQ || p.params.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([p.params[0], p.params[1]]))
}

// ── Write (§3.4.5) ────────────────────────────────────────────────

pub fn build_write_request(handle: u16, value: &[u8]) -> Pdu {
    let mut p = Vec::with_capacity(2 + value.len());
    p.push((handle & 0xFF) as u8);
    p.push((handle >> 8) as u8);
    p.extend_from_slice(value);
    Pdu {
        opcode: ATT_WRITE_REQ,
        params: p,
    }
}

pub fn build_write_command(handle: u16, value: &[u8]) -> Pdu {
    let mut p = Vec::with_capacity(2 + value.len());
    p.push((handle & 0xFF) as u8);
    p.push((handle >> 8) as u8);
    p.extend_from_slice(value);
    Pdu {
        opcode: ATT_WRITE_CMD,
        params: p,
    }
}

pub fn build_write_response() -> Pdu {
    Pdu {
        opcode: ATT_WRITE_RSP,
        params: Vec::new(),
    }
}

/// Decode a Write Request / Write Command parameter block: 2-byte
/// handle followed by the value.
pub fn decode_write(p: &Pdu) -> Option<(u16, &[u8])> {
    if p.opcode != ATT_WRITE_REQ && p.opcode != ATT_WRITE_CMD {
        return None;
    }
    if p.params.len() < 2 {
        return None;
    }
    Some((
        u16::from_le_bytes([p.params[0], p.params[1]]),
        &p.params[2..],
    ))
}

// ── Notification / Indication (§3.4.7) ────────────────────────────

pub fn build_handle_value_notification(handle: u16, value: &[u8]) -> Pdu {
    let mut p = Vec::with_capacity(2 + value.len());
    p.push((handle & 0xFF) as u8);
    p.push((handle >> 8) as u8);
    p.extend_from_slice(value);
    Pdu {
        opcode: ATT_HANDLE_VALUE_NTF,
        params: p,
    }
}

pub fn build_handle_value_indication(handle: u16, value: &[u8]) -> Pdu {
    let mut p = Vec::with_capacity(2 + value.len());
    p.push((handle & 0xFF) as u8);
    p.push((handle >> 8) as u8);
    p.extend_from_slice(value);
    Pdu {
        opcode: ATT_HANDLE_VALUE_IND,
        params: p,
    }
}

pub fn build_handle_value_confirmation() -> Pdu {
    Pdu {
        opcode: ATT_HANDLE_VALUE_CFM,
        params: Vec::new(),
    }
}

/// Decode a notification / indication PDU into `(handle, value)`.
pub fn decode_handle_value(p: &Pdu) -> Option<(u16, &[u8])> {
    if p.opcode != ATT_HANDLE_VALUE_NTF && p.opcode != ATT_HANDLE_VALUE_IND {
        return None;
    }
    if p.params.len() < 2 {
        return None;
    }
    Some((
        u16::from_le_bytes([p.params[0], p.params[1]]),
        &p.params[2..],
    ))
}

// ── Error Response (§3.4.1) ───────────────────────────────────────

/// Decoded Error Response (§3.4.1.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub request_opcode: u8,
    pub attribute_handle: u16,
    pub error_code: u8,
}

pub fn build_error_response(req_opcode: u8, handle: u16, ecode: u8) -> Pdu {
    Pdu {
        opcode: ATT_ERROR_RSP,
        params: alloc::vec![
            req_opcode,
            (handle & 0xFF) as u8,
            (handle >> 8) as u8,
            ecode,
        ],
    }
}

pub fn decode_error_response(p: &Pdu) -> Option<ErrorResponse> {
    if p.opcode != ATT_ERROR_RSP || p.params.len() < 4 {
        return None;
    }
    Some(ErrorResponse {
        request_opcode: p.params[0],
        attribute_handle: u16::from_le_bytes([p.params[1], p.params[2]]),
        error_code: p.params[3],
    })
}
