//! Service Discovery Protocol — clean-room.
//!
//! References (public-only):
//! - "Bluetooth Core Specification 5.3, Vol 3 Part B" — Bluetooth SIG.
//!   §3 (Service Records / Service Attributes), §4 (PDU formats: PDU
//!   Header, ServiceSearchRequest, ServiceAttributeRequest,
//!   ServiceSearchAttributeRequest), §5 (DataElement TLV encoding —
//!   type descriptor in the high 5 bits + size index in the low 3
//!   bits of the first byte).
//! - "Bluetooth Assigned Numbers" — SDP Service-Class UUIDs and
//!   Universal Attribute IDs (ServiceClassIDList = 0x0001,
//!   ProtocolDescriptorList = 0x0004, BluetoothProfileDescriptorList
//!   = 0x0009, ServiceName = 0x0100).
//! - Bluetooth Core 5.3 Vol 4 Part E — for L2CAP context: SDP runs on
//!   the dedicated L2CAP signalling PSM 0x0001.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## PDU header (§4.1)
//!
//! ```text
//!   byte 0      PDU Identifier
//!   bytes 1..2  Transaction ID (big-endian)
//!   bytes 3..4  Parameter length (big-endian, in bytes)
//!   bytes 5..N  PDU-specific parameters
//! ```
//!
//! ## DataElement encoding (§5.1)
//!
//! Every parameter value is wrapped in a TLV "DataElement". Each
//! element starts with one byte:
//!
//! ```text
//!   bits[7..3]  Type Descriptor (0..7)
//!   bits[2..0]  Size Index (0..7)
//! ```
//!
//! Size Index values (§5.1, table 5.1):
//!   0 = 1-byte fixed (or 0 bytes for type=0 NIL)
//!   1 = 2-byte fixed
//!   2 = 4-byte fixed
//!   3 = 8-byte fixed
//!   4 = 16-byte fixed
//!   5 = next 1 byte holds the length
//!   6 = next 2 bytes hold the length (big-endian)
//!   7 = next 4 bytes hold the length (big-endian)
//!
//! Type Descriptors (§5.1, table 5.1):
//!   0 NIL
//!   1 Unsigned Integer
//!   2 Signed Integer
//!   3 UUID
//!   4 Text String
//!   5 Boolean
//!   6 Sequence
//!   7 Alternative
//!   8 URL

use alloc::vec::Vec;

/// L2CAP PSM that carries SDP (Assigned Numbers).
pub const SDP_PSM: u16 = 0x0001;

// ── PDU IDs (§4.2) ─────────────────────────────────────────────────

pub const PDU_ERROR_RESPONSE: u8 = 0x01;
pub const PDU_SERVICE_SEARCH_REQUEST: u8 = 0x02;
pub const PDU_SERVICE_SEARCH_RESPONSE: u8 = 0x03;
pub const PDU_SERVICE_ATTRIBUTE_REQUEST: u8 = 0x04;
pub const PDU_SERVICE_ATTRIBUTE_RESPONSE: u8 = 0x05;
pub const PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST: u8 = 0x06;
pub const PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE: u8 = 0x07;

// ── Type Descriptors (§5.1) ────────────────────────────────────────

pub const DE_TYPE_NIL: u8 = 0;
pub const DE_TYPE_UINT: u8 = 1;
pub const DE_TYPE_INT: u8 = 2;
pub const DE_TYPE_UUID: u8 = 3;
pub const DE_TYPE_TEXT: u8 = 4;
pub const DE_TYPE_BOOL: u8 = 5;
pub const DE_TYPE_SEQUENCE: u8 = 6;
pub const DE_TYPE_ALTERNATIVE: u8 = 7;
pub const DE_TYPE_URL: u8 = 8;

// ── Universal Attribute IDs (Assigned Numbers) ─────────────────────

pub const ATTR_SERVICE_RECORD_HANDLE: u16 = 0x0000;
pub const ATTR_SERVICE_CLASS_ID_LIST: u16 = 0x0001;
pub const ATTR_SERVICE_RECORD_STATE: u16 = 0x0002;
pub const ATTR_SERVICE_ID: u16 = 0x0003;
pub const ATTR_PROTOCOL_DESCRIPTOR_LIST: u16 = 0x0004;
pub const ATTR_BROWSE_GROUP_LIST: u16 = 0x0005;
pub const ATTR_LANGUAGE_BASE_ATTRIBUTE_ID_LIST: u16 = 0x0006;
pub const ATTR_SERVICE_INFO_TIME_TO_LIVE: u16 = 0x0007;
pub const ATTR_SERVICE_AVAILABILITY: u16 = 0x0008;
pub const ATTR_BLUETOOTH_PROFILE_DESCRIPTOR_LIST: u16 = 0x0009;
pub const ATTR_DOCUMENTATION_URL: u16 = 0x000A;
pub const ATTR_CLIENT_EXECUTABLE_URL: u16 = 0x000B;
pub const ATTR_ICON_URL: u16 = 0x000C;
pub const ATTR_SERVICE_NAME: u16 = 0x0100;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdpError {
    Short,
    Truncated,
    BadPdu,
    BadTypeDescriptor,
    BadSizeIndex,
}

// ── PDU header ─────────────────────────────────────────────────────

/// SDP PDU header (5 bytes).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PduHeader {
    pub pdu_id: u8,
    pub transaction_id: u16,
    pub parameter_length: u16,
}

impl PduHeader {
    pub fn encode(self) -> [u8; 5] {
        let tid = self.transaction_id.to_be_bytes();
        let plen = self.parameter_length.to_be_bytes();
        [self.pdu_id, tid[0], tid[1], plen[0], plen[1]]
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SdpError> {
        if buf.len() < 5 {
            return Err(SdpError::Short);
        }
        Ok(Self {
            pdu_id: buf[0],
            transaction_id: u16::from_be_bytes([buf[1], buf[2]]),
            parameter_length: u16::from_be_bytes([buf[3], buf[4]]),
        })
    }
}

// ── DataElement encoder ────────────────────────────────────────────

/// Pack a DataElement header byte: high 5 bits = type, low 3 bits =
/// size index.
pub const fn de_header(type_descriptor: u8, size_index: u8) -> u8 {
    ((type_descriptor & 0x1F) << 3) | (size_index & 0x07)
}

fn append_size_field(out: &mut Vec<u8>, size_index: u8, length: usize) {
    match size_index {
        5 => out.push(length as u8),
        6 => out.extend_from_slice(&(length as u16).to_be_bytes()),
        7 => out.extend_from_slice(&(length as u32).to_be_bytes()),
        _ => {} // fixed-size index — no length field
    }
}

/// Encode an unsigned integer DataElement. `width_bytes` must be 1, 2, 4, or 8.
pub fn encode_uint(out: &mut Vec<u8>, width_bytes: usize, value: u64) {
    let size_index = match width_bytes {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => panic!("width must be 1/2/4/8"),
    };
    out.push(de_header(DE_TYPE_UINT, size_index));
    let bytes = value.to_be_bytes();
    out.extend_from_slice(&bytes[8 - width_bytes..]);
}

/// Encode a UUID DataElement. `bytes.len()` must be 2, 4, or 16.
pub fn encode_uuid(out: &mut Vec<u8>, bytes: &[u8]) {
    let size_index = match bytes.len() {
        2 => 1,
        4 => 2,
        16 => 4,
        _ => panic!("UUID must be 2/4/16 bytes"),
    };
    out.push(de_header(DE_TYPE_UUID, size_index));
    out.extend_from_slice(bytes);
}

/// Encode a Text String DataElement using the variable-size form (Size Index 5).
pub fn encode_text(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.push(de_header(DE_TYPE_TEXT, 5));
    append_size_field(out, 5, bytes.len());
    out.extend_from_slice(bytes);
}

/// Encode a Sequence DataElement: writes a Sequence header then the
/// pre-encoded children. `children_size_form` selects which length-
/// field form is used (5 = 1-byte, 6 = 2-byte, 7 = 4-byte).
pub fn encode_sequence(out: &mut Vec<u8>, children_size_form: u8, children: &[u8]) {
    out.push(de_header(DE_TYPE_SEQUENCE, children_size_form));
    append_size_field(out, children_size_form, children.len());
    out.extend_from_slice(children);
}

/// Encode a Boolean DataElement. Always uses Size Index 0 (1-byte).
pub fn encode_bool(out: &mut Vec<u8>, value: bool) {
    out.push(de_header(DE_TYPE_BOOL, 0));
    out.push(if value { 1 } else { 0 });
}

// ── DataElement decoder ────────────────────────────────────────────

/// Read one DataElement header → (type_descriptor, payload_slice, total_consumed).
pub fn decode_element(buf: &[u8]) -> Result<(u8, &[u8], usize), SdpError> {
    if buf.is_empty() {
        return Err(SdpError::Short);
    }
    let header = buf[0];
    let type_descriptor = (header >> 3) & 0x1F;
    let size_index = header & 0x07;
    let (payload_len, header_len) = match size_index {
        0 => (if type_descriptor == DE_TYPE_NIL { 0 } else { 1 }, 1usize),
        1 => (2, 1),
        2 => (4, 1),
        3 => (8, 1),
        4 => (16, 1),
        5 => {
            if buf.len() < 2 {
                return Err(SdpError::Short);
            }
            (buf[1] as usize, 2)
        }
        6 => {
            if buf.len() < 3 {
                return Err(SdpError::Short);
            }
            (u16::from_be_bytes([buf[1], buf[2]]) as usize, 3)
        }
        7 => {
            if buf.len() < 5 {
                return Err(SdpError::Short);
            }
            (
                u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize,
                5,
            )
        }
        _ => return Err(SdpError::BadSizeIndex),
    };
    if buf.len() < header_len + payload_len {
        return Err(SdpError::Truncated);
    }
    let payload = &buf[header_len..header_len + payload_len];
    Ok((type_descriptor, payload, header_len + payload_len))
}

// ── Specific request builders ──────────────────────────────────────

/// Build a Service Search Request asking the responder for service
/// records matching the supplied UUID list. `max_record_count` limits
/// the response size (commonly 0xFFFF). Continuation state is empty
/// on the first request (single trailing 0 byte).
pub fn build_service_search_request(
    transaction_id: u16,
    uuids: &[&[u8]],
    max_record_count: u16,
) -> Vec<u8> {
    // Build the inner UUID list as a Sequence of UUID elements.
    let mut sequence_body = Vec::new();
    for u in uuids {
        encode_uuid(&mut sequence_body, u);
    }
    let mut params = Vec::new();
    encode_sequence(&mut params, 5, &sequence_body);
    params.extend_from_slice(&max_record_count.to_be_bytes());
    params.push(0); // continuation state size = 0

    let mut out = PduHeader {
        pdu_id: PDU_SERVICE_SEARCH_REQUEST,
        transaction_id,
        parameter_length: params.len() as u16,
    }
    .encode()
    .to_vec();
    out.extend_from_slice(&params);
    out
}

/// Build a Service Attribute Request — fetch attributes from the
/// service record at `record_handle`. `attribute_id_list` is a list
/// of either single attribute IDs (16-bit ints) or attribute ranges
/// (32-bit values where upper 16 bits = start, lower 16 = end).
pub fn build_service_attribute_request(
    transaction_id: u16,
    record_handle: u32,
    max_attribute_byte_count: u16,
    attribute_id_list: &[u32],
    use_ranges: bool,
) -> Vec<u8> {
    let mut id_seq = Vec::new();
    for id in attribute_id_list {
        if use_ranges {
            encode_uint(&mut id_seq, 4, *id as u64);
        } else {
            encode_uint(&mut id_seq, 2, (*id & 0xFFFF) as u64);
        }
    }
    let mut params = Vec::new();
    params.extend_from_slice(&record_handle.to_be_bytes());
    params.extend_from_slice(&max_attribute_byte_count.to_be_bytes());
    encode_sequence(&mut params, 5, &id_seq);
    params.push(0); // continuation state size

    let mut out = PduHeader {
        pdu_id: PDU_SERVICE_ATTRIBUTE_REQUEST,
        transaction_id,
        parameter_length: params.len() as u16,
    }
    .encode()
    .to_vec();
    out.extend_from_slice(&params);
    out
}
