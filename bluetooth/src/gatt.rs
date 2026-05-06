//! GATT — Generic Attribute Profile (clean-room).
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part G. Public
//! Bluetooth SIG document. No GPL Linux source consulted.
//!
//! GATT models a server's attribute database as a hierarchy:
//!
//!   Service      — a coherent group of behaviour (e.g. Battery Service,
//!                  Heart Rate, HID-over-GATT).
//!   ├── Included Service (optional cross-references)
//!   ├── Characteristic
//!   │   ├── Characteristic Declaration   — UUID + handle of value
//!   │   ├── Characteristic Value         — the actual data
//!   │   └── Descriptor (0..N)            — CCCD, format, presentation
//!   └── ...
//!
//! Each entry occupies one ATT attribute slot; GATT is "the protocol
//! that defines what the ATT handles mean."
//!
//! ## Discovery procedures (§4.4)
//!
//! - **Discover All Primary Services**: Read By Group Type with
//!   group type = 0x2800 (Primary Service UUID).
//! - **Find Included Services**: Read By Type with type = 0x2802.
//! - **Discover All Characteristics of a Service**: Read By Type with
//!   type = 0x2803 over the service handle range.
//! - **Discover All Characteristic Descriptors**: Find Information
//!   over the handle range between this characteristic value handle
//!   and the next characteristic / end of service.
//!
//! Today this module ships:
//! - The well-known UUIDs for declarations + popular services /
//!   characteristics.
//! - Builders that turn a high-level discovery request into the
//!   specific ATT request bytes.
//! - Parsers that turn ATT responses back into discovered Service /
//!   Characteristic / Descriptor records.

use alloc::vec::Vec;

use crate::att::{Pdu, ATT_FIND_INFORMATION_REQ, ATT_READ_BY_GROUP_TYPE_REQ, ATT_READ_BY_TYPE_REQ};

// ── Well-known UUIDs (Assigned Numbers, GATT Declarations) ────────
//
// 16-bit shorthand UUIDs; the full 128-bit form is
// `00000000-0000-1000-8000-00805F9B34FB` with the 16-bit value in
// bits 96..112.
pub const UUID_PRIMARY_SERVICE: u16 = 0x2800;
pub const UUID_SECONDARY_SERVICE: u16 = 0x2801;
pub const UUID_INCLUDE: u16 = 0x2802;
pub const UUID_CHARACTERISTIC: u16 = 0x2803;
pub const UUID_CCC_DESCRIPTOR: u16 = 0x2902;
pub const UUID_CHAR_USER_DESC: u16 = 0x2901;
pub const UUID_CHAR_PRESENTATION_FORMAT: u16 = 0x2904;

// Common services
pub const UUID_SERVICE_GAP: u16 = 0x1800;
pub const UUID_SERVICE_GATT: u16 = 0x1801;
pub const UUID_SERVICE_BATTERY: u16 = 0x180F;
pub const UUID_SERVICE_DEVICE_INFORMATION: u16 = 0x180A;
pub const UUID_SERVICE_HID: u16 = 0x1812;

// Characteristic property bits (§3.3.1.1, table 3.5).
pub const CHAR_PROP_BROADCAST: u8 = 1 << 0;
pub const CHAR_PROP_READ: u8 = 1 << 1;
pub const CHAR_PROP_WRITE_WITHOUT_RESPONSE: u8 = 1 << 2;
pub const CHAR_PROP_WRITE: u8 = 1 << 3;
pub const CHAR_PROP_NOTIFY: u8 = 1 << 4;
pub const CHAR_PROP_INDICATE: u8 = 1 << 5;
pub const CHAR_PROP_AUTHENTICATED_SIGNED_WRITES: u8 = 1 << 6;
pub const CHAR_PROP_EXTENDED_PROPERTIES: u8 = 1 << 7;

/// A 16-bit or 128-bit UUID. GATT databases mostly use 16-bit
/// (Assigned Numbers); vendors register 128-bit for custom services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uuid {
    U16(u16),
    U128([u8; 16]),
}

impl Uuid {
    pub fn from_le_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            2 => Some(Uuid::U16(u16::from_le_bytes([b[0], b[1]]))),
            16 => {
                let mut v = [0u8; 16];
                v.copy_from_slice(b);
                Some(Uuid::U128(v))
            }
            _ => None,
        }
    }

    pub fn write_le(&self, out: &mut Vec<u8>) {
        match self {
            Uuid::U16(v) => out.extend_from_slice(&v.to_le_bytes()),
            Uuid::U128(v) => out.extend_from_slice(v),
        }
    }
}

// ── Discovery records ──────────────────────────────────────────────

/// A discovered Primary Service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRecord {
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
}

/// A discovered Characteristic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharacteristicRecord {
    /// Handle of the Characteristic Declaration attribute (the one
    /// whose value is the property+handle+UUID tuple).
    pub declaration_handle: u16,
    pub properties: u8,
    pub value_handle: u16,
    pub uuid: Uuid,
}

/// A discovered descriptor (CCCD, user desc, format, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorRecord {
    pub handle: u16,
    pub uuid: Uuid,
}

// ── Discovery request builders ────────────────────────────────────

/// Build a Discover All Primary Services request — Read By Group Type
/// with handle range [start, end] and group type = 0x2800.
pub fn build_discover_primary_services(start: u16, end: u16) -> Pdu {
    let mut p = Vec::with_capacity(6);
    p.extend_from_slice(&start.to_le_bytes());
    p.extend_from_slice(&end.to_le_bytes());
    p.extend_from_slice(&UUID_PRIMARY_SERVICE.to_le_bytes());
    Pdu {
        opcode: ATT_READ_BY_GROUP_TYPE_REQ,
        params: p,
    }
}

/// Build a Discover All Characteristics request — Read By Type with
/// type = 0x2803 over [start, end].
pub fn build_discover_characteristics(start: u16, end: u16) -> Pdu {
    let mut p = Vec::with_capacity(6);
    p.extend_from_slice(&start.to_le_bytes());
    p.extend_from_slice(&end.to_le_bytes());
    p.extend_from_slice(&UUID_CHARACTERISTIC.to_le_bytes());
    Pdu {
        opcode: ATT_READ_BY_TYPE_REQ,
        params: p,
    }
}

/// Build a Find Information request for descriptor discovery.
pub fn build_discover_descriptors(start: u16, end: u16) -> Pdu {
    let mut p = Vec::with_capacity(4);
    p.extend_from_slice(&start.to_le_bytes());
    p.extend_from_slice(&end.to_le_bytes());
    Pdu {
        opcode: ATT_FIND_INFORMATION_REQ,
        params: p,
    }
}

// ── Discovery response parsers ────────────────────────────────────

/// Parse a Read By Group Type Response payload (post-opcode bytes
/// of the ATT_READ_BY_GROUP_TYPE_RSP) into Service records.
///
/// Layout (ATT §3.4.4.10):
///   0:    u8  Length (per-attribute pair byte count)
///   1..N: list of [handle (2), end_group_handle (2), value (Length-4)]
pub fn parse_primary_services(rsp_params: &[u8]) -> Vec<ServiceRecord> {
    let mut out = Vec::new();
    if rsp_params.is_empty() {
        return out;
    }
    let unit = rsp_params[0] as usize;
    if unit < 6 {
        return out;
    }
    let mut i = 1;
    while i + unit <= rsp_params.len() {
        let start = u16::from_le_bytes([rsp_params[i], rsp_params[i + 1]]);
        let end = u16::from_le_bytes([rsp_params[i + 2], rsp_params[i + 3]]);
        if let Some(uuid) = Uuid::from_le_bytes(&rsp_params[i + 4..i + unit]) {
            out.push(ServiceRecord {
                start_handle: start,
                end_handle: end,
                uuid,
            });
        }
        i += unit;
    }
    out
}

/// Parse a Read By Type Response (UUID = 0x2803) payload into
/// Characteristic records.
///
/// Each tuple is: handle (2) + value_len bytes of value, where the
/// value is properties (1) + value_handle (2) + UUID (2 or 16).
pub fn parse_characteristics(rsp_params: &[u8]) -> Vec<CharacteristicRecord> {
    let mut out = Vec::new();
    if rsp_params.is_empty() {
        return out;
    }
    let unit = rsp_params[0] as usize;
    if unit < 7 {
        return out;
    }
    let mut i = 1;
    while i + unit <= rsp_params.len() {
        let decl = u16::from_le_bytes([rsp_params[i], rsp_params[i + 1]]);
        let props = rsp_params[i + 2];
        let val_h = u16::from_le_bytes([rsp_params[i + 3], rsp_params[i + 4]]);
        if let Some(uuid) = Uuid::from_le_bytes(&rsp_params[i + 5..i + unit]) {
            out.push(CharacteristicRecord {
                declaration_handle: decl,
                properties: props,
                value_handle: val_h,
                uuid,
            });
        }
        i += unit;
    }
    out
}

/// Parse a Find Information Response (§3.4.3.2). Response format byte
/// at offset 0: 0x01 = 16-bit UUID list, 0x02 = 128-bit UUID list.
pub fn parse_descriptors(rsp_params: &[u8]) -> Vec<DescriptorRecord> {
    let mut out = Vec::new();
    if rsp_params.is_empty() {
        return out;
    }
    let format = rsp_params[0];
    let unit = match format {
        0x01 => 4,  // 2-byte handle + 2-byte UUID
        0x02 => 18, // 2-byte handle + 16-byte UUID
        _ => return out,
    };
    let mut i = 1;
    while i + unit <= rsp_params.len() {
        let h = u16::from_le_bytes([rsp_params[i], rsp_params[i + 1]]);
        if let Some(uuid) = Uuid::from_le_bytes(&rsp_params[i + 2..i + unit]) {
            out.push(DescriptorRecord { handle: h, uuid });
        }
        i += unit;
    }
    out
}
