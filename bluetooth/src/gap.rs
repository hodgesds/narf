//! Generic Access Profile — advertising-data records (clean-room).
//!
//! References (public-only):
//! - "Bluetooth Core Specification Supplement, Part A — Data Types
//!   Specification, Version 11" — Bluetooth SIG. Public adopted
//!   document. §1.3 (advertising data record format: 1-byte length
//!   covering type+payload, then 1-byte AD type, then payload).
//! - **Bluetooth Assigned Numbers — Generic Access Profile** —
//!   Bluetooth SIG. Public registry of AD type codes (Flags = 0x01,
//!   Incomplete / Complete 16-bit Service UUIDs = 0x02 / 0x03,
//!   16-bit Service Solicitation UUIDs = 0x14, Local Name (Shortened
//!   = 0x08, Complete = 0x09), Tx Power Level = 0x0A, Slave Connection
//!   Interval Range = 0x12, Service Data 16-bit UUID = 0x16, Public
//!   Target Address = 0x17, Appearance = 0x19, Manufacturer Specific
//!   Data = 0xFF).
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## Wire format (CSS Part A §1.3)
//!
//! ```text
//!   byte 0  length    (number of bytes that follow, ≥ 1, ≤ 30 in
//!                       a 31-byte legacy advertising packet)
//!   byte 1  AD type
//!   bytes 2..N+1  payload (length-1 bytes)
//! ```

use alloc::string::String;
use alloc::vec::Vec;

// ── AD type constants (Assigned Numbers) ───────────────────────────

pub const AD_FLAGS: u8 = 0x01;
pub const AD_INCOMPLETE_LIST_16: u8 = 0x02;
pub const AD_COMPLETE_LIST_16: u8 = 0x03;
pub const AD_INCOMPLETE_LIST_32: u8 = 0x04;
pub const AD_COMPLETE_LIST_32: u8 = 0x05;
pub const AD_INCOMPLETE_LIST_128: u8 = 0x06;
pub const AD_COMPLETE_LIST_128: u8 = 0x07;
pub const AD_SHORTENED_LOCAL_NAME: u8 = 0x08;
pub const AD_COMPLETE_LOCAL_NAME: u8 = 0x09;
pub const AD_TX_POWER_LEVEL: u8 = 0x0A;
pub const AD_CLASS_OF_DEVICE: u8 = 0x0D;
pub const AD_SLAVE_CONN_INTERVAL_RANGE: u8 = 0x12;
pub const AD_LIST_16_SOLICITATION: u8 = 0x14;
pub const AD_LIST_128_SOLICITATION: u8 = 0x15;
pub const AD_SERVICE_DATA_16: u8 = 0x16;
pub const AD_PUBLIC_TARGET_ADDRESS: u8 = 0x17;
pub const AD_RANDOM_TARGET_ADDRESS: u8 = 0x18;
pub const AD_APPEARANCE: u8 = 0x19;
pub const AD_ADVERTISING_INTERVAL: u8 = 0x1A;
pub const AD_LE_BLUETOOTH_DEVICE_ADDRESS: u8 = 0x1B;
pub const AD_LE_ROLE: u8 = 0x1C;
pub const AD_SERVICE_DATA_32: u8 = 0x20;
pub const AD_SERVICE_DATA_128: u8 = 0x21;
pub const AD_URI: u8 = 0x24;
pub const AD_LE_SUPPORTED_FEATURES: u8 = 0x27;
pub const AD_MANUFACTURER_SPECIFIC: u8 = 0xFF;

// ── Flags-byte bits (CSS Part A §1.3, table 1.1) ───────────────────

pub const FLAGS_LE_LIMITED_DISCOVERABLE: u8 = 1 << 0;
pub const FLAGS_LE_GENERAL_DISCOVERABLE: u8 = 1 << 1;
pub const FLAGS_BR_EDR_NOT_SUPPORTED: u8 = 1 << 2;
pub const FLAGS_LE_BR_EDR_CONTROLLER: u8 = 1 << 3;
pub const FLAGS_LE_BR_EDR_HOST: u8 = 1 << 4;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GapError {
    /// Buffer too short for the next record.
    Short,
    /// Record's `length` byte claims more bytes than the buffer carries.
    Truncated,
    /// Payload doesn't have enough bytes for its declared AD type
    /// (e.g. Tx Power Level needs 1 byte; 16-bit UUID list needs
    /// payload divisible by 2).
    BadPayload,
}

// ── TLV iterator ───────────────────────────────────────────────────

/// One advertising data record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdRecord<'a> {
    pub ad_type: u8,
    pub payload: &'a [u8],
}

/// Iterate AD records from the start of an advertising data packet
/// (or scan-response). Stops on `length == 0`, which the spec uses as
/// a terminator inside the 31-byte legacy advertisement payload.
#[derive(Debug)]
pub struct AdIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> AdIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for AdIter<'a> {
    type Item = Result<AdRecord<'a>, GapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let length = self.buf[self.pos] as usize;
        if length == 0 {
            // Terminator inside a legacy advertisement.
            return None;
        }
        if self.pos + 1 + length > self.buf.len() {
            self.pos = self.buf.len();
            return Some(Err(GapError::Truncated));
        }
        if length < 1 {
            return Some(Err(GapError::BadPayload));
        }
        let ad_type = self.buf[self.pos + 1];
        let payload = &self.buf[self.pos + 2..self.pos + 1 + length];
        self.pos += 1 + length;
        Some(Ok(AdRecord { ad_type, payload }))
    }
}

// ── Builder ────────────────────────────────────────────────────────

/// Append one AD record (length + type + payload) to `out`.
pub fn append_record(out: &mut Vec<u8>, ad_type: u8, payload: &[u8]) {
    out.push((1 + payload.len()) as u8);
    out.push(ad_type);
    out.extend_from_slice(payload);
}

/// Build a Flags record. `flags` is a bitmap of the `FLAGS_*` consts.
pub fn append_flags(out: &mut Vec<u8>, flags: u8) {
    append_record(out, AD_FLAGS, &[flags]);
}

/// Build a Complete Local Name record.
pub fn append_complete_local_name(out: &mut Vec<u8>, name: &str) {
    append_record(out, AD_COMPLETE_LOCAL_NAME, name.as_bytes());
}

/// Build a Tx Power Level record. `dbm` is signed (typically −127..+20).
pub fn append_tx_power(out: &mut Vec<u8>, dbm: i8) {
    append_record(out, AD_TX_POWER_LEVEL, &[dbm as u8]);
}

/// Build a Manufacturer Specific Data record. The 16-bit Company ID
/// goes first in little-endian, followed by vendor data.
pub fn append_manufacturer_data(out: &mut Vec<u8>, company_id: u16, data: &[u8]) {
    let mut payload = Vec::with_capacity(2 + data.len());
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(data);
    append_record(out, AD_MANUFACTURER_SPECIFIC, &payload);
}

/// Build an Incomplete or Complete 16-bit Service UUID list. UUIDs
/// are little-endian 16-bit values; `complete` selects the 0x02
/// / 0x03 variant.
pub fn append_service_uuid_list_16(out: &mut Vec<u8>, complete: bool, uuids: &[u16]) {
    let mut payload = Vec::with_capacity(uuids.len() * 2);
    for u in uuids {
        payload.extend_from_slice(&u.to_le_bytes());
    }
    let ad_type = if complete {
        AD_COMPLETE_LIST_16
    } else {
        AD_INCOMPLETE_LIST_16
    };
    append_record(out, ad_type, &payload);
}

/// Build a Service Data — 16-bit UUID record. `uuid` is the 2-byte
/// service UUID (LE on the wire), `data` is the service-defined
/// payload.
pub fn append_service_data_16(out: &mut Vec<u8>, uuid: u16, data: &[u8]) {
    let mut payload = Vec::with_capacity(2 + data.len());
    payload.extend_from_slice(&uuid.to_le_bytes());
    payload.extend_from_slice(data);
    append_record(out, AD_SERVICE_DATA_16, &payload);
}

// ── Convenience decoders ───────────────────────────────────────────

/// Find the first record of `ad_type` and return its payload.
pub fn find<'a>(buf: &'a [u8], ad_type: u8) -> Option<&'a [u8]> {
    for rec in AdIter::new(buf).flatten() {
        if rec.ad_type == ad_type {
            return Some(rec.payload);
        }
    }
    None
}

/// Decode a Local Name — looks up Complete first then Shortened.
pub fn local_name(buf: &[u8]) -> Option<String> {
    let payload = find(buf, AD_COMPLETE_LOCAL_NAME).or_else(|| find(buf, AD_SHORTENED_LOCAL_NAME))?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

/// Decode the Flags byte, if present.
pub fn flags(buf: &[u8]) -> Option<u8> {
    find(buf, AD_FLAGS).and_then(|p| p.first().copied())
}

/// Decode the Tx Power Level (signed dBm) if present.
pub fn tx_power(buf: &[u8]) -> Option<i8> {
    find(buf, AD_TX_POWER_LEVEL).and_then(|p| p.first().copied().map(|b| b as i8))
}

/// Decode a 16-bit Manufacturer Specific Data record. Returns
/// (company id, vendor payload).
pub fn manufacturer_data<'a>(buf: &'a [u8]) -> Option<(u16, &'a [u8])> {
    let p = find(buf, AD_MANUFACTURER_SPECIFIC)?;
    if p.len() < 2 {
        return None;
    }
    Some((u16::from_le_bytes([p[0], p[1]]), &p[2..]))
}

/// Decode all 16-bit Service UUIDs in the buffer (covers both
/// Complete and Incomplete forms).
pub fn service_uuids_16(buf: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    for rec in AdIter::new(buf).flatten() {
        if rec.ad_type == AD_COMPLETE_LIST_16 || rec.ad_type == AD_INCOMPLETE_LIST_16 {
            for chunk in rec.payload.chunks_exact(2) {
                out.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
        }
    }
    out
}
