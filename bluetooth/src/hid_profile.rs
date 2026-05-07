//! Classic Bluetooth HID Profile (HID-over-L2CAP) — clean-room.
//!
//! ## Sources (public only)
//!
//! - **Bluetooth SIG, "Human Interface Device (HID) Profile
//!   Specification"**, Version 1.0, 22 May 2003.
//!   <https://www.bluetooth.com/specifications/specs/human-interface-device-profile-1-0/>
//! - **Bluetooth Core Specification 5.4, Vol 3 Part A** — L2CAP
//!   for the channel transport.
//!   <https://www.bluetooth.com/specifications/specs/core-specification-5-4/>
//! - **HID 1.11 §6.2.2** — Report Descriptor; the Bluetooth HID
//!   profile carries a HID descriptor verbatim and we delegate
//!   parsing to `narf-hid::descriptor::parse`.
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is vs. HOGP
//!
//! Two completely different profiles share the "HID over BT" name:
//!
//! - **HID Profile (HIDP, this module)** — runs over **Classic BT**
//!   (BR/EDR), via L2CAP fixed PSMs (`0x0011` = Control, `0x0013` =
//!   Interrupt). Used by older keyboards, mice, gamepads, and
//!   anything that calls itself a "Bluetooth keyboard".
//! - **HID over GATT Profile (HOGP, [`crate::hogp`])** — runs over
//!   **BLE**, via GATT services / characteristics. Used by modern
//!   low-power peripherals (Logitech MX series, Apple Magic
//!   peripherals in BLE mode, AirPods click handling, etc.).
//!
//! The profiles share their underlying HID Report-Descriptor
//! semantics — both use the descriptor format from HID 1.11. They
//! differ entirely in framing.
//!
//! ## Wire format (HIDP §7.4)
//!
//! Every HIDP message is a single byte header followed by an
//! optional payload:
//!
//! ```text
//!   byte 0:
//!     bits[7:4]  Transaction Type
//!     bits[3:0]  Parameter
//!   byte 1..N:   Payload (Transaction-Type specific)
//! ```
//!
//! Carried over the L2CAP Interrupt channel for `DATA` (and only
//! `DATA`); other transactions use the Control channel.

extern crate alloc;
use alloc::vec::Vec;

/// L2CAP fixed PSM for the HID **Control** channel (HIDP §5.2).
pub const PSM_HID_CONTROL: u16 = 0x0011;
/// L2CAP fixed PSM for the HID **Interrupt** channel (HIDP §5.2).
pub const PSM_HID_INTERRUPT: u16 = 0x0013;

/// Transaction Type field in byte 0 bits[7:4] (HIDP §7.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionType {
    Handshake = 0x0,
    HidControl = 0x1,
    GetReport = 0x4,
    SetReport = 0x5,
    GetProtocol = 0x6,
    SetProtocol = 0x7,
    Data = 0xA,
}

impl TransactionType {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match (b >> 4) & 0x0F {
            0x0 => Self::Handshake,
            0x1 => Self::HidControl,
            0x4 => Self::GetReport,
            0x5 => Self::SetReport,
            0x6 => Self::GetProtocol,
            0x7 => Self::SetProtocol,
            0xA => Self::Data,
            _ => return None,
        })
    }
}

/// HANDSHAKE response codes (HIDP §7.4.1) — written into byte-0
/// `Parameter` bits[3:0].
pub mod handshake {
    pub const SUCCESSFUL: u8 = 0x0;
    pub const NOT_READY: u8 = 0x1;
    pub const ERR_INVALID_REPORT_ID: u8 = 0x2;
    pub const ERR_UNSUPPORTED_REQUEST: u8 = 0x3;
    pub const ERR_INVALID_PARAMETER: u8 = 0x4;
    pub const ERR_UNKNOWN: u8 = 0xE;
    pub const ERR_FATAL: u8 = 0xF;
}

/// HID_CONTROL operation codes (HIDP §7.4.2) — written into the
/// `Parameter` nibble.
pub mod hid_control {
    /// Sent to put the device into a state where it will only
    /// respond to a Suspend or Reset.
    pub const SUSPEND: u8 = 0x3;
    /// Resume normal operation.
    pub const EXIT_SUSPEND: u8 = 0x4;
    /// Forcibly disconnect — host releases the device.
    pub const VIRTUAL_CABLE_UNPLUG: u8 = 0x5;
}

/// Report Type field used by GET_REPORT / SET_REPORT / DATA
/// transactions (HIDP §7.4.3) — written into the `Parameter`
/// nibble.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReportType {
    /// Reserved.
    Other = 0x0,
    Input = 0x1,
    Output = 0x2,
    Feature = 0x3,
}

impl ReportType {
    pub fn from_param(p: u8) -> Option<Self> {
        Some(match p & 0x03 {
            0x0 => Self::Other,
            0x1 => Self::Input,
            0x2 => Self::Output,
            _ => Self::Feature,
        })
    }
}

/// Build a `HANDSHAKE` packet acknowledging or rejecting a prior
/// SET_REPORT / SET_PROTOCOL / HID_CONTROL transaction.
pub fn build_handshake(code: u8) -> Vec<u8> {
    alloc::vec![((TransactionType::Handshake as u8) << 4) | (code & 0x0F)]
}

/// Build a `HID_CONTROL` packet (host → device control op).
pub fn build_hid_control(op: u8) -> Vec<u8> {
    alloc::vec![((TransactionType::HidControl as u8) << 4) | (op & 0x0F)]
}

/// Build a `GET_REPORT` request. `report_id` is an optional 1-byte
/// argument the spec lets the host append when the descriptor uses
/// Report IDs; if `None` it's omitted.
pub fn build_get_report(rt: ReportType, report_id: Option<u8>, size: Option<u16>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    let mut hdr = (TransactionType::GetReport as u8) << 4 | (rt as u8 & 0x03);
    if size.is_some() {
        // Bit 3 of the parameter nibble is "Size" — when set, the
        // host appends a 2-byte little-endian buffer-size hint
        // (HIDP §7.4.3).
        hdr |= 0x08;
    }
    buf.push(hdr);
    if let Some(id) = report_id {
        buf.push(id);
    }
    if let Some(s) = size {
        buf.extend_from_slice(&s.to_le_bytes());
    }
    buf
}

/// Build a `SET_REPORT` request. The payload includes the Report ID
/// byte (when the descriptor uses Report IDs) followed by the
/// report body — caller is responsible for that framing matching the
/// device's descriptor.
pub fn build_set_report(rt: ReportType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push((TransactionType::SetReport as u8) << 4 | (rt as u8 & 0x03));
    buf.extend_from_slice(payload);
    buf
}

/// Build a `DATA` packet — used to carry an Input report from the
/// device to the host (Interrupt channel) or an Output report from
/// host to device (rare, usually goes via SET_REPORT). The payload
/// follows the same Report-ID-prefixed framing as SET_REPORT.
pub fn build_data(rt: ReportType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push((TransactionType::Data as u8) << 4 | (rt as u8 & 0x03));
    buf.extend_from_slice(payload);
    buf
}

/// Decoded HIDP packet header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidpHeader {
    pub transaction: TransactionType,
    pub parameter: u8,
}

/// Decode the first byte of a HIDP packet.
pub fn decode_header(buf: &[u8]) -> Option<HidpHeader> {
    let b0 = *buf.first()?;
    Some(HidpHeader {
        transaction: TransactionType::from_byte(b0)?,
        parameter: b0 & 0x0F,
    })
}

/// A `DATA` packet carrying a HID Input report. Convenience for
/// the receive path: validates the header, peels off the parameter
/// nibble's `ReportType`, and returns the body for narf-hid to
/// decode.
pub fn parse_input_data(buf: &[u8]) -> Option<&[u8]> {
    let h = decode_header(buf)?;
    if h.transaction != TransactionType::Data {
        return None;
    }
    if ReportType::from_param(h.parameter) != Some(ReportType::Input) {
        return None;
    }
    Some(&buf[1..])
}
