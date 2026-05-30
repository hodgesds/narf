// SPDX-License-Identifier: GPL-2.0-or-later
//! WMI core — shared MOF/GUID helpers shared across vendor platform drivers.
//!
//! This module provides the GUID encoding, WMI method argument packing, and
//! ACPI-WMI invocation helpers that all vendor drivers (ThinkPad, Dell, HP,
//! ASUS, IdeaPad, Samsung) share. The per-vendor modules call into here
//! rather than duplicating encode logic.
//!
//! Reference: Linux `drivers/platform/x86/wmi.c` (GPL-2.0-or-later).
//!   `wmi_method_call` — builds the WBEM GUID argument buffer.
//!   `parse_wdg`       — decodes the _WDG buffer into block descriptors.
//!   `wmi_guid_eq`     — mixed-endian byte comparison.
//!
//! ## WMI method invocation argument encoding
//!
//! When calling a WMI method (WMxx AML method) the GUID must be passed
//! as a 16-byte buffer argument to satisfy the WBEM convention that some
//! firmware implementations expect. The argument is:
//!   Arg0 = integer  (instance index, almost always 0)
//!   Arg1 = integer  (method id — the WBEM method ordinal)
//!   Arg2 = buffer   (16 bytes of GUID in _WDG wire format)
//!
//! Linux reference: `wmi.c::wmi_method_call` — passes the GUID buffer as
//! Arg2 after instance and method_id. Some OEM firmware ignores it; we
//! include it for correctness.

extern crate alloc;

use alloc::vec::Vec;

// ── GUID wire-encoding helpers ─────────────────────────────────────────

/// Parse a GUID string in the canonical Microsoft form
/// `"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"` into the raw 16-byte
/// mixed-endian wire format used in `_WDG` descriptors.
///
/// The wire layout (Microsoft WMI spec, RFC 4122 §4.1.2):
///   bytes  0– 3: Data1 little-endian  (text representation is big-endian)
///   bytes  4– 5: Data2 little-endian
///   bytes  6– 7: Data3 little-endian
///   bytes  8–15: Data4 big-endian (unchanged from text)
///
/// Returns `None` if the string is malformed (wrong length, non-hex chars).
///
/// Reference: Linux `wmi.c::wmi_guid_eq` + RFC 4122 §4.1.2 (public spec).
pub fn guid_to_bytes(s: &str) -> Option<[u8; 16]> {
    let hex: alloc::string::String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let mut raw = [0u8; 16];
    for i in 0..16 {
        let hi = hex.as_bytes()[i * 2];
        let lo = hex.as_bytes()[i * 2 + 1];
        raw[i] = (nibble(hi)? << 4) | nibble(lo)?;
    }
    // Apply mixed-endian byte-swap for Data1/2/3.
    raw[0..4].reverse();
    raw[4..6].reverse();
    raw[6..8].reverse();
    Some(raw)
}

/// Encode a 16-byte GUID buffer as a `Vec<u8>` suitable for passing
/// as Arg2 to a WMI method call. This is the packed 16-byte buffer
/// argument described in the WMI spec.
///
/// Reference: `wmi.c::wmi_method_call` — GUID is passed as a Buffer
/// argument so BIOS can verify the caller is addressing the correct
/// GUID surface.
pub fn encode_guid_arg(guid: &[u8; 16]) -> Vec<u8> {
    guid.to_vec()
}

// ── WMI method invocation argument pack ───────────────────────────────

/// Build the standard WMI call argument list:
///   `[Integer(instance), Integer(method_id), Buffer(guid_bytes)]`
///
/// Reference: `wmi.c::wmi_method_call` — fixed three-argument layout.
/// `instance` is almost always 0. `method_id` is the WBEM method ordinal
/// defined by the OEM in their MOF file.
pub fn build_wmi_args(
    instance: u8,
    method_id: u32,
    guid: &[u8; 16],
) -> [narf_aml::Value; 3] {
    [
        narf_aml::Value::Integer(instance as u64),
        narf_aml::Value::Integer(method_id as u64),
        narf_aml::Value::Buffer(encode_guid_arg(guid)),
    ]
}

// ── WMI block payload helpers ──────────────────────────────────────────

/// Extract a little-endian `u32` from `data` at byte offset `off`.
/// Returns `None` if the slice is too short.
///
/// Used by HP and ASUS WMI response parsers.
pub fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    if data.len() < off + 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

/// Extract a little-endian `u16` from `data` at byte offset `off`.
/// Returns `None` if the slice is too short.
pub fn le_u16(data: &[u8], off: usize) -> Option<u16> {
    if data.len() < off + 2 {
        return None;
    }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_parse_dell_wmi_descriptor() {
        let b = guid_to_bytes("8D9DDCBC-A997-11DA-B012-B622A1EF5492");
        assert!(b.is_some(), "Dell descriptor GUID parse failed");
    }

    #[test]
    fn guid_parse_malformed() {
        assert!(guid_to_bytes("not-a-guid").is_none());
        assert!(guid_to_bytes("").is_none());
    }

    #[test]
    fn le_u32_bounds() {
        let data = [1u8, 2, 3, 4, 5];
        assert_eq!(le_u32(&data, 0), Some(0x04030201));
        assert_eq!(le_u32(&data, 2), None); // only 3 bytes remain
    }
}
