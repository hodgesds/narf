//! `/sys/class/tpm/tpm0/` sysfs kobject tree for the NARF TPM driver.
//!
//! Populates the following attributes under `/sys/class/tpm/tpm0/`:
//!
//! | Attribute           | Value                                          |
//! |---------------------|------------------------------------------------|
//! | `tpm_version_major` | `"2\n"`                                        |
//! | `tpm_version_minor` | `"0\n"`                                        |
//! | `enabled`           | `"1\n"`                                        |
//! | `active`            | `"1\n"`                                        |
//! | `owned`             | `"0\n"` or `"1\n"` via StoragePrimary query    |
//! | `manufacturer`      | 4-char ASCII from `PT_MANUFACTURER`            |
//! | `description`       | human-readable vendor string                   |
//! | `caps`              | family/level/revision + vendor strings         |
//! | `pcrs`              | one line per PCR per bank (SHA-1 and SHA-256)  |
//!
//! All attribute values are generated lazily on each read. `pcrs` is
//! expensive (one `TPM2_PCR_Read` per bank) but is acceptable for a
//! sysfs diagnostic read — callers are expected to read infrequently.
//! A cache is not needed at this stage; caching can be added later.
//!
//! ## Linux references
//!
//! - `drivers/char/tpm/tpm-sysfs.c` — `tpm_version_major_show` (line 302),
//!   `enabled_show` (line 117), `active_show` (line 139),
//!   `owned_show` (line 161), `caps_show` (line 205), `pcrs_show` (line 73).
//! - `drivers/char/tpm/tpm-chip.c` — `tpm_class` registration (line 31).
//!
//! ## TPM 2.0 property constants (Part 2 §6.13, TPM_PT)
//!
//! | Constant                | Value        | Meaning                       |
//! |-------------------------|-------------|-------------------------------|
//! | `PT_FAMILY_INDICATOR`   | `0x100`     | Family string ("2.0\0")       |
//! | `PT_LEVEL`              | `0x101`     | Spec level                    |
//! | `PT_REVISION`           | `0x102`     | Spec revision × 100           |
//! | `PT_MANUFACTURER`       | `0x105`     | Vendor ID (4-char ASCII)      |
//! | `PT_VENDOR_STRING_1`    | `0x106`     | Vendor description part 1     |
//! | `PT_VENDOR_STRING_2`    | `0x107`     | Vendor description part 2     |
//! | `PT_VENDOR_STRING_3`    | `0x108`     | Vendor description part 3     |
//! | `PT_VENDOR_STRING_4`    | `0x109`     | Vendor description part 4     |
//! | `PT_PERMANENT`          | `0x10E`     | `TPMA_PERMANENT` flags        |

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr,
};

use crate::devfs_bridge::TpmTransport;
use crate::tpm2::commands::{get_capability, pcr_read};
use crate::tpm2::{
    TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_CAP_TPM_PROPERTIES, TPM_RC_SUCCESS,
};

// ── TPM PT (permanent property) constants ─────────────────────────────

/// `TPM_PT_FAMILY_INDICATOR` — Part 2 §6.13.
const PT_FAMILY_INDICATOR: u32 = 0x0000_0100;
/// `TPM_PT_LEVEL` — spec level.
const PT_LEVEL: u32 = 0x0000_0101;
/// `TPM_PT_REVISION` — spec revision × 100.
const PT_REVISION: u32 = 0x0000_0102;
/// `TPM_PT_MANUFACTURER` — 4-char ASCII vendor ID.
const PT_MANUFACTURER: u32 = 0x0000_0105;
/// `TPM_PT_VENDOR_STRING_1` — vendor description part 1.
const PT_VENDOR_STRING_1: u32 = 0x0000_0106;
/// `TPM_PT_VENDOR_STRING_4` — vendor description part 4.
const PT_VENDOR_STRING_4: u32 = 0x0000_0109;
/// `TPM_PT_PERMANENT` — TPMA_PERMANENT flags. Bit 2 = ownerAuthSet.
const PT_PERMANENT: u32 = 0x0000_010E;

// ── SHA-1 digest size ──────────────────────────────────────────────────
const SHA1_SIZE: usize = 20;
const SHA256_SIZE: usize = 32;

// ── Response parsing helpers ──────────────────────────────────────────

/// Parse a `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, property, 1)`
/// response and extract the single 32-bit property value.
///
/// Response body layout after the 10-byte header (Part 3 §30.2):
/// - byte 0         — moreData (u8)
/// - bytes 1..4     — capabilityCode (u32 BE) — mirrors the request cap
/// - bytes 5..8     — count (u32 BE) = 1 for a single-property query
/// - bytes 9..12    — property tag (u32 BE)
/// - bytes 13..16   — property value (u32 BE)
fn parse_property_response(raw: &[u8]) -> Option<u32> {
    if raw.len() < 10 {
        return None;
    }
    let rc = u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]);
    if rc != TPM_RC_SUCCESS {
        return None;
    }
    // body starts at offset 10; skip moreData(1) + cap(4) + count(4) + tag(4) = 13
    let body_offset = 10 + 1 + 4 + 4 + 4;
    if raw.len() < body_offset + 4 {
        return None;
    }
    Some(u32::from_be_bytes([
        raw[body_offset],
        raw[body_offset + 1],
        raw[body_offset + 2],
        raw[body_offset + 3],
    ]))
}

/// Decode a 32-bit value as a 4-byte big-endian ASCII string, replacing
/// non-printable bytes with `'?'`. Returns a `String` of length 4.
fn u32_to_ascii4(v: u32) -> String {
    let bytes = v.to_be_bytes();
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

/// Read a single TPM property via `TPM2_GetCapability`.
/// Returns `None` on transport error or non-SUCCESS RC.
fn read_property(transport: &dyn TpmTransport, property: u32) -> Option<u32> {
    let cmd = get_capability(TPM_CAP_TPM_PROPERTIES, property, 1);
    let resp = transport.submit(&cmd).ok()?;
    parse_property_response(&resp)
}

/// Parse a `TPM2_PCR_Read` response body and extract the list of digests.
///
/// Response body layout (Part 3 §22.6, after the 10-byte header):
/// - bytes 0..3     — pcrUpdateCounter (u32 BE)
/// - bytes 4..9     — TPML_PCR_SELECTION (count=1, then one TPMS_PCR_SELECTION)
/// - …              — TPML_DIGEST: count(u32) + TPM2B_DIGEST[]
///
/// We do a simplified parse: scan past the fixed fields to find the
/// TPML_DIGEST, then read each `TPM2B_DIGEST` (size u16 + bytes).
fn parse_pcr_read_response(raw: &[u8]) -> Option<Vec<Vec<u8>>> {
    if raw.len() < 10 {
        return None;
    }
    let rc = u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]);
    if rc != TPM_RC_SUCCESS {
        return None;
    }
    // After 10-byte header:
    // pcrUpdateCounter: 4 bytes
    // TPML_PCR_SELECTION:
    //   count (u32): 4 bytes
    //   then `count` × TPMS_PCR_SELECTION:
    //     hashAlg (u16) + sizeofSelect (u8) + pcrSelect (N bytes)
    //     for our queries N=3
    let mut pos = 10;
    // pcrUpdateCounter
    if pos + 4 > raw.len() { return None; }
    pos += 4;
    // TPML_PCR_SELECTION count
    if pos + 4 > raw.len() { return None; }
    let sel_count = u32::from_be_bytes([raw[pos], raw[pos+1], raw[pos+2], raw[pos+3]]) as usize;
    pos += 4;
    // skip sel_count × TPMS_PCR_SELECTION (hashAlg:2 + sizeofSelect:1 + bitmap:N)
    for _ in 0..sel_count {
        if pos + 3 > raw.len() { return None; }
        let sos = raw[pos + 2] as usize;
        pos += 3 + sos;
    }
    // TPML_DIGEST: count (u32)
    if pos + 4 > raw.len() { return None; }
    let digest_count = u32::from_be_bytes([raw[pos], raw[pos+1], raw[pos+2], raw[pos+3]]) as usize;
    pos += 4;
    let mut digests = Vec::new();
    for _ in 0..digest_count {
        if pos + 2 > raw.len() { return None; }
        let dsize = u16::from_be_bytes([raw[pos], raw[pos+1]]) as usize;
        pos += 2;
        if pos + dsize > raw.len() { return None; }
        digests.push(raw[pos..pos+dsize].to_vec());
        pos += dsize;
    }
    Some(digests)
}

// ── Attribute generators ──────────────────────────────────────────────

/// Generate the `tpm_version_major` attribute value.
/// Linux ref: `tpm_version_major_show` (tpm-sysfs.c:302).
fn show_version_major() -> String {
    "2\n".to_string()
}

/// Generate the `tpm_version_minor` attribute value.
fn show_version_minor() -> String {
    "0\n".to_string()
}

/// Generate the `enabled` attribute — always 1 for a working TPM 2.0.
/// Linux ref: `enabled_show` (tpm-sysfs.c:117).
fn show_enabled() -> String {
    "1\n".to_string()
}

/// Generate the `active` attribute — always 1.
/// Linux ref: `active_show` (tpm-sysfs.c:139).
fn show_active() -> String {
    "1\n".to_string()
}

// ── Transport-dependent generators ───────────────────────────────────

/// Build the `owned` attribute show-closure for the given transport.
///
/// Queries `TPM_PT_PERMANENT` and tests bit 2 (`ownerAuthSet`).
/// Returns `"0\n"` or `"1\n"`.
/// Linux ref: `owned_show` (tpm-sysfs.c:161) — for TPM 2.0 uses
/// `TPM2_GetCapability(PT_PERMANENT)`.
fn make_owned_show(transport: Arc<dyn TpmTransport>) -> impl Fn() -> String + Send + Sync {
    move || {
        let val = read_property(transport.as_ref(), PT_PERMANENT).unwrap_or(0);
        // Bit 2 of TPMA_PERMANENT = ownerAuthSet.
        let owned = (val >> 1) & 1;
        format!("{}\n", owned)
    }
}

/// Build the `manufacturer` attribute show-closure.
///
/// Queries `PT_MANUFACTURER` and decodes as 4-char ASCII.
/// Linux ref: `caps_show` (tpm-sysfs.c:205).
fn make_manufacturer_show(transport: Arc<dyn TpmTransport>) -> impl Fn() -> String + Send + Sync {
    move || {
        let val = read_property(transport.as_ref(), PT_MANUFACTURER).unwrap_or(0);
        format!("{}\n", u32_to_ascii4(val))
    }
}

/// Build the `description` attribute show-closure.
///
/// Reads `PT_VENDOR_STRING_1..4` and concatenates them, trimming nulls.
fn make_description_show(
    transport: Arc<dyn TpmTransport>,
) -> impl Fn() -> String + Send + Sync {
    move || {
        let mut out = String::new();
        for prop in PT_VENDOR_STRING_1..=PT_VENDOR_STRING_4 {
            let v = read_property(transport.as_ref(), prop).unwrap_or(0);
            if v == 0 { break; }
            let s = u32_to_ascii4(v);
            let trimmed: String = s.chars().filter(|&c| c != '\0' && c != '?').collect();
            out.push_str(&trimmed);
        }
        if out.is_empty() {
            out.push_str("Unknown");
        }
        out.push('\n');
        out
    }
}

/// Build the `caps` attribute show-closure.
///
/// Queries family, level, revision, and manufacturer and formats them
/// in the same style as Linux `caps_show` (tpm-sysfs.c:205).
fn make_caps_show(transport: Arc<dyn TpmTransport>) -> impl Fn() -> String + Send + Sync {
    move || {
        let family = read_property(transport.as_ref(), PT_FAMILY_INDICATOR).unwrap_or(0);
        let level   = read_property(transport.as_ref(), PT_LEVEL).unwrap_or(0);
        let rev     = read_property(transport.as_ref(), PT_REVISION).unwrap_or(0);
        let mfr     = read_property(transport.as_ref(), PT_MANUFACTURER).unwrap_or(0);
        let family_str = u32_to_ascii4(family);
        let mfr_str    = u32_to_ascii4(mfr);
        format!(
            "TPM 2.0 - manufacturer: {} - family: {} - level: {} - revision: {}.{}\n",
            mfr_str,
            family_str.trim_end_matches('\0').trim_end_matches('?'),
            level,
            rev / 100,
            rev % 100,
        )
    }
}

/// Build the `pcrs` attribute show-closure.
///
/// Reads all 24 PCRs in the SHA-1 and SHA-256 banks and formats them
/// as one line per PCR in the format:
///   `PCR-NN: XX XX ... (SHA-1) | YY YY ... (SHA-256)`
///
/// Linux ref: `pcrs_show` (tpm-sysfs.c:73) — this function queries one
/// PCR at a time; we query one PCR at a time for compatibility.
fn make_pcrs_show(transport: Arc<dyn TpmTransport>) -> impl Fn() -> String + Send + Sync {
    move || {
        let mut out = String::new();
        for pcr in 0u32..24 {
            // Build bitmap for single PCR.
            let mut mask = [0u8; 3];
            if pcr < 24 { mask[(pcr / 8) as usize] |= 1 << (pcr % 8); }

            // SHA-1 bank.
            let sha1_hex = {
                let cmd = pcr_read(TPM_ALG_SHA1, &mask);
                match transport.submit(&cmd).ok()
                    .and_then(|r| parse_pcr_read_response(&r))
                    .and_then(|v| v.into_iter().next())
                {
                    Some(d) => {
                        let mut s = String::new();
                        for (i, b) in d.iter().enumerate() {
                            if i > 0 { s.push(' '); }
                            let hi = (b >> 4) as char;
                            let lo = (b & 0xF) as char;
                            s.push(char::from_digit(hi as u32, 16).unwrap_or('0').to_ascii_uppercase());
                            s.push(char::from_digit(lo as u32, 16).unwrap_or('0').to_ascii_uppercase());
                        }
                        s
                    }
                    None => "??".to_string(),
                }
            };

            // SHA-256 bank.
            let sha256_hex = {
                let cmd = pcr_read(TPM_ALG_SHA256, &mask);
                match transport.submit(&cmd).ok()
                    .and_then(|r| parse_pcr_read_response(&r))
                    .and_then(|v| v.into_iter().next())
                {
                    Some(d) => {
                        let mut s = String::new();
                        for (i, b) in d.iter().enumerate() {
                            if i > 0 { s.push(' '); }
                            let hi = (b >> 4) as char;
                            let lo = (b & 0xF) as char;
                            s.push(char::from_digit(hi as u32, 16).unwrap_or('0').to_ascii_uppercase());
                            s.push(char::from_digit(lo as u32, 16).unwrap_or('0').to_ascii_uppercase());
                        }
                        s
                    }
                    None => "??".to_string(),
                }
            };

            out.push_str(&format!(
                "PCR-{:02}: {} (SHA-1) | {} (SHA-256)\n",
                pcr, sha1_hex, sha256_hex
            ));
        }
        out
    }
}

// ── Public registration function ──────────────────────────────────────

/// Populate `/sys/class/tpm/tpm0/` with all required attributes.
///
/// Called from the TPM driver initcall after the transport is confirmed
/// alive. Attributes that require live TPM queries capture an
/// `Arc<dyn TpmTransport>` clone and call it on each read.
///
/// Linux ref: `tpm_sysfs_add_device` (tpm-chip.c) → the `tpm2_dev_attrs`
/// attribute group (tpm-sysfs.c:343).
pub fn register_sysfs_tpm0(transport: Arc<dyn TpmTransport>) {
    let class_tpm = class_register("tpm");
    let tpm0 = class_device_register(class_tpm, "tpm0");

    // ── Static attributes ─────────────────────────────────────────────

    kobject_add_attr(&tpm0, "tpm_version_major", show_version_major);
    kobject_add_attr(&tpm0, "tpm_version_minor", show_version_minor);
    kobject_add_attr(&tpm0, "enabled",            show_enabled);
    kobject_add_attr(&tpm0, "active",             show_active);

    // ── Transport-dependent attributes ────────────────────────────────

    {
        let t = transport.clone();
        kobject_add_attr(&tpm0, "owned", make_owned_show(t));
    }
    {
        let t = transport.clone();
        kobject_add_attr(&tpm0, "manufacturer", make_manufacturer_show(t));
    }
    {
        let t = transport.clone();
        kobject_add_attr(&tpm0, "description", make_description_show(t));
    }
    {
        let t = transport.clone();
        kobject_add_attr(&tpm0, "caps", make_caps_show(t));
    }
    {
        let t = transport.clone();
        kobject_add_attr(&tpm0, "pcrs", make_pcrs_show(t));
    }
}
