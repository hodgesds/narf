//! `brcmfmac` firmware blob + NVRAM parsers.
//!
//! ## Two payloads
//!
//! The brcmfmac firmware download path actually carries two distinct
//! blobs that the host pushes into device-side RAM at boot:
//!
//!  1. **The firmware image** — a multi-MiB binary that Linux loads via
//!     `request_firmware()` and copies to `ci->rambase` via TCM
//!     (`memcpy_toio(devinfo->tcm + devinfo->ci->rambase, fw->data,
//!     fw->size)`, pcie.c ~L1707). Most chips ship a raw binary
//!     blob, but the USB-bus path wraps the image in a Broadcom-
//!     internal "TRX" container (magic `'HDR0'` / 0x30524448) with a
//!     length, CRC, and partition-offsets table. The PCIe path
//!     doesn't use TRX, so this module only covers the parse — not
//!     the load.
//!  2. **The per-board NVRAM file** — `brcmfmacXXXX-pcie.txt`, an ASCII
//!     `key=value` config file with hash-prefixed `#` comments. The
//!     host parses it into a packed `key=value\0key=value\0...`
//!     NUL-separated buffer and uploads that to the dongle just before
//!     the firmware image. The parser here mirrors Linux's
//!     `brcmf_nvram_handle_*` state machine
//!     (`firmware.c` ~L87..L204) byte-for-byte:
//!     - `#` starts a comment; everything until `\n` is dropped.
//!     - Whitespace / `\0` outside of comments is dropped.
//!     - A `key=value` entry is committed as `key=value\0`.
//!     - `RAW1` entries are explicitly skipped (Linux ~L118).
//!
//! ## References
//!
//! - Linux `brcmfmac/firmware.c::brcmf_nvram_handle_*`
//!     (~L87..L204) — NVRAM state machine.
//! - Linux `brcmfmac/usb.c` — TRX header definition
//!     (`TRX_MAGIC = 0x30524448`, `struct trx_header_le` @L96).
//! - Linux `brcmfmac/pcie.c::brcmf_pcie_download_fw_nvram`
//!     (~L1689) — download orchestration the parsers feed.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;

// ── TRX firmware container ────────────────────────────────────────

/// `'HDR0'` little-endian — magic at the start of a TRX-wrapped
/// firmware blob. Per Linux `usb.c:55`.
pub const TRX_MAGIC: u32 = 0x3052_4448;

/// Number of partition offsets in the TRX header. Per Linux
/// `usb.c::trx_header_le::offsets` (~L101).
pub const TRX_MAX_OFFSET: usize = 3;

/// Wire size of a TRX header: magic + len + crc32 + flag_version + 3 *
/// u32 offsets = 7 × 4 = 28 bytes.
pub const TRX_HEADER_SIZE: usize = 7 * 4;

/// Decoded TRX header.
///
/// Reference: Linux `usb.c::trx_header_le` (~L96..L104).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TrxHeader {
    /// Magic value — always 0x30524448 ("HDR0").
    pub magic: u32,
    /// Total length of file including header.
    pub length: u32,
    /// CRC32 from `flag_version` through end of file.
    pub crc32: u32,
    /// Low 16 bits are flags, high 16 are version.
    pub flag_version: u32,
    /// Up to 3 partition offsets from start of header.
    pub offsets: [u32; TRX_MAX_OFFSET],
}

impl TrxHeader {
    /// Decode a TRX header from `bytes`. Returns `None` on a too-short
    /// buffer or a magic mismatch (the most common reason a "raw"
    /// firmware blob will be rejected as TRX).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < TRX_HEADER_SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        if magic != TRX_MAGIC {
            return None;
        }
        let length = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let crc32 = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let flag_version = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let mut offsets = [0u32; TRX_MAX_OFFSET];
        for (i, off) in offsets.iter_mut().enumerate() {
            let s = 16 + i * 4;
            *off = u32::from_le_bytes(bytes[s..s + 4].try_into().ok()?);
        }
        Some(Self {
            magic,
            length,
            crc32,
            flag_version,
            offsets,
        })
    }

    /// Convenience: 16-bit version field (high half of `flag_version`).
    pub const fn version(&self) -> u16 {
        (self.flag_version >> 16) as u16
    }

    /// Convenience: 16-bit flags field (low half of `flag_version`).
    pub const fn flags(&self) -> u16 {
        (self.flag_version & 0xFFFF) as u16
    }
}

// ── Firmware "RAMSIZE" magic embedded in the blob ──────────────────
//
// Some firmware blobs embed a RAM-size hint at offset 0x6C: a `SMAR`
// magic word (0x534D4152 LE) followed by a u32 with the size in bytes.
// Linux's `brcmf_pcie_fwcon_decode_ramsize` (pcie.c ~L1597) reads this
// to override the chip-id-derived default. The host detects the
// presence of the magic before trusting the size field.
//
// Reference: Linux pcie.c ~L286..L287, ~L1597..L1614.

/// `SMAR` LE — magic that flags an embedded RAM-size hint.
/// `BRCMF_RAMSIZE_MAGIC`. Linux pcie.c:286.
pub const FW_RAMSIZE_MAGIC: u32 = 0x534D_4152;

/// Offset into the firmware blob where the SMAR magic lives.
/// `BRCMF_RAMSIZE_OFFSET`. Linux pcie.c:287.
pub const FW_RAMSIZE_OFFSET: usize = 0x6C;

/// If `fw_blob` carries an embedded RAM-size hint, return the size in
/// bytes; otherwise `None`. The hint is identified by the SMAR magic
/// at offset `FW_RAMSIZE_OFFSET` immediately followed by a u32 size.
pub fn embedded_ramsize(fw_blob: &[u8]) -> Option<u32> {
    if fw_blob.len() < FW_RAMSIZE_OFFSET + 8 {
        return None;
    }
    let magic = u32::from_le_bytes(
        fw_blob[FW_RAMSIZE_OFFSET..FW_RAMSIZE_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    if magic != FW_RAMSIZE_MAGIC {
        return None;
    }
    let size = u32::from_le_bytes(
        fw_blob[FW_RAMSIZE_OFFSET + 4..FW_RAMSIZE_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    Some(size)
}

// ── NVRAM parser ──────────────────────────────────────────────────
//
// Direct port of `brcmf_nvram_handle_idle/key/value/comment`
// (firmware.c ~L87..L204). The output is a packed buffer of
// NUL-separated `key=value` entries with comments and whitespace
// stripped. The on-the-wire size is bounded by
// `BRCMF_FW_MAX_NVRAM_SIZE` (64000) — practical NVRAM files are
// ≤ 2 KiB.

/// Upper bound on NVRAM output buffer size. `BRCMF_FW_MAX_NVRAM_SIZE`.
/// Linux firmware.c:20.
pub const NVRAM_MAX_SIZE: usize = 64000;

/// Default boardrev appended when the input doesn't carry one.
/// `BRCMF_FW_DEFAULT_BOARDREV` = "boardrev=0xff" (firmware.c:23).
pub const NVRAM_DEFAULT_BOARDREV: &[u8] = b"boardrev=0xff";

/// Result of a `parse_nvram` call.
#[derive(Debug)]
pub struct NvramParsed {
    /// Packed NUL-separated `key=value` entries.
    pub bytes: Vec<u8>,
    /// True if the parser observed a `boardrev=…` entry — used by
    /// callers to decide whether to append `BRCMF_FW_DEFAULT_BOARDREV`.
    pub boardrev_seen: bool,
    /// True if the parser observed any `devpath…=…` entries
    /// (`multi_dev_v1` in Linux).
    pub multi_dev_v1: bool,
    /// True if the parser observed any `pcie/…=…` entries
    /// (`multi_dev_v2` in Linux).
    pub multi_dev_v2: bool,
}

/// Returns true iff `c` can legally appear inside an NVRAM key or
/// value. Comments (`#`) are explicitly excluded — they open a comment
/// span.
/// Mirrors Linux `is_nvram_char` (firmware.c:72).
#[inline]
fn is_nvram_char(c: u8) -> bool {
    if c == b'#' {
        return false;
    }
    (0x20..0x7F).contains(&c)
}

#[inline]
fn is_whitespace(c: u8) -> bool {
    c == b' ' || c == b'\r' || c == b'\n' || c == b'\t'
}

/// Parse an NVRAM text blob into the packed `key=value\0` form that
/// the firmware download expects. Drops comments (`#…\n`), drops bare
/// whitespace, and skips `RAW1` / empty-key entries.
///
/// Direct port of the Linux state machine
/// (`brcmf_nvram_handle_*` in `firmware.c` ~L87..L204).
pub fn parse_nvram(data: &[u8]) -> NvramParsed {
    let mut out = Vec::new();
    let mut boardrev_seen = false;
    let mut multi_dev_v1 = false;
    let mut multi_dev_v2 = false;

    // Limit input length to NVRAM_MAX_SIZE per Linux firmware.c:214.
    let data = if data.len() > NVRAM_MAX_SIZE {
        &data[..NVRAM_MAX_SIZE]
    } else {
        data
    };

    let mut i = 0;

    // Strip UTF-8 BOM if present (Linux doesn't, but several real
    // NVRAM files Broadcom ships start with one — the parser would
    // otherwise drop the BOM bytes as "invalid" but log a warning).
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        i = 3;
    }

    while i < data.len() {
        let c = data[i];

        // Comment? Skip until newline / NUL.
        if c == b'#' {
            while i < data.len() && data[i] != b'\n' && data[i] != 0 {
                i += 1;
            }
            // Eat the newline itself if any.
            if i < data.len() {
                i += 1;
            }
            continue;
        }

        // Whitespace / NUL outside a key — skip.
        if is_whitespace(c) || c == 0 {
            i += 1;
            continue;
        }

        // Must be the first char of a key — read until `=` or invalid.
        if !is_nvram_char(c) {
            i += 1;
            continue;
        }
        let key_start = i;

        // Scan KEY.
        while i < data.len() {
            let kc = data[i];
            if kc == b'=' {
                break;
            }
            if !is_nvram_char(kc) || kc == b' ' {
                // Malformed; eat to end of line.
                while i < data.len() && data[i] != b'\n' {
                    i += 1;
                }
                break;
            }
            i += 1;
        }
        // No `=` reached → malformed line, retry next.
        if i >= data.len() || data[i] != b'=' {
            continue;
        }
        let key_end = i; // points at `=`

        // Skip `RAW1=…` entries entirely (Linux firmware.c:118).
        if data[key_start..key_end].starts_with(b"RAW1") {
            // Drop the value too.
            while i < data.len() && data[i] != b'\n' && data[i] != 0 {
                i += 1;
            }
            continue;
        }

        // Track multi-dev / boardrev / devpath markers.
        if data[key_start..key_end].starts_with(b"devpath") {
            multi_dev_v1 = true;
        }
        if data[key_start..key_end].starts_with(b"pcie/") {
            multi_dev_v2 = true;
        }
        if data[key_start..key_end].starts_with(b"boardrev") {
            boardrev_seen = true;
        }

        // Consume `=`.
        i += 1;
        // Scan VALUE until first non-NVRAM char (whitespace/NUL/comment).
        let val_start = i;
        while i < data.len() && is_nvram_char(data[i]) {
            i += 1;
        }
        let val_end = i;

        // Emit `key=value\0`.
        if out.len() + (val_end - key_start) + 2 >= NVRAM_MAX_SIZE {
            break;
        }
        out.extend_from_slice(&data[key_start..val_end]);
        out.push(0);
    }

    NvramParsed {
        bytes: out,
        boardrev_seen,
        multi_dev_v1,
        multi_dev_v2,
    }
}

/// Append the default `boardrev=0xff` entry if the parser didn't see
/// one. Mirrors Linux `firmware.c` ~L262 (allocation accounts for a
/// trailing entry).
pub fn append_default_boardrev(parsed: &mut NvramParsed) {
    if parsed.boardrev_seen {
        return;
    }
    if parsed.bytes.len() + NVRAM_DEFAULT_BOARDREV.len() + 1 >= NVRAM_MAX_SIZE {
        return;
    }
    parsed.bytes.extend_from_slice(NVRAM_DEFAULT_BOARDREV);
    parsed.bytes.push(0);
    parsed.boardrev_seen = true;
}
