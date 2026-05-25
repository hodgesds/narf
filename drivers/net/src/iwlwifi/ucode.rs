//! Intel iwlwifi — ucode (firmware) image header decode.
//!
//! Adapted from Linux `drivers/net/wireless/intel/iwlwifi/fw/file.h`
//! — `struct iwl_tlv_ucode_header` + `enum iwl_ucode_tlv_type`.
//! GPL-2.0-or-later.
//!
//! Stage-2 lands the parser. Actual DMA upload of the section
//! payloads is Stage-3.
//!
//! Layout (each `__le32` is 4 bytes, the `__packed` rule makes the
//! sizes additive):
//!
//! ```text
//!   offset  field                 bytes
//!   0       zero                  4    (distinguishes from v1/v2)
//!   4       magic = 0x0A4C5749    4
//!   8       human_readable        64   (UTF-8, NUL-padded)
//!   72      ver                   4    (maj/min/api/serial)
//!   76      build                 4
//!   80      ignore                8    (legacy padding)
//!   88      TLV stream            ..   (each TLV is { type:u32, len:u32, data[len], align(4) })
//! ```
//!
//! A TLV's declared `len` does NOT include its own 8-byte header,
//! and the next TLV starts at `8 + ((len + 3) & ~3)`.

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

/// Magic at offset 4 of a valid Intel `.ucode` blob. Sourced from
/// Linux `fw/file.h::IWL_TLV_UCODE_MAGIC`.
pub const IWL_TLV_UCODE_MAGIC: u32 = 0x0A4C_5749;

/// Total bytes in the TLV-ucode header before the TLV stream begins.
/// `4 + 4 + 64 + 4 + 4 + 8 = 88`.
pub const TLV_HEADER_BYTES: usize = 88;

/// Maximum length of the "human readable" version string (also from
/// `fw/file.h::FW_VER_HUMAN_READABLE_SZ`).
pub const FW_VER_HUMAN_READABLE_SZ: usize = 64;

/// Decoded firmware header (the non-TLV preamble).
#[derive(Clone, Debug)]
pub struct UcodeHeader {
    /// Major / minor / API / serial — driver displays this as
    /// `maj.min.api.serial` when newer TLV-encoded versions are absent.
    pub version: u32,
    /// CI build number, when set by the build pipeline.
    pub build: u32,
    /// Vendor-supplied version string from the 64-byte field; the
    /// canonical Intel format is `${family}-${vermaj}.${vermin}.${api}.tlv`.
    pub human_readable: String,
}

/// TLV section kinds we recognize. Unknown values are surfaced via
/// `TlvType::Other(u32)` so the walker is forward-compatible with
/// new Linux additions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlvType {
    /// Legacy CPU1 instruction blob (pre-22000 era).
    Inst,
    /// Legacy CPU1 data.
    Data,
    /// Legacy INIT instructions.
    Init,
    /// Legacy INIT data.
    InitData,
    /// Legacy bootstrap code.
    Boot,
    /// Modern runtime section: `{ dest_offset: u32; payload }`.
    SecRt,
    /// Modern INIT section.
    SecInit,
    /// Modern WoWLAN section.
    SecWowlan,
    /// `u32`: 1 or 2. Sections beyond split go to CPU2.
    NumOfCpu,
    /// Cipher schemes.
    Cscheme,
    /// `maj.min.api` version triple — TLV form of `header.version`.
    FwVersion,
    /// API-capability bitmap.
    ApiChangesSet,
    /// Feature-capability bitmap.
    EnabledCapabilities,
    /// PNVM-required version (AX210+ only).
    PnvmVersion,
    /// PNVM SKU selector.
    PnvmSku,
    /// Any TLV type we don't model explicitly.
    Other(u32),
}

impl TlvType {
    pub fn from_raw(v: u32) -> Self {
        match v {
            1 => Self::Inst,
            2 => Self::Data,
            3 => Self::Init,
            4 => Self::InitData,
            5 => Self::Boot,
            19 => Self::SecRt,
            20 => Self::SecInit,
            21 => Self::SecWowlan,
            27 => Self::NumOfCpu,
            28 => Self::Cscheme,
            29 => Self::ApiChangesSet,
            30 => Self::EnabledCapabilities,
            36 => Self::FwVersion,
            62 => Self::PnvmVersion,
            64 => Self::PnvmSku,
            other => Self::Other(other),
        }
    }

    /// Whether this TLV is a section TLV — leads with a 4-byte
    /// `dest_offset` then a payload. Stage 3 DMA-uploads these.
    #[inline]
    pub fn is_section(self) -> bool {
        matches!(self, Self::SecRt | Self::SecInit | Self::SecWowlan)
    }
}

/// One section entry produced by the TLV walker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub kind: TlvType,
    /// Device-side SRAM destination this section gets DMA'd to.
    pub dest_offset: u32,
    /// Offset within the input blob where the payload starts (i.e.
    /// 8 bytes past the TLV header + 4 bytes past the `dest_offset`).
    pub payload_offset: usize,
    /// Length of the payload (declared `len` minus the 4-byte
    /// `dest_offset` field).
    pub payload_len: usize,
}

/// Parsed ucode blob — header + the section table.
#[derive(Clone, Debug)]
pub struct ParsedUcode {
    pub header: UcodeHeader,
    /// One entry per SEC_RT / SEC_INIT / SEC_WOWLAN TLV in
    /// declaration order. Other TLV types are walked but not
    /// surfaced — Stage 3 / 4 wires those in as needed.
    pub sections: Vec<Section>,
    /// Count of TLVs we walked but didn't surface — useful for
    /// diagnostics in the boot log ("ucode: 27 sections, 14 metadata TLVs").
    pub metadata_tlv_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Blob too short for the 88-byte TLV-ucode header.
    TooShort,
    /// Magic at offset 4 didn't match `IWL_TLV_UCODE_MAGIC`. The
    /// observed value is included so the caller can log it.
    BadMagic(u32),
    /// A TLV's declared length runs past EOF.
    TruncatedTlv {
        offset: usize,
        declared_len: u32,
        remaining: usize,
    },
    /// A section TLV is < 4 bytes (no room for `dest_offset`).
    SectionTooShort { offset: usize, len: u32 },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::TooShort => f.write_str("ucode: blob shorter than TLV header"),
            ParseError::BadMagic(v) => write!(f, "ucode: bad magic {:#010x}", v),
            ParseError::TruncatedTlv {
                offset,
                declared_len,
                remaining,
            } => write!(
                f,
                "ucode: truncated TLV at offset {} (declared {} bytes, {} remain)",
                offset, declared_len, remaining
            ),
            ParseError::SectionTooShort { offset, len } => write!(
                f,
                "ucode: section TLV at {} too short ({} bytes; need ≥ 4 for dest_offset)",
                offset, len
            ),
        }
    }
}

/// Parse a `.ucode` blob into header + section table.
///
/// Stops at the first malformed TLV — partial output is not
/// returned, so the caller either gets a fully-walked `ParsedUcode`
/// or a structural error. This matches the upstream behaviour where
/// a corrupt TLV aborts the load.
pub fn parse_header(blob: &[u8]) -> Result<ParsedUcode, ParseError> {
    if blob.len() < TLV_HEADER_BYTES {
        return Err(ParseError::TooShort);
    }

    // First 4 bytes are zero (distinguishes from v1/v2 layout); we
    // intentionally don't enforce that because some images carry
    // build-pipeline padding. Magic is the load-bearing check.
    let magic = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if magic != IWL_TLV_UCODE_MAGIC {
        return Err(ParseError::BadMagic(magic));
    }

    let human_readable = decode_human_readable(&blob[8..8 + FW_VER_HUMAN_READABLE_SZ]);
    let version = u32::from_le_bytes([blob[72], blob[73], blob[74], blob[75]]);
    let build = u32::from_le_bytes([blob[76], blob[77], blob[78], blob[79]]);
    // Bytes 80..88 are the legacy "ignore" padding.

    let header = UcodeHeader {
        version,
        build,
        human_readable,
    };

    let mut sections = Vec::new();
    let mut metadata_tlv_count = 0usize;
    let mut cursor = TLV_HEADER_BYTES;

    while cursor + 8 <= blob.len() {
        let type_raw =
            u32::from_le_bytes([blob[cursor], blob[cursor + 1], blob[cursor + 2], blob[cursor + 3]]);
        let len_raw = u32::from_le_bytes([
            blob[cursor + 4],
            blob[cursor + 5],
            blob[cursor + 6],
            blob[cursor + 7],
        ]);
        let len = len_raw as usize;
        let data_off = cursor + 8;
        let remaining = blob.len() - data_off;
        if len > remaining {
            return Err(ParseError::TruncatedTlv {
                offset: cursor,
                declared_len: len_raw,
                remaining,
            });
        }
        let kind = TlvType::from_raw(type_raw);
        if kind.is_section() {
            if len < 4 {
                return Err(ParseError::SectionTooShort {
                    offset: cursor,
                    len: len_raw,
                });
            }
            let dest_offset = u32::from_le_bytes([
                blob[data_off],
                blob[data_off + 1],
                blob[data_off + 2],
                blob[data_off + 3],
            ]);
            sections.push(Section {
                kind,
                dest_offset,
                payload_offset: data_off + 4,
                payload_len: len - 4,
            });
        } else {
            metadata_tlv_count += 1;
        }

        // TLVs are 4-byte aligned — round up the declared length.
        let aligned_len = (len + 3) & !3;
        // Saturating add so a malicious blob can't wrap us into a
        // false continuation.
        cursor = cursor.saturating_add(8).saturating_add(aligned_len);
    }

    Ok(ParsedUcode {
        header,
        sections,
        metadata_tlv_count,
    })
}

/// Decode the 64-byte NUL-padded human-readable field into a Rust
/// `String`. Non-UTF-8 bytes get the U+FFFD replacement char so we
/// never panic on a junk blob.
fn decode_human_readable(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}
