//! UDF File Identifier Descriptor (FID) — directory-entry decode.
//!
//! Clean-room layout per ECMA-167 (3rd edition, June 1997). No
//! GPL/LGPL UDF source consulted.
//!
//! References:
//! - ECMA-167 §4/14.4 (File Identifier Descriptor — variable-length
//!   directory entry: 16-byte tag + 16-bit FileVersionNumber +
//!   FileCharacteristics byte + L_FI byte + 16-byte ICB +
//!   L_IU u16 + L_IU bytes of ImplementationUse + identifier bytes
//!   (preceded by a 1-byte CompressionID) + padding to a 4-byte
//!   boundary).
//! - ECMA-167 §4/14.4.3 (FileCharacteristics — bit values used
//!   below).
//! - OSTA UDF 2.60 §2.1.1 (CompressionID — 8 = bytewise 8-bit
//!   characters; 16 = UTF-16BE).

use alloc::string::String;

use super::descriptor::{read_descriptor_tag, tag_id, DescriptorTag};
use super::icb::{read_long_ad, LongAd};

/// FileCharacteristics bit values (ECMA-167 §4/14.4.3).
pub mod characteristics {
    /// §4/14.4.3 — entry refers to a directory.
    pub const DIRECTORY: u8 = 0x02;
    /// §4/14.4.3 — entry has been deleted.
    pub const DELETED: u8 = 0x04;
    /// §4/14.4.3 — entry refers to the parent directory ("..").
    pub const PARENT: u8 = 0x08;
    /// §4/14.4.3 — entry refers to a metadata file (rare).
    pub const METADATA: u8 = 0x10;
}

/// Decoded File Identifier Descriptor — the bits the read-only walk
/// actually consumes.
#[derive(Clone, Debug)]
pub struct Fid {
    /// Descriptor Tag — the caller already validated `tag_identifier
    /// == 257` to reach this struct.
    pub tag: DescriptorTag,
    /// FileVersionNumber (ECMA-167 §4/14.4.1) — usually 1.
    pub file_version_number: u16,
    /// FileCharacteristics (ECMA-167 §4/14.4.3).
    pub file_characteristics: u8,
    /// 16-byte long_ad pointing at the child's File Entry ICB
    /// (ECMA-167 §4/14.4.4).
    pub icb: LongAd,
    /// Length of ImplementationUse area, in bytes.
    pub length_of_implementation_use: u16,
    /// Decoded identifier as an ASCII-flavoured `String` (see
    /// [`decode_identifier`]).
    pub identifier: String,
    /// Total record length on disc (header + L_IU + L_FI bytes,
    /// padded up to a 4-byte boundary).
    pub record_length: usize,
}

impl Fid {
    #[inline]
    pub fn is_directory(&self) -> bool {
        (self.file_characteristics & characteristics::DIRECTORY) != 0
    }
    #[inline]
    pub fn is_deleted(&self) -> bool {
        (self.file_characteristics & characteristics::DELETED) != 0
    }
    #[inline]
    pub fn is_parent(&self) -> bool {
        (self.file_characteristics & characteristics::PARENT) != 0
    }
}

/// Errors returned by [`decode_fid`]. The caller surfaces them as
/// `FsError::Io(BlockError::IOError)` once they bubble up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FidDecodeError {
    /// Buffer too small to hold the fixed 38-byte FID header.
    Truncated,
    /// Buffer too small to hold the variable-length tail.
    TailTruncated,
    /// Tag identifier ≠ 257.
    NotAFid,
}

/// Round `n` up to the next multiple of 4 (FID padding rule —
/// ECMA-167 §4/14.4.9).
#[inline]
pub fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Decode one File Identifier Descriptor at `buf[offset..]`. On
/// success returns the decoded FID and the total bytes the record
/// consumes on disc (already 4-byte aligned).
pub fn decode_fid(buf: &[u8], offset: usize) -> Result<Fid, FidDecodeError> {
    // §4/14.4 fixed header is 38 bytes (16 tag + 2 version + 1
    // characteristics + 1 L_FI + 16 ICB + 2 L_IU). Then comes
    // L_IU bytes of ImplementationUse, then L_FI bytes of identifier
    // (when L_FI > 0 the first identifier byte is the CompressionID).
    if buf.len() < offset + 38 {
        return Err(FidDecodeError::Truncated);
    }
    let tag = read_descriptor_tag(buf, offset);
    if tag.tag_identifier != tag_id::FILE_IDENTIFIER_DESCRIPTOR {
        return Err(FidDecodeError::NotAFid);
    }

    let mut t2 = [0u8; 2];
    t2.copy_from_slice(&buf[offset + 16..offset + 18]);
    let file_version_number = u16::from_le_bytes(t2);
    let file_characteristics = buf[offset + 18];
    let l_fi = buf[offset + 19] as usize;
    let icb = read_long_ad(buf, offset + 20);
    t2.copy_from_slice(&buf[offset + 36..offset + 38]);
    let length_of_implementation_use = u16::from_le_bytes(t2);
    let l_iu = length_of_implementation_use as usize;

    let id_off = offset + 38 + l_iu;
    if buf.len() < id_off + l_fi {
        return Err(FidDecodeError::TailTruncated);
    }
    let identifier_bytes = &buf[id_off..id_off + l_fi];
    let identifier = decode_identifier(identifier_bytes);

    // §4/14.4.9 — padding to next 4-byte boundary.
    let raw_len = 38 + l_iu + l_fi;
    let record_length = align4(raw_len);

    Ok(Fid {
        tag,
        file_version_number,
        file_characteristics,
        icb,
        length_of_implementation_use,
        identifier,
        record_length,
    })
}

/// Decode a UDF identifier string. The first byte is the
/// CompressionID (OSTA UDF 2.60 §2.1.1); everything after is the
/// raw character data.
///
/// - CompressionID 8 — each subsequent byte is a single 8-bit
///   character. Treat as ASCII; non-ASCII bytes (>= 0x80) become
///   `?`.
/// - CompressionID 16 — each subsequent two bytes is a UTF-16BE
///   codepoint. The MVP only handles BMP codepoints in the
///   ASCII / Latin-1 plane; anything outside ASCII becomes `?`.
/// - Anything else (or empty input) — return an empty String. UDF
///   reserves a few CompressionIDs for future use; until they appear
///   on real media we deliberately don't synthesise plausible
///   characters.
pub fn decode_identifier(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let cid = bytes[0];
    let body = &bytes[1..];
    match cid {
        8 => {
            // 8-bit characters — ASCII fast path.
            let mut s = String::with_capacity(body.len());
            for &b in body {
                if b < 0x80 {
                    s.push(b as char);
                } else {
                    s.push('?');
                }
            }
            s
        }
        16 => {
            // UTF-16BE pairs. Decode BMP-only; everything outside
            // ASCII becomes `?` per the MVP scope.
            let mut s = String::with_capacity(body.len() / 2);
            let mut i = 0;
            while i + 1 < body.len() {
                let hi = body[i];
                let lo = body[i + 1];
                let cp = ((hi as u32) << 8) | (lo as u32);
                if cp < 0x80 {
                    s.push(cp as u8 as char);
                } else {
                    s.push('?');
                }
                i += 2;
            }
            s
        }
        _ => String::new(),
    }
}
