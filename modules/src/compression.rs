//! Bounded compressed-module envelope.
//!
//! Compression is deliberately outside the ELF payload. A production image
//! is laid out as:
//!
//! ```text
//! NRFCMOD header | LZ4 block | optional NRFM signature trailer
//! ```
//!
//! The signature therefore authenticates both the declared lengths and the
//! compressed bytes before this module allocates an output buffer or invokes
//! the decoder. Raw ELF remains a supported input; this module handles only
//! images beginning with [`MODULE_COMPRESSION_MAGIC`].

use alloc::vec::Vec;

/// Magic at the start of a compressed NARF module.
pub const MODULE_COMPRESSION_MAGIC: [u8; 8] = *b"NRFCMOD\0";
/// Current envelope version.
pub const MODULE_COMPRESSION_VERSION: u16 = 1;
/// LZ4 block-format algorithm identifier.
pub const MODULE_COMPRESSION_LZ4: u16 = 1;
/// Fixed v1 header length.
pub const MODULE_COMPRESSION_HEADER_LEN: usize = 24;
/// Hard decompression and compressed-input bound.
///
/// This is intentionally well below the 128 MiB module VA window. It bounds
/// both the temporary load buffer and decompressor work before ELF section
/// layout applies its own tighter mapped-image limit.
pub const MAX_MODULE_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Rejection reasons for a claimed compressed-module envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompressionError {
    Truncated,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    InvalidHeader,
    TooLarge,
    LengthMismatch,
    OutOfMemory,
    DecompressionFailed,
}

/// Whether `image` explicitly claims the NARF compressed-module format.
#[inline]
pub fn is_compressed(image: &[u8]) -> bool {
    image.starts_with(&MODULE_COMPRESSION_MAGIC)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Decode an authenticated compressed-module envelope into its raw ELF.
///
/// The caller must authenticate the exact `image` bytes first in production.
/// Keeping authentication in the loader makes that ordering explicit and
/// lets developer builds use the same decoder for deliberately unsigned test
/// fixtures.
pub(crate) fn decompress(image: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if image.len() < MODULE_COMPRESSION_HEADER_LEN {
        return Err(CompressionError::Truncated);
    }
    if !is_compressed(image) {
        return Err(CompressionError::InvalidHeader);
    }
    if u16_at(image, 8) != MODULE_COMPRESSION_VERSION {
        return Err(CompressionError::UnsupportedVersion);
    }
    if u16_at(image, 10) != MODULE_COMPRESSION_LZ4 {
        return Err(CompressionError::UnsupportedAlgorithm);
    }
    if u32_at(image, 12) as usize != MODULE_COMPRESSION_HEADER_LEN {
        return Err(CompressionError::InvalidHeader);
    }

    let plain_len = u32_at(image, 16) as usize;
    let compressed_len = u32_at(image, 20) as usize;
    if plain_len == 0
        || compressed_len == 0
        || plain_len > MAX_MODULE_FILE_BYTES
        || compressed_len > MAX_MODULE_FILE_BYTES
    {
        return Err(CompressionError::TooLarge);
    }
    if image.len() != MODULE_COMPRESSION_HEADER_LEN + compressed_len {
        return Err(CompressionError::LengthMismatch);
    }

    let mut plain = Vec::new();
    plain
        .try_reserve_exact(plain_len)
        .map_err(|_| CompressionError::OutOfMemory)?;
    plain.resize(plain_len, 0);
    let written =
        narf_memory::compress::lz4_decode(&image[MODULE_COMPRESSION_HEADER_LEN..], &mut plain)
            .map_err(|_| CompressionError::DecompressionFailed)?;
    if written != plain_len {
        return Err(CompressionError::LengthMismatch);
    }
    Ok(plain)
}

/// Construct a v1 envelope from an already-compressed LZ4 block.
///
/// Kept crate-visible so kernel smokes can construct adversarial envelopes
/// without duplicating the wire format. Production creation lives in xtask.
#[doc(hidden)]
pub(crate) fn envelope_lz4(
    plain_len: usize,
    compressed: &[u8],
) -> Result<Vec<u8>, CompressionError> {
    if plain_len == 0
        || compressed.is_empty()
        || plain_len > MAX_MODULE_FILE_BYTES
        || compressed.len() > MAX_MODULE_FILE_BYTES
    {
        return Err(CompressionError::TooLarge);
    }
    let plain_len = u32::try_from(plain_len).map_err(|_| CompressionError::TooLarge)?;
    let compressed_len = u32::try_from(compressed.len()).map_err(|_| CompressionError::TooLarge)?;
    let mut out = Vec::with_capacity(MODULE_COMPRESSION_HEADER_LEN + compressed.len());
    out.extend_from_slice(&MODULE_COMPRESSION_MAGIC);
    out.extend_from_slice(&MODULE_COMPRESSION_VERSION.to_le_bytes());
    out.extend_from_slice(&MODULE_COMPRESSION_LZ4.to_le_bytes());
    out.extend_from_slice(&(MODULE_COMPRESSION_HEADER_LEN as u32).to_le_bytes());
    out.extend_from_slice(&plain_len.to_le_bytes());
    out.extend_from_slice(&compressed_len.to_le_bytes());
    out.extend_from_slice(compressed);
    Ok(out)
}
