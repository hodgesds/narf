//! File data: `EXTENT_DATA` items (`struct btrfs_file_extent_item`) and the
//! read path.
//!
//! A regular file's data is described by `EXTENT_DATA` items keyed by file
//! offset. An item is either *inline* (the bytes live in the item body, only for
//! small tails at offset 0) or *regular* (the body points at a data extent by
//! logical address). A hole is a regular item with `disk_bytenr == 0`, or —
//! under the `no-holes` feature — simply the absence of an item over that range;
//! either way the gap reads as zeros. Preallocated extents also read as zeros.
//!
//! zlib-, zstd- and LZO-compressed extents (inline and regular) are
//! decompressed on read.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree;
use crate::format::{self, le64};
use crate::volume::BtrfsVolume;

/// Decompress a whole compressed extent according to its algorithm. zlib and
/// zstd are single streams; LZO is btrfs's sector-segmented framing, which needs
/// `sectorsize`.
fn decompress(compression: u8, input: &[u8], sectorsize: usize) -> Result<Vec<u8>, FsError> {
    match compression {
        format::COMPRESS_ZLIB => {
            miniz_oxide::inflate::decompress_to_vec_zlib(input).map_err(|_| FsError::InvalidData)
        }
        format::COMPRESS_ZSTD => {
            use ruzstd::io::Read;
            let mut decoder =
                ruzstd::decoding::StreamingDecoder::new(input).map_err(|_| FsError::InvalidData)?;
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|_| FsError::InvalidData)?;
            Ok(out)
        }
        format::COMPRESS_LZO => crate::lzo::decompress_extent(input, sectorsize),
        _ => Err(FsError::InvalidData),
    }
}

// Field offsets within `struct btrfs_file_extent_item`.
const OFF_RAM_BYTES: usize = 8;
const OFF_COMPRESSION: usize = 16;
const OFF_TYPE: usize = 20;
const OFF_DISK_BYTENR: usize = 21;
const OFF_DISK_NUM_BYTES: usize = 29;
const OFF_EXTENT_OFFSET: usize = 37;
const OFF_NUM_BYTES: usize = 45;
/// Body offset where inline data begins (right after `type`).
const INLINE_DATA_OFF: usize = 21;
/// Minimum size of the fixed header of a regular extent item.
const REG_HEADER_MIN: usize = OFF_NUM_BYTES + 8;

/// A decoded file-extent item.
#[derive(Clone, Debug)]
enum Extent {
    /// Bytes stored inline in the item body (`data` is the slice within it).
    Inline { compression: u8, data: Vec<u8> },
    /// A regular or preallocated extent. `disk_bytenr == 0` (or `prealloc`)
    /// reads as a hole.
    Regular {
        compression: u8,
        disk_bytenr: u64,
        /// On-disk (possibly compressed) length of the whole extent.
        disk_num_bytes: u64,
        /// Offset into the uncompressed extent where this file range begins.
        extent_offset: u64,
        num_bytes: u64,
        /// Uncompressed size of the whole extent.
        ram_bytes: u64,
        prealloc: bool,
    },
}

impl Extent {
    /// Length this extent occupies in the file's logical byte range.
    fn file_len(&self, ram_bytes: u64) -> u64 {
        match self {
            Extent::Inline { .. } => ram_bytes,
            Extent::Regular { num_bytes, .. } => *num_bytes,
        }
    }
}

/// Decode one `EXTENT_DATA` body into `(extent, ram_bytes)`.
fn decode_extent(body: &[u8]) -> Result<(Extent, u64), FsError> {
    if body.len() <= OFF_TYPE {
        return Err(FsError::InvalidData);
    }
    let ram_bytes = le64(body, OFF_RAM_BYTES)?;
    let compression = body[OFF_COMPRESSION];
    let etype = body[OFF_TYPE];
    match etype {
        format::FILE_EXTENT_INLINE => {
            let data = body.get(INLINE_DATA_OFF..).unwrap_or(&[]).to_vec();
            Ok((Extent::Inline { compression, data }, ram_bytes))
        }
        format::FILE_EXTENT_REG | format::FILE_EXTENT_PREALLOC => {
            if body.len() < REG_HEADER_MIN {
                return Err(FsError::InvalidData);
            }
            Ok((
                Extent::Regular {
                    compression,
                    disk_bytenr: le64(body, OFF_DISK_BYTENR)?,
                    disk_num_bytes: le64(body, OFF_DISK_NUM_BYTES)?,
                    extent_offset: le64(body, OFF_EXTENT_OFFSET)?,
                    num_bytes: le64(body, OFF_NUM_BYTES)?,
                    ram_bytes,
                    prealloc: etype == format::FILE_EXTENT_PREALLOC,
                },
                ram_bytes,
            ))
        }
        _ => Err(FsError::InvalidData),
    }
}

/// Read up to `dst.len()` bytes of the file `ino` (byte size `size`) starting at
/// `offset`. Short reads signal EOF. Holes and preallocated ranges read as zero.
pub async fn read_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    tree_root: u64,
    ino: u64,
    size: u64,
    offset: u64,
    dst: &mut [u8],
) -> Result<usize, FsError> {
    if offset >= size || dst.is_empty() {
        return Ok(0);
    }
    let want = dst.len().min((size - offset) as usize);
    let sectorsize = vol.sectorsize() as usize;
    let extents = btree::collect_for(vol, tree_root, ino, format::EXTENT_DATA_KEY).await?;

    // Zero the window first; extents overwrite what they cover, so any hole
    // (explicit or `no-holes`-implicit) is left as zeros.
    dst[..want].fill(0);

    let win_start = offset;
    let win_end = offset + want as u64;
    for (key, body) in &extents {
        let (extent, ram_bytes) = decode_extent(body)?;
        let file_start = key.offset;
        let file_end = file_start.saturating_add(extent.file_len(ram_bytes));
        let ov_start = win_start.max(file_start);
        let ov_end = win_end.min(file_end);
        if ov_start >= ov_end {
            continue;
        }
        match extent {
            Extent::Inline { compression, data } => {
                // Inline data is stored at file offset 0; decompress if needed.
                let plain = if compression == format::COMPRESS_NONE {
                    data
                } else {
                    decompress(compression, &data, sectorsize)?
                };
                for pos in ov_start..ov_end {
                    let src_idx = (pos - file_start) as usize;
                    let byte = *plain.get(src_idx).ok_or(FsError::InvalidData)?;
                    dst[(pos - offset) as usize] = byte;
                }
            }
            Extent::Regular {
                compression,
                disk_bytenr,
                disk_num_bytes,
                extent_offset,
                ram_bytes,
                prealloc,
                ..
            } => {
                // Holes and preallocated ranges stay zero-filled.
                if disk_bytenr == 0 || prealloc {
                    continue;
                }
                let d0 = (ov_start - offset) as usize;
                let read_len = (ov_end - ov_start) as usize;
                if compression == format::COMPRESS_NONE {
                    // Read only the bytes the window needs.
                    let logical = disk_bytenr + extent_offset + (ov_start - file_start);
                    let data = vol.read_logical(logical, read_len).await?;
                    dst[d0..d0 + read_len].copy_from_slice(&data);
                } else {
                    // Compressed extents are decoded whole, then sliced. The
                    // compressed payload of length `disk_num_bytes` lives at
                    // `disk_bytenr`. The inflated stream holds only the real
                    // data (btrfs does not pad it out to the sector-aligned
                    // `ram_bytes`), so any index past its end is implicit zero
                    // padding — dst is already zeroed.
                    let _ = ram_bytes;
                    let raw = vol
                        .read_logical(disk_bytenr, disk_num_bytes as usize)
                        .await?;
                    let plain = decompress(compression, &raw, sectorsize)?;
                    for pos in ov_start..ov_end {
                        let src_idx = (extent_offset + (pos - file_start)) as usize;
                        if let Some(&byte) = plain.get(src_idx) {
                            dst[(pos - offset) as usize] = byte;
                        }
                    }
                }
            }
        }
    }
    Ok(want)
}
