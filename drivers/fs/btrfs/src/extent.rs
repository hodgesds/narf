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
//! Compression is out of scope: any item with `compression != 0` is rejected
//! with `Unsupported` rather than returning wrong bytes.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree;
use crate::format::{self, le64, BtrfsKey};
use crate::volume::BtrfsVolume;

// Field offsets within `struct btrfs_file_extent_item`.
const OFF_RAM_BYTES: usize = 8;
const OFF_COMPRESSION: usize = 16;
const OFF_TYPE: usize = 20;
const OFF_DISK_BYTENR: usize = 21;
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
        extent_offset: u64,
        num_bytes: u64,
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
                    extent_offset: le64(body, OFF_EXTENT_OFFSET)?,
                    num_bytes: le64(body, OFF_NUM_BYTES)?,
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
    ino: u64,
    size: u64,
    offset: u64,
    dst: &mut [u8],
) -> Result<usize, FsError> {
    if offset >= size || dst.is_empty() {
        return Ok(0);
    }
    let want = dst.len().min((size - offset) as usize);
    let (fs_root, _) = vol.fs_tree_root();
    let extents = btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY).await?;

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
                if compression != 0 {
                    return Err(FsError::Unsupported);
                }
                for pos in ov_start..ov_end {
                    let src_idx = (pos - file_start) as usize;
                    let byte = *data.get(src_idx).ok_or(FsError::InvalidData)?;
                    dst[(pos - offset) as usize] = byte;
                }
            }
            Extent::Regular {
                compression,
                disk_bytenr,
                extent_offset,
                prealloc,
                ..
            } => {
                if compression != 0 {
                    return Err(FsError::Unsupported);
                }
                // Holes and preallocated ranges stay zero-filled.
                if disk_bytenr == 0 || prealloc {
                    continue;
                }
                let read_len = (ov_end - ov_start) as usize;
                let logical = disk_bytenr + extent_offset + (ov_start - file_start);
                let data = vol.read_logical(logical, read_len).await?;
                let d0 = (ov_start - offset) as usize;
                dst[d0..d0 + read_len].copy_from_slice(&data);
            }
        }
    }
    Ok(want)
}

/// Whether the file's data uses compression (any `EXTENT_DATA.compression !=
/// 0`). Used by the write path to refuse compressed files up front.
pub async fn is_compressed<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
) -> Result<bool, FsError> {
    let (fs_root, _) = vol.fs_tree_root();
    let start = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, 0);
    let mut cursor = btree::Cursor::seek(vol, fs_root, &start).await?;
    while let Some((key, body)) = cursor.current()? {
        if key.objectid != ino || key.item_type != format::EXTENT_DATA_KEY {
            break;
        }
        if body.len() > OFF_COMPRESSION && body[OFF_COMPRESSION] != 0 {
            return Ok(true);
        }
        cursor.advance().await?;
    }
    Ok(false)
}
