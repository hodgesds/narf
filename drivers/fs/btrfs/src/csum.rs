//! Data checksums (the CSUM tree).
//!
//! btrfs stores one checksum for every `sectorsize` block of file data in a
//! separate tree, keyed `(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, logical)`.
//! Each item body is a packed array of the filesystem's selected checksum type,
//! covering a contiguous logical range starting at `key.offset`. A real Linux
//! kernel verifies these on every data read, so the read and write paths must
//! agree on both the algorithm and its on-disk width.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree::Cursor;
use crate::format::{self, BtrfsKey};
use crate::volume::BtrfsVolume;

/// Look up the stored data checksum for the sector at logical address `logical`
/// (which must be `sectorsize`-aligned). Returns `None` if no csum item covers
/// it (e.g. a `nodatasum` extent).
pub async fn find_csum<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    csum_root: u64,
    logical: u64,
    sectorsize: u64,
) -> Result<Option<Vec<u8>>, FsError> {
    let csum_bytes = crate::checksum::size(vol.csum_type())?;
    let start = BtrfsKey::new(format::EXTENT_CSUM_OBJECTID, format::EXTENT_CSUM_KEY, 0);
    let mut cursor = Cursor::seek(vol, csum_root, &start).await?;
    while let Some((key, body)) = cursor.current()? {
        if key.objectid != format::EXTENT_CSUM_OBJECTID || key.item_type != format::EXTENT_CSUM_KEY
        {
            break;
        }
        if key.offset > logical {
            break; // items are ordered by offset; the covering one is earlier
        }
        if body.len() % csum_bytes != 0 {
            return Err(FsError::InvalidData);
        }
        let sectors = (body.len() / csum_bytes) as u64;
        let covered_end = key.offset + sectors * sectorsize;
        if logical < covered_end {
            let idx = ((logical - key.offset) / sectorsize) as usize;
            let start = idx.checked_mul(csum_bytes).ok_or(FsError::InvalidData)?;
            let stored = body
                .get(start..start + csum_bytes)
                .ok_or(FsError::InvalidData)?;
            return Ok(Some(stored.to_vec()));
        }
        cursor.advance().await?;
    }
    Ok(None)
}

/// Verify that every physical `sectorsize` block of a file's regular extents
/// matches its stored data checksum. For compressed extents btrfs checksums the
/// sector-padded compressed payload, not the inflated bytes. `Ok(true)` if all
/// present csums match; `Ok(false)` on any mismatch or missing csum.
pub async fn verify_file_data_csums<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    tree_root: u64,
    csum_root: u64,
    ino: u64,
) -> Result<bool, FsError> {
    let sectorsize = u64::from(vol.sectorsize());
    let extents = crate::btree::collect_for(vol, tree_root, ino, format::EXTENT_DATA_KEY).await?;
    for (_key, body) in &extents {
        if body.len() < 53 || body[20] != format::FILE_EXTENT_REG {
            continue;
        }
        let disk_bytenr = format::le64(body, 21)?;
        let disk_num_bytes = format::le64(body, 29)?;
        if disk_bytenr == 0 {
            continue; // hole
        }
        let mut off = 0u64;
        while off < disk_num_bytes {
            let logical = disk_bytenr + off;
            let sector = vol.read_logical(logical, sectorsize as usize).await?;
            let want = crate::checksum::digest(vol.csum_type(), &sector)?;
            let csum_bytes = crate::checksum::size(vol.csum_type())?;
            match find_csum(vol, csum_root, logical, sectorsize).await? {
                Some(stored) if stored == want[..csum_bytes] => {}
                _ => return Ok(false),
            }
            off += sectorsize;
        }
    }
    Ok(true)
}

/// Compute the packed csum-item body (one selected digest per sector) for a
/// freshly written `data` extent. Used by the write path to emit csums.
pub fn compute_csums(csum_type: u16, data: &[u8], sectorsize: usize) -> Result<Vec<u8>, FsError> {
    if sectorsize == 0 {
        return Err(FsError::InvalidData);
    }
    let csum_bytes = crate::checksum::size(csum_type)?;
    let sectors = data.len().div_ceil(sectorsize);
    let mut out = Vec::with_capacity(sectors * csum_bytes);
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + sectorsize).min(data.len());
        let sum = crate::checksum::digest(csum_type, &data[off..end])?;
        out.extend_from_slice(&sum[..csum_bytes]);
        off += sectorsize;
    }
    Ok(out)
}
