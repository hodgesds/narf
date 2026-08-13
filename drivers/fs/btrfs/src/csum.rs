//! Data checksums (the CSUM tree).
//!
//! btrfs stores a CRC32C for every `sectorsize` block of file data in a separate
//! tree, keyed `(EXTENT_CSUM_OBJECTID, EXTENT_CSUM_KEY, logical)`. Each item body
//! is a packed array of little-endian `u32` checksums covering a contiguous
//! logical range starting at `key.offset`. A real Linux kernel verifies these on
//! every data read, so a write that does not maintain them produces a file the
//! kernel refuses to read — hence this module both *reads* csums (to validate
//! that our CRC32C form matches mkfs, and optionally to verify data on read) and
//! is the basis the write path uses to *emit* them.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree::Cursor;
use crate::checksum::block_csum;
use crate::format::{self, le32, BtrfsKey};
use crate::volume::BtrfsVolume;

/// CRC32C is 4 bytes on disk.
pub const CSUM_ITEM_BYTES: usize = 4;

/// Look up the stored data checksum for the sector at logical address `logical`
/// (which must be `sectorsize`-aligned). Returns `None` if no csum item covers
/// it (e.g. a `nodatasum` extent).
pub async fn find_csum<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    csum_root: u64,
    logical: u64,
    sectorsize: u64,
) -> Result<Option<u32>, FsError> {
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
        let sectors = (body.len() / CSUM_ITEM_BYTES) as u64;
        let covered_end = key.offset + sectors * sectorsize;
        if logical < covered_end {
            let idx = ((logical - key.offset) / sectorsize) as usize;
            return Ok(Some(le32(body, idx * CSUM_ITEM_BYTES)?));
        }
        cursor.advance().await?;
    }
    Ok(None)
}

/// Verify that every `sectorsize` block of a file's single uncompressed regular
/// extent matches its stored data checksum. `Ok(true)` if all present csums
/// match; `Ok(false)` on any mismatch or missing csum. Used to prove our CRC32C
/// data-csum form agrees with mkfs, and to check the write path's own output.
pub async fn verify_file_data_csums<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    tree_root: u64,
    csum_root: u64,
    ino: u64,
) -> Result<bool, FsError> {
    let sectorsize = u64::from(vol.sectorsize());
    let extents = crate::btree::collect_for(vol, tree_root, ino, format::EXTENT_DATA_KEY).await?;
    for (_key, body) in &extents {
        // Only uncompressed regular extents carry per-sector data csums here.
        if body.len() < 53 || body[20] != format::FILE_EXTENT_REG || body[16] != 0 {
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
            let want = block_csum(&sector);
            match find_csum(vol, csum_root, logical, sectorsize).await? {
                Some(stored) if stored == want => {}
                _ => return Ok(false),
            }
            off += sectorsize;
        }
    }
    Ok(true)
}

/// Compute the packed csum-item body (one little-endian CRC32C per sector) for a
/// freshly written `data` extent. Used by the write path to emit csums.
pub fn compute_csums(data: &[u8], sectorsize: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / sectorsize * CSUM_ITEM_BYTES);
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + sectorsize).min(data.len());
        out.extend_from_slice(&block_csum(&data[off..end]).to_le_bytes());
        off += sectorsize;
    }
    out
}
