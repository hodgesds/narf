//! Chunk tree: logical → physical address mapping.
//!
//! Every btrfs address above the superblock is *logical*; the chunk tree
//! translates it to a `(devid, physical)` location on a device. The superblock
//! embeds a `sys_chunk_array` of `(disk_key, btrfs_chunk)` pairs that map just
//! enough of the address space to read the chunk tree itself; walking the chunk
//! tree then yields every remaining chunk. This module parses `btrfs_chunk`
//! items and maintains the resulting map.
//!
//! Scope: single-device SINGLE and DUP profiles only. Any RAID geometry (or a
//! stripe on a foreign device) is rejected with `Unsupported`, since this
//! driver cannot reconstruct data across stripes/mirrors.

use alloc::vec::Vec;

use narf_filesystem::FsError;

use crate::format::{
    le16, le64, BtrfsKey, BLOCK_GROUP_DUP, BLOCK_GROUP_PROFILE_MASK, CHUNK_ITEM_KEY, DISK_KEY_SIZE,
};

/// On-disk `struct btrfs_chunk` header size (fields before the first stripe).
const CHUNK_HEADER_SIZE: usize = 48;
/// On-disk `struct btrfs_stripe` size (devid + offset + 16-byte uuid).
const STRIPE_SIZE: usize = 32;

/// One resolved chunk: a logical range and its one or two physical copies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChunkMapEntry {
    pub logical_start: u64,
    pub length: u64,
    /// Device id owning the stripe. Single-device volumes use one devid.
    pub devid: u64,
    /// Byte offset of the stripe on the device.
    pub physical: u64,
    /// Second same-device copy for the DUP profile.
    pub mirror_physical: Option<u64>,
}

/// The logical→physical translation table, ordered for lookup.
#[derive(Clone, Debug, Default)]
pub struct ChunkMap {
    entries: Vec<ChunkMapEntry>,
}

impl ChunkMap {
    pub fn new() -> Self {
        ChunkMap {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Register a freshly-allocated chunk mapping (the chunk-growth path adds one
    /// SINGLE-profile chunk on one device).
    pub fn add_entry(&mut self, logical_start: u64, length: u64, devid: u64, physical: u64) {
        self.entries.push(ChunkMapEntry {
            logical_start,
            length,
            devid,
            physical,
            mirror_physical: None,
        });
    }

    /// The highest `logical_start + length` across all mapped chunks — the next
    /// free logical address for a new chunk.
    pub fn logical_end(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.logical_start.saturating_add(e.length))
            .max()
            .unwrap_or(0)
    }

    /// Translate a logical address to a physical device offset. Returns
    /// `NotFound` if no chunk covers it.
    pub fn map_logical(&self, logical: u64) -> Result<u64, FsError> {
        self.map_logical_copies(logical).map(|copies| copies.0)
    }

    /// Translate a logical address to its primary and optional DUP physical
    /// copy. Both offsets include the logical offset within the chunk.
    pub fn map_logical_copies(&self, logical: u64) -> Result<(u64, Option<u64>), FsError> {
        for e in &self.entries {
            if logical >= e.logical_start && logical < e.logical_start.saturating_add(e.length) {
                let delta = logical - e.logical_start;
                return Ok((
                    e.physical + delta,
                    e.mirror_physical.map(|physical| physical + delta),
                ));
            }
        }
        Err(FsError::NotFound)
    }

    /// Parse and insert a single `btrfs_chunk` item covering `[logical_start,
    /// logical_start+length)`. `chunk` is the item body (starting at the
    /// `length` field). Rejects unsupported RAID geometry.
    pub fn insert_chunk_item(&mut self, logical_start: u64, chunk: &[u8]) -> Result<(), FsError> {
        if chunk.len() < CHUNK_HEADER_SIZE {
            return Err(FsError::InvalidData);
        }
        let length = le64(chunk, 0)?;
        let chunk_type = le64(chunk, 24)?;
        let num_stripes = le16(chunk, 44)?;
        if num_stripes == 0 {
            return Err(FsError::InvalidData);
        }

        // Only SINGLE (one stripe) or DUP (two stripes on the same device) are
        // supported. Any RAID profile requires reconstruction or routing that
        // this single-device driver deliberately does not implement.
        let profile = chunk_type & BLOCK_GROUP_PROFILE_MASK;
        if profile != 0 && profile != BLOCK_GROUP_DUP {
            return Err(FsError::Unsupported);
        }
        if (profile == 0 && num_stripes != 1) || (profile == BLOCK_GROUP_DUP && num_stripes != 2) {
            return Err(FsError::InvalidData);
        }

        let need = CHUNK_HEADER_SIZE
            .checked_add(
                STRIPE_SIZE
                    .checked_mul(num_stripes as usize)
                    .ok_or(FsError::InvalidData)?,
            )
            .ok_or(FsError::InvalidData)?;
        if chunk.len() < need {
            return Err(FsError::InvalidData);
        }

        // Stripe 0.
        let devid = le64(chunk, CHUNK_HEADER_SIZE)?;
        let physical = le64(chunk, CHUNK_HEADER_SIZE + 8)?;
        let mirror_physical = if profile == BLOCK_GROUP_DUP {
            let second = CHUNK_HEADER_SIZE + STRIPE_SIZE;
            if le64(chunk, second)? != devid {
                return Err(FsError::Unsupported);
            }
            Some(le64(chunk, second + 8)?)
        } else {
            None
        };

        self.entries.push(ChunkMapEntry {
            logical_start,
            length,
            devid,
            physical,
            mirror_physical,
        });
        Ok(())
    }

    /// Seed the map from the superblock's embedded `sys_chunk_array`, a packed
    /// sequence of `(btrfs_disk_key, btrfs_chunk)` pairs. This provides enough
    /// mapping to reach the chunk-tree root; the full map is completed by
    /// walking the chunk tree.
    pub fn seed_from_sys_array(sys: &[u8]) -> Result<Self, FsError> {
        let mut map = ChunkMap::new();
        let mut pos = 0usize;
        while pos < sys.len() {
            // Each record is a disk_key followed by a variable-length chunk.
            let key = BtrfsKey::decode(sys, pos)?;
            if key.item_type != CHUNK_ITEM_KEY {
                return Err(FsError::InvalidData);
            }
            let chunk_off = pos + DISK_KEY_SIZE;
            if chunk_off + CHUNK_HEADER_SIZE > sys.len() {
                return Err(FsError::InvalidData);
            }
            let num_stripes = le16(sys, chunk_off + 44)?;
            let chunk_len = CHUNK_HEADER_SIZE
                + STRIPE_SIZE
                    .checked_mul(num_stripes as usize)
                    .ok_or(FsError::InvalidData)?;
            let chunk_end = chunk_off
                .checked_add(chunk_len)
                .ok_or(FsError::InvalidData)?;
            if chunk_end > sys.len() {
                return Err(FsError::InvalidData);
            }
            // key.offset is the logical start of the chunk.
            map.insert_chunk_item(key.offset, &sys[chunk_off..chunk_end])?;
            pos = chunk_end;
        }
        if map.is_empty() {
            return Err(FsError::InvalidData);
        }
        Ok(map)
    }
}
