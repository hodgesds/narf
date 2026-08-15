//! Chunk tree: logical → physical address mapping.
//!
//! Every btrfs address above the superblock is *logical*; the chunk tree
//! translates it to a `(devid, physical)` location on a device. The superblock
//! embeds a `sys_chunk_array` of `(disk_key, btrfs_chunk)` pairs that map just
//! enough of the address space to read the chunk tree itself; walking the chunk
//! tree then yields every remaining chunk. This module parses `btrfs_chunk`
//! items and maintains the resulting map.
//!
//! The map retains complete stripe geometry for SINGLE, DUP, RAID0, RAID1,
//! RAID10, RAID5 and RAID6 chunks. I/O routing is deliberately separate: this
//! module answers which `(devid, physical)` locations cover a logical byte and
//! how far that mapping stays contiguous.

use alloc::vec::Vec;

use narf_filesystem::FsError;

use crate::format::{
    le16, le64, BtrfsKey, BLOCK_GROUP_DUP, BLOCK_GROUP_PROFILE_MASK, BLOCK_GROUP_RAID0,
    BLOCK_GROUP_RAID1, BLOCK_GROUP_RAID10, BLOCK_GROUP_RAID5, BLOCK_GROUP_RAID6, CHUNK_ITEM_KEY,
    DISK_KEY_SIZE,
};

/// On-disk `struct btrfs_chunk` header size (fields before the first stripe).
const CHUNK_HEADER_SIZE: usize = 48;
/// On-disk `struct btrfs_stripe` size (devid + offset + 16-byte uuid).
const STRIPE_SIZE: usize = 32;

/// Supported on-disk block-group profiles.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChunkProfile {
    Single,
    Dup,
    Raid0,
    Raid1,
    Raid10,
    Raid5,
    Raid6,
}

/// One physical stripe described by a chunk item.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChunkStripe {
    pub devid: u64,
    pub physical: u64,
}

/// One resolved physical location for a logical byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StripeLocation {
    pub devid: u64,
    pub physical: u64,
}

/// A complete RAID5/6 full-stripe set in data/P/Q order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raid56Set {
    pub logical_start: u64,
    pub stripe_len: u64,
    pub data: Vec<StripeLocation>,
    pub parity: Vec<StripeLocation>,
}

/// One resolved chunk and its complete stripe geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkMapEntry {
    pub logical_start: u64,
    pub length: u64,
    pub stripe_len: u64,
    pub profile: ChunkProfile,
    /// Number of adjacent mirrors in each RAID10 stripe group.
    pub sub_stripes: u16,
    pub stripes: Vec<ChunkStripe>,
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
            stripe_len: length,
            profile: ChunkProfile::Single,
            sub_stripes: 1,
            stripes: alloc::vec![ChunkStripe { devid, physical }],
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
        self.map_logical_stripes(logical).and_then(|stripes| {
            stripes
                .first()
                .map(|s| s.physical)
                .ok_or(FsError::InvalidData)
        })
    }

    /// Translate a logical address to its primary and optional DUP physical
    /// copy. Both offsets include the logical offset within the chunk.
    pub fn map_logical_copies(&self, logical: u64) -> Result<(u64, Option<u64>), FsError> {
        let stripes = self.map_logical_stripes(logical)?;
        let primary = stripes.first().ok_or(FsError::InvalidData)?.physical;
        Ok((primary, stripes.get(1).map(|s| s.physical)))
    }

    /// Resolve all direct copies of one logical byte. RAID5/6 return the data
    /// stripe only; callers needing degraded reconstruction use
    /// [`Self::raid56_set`].
    pub fn map_logical_stripes(&self, logical: u64) -> Result<Vec<StripeLocation>, FsError> {
        let e = self.entry(logical)?;
        let delta = logical - e.logical_start;
        let stripe_nr = delta / e.stripe_len;
        let within = delta % e.stripe_len;
        let at = |stripe: ChunkStripe, device_stripe: u64| StripeLocation {
            devid: stripe.devid,
            physical: stripe.physical + device_stripe * e.stripe_len + within,
        };
        let locations = match e.profile {
            ChunkProfile::Single | ChunkProfile::Dup | ChunkProfile::Raid1 => e
                .stripes
                .iter()
                .copied()
                .map(|stripe| StripeLocation {
                    devid: stripe.devid,
                    physical: stripe.physical + delta,
                })
                .collect(),
            ChunkProfile::Raid0 => {
                let count = e.stripes.len() as u64;
                alloc::vec![at(
                    e.stripes[(stripe_nr % count) as usize],
                    stripe_nr / count
                )]
            }
            ChunkProfile::Raid10 => {
                let copies = u64::from(e.sub_stripes);
                let data_stripes = e.stripes.len() as u64 / copies;
                let first = (stripe_nr % data_stripes) * copies;
                let device_stripe = stripe_nr / data_stripes;
                (0..copies)
                    .map(|copy| at(e.stripes[(first + copy) as usize], device_stripe))
                    .collect()
            }
            ChunkProfile::Raid5 | ChunkProfile::Raid6 => {
                let parity = if e.profile == ChunkProfile::Raid5 {
                    1
                } else {
                    2
                };
                let data_stripes = e.stripes.len() as u64 - parity;
                let full_stripe = stripe_nr / data_stripes;
                let data_index = stripe_nr % data_stripes;
                let stripe_index = (full_stripe + data_index) % e.stripes.len() as u64;
                alloc::vec![at(e.stripes[stripe_index as usize], full_stripe)]
            }
        };
        Ok(locations)
    }

    /// Maximum bytes from `logical` that retain the returned physical mapping.
    /// Mirrored profiles are linear for the complete chunk; striped profiles
    /// stop at the next stripe boundary.
    pub fn max_contiguous(&self, logical: u64) -> Result<u64, FsError> {
        let e = self.entry(logical)?;
        let delta = logical - e.logical_start;
        let chunk_left = e.length - delta;
        match e.profile {
            ChunkProfile::Single | ChunkProfile::Dup | ChunkProfile::Raid1 => Ok(chunk_left),
            _ => Ok(chunk_left.min(e.stripe_len - delta % e.stripe_len)),
        }
    }

    /// Bytes remaining in the chunk that contains `logical`, independent of
    /// stripe boundaries. Allocators use this to keep one extent inside one
    /// block group while the I/O layer splits it across member stripes.
    pub fn chunk_remaining(&self, logical: u64) -> Result<u64, FsError> {
        let e = self.entry(logical)?;
        Ok(e.length - (logical - e.logical_start))
    }

    /// Resolve the complete RAID5/6 stripe set containing `logical`. Physical
    /// stripes are returned in Linux's data-then-P-then-Q order after applying
    /// the per-full-stripe rotation.
    pub fn raid56_set(&self, logical: u64) -> Result<Raid56Set, FsError> {
        let e = self.entry(logical)?;
        let parity_count = match e.profile {
            ChunkProfile::Raid5 => 1usize,
            ChunkProfile::Raid6 => 2usize,
            _ => return Err(FsError::Unsupported),
        };
        let data_count = e.stripes.len() - parity_count;
        let full_logical_len = e
            .stripe_len
            .checked_mul(data_count as u64)
            .ok_or(FsError::InvalidData)?;
        let delta = logical - e.logical_start;
        let full_stripe = delta / full_logical_len;
        let logical_start = e.logical_start + full_stripe * full_logical_len;
        let mut ordered = Vec::with_capacity(e.stripes.len());
        for i in 0..e.stripes.len() {
            let stripe = e.stripes[(i as u64 + full_stripe) as usize % e.stripes.len()];
            ordered.push(StripeLocation {
                devid: stripe.devid,
                physical: stripe.physical + full_stripe * e.stripe_len,
            });
        }
        let parity = ordered.split_off(data_count);
        Ok(Raid56Set {
            logical_start,
            stripe_len: e.stripe_len,
            data: ordered,
            parity,
        })
    }

    fn entry(&self, logical: u64) -> Result<&ChunkMapEntry, FsError> {
        self.entries
            .iter()
            .find(|e| {
                logical >= e.logical_start && logical < e.logical_start.saturating_add(e.length)
            })
            .ok_or(FsError::NotFound)
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

        let profile = chunk_type & BLOCK_GROUP_PROFILE_MASK;
        let sub_stripes = le16(chunk, 46)?;
        let profile = match profile {
            0 if num_stripes == 1 => ChunkProfile::Single,
            0 => return Err(FsError::InvalidData),
            BLOCK_GROUP_DUP if num_stripes == 2 => ChunkProfile::Dup,
            BLOCK_GROUP_DUP => return Err(FsError::InvalidData),
            BLOCK_GROUP_RAID0 if num_stripes >= 2 => ChunkProfile::Raid0,
            BLOCK_GROUP_RAID0 => return Err(FsError::InvalidData),
            BLOCK_GROUP_RAID1 if num_stripes >= 2 => ChunkProfile::Raid1,
            BLOCK_GROUP_RAID1 => return Err(FsError::InvalidData),
            BLOCK_GROUP_RAID10
                if num_stripes >= 4 && sub_stripes >= 2 && num_stripes % sub_stripes == 0 =>
            {
                ChunkProfile::Raid10
            }
            BLOCK_GROUP_RAID10 => return Err(FsError::InvalidData),
            BLOCK_GROUP_RAID5 if num_stripes >= 2 => ChunkProfile::Raid5,
            BLOCK_GROUP_RAID5 => return Err(FsError::InvalidData),
            BLOCK_GROUP_RAID6 if num_stripes >= 3 => ChunkProfile::Raid6,
            BLOCK_GROUP_RAID6 => return Err(FsError::InvalidData),
            _ => return Err(FsError::Unsupported),
        };

        let stripe_len = le64(chunk, 16)?;
        if stripe_len == 0 || !stripe_len.is_power_of_two() {
            return Err(FsError::InvalidData);
        }
        let data_stripes = match profile {
            ChunkProfile::Raid0 => usize::from(num_stripes),
            ChunkProfile::Raid10 => usize::from(num_stripes / sub_stripes),
            ChunkProfile::Raid5 => usize::from(num_stripes - 1),
            ChunkProfile::Raid6 => usize::from(num_stripes - 2),
            _ => 1,
        };
        let stripe_set_len = stripe_len
            .checked_mul(data_stripes as u64)
            .ok_or(FsError::InvalidData)?;
        if matches!(
            profile,
            ChunkProfile::Raid0 | ChunkProfile::Raid10 | ChunkProfile::Raid5 | ChunkProfile::Raid6
        ) && length % stripe_set_len != 0
        {
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

        let mut stripes = Vec::with_capacity(num_stripes as usize);
        for i in 0..usize::from(num_stripes) {
            let at = CHUNK_HEADER_SIZE + i * STRIPE_SIZE;
            stripes.push(ChunkStripe {
                devid: le64(chunk, at)?,
                physical: le64(chunk, at + 8)?,
            });
        }
        if profile == ChunkProfile::Dup && stripes[0].devid != stripes[1].devid {
            return Err(FsError::InvalidData);
        }

        self.entries.push(ChunkMapEntry {
            logical_start,
            length,
            stripe_len,
            profile,
            sub_stripes,
            stripes,
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
