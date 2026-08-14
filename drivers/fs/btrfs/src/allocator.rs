//! Simple append allocator for the COW write path.
//!
//! Genuine free-space management (the extent/free-space trees) is out of scope.
//! Instead this hands out logical addresses strictly **above** the extent tree's
//! high-water mark — the end of the highest recorded allocation — so a new
//! extent or tree node can never overlap live data. Freed space is never reused
//! and no new chunk is allocated: if the bump cursor would leave the covering
//! chunk, allocation fails with `NoSpace`.

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree::Cursor;
use crate::format::{self, BtrfsKey};
use crate::volume::BtrfsVolume;

/// Round `x` up to a multiple of `align` (a power of two).
fn align_up(x: u64, align: u64) -> u64 {
    (x + (align - 1)) & !(align - 1)
}

/// Highest byte end recorded in the extent tree (`bytenr + length` over all
/// `EXTENT_ITEM` / `METADATA_ITEM` items).
pub async fn extent_high_water<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    extent_tree: u64,
) -> Result<u64, FsError> {
    let nodesize = vol.nodesize() as u64;
    let mut cursor = Cursor::seek(vol, extent_tree, &BtrfsKey::new(0, 0, 0)).await?;
    let mut high = 0u64;
    while let Some((key, _)) = cursor.current()? {
        let end = match key.item_type {
            format::EXTENT_ITEM_KEY => key.objectid.saturating_add(key.offset),
            format::METADATA_ITEM_KEY => key.objectid.saturating_add(nodesize),
            _ => 0,
        };
        high = high.max(end);
        cursor.advance().await?;
    }
    if high == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(high)
}

/// Bump allocator over logical space past the extent-tree high-water mark.
#[derive(Debug)]
pub struct BumpAllocator {
    next: u64,
}

impl BumpAllocator {
    pub fn new(high_water: u64) -> Self {
        BumpAllocator { next: high_water }
    }

    /// The next logical address the allocator would hand out. Persisted across
    /// writes so a later write doesn't re-hand-out space the extent tree hasn't
    /// been told about yet.
    pub fn next(&self) -> u64 {
        self.next
    }

    /// Allocate `len` bytes aligned to `align`, verifying the whole range maps
    /// contiguously inside one existing chunk (else `NoSpace`).
    fn alloc<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        len: u64,
        align: u64,
    ) -> Result<u64, FsError> {
        let start = align_up(self.next, align);
        let size = align_up(len, align).max(align);
        // Both ends must map, and physically contiguously — i.e. within one chunk.
        // An unmapped address (the cursor ran past the last chunk) is out of
        // space, not a lookup error, so it must surface as `NoSpace` — that is
        // what lets a caller grow the filesystem and retry.
        let phys_start = vol.map_logical(start).map_err(|_| FsError::NoSpace)?;
        let phys_end = vol
            .map_logical(start + size - 1)
            .map_err(|_| FsError::NoSpace)?;
        if phys_end != phys_start + size - 1 {
            return Err(FsError::NoSpace);
        }
        self.next = start + size;
        Ok(start)
    }

    /// Allocate one tree node (`nodesize`, node-aligned).
    pub fn alloc_node<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
    ) -> Result<u64, FsError> {
        let n = vol.nodesize() as u64;
        self.alloc(vol, n, n)
    }

    /// Allocate a data extent of `len` bytes (sector-aligned).
    pub fn alloc_data<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        len: u64,
    ) -> Result<u64, FsError> {
        let s = u64::from(vol.sectorsize());
        self.alloc(vol, len, s)
    }
}
