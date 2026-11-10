//! Incremental free-space-tree maintenance for [`super::commit_txn`].
//!
//! A commit used to read the whole free-space tree into one logical leaf,
//! edit it and write all of it back, so its cost followed the size of the
//! filesystem. Here a commit touches only the items its allocations and frees
//! reach, as Linux does (`btrfs_remove_from_free_space_tree` from
//! `alloc_reserved_extent`, `btrfs_add_to_free_space_tree` from
//! `do_free_extent_accounting`, both run from the delayed refs):
//!
//!  1. [`FstWindow`] fetches, from the committed tree, the few items around
//!     each range the transaction allocates or frees — the block group's
//!     `FREE_SPACE_INFO`, and the `FREE_SPACE_EXTENT` or `FREE_SPACE_BITMAP`
//!     items the range and its immediate neighbours live in;
//!  2. [`FstEdit`] applies the allocations and frees to a private copy of
//!     those items, in whichever form each block group already uses (extent
//!     items carved and merged, never across a block-group boundary; bitmap
//!     bits cleared and set, with `extent_count` adjusted from the bits on
//!     either side as `modify_free_space_bitmap` does), and
//!  3. reports the difference as key edits, which the caller path-COWs into
//!     the tree like any other.
//!
//! A block group is never converted between the two forms. Every operation
//! fails closed (`InvalidData`) when the tree disagrees with it — allocating
//! space the tree does not hold free, or freeing space it already does —
//! since writing either would record free space that is in use.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::{Edit, FREE_SPACE_USING_BITMAPS};
use crate::btree;
use crate::format::{self, BtrfsKey};
use crate::volume::BtrfsVolume;

/// The committed free-space-tree items a commit has looked at so far, and
/// what the tree the commit is building holds in their place.
///
/// The committed tree does not change while a commit computes, so what one
/// pass of recording the commit's blocks fetched stays valid for the next
/// and is not fetched again.
#[derive(Debug, Default)]
pub(super) struct FstWindow {
    /// Committed items, unmodified.
    items: BTreeMap<BtrfsKey, Vec<u8>>,
    /// The same keys as the tree in progress holds them: the committed
    /// items, with every edit [`Self::take_edits`] has handed out applied.
    applied: BTreeMap<BtrfsKey, Vec<u8>>,
    /// Key spans already fetched, `first -> (last, from_start, to_end)`:
    /// every committed item with a key in `[first, last]` is in `items`.
    /// `from_start` / `to_end` say that nothing precedes `first` / follows
    /// `last` in the tree.
    loaded: BTreeMap<BtrfsKey, (BtrfsKey, bool, bool)>,
}

impl FstWindow {
    /// Test-only: a window that already holds a whole tree's `items`.
    #[cfg(feature = "kernel-test")]
    pub(super) fn __test_whole_tree(items: BTreeMap<BtrfsKey, Vec<u8>>) -> Self {
        let mut loaded = BTreeMap::new();
        loaded.insert(
            BtrfsKey::new(0, 0, 0),
            (BtrfsKey::new(u64::MAX, u8::MAX, u64::MAX), true, true),
        );
        Self {
            applied: items.clone(),
            items,
            loaded,
        }
    }

    /// Remember one committed item. Every fetched span is complete, so an
    /// item seen for the first time lies outside all of them and no edit can
    /// have put anything at its key: a tree that disagrees is corrupt.
    fn add(&mut self, key: BtrfsKey, body: Vec<u8>) -> Result<(), FsError> {
        if self.items.contains_key(&key) {
            return Ok(());
        }
        if self.applied.insert(key, body.clone()).is_some() {
            return Err(FsError::InvalidData);
        }
        self.items.insert(key, body);
        Ok(())
    }

    /// Fetch every committed item with a key in `[lo, hi]`, the last item
    /// before `lo` and the first item after `hi`.
    ///
    /// Whole leaves are fetched and remembered, so the allocations and frees
    /// of one commit — which cluster — cost one descent per leaf they reach,
    /// not one per range.
    async fn ensure<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        root: u64,
        lo: BtrfsKey,
        hi: BtrfsKey,
    ) -> Result<(), FsError> {
        // Covered when a fetched span holds an item strictly before `lo`
        // (so the last item before `lo` is in it) and one strictly after
        // `hi`, or reaches the corresponding end of the tree.
        if let Some((&first, &(last, from_start, to_end))) = self.loaded.range(..=lo).next_back() {
            if (first < lo || from_start) && (hi < last || to_end) {
                return Ok(());
            }
        }
        let mut cursor = btree::Cursor::seek(vol, root, &lo).await?;
        let mut span: Option<(BtrfsKey, bool)> = None;
        let mut last = lo;
        let mut to_end = true;
        while let Some((items, slot)) = cursor.leaf()? {
            if span.is_none() {
                // The item before `lo` is in this leaf unless the cursor
                // sits on its first item.
                span = Some(match items.first() {
                    Some((first, _)) if slot > 0 => (*first, false),
                    _ => match btree::last_before(vol, root, &lo).await? {
                        Some((key, body)) => {
                            self.add(key, body)?;
                            (key, false)
                        }
                        None => (lo, true),
                    },
                });
            }
            if let Some((key, _)) = items.last() {
                last = *key;
            }
            for (key, body) in items {
                self.add(key, body)?;
            }
            if last > hi {
                to_end = false;
                break;
            }
            cursor.next_leaf().await?;
        }
        let (first, from_start) = match span {
            Some(span) => span,
            // Nothing at or after `lo`: the tree's last item precedes it.
            None => match btree::last_before(vol, root, &lo).await? {
                Some((key, body)) => {
                    self.add(key, body)?;
                    (key, false)
                }
                None => (lo, true),
            },
        };
        self.loaded
            .insert(first, (last.max(hi), from_start, to_end));
        Ok(())
    }

    /// Fetch what [`FstEdit`] needs to mark `[start, start + len)` used or
    /// free in the block group `[bg_start, bg_start + bg_len)`: the group's
    /// info item, every item keyed inside the range widened by one sector on
    /// each side, and the nearest item on either side of that.
    pub(super) async fn prepare<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        root: u64,
        (bg_start, bg_len): (u64, u64),
        start: u64,
        len: u64,
    ) -> Result<(), FsError> {
        let info = BtrfsKey::new(bg_start, format::FREE_SPACE_INFO_KEY, bg_len);
        self.ensure(vol, root, info, info).await?;
        let sectorsize = u64::from(vol.sectorsize());
        let lo = start.saturating_sub(sectorsize).max(bg_start);
        let hi = start.checked_add(len).ok_or(FsError::InvalidData)?;
        self.ensure(
            vol,
            root,
            BtrfsKey::new(lo, 0, 0),
            BtrfsKey::new(hi, u8::MAX, u64::MAX),
        )
        .await
    }

    /// Start editing: a private copy of everything fetched, as committed.
    pub(super) fn edit(&self, sectorsize: u64) -> FstEdit {
        FstEdit {
            items: self.items.clone(),
            sectorsize,
        }
    }

    /// The key edits that take the tree in progress from what it holds — the
    /// committed items, with every earlier call's edits applied — to
    /// `desired` ([`FstEdit::into_items`] of an edit started from this
    /// window as it is now), which it holds from here on.
    pub(super) fn take_edits(&mut self, desired: BTreeMap<BtrfsKey, Vec<u8>>) -> Vec<Edit> {
        let mut edits = Vec::new();
        for key in self.applied.keys() {
            if !desired.contains_key(key) {
                edits.push(Edit::Delete(*key));
            }
        }
        for (key, body) in &desired {
            if self.applied.get(key) != Some(body) {
                edits.push(Edit::Upsert(*key, body.clone()));
            }
        }
        self.applied = desired;
        edits
    }
}

/// The free-space tree's items as a transaction's allocations and frees leave
/// them, over the committed items an [`FstWindow`] fetched. Every range passed to [`Self::mark_used`] /
/// [`Self::mark_free`] must have been [`FstWindow::prepare`]d.
#[derive(Debug)]
pub(super) struct FstEdit {
    items: BTreeMap<BtrfsKey, Vec<u8>>,
    sectorsize: u64,
}

fn extent_key(start: u64, len: u64) -> BtrfsKey {
    BtrfsKey::new(start, format::FREE_SPACE_EXTENT_KEY, len)
}

impl FstEdit {
    /// Add an empty block group: its info item and one free extent spanning
    /// it, in extent form (Linux `add_new_free_space_info` +
    /// `add_block_group_free_space`).
    pub(super) fn add_block_group(&mut self, start: u64, len: u64) -> Result<(), FsError> {
        let info_key = BtrfsKey::new(start, format::FREE_SPACE_INFO_KEY, len);
        if self.items.contains_key(&info_key) {
            return Err(FsError::InvalidData);
        }
        let mut info = alloc::vec![0u8; 8];
        info[0..4].copy_from_slice(&1u32.to_le_bytes());
        self.items.insert(info_key, info);
        self.items.insert(extent_key(start, len), Vec::new());
        Ok(())
    }

    /// The group's `FREE_SPACE_INFO` body.
    fn info(&self, bg_start: u64, bg_len: u64) -> Result<&[u8], FsError> {
        let body = self
            .items
            .get(&BtrfsKey::new(
                bg_start,
                format::FREE_SPACE_INFO_KEY,
                bg_len,
            ))
            .ok_or(FsError::InvalidData)?;
        if body.len() < 8 {
            return Err(FsError::InvalidData);
        }
        Ok(body)
    }

    fn uses_bitmaps(&self, bg_start: u64, bg_len: u64) -> Result<bool, FsError> {
        let flags = format::le32(self.info(bg_start, bg_len)?, 4)?;
        Ok(flags & FREE_SPACE_USING_BITMAPS != 0)
    }

    /// Adjust the group's `extent_count` by `delta`
    /// (`update_free_space_extent_count`, without the conversion).
    fn adjust_count(&mut self, bg_start: u64, bg_len: u64, delta: i64) -> Result<(), FsError> {
        if delta == 0 {
            return Ok(());
        }
        let count = i64::from(format::le32(self.info(bg_start, bg_len)?, 0)?) + delta;
        let count = u32::try_from(count).map_err(|_| FsError::InvalidData)?;
        let body = self
            .items
            .get_mut(&BtrfsKey::new(
                bg_start,
                format::FREE_SPACE_INFO_KEY,
                bg_len,
            ))
            .ok_or(FsError::InvalidData)?;
        body[0..4].copy_from_slice(&count.to_le_bytes());
        Ok(())
    }

    /// The bitmap item covering `addr`, as its key.
    fn bitmap_at(&self, addr: u64) -> Result<BtrfsKey, FsError> {
        // The last key at/below addr must be the containing bitmap. Info
        // sorts before a bitmap with the same start; other item kinds or
        // gaps are errors, never an invitation to alter a neighbouring map.
        let (key, body) = self
            .items
            .range(..=BtrfsKey::new(addr, u8::MAX, u64::MAX))
            .next_back()
            .ok_or(FsError::InvalidData)?;
        let ss = self.sectorsize;
        let end = key
            .objectid
            .checked_add(key.offset)
            .ok_or(FsError::InvalidData)?;
        if key.item_type != format::FREE_SPACE_BITMAP_KEY
            || addr < key.objectid
            || addr >= end
            || key.objectid % ss != 0
            || key.offset % ss != 0
            || key.offset / ss > body.len() as u64 * 8
        {
            return Err(FsError::InvalidData);
        }
        Ok(*key)
    }

    /// Whether the sector at `addr` is free in its bitmap
    /// (`btrfs_free_space_test_bit`).
    fn test_bit(&self, addr: u64) -> Result<bool, FsError> {
        let key = self.bitmap_at(addr)?;
        let bit = ((addr - key.objectid) / self.sectorsize) as usize;
        let body = self.items.get(&key).ok_or(FsError::InvalidData)?;
        Ok(body[bit / 8] & (1u8 << (bit % 8)) != 0)
    }

    /// Set (`free`) or clear the bit of every sector in `[start, end)`,
    /// which must all be in the opposite state, and adjust the group's
    /// `extent_count` from the bits on either side (Linux
    /// `modify_free_space_bitmap`). Bits are little-endian: bit `i` of a
    /// bitmap keyed at `s` is the sector at `s + i * sectorsize`.
    fn modify_bitmap(
        &mut self,
        (bg_start, bg_len): (u64, u64),
        start: u64,
        end: u64,
        free: bool,
    ) -> Result<(), FsError> {
        let ss = self.sectorsize;
        if start % ss != 0 || end % ss != 0 {
            return Err(FsError::InvalidData);
        }
        let bg_end = bg_start + bg_len;
        let prev_set = start > bg_start && self.test_bit(start - ss)?;
        let next_set = end < bg_end && self.test_bit(end)?;
        let mut addr = start;
        while addr < end {
            let key = self.bitmap_at(addr)?;
            let part_end = end.min(key.objectid + key.offset);
            let first = ((addr - key.objectid) / ss) as usize;
            let limit = ((part_end - key.objectid) / ss) as usize;
            let body = self.items.get_mut(&key).ok_or(FsError::InvalidData)?;
            for bit in first..limit {
                let mask = 1u8 << (bit % 8);
                // Allocating space the bitmap holds used, or freeing space it
                // holds free, means the tree and the transaction disagree.
                if (body[bit / 8] & mask != 0) == free {
                    return Err(FsError::InvalidData);
                }
                if free {
                    body[bit / 8] |= mask;
                } else {
                    body[bit / 8] &= !mask;
                }
            }
            addr = part_end;
        }
        // Allocating out of a free run removes it, less a leftover on either
        // side; freeing adds a run, less a merge with either side.
        let neighbours = i64::from(prev_set) + i64::from(next_set);
        let delta = if free { 1 - neighbours } else { neighbours - 1 };
        self.adjust_count(bg_start, bg_len, delta)
    }

    /// Mark `[start, start + len)` USED. In a bitmap block group this clears
    /// the range's bits; in an extent-mode one it carves the range out of
    /// the `FREE_SPACE_EXTENT` that contains it, leaving up to two remainders
    /// (Linux `remove_free_space_extent`).
    pub(super) fn mark_used(
        &mut self,
        (bg_start, bg_len): (u64, u64),
        start: u64,
        len: u64,
    ) -> Result<(), FsError> {
        let end = start.checked_add(len).ok_or(FsError::InvalidData)?;
        if len == 0 || start < bg_start || end > bg_start + bg_len {
            return Err(FsError::InvalidData);
        }
        if self.uses_bitmaps(bg_start, bg_len)? {
            return self.modify_bitmap((bg_start, bg_len), start, end, false);
        }
        // The free extent holding the range is the last one keyed at or
        // below its start.
        let found = self
            .items
            .range(..=extent_key(start, u64::MAX))
            .next_back()
            .map(|(key, _)| *key)
            .filter(|key| {
                key.item_type == format::FREE_SPACE_EXTENT_KEY
                    && key.objectid >= bg_start
                    && end <= key.objectid.saturating_add(key.offset)
            })
            .ok_or(FsError::InvalidData)?;
        let (free_start, free_end) = (found.objectid, found.objectid + found.offset);
        self.items.remove(&found);
        let mut added = 0i64;
        if free_start < start {
            self.items
                .insert(extent_key(free_start, start - free_start), Vec::new());
            added += 1;
        }
        if end < free_end {
            self.items
                .insert(extent_key(end, free_end - end), Vec::new());
            added += 1;
        }
        self.adjust_count(bg_start, bg_len, added - 1)
    }

    /// Mark `[start, start + len)` FREE: add it back, merging with an
    /// immediately adjacent free extent on either side — but only within the
    /// same block group (free extents never span a block-group boundary, so
    /// a neighbour in an adjacent group is not merged; Linux
    /// `add_free_space_extent`).
    pub(super) fn mark_free(
        &mut self,
        (bg_start, bg_len): (u64, u64),
        start: u64,
        len: u64,
    ) -> Result<(), FsError> {
        let end = start.checked_add(len).ok_or(FsError::InvalidData)?;
        let bg_end = bg_start + bg_len;
        if len == 0 || start < bg_start || end > bg_end {
            return Err(FsError::InvalidData);
        }
        if self.uses_bitmaps(bg_start, bg_len)? {
            return self.modify_bitmap((bg_start, bg_len), start, end, true);
        }
        // No free extent may begin inside the range...
        if self
            .items
            .range(extent_key(start, 0)..extent_key(end, 0))
            .any(|(key, _)| key.item_type == format::FREE_SPACE_EXTENT_KEY)
        {
            return Err(FsError::InvalidData);
        }
        let (mut new_start, mut new_end) = (start, end);
        let mut removed = 0i64;
        // ...nor may the one before it reach into it. One ending exactly at
        // `start` is the left neighbour.
        let left = self
            .items
            .range(..extent_key(start, 0))
            .next_back()
            .map(|(key, _)| *key)
            .filter(|key| {
                key.item_type == format::FREE_SPACE_EXTENT_KEY && key.objectid >= bg_start
            });
        if let Some(key) = left {
            let left_end = key.objectid.saturating_add(key.offset);
            if left_end > start {
                return Err(FsError::InvalidData);
            }
            if left_end == start {
                new_start = key.objectid;
                self.items.remove(&key);
                removed += 1;
            }
        }
        if end < bg_end {
            let right = self
                .items
                .range(extent_key(end, 0)..=extent_key(end, u64::MAX))
                .next()
                .map(|(key, _)| *key);
            if let Some(key) = right {
                new_end = key.objectid.saturating_add(key.offset);
                if new_end > bg_end {
                    return Err(FsError::InvalidData);
                }
                self.items.remove(&key);
                removed += 1;
            }
        }
        self.items
            .insert(extent_key(new_start, new_end - new_start), Vec::new());
        self.adjust_count(bg_start, bg_len, 1 - removed)
    }

    /// The edited items: every fetched item the edits left, and every item
    /// they added.
    pub(super) fn into_items(self) -> BTreeMap<BtrfsKey, Vec<u8>> {
        self.items
    }
}
