//! Blocks a change stops referencing, freed only after the references are
//! off the disk.
//!
//! Without a journal, freeing a block before the inode or tree node that
//! maps it is written lets another file allocate it and write it while the
//! old mapping is still on disk; a crash then leaves two files sharing a
//! block. So a removal writes the trimmed nodes bottom-up, then the inode,
//! and only then frees (`release_deferred`). A crash in between leaves
//! blocks allocated that nothing maps, a leak e2fsck reclaims.
//!
//! The list keeps runs, so a large truncate costs one entry per extent (or
//! per contiguous span of a block map), not one per block, and the free
//! writes each group's bitmap and descriptor once per run.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::super::inode::Inode;
use super::{BitmapKind, Ext2Volume};

#[derive(Default)]
pub(crate) struct FreeList {
    runs: Vec<(u64, u64)>,
}

impl FreeList {
    pub(crate) fn push(&mut self, block: u64) {
        self.push_run(block, 1);
    }

    pub(crate) fn push_run(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        if let Some(last) = self.runs.last_mut() {
            if last.0 + last.1 == start {
                last.1 += len;
                return;
            }
        }
        self.runs.push((start, len));
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Write `inode` (no longer mapping anything in `list`), then free the
    /// list.
    pub(crate) async fn release_deferred(
        &self,
        inode_no: u32,
        inode: &Inode,
        list: FreeList,
    ) -> Result<(), FsError> {
        if list.is_empty() {
            return Ok(());
        }
        self.write_inode(inode_no, inode).await?;
        for (start, len) in list.runs {
            self.free_run(start, len).await?;
        }
        Ok(())
    }

    /// `ext4_free_blocks` for `len` blocks from `start`: one bitmap,
    /// descriptor and superblock update per group the run touches. A bit
    /// already clear is skipped, as [`Self::free_block`] skips it.
    pub(crate) async fn free_run(&self, start: u64, len: u64) -> Result<(), FsError> {
        let _allocation = self.allocation_lock.lock().await;
        let bpg = u64::from(self.superblock.blocks_per_group);
        let first_block = u64::from(self.superblock.first_data_block);
        let end = start
            .checked_add(len)
            .filter(|&end| start >= first_block && end <= self.superblock.total_blocks())
            .ok_or(FsError::Io(narf_block::BlockError::InvalidRange))?;
        let mut at = start;
        while at < end {
            let group = ((at - first_block) / bpg) as usize;
            let stop = end.min(first_block + (group as u64 + 1) * bpg);
            if group >= self.group_descs.len() {
                return Err(FsError::Io(narf_block::BlockError::InvalidRange));
            }
            if super::uninit::has_group_desc_csum(&self.superblock)
                && self.current_group_desc(group).await?.flags
                    & super::super::group_desc::BG_BLOCK_UNINIT
                    != 0
            {
                // Nothing was ever allocated there (Linux: "bit already
                // cleared", EFSCORRUPTED).
                return Err(FsError::Corrupted);
            }
            let bm_block = self.group_descs[group].block_bitmap;
            let mut buf = alloc::vec![0u8; self.block_size()];
            self.read_block(bm_block, &mut buf).await?;
            self.verify_bitmap(group, BitmapKind::Block, &buf).await?;
            let mut cleared = 0i64;
            for block in at..stop {
                let bit = ((block - first_block) % bpg) as usize;
                let mask = 1u8 << (bit % 8);
                if buf[bit / 8] & mask != 0 {
                    buf[bit / 8] &= !mask;
                    cleared += 1;
                }
            }
            if cleared != 0 {
                self.write_block(bm_block, &buf).await?;
                // Not reusable until the running journal transaction commits.
                self.hold_blocks(at, stop - at);
                self.update_group_desc(
                    group,
                    cleared,
                    0,
                    0,
                    Some((BitmapKind::Block, &buf)),
                    None,
                    0,
                )
                .await?;
                self.update_superblock_counters(cleared, 0).await?;
            }
            at = stop;
        }
        Ok(())
    }
}
