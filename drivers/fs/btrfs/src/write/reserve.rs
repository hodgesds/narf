//! Metadata reservation for the batched transaction.
//!
//! A commit that runs out of metadata space can only abort, and then every
//! operation the batch already acknowledged is lost. So space is reserved
//! the way Linux reserves it — before an operation is accepted, never inside
//! the commit — and an operation whose reservation does not fit is the one
//! that waits for reclaim or gets `ENOSPC`
//! (`btrfs_start_transaction` → `btrfs_block_rsv_add` →
//! `btrfs_reserve_metadata_bytes`, with flushing at reservation time).
//!
//! # What a commit allocates
//!
//! `commit_txn` allocates metadata only by path-COWing the csum, extent,
//! block-group and free-space trees (and re-packing the small root tree).
//! Path COW of `E` key edits into a tree of height `H` allocates at most:
//!
//!  * one block per level per edit to replace the committed path (`E * H`,
//!    reached only when no two edits share a block), plus
//!  * the blocks its inserts add by splitting — a touched leaf is re-tiled
//!    once, so it gains at most one leaf per leaf's worth of inserted bytes
//!    plus one remainder, and so on up the path: no more than another
//!    `E * H` for edits that insert.
//!
//! That is Linux's unit: `btrfs_calc_insert_metadata_size` is
//! `nodesize * BTRFS_MAX_LEVEL * 2` per inserted item and
//! `btrfs_calc_metadata_size` `nodesize * BTRFS_MAX_LEVEL` per modified one;
//! here the tree's actual height replaces `BTRFS_MAX_LEVEL`, since the bound
//! is recomputed for every operation against the trees as they are.
//!
//! The edits a batch's commit makes are known from what the batch holds
//! ([`CommitLoad`]): `D` new data extents, `X` dropped and `A` added data
//! references, `P` new and `F` freed fs-tree blocks.
//!
//! | tree | edits | blocks |
//! |---|---|---|
//! | csum | one item per new extent; a released extent deletes its item and re-inserts up to two neighbours' remainders | `2 * H * (D + 3X)` |
//! | extent | an item per new extent, new block and snapshot-COW reference `R` (insert), per dropped/added reference and freed block (modify/delete) | `2 * H * (D + P + R) + H * (X + A + F)` |
//! | block group | one item per group touched, at most one per range | `H * min(groups, D + X + P + F)` |
//! | free space | per allocated or freed range: its extent/bitmap items, adjacent keys in one leaf (carve or merge, may split); and its group's info item, rewritten in place, one per group touched | `2 * H * (D + X + P + F) + H * min(groups, D + X + P + F)` |
//!
//! Their sum is the batch's *first-order* need ([`ReserveGeometry::first_order`]).
//! (One case it prices short: in a bitmap block group a range longer than a
//! bitmap item covers — 8 MiB at 4 KiB sectors — flips bits in several
//! adjacent items, which can reach one more leaf per leaf's worth of
//! bitmaps. Nothing is inserted, so that is one path, and it comes out of
//! the doubling below.)
//!
//! # The commit's own blocks
//!
//! Those blocks are themselves metadata allocations: each needs an extent
//! item and leaves free space, and each committed block they replace is
//! freed — more edits to the extent, block-group and free-space trees, whose
//! blocks need recording in turn (the commit's recording passes; Linux's
//! delayed refs run from `btrfs_run_delayed_refs` until none remain). Applying the
//! per-edit bound to that closure does not converge: it prices every record
//! as landing in a leaf nothing else touches, which the allocator — handing
//! out neighbouring addresses — does not produce. Linux does not reserve for
//! it per operation either. It keeps a **global reserve** no ordinary
//! reservation may use, sized from the trees the commit-critical work
//! rewrites (`btrfs_update_global_block_rsv`: the bytes used by the root,
//! extent, csum and free-space trees, at least a few items' worth, at most
//! 512 MiB), and relies on it for whatever runs inside the commit.
//!
//! This reserve is the same, in the same two parts:
//!
//!  * a batch reserves **twice** its first-order need — the second share for
//!    the first level of the closure, recording the first-order blocks;
//!  * [`ReserveGeometry::global`] is held back on top: at least
//!    [`GLOBAL_FLOOR_BLOCKS`] (the root tree's re-pack and the tail of the
//!    closure of a small commit), and otherwise the recorded size of the
//!    extent, csum, block-group and free-space trees, capped at 512 MiB and
//!    at an eighth of the metadata space (Linux reaches the same effect on a
//!    small filesystem by over-committing against the reserve; this driver
//!    never over-commits).
//!
//! The first-order share is a bound; the closure allowance and the global
//! reserve are sized, not proven, exactly as in Linux. A commit that still
//! finds no space fails without writing a superblock and the transaction
//! aborts — the last-resort net, unchanged.
//!
//! # Growing metadata ahead of need
//!
//! Committing the open batch always makes a refused operation fit again
//! while the global reserve itself fits, so a filesystem whose free metadata
//! is only a little more than the reserve would never reach the chunk
//! allocation: it would run on short batches and commit constantly. Linux
//! flushes `ALLOC_CHUNK` before `COMMIT_TRANS` and allocates when the space
//! is past 80% in use, reserve included ([`should_alloc_chunk`]). A batch
//! here must close before a chunk can be allocated, so the order is the
//! other way round, but the rule is the same: after the commit a refusal
//! forced, a METADATA chunk is allocated if the space is past that
//! threshold, and only then is the operation retried. A device with no room
//! for the chunk is not an error at this point; the retry decides.
//!
//! # Unlink
//!
//! An operation that only releases space must not be refused for lack of it,
//! or a full filesystem could never be emptied. Linux lets `unlink`, `rmdir`
//! and inode eviction fall back to the global reserve
//! (`btrfs_start_transaction_fallback_global_rsv`, `evict_refill_and_join`).
//! Here such an operation is admitted while the batch's first-order need
//! still fits, and the batch is then committed at once, so the reserve it
//! borrowed is back before anything else is accepted.

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::block_group::{self, BgHome};
use crate::format;
use crate::roots;
use crate::volume::BtrfsVolume;

/// The least the global reserve holds, in tree blocks.
pub(crate) const GLOBAL_FLOOR_BLOCKS: u64 = 256;
/// `SZ_512M`: the most the global reserve holds
/// (`btrfs_update_global_block_rsv`).
const GLOBAL_MAX_BYTES: u64 = 512 << 20;

/// Linux `should_alloc_chunk` (`CHUNK_ALLOC_NO_FORCE`): a space is due
/// another chunk once what it has in use — here the allocated metadata plus
/// the global reserve, which Linux counts through `bytes_may_use` — comes
/// within 2 MiB of 80% of its size.
pub(crate) fn should_alloc_chunk(used: u64, total: u64) -> bool {
    used.saturating_add(2 << 20) >= total / 100 * 80 + total % 100 * 80 / 100
}

/// What a batch's commit has to record, counted from the batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommitLoad {
    /// Data extents born in the batch.
    pub(crate) new_data: u64,
    /// Data references dropped / added by the batch.
    pub(crate) dropped_data: u64,
    pub(crate) added_data: u64,
    /// Fs-tree blocks the batch wrote / freed.
    pub(crate) new_meta: u64,
    pub(crate) freed_meta: u64,
    /// Extent-tree items rewritten by snapshot-aware COW of shared fs-tree
    /// blocks (Linux `update_ref_for_cow`: a reference per child).
    pub(crate) ref_items: u64,
}

/// The shape of the trees a commit rewrites, sampled when a batch opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReserveGeometry {
    /// Tree heights (levels, a single leaf being 1).
    csum: u64,
    extent: u64,
    block_group: u64,
    free_space: u64,
    /// Block groups on the filesystem.
    groups: u64,
    /// The global reserve, in tree blocks.
    global: u64,
}

impl ReserveGeometry {
    /// Sample the committed trees. `groups` and `metadata_bytes` describe
    /// the block groups (their number, and the bytes in METADATA ones).
    pub(crate) async fn sample<B: BlockDevice + 'static>(
        vol: &BtrfsVolume<B>,
        groups: u64,
        metadata_bytes: u64,
    ) -> Result<Self, FsError> {
        let (root_tree, _) = vol.root_tree_root();
        let nodesize = vol.nodesize() as u64;
        let has_bgt = matches!(
            block_group::bg_home(vol, root_tree).await?,
            BgHome::BlockGroupTree { .. }
        );
        let trees = [
            format::EXTENT_TREE_OBJECTID,
            format::CSUM_TREE_OBJECTID,
            format::FREE_SPACE_TREE_OBJECTID,
            format::BLOCK_GROUP_TREE_OBJECTID,
        ];
        let mut used = 0u64;
        // A tree the filesystem does not have costs nothing; height 1 keeps
        // the arithmetic total.
        let mut heights = [1u64; 4];
        for (slot, &objectid) in trees.iter().enumerate() {
            if objectid == format::BLOCK_GROUP_TREE_OBJECTID && !has_bgt {
                continue;
            }
            match roots::find_root_usage(vol, root_tree, objectid).await {
                Ok((level, bytes)) => {
                    used = used.saturating_add(bytes);
                    heights[slot] = u64::from(level) + 1;
                }
                Err(FsError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        let [extent, csum, free_space, bgt] = heights;
        let block_group = if has_bgt { bgt } else { extent };
        let global = (used / nodesize)
            .min(GLOBAL_MAX_BYTES / nodesize)
            .min(metadata_bytes / nodesize / 8)
            .max(GLOBAL_FLOOR_BLOCKS);
        Ok(Self {
            csum,
            extent,
            block_group,
            free_space,
            groups: groups.max(1),
            global,
        })
    }

    /// The global reserve, in tree blocks.
    pub(crate) fn global(&self) -> u64 {
        self.global
    }

    /// Blocks the commit of a batch holding `load` can allocate for its own
    /// edits (the table in the module documentation).
    pub(crate) fn first_order(&self, load: &CommitLoad) -> u64 {
        let ranges = load
            .new_data
            .saturating_add(load.dropped_data)
            .saturating_add(load.new_meta)
            .saturating_add(load.freed_meta);
        let csum = 2 * self.csum * load.new_data.saturating_add(3 * load.dropped_data);
        let extent = 2
            * self.extent
            * load
                .new_data
                .saturating_add(load.new_meta)
                .saturating_add(load.ref_items)
            + self.extent
                * load
                    .dropped_data
                    .saturating_add(load.added_data)
                    .saturating_add(load.freed_meta);
        let block_group = self.block_group * ranges.min(self.groups);
        let free_space = 2 * self.free_space * ranges + self.free_space * ranges.min(self.groups);
        csum.saturating_add(extent)
            .saturating_add(block_group)
            .saturating_add(free_space)
    }

    /// Blocks that must be free for a batch holding `load` to accept one
    /// more ordinary operation: twice its first-order need, over the global
    /// reserve.
    pub(crate) fn ordinary_need(&self, load: &CommitLoad) -> u64 {
        self.global
            .saturating_add(self.first_order(load).saturating_mul(2))
    }

    /// The same for an operation that only releases space (unlink, rmdir,
    /// eviction), which may borrow the global reserve.
    pub(crate) fn reclaiming_need(&self, load: &CommitLoad) -> u64 {
        self.first_order(load)
    }
}
