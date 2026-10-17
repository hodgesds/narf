//! Block group items: where they live and how mount validates them.
//!
//! Without `COMPAT_RO_BLOCK_GROUP_TREE` every `BLOCK_GROUP_ITEM` is interleaved
//! with the extent records in the extent tree. With it they live alone in the
//! block-group tree (objectid 11), located through its `ROOT_ITEM` in the root
//! tree exactly like the extent tree. This mirrors Linux
//! `btrfs_block_group_root()` in `fs/btrfs/block-group.c`: every reader and
//! writer asks one helper which tree holds the items, so the extent tree is
//! never searched for block groups on a block-group-tree filesystem and the
//! block-group tree is never consulted on one without it.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree::Cursor;
use crate::format::{self, le64, BtrfsKey};
use crate::roots;
use crate::volume::BtrfsVolume;

/// Size of `struct btrfs_block_group_item`: used, chunk_objectid, flags.
pub(crate) const BLOCK_GROUP_ITEM_SIZE: usize = 24;

/// Type bits a block group and its chunk must agree on
/// (`BTRFS_BLOCK_GROUP_TYPE_MASK`).
const TYPE_MASK: u64 =
    format::BLOCK_GROUP_DATA | format::BLOCK_GROUP_SYSTEM | format::BLOCK_GROUP_METADATA;

/// Where this filesystem keeps its block group items.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BgHome {
    /// Interleaved in the extent tree.
    ExtentTree,
    /// In the block-group tree, whose root node is `(root, level)`.
    BlockGroupTree { root: u64, level: u8 },
}

/// Resolve where block group items live for the root tree at `root_tree`
/// (Linux `btrfs_block_group_root`). A block-group-tree filesystem whose root
/// tree lacks the objectid-11 `ROOT_ITEM` is corrupt: Linux `load_global_roots`
/// fails the mount unless `rescue=ignorebadroots`, which this driver lacks.
pub(crate) async fn bg_home<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root_tree: u64,
) -> Result<BgHome, FsError> {
    if !vol.superblock().has_block_group_tree() {
        return Ok(BgHome::ExtentTree);
    }
    match roots::find_root(vol, root_tree, format::BLOCK_GROUP_TREE_OBJECTID).await {
        Ok((root, level)) => Ok(BgHome::BlockGroupTree { root, level }),
        Err(FsError::NotFound) => Err(FsError::InvalidData),
        Err(error) => Err(error),
    }
}

/// Mount-time cross-check of block groups against chunks, as Linux
/// `read_one_block_group` + `check_chunk_block_group_mappings` do: every block
/// group must match a chunk with the same start, length and type bits, and every
/// chunk must have its block group. `chunks` is `(logical, CHUNK_ITEM body)`.
///
/// `tree` must hold only block group items when it is the block-group tree;
/// any other item there is corruption.
pub(crate) async fn validate_block_groups<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    tree: u64,
    exclusive: bool,
    chunks: &[(u64, Vec<u8>)],
) -> Result<(), FsError> {
    let mut cursor = Cursor::seek(vol, tree, &BtrfsKey::new(0, 0, 0)).await?;
    let mut matched = 0usize;
    while let Some((k, body)) = cursor.current()? {
        if k.item_type != format::BLOCK_GROUP_ITEM_KEY {
            if exclusive {
                return Err(FsError::InvalidData);
            }
            cursor.advance().await?;
            continue;
        }
        if body.len() < BLOCK_GROUP_ITEM_SIZE || k.offset == 0 {
            return Err(FsError::InvalidData);
        }
        let used = le64(body, 0)?;
        let flags = le64(body, 16)?;
        let (_, chunk) = chunks
            .iter()
            .find(|(logical, _)| *logical == k.objectid)
            .ok_or(FsError::InvalidData)?;
        let chunk_len = le64(chunk, 0)?;
        let chunk_type = le64(chunk, 24)?;
        if chunk_len != k.offset || used > k.offset || chunk_type & TYPE_MASK != flags & TYPE_MASK {
            return Err(FsError::InvalidData);
        }
        matched += 1;
        cursor.advance().await?;
    }
    if matched != chunks.len() {
        return Err(FsError::InvalidData);
    }
    Ok(())
}
