//! Root tree: locating subvolume tree roots.
//!
//! The root tree (superblock `root`) maps a tree's objectid to a `ROOT_ITEM`
//! (`struct btrfs_root_item`) whose `bytenr`/`level` give that tree's on-disk
//! root node. The same decoder locates selected subvolume, CSUM, and EXTENT
//! roots for the read/write paths.

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::btree;
use crate::format::{self, le64, BtrfsKey};
use crate::volume::BtrfsVolume;

// Offsets within `struct btrfs_root_item` (which begins with a 160-byte
// `btrfs_inode_item`).
const ROOT_ITEM_BYTENR: usize = 176;
pub(crate) const ROOT_ITEM_FLAGS: usize = 208;
const ROOT_ITEM_LEVEL: usize = 238;
/// Minimum decodable `btrfs_root_item` size (through the `level` byte).
const ROOT_ITEM_MIN: usize = ROOT_ITEM_LEVEL + 1;

/// Decode a `ROOT_ITEM` body into `(root_node_logical, level)`.
fn decode_root_item(body: &[u8]) -> Result<(u64, u8), FsError> {
    if body.len() < ROOT_ITEM_MIN {
        return Err(FsError::InvalidData);
    }
    Ok((le64(body, ROOT_ITEM_BYTENR)?, body[ROOT_ITEM_LEVEL]))
}

/// Find a tree root and its root-item flags. Subvolume mounts use the flags to
/// preserve Linux's read-only snapshot bit while allowing ordinary writable
/// subvolumes to use the COW writer.
pub async fn find_root_with_flags<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root_tree: u64,
    objectid: u64,
) -> Result<(u64, u8, u64), FsError> {
    // Root items are keyed (objectid, ROOT_ITEM_KEY, offset); the live root of a
    // tree is the first such item in key order.
    let start = BtrfsKey::new(objectid, format::ROOT_ITEM_KEY, 0);
    let cursor = btree::Cursor::seek(vol, root_tree, &start).await?;
    match cursor.current()? {
        Some((key, body)) if key.objectid == objectid && key.item_type == format::ROOT_ITEM_KEY => {
            let (bytenr, level) = decode_root_item(body)?;
            Ok((bytenr, level, le64(body, ROOT_ITEM_FLAGS)?))
        }
        _ => Err(FsError::NotFound),
    }
}

/// Find the tree root `(logical, level)` for `objectid` in the root tree rooted
/// at logical `root_tree`. Returns `NotFound` if absent.
pub async fn find_root<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root_tree: u64,
    objectid: u64,
) -> Result<(u64, u8), FsError> {
    let (bytenr, level, _) = find_root_with_flags(vol, root_tree, objectid).await?;
    Ok((bytenr, level))
}

/// Locate the default FS_TREE root `(logical, level)`.
pub async fn find_fs_tree<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root_tree: u64,
) -> Result<(u64, u8), FsError> {
    find_root(vol, root_tree, format::FS_TREE_OBJECTID).await
}
