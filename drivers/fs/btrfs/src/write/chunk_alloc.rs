//! Incremental chunk allocation (Linux `btrfs_alloc_chunk` +
//! `btrfs_chunk_alloc_add_chunk_item` + `btrfs_make_block_group`).
//!
//! A full filesystem used to be grown by [`super::grow_add_chunk`], which
//! re-packs the chunk, device, extent, root and free-space trees whole. That is
//! fine on a small test image and unthinkable on an installed root whose
//! extent tree is hundreds of megabytes, so under `narf.disks=root-rw` growth
//! was refused outright — which made a root ENOSPC as soon as the space Linux
//! had already allocated ran out, long before the device was full.
//!
//! This allocates one DATA or METADATA chunk the way Linux does, touching only
//! the paths that change: a `CHUNK_ITEM` and the `DEV_ITEM`'s `bytes_used` in
//! the chunk tree (COWed into the SYSTEM block group), a `DEV_EXTENT` per
//! stripe in the device tree, the new `BLOCK_GROUP_ITEM`, and the group's
//! free-space info and one free extent — all in one ordinary COW transaction
//! through [`super::commit_txn`]. Single-device SINGLE and DUP profiles only
//! (an installed root's shape); anything else is `NoSpace`, as before.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::{
    chunk_span_avoiding_supers, commit_txn, fs_commit_from, unchanged_fs_commit, Edit, ExtraTree,
    FsCommit, PathCow, Txn,
};
use crate::allocator::Allocator;
use crate::btree::Cursor;
use crate::format::{self, le16, le64, BtrfsKey};
use crate::roots;
use crate::volume::BtrfsVolume;

/// `BTRFS_DEVICE_RANGE_RESERVED`: the first MiB of a device is never
/// allocated to a chunk.
const DEVICE_RANGE_RESERVED: u64 = 1 << 20;
/// Chunk sizing (`calc_chunk_size`): data up to 1 GiB, metadata up to
/// 256 MiB, never more than a tenth of the filesystem, in 16 MiB steps, and
/// never less than 8 MiB.
const DATA_CHUNK_MAX: u64 = 1 << 30;
const METADATA_CHUNK_MAX: u64 = 256 << 20;
const CHUNK_STEP: u64 = 16 << 20;
const CHUNK_MIN: u64 = 8 << 20;
/// `sizeof(struct btrfs_chunk)` without stripes, and one `btrfs_stripe`.
const CHUNK_HEADER: usize = 48;
const STRIPE: usize = 32;

/// The parts of a chunk allocation [`commit_txn`] threads through its trees.
pub(crate) struct ChunkAlloc {
    /// The chunk tree's path COW (blocks in the SYSTEM group).
    pub(crate) chunk: FsCommit,
    pub(crate) logical: u64,
    pub(crate) length: u64,
    pub(crate) chunk_item: Vec<u8>,
    /// `BLOCK_GROUP_ITEM` body (`used` 0).
    pub(crate) bg_item: Vec<u8>,
    /// Per-device `bytes_used` after the allocation.
    pub(crate) dev_bytes_used: BTreeMap<u64, u64>,
}

/// The `(start, len)` of every hole in `used` (sorted, disjoint
/// `(start, len)` device extents) within `[from, end)`.
pub(crate) fn device_holes(used: &[(u64, u64)], from: u64, end: u64) -> Vec<(u64, u64)> {
    let mut holes = Vec::new();
    let mut at = from;
    for &(start, len) in used {
        if start > at && at < end {
            holes.push((at, start.min(end) - at));
        }
        at = at.max(start.saturating_add(len));
    }
    if at < end {
        holes.push((at, end - at));
    }
    holes
}

/// Place `stripes` stripes of `want` bytes (shrinking toward `CHUNK_MIN` in
/// 1 MiB steps when the holes are smaller) in `holes`, clear of the
/// superblock mirrors. Returns the stripe size and offsets. Pure.
pub(crate) fn place_stripes(
    holes: &[(u64, u64)],
    stripes: usize,
    want: u64,
) -> Option<(u64, Vec<u64>)> {
    let mut size = want;
    while size >= CHUNK_MIN {
        let mut offsets = Vec::new();
        for &(start, len) in holes {
            let mut at = start;
            let end = start + len;
            while offsets.len() < stripes {
                let (s, room) = chunk_span_avoiding_supers(at, end);
                if room < size {
                    // Past a mirror band there may be room again.
                    if s + room >= end {
                        break;
                    }
                    at = s + room + 1;
                    continue;
                }
                offsets.push(s);
                at = s + size;
            }
            if offsets.len() == stripes {
                return Some((size, offsets));
            }
        }
        size -= 1 << 20;
    }
    None
}

/// Allocate one chunk of type `kind` (`BLOCK_GROUP_DATA` or
/// `BLOCK_GROUP_METADATA`) and commit it, so the next allocation finds room.
/// `NoSpace` when the device has no hole big enough, or the filesystem's
/// shape is one this allocator does not handle.
pub(crate) async fn alloc_chunk<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    kind: u64,
) -> Result<(), FsError> {
    // Its own transaction over the committed trees, like any non-batchable
    // operation: the batch's allocator predates the new group.
    vol.sync_to_disk().await?;
    let sb = vol.superblock();
    let members = vol.member_dev_items();
    if members.len() != 1 || sb.num_devices != 1 {
        return Err(FsError::NoSpace);
    }
    let (devid, dev_item) = members[0];
    let dev_total = le64(&dev_item, 8)?.min(
        vol.member_capacities()
            .first()
            .map(|&(_, c)| c)
            .unwrap_or(0),
    );
    let (root_tree, _) = vol.root_tree_root();
    if roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .is_err()
    {
        return Err(FsError::NoSpace);
    }

    // Chunks: the logical end, and a template of the wanted type.
    let mut logical_end = 0u64;
    let mut template: Option<Vec<u8>> = None;
    let mut dev_item_body: Option<Vec<u8>> = None;
    {
        let mut c = Cursor::seek(vol, sb.chunk_root, &BtrfsKey::new(0, 0, 0)).await?;
        while let Some((key, body)) = c.current()? {
            match key.item_type {
                format::CHUNK_ITEM_KEY => {
                    let length = le64(body, 0)?;
                    let flags = le64(body, 24)?;
                    logical_end = logical_end.max(key.offset.saturating_add(length));
                    let profile = flags & format::BLOCK_GROUP_PROFILE_MASK;
                    let same_type = flags
                        & (format::BLOCK_GROUP_DATA
                            | format::BLOCK_GROUP_METADATA
                            | format::BLOCK_GROUP_SYSTEM)
                        == kind;
                    if same_type && (profile == 0 || profile == format::BLOCK_GROUP_DUP) {
                        template = Some(body.to_vec());
                    }
                }
                format::DEV_ITEM_KEY if key.offset == devid => {
                    dev_item_body = Some(body.to_vec());
                }
                _ => {}
            }
            c.advance().await?;
        }
    }
    let template = template.ok_or(FsError::NoSpace)?;
    let mut dev_item_body = dev_item_body.ok_or(FsError::InvalidData)?;
    let stripes = usize::from(le16(&template, 44)?);
    if !(1..=2).contains(&stripes) || template.len() < CHUNK_HEADER + stripes * STRIPE {
        return Err(FsError::NoSpace);
    }

    // Device extents: the holes.
    let (dev_root, dev_level) = roots::find_root(vol, root_tree, format::DEV_TREE_OBJECTID).await?;
    let mut used = Vec::new();
    let mut dev_extent_template: Option<Vec<u8>> = None;
    {
        let mut c = Cursor::seek(
            vol,
            dev_root,
            &BtrfsKey::new(devid, format::DEV_EXTENT_KEY, 0),
        )
        .await?;
        while let Some((key, body)) = c.current()? {
            if key.objectid != devid || key.item_type != format::DEV_EXTENT_KEY {
                break;
            }
            used.push((key.offset, le64(body, 24)?));
            dev_extent_template = Some(body.to_vec());
            c.advance().await?;
        }
    }
    used.sort_unstable();
    let dev_extent_template = dev_extent_template.ok_or(FsError::InvalidData)?;
    let holes = device_holes(&used, DEVICE_RANGE_RESERVED, dev_total);
    let cap = if kind == format::BLOCK_GROUP_DATA {
        DATA_CHUNK_MAX
    } else {
        METADATA_CHUNK_MAX
    };
    let want = (cap.min(sb.total_bytes / 10) / CHUNK_STEP * CHUNK_STEP).max(CHUNK_MIN);
    let (size, offsets) = place_stripes(&holes, stripes, want).ok_or(FsError::NoSpace)?;

    // The new chunk, its device extents and its block group.
    let logical = logical_end;
    let mut chunk_item = template[..CHUNK_HEADER + stripes * STRIPE].to_vec();
    chunk_item[0..8].copy_from_slice(&size.to_le_bytes());
    for (i, &offset) in offsets.iter().enumerate() {
        let at = CHUNK_HEADER + i * STRIPE;
        chunk_item[at..at + 8].copy_from_slice(&devid.to_le_bytes());
        chunk_item[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
    }
    let flags = le64(&chunk_item, 24)?;
    let mut dev_edits = Vec::new();
    for &offset in &offsets {
        let mut body = dev_extent_template.clone();
        body[16..24].copy_from_slice(&logical.to_le_bytes()); // chunk_offset
        body[24..32].copy_from_slice(&size.to_le_bytes()); // length
        dev_edits.push(Edit::Upsert(
            BtrfsKey::new(devid, format::DEV_EXTENT_KEY, offset),
            body,
        ));
    }
    let bytes_used = le64(&dev_item_body, 16)?
        .checked_add(size * offsets.len() as u64)
        .ok_or(FsError::InvalidData)?;
    dev_item_body[16..24].copy_from_slice(&bytes_used.to_le_bytes());
    let mut bg_item = alloc::vec![0u8; 24];
    bg_item[8..16].copy_from_slice(&format::FIRST_CHUNK_TREE_OBJECTID.to_le_bytes());
    bg_item[16..24].copy_from_slice(&flags.to_le_bytes());

    let gen = sb.generation.checked_add(1).ok_or(FsError::InvalidData)?;
    let mut alloc = Allocator::build(vol).await?;
    let mut system = Allocator::build_system(vol).await?;
    let chunk_out = PathCow::new_system(vol, gen, sb.chunk_root, sb.chunk_root_level)
        .await?
        .apply(
            &mut system,
            &[
                Edit::Upsert(
                    BtrfsKey::new(
                        format::FIRST_CHUNK_TREE_OBJECTID,
                        format::CHUNK_ITEM_KEY,
                        logical,
                    ),
                    chunk_item.clone(),
                ),
                Edit::Upsert(
                    BtrfsKey::new(format::DEV_ITEMS_OBJECTID, format::DEV_ITEM_KEY, devid),
                    dev_item_body,
                ),
            ],
        )
        .await?;
    let dev_out = PathCow::new(vol, gen, dev_root, dev_level)
        .await?
        .apply(&mut alloc, &dev_edits)
        .await?;
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "btrfs: allocating a {} chunk: logical {logical:#x} len {size:#x} at {offsets:x?}",
            if kind == format::BLOCK_GROUP_DATA {
                "DATA"
            } else {
                "METADATA"
            }
        );
    }
    let mut dev_bytes_used = BTreeMap::new();
    dev_bytes_used.insert(devid, bytes_used);
    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            chunk_alloc: Some(ChunkAlloc {
                chunk: fs_commit_from(chunk_out, gen, vol.csum_type())?,
                logical,
                length: size,
                chunk_item,
                bg_item,
                dev_bytes_used,
            }),
            fs: unchanged_fs_commit(vol),
            dropped_data: Vec::new(),
            added_data: Vec::new(),
            added_meta: Vec::new(),
            dropped_meta: Vec::new(),
            new_data: Vec::new(),
            root_flags: None,
            extra_trees: alloc::vec![ExtraTree {
                owner: format::DEV_TREE_OBJECTID,
                commit: fs_commit_from(dev_out, gen, vol.csum_type())?,
            }],
            root_edits: Vec::new(),
            retired_meta: Vec::new(),
            qgroup_create: None,
            qgroup_delete: None,
            qgroup_edits: Vec::new(),
            skip_qgroup_recount: true,
            incompat_flags_add: 0,
        },
    )
    .await
}
