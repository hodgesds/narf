//! Size and allocation changes of a regular file: `truncate`, `fallocate`
//! (preallocate, keep-size, punch-hole, zero-range) and the extent carving
//! that the write path's PREALLOC write-to-convert shares with them.
//!
//! Mirrors `fs/btrfs/inode.c::btrfs_setattr` → `btrfs_truncate` /
//! `btrfs_truncate_inode_items` / `btrfs_cont_expand` and
//! `fs/btrfs/file.c::btrfs_fallocate` / `btrfs_punch_hole` /
//! `btrfs_zero_range`. Like Linux, a file item is trimmed, moved or split in
//! place rather than its data copied: a trimmed piece keeps its key and
//! `extent_offset`, a moved piece advances both by the same amount, so the
//! piece's backref identity `(root, inode, key.offset - extent_offset)` and
//! hence its `EXTENT_DATA_REF` are unchanged. Splitting one item in two adds a
//! second file item with the same identity: the ref's `count` goes up by one,
//! exactly as Linux's `btrfs_drop_extents` split does. Checksums stay with
//! the disk extent until its last reference goes.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::{
    align_up, batch_begin, batch_gen, batch_stage_refs, cow_write_file_once, ensure_private_subvol,
    flush_batch_from, qgroup_begin_op, qgroup_reserve, qgroup_reserve_meta, with_space_retry,
    DataRef, DataRefId, Edit, FlushOrigin, MAX_BATCH_OPS,
};
use crate::btree;
use crate::format::{self, le64, BtrfsKey};
use crate::inode::InodeItem;
use crate::volume::BtrfsVolume;

/// `FALLOC_FL_KEEP_SIZE`.
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
/// `FALLOC_FL_PUNCH_HOLE`.
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
/// `FALLOC_FL_ZERO_RANGE`.
pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;

/// Largest PREALLOC extent one `fallocate` lays down. Linux caps a prealloc
/// extent at `BTRFS_MAX_EXTENT_SIZE` (128 MiB); smaller tiles find contiguous
/// free space more easily and cost nothing, since writes carve them.
const MAX_PREALLOC_EXTENT: u64 = 8 << 20;

// `btrfs_file_extent_item` offsets.
const FE_COMPRESSION: usize = 16;
const FE_TYPE: usize = 20;
const FE_DISK_BYTENR: usize = 21;
const FE_DISK_NUM: usize = 29;
const FE_OFFSET: usize = 37;
const FE_NUM_BYTES: usize = 45;
const FE_RAM_BYTES: usize = 8;

/// What one `EXTENT_DATA` item covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Data in the item; at file offset 0, `ram_bytes` long.
    Inline,
    /// A `disk_bytenr == 0` regular item (explicit hole, `^no-holes`).
    Hole,
    /// A REG or PREALLOC item backed by a disk extent.
    Disk { prealloc: bool },
}

/// One decoded file item.
#[derive(Clone, Debug)]
pub(crate) struct FileItem {
    pub key: BtrfsKey,
    pub body: Vec<u8>,
    pub start: u64,
    pub end: u64,
    pub kind: Kind,
}

impl FileItem {
    pub fn decode(key: BtrfsKey, body: Vec<u8>) -> Result<Self, FsError> {
        if body.len() <= FE_TYPE {
            return Err(FsError::InvalidData);
        }
        let (len, kind) = match body[FE_TYPE] {
            format::FILE_EXTENT_INLINE => (le64(&body, FE_RAM_BYTES)?, Kind::Inline),
            t @ (format::FILE_EXTENT_REG | format::FILE_EXTENT_PREALLOC) => {
                if body.len() < 53 {
                    return Err(FsError::InvalidData);
                }
                let kind = if le64(&body, FE_DISK_BYTENR)? == 0 {
                    Kind::Hole
                } else {
                    Kind::Disk {
                        prealloc: t == format::FILE_EXTENT_PREALLOC,
                    }
                };
                (le64(&body, FE_NUM_BYTES)?, kind)
            }
            _ => return Err(FsError::InvalidData),
        };
        Ok(FileItem {
            key,
            start: key.offset,
            end: key.offset.checked_add(len).ok_or(FsError::InvalidData)?,
            body,
            kind,
        })
    }

    /// The data-ref identity this item holds on its disk extent.
    fn ref_id(&self, root: u64, ino: u64) -> Result<DataRefId, FsError> {
        Ok(DataRefId {
            bytenr: le64(&self.body, FE_DISK_BYTENR)?,
            len: le64(&self.body, FE_DISK_NUM)?,
            ref_root: root,
            objectid: ino,
            offset: self
                .start
                .checked_sub(le64(&self.body, FE_OFFSET)?)
                .ok_or(FsError::InvalidData)?,
        })
    }

    /// Bytes this item contributes to the inode's `nbytes`.
    fn nbytes(&self) -> u64 {
        match self.kind {
            Kind::Hole => 0,
            Kind::Inline | Kind::Disk { .. } => self.end - self.start,
        }
    }
}

/// Every file item of `ino`, in key order.
pub(crate) async fn file_items<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
) -> Result<Vec<FileItem>, FsError> {
    btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY)
        .await?
        .into_iter()
        .map(|(key, body)| FileItem::decode(key, body))
        .collect()
}

/// The result of carving a file range out of its items.
#[derive(Default)]
pub(super) struct Carve {
    pub edits: Vec<Edit>,
    pub dropped: Vec<DataRefId>,
    pub added: Vec<DataRefId>,
    /// `nbytes` the carved range held.
    pub removed_nbytes: u64,
}

/// Remove the file range `[a, b)` (sector aligned, `b` may be `u64::MAX`)
/// from every disk-backed or hole item `filter` selects. Pieces outside the
/// range are kept by trimming (left piece, same key) and moving (right piece,
/// new key, `extent_offset` advanced); an item that keeps both pieces is split
/// and its extent gains a reference. Inline items are never carved: callers
/// convert or rewrite them first.
pub(super) fn carve(
    items: &[FileItem],
    a: u64,
    b: u64,
    root: u64,
    ino: u64,
    filter: impl Fn(&FileItem) -> bool,
) -> Result<Carve, FsError> {
    let mut out = Carve::default();
    for item in items {
        if item.end <= a || item.start >= b || !filter(item) {
            continue;
        }
        if item.kind == Kind::Inline {
            return Err(FsError::InvalidData);
        }
        let left = (item.start < a).then_some((item.start, a));
        let right = (item.end > b).then_some((b, item.end));
        let cut_start = item.start.max(a);
        let cut_end = item.end.min(b);
        if matches!(item.kind, Kind::Disk { .. }) {
            out.removed_nbytes += cut_end - cut_start;
        }
        match left {
            Some((s, e)) => {
                let mut body = item.body.clone();
                body[FE_NUM_BYTES..FE_NUM_BYTES + 8].copy_from_slice(&(e - s).to_le_bytes());
                out.edits.push(Edit::Upsert(item.key, body));
            }
            None => out.edits.push(Edit::Delete(item.key)),
        }
        if let Some((s, e)) = right {
            let mut body = item.body.clone();
            if item.kind != Kind::Hole {
                let advanced = le64(&body, FE_OFFSET)? + (s - item.start);
                body[FE_OFFSET..FE_OFFSET + 8].copy_from_slice(&advanced.to_le_bytes());
            } else {
                body[FE_RAM_BYTES..FE_RAM_BYTES + 8].copy_from_slice(&(e - s).to_le_bytes());
            }
            body[FE_NUM_BYTES..FE_NUM_BYTES + 8].copy_from_slice(&(e - s).to_le_bytes());
            out.edits.push(Edit::Upsert(
                BtrfsKey::new(ino, format::EXTENT_DATA_KEY, s),
                body,
            ));
        }
        if matches!(item.kind, Kind::Disk { .. }) {
            let id = item.ref_id(root, ino)?;
            match (left.is_some(), right.is_some()) {
                (false, false) => out.dropped.push(id),
                (true, true) => out.added.push(id),
                _ => {}
            }
        }
    }
    Ok(out)
}

/// A `^no-holes` explicit hole item covering `[start, start + len)`.
fn hole_item(gen: u64, len: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 53];
    v[0..8].copy_from_slice(&gen.to_le_bytes());
    v[FE_RAM_BYTES..FE_RAM_BYTES + 8].copy_from_slice(&len.to_le_bytes());
    v[FE_TYPE] = format::FILE_EXTENT_REG;
    v[FE_NUM_BYTES..FE_NUM_BYTES + 8].copy_from_slice(&len.to_le_bytes());
    v
}

/// A PREALLOC item for a fresh `len`-byte disk extent at `bytenr`.
fn prealloc_item(gen: u64, bytenr: u64, len: u64) -> Vec<u8> {
    let mut v = super::file_extent_reg_encoded(gen, bytenr, len, len, format::COMPRESS_NONE);
    v[FE_TYPE] = format::FILE_EXTENT_PREALLOC;
    v
}

/// Uncovered sub-ranges of `[a, b)`. Inline and disk-backed items cover;
/// explicit hole items cover only when `holes_cover`.
fn gaps(items: &[FileItem], a: u64, b: u64, holes_cover: bool) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = a;
    for item in items.iter().filter(|i| holes_cover || i.kind != Kind::Hole) {
        if item.end <= at || item.start >= b {
            continue;
        }
        if item.start > at {
            out.push((at, item.start.min(b)));
        }
        at = at.max(item.end);
        if at >= b {
            break;
        }
    }
    if at < b {
        out.push((at, b));
    }
    out
}

fn no_holes<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> bool {
    vol.superblock().incompat_flags & format::INCOMPAT_NO_HOLES != 0
}

/// The live inode item body.
async fn inode_body<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
) -> Result<Vec<u8>, FsError> {
    let (fs_root, _) = vol.fs_tree_root();
    btree::find_item(vol, fs_root, &BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0))
        .await?
        .ok_or(FsError::NotFound)
}

/// Zero `[from, to)` of the file through the write path when any of those
/// bytes (read as if the file were `cover` long) are non-zero. Used for the
/// partial sectors at a new EOF or a punched edge: Linux's
/// `btrfs_truncate_block`.
async fn zero_if_dirty<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    from: u64,
    to: u64,
    cover: u64,
) -> Result<(), FsError> {
    if from >= to {
        return Ok(());
    }
    let (fs_root, _) = vol.fs_tree_root();
    let mut buf = alloc::vec![0u8; (to - from) as usize];
    let n = crate::extent::read_file(vol, fs_root, ino, cover, from, &mut buf).await?;
    if buf[..n].iter().all(|&b| b == 0) && !compressed_in(vol, fs_root, ino, from, to).await? {
        return Ok(());
    }
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    let zeros = alloc::vec![0u8; (to - from) as usize];
    cow_write_file_once(vol, ino, &inode, from, &zeros).await?;
    Ok(())
}

/// Whether a compressed extent backs any of `[from, to)`. Its bytes past
/// EOF are whatever the decompressor leaves beyond the end of the stream
/// (`mkfs.btrfs --compress` frames hold exactly `i_size` bytes; Linux zero
/// fills, `btrfs restore` does not), so a range of one that must read as
/// zeros is rewritten rather than trusted.
async fn compressed_in<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
    from: u64,
    to: u64,
) -> Result<bool, FsError> {
    Ok(file_items(vol, fs_root, ino).await?.iter().any(|item| {
        item.start < to
            && item.end > from
            && !matches!(item.kind, Kind::Hole | Kind::Disk { prealloc: true })
            && item
                .body
                .get(FE_COMPRESSION)
                .is_some_and(|&c| c != format::COMPRESS_NONE)
    }))
}

/// Linux `btrfs_cont_expand` → `btrfs_truncate_block(inode, oldsize, 0, 0)`
/// for a write starting past the sector that holds EOF: the rest of that
/// sector becomes part of the gap the write opens, so it must read as zeros
/// whatever the old extent holds past EOF. (A write starting inside that
/// sector rewrites it itself.)
pub(crate) async fn zero_tail_before_write<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    offset: u64,
) -> Result<(), FsError> {
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Ok(());
    }
    let ss = u64::from(vol.sectorsize());
    let old_size = inode.size;
    let sector_end = align_up(old_size, ss);
    if old_size % ss == 0 || offset < sector_end {
        return Ok(());
    }
    zero_if_dirty(vol, ino, old_size, sector_end, sector_end).await
}

/// Rewrite an inline extent as a regular one (same bytes), so ranges after
/// it can take regular items: a file never mixes inline and regular items.
async fn uninline<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>, ino: u64) -> Result<(), FsError> {
    let (fs_root, _) = vol.fs_tree_root();
    let items = file_items(vol, fs_root, ino).await?;
    let Some(inline) = items.iter().find(|i| i.kind == Kind::Inline) else {
        return Ok(());
    };
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    let len = (inline.end - inline.start).min(inode.size);
    let mut data = alloc::vec![0u8; len as usize];
    let n = crate::extent::read_file(vol, fs_root, ino, inode.size, 0, &mut data).await?;
    data.truncate(n);
    if data.is_empty() {
        return Ok(());
    }
    cow_write_file_once(vol, ino, &inode, 0, &data).await?;
    Ok(())
}

/// Stage one size/allocation change: `edits` + ref changes + new extents,
/// and the inode's new `size`/`nbytes`.
///
/// `prealloc` ranges get fresh PREALLOC extents, allocated from the batch's
/// allocator under the same lock that stages them.
async fn stage<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    carve: Carve,
    mut extra: Vec<Edit>,
    prealloc: &[(u64, u64)],
    new_size: Option<u64>,
    touch_mtime: bool,
) -> Result<(), FsError> {
    let ss = u64::from(vol.sectorsize());
    let root = vol.fs_tree_id();
    let full = {
        let mut guard = batch_begin(vol).await?;
        let batch = guard.as_mut().ok_or(FsError::InvalidData)?;
        let gen = batch.gen;
        let added_nbytes: u64 = prealloc.iter().map(|&(s, e)| e - s).sum();
        let tiles = prealloc
            .iter()
            .map(|&(s, e)| (e - s).div_ceil(MAX_PREALLOC_EXTENT) as usize)
            .sum::<usize>();
        qgroup_begin_op(batch);
        if added_nbytes > 0 {
            qgroup_reserve(vol, batch, root, added_nbytes).await?;
        }
        let snapshot = batch.alloc.clone();
        let mut new_data = Vec::new();
        for &(mut s, e) in prealloc {
            while s < e {
                let mut tile = (e - s).min(MAX_PREALLOC_EXTENT);
                let bytenr = loop {
                    match batch.alloc.alloc_data(vol, tile) {
                        Ok(at) => break at,
                        Err(FsError::NoSpace) if tile > ss => {
                            tile = ((tile / 2) & !(ss - 1)).max(ss);
                        }
                        Err(err) => {
                            batch.alloc = snapshot;
                            return Err(err);
                        }
                    }
                };
                extra.push(Edit::Upsert(
                    BtrfsKey::new(ino, format::EXTENT_DATA_KEY, s),
                    prealloc_item(gen, bytenr, tile),
                ));
                new_data.push(DataRef {
                    id: DataRefId {
                        bytenr,
                        len: tile,
                        ref_root: root,
                        objectid: ino,
                        offset: s,
                    },
                    // Preallocated space carries no checksums (Linux
                    // `__btrfs_prealloc_file_range`).
                    csums: Vec::new(),
                });
                s += tile;
            }
        }
        qgroup_reserve_meta(
            vol,
            batch,
            vol.fs_tree_id(),
            carve.edits.len() + extra.len() + tiles + 1,
        )
        .await?;
        let inode_key = BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0);
        let mut inode = inode_body(vol, ino).await?;
        inode[0..8].copy_from_slice(&gen.to_le_bytes());
        inode[8..16].copy_from_slice(&gen.to_le_bytes());
        if let Some(size) = new_size {
            inode[16..24].copy_from_slice(&size.to_le_bytes());
        }
        let nbytes = le64(&inode, 24)?
            .checked_sub(carve.removed_nbytes)
            .and_then(|n| n.checked_add(added_nbytes))
            .ok_or(FsError::InvalidData)?;
        inode[24..32].copy_from_slice(&nbytes.to_le_bytes());
        // ctime always (fallocate, truncate); mtime when the size or the data
        // changed (`btrfs_setsize`, `btrfs_punch_hole`).
        super::touch_times(&mut inode, new_size.is_some() || touch_mtime);
        let mut edits = carve.edits;
        edits.append(&mut extra);
        edits.push(Edit::Upsert(inode_key, inode));
        if let Err(err) =
            batch_stage_refs(vol, batch, &edits, carve.dropped, carve.added, new_data).await
        {
            batch.alloc = snapshot;
            return Err(err);
        }
        batch.ops >= MAX_BATCH_OPS
    };
    if full {
        flush_batch_from(vol, FlushOrigin::StagingOperation).await?;
    }
    Ok(())
}

/// Explicit hole items (`^no-holes` only) for the gaps of `[a, b)`.
fn hole_edits(items: &[FileItem], a: u64, b: u64, ino: u64, gen: u64) -> Vec<Edit> {
    gaps(items, a, b, true)
        .into_iter()
        .filter(|&(s, e)| e > s)
        .map(|(s, e)| {
            Edit::Upsert(
                BtrfsKey::new(ino, format::EXTENT_DATA_KEY, s),
                hole_item(gen, e - s),
            )
        })
        .collect()
}

/// Resize `ino` to exactly `new_size` (`btrfs_setattr` → `btrfs_truncate` for
/// a shrink, `btrfs_cont_expand` for a grow).
pub async fn truncate_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    new_size: u64,
) -> Result<(), FsError> {
    with_space_retry(vol, || truncate_once(vol, ino, new_size)).await
}

async fn truncate_once<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    new_size: u64,
) -> Result<(), FsError> {
    ensure_private_subvol(vol).await?;
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let old_size = inode.size;
    let ss = u64::from(vol.sectorsize());
    let root = vol.fs_tree_id();
    // Same size still truncates, as `btrfs_setsize` does (`btrfs_truncate`
    // with `skip_writeback`): it drops preallocation past EOF.
    if new_size <= old_size {
        // The new last sector's bytes past EOF must read as zero if the file
        // later grows (`btrfs_truncate_block(inode, newsize, 0, 0)`).
        if new_size % ss != 0 {
            let sector_end = align_up(new_size, ss).min(old_size);
            zero_if_dirty(vol, ino, new_size, sector_end, old_size).await?;
        }
        let (fs_root, _) = vol.fs_tree_root();
        let items = file_items(vol, fs_root, ino).await?;
        let gen = batch_gen(vol).await?;
        let cut = align_up(new_size, ss);
        let mut extra = Vec::new();
        let mut inline_removed = 0u64;
        // An inline item past the new size shrinks in place, as
        // `btrfs_truncate_inode_items` does for an uncompressed inline
        // extent; a compressed one is re-encoded uncompressed.
        if let Some(inline) = items.iter().find(|i| i.kind == Kind::Inline) {
            if inline.end > new_size {
                inline_removed = inline.end - new_size.min(inline.end);
                if new_size == 0 {
                    extra.push(Edit::Delete(inline.key));
                } else {
                    let mut data = alloc::vec![0u8; new_size as usize];
                    crate::extent::read_file(vol, fs_root, ino, old_size, 0, &mut data).await?;
                    extra.push(Edit::Upsert(
                        inline.key,
                        super::file_extent_inline(gen, &data),
                    ));
                }
            }
        }
        // The inline item was handled above; `carve` refuses inline items
        // (a Linux-written small file is one), so keep it out.
        let mut carved = carve(&items, cut, u64::MAX, root, ino, |item| {
            item.kind != Kind::Inline
        })?;
        carved.removed_nbytes += inline_removed;
        if new_size == old_size && carved.edits.is_empty() && extra.is_empty() {
            return Ok(());
        }
        stage(vol, ino, carved, extra, &[], Some(new_size), true).await
    } else {
        // Growing: zero the stale tail of the old last sector, then only the
        // size moves (`NO_HOLES`) or explicit holes fill the gap.
        if old_size % ss != 0 {
            let sector_end = align_up(old_size, ss);
            zero_if_dirty(vol, ino, old_size, sector_end.min(new_size), sector_end).await?;
        }
        let (fs_root, _) = vol.fs_tree_root();
        let items = file_items(vol, fs_root, ino).await?;
        let gen = batch_gen(vol).await?;
        let extra = if no_holes(vol) {
            Vec::new()
        } else {
            hole_edits(
                &items,
                align_up(old_size, ss),
                align_up(new_size, ss),
                ino,
                gen,
            )
        };
        stage(vol, ino, Carve::default(), extra, &[], Some(new_size), true).await
    }
}

/// `fallocate(2)` for btrfs (`btrfs_fallocate`): mode 0 and
/// `FALLOC_FL_KEEP_SIZE` preallocate, `FALLOC_FL_PUNCH_HOLE` (with
/// `KEEP_SIZE`) deallocates, `FALLOC_FL_ZERO_RANGE` zeroes as preallocated
/// space. Every other mode is `Unsupported` (EOPNOTSUPP), as Linux answers.
pub async fn fallocate_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    mode: u32,
    offset: u64,
    len: u64,
) -> Result<(), FsError> {
    if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0 {
        return Err(FsError::Unsupported);
    }
    if len == 0 {
        return Err(FsError::InvalidData);
    }
    let end = offset.checked_add(len).ok_or(FsError::FileTooLarge)?;
    let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        if !keep || mode & FALLOC_FL_ZERO_RANGE != 0 {
            return Err(FsError::Unsupported);
        }
        return with_space_retry(vol, || punch_once(vol, ino, offset, end)).await;
    }
    if mode & FALLOC_FL_ZERO_RANGE != 0 {
        with_space_retry(vol, || punch_once(vol, ino, offset, end)).await?;
    }
    with_space_retry(vol, || prealloc_once(vol, ino, offset, end, keep)).await
}

async fn prealloc_once<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    offset: u64,
    end: u64,
    keep: bool,
) -> Result<(), FsError> {
    ensure_private_subvol(vol).await?;
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let ss = u64::from(vol.sectorsize());
    let old_size = inode.size;
    let (a, b) = (offset - offset % ss, align_up(end, ss));
    let new_size = if keep { old_size } else { old_size.max(end) };
    if b > ss {
        uninline(vol, ino).await?;
    }
    // Growing past a partial old last sector exposes its tail.
    if new_size > old_size && old_size % ss != 0 {
        let sector_end = align_up(old_size, ss);
        zero_if_dirty(vol, ino, old_size, sector_end.min(new_size), sector_end).await?;
    }
    let (fs_root, _) = vol.fs_tree_root();
    let items = file_items(vol, fs_root, ino).await?;
    // A (still) inline file owns its whole first sector: Linux's extent map
    // reports the inline extent as `[0, sectorsize)`, so `btrfs_fallocate`
    // finds nothing to preallocate there. Preallocating from the inline
    // item's byte length instead would put a sector-unaligned PREALLOC
    // extent beside the inline one, which `btrfs check` rejects.
    let a = if a < ss && items.iter().any(|i| i.kind == Kind::Inline) {
        ss
    } else {
        a
    };
    let b = b.max(a);
    let holes = gaps(&items, a, b, false);
    let root = vol.fs_tree_id();
    // Explicit hole items in the range give way to the prealloc extents.
    let carved = carve(&items, a, b, root, ino, |i| i.kind == Kind::Hole)?;
    let mut extra = Vec::new();
    if !no_holes(vol) && new_size > old_size {
        // `btrfs_cont_expand`: holes between the old EOF and the new extents.
        let mut covered: Vec<FileItem> = Vec::new();
        for i in &items {
            if i.end <= a || i.start >= b || i.kind != Kind::Hole {
                covered.push(i.clone());
                continue;
            }
            // The pieces of a carved hole item that survive outside [a, b).
            for (s, e) in [(i.start, a), (b, i.end)] {
                if s < e {
                    let mut piece = i.clone();
                    piece.start = s;
                    piece.end = e;
                    covered.push(piece);
                }
            }
        }
        for &(s, e) in &holes {
            covered.push(FileItem {
                key: BtrfsKey::new(ino, format::EXTENT_DATA_KEY, s),
                body: Vec::new(),
                start: s,
                end: e,
                kind: Kind::Disk { prealloc: true },
            });
        }
        covered.sort_by_key(|i| i.start);
        let gen = batch_gen(vol).await?;
        extra.extend(hole_edits(
            &covered,
            align_up(old_size, ss),
            align_up(new_size, ss),
            ino,
            gen,
        ));
    }
    if holes.is_empty() && carved.edits.is_empty() && extra.is_empty() && new_size == old_size {
        return Ok(());
    }
    stage(
        vol,
        ino,
        carved,
        extra,
        &holes,
        (new_size != old_size).then_some(new_size),
        false,
    )
    .await
}

async fn punch_once<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    offset: u64,
    end: u64,
) -> Result<(), FsError> {
    ensure_private_subvol(vol).await?;
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let old_size = inode.size;
    // `btrfs_punch_hole`: nothing at or past EOF.
    if offset >= old_size {
        return Ok(());
    }
    let ss = u64::from(vol.sectorsize());
    let fa = align_up(offset, ss);
    let fb = end - end % ss;
    // Partial sectors at either edge are zeroed in place (within EOF).
    if fa >= fb {
        zero_if_dirty(vol, ino, offset, end.min(old_size), old_size).await?;
        return Ok(());
    }
    zero_if_dirty(vol, ino, offset, fa.min(old_size), old_size).await?;
    if end % ss != 0 {
        zero_if_dirty(vol, ino, fb, end.min(old_size), old_size).await?;
    }
    let (fs_root, _) = vol.fs_tree_root();
    let mut items = file_items(vol, fs_root, ino).await?;
    let mut extra = Vec::new();
    let mut inline_removed = 0u64;
    if let Some(pos) = items.iter().position(|i| i.kind == Kind::Inline) {
        // The inline item lives in sector 0; a punch covering that whole
        // sector removes it.
        if fa == 0 {
            inline_removed = items[pos].nbytes();
            extra.push(Edit::Delete(items[pos].key));
        }
        items.remove(pos);
    }
    let root = vol.fs_tree_id();
    let mut carved = carve(&items, fa, fb, root, ino, |_| true)?;
    carved.removed_nbytes += inline_removed;
    if !no_holes(vol) {
        let hole_end = fb.min(align_up(old_size, ss));
        if hole_end > fa {
            let gen = batch_gen(vol).await?;
            extra.push(Edit::Upsert(
                BtrfsKey::new(ino, format::EXTENT_DATA_KEY, fa),
                hole_item(gen, hole_end - fa),
            ));
        }
    }
    stage(vol, ino, carved, extra, &[], None, true).await
}
