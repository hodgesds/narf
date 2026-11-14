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
    flush_batch_from, flush_if_full, qgroup_begin_op, qgroup_reserve, qgroup_reserve_meta,
    with_space_retry, DataRef, DataRefId, Edit, FlushOrigin,
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

/// Every file item of `ino`, in key order. For tests: every operation reads
/// the items of the range it works on ([`file_items_in`]).
#[cfg(feature = "kernel-test")]
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

/// The file items of `ino` that overlap `[a, b)`, in key order: the item at
/// or before `a` when it reaches past `a`, then every item starting below
/// `b` — Linux `btrfs_lookup_file_extent` and the forward walk of
/// `btrfs_drop_extents`. Reads the leaves holding those items, not the
/// inode's whole extent list.
pub(crate) async fn file_items_in<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
    a: u64,
    b: u64,
) -> Result<Vec<FileItem>, FsError> {
    let mine = |key: &BtrfsKey| key.objectid == ino && key.item_type == format::EXTENT_DATA_KEY;
    let ceiling = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, a.saturating_add(1));
    let from = match btree::last_before(vol, fs_root, &ceiling).await? {
        Some((key, _)) if mine(&key) => key.offset,
        _ => a,
    };
    let start = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, from);
    let mut cursor = btree::Cursor::seek(vol, fs_root, &start).await?;
    let mut out = Vec::new();
    while let Some((key, body)) = cursor.current()? {
        if !mine(&key) || key.offset >= b {
            break;
        }
        let item = FileItem::decode(key, body.to_vec())?;
        if item.end > a {
            out.push(item);
        }
        cursor.advance().await?;
    }
    Ok(out)
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
    let mut buf = crate::databuf::zeroed((to - from) as usize)?;
    let n = crate::extent::read_file(vol, fs_root, ino, cover, from, &mut buf).await?;
    if buf[..n].iter().all(|&b| b == 0) && !compressed_in(vol, fs_root, ino, from, to).await? {
        return Ok(());
    }
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    buf.fill(0);
    cow_write_file_once(vol, ino, &inode, from, &buf).await?;
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
    Ok(file_items_in(vol, fs_root, ino, from, to)
        .await?
        .iter()
        .any(|item| {
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
    // An inline item is the file's item at offset 0.
    let first = file_items_in(vol, fs_root, ino, 0, u64::from(vol.sectorsize())).await?;
    let Some(inline) = first.iter().find(|i| i.kind == Kind::Inline) else {
        return Ok(());
    };
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    let len = (inline.end - inline.start).min(inode.size);
    let mut data = crate::databuf::zeroed(len as usize)?;
    let n = crate::extent::read_file(vol, fs_root, ino, inode.size, 0, &mut data).await?;
    data.truncate(n);
    if data.is_empty() {
        return Ok(());
    }
    cow_write_file_once(vol, ino, &inode, 0, &data).await?;
    Ok(())
}

/// What one preallocating step asks of [`stage_fill`].
struct Fill<'a> {
    /// Uncovered ranges to lay PREALLOC extents over, ascending.
    ranges: &'a [(u64, u64)],
    /// The explicit hole items (`^no-holes`) met from `from` on: what of them
    /// lies below where the step reaches gives way to the new extents.
    holes: &'a [FileItem],
    /// Where the step starts.
    from: u64,
    /// Where it reaches when every range is allocated in full.
    reach: u64,
    /// The end the caller asked for, when the file's size follows the
    /// allocation (no `FALLOC_FL_KEEP_SIZE`).
    grow_to: Option<u64>,
}

/// Stage one size/allocation change: `edits` + ref changes, and the inode's
/// new `size`/`nbytes`.
async fn stage<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    carved: Carve,
    extra: Vec<Edit>,
    new_size: Option<u64>,
    touch_mtime: bool,
) -> Result<(), FsError> {
    stage_fill(vol, ino, carved, extra, None, new_size, touch_mtime)
        .await
        .map(|_| ())
}

/// [`stage`] that also preallocates: the ranges of `fill` get fresh PREALLOC
/// extents, allocated from the batch's allocator under the same lock that
/// stages them, and the explicit hole items under them go. Returns where
/// the step reached.
///
/// A step lays down at most [`super::DEALLOC_STEP_EXTENTS`] extents. Where
/// free space is in pieces and the ranges take more than that, the step
/// ends at the last extent it placed — short of `fill.reach` — and the next
/// goes on from there. Without `FALLOC_FL_KEEP_SIZE` the file's size
/// follows to where the step reached, as Linux
/// `__btrfs_prealloc_file_range` writes `i_size` forward after each extent.
async fn stage_fill<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    mut carved: Carve,
    mut extra: Vec<Edit>,
    fill: Option<Fill<'_>>,
    mut new_size: Option<u64>,
    touch_mtime: bool,
) -> Result<u64, FsError> {
    let ss = u64::from(vol.sectorsize());
    let root = vol.fs_tree_id();
    let (full, reach) = {
        let mut guard = batch_begin(vol).await?;
        let batch = guard.as_mut().ok_or(FsError::InvalidData)?;
        let gen = batch.gen;
        qgroup_begin_op(batch);
        // Whatever fails from here on, the extents taken for this step go
        // back to the allocator.
        let snapshot = batch.alloc.clone();
        let staged: Result<u64, FsError> = async {
            let mut new_data = Vec::new();
            let mut added_nbytes = 0u64;
            let mut reach = 0u64;
            if let Some(fill) = &fill {
                reach = fill.reach;
                'ranges: for &(mut s, e) in fill.ranges {
                    while s < e {
                        if new_data.len() == super::DEALLOC_STEP_EXTENTS {
                            reach = s;
                            break 'ranges;
                        }
                        let mut tile = (e - s).min(MAX_PREALLOC_EXTENT);
                        let bytenr = loop {
                            match batch.alloc.alloc_data(vol, tile) {
                                Ok(at) => break at,
                                Err(FsError::NoSpace) if tile > ss => {
                                    tile = ((tile / 2) & !(ss - 1)).max(ss);
                                }
                                Err(err) => return Err(err),
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
                        added_nbytes += tile;
                        s += tile;
                    }
                }
                // Explicit hole items give way to the extents laid over
                // them, as far as the step got.
                let holes = carve(fill.holes, fill.from, reach, root, ino, |i| {
                    i.kind == Kind::Hole
                })?;
                carved.edits.extend(holes.edits);
                if added_nbytes > 0 {
                    qgroup_reserve(vol, batch, root, added_nbytes).await?;
                }
            }
            qgroup_reserve_meta(
                vol,
                batch,
                vol.fs_tree_id(),
                carved.edits.len() + extra.len() + new_data.len() + 1,
            )
            .await?;
            let inode_key = BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0);
            let mut inode = inode_body(vol, ino).await?;
            if let Some(end) = fill.as_ref().and_then(|fill| fill.grow_to) {
                let size = reach.min(end);
                if size > le64(&inode, 16)? {
                    new_size = Some(size);
                }
            }
            inode[0..8].copy_from_slice(&gen.to_le_bytes());
            inode[8..16].copy_from_slice(&gen.to_le_bytes());
            if let Some(size) = new_size {
                inode[16..24].copy_from_slice(&size.to_le_bytes());
            }
            let nbytes = le64(&inode, 24)?
                .checked_sub(carved.removed_nbytes)
                .and_then(|n| n.checked_add(added_nbytes))
                .ok_or(FsError::InvalidData)?;
            inode[24..32].copy_from_slice(&nbytes.to_le_bytes());
            // ctime always (fallocate, truncate); mtime when the size or the
            // data changed (`btrfs_setsize`, `btrfs_punch_hole`).
            super::touch_times(&mut inode, new_size.is_some() || touch_mtime);
            let mut edits = core::mem::take(&mut carved.edits);
            edits.append(&mut extra);
            edits.push(Edit::Upsert(inode_key, inode));
            batch_stage_refs(
                vol,
                batch,
                &edits,
                core::mem::take(&mut carved.dropped),
                core::mem::take(&mut carved.added),
                new_data,
            )
            .await?;
            Ok(reach)
        }
        .await;
        match staged {
            Ok(reach) => (batch.is_full() && !vol.commits_held(), reach),
            Err(err) => {
                batch.alloc = snapshot;
                return Err(err);
            }
        }
    };
    if full {
        flush_batch_from(vol, FlushOrigin::StagingOperation).await?;
    }
    Ok(reach)
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
///
/// A truncate that drops many extents does it from the end of the file in
/// steps of [`super::DEALLOC_STEP_EXTENTS`], each a truncate of its own to
/// an intermediate size (Linux `btrfs_truncate`: `btrfs_truncate_inode_items`
/// until it returns `-EAGAIN`, then a new transaction), so what is reserved
/// at a time does not grow with the file. Every intermediate state is a
/// shorter file with nothing past its end; when the reservation runs out
/// between two steps the batch commits there, so a crash during a large
/// truncate can leave the file at one of those sizes — above the size asked
/// for, with its old contents up to that point — where Linux, which records
/// the new size first and finishes from an orphan item at the next mount,
/// leaves it at the new size.
pub async fn truncate_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    new_size: u64,
) -> Result<(), FsError> {
    let ss = u64::from(vol.sectorsize());
    crate::stats::begin_step_marks();
    loop {
        // Each step works out its own range from the tree as it is, under
        // the operation lock; the caller's inode lock keeps every other
        // change of this file out in between.
        let last = super::locked_step(vol, move || async move {
            let next = next_truncate_step(vol, ino, new_size).await?;
            let (size, drop_from) = next.unwrap_or((new_size, align_up(new_size, ss)));
            let r = {
                let _hold = vol.hold_commits();
                with_space_retry(vol, || truncate_once(vol, ino, size, drop_from)).await
            };
            flush_if_full(vol).await?;
            r?;
            if next.is_some() {
                crate::stats::note_step_mark(size);
            }
            super::dealloc_step_done(vol).await?;
            Ok(next.is_none())
        })
        .await?;
        if last {
            return Ok(());
        }
        super::step_break().await;
    }
}

/// The next step of a shrinking (or same-size) truncate to `new_size`
/// before its last: `(size, drop_from)`, dropping the
/// [`super::DEALLOC_STEP_EXTENTS`] highest extent items from `drop_from` on
/// and leaving the file `size` long (its own size where the items dropped
/// are preallocation past EOF). `None` when what is left is the last step's
/// worth. Reads only the items it drops, from the end down.
async fn next_truncate_step<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    new_size: u64,
) -> Result<Option<(u64, u64)>, FsError> {
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() || new_size > inode.size {
        return Ok(None);
    }
    let cut = align_up(new_size, u64::from(vol.sectorsize()));
    let (fs_root, _) = vol.fs_tree_root();
    let mut ceiling = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, u64::MAX);
    let mut starts: Vec<u64> = Vec::new();
    while starts.len() <= super::DEALLOC_STEP_EXTENTS {
        match btree::last_before(vol, fs_root, &ceiling).await? {
            Some((key, _))
                if key.objectid == ino
                    && key.item_type == format::EXTENT_DATA_KEY
                    && key.offset >= cut =>
            {
                starts.push(key.offset);
                ceiling = key;
            }
            _ => break,
        }
    }
    if starts.len() <= super::DEALLOC_STEP_EXTENTS {
        return Ok(None);
    }
    let drop_from = starts[super::DEALLOC_STEP_EXTENTS - 1];
    Ok(Some((drop_from.min(inode.size).max(new_size), drop_from)))
}

/// Truncate to `new_size`, dropping the extent items from `drop_from` on
/// (`align_up(new_size)` for a plain truncate; higher for a step of a large
/// one that only drops preallocation past EOF).
async fn truncate_once<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    new_size: u64,
    drop_from: u64,
) -> Result<(), FsError> {
    // The tree reads are boxed: this future sat at the 8 KiB frame budget
    // (64 KiB task stacks), and the subvolume check's and the reads' states
    // are the largest it holds.
    alloc::boxed::Box::pin(ensure_private_subvol(vol)).await?;
    let inode = InodeItem::decode(&alloc::boxed::Box::pin(inode_body(vol, ino)).await?)?;
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
            alloc::boxed::Box::pin(zero_if_dirty(vol, ino, new_size, sector_end, old_size)).await?;
        }
        // Only the items from the cut on are read (and, below a sector, the
        // one at offset 0, which may be inline).
        let (fs_root, _) = vol.fs_tree_root();
        let cut = drop_from.max(align_up(new_size, ss));
        let from = if new_size < ss { 0 } else { cut };
        let items =
            alloc::boxed::Box::pin(file_items_in(vol, fs_root, ino, from, u64::MAX)).await?;
        let gen = batch_gen(vol).await?;
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
                    let mut data = crate::databuf::zeroed(new_size as usize)?;
                    alloc::boxed::Box::pin(crate::extent::read_file(
                        vol, fs_root, ino, old_size, 0, &mut data,
                    ))
                    .await?;
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
        alloc::boxed::Box::pin(stage(vol, ino, carved, extra, Some(new_size), true)).await
    } else {
        // Growing: zero the stale tail of the old last sector, then only the
        // size moves (`NO_HOLES`) or explicit holes fill the gap.
        if old_size % ss != 0 {
            let sector_end = align_up(old_size, ss);
            alloc::boxed::Box::pin(zero_if_dirty(
                vol,
                ino,
                old_size,
                sector_end.min(new_size),
                sector_end,
            ))
            .await?;
        }
        let extra = if no_holes(vol) {
            Vec::new()
        } else {
            // Only the items past the old EOF matter (preallocation there).
            let (lo, hi) = (align_up(old_size, ss), align_up(new_size, ss));
            let (fs_root, _) = vol.fs_tree_root();
            let items = file_items_in(vol, fs_root, ino, lo, hi).await?;
            let gen = batch_gen(vol).await?;
            hole_edits(&items, lo, hi, ino, gen)
        };
        alloc::boxed::Box::pin(stage(
            vol,
            ino,
            Carve::default(),
            extra,
            Some(new_size),
            true,
        ))
        .await
    }
}

/// The most file bytes one step of a zero-range converts: what a step's
/// worth of PREALLOC extents covers.
const STEP_PREALLOC_BYTES: u64 = super::DEALLOC_STEP_EXTENTS as u64 * MAX_PREALLOC_EXTENT;

/// `fallocate(2)` for btrfs (`btrfs_fallocate`): mode 0 and
/// `FALLOC_FL_KEEP_SIZE` preallocate, `FALLOC_FL_PUNCH_HOLE` (with
/// `KEEP_SIZE`) deallocates, `FALLOC_FL_ZERO_RANGE` zeroes as preallocated
/// space. Every other mode is `Unsupported` (EOPNOTSUPP), as Linux answers.
///
/// Every mode works through its range in steps from the front, each one
/// staged operation that drops at most [`super::DEALLOC_STEP_EXTENTS`]
/// extent items or lays down as many new extents, so what is reserved at a
/// time does not follow the size of the range (Linux
/// `btrfs_replace_file_extents`, which ends and restarts its transaction
/// whenever `btrfs_drop_extents` runs out of its one-item reserve, and
/// `btrfs_prealloc_file_range`, one extent a transaction). The batch
/// commits between two steps when its reservation runs out, so a crash can
/// leave the operation done up to a step boundary:
///
/// - a punch: a hole from the start of the range to that boundary, the old
///   data from there on, the size as it was;
/// - a preallocation: the holes up to the boundary allocated and, without
///   `KEEP_SIZE`, the size moved up to it (`__btrfs_prealloc_file_range`
///   writes `i_size` forward after every extent);
/// - a zero-range: preallocated (reading zeros) up to the boundary, the old
///   data from there on. A step punches and preallocates the same stretch
///   before commits are let through, as `btrfs_replace_file_extents` inserts
///   the replacement for what it dropped before it ends a transaction.
///
/// Nothing outside the requested bytes changes in any of them. An operation
/// that fits one step is one operation in one transaction.
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
    let punch = mode & FALLOC_FL_PUNCH_HOLE != 0;
    let zero = mode & FALLOC_FL_ZERO_RANGE != 0;
    if punch && (!keep || zero) {
        return Err(FsError::Unsupported);
    }
    crate::stats::begin_step_marks();
    if !punch {
        super::locked_step(vol, move || {
            with_space_retry(vol, move || prealloc_fits(vol, ino, offset, end, zero))
        })
        .await?;
    }
    let ss = u64::from(vol.sectorsize());
    // Where the next punching step starts (after the first), where the next
    // preallocating step starts, and the end preallocation may run to now:
    // none while a zero-range has punched no further than it has filled.
    // Shared with the step, which is run again after the filesystem grew and
    // then sees what the first try already staged. Atomics, as the future
    // must be `Send`; `NONE` stands for `None`.
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
    const NONE: u64 = u64::MAX;
    let get = |cell: &AtomicU64| Some(cell.load(Relaxed)).filter(|&v| v != NONE);
    let put = |cell: &AtomicU64, value: Option<u64>| cell.store(value.unwrap_or(NONE), Relaxed);
    let punching = AtomicBool::new(punch || zero);
    let punch_from = AtomicU64::new(NONE);
    let fill_from = AtomicU64::new(NONE);
    let fill_to = AtomicU64::new(if punch || zero { NONE } else { end });
    let (punching, punch_from, fill_from, fill_to) = (&punching, &punch_from, &fill_from, &fill_to);
    loop {
        let done = super::locked_step(vol, move || async move {
            // Edge zeroing, uninlining, a step's punch and its allocation
            // are separate stages; keep them in one transaction.
            let step: Result<bool, FsError> = async {
                let _hold = vol.hold_commits();
                if get(fill_to).is_none() {
                    let from = get(punch_from);
                    match with_space_retry(vol, || punch_step(vol, ino, offset, end, from, zero))
                        .await?
                    {
                        Some(next) => {
                            put(punch_from, Some(next));
                            put(fill_to, zero.then_some(next));
                            crate::stats::note_step_mark(next);
                        }
                        None => {
                            punching.store(false, Relaxed);
                            put(fill_to, zero.then_some(end));
                        }
                    }
                }
                let Some(target) = get(fill_to) else {
                    // A punch is done with its last step.
                    return Ok(!punching.load(Relaxed));
                };
                let from = get(fill_from);
                match with_space_retry(vol, || prealloc_step(vol, ino, offset, target, keep, from))
                    .await?
                {
                    Some(next) => {
                        put(fill_from, Some(next));
                        if !zero {
                            crate::stats::note_step_mark(next);
                        }
                        Ok(false)
                    }
                    // Filled as far as it was punched: a zero-range goes on
                    // punching, or is done.
                    None => {
                        put(fill_from, Some(align_up(target, ss)));
                        put(fill_to, None);
                        Ok(!punching.load(Relaxed))
                    }
                }
            }
            .await;
            flush_if_full(vol).await?;
            let done = step?;
            if !done {
                super::dealloc_step_done(vol).await?;
            }
            Ok(done)
        })
        .await?;
        if done {
            return Ok(());
        }
        super::step_break().await;
    }
}

/// Where a step that starts at `from` ends: at the start of the extent item
/// after the [`super::DEALLOC_STEP_EXTENTS`]th that begins in `[from, to)`,
/// or at `to`. (An item reaching in from before `from` is one more, for the
/// first step of an operation.)
async fn step_end<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
    from: u64,
    to: u64,
) -> Result<u64, FsError> {
    let first = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, from);
    let mut cursor = btree::Cursor::seek(vol, fs_root, &first).await?;
    let mut seen = 0usize;
    while let Some((key, _)) = cursor.current()? {
        if key.objectid != ino || key.item_type != format::EXTENT_DATA_KEY || key.offset >= to {
            break;
        }
        if seen == super::DEALLOC_STEP_EXTENTS {
            return Ok(key.offset);
        }
        seen += 1;
        cursor.advance().await?;
    }
    Ok(to)
}

/// One step of `FALLOC_FL_PUNCH_HOLE` over `[offset, end)`
/// (`btrfs_punch_hole`; one turn of the loop in
/// `btrfs_replace_file_extents`). The first step (`from` is `None`) zeroes
/// the partial sectors at either edge in place; every step then drops the
/// next [`super::DEALLOC_STEP_EXTENTS`] extent items of the range's whole
/// sectors — and, when preallocation follows it (`fill_follows`, a
/// zero-range), no more than a step of that covers — puts a hole item in
/// their place where the filesystem keeps them, and takes their bytes off
/// the inode. Returns where the next step starts, `None` after the last.
///
/// Everything is read from the tree as it is, so a step that is retried, or
/// an operation that starts over after the filesystem grew, goes on from
/// what is already punched.
async fn punch_step<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    offset: u64,
    end: u64,
    from: Option<u64>,
    fill_follows: bool,
) -> Result<Option<u64>, FsError> {
    ensure_private_subvol(vol).await?;
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let old_size = inode.size;
    // `btrfs_punch_hole`: nothing at or past EOF.
    if offset >= old_size {
        return Ok(None);
    }
    let ss = u64::from(vol.sectorsize());
    let fa = align_up(offset, ss);
    let fb = end - end % ss;
    if from.is_none() {
        // Partial sectors at either edge are zeroed in place (within EOF).
        if fa >= fb {
            zero_if_dirty(vol, ino, offset, end.min(old_size), old_size).await?;
            return Ok(None);
        }
        zero_if_dirty(vol, ino, offset, fa.min(old_size), old_size).await?;
        if end % ss != 0 {
            zero_if_dirty(vol, ino, fb, end.min(old_size), old_size).await?;
        }
    }
    let cur = from.unwrap_or(fa);
    if cur >= fb {
        return Ok(None);
    }
    let (fs_root, _) = vol.fs_tree_root();
    let mut stop = step_end(vol, fs_root, ino, cur, fb).await?;
    if fill_follows {
        stop = stop.min(cur.saturating_add(STEP_PREALLOC_BYTES));
    }
    let mut items = file_items_in(vol, fs_root, ino, cur, stop).await?;
    let mut extra = Vec::new();
    let mut inline_removed = 0u64;
    if let Some(pos) = items.iter().position(|i| i.kind == Kind::Inline) {
        // The inline item lives in sector 0; a punch covering that whole
        // sector removes it.
        if cur == 0 {
            inline_removed = items[pos].nbytes();
            extra.push(Edit::Delete(items[pos].key));
        }
        items.remove(pos);
    }
    let root = vol.fs_tree_id();
    let mut carved = carve(&items, cur, stop, root, ino, |_| true)?;
    carved.removed_nbytes += inline_removed;
    if !no_holes(vol) {
        let hole_end = stop.min(align_up(old_size, ss));
        if hole_end > cur {
            // `fill_holes`: the hole item an earlier step of this punch left
            // ending here grows over what this one dropped; otherwise a new
            // item starts here.
            let here = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, cur);
            let grows = match btree::last_before(vol, fs_root, &here).await? {
                Some((key, body))
                    if key.objectid == ino
                        && key.item_type == format::EXTENT_DATA_KEY
                        && key.offset >= fa =>
                {
                    let before = FileItem::decode(key, body)?;
                    (before.kind == Kind::Hole && before.end == cur).then_some(before.start)
                }
                _ => None,
            };
            let start = grows.unwrap_or(cur);
            let gen = batch_gen(vol).await?;
            extra.push(Edit::Upsert(
                BtrfsKey::new(ino, format::EXTENT_DATA_KEY, start),
                hole_item(gen, hole_end - start),
            ));
        }
    }
    stage(vol, ino, carved, extra, None, true).await?;
    Ok((stop < fb).then_some(stop))
}

/// Refuse a preallocation that the filesystem's free data space cannot
/// hold, before any of it is allocated: Linux `btrfs_fallocate` and
/// `btrfs_zero_range` reserve the data space of the whole request
/// (`btrfs_alloc_data_chunk_ondemand`) ahead of
/// `btrfs_prealloc_file_range`, so a request that does not fit fails with
/// the file as it was. `NoSpace` here takes the same commit, grow and retry
/// path as an allocation that failed. Free space in pieces can still fail a
/// later step, as it can a later extent in Linux; what the earlier steps
/// allocated then stays.
async fn prealloc_fits<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    offset: u64,
    end: u64,
    zero: bool,
) -> Result<(), FsError> {
    ensure_private_subvol(vol).await?;
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let ss = u64::from(vol.sectorsize());
    let (a, b) = (offset - offset % ss, align_up(end, ss));
    let (fa, fb) = (align_up(offset, ss), end - end % ss);
    let (fs_root, _) = vol.fs_tree_root();
    // A zero-range below EOF replaces every whole sector of its range,
    // covered or not; otherwise only what nothing covers is allocated.
    let needed = if zero && offset < inode.size && fa < fb {
        uncovered_bytes(vol, fs_root, ino, a, fa).await?
            + (fb - fa)
            + uncovered_bytes(vol, fs_root, ino, fb, b).await?
    } else {
        uncovered_bytes(vol, fs_root, ino, a, b).await?
    };
    if needed == 0 {
        return Ok(());
    }
    let guard = batch_begin(vol).await?;
    let batch = guard.as_ref().ok_or(FsError::InvalidData)?;
    if batch.alloc.free_bytes(format::BLOCK_GROUP_DATA) < needed {
        return Err(FsError::NoSpace);
    }
    Ok(())
}

/// The first extent item of `ino` a scan of the file from `from` has to
/// look at: the one at or before `from`, which may reach past it.
async fn scan_start<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
    from: u64,
) -> Result<BtrfsKey, FsError> {
    let ceiling = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, from.saturating_add(1));
    let start = match btree::last_before(vol, fs_root, &ceiling).await? {
        Some((key, _)) if key.objectid == ino && key.item_type == format::EXTENT_DATA_KEY => {
            key.offset
        }
        _ => from,
    };
    Ok(BtrfsKey::new(ino, format::EXTENT_DATA_KEY, start))
}

/// Bytes of `[from, to)` (sector aligned) that no extent covers. An
/// explicit hole item covers nothing; an inline item covers its sector.
async fn uncovered_bytes<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
    from: u64,
    to: u64,
) -> Result<u64, FsError> {
    if from >= to {
        return Ok(0);
    }
    let ss = u64::from(vol.sectorsize());
    let first = scan_start(vol, fs_root, ino, from).await?;
    let mut cursor = btree::Cursor::seek(vol, fs_root, &first).await?;
    let (mut at, mut sum) = (from, 0u64);
    while let Some((key, body)) = cursor.current()? {
        if key.objectid != ino || key.item_type != format::EXTENT_DATA_KEY || key.offset >= to {
            break;
        }
        let item = FileItem::decode(key, body.to_vec())?;
        if item.kind != Kind::Hole {
            let covered_to = match item.kind {
                Kind::Inline => align_up(item.end, ss),
                _ => item.end,
            };
            if item.start > at {
                sum += item.start - at;
            }
            at = at.max(covered_to);
            if at >= to {
                return Ok(sum);
            }
        }
        cursor.advance().await?;
    }
    Ok(sum + (to - at))
}

/// What one preallocating step does, from a scan of the file that stops
/// where the step is full.
struct FillPlan {
    /// Uncovered ranges, ascending.
    ranges: Vec<(u64, u64)>,
    /// The explicit hole items met.
    holes: Vec<FileItem>,
    /// Where the next step starts, once the ranges are allocated: the end of
    /// the scan, or of the last range if the step filled up first.
    reach: u64,
}

/// Plan a preallocating step over `[from, to)`: the stretches no extent
/// covers (holes, with an item or without), in order, until they come to
/// [`super::DEALLOC_STEP_EXTENTS`] extents of [`MAX_PREALLOC_EXTENT`]. Reads
/// the extent items as far as the plan goes, not the rest of the range.
async fn plan_fill<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ino: u64,
    from: u64,
    to: u64,
) -> Result<FillPlan, FsError> {
    let mut plan = FillPlan {
        ranges: Vec::new(),
        holes: Vec::new(),
        reach: to,
    };
    if from >= to {
        return Ok(plan);
    }
    let mut budget = super::DEALLOC_STEP_EXTENTS as u64;
    let first = scan_start(vol, fs_root, ino, from).await?;
    let mut cursor = btree::Cursor::seek(vol, fs_root, &first).await?;
    // Everything in `[from, at)` is covered or planned.
    let mut at = from;
    loop {
        let item = match cursor.current()? {
            Some((key, body))
                if key.objectid == ino
                    && key.item_type == format::EXTENT_DATA_KEY
                    && key.offset < to =>
            {
                Some(FileItem::decode(key, body.to_vec())?)
            }
            _ => None,
        };
        // The uncovered stretch up to the next covering item, or to the end.
        let (gap_end, covered_to) = match item {
            Some(item) if item.kind == Kind::Hole => {
                if item.end > at {
                    plan.holes.push(item);
                }
                cursor.advance().await?;
                continue;
            }
            Some(item) => (item.start.clamp(at, to), Some(item.end)),
            None => (to, None),
        };
        if gap_end > at {
            let len = (gap_end - at).min(budget * MAX_PREALLOC_EXTENT);
            plan.ranges.push((at, at + len));
            budget -= len.div_ceil(MAX_PREALLOC_EXTENT);
            at += len;
            if at < gap_end || budget == 0 {
                plan.reach = at;
                return Ok(plan);
            }
        }
        match covered_to {
            Some(end) => at = at.max(end),
            None => return Ok(plan),
        }
        if at >= to {
            return Ok(plan);
        }
        cursor.advance().await?;
    }
}

/// One step of preallocating `[offset, end)` (`btrfs_fallocate` →
/// `btrfs_prealloc_file_range`), from `from` on (`None`: from the start of
/// the range): at most [`super::DEALLOC_STEP_EXTENTS`] PREALLOC extents over
/// the next stretches nothing covers, the explicit hole items there giving
/// way to them, and, unless `keep`, the file's size following to where the
/// step reached. Returns where the next step starts, `None` when the range
/// is done.
///
/// Everything is read from the tree as it is — whether the file is still
/// inline, whether the size is about to pass a partial last sector, whether
/// holes are owed between the old EOF and the range — so a step that is
/// retried, or an operation that starts over after the filesystem grew,
/// goes on from what is already allocated.
async fn prealloc_step<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    offset: u64,
    end: u64,
    keep: bool,
    from: Option<u64>,
) -> Result<Option<u64>, FsError> {
    ensure_private_subvol(vol).await?;
    let inode = InodeItem::decode(&inode_body(vol, ino).await?)?;
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let ss = u64::from(vol.sectorsize());
    let old_size = inode.size;
    let (a, b) = (offset - offset % ss, align_up(end, ss));
    let grows = !keep && end > old_size;
    if b > ss {
        uninline(vol, ino).await?;
    }
    // Growing past a partial old last sector exposes its tail.
    if grows && old_size % ss != 0 {
        let sector_end = align_up(old_size, ss);
        zero_if_dirty(vol, ino, old_size, sector_end.min(end), sector_end).await?;
    }
    let (fs_root, _) = vol.fs_tree_root();
    let mut extra = Vec::new();
    // `btrfs_cont_expand`: explicit holes between the old EOF and the range.
    let old_end = align_up(old_size, ss);
    if grows && !no_holes(vol) && old_end < a {
        let between = file_items_in(vol, fs_root, ino, old_end, a).await?;
        let gen = batch_gen(vol).await?;
        extra.extend(hole_edits(&between, old_end, a, ino, gen));
    }
    let mut cur = from.unwrap_or(a);
    // A (still) inline file owns its whole first sector: Linux's extent map
    // reports the inline extent as `[0, sectorsize)`, so `btrfs_fallocate`
    // finds nothing to preallocate there. Preallocating from the inline
    // item's byte length instead would put a sector-unaligned PREALLOC
    // extent beside the inline one, which `btrfs check` rejects.
    if cur < ss
        && file_items_in(vol, fs_root, ino, 0, ss)
            .await?
            .iter()
            .any(|i| i.kind == Kind::Inline)
    {
        cur = ss;
    }
    let b = b.max(cur);
    let plan = plan_fill(vol, fs_root, ino, cur, b).await?;
    let size_moves = grows && plan.reach.min(end) > old_size;
    if plan.ranges.is_empty() && extra.is_empty() && !size_moves {
        return Ok(None);
    }
    let reach = stage_fill(
        vol,
        ino,
        Carve::default(),
        extra,
        Some(Fill {
            ranges: &plan.ranges,
            holes: &plan.holes,
            from: cur,
            reach: plan.reach,
            grow_to: grows.then_some(end),
        }),
        None,
        false,
    )
    .await?;
    Ok((reach < b).then_some(reach))
}
