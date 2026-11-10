//! Tree-log replay at mount: Linux `btrfs_recover_log_trees`
//! (`fs/btrfs/tree-log.c`), function for function.
//!
//! A tree log is an overlay on the last committed transaction. The log root
//! tree (`super.log_root`) holds one `ROOT_ITEM` per subvolume that was
//! fsynced; each names a log tree whose items are keyed like that
//! subvolume's own. Replay applies them in the stages Linux does:
//!
//! 0. **Pin** (`LOG_WALK_PIN_ONLY`, `process_one_buffer`). Every block of
//!    every log tree, and every data extent a logged file-extent item names,
//!    is withheld from allocation (`tree_log::LogCore::pin`) before the
//!    first block is allocated: neither is recorded in the extent or
//!    free-space tree. All log items are read into memory here.
//! 1. **Inodes** (`LOG_WALK_REPLAY_INODES`). Per logged `INODE_ITEM` with a
//!    link count: xattrs missing from the log are deleted
//!    (`replay_xattr_deletes`), directory entries inside a logged
//!    `DIR_LOG_INDEX` range but absent from the log are unlinked
//!    (`replay_dir_deletes`), the inode item is written (`overwrite_item`,
//!    with its `nbytes`/`size`/`generation == 0` rules) and a regular file's
//!    extents beyond its size are dropped.
//! 2. **Directory indexes** (`LOG_WALK_REPLAY_DIR_INDEX`, `replay_one_name`).
//! 3. **Everything else** (`LOG_WALK_REPLAY_ALL`): xattrs, inode references
//!    (`add_inode_ref`: names are linked into, and stale names unlinked from,
//!    their directories) and file extents (`replay_one_extent`: overlapped
//!    ranges dropped with their references, the logged item inserted, and
//!    its disk extent either given another reference or allocated — extent
//!    item, block-group and free-space accounting, checksums from the log's
//!    csum items).
//! 4. **Link counts** (`fixup_inode_link_counts`): every inode a stage
//!    touched gets the link count its back references add up to; one left
//!    with none becomes an orphan (a directory is emptied first).
//!
//! The whole replay is one transaction, as in Linux: nothing commits until
//! the last stage is done (`LogCore::begin_replay`), and the commit that
//! makes it durable is the one that clears `super.log_root`
//! (`tree_log::on_commit`). A crash at any point before that superblock
//! leaves the log exactly as it was, to be replayed again by NARF or by
//! Linux. A replay that cannot complete aborts the filesystem without having
//! written a superblock.
//!
//! Differences from Linux, all fail-closed: a log naming a subvolume whose
//! tree is still shared with a snapshot root, a directory entry or back
//! reference pointing at another subvolume, and a name collision Linux would
//! resolve by a partial insert are refused (`Unsupported` / `InvalidData`)
//! and the mount fails with the log intact. A directory left without links
//! is removed during replay instead of through an orphan item, the state
//! Linux reaches by orphan cleanup in the same mount.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::fileops::{self, Kind};
use super::{
    align_up, batch_begin, batch_stage_refs, dir_item_body, inode_ref, inode_ref_remove,
    metadata_root_refcount, qgroup_begin_op, touch_times, DataRef, DataRefId, Edit, HDR_GENERATION,
    HDR_OWNER,
};
use crate::btree;
use crate::checksum::{crc32c, name_hash};
use crate::format::{self, le16, le32, le64, BtrfsKey};
use crate::roots;
use crate::volume::BtrfsVolume;

/// `BTRFS_INODE_EXTREF_KEY`.
const INODE_EXTREF_KEY: u8 = 13;

// `struct btrfs_inode_item` offsets.
const II_GENERATION: usize = 0;
const II_TRANSID: usize = 8;
const II_SIZE: usize = 16;
const II_NBYTES: usize = 24;
const II_NLINK: usize = 40;
const II_MODE: usize = 52;
const II_SEQUENCE: usize = 72;
const INODE_ITEM_SIZE: usize = 160;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

// `struct btrfs_file_extent_item` offsets.
const FE_RAM_BYTES: usize = 8;
const FE_COMPRESSION: usize = 16;
const FE_TYPE: usize = 20;
const FE_DISK_BYTENR: usize = 21;
const FE_DISK_NUM: usize = 29;
const FE_OFFSET: usize = 37;
const FE_NUM_BYTES: usize = 45;
const FE_REG_SIZE: usize = 53;

// `struct btrfs_root_item` offsets.
const RI_GENERATION: usize = 160;
const RI_BYTENR: usize = 176;
const RI_LEVEL: usize = 238;

/// `struct btrfs_dir_item` header: location key, transid, data_len,
/// name_len, type.
const DIR_HEADER: usize = 30;

/// A log (or the subvolume under it) that replay cannot make sense of:
/// say what, once, on the console; the mount fails with the log in place.
fn bad(what: &str) -> FsError {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "btrfs: log replay: {what}");
    FsError::InvalidData
}

fn inode_key(ino: u64) -> BtrfsKey {
    BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0)
}

fn mode_of(inode: &[u8]) -> Result<u32, FsError> {
    le32(inode, II_MODE)
}

fn is_dir(inode: &[u8]) -> Result<bool, FsError> {
    Ok(mode_of(inode)? & S_IFMT == S_IFDIR)
}

fn is_reg(inode: &[u8]) -> Result<bool, FsError> {
    Ok(mode_of(inode)? & S_IFMT == S_IFREG)
}

fn put64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// `btrfs_inode_type`: the `BTRFS_FT_*` of a directory entry naming an inode
/// of `mode`.
fn ftype_of_mode(mode: u32) -> u8 {
    match mode & S_IFMT {
        0o100000 => format::FT_REG_FILE,
        0o040000 => format::FT_DIR,
        0o020000 => format::FT_CHRDEV,
        0o060000 => format::FT_BLKDEV,
        0o010000 => format::FT_FIFO,
        0o140000 => format::FT_SOCK,
        0o120000 => format::FT_SYMLINK,
        _ => 0,
    }
}

/// `btrfs_extref_hash`.
fn extref_hash(parent: u64, name: &[u8]) -> u64 {
    u64::from(crc32c(parent as u32, name))
}

/// One `btrfs_dir_item` of a packed item body, undecoded: names are bytes.
struct RawDirEntry<'a> {
    location: BtrfsKey,
    ftype: u8,
    name: &'a [u8],
    /// The whole record, header to the end of its data.
    record: &'a [u8],
}

fn dir_entries(body: &[u8]) -> Result<Vec<RawDirEntry<'_>>, FsError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < DIR_HEADER {
            return Err(FsError::InvalidData);
        }
        let location = BtrfsKey::decode(body, pos)?;
        let data_len = le16(body, pos + 25)? as usize;
        let name_len = le16(body, pos + 27)? as usize;
        let ftype = body[pos + 29];
        let name_end = pos + DIR_HEADER + name_len;
        let end = name_end + data_len;
        let record = body.get(pos..end).ok_or(FsError::InvalidData)?;
        out.push(RawDirEntry {
            location,
            ftype,
            name: &record[DIR_HEADER..DIR_HEADER + name_len],
            record,
        });
        pos = end;
    }
    Ok(out)
}

/// The entry named `name` in a packed dir-item body.
fn dir_find<'a>(body: &'a [u8], name: &[u8]) -> Result<Option<RawDirEntry<'a>>, FsError> {
    Ok(dir_entries(body)?.into_iter().find(|e| e.name == name))
}

/// `body` without the entry named `name`.
fn dir_without(body: &[u8], name: &[u8]) -> Result<Vec<u8>, FsError> {
    let mut out = Vec::with_capacity(body.len());
    for e in dir_entries(body)? {
        if e.name != name {
            out.extend_from_slice(e.record);
        }
    }
    Ok(out)
}

/// The entries `(index, name)` of an `INODE_REF` item body.
fn ref_entries(body: &[u8]) -> Result<Vec<(u64, &[u8])>, FsError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let index = le64(body, pos)?;
        let len = le16(body, pos + 8)? as usize;
        let name = body
            .get(pos + 10..pos + 10 + len)
            .ok_or(FsError::InvalidData)?;
        out.push((index, name));
        pos += 10 + len;
    }
    Ok(out)
}

/// One entry of an `INODE_EXTREF` item: `(parent, index, name)`.
type ExtRef<'a> = (u64, u64, &'a [u8]);

/// The entries of an `INODE_EXTREF` item body.
fn extref_entries(body: &[u8]) -> Result<Vec<ExtRef<'_>>, FsError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let parent = le64(body, pos)?;
        let index = le64(body, pos + 8)?;
        let len = le16(body, pos + 16)? as usize;
        let name = body
            .get(pos + 18..pos + 18 + len)
            .ok_or(FsError::InvalidData)?;
        out.push((parent, index, name));
        pos += 18 + len;
    }
    Ok(out)
}

/// One name of an inode, from either back-reference item form.
struct LoggedRef {
    parent: u64,
    index: u64,
    name: Vec<u8>,
}

fn logged_refs(key: &BtrfsKey, body: &[u8]) -> Result<Vec<LoggedRef>, FsError> {
    if key.item_type == INODE_EXTREF_KEY {
        Ok(extref_entries(body)?
            .into_iter()
            .map(|(parent, index, name)| LoggedRef {
                parent,
                index,
                name: name.to_vec(),
            })
            .collect())
    } else {
        Ok(ref_entries(body)?
            .into_iter()
            .map(|(index, name)| LoggedRef {
                parent: key.offset,
                index,
                name: name.to_vec(),
            })
            .collect())
    }
}

/// The items of one log tree, by key.
type LogItems = BTreeMap<BtrfsKey, Vec<u8>>;

/// Read the log tree rooted at `(root, level)` into `items`, recording every
/// block it occupies. Each block must be a log-tree block of generation
/// `gen` (Linux reads the log with `check.transid = fs_info->generation + 1`
/// and `check.owner_root = BTRFS_TREE_LOG_OBJECTID`).
async fn read_log_tree<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    level: u8,
    gen: u64,
    blocks: &mut Vec<u64>,
    items: &mut LogItems,
) -> Result<(), FsError> {
    let mut stack = alloc::vec![(root, level)];
    while let Some((addr, expect_level)) = stack.pop() {
        let node = vol.read_node(addr).await?;
        if le64(&node, HDR_OWNER)? != format::TREE_LOG_OBJECTID
            || le64(&node, HDR_GENERATION)? != gen
            || btree::level(&node)? != expect_level
        {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "btrfs: log replay: block {addr:#x}: owner {:#x} generation {} level {}, expected a level-{expect_level} log block of generation {gen}",
                le64(&node, HDR_OWNER)?,
                le64(&node, HDR_GENERATION)?,
                btree::level(&node)?
            );
            return Err(bad(
                "a log tree block has the wrong owner, generation or level",
            ));
        }
        blocks.push(addr);
        let n = btree::nritems(&node)? as usize;
        if expect_level == 0 {
            for i in 0..n {
                items.insert(
                    btree::leaf_item_key(&node, i)?,
                    btree::leaf_item_data(&node, i)?.to_vec(),
                );
            }
        } else {
            for i in (0..n).rev() {
                stack.push((btree::internal_blockptr(&node, i)?, expect_level - 1));
            }
        }
    }
    Ok(())
}

/// The disk extents the file-extent items of `items` name.
fn logged_data_extents(items: &LogItems) -> Result<Vec<(u64, u64)>, FsError> {
    let mut out = Vec::new();
    for (key, body) in items {
        if key.item_type != format::EXTENT_DATA_KEY || body.len() <= FE_TYPE {
            continue;
        }
        if body[FE_TYPE] == format::FILE_EXTENT_INLINE {
            continue;
        }
        if body.len() < FE_REG_SIZE {
            return Err(FsError::InvalidData);
        }
        let bytenr = le64(body, FE_DISK_BYTENR)?;
        if bytenr != 0 {
            out.push((bytenr, le64(body, FE_DISK_NUM)?));
        }
    }
    Ok(out)
}

/// If the superblock names an unreplayed tree log, replay it into the
/// subvolume trees, commit, and clear the pointer — `btrfs_recover_log_trees`,
/// run once at mount before anything else writes. Returns whether a log was
/// replayed.
pub async fn replay_log<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<bool, FsError> {
    let sb = vol.superblock();
    if sb.log_root == 0 {
        return Ok(false);
    }
    if !vol.supports_writes() {
        return Err(FsError::Unsupported);
    }
    let _op = vol.op_lock().lock().await;
    let gen = sb.generation.checked_add(1).ok_or(FsError::InvalidData)?;

    // Stage 0: read the whole log and pin what it occupies.
    let mut blocks = Vec::new();
    let mut root_items = LogItems::new();
    read_log_tree(
        vol,
        sb.log_root,
        sb.log_root_level,
        gen,
        &mut blocks,
        &mut root_items,
    )
    .await?;
    let mut trees: Vec<(u64, LogItems)> = Vec::new();
    // Linux walks the log roots from the highest subvolume id down.
    for (key, item) in root_items.iter().rev() {
        if key.objectid != format::TREE_LOG_OBJECTID || key.item_type != format::ROOT_ITEM_KEY {
            return Err(bad(
                "the log root tree holds something other than log roots",
            ));
        }
        if item.len() <= RI_LEVEL || le64(item, RI_GENERATION)? != gen {
            return Err(bad("a log root item is short or of another generation"));
        }
        let mut items = LogItems::new();
        read_log_tree(
            vol,
            le64(item, RI_BYTENR)?,
            item[RI_LEVEL],
            gen,
            &mut blocks,
            &mut items,
        )
        .await?;
        trees.push((key.offset, items));
    }
    let nodesize = vol.nodesize() as u64;
    for &addr in &blocks {
        vol.tree_log.pin(addr, nodesize);
    }
    for (_, items) in &trees {
        for (bytenr, len) in logged_data_extents(items)? {
            vol.tree_log.pin(bytenr, len);
        }
    }

    vol.tree_log.begin_replay();
    let applied = {
        let _hold = vol.hold_commits();
        apply(vol, gen, &trees).await
    };
    if let Err(error) = applied {
        // Nothing of the replay is durable: its tree blocks are referenced
        // by no superblock. Refuse every later write so nothing ever commits
        // the half-applied trees; the log stays for the next mount.
        vol.abort_transaction();
        vol.tree_log.end_replay();
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "btrfs: log replay failed ({error:?}); the log is left in place"
        );
        return Err(error);
    }
    vol.tree_log.finish_replay();
    let finished = finish(vol).await;
    vol.tree_log.end_replay();
    finished?;
    vol.clear_log_root();
    Ok(true)
}

/// Commit the replay and make sure the superblock on disk no longer names
/// the log (step 4 of `btrfs_recover_log_trees`).
async fn finish<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<(), FsError> {
    vol.sync_to_disk().await?;
    // A log whose items all matched the committed trees staged nothing, so
    // no commit ran: clear the pointer in the superblock as it stands.
    let mut raw = vol.read_raw_superblock().await?;
    if le64(&raw, format::OFF_LOG_ROOT)? != 0 {
        super::tree_log::on_commit(vol, &mut raw)?;
        crate::checksum::stamp_block(vol.csum_type(), &mut raw)?;
        vol.write_superblock(&raw).await?;
        vol.unpin_all();
    }
    Ok(())
}

async fn apply<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    gen: u64,
    trees: &[(u64, LogItems)],
) -> Result<(), FsError> {
    let (root_tree, _) = vol.root_tree_root();
    for (root_id, items) in trees {
        // A subvolume deleted after it was logged: Linux skips its log.
        let (root, level, flags) = match roots::find_root_with_flags(vol, root_tree, *root_id).await
        {
            Ok(found) => found,
            Err(FsError::NotFound) => continue,
            Err(error) => return Err(error),
        };
        let view = BtrfsVolume::view_for_replay(vol.core(), *root_id, root, level, flags);
        replay_root(&view, gen, *root_id, items).await?;
    }
    Ok(())
}

async fn replay_root<B: BlockDevice + 'static>(
    view: &Arc<BtrfsVolume<B>>,
    gen: u64,
    root_id: u64,
    log: &LogItems,
) -> Result<(), FsError> {
    if !view.supports_writes() {
        return Err(FsError::Unsupported);
    }
    // Every write path privatises a tree still shared with a snapshot root
    // first, in a transaction of its own. Replay has to stay one
    // transaction, so such a tree is refused instead.
    let (root, level) = view.fs_tree_root();
    let header = view.read_node(root).await?;
    if le64(&header, HDR_OWNER)? != root_id
        || metadata_root_refcount(view, root, level, root_id).await? != 1
    {
        return Err(FsError::Unsupported);
    }

    let mut replay = Replay {
        vol: view,
        log,
        gen,
        fixup: BTreeSet::new(),
    };
    // `wc->ignore_cur_inode`: an inode logged with no links, and whatever
    // follows it in key order up to the next inode item, is skipped.
    let mut active: Vec<(&BtrfsKey, &Vec<u8>)> = Vec::new();
    let mut ignore = false;
    for (key, body) in log {
        if key.item_type == format::INODE_ITEM_KEY {
            if body.len() < INODE_ITEM_SIZE {
                return Err(FsError::InvalidData);
            }
            ignore = le32(body, II_NLINK)? == 0;
        }
        if !ignore {
            active.push((key, body));
        }
    }

    for (key, body) in &active {
        if key.item_type == format::INODE_ITEM_KEY {
            replay.replay_inode(key.objectid, body).await?;
        }
    }
    for (key, body) in &active {
        if key.item_type == format::DIR_INDEX_KEY {
            replay.replay_dir_index(key, body).await?;
        }
    }
    for (key, body) in &active {
        match key.item_type {
            format::XATTR_ITEM_KEY => replay.overwrite(key, body).await?,
            format::INODE_REF_KEY | INODE_EXTREF_KEY => replay.add_inode_ref(key, body).await?,
            format::EXTENT_DATA_KEY => replay.replay_one_extent(key, body).await?,
            _ => {}
        }
    }
    replay.fixup_inode_link_counts().await
}

struct Replay<'a, B: BlockDevice + 'static> {
    vol: &'a Arc<BtrfsVolume<B>>,
    log: &'a LogItems,
    gen: u64,
    /// Linux's fixup directory (`BTRFS_TREE_LOG_FIXUP_OBJECTID` orphan
    /// items): inodes whose link count is recomputed at the end.
    fixup: BTreeSet<u64>,
}

impl<B: BlockDevice + 'static> Replay<'_, B> {
    fn root(&self) -> u64 {
        self.vol.fs_tree_root().0
    }

    async fn get(&self, key: &BtrfsKey) -> Result<Option<Vec<u8>>, FsError> {
        btree::find_item(self.vol, self.root(), key).await
    }

    async fn inode(&self, ino: u64) -> Result<Option<Vec<u8>>, FsError> {
        match self.get(&inode_key(ino)).await? {
            Some(body) if body.len() < INODE_ITEM_SIZE => Err(FsError::InvalidData),
            other => Ok(other),
        }
    }

    /// Stage one replay step into the replay's transaction. No retry and no
    /// quota reservation: a replay that does not fit even in the global
    /// reserve fails as a whole.
    async fn stage(
        &self,
        edits: &[Edit],
        dropped: Vec<DataRefId>,
        added: Vec<DataRefId>,
        new_data: Vec<DataRef>,
    ) -> Result<(), FsError> {
        if edits.is_empty() {
            return Ok(());
        }
        let mut guard = batch_begin(self.vol).await?;
        let batch = guard.as_mut().ok_or(FsError::InvalidData)?;
        if batch.gen != self.gen {
            return Err(FsError::InvalidData);
        }
        qgroup_begin_op(batch);
        // Linux replays in a transaction with no reservation of its own
        // (`btrfs_start_transaction(root, 0)`), on the global block reserve.
        batch.op_reclaims = true;
        batch_stage_refs(self.vol, batch, edits, dropped, added, new_data).await
    }

    // ── overwrite_item ─────────────────────────────────────────────

    /// `overwrite_item` for a non-inode item: copy it into the subvolume.
    async fn overwrite(&self, key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
        if self.get(key).await?.as_deref() == Some(body) {
            return Ok(());
        }
        self.stage(
            &[Edit::Upsert(*key, body.to_vec())],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    /// `overwrite_item` for an inode item.
    async fn overwrite_inode(&self, ino: u64, logged: &[u8]) -> Result<(), FsError> {
        let mut src = logged.to_vec();
        let key = inode_key(ino);
        let body = match self.inode(ino).await? {
            Some(dst) if dst == src => return Ok(()),
            Some(mut dst) => {
                if dst.len() == src.len() {
                    // The extents replayed later adjust `nbytes` from what
                    // the subvolume has; a directory's size follows the names
                    // replay adds and removes.
                    let nbytes = le64(&dst, II_NBYTES)?;
                    put64(&mut src, II_NBYTES, nbytes);
                    if is_dir(&src)? {
                        put64(&mut src, II_SIZE, 0);
                    }
                }
                if le64(&src, II_GENERATION)? == 0 {
                    // Logged only to say the inode exists: keep the
                    // subvolume's item, except a regular file's size.
                    let size = le64(&src, II_SIZE)?;
                    if !(is_reg(&src)? && is_reg(&dst)? && size != 0) {
                        return Ok(());
                    }
                    put64(&mut dst, II_SIZE, size);
                    dst
                } else {
                    if is_dir(&src)? && is_dir(&dst)? {
                        let size = le64(&dst, II_SIZE)?;
                        put64(&mut src, II_SIZE, size);
                    }
                    src
                }
            }
            None => {
                put64(&mut src, II_NBYTES, 0);
                if is_dir(&src)? {
                    put64(&mut src, II_SIZE, 0);
                }
                if le64(&src, II_GENERATION)? == 0 {
                    put64(&mut src, II_GENERATION, self.gen);
                }
                src
            }
        };
        self.stage(
            &[Edit::Upsert(key, body)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    // ── Stage 1: inodes ────────────────────────────────────────────

    async fn replay_inode(&mut self, ino: u64, logged: &[u8]) -> Result<(), FsError> {
        self.replay_xattr_deletes(ino).await?;
        if is_dir(logged)? {
            self.replay_dir_deletes(ino, false).await?;
        }
        self.overwrite_inode(ino, logged).await?;
        if is_reg(logged)? {
            // Truncate to the inode's size now: prealloc extents beyond it
            // that the log carries are replayed afterwards.
            let inode = self.inode(ino).await?.ok_or(FsError::InvalidData)?;
            let sectorsize = u64::from(self.vol.sectorsize());
            let from = align_up(le64(&inode, II_SIZE)?, sectorsize);
            let drop = self.drop_extents(ino, from, u64::MAX).await?;
            if !drop.edits.is_empty() {
                let mut inode = inode;
                let nbytes = le64(&inode, II_NBYTES)?.saturating_sub(drop.removed_nbytes);
                put64(&mut inode, II_NBYTES, nbytes);
                let mut edits = drop.edits;
                edits.push(Edit::Upsert(inode_key(ino), inode));
                self.stage(&edits, drop.dropped, drop.added, Vec::new())
                    .await?;
            }
        }
        self.fixup.insert(ino);
        Ok(())
    }

    /// `replay_xattr_deletes`: an xattr of the subvolume's inode that the
    /// log does not have was deleted before the fsync.
    async fn replay_xattr_deletes(&self, ino: u64) -> Result<(), FsError> {
        let items = btree::collect_for(self.vol, self.root(), ino, format::XATTR_ITEM_KEY).await?;
        let mut edits = Vec::new();
        for (key, body) in items {
            let mut kept = Vec::with_capacity(body.len());
            for entry in dir_entries(&body)? {
                let log_key = BtrfsKey::new(
                    ino,
                    format::XATTR_ITEM_KEY,
                    u64::from(name_hash(entry.name)),
                );
                let in_log = match self.log.get(&log_key) {
                    Some(logged) => dir_find(logged, entry.name)?.is_some(),
                    None => false,
                };
                if in_log {
                    kept.extend_from_slice(entry.record);
                }
            }
            if kept.len() == body.len() {
                continue;
            }
            edits.push(if kept.is_empty() {
                Edit::Delete(key)
            } else {
                Edit::Upsert(key, kept)
            });
        }
        self.stage(&edits, Vec::new(), Vec::new(), Vec::new()).await
    }

    /// `replay_dir_deletes`: unlink the entries of `dir` whose index lies in
    /// a range the log is authoritative for (`DIR_LOG_INDEX`, or everything
    /// when `del_all`) and that the log does not hold (`check_item_in_log`).
    async fn replay_dir_deletes(&mut self, dir: u64, del_all: bool) -> Result<(), FsError> {
        if self.inode(dir).await?.is_none() {
            return Ok(());
        }
        let ranges: Vec<(u64, u64)> = if del_all {
            alloc::vec![(0, u64::MAX)]
        } else {
            let mut ranges = Vec::new();
            let lo = BtrfsKey::new(dir, format::DIR_LOG_INDEX_KEY, 0);
            let hi = BtrfsKey::new(dir, format::DIR_LOG_INDEX_KEY, u64::MAX);
            for (key, body) in self.log.range(lo..=hi) {
                if body.len() < 8 {
                    return Err(FsError::InvalidData);
                }
                let end = le64(body, 0)?;
                if end < key.offset {
                    return Err(FsError::InvalidData);
                }
                ranges.push((key.offset, end));
            }
            ranges
        };
        if ranges.is_empty() {
            return Ok(());
        }
        let entries = btree::collect_for(self.vol, self.root(), dir, format::DIR_INDEX_KEY).await?;
        for (key, body) in entries {
            if !ranges
                .iter()
                .any(|&(start, end)| key.offset >= start && key.offset <= end)
            {
                continue;
            }
            let found = dir_entries(&body)?;
            let [entry] = found.as_slice() else {
                return Err(FsError::InvalidData); // a dir index holds one name
            };
            if !del_all {
                let logged = self.log.get(&key);
                if let Some(logged) = logged {
                    if dir_find(logged, entry.name)?.is_some() {
                        continue;
                    }
                }
            }
            let (child, name) = (self.child_of(entry)?, entry.name.to_vec());
            if self.inode(child).await?.is_none() {
                return Err(FsError::InvalidData);
            }
            self.unlink(dir, child, &name).await?;
        }
        Ok(())
    }

    /// The inode a directory entry names. An entry naming another subvolume
    /// cannot be replayed against here.
    fn child_of(&self, entry: &RawDirEntry<'_>) -> Result<u64, FsError> {
        if entry.location.item_type != format::INODE_ITEM_KEY {
            return Err(FsError::Unsupported);
        }
        Ok(entry.location.objectid)
    }

    // ── Names ──────────────────────────────────────────────────────

    /// Whether the log's back-reference item at `key` holds `name` for
    /// `parent` (`backref_in_log`).
    fn backref_in_log(&self, key: &BtrfsKey, parent: u64, name: &[u8]) -> Result<bool, FsError> {
        let Some(body) = self.log.get(key) else {
            return Ok(false);
        };
        Ok(logged_refs(key, body)?
            .iter()
            .any(|r| r.parent == parent && r.name == name))
    }

    /// Remove the back reference `(ino, dir, name)` from the subvolume,
    /// returning the directory index it recorded and the edit that removes
    /// it (`btrfs_del_inode_ref`).
    async fn del_inode_ref(&self, ino: u64, dir: u64, name: &[u8]) -> Result<(u64, Edit), FsError> {
        let ref_key = BtrfsKey::new(ino, format::INODE_REF_KEY, dir);
        if let Some(body) = self.get(&ref_key).await? {
            if ref_entries(&body)?.iter().any(|&(_, n)| n == name) {
                let (index, rest) = inode_ref_remove(&body, name)?;
                let edit = if rest.is_empty() {
                    Edit::Delete(ref_key)
                } else {
                    Edit::Upsert(ref_key, rest)
                };
                return Ok((index, edit));
            }
        }
        let ext_key = BtrfsKey::new(ino, INODE_EXTREF_KEY, extref_hash(dir, name));
        let body = self.get(&ext_key).await?.ok_or(FsError::InvalidData)?;
        let mut index = None;
        let mut rest = Vec::with_capacity(body.len());
        for (parent, idx, n) in extref_entries(&body)? {
            if index.is_none() && parent == dir && n == name {
                index = Some(idx);
                continue;
            }
            rest.extend_from_slice(&parent.to_le_bytes());
            rest.extend_from_slice(&idx.to_le_bytes());
            rest.extend_from_slice(&(n.len() as u16).to_le_bytes());
            rest.extend_from_slice(n);
        }
        let index = index.ok_or(FsError::InvalidData)?;
        let edit = if rest.is_empty() {
            Edit::Delete(ext_key)
        } else {
            Edit::Upsert(ext_key, rest)
        };
        Ok((index, edit))
    }

    /// `unlink_inode_for_log_replay` → `btrfs_unlink_inode`: remove `name`
    /// from `dir` — its `DIR_ITEM` entry, its `DIR_INDEX`, the inode's back
    /// reference — and shrink the directory. The link count is settled by
    /// the fixup pass, which every caller in Linux queues the inode for.
    async fn unlink(&mut self, dir: u64, ino: u64, name: &[u8]) -> Result<(), FsError> {
        self.fixup.insert(ino);
        let item_key = BtrfsKey::new(dir, format::DIR_ITEM_KEY, u64::from(name_hash(name)));
        let bucket = self.get(&item_key).await?.ok_or(FsError::InvalidData)?;
        if dir_find(&bucket, name)?.is_none() {
            return Err(FsError::InvalidData);
        }
        let rest = dir_without(&bucket, name)?;
        let (index, ref_edit) = self.del_inode_ref(ino, dir, name).await?;
        let mut parent = self.inode(dir).await?.ok_or(FsError::InvalidData)?;
        let size = le64(&parent, II_SIZE)?.saturating_sub(2 * name.len() as u64);
        put64(&mut parent, II_SIZE, size);
        put64(&mut parent, II_TRANSID, self.gen);
        let seq = le64(&parent, II_SEQUENCE)?;
        put64(&mut parent, II_SEQUENCE, seq + 1);
        touch_times(&mut parent, true);
        let edits = [
            if rest.is_empty() {
                Edit::Delete(item_key)
            } else {
                Edit::Upsert(item_key, rest)
            },
            Edit::Delete(BtrfsKey::new(dir, format::DIR_INDEX_KEY, index)),
            ref_edit,
            Edit::Upsert(inode_key(dir), parent),
        ];
        self.stage(&edits, Vec::new(), Vec::new(), Vec::new()).await
    }

    /// `btrfs_add_link`: enter `name` → `ino` into `dir` at `index`
    /// (`DIR_ITEM` + `DIR_INDEX`), grow the directory, and with
    /// `add_backref` record the inode's back reference. Parent times are
    /// left alone, as Linux leaves them during log recovery. Returns `false`
    /// without changing anything when the inode already has this name
    /// (`-EEXIST` from the back-reference insert).
    async fn add_link(
        &mut self,
        dir: u64,
        ino: u64,
        name: &[u8],
        index: u64,
        add_backref: bool,
    ) -> Result<bool, FsError> {
        let inode = self.inode(ino).await?.ok_or(FsError::NotFound)?;
        let mut parent = self.inode(dir).await?.ok_or(FsError::NotFound)?;
        let mut edits = Vec::new();
        if add_backref {
            let ref_key = BtrfsKey::new(ino, format::INODE_REF_KEY, dir);
            let mut body = self.get(&ref_key).await?.unwrap_or_default();
            if ref_entries(&body)?.iter().any(|&(_, n)| n == name) {
                return Ok(false);
            }
            body.extend_from_slice(&inode_ref(index, name));
            // Linux moves a name that no longer fits to an INODE_EXTREF.
            if body.len() > self.vol.nodesize() / 4 {
                return Err(FsError::Unsupported);
            }
            edits.push(Edit::Upsert(ref_key, body));
        }
        let item_key = BtrfsKey::new(dir, format::DIR_ITEM_KEY, u64::from(name_hash(name)));
        let index_key = BtrfsKey::new(dir, format::DIR_INDEX_KEY, index);
        let mut bucket = self.get(&item_key).await?.unwrap_or_default();
        // Linux would insert half of the entry and fail; whatever held the
        // name or the index should have been unlinked before this.
        if dir_find(&bucket, name)?.is_some() || self.get(&index_key).await?.is_some() {
            return Err(FsError::InvalidData);
        }
        let record = dir_item_body(ino, self.gen, ftype_of_mode(mode_of(&inode)?), name);
        bucket.extend_from_slice(&record);
        edits.push(Edit::Upsert(item_key, bucket));
        edits.push(Edit::Upsert(index_key, record));
        let size = le64(&parent, II_SIZE)? + 2 * name.len() as u64;
        put64(&mut parent, II_SIZE, size);
        put64(&mut parent, II_TRANSID, self.gen);
        let seq = le64(&parent, II_SEQUENCE)?;
        put64(&mut parent, II_SEQUENCE, seq + 1);
        edits.push(Edit::Upsert(inode_key(dir), parent));
        self.stage(&edits, Vec::new(), Vec::new(), Vec::new())
            .await?;
        Ok(true)
    }

    /// `drop_one_dir_item`: unlink the entry `name` of `dir`, which names
    /// `child`.
    async fn drop_one_dir_item(
        &mut self,
        dir: u64,
        child: u64,
        name: &[u8],
    ) -> Result<(), FsError> {
        if self.inode(child).await?.is_none() {
            return Err(FsError::InvalidData);
        }
        self.unlink(dir, child, name).await
    }

    /// The subvolume's `DIR_ITEM` entry `name` of `dir`: `(location, type)`.
    async fn lookup_dir_item(
        &self,
        dir: u64,
        name: &[u8],
    ) -> Result<Option<(BtrfsKey, u8)>, FsError> {
        let key = BtrfsKey::new(dir, format::DIR_ITEM_KEY, u64::from(name_hash(name)));
        let Some(body) = self.get(&key).await? else {
            return Ok(None);
        };
        Ok(dir_find(&body, name)?.map(|e| (e.location, e.ftype)))
    }

    /// The subvolume's `DIR_INDEX` entry of `dir` at `index`, if it is
    /// `name`.
    async fn lookup_dir_index(
        &self,
        dir: u64,
        index: u64,
        name: &[u8],
    ) -> Result<Option<(BtrfsKey, u8)>, FsError> {
        let key = BtrfsKey::new(dir, format::DIR_INDEX_KEY, index);
        let Some(body) = self.get(&key).await? else {
            return Ok(None);
        };
        Ok(dir_find(&body, name)?.map(|e| (e.location, e.ftype)))
    }

    // ── Stage 2: directory indexes ─────────────────────────────────

    /// `replay_one_dir_item` → `replay_one_name`.
    async fn replay_dir_index(&mut self, key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
        let dir = key.objectid;
        if self.inode(dir).await?.is_none() {
            return Err(FsError::InvalidData);
        }
        let found = dir_entries(body)?;
        let [entry] = found.as_slice() else {
            return Err(FsError::InvalidData);
        };
        let (location, ftype, name) = (entry.location, entry.ftype, entry.name.to_vec());
        // `btrfs_lookup_inode(log_key)`: an entry naming a subvolume root
        // never "exists" as an inode of this tree.
        let exists = location.item_type == format::INODE_ITEM_KEY
            && self.inode(location.objectid).await?.is_some();

        // `delete_conflicting_dir_entry` for the name, then for the index.
        let mut matches = [false, false];
        for (slot, by_index) in [false, true].into_iter().enumerate() {
            let existing = if by_index {
                self.lookup_dir_index(dir, key.offset, &name).await?
            } else {
                self.lookup_dir_item(dir, &name).await?
            };
            let Some((found_location, found_type)) = existing else {
                continue;
            };
            if found_location == location && found_type == ftype {
                matches[slot] = true;
            } else if exists {
                if found_location.item_type != format::INODE_ITEM_KEY {
                    return Err(FsError::Unsupported);
                }
                self.drop_one_dir_item(dir, found_location.objectid, &name)
                    .await?;
            }
        }
        if matches[0] && matches[1] {
            return Ok(());
        }
        // The inode's own back reference is in the log: `add_inode_ref`
        // enters the name in the last stage.
        let ref_key = BtrfsKey::new(location.objectid, format::INODE_REF_KEY, dir);
        let ext_key = BtrfsKey::new(location.objectid, INODE_EXTREF_KEY, extref_hash(dir, &name));
        if self.backref_in_log(&ref_key, dir, &name)?
            || self.backref_in_log(&ext_key, dir, &name)?
        {
            return Ok(());
        }
        // `insert_one_name`: only names of inodes that exist are entered.
        if !exists {
            return Ok(());
        }
        let added = self
            .add_link(dir, location.objectid, &name, key.offset, true)
            .await?;
        if added && ftype != format::FT_DIR {
            self.fixup.insert(location.objectid);
        }
        Ok(())
    }

    // ── Stage 3: back references ───────────────────────────────────

    /// `add_inode_ref`: make the subvolume's names of the inode in one
    /// parent (one `INODE_REF` item) or one hash bucket (`INODE_EXTREF`)
    /// those of the logged item.
    async fn add_inode_ref(&mut self, key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
        let ino = key.objectid;
        let is_extref = key.item_type == INODE_EXTREF_KEY;
        if !is_extref && self.inode(key.offset).await?.is_none() {
            return Ok(()); // the parent is gone: nothing to link into
        }
        if self.inode(ino).await?.is_none() {
            return Err(FsError::InvalidData);
        }
        self.fixup.insert(ino);
        let refs = logged_refs(key, body)?;
        for r in &refs {
            if is_extref && self.inode(r.parent).await?.is_none() {
                continue;
            }
            if self.inode_in_dir(r.parent, ino, r.index, &r.name).await? {
                continue;
            }
            if !self.clear_for_ref(r.parent, ino, r.index, &r.name).await? {
                continue;
            }
            self.add_link(r.parent, ino, &r.name, r.index, false)
                .await?;
        }
        // `unlink_old_inode_refs`: names the subvolume's item at this key
        // still has that the logged one does not.
        while let Some(existing) = self.get(key).await? {
            let stale = logged_refs(key, &existing)?.into_iter().find(|old| {
                !refs
                    .iter()
                    .any(|r| r.parent == old.parent && r.name == old.name)
            });
            let Some(stale) = stale else {
                break;
            };
            if self.inode(stale.parent).await?.is_none() {
                return Err(FsError::InvalidData);
            }
            self.unlink(stale.parent, ino, &stale.name).await?;
        }
        self.overwrite(key, body).await
    }

    /// `inode_in_dir`: whether `dir` already names `ino` as `name` at
    /// `index`.
    async fn inode_in_dir(
        &self,
        dir: u64,
        ino: u64,
        index: u64,
        name: &[u8],
    ) -> Result<bool, FsError> {
        match self.lookup_dir_index(dir, index, name).await? {
            Some((location, _)) if location.objectid == ino => {}
            _ => return Ok(false),
        }
        Ok(matches!(
            self.lookup_dir_item(dir, name).await?,
            Some((location, _)) if location.objectid == ino
        ))
    }

    /// `__add_inode_ref`: unlink what stands in the way of linking `ino`
    /// into `dir` as `name` at `index` — the inode's own names in `dir` that
    /// the log no longer has, and whatever else holds the index or the name.
    /// Returns `false` when there is nothing to add (a subvolume root's own
    /// `..` reference).
    async fn clear_for_ref(
        &mut self,
        dir: u64,
        ino: u64,
        index: u64,
        name: &[u8],
    ) -> Result<bool, FsError> {
        let ref_key = BtrfsKey::new(ino, format::INODE_REF_KEY, dir);
        // `unlink_refs_not_in_log`.
        while let Some(existing) = self.get(&ref_key).await? {
            if ino == dir {
                return Ok(false);
            }
            let mut victim = None;
            for (_, old) in ref_entries(&existing)? {
                if !self.backref_in_log(&ref_key, dir, old)? {
                    victim = Some(old.to_vec());
                    break;
                }
            }
            let Some(victim) = victim else {
                break;
            };
            self.unlink(dir, ino, &victim).await?;
        }
        // `unlink_extrefs_not_in_log`, for the bucket this name hashes to.
        let ext_key = BtrfsKey::new(ino, INODE_EXTREF_KEY, extref_hash(dir, name));
        while let Some(existing) = self.get(&ext_key).await? {
            let mut victim = None;
            for (parent, _, old) in extref_entries(&existing)? {
                if parent != dir {
                    continue;
                }
                let key = BtrfsKey::new(ino, INODE_EXTREF_KEY, extref_hash(dir, old));
                if !self.backref_in_log(&key, dir, old)? {
                    victim = Some(old.to_vec());
                    break;
                }
            }
            let Some(victim) = victim else {
                break;
            };
            self.unlink(dir, ino, &victim).await?;
        }
        if let Some((location, _)) = self.lookup_dir_index(dir, index, name).await? {
            if location.item_type != format::INODE_ITEM_KEY {
                return Err(FsError::Unsupported);
            }
            self.drop_one_dir_item(dir, location.objectid, name).await?;
        }
        if let Some((location, _)) = self.lookup_dir_item(dir, name).await? {
            if location.item_type != format::INODE_ITEM_KEY {
                return Err(FsError::Unsupported);
            }
            self.drop_one_dir_item(dir, location.objectid, name).await?;
        }
        Ok(true)
    }

    // ── Stage 3: file extents ──────────────────────────────────────

    /// `btrfs_drop_extents` for `[a, b)` of `ino`: what to edit and which
    /// extent references go or are added (a split).
    async fn drop_extents(&self, ino: u64, a: u64, b: u64) -> Result<fileops::Carve, FsError> {
        let items = fileops::file_items(self.vol, self.root(), ino).await?;
        let sectorsize = u64::from(self.vol.sectorsize());
        let mut out = fileops::carve(&items, a, b, self.vol.fs_tree_id(), ino, |item| {
            item.kind != Kind::Inline
        })?;
        // An inline extent the range reaches goes whole.
        for item in items.iter().filter(|i| i.kind == Kind::Inline) {
            if item.start < b && align_up(item.end, sectorsize) > a {
                out.edits.push(Edit::Delete(item.key));
                out.removed_nbytes += item.end - item.start;
            }
        }
        Ok(out)
    }

    /// Whether the data extent `(bytenr, len)` already has an extent item:
    /// in the committed extent tree, or born earlier in this replay
    /// (`btrfs_lookup_data_extent`).
    async fn extent_exists(&self, bytenr: u64, len: u64) -> Result<bool, FsError> {
        let born_here = self
            .vol
            .fs_batch()
            .lock()
            .await
            .as_ref()
            .is_some_and(|batch| {
                batch
                    .new_data
                    .iter()
                    .any(|d| d.id.bytenr == bytenr && d.id.len == len)
            });
        if born_here {
            return Ok(true);
        }
        let (root_tree, _) = self.vol.root_tree_root();
        let (ext_root, _) =
            roots::find_root(self.vol, root_tree, format::EXTENT_TREE_OBJECTID).await?;
        let key = BtrfsKey::new(bytenr, format::EXTENT_ITEM_KEY, len);
        if btree::find_item(self.vol, ext_root, &key).await?.is_some() {
            return Ok(true);
        }
        // Not there: then nothing else may occupy any of the range.
        let end = bytenr.checked_add(len).ok_or(FsError::InvalidData)?;
        if let Some((found, _)) =
            btree::last_before(self.vol, ext_root, &BtrfsKey::new(end, 0, 0)).await?
        {
            let found_end = match found.item_type {
                format::EXTENT_ITEM_KEY => found.objectid.saturating_add(found.offset),
                format::METADATA_ITEM_KEY => {
                    found.objectid.saturating_add(self.vol.nodesize() as u64)
                }
                _ => 0,
            };
            if found_end > bytenr {
                return Err(FsError::InvalidData);
            }
        }
        Ok(false)
    }

    /// Hand the checksums the log carries for the range a replayed file
    /// item references to the replay's commit, which puts them in the csum
    /// tree in place of whatever it holds there. The range is the one Linux
    /// looks up: the whole disk extent when compressed, else the referenced
    /// part. A log without checksums for it (`nodatasum`, prealloc) changes
    /// nothing.
    fn replay_csums(&self, body: &[u8], bytenr: u64, len: u64) -> Result<(), FsError> {
        let sectorsize = u64::from(self.vol.sectorsize());
        let width = crate::checksum::size(self.vol.csum_type())?;
        let (start, end) = if body[FE_COMPRESSION] != format::COMPRESS_NONE {
            (bytenr, bytenr + len)
        } else {
            let start = bytenr + le64(body, FE_OFFSET)?;
            (start, start + le64(body, FE_NUM_BYTES)?)
        };
        if end > bytenr + len || start >= end {
            return Err(bad("a logged file extent reaches outside its disk extent"));
        }
        let lo = BtrfsKey::new(format::EXTENT_CSUM_OBJECTID, format::EXTENT_CSUM_KEY, 0);
        let hi = BtrfsKey::new(
            format::EXTENT_CSUM_OBJECTID,
            format::EXTENT_CSUM_KEY,
            end - 1,
        );
        for (key, sums) in self.log.range(lo..=hi) {
            if sums.len() % width != 0 || key.offset % sectorsize != 0 {
                return Err(bad("a logged checksum item is misaligned"));
            }
            for (i, sum) in sums.chunks_exact(width).enumerate() {
                let addr = key.offset + i as u64 * sectorsize;
                if addr >= start && addr < end {
                    self.vol.tree_log.replay_csum(addr, sum);
                }
            }
        }
        Ok(())
    }

    /// `replay_one_extent`.
    async fn replay_one_extent(&self, key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
        let ino = key.objectid;
        let start = key.offset;
        let sectorsize = u64::from(self.vol.sectorsize());
        if body.len() <= FE_TYPE {
            return Err(FsError::InvalidData);
        }
        let inline = match body[FE_TYPE] {
            format::FILE_EXTENT_INLINE => true,
            format::FILE_EXTENT_REG | format::FILE_EXTENT_PREALLOC => {
                if body.len() < FE_REG_SIZE {
                    return Err(FsError::InvalidData);
                }
                false
            }
            _ => return Err(FsError::InvalidData),
        };
        let (extent_end, nbytes) = if inline {
            let ram = le64(body, FE_RAM_BYTES)?;
            (align_up(start + ram, sectorsize), ram)
        } else {
            let num = le64(body, FE_NUM_BYTES)?;
            let held = if le64(body, FE_DISK_BYTENR)? != 0 {
                num
            } else {
                0
            };
            (start.checked_add(num).ok_or(FsError::InvalidData)?, held)
        };
        let mut inode = self.inode(ino).await?.ok_or(FsError::InvalidData)?;

        // The subvolume already points at exactly this extent.
        if !inline {
            if let Some(existing) = self.get(key).await? {
                if existing.get(..FE_REG_SIZE) == Some(&body[..FE_REG_SIZE]) {
                    return Ok(());
                }
            }
        }

        let drop = self.drop_extents(ino, start, extent_end).await?;
        let mut edits = drop.edits;
        let dropped = drop.dropped;
        let mut added = drop.added;
        let mut new_data = Vec::new();
        if inline {
            edits.push(Edit::Upsert(*key, body.to_vec()));
        } else {
            let bytenr = le64(body, FE_DISK_BYTENR)?;
            let no_holes = self.vol.superblock().incompat_flags & format::INCOMPAT_NO_HOLES != 0;
            // A hole needs no item when holes are implicit.
            if bytenr != 0 || !no_holes {
                edits.push(Edit::Upsert(*key, body[..FE_REG_SIZE].to_vec()));
            }
            if bytenr != 0 {
                let len = le64(body, FE_DISK_NUM)?;
                if bytenr % sectorsize != 0 || len == 0 || len % sectorsize != 0 {
                    return Err(FsError::InvalidData);
                }
                let id = DataRefId {
                    bytenr,
                    len,
                    ref_root: self.vol.fs_tree_id(),
                    objectid: ino,
                    offset: start
                        .checked_sub(le64(body, FE_OFFSET)?)
                        .ok_or(FsError::InvalidData)?,
                };
                if self.extent_exists(bytenr, len).await? {
                    // `btrfs_inc_extent_ref`.
                    added.push(id);
                } else {
                    // `btrfs_alloc_logged_file_extent`. Its checksums come
                    // from the log, below, like any replayed range's.
                    new_data.push(DataRef {
                        id,
                        csums: Vec::new(),
                    });
                }
                self.replay_csums(body, bytenr, len)?;
            }
        }
        // `btrfs_update_inode_bytes(inode, nbytes, drop_args.bytes_found)`.
        let held = le64(&inode, II_NBYTES)?
            .saturating_sub(drop.removed_nbytes)
            .checked_add(nbytes)
            .ok_or(FsError::InvalidData)?;
        put64(&mut inode, II_NBYTES, held);
        edits.push(Edit::Upsert(inode_key(ino), inode));
        self.stage(&edits, dropped, added, new_data).await
    }

    // ── Stage 4: link counts ───────────────────────────────────────

    /// How many names the subvolume's back references give `ino`
    /// (`count_inode_refs` + `count_inode_extrefs`).
    async fn count_refs(&self, ino: u64) -> Result<u32, FsError> {
        let mut count = 0usize;
        for (_, body) in
            btree::collect_for(self.vol, self.root(), ino, format::INODE_REF_KEY).await?
        {
            count += ref_entries(&body)?.len();
        }
        for (_, body) in btree::collect_for(self.vol, self.root(), ino, INODE_EXTREF_KEY).await? {
            count += extref_entries(&body)?.len();
        }
        u32::try_from(count).map_err(|_| FsError::InvalidData)
    }

    /// `fixup_inode_link_counts`: highest inode first; emptying a directory
    /// queues its children.
    async fn fixup_inode_link_counts(&mut self) -> Result<(), FsError> {
        while let Some(ino) = self.fixup.pop_last() {
            let Some(mut inode) = self.inode(ino).await? else {
                return Err(FsError::InvalidData);
            };
            let nlink = self.count_refs(ino).await?;
            if nlink != le32(&inode, II_NLINK)? {
                inode[II_NLINK..II_NLINK + 4].copy_from_slice(&nlink.to_le_bytes());
                self.stage(
                    &[Edit::Upsert(inode_key(ino), inode.clone())],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
                .await?;
            }
            if nlink != 0 {
                continue;
            }
            if is_dir(&inode)? {
                // Linux empties the directory and leaves an orphan item for
                // the orphan cleanup later in the same mount to delete it by.
                // The writer's orphan reclaim handles files only, so the
                // emptied directory is deleted here, to the same end state.
                self.replay_dir_deletes(ino, true).await?;
                let mut edits = alloc::vec![Edit::Delete(inode_key(ino))];
                for (key, _) in
                    btree::collect_for(self.vol, self.root(), ino, format::XATTR_ITEM_KEY).await?
                {
                    edits.push(Edit::Delete(key));
                }
                self.stage(&edits, Vec::new(), Vec::new(), Vec::new())
                    .await?;
            } else {
                // `btrfs_insert_orphan_item`; reclaimed after the replay
                // commits (`recover_orphans`).
                self.stage(
                    &[Edit::Upsert(crate::orphans::key(ino), Vec::new())],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
                .await?;
                self.vol.note_orphan(self.vol.fs_tree_id(), ino);
            }
        }
        Ok(())
    }
}
