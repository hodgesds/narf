//! Per-filesystem tree-log state: the space a log on disk occupies, and what
//! a transaction commit owes it.
//!
//! A tree log lives outside the committed trees. Its tree blocks, and the
//! data extents its file-extent items name, are free space as far as the
//! extent and free-space trees know, from the moment the log is written
//! until a commit makes the log obsolete. Linux covers that window in
//! memory: log blocks are allocations of the running transaction that never
//! get an extent item (`btrfs_alloc_tree_block` skips the delayed ref for
//! `BTRFS_TREE_LOG_OBJECTID`), are pinned when the log is freed at commit
//! (`btrfs_free_log` → `btrfs_pin_reserved_extent`), and at mount
//! `btrfs_recover_log_trees` pins every block of the log it is about to
//! replay (`btrfs_pin_extent_for_log_replay`) and excludes the logged data
//! extents (`btrfs_exclude_logged_extents`) before the first allocation.
//!
//! [`LogCore::pins`] is that set. Every allocator subtracts it
//! (`BtrfsVolume::pinned_ranges`), and [`on_commit`] hands it to the ordinary
//! pinned set, which is released only once the superblock that no longer
//! names the log is on the device.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_block::BlockDevice;
use narf_filesystem::FsError;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use super::fileops::{FileItem, Kind};
use super::{
    align_up, alloc_nodes, group_items, normalize_cow_header, pack_leaf, pack_tree_at, reserve,
    tree_block_count, DataRef, FsBatch, LEAF_ITEM_SIZE,
};
use crate::btree::{self, HEADER_SIZE};
use crate::checksum::name_hash;
use crate::format::{self, le32, le64, BtrfsKey};
use crate::roots;
use crate::volume::BtrfsVolume;

/// No log replay is running.
const REPLAY_IDLE: u8 = 0;
/// A replay is applying the log: nothing may commit, because a committed
/// superblock in the middle of a replay would either drop the log with the
/// replay half done or keep a log whose generation no longer follows the
/// superblock's (which Linux refuses to mount).
const REPLAY_APPLYING: u8 = 1;
/// The replay is complete and its one transaction may commit.
const REPLAY_FINISHING: u8 = 2;

/// Tree-log state of one filesystem core.
#[derive(Debug)]
pub(crate) struct LogCore {
    /// Ranges a log on disk references that the committed trees hold free:
    /// its tree blocks and its not-yet-committed data extents.
    pins: IrqSafeSpinLock<Vec<(u64, u64)>>,
    replay: AtomicU8,
    /// Data checksums a running replay took from the log, by sector
    /// address, for the commit that ends the replay to write into the csum
    /// tree ([`take_replayed_csums`]).
    replayed_csums: IrqSafeSpinLock<BTreeMap<u64, Vec<u8>>>,
    /// The logs the running transaction has written (the writer's state).
    state: Mutex<LogState>,
}

impl LogCore {
    pub(crate) fn new() -> Self {
        Self {
            pins: IrqSafeSpinLock::new(Vec::new()),
            replay: AtomicU8::new(REPLAY_IDLE),
            replayed_csums: IrqSafeSpinLock::new(BTreeMap::new()),
            state: Mutex::new(LogState::default()),
        }
    }

    /// The ranges every allocator must leave alone.
    pub(crate) fn pinned(&self) -> Vec<(u64, u64)> {
        self.pins.lock().clone()
    }

    /// Withhold `[start, start + len)` until the next commit's superblock is
    /// durable.
    pub(crate) fn pin(&self, start: u64, len: u64) {
        if len != 0 {
            self.pins.lock().push((start, len));
        }
    }

    /// [`Self::pin`] for a range that may be pinned already.
    fn pin_once(&self, start: u64, len: u64) {
        let mut pins = self.pins.lock();
        if len != 0 && !pins.contains(&(start, len)) {
            pins.push((start, len));
        }
    }

    pub(super) fn begin_replay(&self) {
        self.replayed_csums.lock().clear();
        self.replay.store(REPLAY_APPLYING, Ordering::Release);
    }

    /// Record the logged checksum of the data sector at `addr`.
    pub(super) fn replay_csum(&self, addr: u64, sum: &[u8]) {
        self.replayed_csums.lock().insert(addr, sum.to_vec());
    }

    pub(super) fn finish_replay(&self) {
        self.replay.store(REPLAY_FINISHING, Ordering::Release);
    }

    pub(super) fn end_replay(&self) {
        self.replayed_csums.lock().clear();
        self.replay.store(REPLAY_IDLE, Ordering::Release);
    }

    /// Drop every pin without a commit: the log they protected is gone from
    /// the superblock on disk.
    pub(super) fn release_pins(&self) -> Vec<(u64, u64)> {
        core::mem::take(&mut *self.pins.lock())
    }
}

/// What every transaction commit does for the tree log, on the superblock
/// image `raw` it is about to stage: Linux `btrfs_commit_transaction` zeroes
/// `super_copy->log_root` / `log_root_level` and frees the log trees
/// (`btrfs_free_log`, `btrfs_free_log_root_tree`), whose blocks stay pinned
/// until the superblock is written.
///
/// Fails, and so fails the commit, while a log replay is still applying.
pub(crate) fn on_commit<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    raw: &mut [u8],
) -> Result<(), FsError> {
    let log = &vol.tree_log;
    if log.replay.load(Ordering::Acquire) == REPLAY_APPLYING {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "btrfs: a transaction tried to commit in the middle of a log replay; refusing"
        );
        return Err(FsError::InvalidData);
    }
    raw[format::OFF_LOG_ROOT..format::OFF_LOG_ROOT + 8].copy_from_slice(&0u64.to_le_bytes());
    raw[format::OFF_LOG_ROOT_TRANSID..format::OFF_LOG_ROOT_TRANSID + 8]
        .copy_from_slice(&0u64.to_le_bytes());
    raw[format::OFF_LOG_ROOT_LEVEL] = 0;
    // From here the staged image no longer names the log. Its space joins
    // what this transaction freed: withheld until that image is durable.
    for (start, len) in log.release_pins() {
        vol.pin_extent(start, len);
    }
    Ok(())
}

/// Most checksums one csum item written by replay holds.
const REPLAY_CSUMS_PER_ITEM: usize = 512;

/// The checksums a log replay took from the log, as csum-tree items
/// `(first sector address, packed checksums)` over runs of adjacent
/// sectors. Linux `replay_one_extent` deletes whatever the csum tree holds
/// for each replayed range (`btrfs_del_csums`) and inserts the logged sums
/// (`btrfs_csum_file_blocks`); the commit that ends the replay does both.
pub(crate) fn take_replayed_csums<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
) -> Vec<(u64, Vec<u8>)> {
    let sums = core::mem::take(&mut *vol.tree_log.replayed_csums.lock());
    let sectorsize = u64::from(vol.sectorsize());
    let mut items: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut next = 0u64;
    let mut count = 0usize;
    for (addr, sum) in sums {
        match items.last_mut() {
            Some((_, body)) if addr == next && count < REPLAY_CSUMS_PER_ITEM => {
                body.extend_from_slice(&sum);
                count += 1;
            }
            _ => {
                items.push((addr, sum));
                count = 1;
            }
        }
        next = addr + sectorsize;
    }
    items
}

// ── The log writer ─────────────────────────────────────────────────

/// Most `EXTENT_DATA`/xattr/ref items one inode may put in the log; a file
/// that changed in more places than this in one transaction commits instead.
const MAX_INODE_LOG_ITEMS: usize = 2048;
/// Most leaves one subvolume's log tree may have. Each log sync rewrites the
/// subvolume's log tree, so this bounds what one fsync writes.
const MAX_LOG_LEAVES: usize = 16;
/// Most tree blocks the logs of one transaction may use before an fsync
/// commits instead: superseded log blocks stay withheld until the commit.
const MAX_LOG_BLOCKS: u64 = 1024;
/// Deepest chain of not-yet-committed parent directories logged with a file.
const MAX_NEW_ANCESTORS: usize = 64;

/// Why an fsync commits the transaction instead of writing the log —
/// Linux's `BTRFS_LOG_FORCE_COMMIT` / `btrfs_set_log_full_commit` cases plus
/// the ones this writer does not log (driver spec §4, "Tree log").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Fallback {
    /// The log path is switched off ([`set_fsync_via_log`]).
    Disabled,
    /// An earlier log write of this transaction failed part-way.
    LogAborted,
    /// A directory, symlink or special file.
    NotRegularFile,
    /// The inode has no link left (an open, unlinked file).
    Unlinked,
    /// The inode number, or a parent's, was freed and given to a new inode
    /// since the last commit.
    InodeReused,
    /// The inode's names changed since the last commit (rename, link,
    /// unlink of one of several links).
    NamesChanged,
    /// A name of the inode lives in an `INODE_EXTREF`.
    ExtendedRef,
    /// A name (or directory index) of a new inode was held by another inode
    /// at the last commit, or is held by another inode in the log.
    NameCollision,
    /// An item type the writer does not log (verity, …) or an extent shape
    /// it cannot account for.
    Unsupported,
    /// The inode changed in more places than [`MAX_INODE_LOG_ITEMS`].
    InodeTooBig,
    /// The log tree would outgrow [`MAX_LOG_LEAVES`] / [`MAX_LOG_BLOCKS`].
    LogFull,
    /// No metadata space for the log blocks beside the transaction's own
    /// reservation.
    NoSpace,
    /// Quotas are enabled: replay does not maintain qgroup counts.
    Quota,
    /// No free-space tree: the allocator cannot withhold log blocks.
    NoFreeSpaceTree,
    /// The filesystem takes no writes (read-only, or aborted): the commit
    /// path reports why.
    ReadOnly,
}

impl Fallback {
    pub const ALL: [Fallback; 15] = [
        Fallback::Disabled,
        Fallback::LogAborted,
        Fallback::NotRegularFile,
        Fallback::Unlinked,
        Fallback::InodeReused,
        Fallback::NamesChanged,
        Fallback::ExtendedRef,
        Fallback::NameCollision,
        Fallback::Unsupported,
        Fallback::InodeTooBig,
        Fallback::LogFull,
        Fallback::NoSpace,
        Fallback::Quota,
        Fallback::NoFreeSpaceTree,
        Fallback::ReadOnly,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Fallback::Disabled => "log disabled",
            Fallback::LogAborted => "earlier log write failed",
            Fallback::NotRegularFile => "not a regular file",
            Fallback::Unlinked => "unlinked inode",
            Fallback::InodeReused => "inode number reused",
            Fallback::NamesChanged => "names changed",
            Fallback::ExtendedRef => "extended ref",
            Fallback::NameCollision => "name collision",
            Fallback::Unsupported => "unsupported item",
            Fallback::InodeTooBig => "inode log too big",
            Fallback::LogFull => "log full",
            Fallback::NoSpace => "no metadata space",
            Fallback::Quota => "quotas enabled",
            Fallback::NoFreeSpaceTree => "no free-space tree",
            Fallback::ReadOnly => "read-only filesystem",
        }
    }
}

/// One name of an inode: `(parent directory, directory index, name)`.
type Name = (u64, u64, Vec<u8>);

/// What the log holds for one inode.
#[derive(Clone, Debug)]
struct LoggedInode {
    /// The inode's creation time, its identity across inode-number reuse.
    otime: [u8; 12],
    /// Its log-tree items, keyed as in the subvolume tree.
    items: Vec<(BtrfsKey, Vec<u8>)>,
    /// Checksums of its data extents born in this transaction:
    /// `(disk bytenr, packed sums)`.
    csums: Vec<(u64, Vec<u8>)>,
    names: Vec<Name>,
    /// Data extents the items name that no committed tree accounts for.
    data: Vec<(u64, u64)>,
}

/// The log tree of one subvolume as last written.
#[derive(Clone, Debug, Default)]
struct SubvolLog {
    inodes: BTreeMap<u64, LoggedInode>,
    root: u64,
    level: u8,
}

/// The logs of the running transaction.
#[derive(Debug, Default)]
pub(super) struct LogState {
    /// The transaction (`batch.gen`) these logs belong to.
    gen: u64,
    /// `btrfs_set_log_full_commit`: every later fsync of this transaction
    /// commits.
    full_commit: bool,
    subvols: BTreeMap<u64, SubvolLog>,
    /// Log tree blocks allocated in this transaction.
    blocks: u64,
}

/// What an fsync through the log came to.
enum Outcome {
    /// The log holds the inode and is on stable storage.
    Logged,
    /// Nothing of the inode is newer than the last commit, which is durable.
    Clean,
    /// Commit the transaction instead.
    Commit(Fallback),
}

static FSYNC_VIA_LOG: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Route `fsync`/`fdatasync` through the tree log (`true`) or a full commit
/// (`false`, the default while the log path is being proven).
pub fn set_fsync_via_log(on: bool) {
    FSYNC_VIA_LOG.store(on, Ordering::Release);
}

// `struct btrfs_inode_item` offsets.
const II_SIZE: usize = 16;
const II_NLINK: usize = 40;
const II_MODE: usize = 52;
const II_OTIME: usize = 148;
const INODE_ITEM_SIZE: usize = 160;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
/// `BTRFS_INODE_EXTREF_KEY`.
const INODE_EXTREF_KEY: u8 = 13;

// `struct btrfs_file_extent_item` offsets.
const FE_RAM_BYTES: usize = 8;
const FE_TYPE: usize = 20;
const FE_DISK_BYTENR: usize = 21;
const FE_DISK_NUM: usize = 29;
const FE_NUM_BYTES: usize = 45;
const FE_REG_SIZE: usize = 53;

/// `fsync`/`fdatasync` of inode `ino` of `vol`'s subvolume: Linux
/// `btrfs_sync_file`. The inode's changes since the last commit go to the
/// tree log and the log to stable storage (`btrfs_log_dentry_safe` +
/// `btrfs_sync_log`); whatever the log cannot express exactly commits the
/// transaction instead (`btrfs_commit_transaction`), which is always correct.
pub(crate) async fn fsync_inode<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    is_dir: bool,
) -> Result<(), FsError> {
    let _op = vol.op_lock().lock().await;
    let outcome = if !FSYNC_VIA_LOG.load(Ordering::Acquire) {
        Outcome::Commit(Fallback::Disabled)
    } else if is_dir {
        Outcome::Commit(Fallback::NotRegularFile)
    } else if !vol.admits_writes() {
        Outcome::Commit(Fallback::ReadOnly)
    } else {
        log_inode(vol, ino).await?
    };
    match outcome {
        Outcome::Logged => {
            crate::stats::note_fsync_logged();
            Ok(())
        }
        Outcome::Clean => {
            crate::stats::note_fsync_clean();
            Ok(())
        }
        Outcome::Commit(why) => {
            crate::stats::note_fsync_committed(why as usize);
            vol.sync_to_disk_op_locked().await
        }
    }
}

fn mode_of(inode: &[u8]) -> Result<u32, FsError> {
    le32(inode, II_MODE)
}

fn otime_of(inode: &[u8]) -> Result<[u8; 12], FsError> {
    inode
        .get(II_OTIME..II_OTIME + 12)
        .and_then(|b| b.try_into().ok())
        .ok_or(FsError::InvalidData)
}

/// Every item of object `ino` in the tree at `root`, in key order.
async fn object_items<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    ino: u64,
) -> Result<Vec<(BtrfsKey, Vec<u8>)>, FsError> {
    let mut out = Vec::new();
    let mut cursor = btree::Cursor::seek(vol, root, &BtrfsKey::new(ino, 0, 0)).await?;
    while let Some((key, body)) = cursor.current()? {
        if key.objectid != ino {
            break;
        }
        out.push((key, body.to_vec()));
        cursor.advance().await?;
    }
    Ok(out)
}

fn inode_item_of(items: &[(BtrfsKey, Vec<u8>)]) -> Result<Option<&[u8]>, FsError> {
    match items.first() {
        Some((key, body)) if key.item_type == format::INODE_ITEM_KEY => {
            if body.len() < INODE_ITEM_SIZE {
                return Err(FsError::InvalidData);
            }
            Ok(Some(body))
        }
        _ => Ok(None),
    }
}

/// The names `(parent, index, name)` an inode's `INODE_REF` items hold.
fn names_of(items: &[(BtrfsKey, Vec<u8>)]) -> Result<Vec<Name>, FsError> {
    let mut out = Vec::new();
    for (key, body) in items {
        if key.item_type != format::INODE_REF_KEY {
            continue;
        }
        let mut pos = 0usize;
        while pos < body.len() {
            let index = le64(body, pos)?;
            let len = format::le16(body, pos + 8)? as usize;
            let name = body
                .get(pos + 10..pos + 10 + len)
                .ok_or(FsError::InvalidData)?;
            out.push((key.offset, index, name.to_vec()));
            pos += 10 + len;
        }
    }
    Ok(out)
}

/// How an inode of the running transaction relates to the last commit.
enum Identity {
    /// The same inode existed at the last commit.
    Same,
    /// No inode had this number at the last commit.
    New,
}

/// Compare the live inode with whatever had its number at the last commit:
/// the same object (creation time and type), nothing, or — `Err` — another
/// inode whose number was reused.
fn identity(
    live: &[u8],
    base: &[(BtrfsKey, Vec<u8>)],
) -> Result<Result<Identity, Fallback>, FsError> {
    match inode_item_of(base)? {
        Some(was) => {
            if otime_of(was)? == otime_of(live)?
                && mode_of(was)? & S_IFMT == mode_of(live)? & S_IFMT
            {
                Ok(Ok(Identity::Same))
            } else {
                Ok(Err(Fallback::InodeReused))
            }
        }
        None if base.is_empty() => Ok(Ok(Identity::New)),
        None => Ok(Err(Fallback::InodeReused)),
    }
}

/// One inode's contribution to the log, about to be written.
struct InodePlan {
    ino: u64,
    logged: LoggedInode,
}

/// What reading the trees for one fsync needs.
struct Planner<'a, B: BlockDevice + 'static> {
    vol: &'a BtrfsVolume<B>,
    /// The subvolume tree as of the last commit.
    base_root: u64,
    /// The subvolume tree with the running transaction's operations.
    live_root: u64,
    gen: u64,
    /// What the log already holds for this subvolume.
    logged: &'a BTreeMap<u64, LoggedInode>,
    /// Data extents born in this transaction, with their checksums.
    new_data: &'a [DataRef],
    plans: Vec<InodePlan>,
}

impl<B: BlockDevice + 'static> Planner<'_, B> {
    /// A new inode may be logged under `name` only if replaying that name
    /// over the last commit cannot displace anything: nothing held the name
    /// or the directory index then, and no other logged inode claims them.
    async fn name_is_free(&self, ino: u64, name: &Name) -> Result<bool, FsError> {
        let (parent, index, text) = name;
        let item_key = BtrfsKey::new(*parent, format::DIR_ITEM_KEY, u64::from(name_hash(text)));
        if let Some(bucket) = btree::find_item(self.vol, self.base_root, &item_key).await? {
            // Names are compared as bytes; a bucket holds every name of
            // this hash.
            let mut pos = 0usize;
            while pos < bucket.len() {
                let data_len = format::le16(&bucket, pos + 25)? as usize;
                let name_len = format::le16(&bucket, pos + 27)? as usize;
                let held = bucket
                    .get(pos + 30..pos + 30 + name_len)
                    .ok_or(FsError::InvalidData)?;
                if held == text.as_slice() {
                    return Ok(false);
                }
                pos += 30 + name_len + data_len;
            }
        }
        let index_key = BtrfsKey::new(*parent, format::DIR_INDEX_KEY, *index);
        if btree::find_item(self.vol, self.base_root, &index_key)
            .await?
            .is_some()
        {
            return Ok(false);
        }
        let claimed = |other: u64, names: &[Name]| {
            other != ino
                && names
                    .iter()
                    .any(|(p, i, n)| p == parent && (i == index || n == text))
        };
        if self
            .logged
            .iter()
            .any(|(&other, l)| claimed(other, &l.names))
            || self.plans.iter().any(|p| claimed(p.ino, &p.logged.names))
        {
            return Ok(false);
        }
        Ok(true)
    }

    /// The items common to every logged inode — its `INODE_ITEM`, back
    /// references and xattrs, all as they are in the live tree — after the
    /// checks that make logging it safe. `Ok(Ok(None))`: the inode is
    /// exactly as committed and needs no log.
    async fn plan_common(
        &self,
        ino: u64,
        live: &[(BtrfsKey, Vec<u8>)],
        want_dir: bool,
    ) -> Result<Result<Option<(Identity, LoggedInode)>, Fallback>, FsError> {
        let Some(inode) = inode_item_of(live)? else {
            return Ok(Err(Fallback::Unlinked));
        };
        if le32(inode, II_NLINK)? == 0 {
            return Ok(Err(Fallback::Unlinked));
        }
        let kind = mode_of(inode)? & S_IFMT;
        if kind != if want_dir { S_IFDIR } else { S_IFREG } {
            return Ok(Err(Fallback::NotRegularFile));
        }
        let base = object_items(self.vol, self.base_root, ino).await?;
        let identity = match identity(inode, &base)? {
            Ok(identity) => identity,
            Err(why) => return Ok(Err(why)),
        };
        let otime = otime_of(inode)?;
        if self.logged.get(&ino).is_some_and(|l| l.otime != otime) {
            return Ok(Err(Fallback::InodeReused));
        }
        if matches!(identity, Identity::Same) && base.as_slice() == live {
            // Unchanged since the commit. Were it in the log all the same,
            // the log would hold a state it no longer has.
            return Ok(if self.logged.contains_key(&ino) {
                Err(Fallback::Unsupported)
            } else {
                Ok(None)
            });
        }
        let has =
            |items: &[(BtrfsKey, Vec<u8>)], t: u8| items.iter().any(|(k, _)| k.item_type == t);
        if has(live, INODE_EXTREF_KEY) || has(&base, INODE_EXTREF_KEY) {
            return Ok(Err(Fallback::ExtendedRef));
        }
        let names = names_of(live)?;
        if names.is_empty() {
            return Ok(Err(Fallback::Unlinked));
        }
        match identity {
            Identity::Same => {
                // Replay keeps the committed names; they must still be the
                // inode's names.
                let refs = |items: &[(BtrfsKey, Vec<u8>)]| -> Vec<(BtrfsKey, Vec<u8>)> {
                    items
                        .iter()
                        .filter(|(k, _)| k.item_type == format::INODE_REF_KEY)
                        .cloned()
                        .collect()
                };
                if refs(live) != refs(&base) {
                    return Ok(Err(Fallback::NamesChanged));
                }
            }
            Identity::New => {
                for name in &names {
                    if !self.name_is_free(ino, name).await? {
                        return Ok(Err(Fallback::NameCollision));
                    }
                }
            }
        }
        let mut items = Vec::new();
        for (key, body) in live {
            match key.item_type {
                format::INODE_ITEM_KEY | format::INODE_REF_KEY | format::XATTR_ITEM_KEY => {
                    items.push((*key, body.clone()));
                }
                format::EXTENT_DATA_KEY if !want_dir => {}
                format::DIR_ITEM_KEY | format::DIR_INDEX_KEY if want_dir => {}
                _ => return Ok(Err(Fallback::Unsupported)),
            }
        }
        Ok(Ok(Some((
            identity,
            LoggedInode {
                otime,
                items,
                csums: Vec::new(),
                names,
                data: Vec::new(),
            },
        ))))
    }

    /// Log the parents of a new inode that are themselves new
    /// (`log_all_new_ancestors`): replay can only link a name into a
    /// directory that exists. A directory is logged as existing — its inode
    /// item, name and xattrs, none of its entries.
    async fn plan_new_ancestors(
        &mut self,
        names: &[Name],
    ) -> Result<Result<(), Fallback>, FsError> {
        let mut pending: Vec<u64> = names.iter().map(|(parent, _, _)| *parent).collect();
        let mut seen = 0usize;
        while let Some(dir) = pending.pop() {
            if self.plans.iter().any(|p| p.ino == dir) {
                continue;
            }
            seen += 1;
            if seen > MAX_NEW_ANCESTORS {
                return Ok(Err(Fallback::Unsupported));
            }
            let live = object_items(self.vol, self.live_root, dir).await?;
            match self.plan_common(dir, &live, true).await? {
                Err(why) => return Ok(Err(why)),
                // A committed directory, unchanged or not, is where replay
                // finds it.
                Ok(None) | Ok(Some((Identity::Same, _))) => {}
                Ok(Some((Identity::New, logged))) => {
                    pending.extend(logged.names.iter().map(|(parent, _, _)| *parent));
                    self.plans.push(InodePlan { ino: dir, logged });
                }
            }
        }
        Ok(Ok(()))
    }

    /// Plan the log of regular file `ino` (`btrfs_log_inode` with
    /// `LOG_INODE_ALL`, then `btrfs_log_inode_parent`'s new ancestors).
    /// `Ok(Ok(false))`: nothing to log.
    async fn plan_file(&mut self, ino: u64) -> Result<Result<bool, Fallback>, FsError> {
        let live = object_items(self.vol, self.live_root, ino).await?;
        let (identity, mut logged) = match self.plan_common(ino, &live, false).await? {
            Err(why) => return Ok(Err(why)),
            Ok(None) => return Ok(Ok(false)),
            Ok(Some(found)) => found,
        };
        let inode = inode_item_of(&live)?.ok_or(FsError::InvalidData)?;
        let sectorsize = u64::from(self.vol.sectorsize());
        let cut = align_up(le64(inode, II_SIZE)?, sectorsize);
        let base: BTreeMap<BtrfsKey, Vec<u8>> =
            btree::collect_for(self.vol, self.base_root, ino, format::EXTENT_DATA_KEY)
                .await?
                .into_iter()
                .collect();

        // File extents: every item that is not exactly as committed, and
        // every item reaching past the size (replay truncates to the size
        // first, so preallocation kept beyond it has to be in the log to
        // survive whole: `btrfs_log_prealloc_extents`).
        let mut covered: Vec<(u64, u64)> = Vec::new();
        for (key, body) in live
            .iter()
            .filter(|(k, _)| k.item_type == format::EXTENT_DATA_KEY)
        {
            if body.len() <= FE_TYPE {
                return Err(FsError::InvalidData);
            }
            let inline = body[FE_TYPE] == format::FILE_EXTENT_INLINE;
            let len = if inline {
                align_up(le64(body, FE_RAM_BYTES)?, sectorsize)
            } else {
                if body.len() < FE_REG_SIZE {
                    return Err(FsError::InvalidData);
                }
                le64(body, FE_NUM_BYTES)?
            };
            covered.push((key.offset, key.offset.saturating_add(len)));
            if base.get(key) == Some(body) && key.offset.saturating_add(len) <= cut {
                continue;
            }
            logged.items.push((*key, body.clone()));
            if inline {
                continue;
            }
            let bytenr = le64(body, FE_DISK_BYTENR)?;
            if bytenr == 0 {
                continue;
            }
            // An extent born in this transaction is known to no committed
            // tree: the log carries its checksums, and its space is withheld
            // with the log's. Any other extent is committed, checksums and
            // all, and replay only takes a reference.
            if let Some(born) = self.new_data.iter().find(|d| d.id.bytenr == bytenr) {
                if born.id.len != le64(body, FE_DISK_NUM)? {
                    return Ok(Err(Fallback::Unsupported));
                }
                if !logged.data.contains(&(bytenr, born.id.len)) {
                    logged.data.push((bytenr, born.id.len));
                    if !born.csums.is_empty() {
                        logged.csums.push((bytenr, born.csums.clone()));
                    }
                }
            }
        }
        // Holes: with NO_HOLES a hole has no item, so a range that held data
        // at the commit and holds none now is logged as an explicit hole for
        // replay to drop what is there (`btrfs_log_holes`).
        if self.vol.superblock().incompat_flags & format::INCOMPAT_NO_HOLES != 0 {
            let mut at = 0u64;
            let mut gaps: Vec<(u64, u64)> = Vec::new();
            for &(start, end) in &covered {
                if start > at && at < cut {
                    gaps.push((at, start.min(cut)));
                }
                at = at.max(end);
            }
            if at < cut {
                gaps.push((at, cut));
            }
            for (start, end) in gaps {
                let mut held = false;
                for (key, body) in &base {
                    let item = FileItem::decode(*key, body.clone())?;
                    let item_end = align_up(item.end, sectorsize);
                    if item.start < end && item_end > start && item.kind != Kind::Hole {
                        held = true;
                        break;
                    }
                }
                if held {
                    logged.items.push((
                        BtrfsKey::new(ino, format::EXTENT_DATA_KEY, start),
                        hole_item(self.gen, end - start),
                    ));
                }
            }
        }
        if logged.items.len() > MAX_INODE_LOG_ITEMS {
            return Ok(Err(Fallback::InodeTooBig));
        }
        logged.items.sort_by(|a, b| a.0.cmp(&b.0));
        let names = logged.names.clone();
        self.plans.push(InodePlan { ino, logged });
        if matches!(identity, Identity::New) {
            if let Err(why) = self.plan_new_ancestors(&names).await? {
                return Ok(Err(why));
            }
        }
        Ok(Ok(true))
    }
}

/// An explicit hole file-extent item (`btrfs_insert_hole_extent`).
fn hole_item(gen: u64, len: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; FE_REG_SIZE];
    v[0..8].copy_from_slice(&gen.to_le_bytes());
    v[FE_RAM_BYTES..FE_RAM_BYTES + 8].copy_from_slice(&len.to_le_bytes());
    v[FE_TYPE] = format::FILE_EXTENT_REG;
    v[FE_NUM_BYTES..FE_NUM_BYTES + 8].copy_from_slice(&len.to_le_bytes());
    v
}

/// The `btrfs_root_item` of a log tree in the log root tree, as
/// `btrfs_add_log_tree` + `btrfs_set_root_node` leave it.
fn log_root_item(gen: u64, bytenr: u64, level: u8, nodesize: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 439];
    // The embedded inode item: generation 1, size 3, nlink 1, one node of
    // bytes, a directory.
    v[0..8].copy_from_slice(&1u64.to_le_bytes());
    v[16..24].copy_from_slice(&3u64.to_le_bytes());
    v[24..32].copy_from_slice(&nodesize.to_le_bytes());
    v[40..44].copy_from_slice(&1u32.to_le_bytes());
    v[52..56].copy_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
    v[160..168].copy_from_slice(&gen.to_le_bytes()); // generation
    v[176..184].copy_from_slice(&bytenr.to_le_bytes()); // bytenr
    v[238] = level;
    v[239..247].copy_from_slice(&gen.to_le_bytes()); // generation_v2
    v
}

/// The metadata the open transaction's commit still has to find, for the
/// check that log blocks do not eat into it ([`reserve`]).
fn batch_load(batch: &FsBatch) -> reserve::CommitLoad {
    let mut load = reserve::CommitLoad {
        new_data: batch.new_data.len() as u64,
        dropped_data: batch.dropped_data.len() as u64,
        added_data: batch.added_data.len() as u64,
        ..Default::default()
    };
    for tree in batch.trees.values() {
        load.new_meta += tree.cow.pending.len() as u64;
        load.freed_meta += tree.cow.freed.len() as u64;
        load.ref_items += tree.cow.shared.as_ref().map_or(0, |s| s.refs.item_count()) as u64;
    }
    load
}

async fn log_inode<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
) -> Result<Outcome, FsError> {
    let sb = vol.superblock();
    if sb.compat_ro_flags & format::COMPAT_RO_FREE_SPACE_TREE == 0 {
        return Ok(Outcome::Commit(Fallback::NoFreeSpaceTree));
    }
    // The log is an overlay on the last commit, so that commit's superblock
    // has to be on the device before a log can name it as its base
    // (`log_root_tree` blocks carry `super.generation + 1`).
    if vol.has_staged_super() {
        vol.write_staged_super().await?;
    }
    let tree_id = vol.fs_tree_id();
    let mut guard = vol.fs_batch().lock().await;
    let (gen, base_root) = match guard.as_ref() {
        Some(batch) => match batch.trees.get(&tree_id) {
            Some(tree) if tree.ops > 0 => (batch.gen, tree.base_root.0),
            _ => (0, 0),
        },
        None => (0, 0),
    };
    if gen == 0 {
        // Nothing of this subvolume is uncommitted, and its last commit is
        // on the device; the barrier covers a write cache still holding it.
        drop(guard);
        vol.flush().await?;
        return Ok(Outcome::Clean);
    }
    let batch = guard.as_mut().ok_or(FsError::InvalidData)?;
    let (root_tree, _) = vol.root_tree_root();
    if roots::find_root(vol, root_tree, format::QUOTA_TREE_OBJECTID)
        .await
        .is_ok()
    {
        return Ok(Outcome::Commit(Fallback::Quota));
    }

    let mut state = vol.tree_log.state.lock().await;
    if state.gen != gen {
        // A new transaction: its predecessor's commit dropped the old log.
        *state = LogState {
            gen,
            ..Default::default()
        };
    }
    if state.full_commit {
        return Ok(Outcome::Commit(Fallback::LogAborted));
    }
    let empty = BTreeMap::new();
    let mut planner = Planner {
        vol,
        base_root,
        live_root: vol.fs_tree_root().0,
        gen,
        logged: state.subvols.get(&tree_id).map_or(&empty, |s| &s.inodes),
        new_data: &batch.new_data,
        plans: Vec::new(),
    };
    match planner.plan_file(ino).await? {
        Err(why) => return Ok(Outcome::Commit(why)),
        Ok(false) => {
            drop(state);
            drop(guard);
            vol.flush().await?;
            return Ok(Outcome::Clean);
        }
        Ok(true) => {}
    }
    let plans = planner.plans;

    // The subvolume's log tree with these inodes in it.
    let mut subvol = state.subvols.get(&tree_id).cloned().unwrap_or_default();
    for plan in plans {
        subvol.inodes.insert(plan.ino, plan.logged);
    }
    let mut items: Vec<(BtrfsKey, Vec<u8>)> = Vec::new();
    let mut csums: BTreeMap<u64, &Vec<u8>> = BTreeMap::new();
    for inode in subvol.inodes.values() {
        items.extend(inode.items.iter().cloned());
        for (bytenr, sums) in &inode.csums {
            csums.insert(*bytenr, sums);
        }
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let width = crate::checksum::size(vol.csum_type())? as u64;
    let sectorsize = u64::from(vol.sectorsize());
    let mut csum_end = 0u64;
    for (bytenr, sums) in csums {
        // Csum items of one tree never overlap (`check_csum_item`).
        if bytenr < csum_end {
            return Ok(Outcome::Commit(Fallback::Unsupported));
        }
        csum_end = bytenr + sums.len() as u64 / width * sectorsize;
        items.push((
            BtrfsKey::new(
                format::EXTENT_CSUM_OBJECTID,
                format::EXTENT_CSUM_KEY,
                bytenr,
            ),
            sums.clone(),
        ));
    }

    // Every block of a log tree is a log block: owner TREE_LOG, written,
    // mixed backrefs (`btrfs_init_new_buffer` for a log root).
    let mut header = vol.read_node(vol.fs_tree_root().0).await?[..HEADER_SIZE].to_vec();
    normalize_cow_header(&mut header, format::TREE_LOG_OBJECTID);
    let body_total: usize = items.iter().map(|(_, b)| b.len()).sum();
    let capacity = HEADER_SIZE + items.len() * LEAF_ITEM_SIZE + body_total + HEADER_SIZE;
    let refs: Vec<(BtrfsKey, &[u8])> = items.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let leaf = pack_leaf(&header, &refs, capacity);
    let groups = match group_items(vol, &leaf) {
        Ok(groups) => groups,
        // One item larger than a leaf.
        Err(FsError::Unsupported) => return Ok(Outcome::Commit(Fallback::Unsupported)),
        Err(error) => return Err(error),
    };
    let nodesize = vol.nodesize() as u64;
    let tree_blocks = tree_block_count(groups.len(), vol.nodesize());
    let blocks = tree_blocks as u64 + 1; // and the log root tree's one leaf
    if groups.len() > MAX_LOG_LEAVES || state.blocks + blocks > MAX_LOG_BLOCKS {
        return Ok(Outcome::Commit(Fallback::LogFull));
    }
    // The log root tree: one ROOT_ITEM per logged subvolume, in one leaf.
    let logged_subvols = state.subvols.len() + usize::from(!state.subvols.contains_key(&tree_id));
    if logged_subvols * (LEAF_ITEM_SIZE + 439) > vol.nodesize() - HEADER_SIZE {
        return Ok(Outcome::Commit(Fallback::LogFull));
    }

    // Log blocks are metadata allocations of this transaction
    // (`btrfs_alloc_tree_block`), taken from its allocator so that nothing
    // else in it lands on them, and only while the reservation of the
    // operations already accepted still fits beside them.
    let snapshot = batch.alloc.clone();
    let addrs = match alloc_nodes(&mut batch.alloc, vol, blocks as usize) {
        Ok(addrs) => addrs,
        Err(FsError::NoSpace) => {
            batch.alloc = snapshot;
            return Ok(Outcome::Commit(Fallback::NoSpace));
        }
        Err(error) => {
            batch.alloc = snapshot;
            return Err(error);
        }
    };
    let free = batch.alloc.free_bytes(format::BLOCK_GROUP_METADATA);
    let need = batch
        .geometry
        .ordinary_need(&batch_load(batch))
        .saturating_mul(nodesize);
    if free < need {
        batch.alloc = snapshot;
        return Ok(Outcome::Commit(Fallback::NoSpace));
    }

    let (mut nodes, root, level) = pack_tree_at(vol, &leaf, &groups, &addrs[..tree_blocks], gen)?;
    subvol.root = root;
    subvol.level = level;
    let mut root_items: Vec<(BtrfsKey, Vec<u8>)> = state
        .subvols
        .iter()
        .filter(|(&id, _)| id != tree_id)
        .map(|(&id, s)| (id, s.root, s.level))
        .chain(core::iter::once((tree_id, root, level)))
        .map(|(id, root, level)| {
            (
                BtrfsKey::new(format::TREE_LOG_OBJECTID, format::ROOT_ITEM_KEY, id),
                log_root_item(gen, root, level, nodesize),
            )
        })
        .collect();
    root_items.sort_by(|a, b| a.0.cmp(&b.0));
    let root_refs: Vec<(BtrfsKey, &[u8])> =
        root_items.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let root_leaf = pack_leaf(&header, &root_refs, vol.nodesize());
    let (root_nodes, log_root, log_root_level) = pack_tree_at(
        vol,
        &root_leaf,
        &[(0, root_items.len())],
        &addrs[tree_blocks..],
        gen,
    )?;
    nodes.extend(root_nodes);

    // From here the device may hold a log naming these blocks and extents:
    // they stay out of every allocator until a commit's superblock replaces
    // the log's. A failure below leaves the previous log, if any, on the
    // device and still valid, but this transaction logs nothing more.
    for &addr in &addrs {
        vol.tree_log.pin(addr, nodesize);
    }
    for inode in subvol.inodes.values() {
        for &(bytenr, len) in &inode.data {
            vol.tree_log.pin_once(bytenr, len);
        }
    }
    state.blocks += blocks;
    state.full_commit = true;
    for (addr, buf) in &nodes {
        vol.write_node(*addr, buf).await?;
    }
    // `btrfs_sync_log`: the log (and every data block written before this
    // fsync) is made durable by the pre-flush of the superblock write, and
    // the superblock that names the log root goes out with FUA.
    let mut raw = vol.read_raw_superblock().await?;
    raw[format::OFF_LOG_ROOT..format::OFF_LOG_ROOT + 8].copy_from_slice(&log_root.to_le_bytes());
    raw[format::OFF_LOG_ROOT_LEVEL] = log_root_level;
    crate::checksum::stamp_block(vol.csum_type(), &mut raw)?;
    vol.write_superblock(&raw).await?;
    state.subvols.insert(tree_id, subvol);
    state.full_commit = false;
    Ok(Outcome::Logged)
}
