//! Mounted btrfs volume: block I/O, chunk-map bootstrap, logical reads.
//!
//! Read call chain mirrors `/usr/src/linux/fs/btrfs`: `open_ctree` reads the
//! superblock, bootstraps the chunk map from `sys_chunk_array`, walks the chunk
//! tree to complete the logical→physical map, then reads the root tree to find
//! the default FS tree. Every read above the superblock is by logical address
//! and goes through [`BtrfsVolume::read_logical`].
//!
//! Mutable metadata (the chunk map, the tree roots, the live superblock) lives
//! behind one `IrqSafeSpinLock`. The lock is **never** held across a block-I/O
//! `await`: readers snapshot the scalars they need (a physical offset, a root
//! address), drop the guard, then do I/O. Holding a spinlock across
//! `poll_blocking` would wedge the volume under an IRQ-driven backend.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockError, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_filesystem::FsError;
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use alloc::string::String;

use crate::chunk::{ChunkMap, ChunkProfile};
use crate::format::{self, BtrfsKey, Superblock};
use crate::inode::InodeItem;

/// Selects which subvolume a `mount -t btrfs` request roots at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subvol {
    /// `subvolid=N` — a subvolume root objectid.
    Id(u64),
    /// `subvol=PATH` — a path from the top-level FS tree to a subvolume root.
    Name(String),
}

/// Profile targets for a balance conversion. `None` leaves that allocation
/// class unchanged. Mixed DATA+METADATA block groups require identical data
/// and metadata targets, as they do in Linux.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BalanceProfiles {
    pub data: Option<ChunkProfile>,
    pub metadata: Option<ChunkProfile>,
    pub system: Option<ChunkProfile>,
}

/// Counts returned by a completed synchronous balance.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BalanceStats {
    pub considered: u64,
    pub converted: u64,
}

/// Volume-owned scratch DMA buffer, serialised across all block submissions.
#[derive(Debug)]
struct VolumeIo {
    cap: Cap<DmaBuffer, Write>,
    block_size: usize,
    /// Bytes in the scratch buffer: a whole number of blocks, at least one
    /// superblock and one maximum-size tree node.
    len: usize,
}

/// Scratch transfer size per member. A superblock copy (4 KiB) and every tree
/// node (at most 64 KiB) then go to the device as ONE request: on a 512-byte
/// LBA namespace a block-at-a-time writer turned the FUA primary superblock
/// into eight separate FUA writes, any prefix of which a power cut could leave
/// on disk as a torn, checksum-failing primary.
const SCRATCH_BYTES: usize = 64 * 1024;

/// The scratch length for a device of `block_size`-byte blocks.
fn scratch_len(block_size: usize) -> usize {
    (SCRATCH_BYTES / block_size).max(1) * block_size
}

/// Allocate one member's scratch I/O state.
fn new_volume_io(block_size: usize, domain: DomainId) -> Result<VolumeIo, FsError> {
    let len = scratch_len(block_size);
    let dma = alloc_coherent(len, domain).map_err(|_| FsError::Io(BlockError::IOError))?;
    Ok(VolumeIo {
        cap: register_with_cap(dma),
        block_size,
        len,
    })
}

/// One member device, with geometry and scratch I/O state local to that
/// device. Different members may expose different logical block sizes.
#[derive(Debug)]
struct VolumeDevice<B: BlockDevice> {
    device: Arc<B>,
    capacity: u64,
    /// Member-specific embedded dev_item, preserved while common superblock
    /// transaction fields are replicated to every device.
    dev_item: IrqSafeSpinLock<[u8; format::SUPERBLOCK_DEV_ITEM_SIZE]>,
    io: Mutex<VolumeIo>,
}

impl VolumeIo {
    fn buffer(&self) -> Option<Arc<DmaBuffer>> {
        resolve_cap(&self.cap)
    }
}

impl Drop for VolumeIo {
    fn drop(&mut self) {
        unregister(self.cap);
    }
}

/// Cached metadata nodes, keyed by logical address.
///
/// `epoch` is what makes filling the cache safe against a concurrent write.
/// A reader that misses must drop the lock to do its I/O, and a writer may
/// invalidate that very address while the read is in flight; inserting the
/// bytes afterwards would publish a node that is already stale. The reader
/// samples `epoch` before its read and only inserts if no invalidation has
/// happened since, so a racing write costs a skipped fill rather than a wrong
/// answer.
#[derive(Debug, Default)]
struct NodeCache {
    entries: BTreeMap<u64, Arc<alloc::vec::Vec<u8>>>,
    epoch: u64,
}

/// Cached nodes. At a 16 KiB nodesize this bounds the cache at 4 MiB, which
/// comfortably holds the working set a commit's fixed point revisits while
/// staying a fixed, predictable cost.
const NODE_CACHE_MAX: usize = 256;

/// Commits allowed to stage before the superblock is forced out.
///
/// Bounds two things: how much work a crash discards, and how long pinned
/// extents withhold free space.
///
/// One, because staging a second buys nothing measurable. Deferring the
/// superblock was worth having when every operation committed — it was then
/// the only thing amortising a write and a barrier across more than one
/// mutation. Now that a transaction carries up to `MAX_BATCH_OPS`
/// operations, that amortisation has already happened, and the superblock is
/// one write per batch rather than one per operation. Interleaved paired runs
/// of the write smoke put a depth of 1 at 2.51e9 cycles against 2.49e9 for a
/// depth of 2 — a 0.7% difference on a host whose run-to-run spread is nearer
/// 2x, which is to say no difference at all.
///
/// So the depth is spent on the other side of the trade instead: at 1, a
/// crash can discard one batch rather than two, and freed space is withheld
/// for one commit rather than two. Both are paid for in real failure
/// behaviour; the throughput it would have bought is not there to lose.
const MAX_STAGED_COMMITS: usize = 1;

impl NodeCache {
    /// Drop `logical` and advance the epoch, so any fill already in flight for
    /// it (or for anything else) declines to publish.
    fn invalidate(&mut self, logical: u64) {
        self.entries.remove(&logical);
        self.epoch = self.epoch.wrapping_add(1);
    }
}

/// Mutable volume metadata guarded by one lock (never held across I/O).
#[derive(Debug)]
struct VolState {
    /// The live superblock. Its tree roots and `generation` advance on a COW
    /// write; the read path snapshots the roots it needs.
    superblock: Superblock,
    /// Physical offset of the superblock copy selected at mount. Reads use this
    /// until the next commit rewrites every mirror and heals the primary.
    superblock_source: (u64, u64),
    /// Completed logical→physical chunk map.
    chunk_map: ChunkMap,
    /// Live root of every subvolume some mount (or an in-flight commit) has
    /// selected, keyed by tree objectid. Shared by every mount of the
    /// filesystem, so a batch staged through one mount of a subvolume is seen
    /// by every other mount of it, as Linux shares one `btrfs_root` per tree.
    subvols: BTreeMap<u64, LiveSubvol>,
    /// Highest logical address handed out by a write this session. Seeds the
    /// next write's allocator so successive writes don't collide before the
    /// extent tree records the allocations. Reset to 0 at mount.
    alloc_floor: u64,
}

/// The live state of one subvolume tree, shared by every mount of it.
#[derive(Copy, Clone, Debug)]
struct LiveSubvol {
    root: u64,
    level: u8,
    /// On-disk `btrfs_root_item.flags` (`BTRFS_ROOT_SUBVOL_RDONLY`).
    flags: u64,
    /// Mounts currently rooted at this subvolume.
    mounts: usize,
}

/// A live tree root pinned against reallocation while a lock-free reader
/// walks from it ([`BtrfsVolume::pin_live_root`]).
pub(crate) struct RootPin<B: BlockDevice> {
    core: Arc<VolCore<B>>,
    root: u64,
}

impl<B: BlockDevice> RootPin<B> {
    pub(crate) fn root(&self) -> u64 {
        self.root
    }
}

impl<B: BlockDevice> Drop for RootPin<B> {
    fn drop(&mut self) {
        let mut pins = self.core.reader_roots.lock();
        if let Some(count) = pins.get_mut(&self.root) {
            *count -= 1;
            if *count == 0 {
                pins.remove(&self.root);
            }
        }
    }
}

/// Guard of [`VolCore::hold_commits`]; releases the hold when dropped (also
/// when the operation's future is dropped mid-way).
#[derive(Debug)]
pub(crate) struct CommitHold<'a>(&'a core::sync::atomic::AtomicUsize);

impl Drop for CommitHold<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    }
}

/// Per-mount state: which subvolume this mount exposes.
#[derive(Debug)]
struct ViewState {
    /// Selected FS-tree objectid.
    fs_tree_id: u64,
    /// Cached root-directory inode (objectid 256), for the sync `root()` path.
    root_inode: Option<InodeItem>,
}

/// A mounted btrfs filesystem as one mount sees it: a subvolume root over the
/// shared [`VolCore`].
///
/// Linux splits the same way: one `btrfs_fs_info` (with its transaction,
/// allocator, superblock commit and `transaction_kthread`) per filesystem, and
/// each mount's `sb->s_root` a dentry inside whichever subvolume
/// `btrfs_get_subvol_root`/`get_tree_subvol` selected. Every mount of one
/// filesystem therefore shares one writer; [`crate::registry`] hands out
/// views over a single core per fsid, and the core is freed with its last view.
///
/// Dereferences to the core, so filesystem-wide state reads the same through
/// any view.
#[derive(Debug)]
pub struct BtrfsVolume<B: BlockDevice> {
    core: Arc<VolCore<B>>,
    pub self_weak: Weak<BtrfsVolume<B>>,
    view: IrqSafeSpinLock<ViewState>,
    /// This mount was requested read-only. The core may still be writable
    /// through other mounts, as a Linux `ro` bind of a `rw` superblock is.
    view_read_only: core::sync::atomic::AtomicBool,
    /// The `mount -t btrfs` data options this volume was mounted with
    /// (compression, discard, ...). Recorded so the writer and
    /// `show_options` can honour them; see [`crate::mount_opts`].
    mount_options: IrqSafeSpinLock<crate::mount_opts::MountOptions>,
}

impl<B: BlockDevice> core::ops::Deref for BtrfsVolume<B> {
    type Target = VolCore<B>;
    fn deref(&self) -> &VolCore<B> {
        &self.core
    }
}

impl<B: BlockDevice> Drop for BtrfsVolume<B> {
    fn drop(&mut self) {
        let id = self.view.lock().fs_tree_id;
        if let Some(live) = self.core.state.lock().subvols.get_mut(&id) {
            live.mounts = live.mounts.saturating_sub(1);
        }
        // The last view of the core: nothing else can commit for it now.
        if Arc::strong_count(&self.core) == 1 {
            (self.core.last_view_dropped)(&self.core);
        }
    }
}

/// Accessors on the shared core.
impl<B: BlockDevice> VolCore<B> {
    /// The live superblock's generation (the last committed transaction).
    pub(crate) fn committed_generation(&self) -> u64 {
        self.state.lock().superblock.generation
    }

    /// Current content generation for inode `ino` in fs tree `tree`
    /// (see [`CacheGenerations`]). An inode nobody has issued a
    /// generation for yet is assigned a fresh tick on first read:
    /// issuing lazily here (rather than only on mutation) is what
    /// gives a pre-existing, never-mutated file an instance-unique
    /// value before any page can be retained under it.
    pub(crate) fn cache_generation(&self, tree: u64, ino: u64) -> u64 {
        let mut generations = self.cache_generations.lock();
        match generations.values.get(&(tree, ino)) {
            Some(&generation) => generation,
            None => {
                let generation = generations.fresh_tick();
                generations.values.insert((tree, ino), generation);
                generation
            }
        }
    }

    /// Record a change to inode `ino` in fs tree `tree`: a content
    /// mutation (bytes or length), the inode's destruction, or a
    /// create landing a new file on a (possibly recycled) inode
    /// number. Assigns a fresh tick rather than incrementing, so the
    /// value afterwards names the new instance / epoch and no earlier
    /// tenant's. Every such change in this driver bumps exactly once,
    /// before the operation returns, so a completed mutation can
    /// never leave a retained page looking current.
    pub(crate) fn bump_cache_generation(&self, tree: u64, ino: u64) {
        let mut generations = self.cache_generations.lock();
        let generation = generations.fresh_tick();
        generations.values.insert((tree, ino), generation);
    }

    /// Forget every generation issued for fs tree `tree` (subvolume
    /// destruction). Tree ids are issued max+1 (`next_subvol_id`), so
    /// a destroyed tree's id can be reissued to a later subvolume;
    /// without this, the new tree's files could read the destroyed
    /// tree's leftover values. Forgotten keys are reissued lazily
    /// from the same never-repeating tick source, so a recycled tree
    /// id starts from values no page was ever retained under.
    pub(crate) fn prune_cache_generations(&self, tree: u64) {
        self.cache_generations
            .lock()
            .values
            .retain(|&(t, _), _| t != tree);
        self.orphans.lock().retain(|&(t, _)| t != tree);
    }

    /// The live [`MmapAnchor`] of inode `ino` in fs tree `tree`, created on
    /// first use. Dead entries are pruned as the table grows.
    pub(crate) fn mmap_anchor(&self, tree: u64, ino: u64, inode: InodeItem) -> Arc<MmapAnchor> {
        let mut anchors = self.mmap_anchors.lock();
        if let Some(anchor) = anchors.get(&(tree, ino)).and_then(Weak::upgrade) {
            return anchor;
        }
        if anchors.len() >= 256 && anchors.len().is_power_of_two() {
            anchors.retain(|_, anchor| anchor.strong_count() != 0);
        }
        let anchor = Arc::new(MmapAnchor {
            _tree: tree,
            _ino: ino,
            inode: IrqSafeSpinLock::new(inode),
            live_size: core::sync::atomic::AtomicU64::new(inode.size),
        });
        anchors.insert((tree, ino), Arc::downgrade(&anchor));
        anchor
    }

    pub(crate) fn inode_is_open(&self, tree: u64, ino: u64) -> bool {
        self.mmap_anchors
            .lock()
            .get(&(tree, ino))
            .is_some_and(|inode| inode.strong_count() != 0)
    }

    pub(crate) fn note_orphan(&self, tree: u64, ino: u64) {
        self.orphans.lock().insert((tree, ino));
        let anchor = self
            .mmap_anchors
            .lock()
            .get(&(tree, ino))
            .and_then(Weak::upgrade);
        if let Some(anchor) = anchor {
            anchor.inode.lock().nlink = 0;
        }
    }

    pub(crate) fn orphan_snapshot(&self) -> Vec<(u64, u64)> {
        self.orphans.lock().iter().copied().collect()
    }

    pub(crate) fn forget_orphan(&self, tree: u64, ino: u64) {
        self.orphans.lock().remove(&(tree, ino));
    }

    /// The transaction accumulating operations that have not committed yet.
    pub(crate) fn fs_batch(&self) -> &Mutex<Option<crate::write::FsBatch>> {
        &self.fs_batch
    }

    /// No mount of this filesystem may write (mounted or remounted ro).
    pub(crate) fn is_core_read_only(&self) -> bool {
        self.read_only.load(core::sync::atomic::Ordering::Acquire)
    }

    /// The filesystem UUID this instance serves.
    pub fn fsid(&self) -> [u8; 16] {
        self.state.lock().superblock.fsid
    }

    /// Whether `devid` is one of this instance's assembled members.
    pub fn has_member(&self, devid: u64) -> bool {
        self.devices.lock().contains_key(&devid)
    }

    /// Mounts currently rooted at subvolume `id`, across every view.
    pub fn subvol_mount_count(&self, id: u64) -> usize {
        self.state
            .lock()
            .subvols
            .get(&id)
            .map_or(0, |live| live.mounts)
    }
}

/// One btrfs inode's `MAP_SHARED` identity. Every open of a btrfs file gets
/// its own [`crate::node::BtrfsNode`], but `MAP_SHARED` mappings of the
/// same inode must share pages across those opens (journald writes its
/// journal through one mapping while `journalctl` reads it through
/// another). The address of the single live anchor per `(fs tree, inode)`
/// is what `FileOps::mmap_backing_identity` reports; every node of the
/// inode holds it, so it cannot be reused while any mapping exists.
#[derive(Debug)]
pub(crate) struct MmapAnchor {
    _tree: u64,
    _ino: u64,
    pub(crate) inode: IrqSafeSpinLock<InodeItem>,
    pub(crate) live_size: core::sync::atomic::AtomicU64,
}

/// Content-generation counters for one filesystem instance, backing
/// `FileOps::mmap_cache_generation` and keyed by the same
/// `(fs tree id, inode number)` pair as the identity anchors above.
/// Nodes are minted per lookup, so the counter cannot live on the
/// node: two opens of one file are two objects, and a write through
/// one must invalidate pages retained through the other. The core is
/// the one place every view (mount) of the filesystem shares.
///
/// Values are NOT per-inode counters: every assignment — the first
/// read of an inode, a content mutation, a create — draws a fresh
/// core-wide tick. A generation therefore names one file *instance*
/// at one mutation epoch: two different inodes (or two successive
/// tenants of one recycled inode number, or of one recycled tree id)
/// can never hold the same value, so a retained page's recorded
/// generation can only ever match the file instance that published
/// it. That uniqueness is what makes the generation half of the
/// page cache's (identity, generation) guard sound even when an
/// identity anchor's address is recycled.
#[derive(Debug)]
pub(crate) struct CacheGenerations {
    values: BTreeMap<(u64, u64), u64>,
    /// Next tick to issue. Starts at 1: 0 is never a real generation,
    /// so an inode with no entry yet cannot alias an issued one.
    next_tick: u64,
}

impl CacheGenerations {
    fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            next_tick: 1,
        }
    }

    fn fresh_tick(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick = self.next_tick.wrapping_add(1);
        if self.next_tick == 0 {
            self.next_tick = 1;
        }
        tick
    }
}

/// The filesystem-wide half of a mount (Linux `btrfs_fs_info`): devices,
/// superblock, chunk map, node cache, the running transaction and its
/// allocator, pinned extents, and the commit timer.
#[derive(Debug)]
pub struct VolCore<B: BlockDevice> {
    /// Live [`MmapAnchor`]s by `(fs tree id, inode number)`.
    mmap_anchors: IrqSafeSpinLock<BTreeMap<(u64, u64), Weak<MmapAnchor>>>,
    /// Unlinked inode items are persisted with Linux ORPHAN_ITEM records.
    /// Cleanup waits for every lookup/mapping anchor, then runs under op_lock.
    orphans: IrqSafeSpinLock<BTreeSet<(u64, u64)>>,
    /// Per-inode content generations backing
    /// `FileOps::mmap_cache_generation`, keyed by the same
    /// `(fs tree id, inode number)` pair as `mmap_anchors`: the
    /// generation domain must be exactly the identity domain, so
    /// both live here on the shared core, not on a mount view.
    cache_generations: IrqSafeSpinLock<CacheGenerations>,
    /// Source device passed first at mount. Retained for compatibility with
    /// single-device callers and tests; logical I/O routes through `devices`.
    pub device: Arc<B>,
    /// Immutable geometry (copied out of the superblock so hot reads need no
    /// lock).
    magic: u64,
    nodesize: u32,
    sectorsize: u32,
    domain: DomainId,
    /// On-disk metadata/data checksum algorithm selected by the superblock.
    csum_type: u16,
    /// Enforce per-node/superblock checksum verification.
    verify_checksums: bool,
    /// Missing members make a redundant array readable but never writable.
    degraded: bool,
    /// Mounted read-only: requested, or a member device reports
    /// `is_read_only` (`narf.disks=boot-only`). Nothing is ever written —
    /// no log replay (a pending log tree refuses the mount), no commit timer,
    /// and every device write funnel returns `ReadOnly`. A later read-write
    /// mount of the same filesystem may clear it ([`BtrfsVolume::make_writable`]),
    /// as Linux's `btrfs_reconfigure` flips the superblock to rw.
    read_only: core::sync::atomic::AtomicBool,
    /// Serialises closing a transaction against opening the next one, so a
    /// new batch never builds its allocator or generation from state an
    /// in-flight commit is about to change (Linux waits on
    /// `fs_info->trans_lock`/`TRANS_STATE_COMMIT_START` the same way).
    txn_lock: Mutex<()>,
    /// Serialises mutating operations on the filesystem, from their first
    /// tree read to their staging. Every operation computes its edits (the new
    /// inode number, the directory index, the extents a write displaces) from
    /// the tree as it reads it; another CPU's operation staging in between
    /// would make those edits collide (two inodes with one number, one
    /// directory index for two names). Linux holds the parent directory's
    /// `i_rwsem` and the btree path locks for the same span; one lock per
    /// filesystem is the coarse equivalent.
    op_lock: Mutex<()>,
    /// Raw `flags` word of the selected superblock (for [`crate::rw_gate`]).
    super_flags: u64,
    /// The write-safety gate's verdict, computed once at mount: `Some` means
    /// no mount of this core may ever write (see [`crate::rw_gate`]).
    rw_refusal: IrqSafeSpinLock<Option<crate::rw_gate::Refusal>>,
    /// The gate's sharing walk ([`crate::rw_gate::check_sharing`]) has run
    /// for this core. A core mounted read-only skips it (it reads every
    /// metadata extent item, slow on a root with many snapshots, and a read
    /// error in it would only matter for writing); the first request to
    /// write runs it ([`BtrfsVolume::ensure_sharing_checked`]).
    sharing_checked: core::sync::atomic::AtomicBool,
    /// The commit timer (Linux `transaction_kthread`) runs once per core.
    timer_started: core::sync::atomic::AtomicBool,
    /// A remount to read-only is draining the running transaction: new
    /// operations are refused while the commit it forces still writes.
    frozen: core::sync::atomic::AtomicBool,
    devices: IrqSafeSpinLock<BTreeMap<u64, Arc<VolumeDevice<B>>>>,
    state: IrqSafeSpinLock<VolState>,
    /// A stamped superblock image whose commit has completed in memory but
    /// which is not yet on disk, plus whether it must go through the
    /// root-admin write path.
    ///
    /// Batching commits means the superblock stops flipping per write. The
    /// tree blocks are already out and `commit_roots` has advanced the
    /// in-memory roots, so readers follow the new tree; only durability lags.
    /// A crash here loses every staged commit and the filesystem falls back to
    /// the last superblock on disk — which is intact precisely because the
    /// blocks it references are pinned until this image lands.
    staged_super: IrqSafeSpinLock<Option<(alloc::vec::Vec<u8>, bool)>>,
    /// Commits staged since the superblock last reached disk.
    staged_count: core::sync::atomic::AtomicUsize,
    /// Multi-stage operations in flight ([`VolCore::hold_commits`]): while
    /// non-zero, a full batch is not committed between their stages.
    commit_holds: core::sync::atomic::AtomicUsize,
    /// Test-only: abort the next commit after its nodes are written but before
    /// the superblock, standing in for a crash at the one instant the COW
    /// invariant is load-bearing.
    #[cfg(feature = "kernel-test")]
    crash_before_super: core::sync::atomic::AtomicBool,
    /// Extents freed by the in-flight transaction, withheld from allocation
    /// until a superblock that no longer references them is durable.
    ///
    /// This is Linux's `trans->transaction->pinned_extents`. Freeing a block
    /// mid-transaction does NOT return it to the allocator
    /// (`extent-tree.c::pin_down_extent`); `btrfs_commit_transaction` releases
    /// the set only after `write_all_supers` succeeds, with the comment "the
    /// super is written, we can safely allow the tree-loggers to go about
    /// their business".
    ///
    /// The invariant that buys: a block a transaction freed cannot be
    /// reallocated until a superblock referencing the tree that no longer uses
    /// it is on disk. Without it, a crash between writing new nodes and
    /// writing the superblock leaves the committed tree pointing at a block
    /// that has already been overwritten — silent corruption, and invisible to
    /// `btrfs check` until after the crash.
    ///
    /// NARF flips the superblock on every write, so today the set is emptied
    /// before the next allocation and never withholds anything. It exists so
    /// that stops being what makes the invariant hold. Linux keeps it on the
    /// transaction; it sits here until NARF has a transaction object, which is
    /// sound only while at most one commit is in flight.
    pinned: IrqSafeSpinLock<alloc::vec::Vec<(u64, u64)>>,
    /// Tree roots a lock-free reader is walking from, with a count per
    /// address ([`BtrfsVolume::pin_live_root`]). A reader verifies every
    /// child it reads against its parent's pointer (generation, level, first
    /// key), so a block freed and reused under it is caught — except the
    /// root, which has no parent. A root the reader sampled can be retired
    /// by the next operation, committed, unpinned and handed out again while
    /// the reader is still on its way to it; the reader would then walk
    /// whatever was written there as if it were the tree (seen as ENOENT and
    /// as wrong file contents in the SMP racing-writers test). The allocator
    /// withholds these addresses ([`crate::allocator::Allocator::build`]).
    reader_roots: IrqSafeSpinLock<BTreeMap<u64, u32>>,
    /// Metadata node cache, keyed by logical address.
    ///
    /// A commit path-COWs the extent tree once per fixed-point round, and a
    /// round re-reads the same nodes the previous one did — measured at 724
    /// rounds across 152 commits in the boot write smoke, with that re-reading
    /// the single largest cost in the whole commit. Every miss costs an
    /// (emulated) device read plus a full-node checksum verification, and both
    /// are pure repetition for a block nothing has written since.
    nodes: IrqSafeSpinLock<NodeCache>,
    /// Set when a transaction was lost after its operations had already
    /// reported success. See [`Self::abort_transaction`].
    aborted: core::sync::atomic::AtomicBool,
    /// `BTRFS_FS_QUOTA_OVERRIDE` — see [`Self::quota_override`].
    quota_override: core::sync::atomic::AtomicBool,
    /// Operations accumulated into the transaction that has not committed yet.
    /// An async mutex rather than a spinlock: an operation holds it across its
    /// tree reads and node writes, which is also what serialises the shared
    /// allocator inside it.
    fs_batch: Mutex<Option<crate::write::FsBatch>>,
    /// Run when the last mount (view) of this core drops: commits whatever a
    /// writable core still holds (see [`commit_on_last_drop`]). A function
    /// pointer because `Drop` cannot carry the `'static` bound committing
    /// needs; it is instantiated where the core is built.
    last_view_dropped: fn(&Arc<VolCore<B>>),
    /// The drop-time commit has been started once; a failed one is not
    /// retried by every internal view that drops after it.
    drop_commit_tried: core::sync::atomic::AtomicBool,
}

/// Whether a core still holds work no superblock on disk describes: a batch
/// with staged operations, or a committed transaction whose superblock is
/// only staged. A batch lock held by someone else counts as dirty.
fn core_is_dirty<B: BlockDevice>(core: &VolCore<B>) -> Option<u64> {
    let staged = core.staged_super.lock().is_some();
    let batch_tree = match core.fs_batch.try_lock() {
        Some(guard) => guard
            .as_ref()
            .filter(|batch| batch.has_ops())
            .map(|batch| batch.tree_id()),
        None => Some(format::FS_TREE_OBJECTID),
    };
    match (batch_tree, staged) {
        (Some(tree), _) => Some(tree),
        (None, true) => Some(format::FS_TREE_OBJECTID),
        (None, false) => None,
    }
}

/// The last mount of a writable filesystem went away (umount, a dropped
/// internal mount): make everything it accepted durable instead of silently
/// discarding the open batch and the staged superblock with the core (Linux
/// `close_ctree` → `btrfs_commit_super`).
///
/// Drop cannot block, so the commit runs on an internal view of the core:
/// polled once in place — on a synchronous block device with nothing else
/// holding the locks that completes it — and otherwise handed to the
/// executor, which keeps the core alive until it is done. A failure is
/// logged and leaves the filesystem in its error state; it is never retried
/// in a loop.
fn commit_on_last_drop<B: BlockDevice + 'static>(core: &Arc<VolCore<B>>) {
    use core::fmt::Write as _;
    if core.is_core_read_only() || core.aborted.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let Some(tree) = core_is_dirty(core) else {
        return;
    };
    if core
        .drop_commit_tried
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let view = BtrfsVolume::view_for_tree(core, tree);
    let mut commit: core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = ()> + Send>,
    > = alloc::boxed::Box::pin(async move {
        // Drop makes accepted changes durable; it does not start a new
        // eviction transaction. Unreaped ORPHAN_ITEMs remain recoverable at
        // the next writable mount, even when no scheduler work can run.
        if let Err(error) = view.sync_to_disk().await {
            let _ = writeln!(
                    narf_console::Writer,
                    "btrfs: commit at last unmount FAILED ({error:?}); the filesystem stays at its last durable generation"
                );
        }
    });
    let waker = noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    if commit.as_mut().poll(&mut cx).is_pending() {
        narf_scheduler::spawn(commit);
    }
}

/// A waker that does nothing, for the single in-place poll above.
fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn clone(_: *const ()) -> RawWaker {
        raw()
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable never dereferences the (null) data pointer.
    unsafe { Waker::from_raw(raw()) }
}

/// `CAP_SYS_RESOURCE` — see [`BtrfsVolume::quota_override`].
const CAP_SYS_RESOURCE: u32 = 24;

/// Render a 16-byte fsid the way btrfs names its sysfs directory.
fn format_fsid(fsid: &[u8; 16]) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(36);
    for (i, byte) in fsid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&alloc::format!("{byte:02x}"));
    }
    out
}

impl<B: BlockDevice + 'static> BtrfsVolume<B> {
    // ── Geometry accessors (lock-free) ─────────────────────────────

    pub fn magic(&self) -> u64 {
        self.magic
    }

    pub fn nodesize(&self) -> usize {
        self.nodesize as usize
    }

    pub fn sectorsize(&self) -> u32 {
        self.sectorsize
    }

    pub fn total_bytes(&self) -> u64 {
        self.state.lock().superblock.total_bytes
    }

    pub fn verify_checksums(&self) -> bool {
        self.verify_checksums
    }

    pub(crate) fn csum_type(&self) -> u16 {
        self.csum_type
    }

    /// All checksum algorithms accepted at mount are emitted by the COW writer.
    /// A subvolume marked read-only in its root item remains read-only, and so
    /// does one whose transaction was aborted.
    pub(crate) fn supports_writes(&self) -> bool {
        !self.core_read_only()
            && !self.view_read_only()
            && !self.degraded
            && !self.aborted.load(core::sync::atomic::Ordering::Acquire)
            && self.fs_tree_flags() & format::ROOT_SUBVOL_RDONLY == 0
    }

    /// [`Self::supports_writes`] and not being remounted read-only: the check
    /// an operation passes before it starts. The write funnels keep using
    /// `supports_writes`, so the draining commit itself can still land.
    pub(crate) fn admits_writes(&self) -> bool {
        self.supports_writes() && !self.frozen.load(core::sync::atomic::Ordering::Acquire)
    }

    /// The gate for administrative writers that may legitimately run on a
    /// subvolume marked read-only (`BTRFS_IOC_SUBVOL_SETFLAGS` clearing that
    /// very flag, qgroup/quota administration): everything
    /// [`Self::admits_writes`] requires except the subvolume's `RDONLY` flag.
    pub(crate) fn admits_admin_writes(&self) -> bool {
        use core::sync::atomic::Ordering;
        !self.core_read_only()
            && !self.view_read_only()
            && !self.degraded
            && !self.aborted.load(Ordering::Acquire)
            && !self.frozen.load(Ordering::Acquire)
    }

    fn view_read_only(&self) -> bool {
        self.view_read_only
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// `mount -o remount,ro` (Linux `btrfs_reconfigure` →
    /// `btrfs_remount_ro`): stop admitting operations, commit the running
    /// transaction and make its superblock durable (`btrfs_commit_super`),
    /// then mark the filesystem read-only. The superblock is shared by every
    /// mount of the filesystem, so they all become read-only, as on Linux.
    /// The commit timer idles while the filesystem is read-only.
    pub async fn remount_read_only(&self) -> Result<(), FsError> {
        use core::sync::atomic::Ordering;
        if self.core_read_only() {
            return Ok(());
        }
        self.frozen.store(true, Ordering::Release);
        // Wait out any operation admitted before the freeze; none can start
        // after it.
        let _ops = self.op_lock.lock().await;
        let result = loop {
            if let Err(err) = self.sync_to_disk().await {
                break Err(err);
            }
            // Close the window an operation admitted just before the freeze
            // could still use: flip only with no batch open and nothing
            // staged, under the lock every new batch must take.
            let _txn = self.txn_lock().lock().await;
            let mut batch = self.fs_batch().lock().await;
            let pending =
                batch.as_ref().is_some_and(|b| b.has_ops()) || self.staged_super.lock().is_some();
            if pending {
                continue;
            }
            *batch = None;
            self.read_only.store(true, Ordering::Release);
            break Ok(());
        };
        self.frozen.store(false, Ordering::Release);
        result
    }

    /// Run the gate's deferred sharing walk if this core was mounted
    /// read-only and has not had it yet; a refusal is recorded like one at
    /// mount (and makes [`Self::make_writable`] fail). Called before any
    /// read-write request on such a core.
    pub(crate) async fn ensure_sharing_checked(&self) -> Result<(), FsError> {
        use core::sync::atomic::Ordering;
        if self.sharing_checked.load(Ordering::Acquire) {
            return Ok(());
        }
        let verdict = crate::rw_gate::check_sharing(self).await;
        if let Err(why) = verdict {
            let mut refusal = self.rw_refusal.lock();
            if refusal.is_none() {
                *refusal = Some(why);
            }
        }
        self.sharing_checked.store(true, Ordering::Release);
        Ok(())
    }

    /// Test accessor: whether the gate's sharing walk has run for this core.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn __test_sharing_checked(&self) -> bool {
        self.sharing_checked
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// `mount -o remount,rw` (`btrfs_remount_rw`): make the filesystem
    /// writable again, refused (`ReadOnly` → EROFS) exactly where a
    /// read-write mount would be, and clear this mount's own read-only
    /// request.
    pub fn remount_read_write(self: &Arc<Self>) -> Result<(), FsError> {
        self.make_writable()?;
        self.view_read_only
            .store(false, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// The data options recorded at mount (see [`crate::mount_opts`]).
    pub fn mount_options(&self) -> crate::mount_opts::MountOptions {
        self.mount_options.lock().clone()
    }

    /// Record the data options of the mount that built this volume.
    pub fn set_mount_options(&self, options: crate::mount_opts::MountOptions) {
        *self.mount_options.lock() = options;
    }

    /// Objectid of the mounted subvolume (`5` = the top-level FS tree).
    pub fn mounted_subvol_id(&self) -> u64 {
        self.view.lock().fs_tree_id
    }

    pub fn is_read_only(&self) -> bool {
        self.core_read_only() || self.view_read_only()
    }

    /// Refuse all further writes, because a transaction was lost after its
    /// operations had already reported success.
    ///
    /// This is `btrfs_abort_transaction`, whose comment states the same
    /// reasoning: "We only mark the transaction aborted and then set the file
    /// system read-only. This will prevent new transactions from starting."
    /// There is nothing else honest to do. A batch commits many operations at
    /// once; if it fails, the callers of the operations it held have already
    /// been told those succeeded, and there is no one left to report the
    /// failure to. Continuing to accept writes would build the next
    /// transaction on a tree those callers believe contains their work and
    /// which does not.
    ///
    /// Read paths keep working, and they show the last committed tree — the
    /// lost operations are absent from it, which is the truth.
    pub(crate) fn abort_transaction(&self) {
        self.aborted
            .store(true, core::sync::atomic::Ordering::Release);
    }

    /// Whether `BTRFS_FS_QUOTA_OVERRIDE` is set on this filesystem.
    ///
    /// Half of the condition; the other half is the RESERVING caller holding
    /// CAP_SYS_RESOURCE, which is checked at the reservation itself. Linux
    /// requires both:
    ///
    /// ```text
    /// if (test_bit(BTRFS_FS_QUOTA_OVERRIDE, &fs_info->flags) &&
    ///     capable(CAP_SYS_RESOURCE))
    ///         enforce = false;
    /// ```
    ///
    /// The flag alone is not the bypass. An administrator turning it on does
    /// not disable quota enforcement for everyone — unprivileged writers stay
    /// enforced, and only a privileged one may dig the filesystem out from
    /// under a limit it can no longer write beneath.
    pub(crate) fn quota_override(&self) -> bool {
        self.quota_override
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// Set or clear `BTRFS_FS_QUOTA_OVERRIDE`.
    ///
    /// Linux exposes this as `/sys/fs/btrfs/<uuid>/quota_override`, whose
    /// store handler requires CAP_SYS_RESOURCE (`fs/btrfs/sysfs.c`); the
    /// attribute registered at mount enforces that before calling here.
    pub(crate) fn set_quota_override(&self, on: bool) {
        self.quota_override
            .store(on, core::sync::atomic::Ordering::Release);
    }

    /// Test-only: set the flag without going through sysfs, so the bypass can
    /// be exercised independently of the attribute that publishes it.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn __test_set_quota_override(&self, on: bool) {
        self.set_quota_override(on);
    }

    /// The write-safety gate's refusal, if it refused this core.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn rw_refusal(&self) -> Option<crate::rw_gate::Refusal> {
        self.rw_refusal.lock().clone()
    }

    /// Whether a transaction has been aborted on this volume.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn transaction_aborted(&self) -> bool {
        self.aborted.load(core::sync::atomic::Ordering::Acquire)
    }

    /// `(devid, physical capacity)` for every assembled member.
    pub(crate) fn member_capacities(&self) -> Vec<(u64, u64)> {
        self.devices
            .lock()
            .iter()
            .map(|(&devid, member)| (devid, member.capacity))
            .collect()
    }

    pub(crate) fn member_dev_items(&self) -> Vec<(u64, [u8; format::SUPERBLOCK_DEV_ITEM_SIZE])> {
        self.devices
            .lock()
            .iter()
            .map(|(&devid, member)| (devid, *member.dev_item.lock()))
            .collect()
    }

    fn device_uuid(&self, devid: u64, capacity: u64) -> [u8; 16] {
        let sb = self.superblock();
        let mut uuid = sb.fsid;
        let salt = devid ^ capacity.rotate_left(17) ^ sb.generation.rotate_left(31);
        for (index, byte) in uuid.iter_mut().enumerate() {
            *byte ^= salt.rotate_left((index * 7) as u32) as u8;
            *byte = byte.wrapping_add((index as u8).wrapping_mul(0x3d));
        }
        // RFC-4122-shaped bits are conventional for btrfs UUIDs even though
        // the on-disk format treats the field as opaque.
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        uuid
    }

    async fn new_member(
        &self,
        device: Arc<B>,
        dev_item: [u8; format::SUPERBLOCK_DEV_ITEM_SIZE],
    ) -> Result<Arc<VolumeDevice<B>>, FsError> {
        let logical = device.logical_block_size() as usize;
        if !(512..=4096).contains(&logical) || !logical.is_power_of_two() {
            return Err(FsError::Unsupported);
        }
        let capacity = device
            .capacity_blocks()
            .checked_mul(logical as u64)
            .ok_or(FsError::InvalidData)?;
        if capacity <= 1024 * 1024 || capacity % u64::from(self.sectorsize) != 0 {
            return Err(FsError::InvalidData);
        }
        let io = new_volume_io(logical, self.domain)?;
        Ok(Arc::new(VolumeDevice {
            device,
            capacity,
            dev_item: IrqSafeSpinLock::new(dev_item),
            io: Mutex::new(io),
        }))
    }

    /// Add a writable member and commit its `DEV_ITEM` plus superblocks. New
    /// chunks continue to use the current profiles; a later balance can spread
    /// existing allocations onto the member.
    pub async fn add_device(&self, device: Arc<B>) -> Result<u64, FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        if self
            .devices
            .lock()
            .values()
            .any(|member| Arc::ptr_eq(&member.device, &device))
        {
            return Err(FsError::Busy);
        }
        let devid = self
            .devices
            .lock()
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(FsError::InvalidData)?;
        let logical = device.logical_block_size() as u64;
        let capacity = device
            .capacity_blocks()
            .checked_mul(logical)
            .ok_or(FsError::InvalidData)?;
        let total = capacity / u64::from(self.sectorsize) * u64::from(self.sectorsize);
        let mut item = [0u8; format::SUPERBLOCK_DEV_ITEM_SIZE];
        item[0..8].copy_from_slice(&devid.to_le_bytes());
        item[8..16].copy_from_slice(&total.to_le_bytes());
        item[24..28].copy_from_slice(&self.sectorsize.to_le_bytes());
        item[28..32].copy_from_slice(&self.sectorsize.to_le_bytes());
        item[32..36].copy_from_slice(&self.sectorsize.to_le_bytes());
        item[66..82].copy_from_slice(&self.device_uuid(devid, total));
        item[82..98].copy_from_slice(&self.superblock().fsid);
        let member = self.new_member(device, item).await?;
        self.devices.lock().insert(devid, member);
        if let Err(error) = crate::write::grow_add_chunk(self).await {
            self.devices.lock().remove(&devid);
            return Err(error);
        }
        Ok(devid)
    }

    /// Relocate selected block groups onto freshly allocated physical extents
    /// and atomically replace their chunk geometry. Logical addresses do not
    /// change, so file/tree backreferences remain valid while the profile does.
    pub async fn balance_profiles(
        &self,
        profiles: BalanceProfiles,
    ) -> Result<BalanceStats, FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        crate::write::balance_profiles(self, profiles, None).await
    }

    /// Replace one member with another device while retaining its devid, UUID,
    /// and physical stripe offsets. Only allocated device extents are copied.
    pub async fn replace_device(&self, devid: u64, target: Arc<B>) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        if crate::rw_gate::active_profile() == crate::rw_gate::Profile::RootRw {
            return Err(FsError::Unsupported);
        }
        let source = self.member(devid)?;
        if self
            .devices
            .lock()
            .values()
            .any(|member| Arc::ptr_eq(&member.device, &target))
        {
            return Err(FsError::Busy);
        }
        let replacement = self.new_member(target, *source.dev_item.lock()).await?;
        if replacement.capacity < source.capacity {
            return Err(FsError::NoSpace);
        }
        for (start, length) in crate::write::device_extent_ranges(self, devid).await? {
            let mut offset = 0u64;
            while offset < length {
                let take = (length - offset).min(128 * 1024) as usize;
                let mut bytes = vec![0u8; take];
                read_exact_from(
                    &*source.device,
                    &source.io,
                    source.capacity,
                    start + offset,
                    &mut bytes,
                )
                .await?;
                write_exact_to(
                    &*replacement.device,
                    &replacement.io,
                    replacement.capacity,
                    start + offset,
                    &bytes,
                    false,
                )
                .await?;
                offset += take as u64;
            }
        }
        let raw = self.read_raw_superblock().await?;
        self.devices.lock().insert(devid, replacement);
        self.write_superblock(&raw).await?;
        let zero = vec![0u8; format::SUPERBLOCK_SIZE];
        for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
            if offset + format::SUPERBLOCK_SIZE as u64 <= source.capacity {
                write_exact_to(
                    &*source.device,
                    &source.io,
                    source.capacity,
                    offset,
                    &zero,
                    false,
                )
                .await?;
            }
        }
        source.device.flush_result().await.map_err(FsError::Io)?;
        Ok(())
    }

    /// Remove a member, first relocating every chunk stripe that resides on it
    /// while retaining each block group's current profile.
    pub async fn remove_device(&self, devid: u64) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        if self.devices.lock().len() <= 1 {
            return Err(FsError::Busy);
        }
        if !crate::write::device_extent_ranges(self, devid)
            .await?
            .is_empty()
        {
            crate::write::balance_profiles(self, BalanceProfiles::default(), Some(devid)).await?;
        }
        let removed = self
            .devices
            .lock()
            .remove(&devid)
            .ok_or(FsError::NotFound)?;
        self.select_live_superblock_source()?;
        if let Err(error) = crate::write::grow_add_chunk(self).await {
            self.devices.lock().insert(devid, removed);
            self.select_live_superblock_source()?;
            return Err(error);
        }
        let zero = vec![0u8; format::SUPERBLOCK_SIZE];
        for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
            if offset + format::SUPERBLOCK_SIZE as u64 <= removed.capacity {
                write_exact_to(
                    &*removed.device,
                    &removed.io,
                    removed.capacity,
                    offset,
                    &zero,
                    false,
                )
                .await?;
            }
        }
        removed.device.flush_result().await.map_err(FsError::Io)?;
        Ok(())
    }

    /// Objectid of the currently mounted fs tree (`5` for the top-level tree).
    pub(crate) fn fs_tree_id(&self) -> u64 {
        self.view.lock().fs_tree_id
    }

    /// On-disk `btrfs_root_item.flags` for the mounted subvolume.
    pub(crate) fn fs_tree_flags(&self) -> u64 {
        let id = self.fs_tree_id();
        self.state
            .lock()
            .subvols
            .get(&id)
            .map_or(0, |live| live.flags)
    }

    // ── State snapshots (brief lock, no I/O) ───────────────────────

    /// Currently mounted fs-tree/subvolume root `(logical, level)`.
    pub fn fs_tree_root(&self) -> (u64, u8) {
        let id = self.fs_tree_id();
        self.state
            .lock()
            .subvols
            .get(&id)
            .map_or((0, 0), |live| (live.root, live.level))
    }

    /// Root-tree root `(logical, level)` from the live superblock.
    pub fn root_tree_root(&self) -> (u64, u8) {
        let g = self.state.lock();
        (g.superblock.root, g.superblock.root_level)
    }

    /// Number of chunks currently in the map.
    pub fn chunk_map_len(&self) -> usize {
        self.state.lock().chunk_map.len()
    }

    /// Translate a logical address to a physical offset via the chunk map.
    pub fn map_logical(&self, logical: u64) -> Result<u64, FsError> {
        self.state.lock().chunk_map.map_logical(logical)
    }

    /// Translate a logical address to its primary and optional single-device
    /// DUP copy.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn map_logical_copies(&self, logical: u64) -> Result<(u64, Option<u64>), FsError> {
        self.state.lock().chunk_map.map_logical_copies(logical)
    }

    /// Logical ranges the allocator must never hand out because a
    /// superblock copy lives under them (see
    /// [`ChunkMap::super_stripe_exclusions`]).
    pub(crate) fn super_stripe_exclusions(&self) -> Vec<(u64, u64)> {
        self.state
            .lock()
            .chunk_map
            .super_stripe_exclusions(&format::SUPERBLOCK_MIRROR_OFFSETS)
    }

    /// Logical bytes left in the containing chunk/block group.
    pub(crate) fn logical_chunk_remaining(&self, logical: u64) -> Result<u64, FsError> {
        self.state.lock().chunk_map.chunk_remaining(logical)
    }

    /// Resolve every direct copy of a logical byte, preserving device ids.
    pub fn map_logical_stripes(
        &self,
        logical: u64,
    ) -> Result<Vec<crate::chunk::StripeLocation>, FsError> {
        self.state.lock().chunk_map.map_logical_stripes(logical)
    }

    /// Snapshot of the live superblock (for statfs / write bookkeeping).
    pub fn superblock(&self) -> Superblock {
        self.state.lock().superblock.clone()
    }

    // ── Physical / logical reads ───────────────────────────────────

    fn member(&self, devid: u64) -> Result<Arc<VolumeDevice<B>>, FsError> {
        self.devices
            .lock()
            .get(&devid)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    /// Read `dst.len()` bytes at a member device's physical byte offset.
    pub(crate) async fn read_physical_on(
        &self,
        devid: u64,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let member = self.member(devid)?;
        read_exact_from(&*member.device, &member.io, member.capacity, offset, dst).await
    }

    /// Read one direct-copy choice, splitting at chunk/stripe boundaries.
    async fn read_logical_copy(
        &self,
        logical: u64,
        dst: &mut [u8],
        copy: usize,
    ) -> Result<(), FsError> {
        let mut done = 0usize;
        while done < dst.len() {
            let at = logical
                .checked_add(done as u64)
                .ok_or(FsError::InvalidData)?;
            let (locations, contiguous) = {
                let g = self.state.lock();
                (
                    g.chunk_map.map_logical_stripes(at)?,
                    g.chunk_map.max_contiguous(at)?,
                )
            };
            let take = (dst.len() - done).min(contiguous as usize);
            if let Some(location) = locations.get(copy) {
                self.read_physical_on(
                    location.devid,
                    location.physical,
                    &mut dst[done..done + take],
                )
                .await?;
            } else if copy == locations.len() {
                self.reconstruct_raid56(at, &mut dst[done..done + take])
                    .await?;
            } else {
                return Err(FsError::NotFound);
            }
            done += take;
        }
        Ok(())
    }

    /// Rebuild one RAID5/6 logical data slice. The requested stripe is treated
    /// as absent even when readable, which gives checksum-aware callers an
    /// independent parity-derived retry for silent corruption.
    async fn reconstruct_raid56(&self, logical: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let set = self.state.lock().chunk_map.raid56_set(logical)?;
        let delta = logical
            .checked_sub(set.logical_start)
            .ok_or(FsError::InvalidData)?;
        let target = (delta / set.stripe_len) as usize;
        let within = delta % set.stripe_len;
        if target >= set.data.len() || dst.len() as u64 > set.stripe_len - within {
            return Err(FsError::InvalidData);
        }

        let mut data = Vec::with_capacity(set.data.len());
        let mut unavailable = 1usize; // requested data stripe is intentionally absent
        for (index, location) in set.data.iter().enumerate() {
            if index == target {
                data.push(None);
                continue;
            }
            let mut bytes = vec![0u8; dst.len()];
            if self
                .read_physical_on(location.devid, location.physical + within, &mut bytes)
                .await
                .is_ok()
            {
                data.push(Some(bytes));
            } else {
                unavailable += 1;
                data.push(None);
            }
        }

        let mut parity = Vec::with_capacity(set.parity.len());
        for location in &set.parity {
            let mut bytes = vec![0u8; dst.len()];
            if self
                .read_physical_on(location.devid, location.physical + within, &mut bytes)
                .await
                .is_ok()
            {
                parity.push(Some(bytes));
            } else {
                unavailable += 1;
                parity.push(None);
            }
        }
        if unavailable > set.parity.len() {
            return Err(FsError::NotFound);
        }
        crate::raid56::recover(
            &mut data,
            parity.first().and_then(Option::as_deref),
            parity.get(1).and_then(Option::as_deref),
            dst.len(),
        )?;
        dst.copy_from_slice(data[target].as_deref().ok_or(FsError::InvalidData)?);
        Ok(())
    }

    fn logical_read_copies(&self, logical: u64) -> Result<usize, FsError> {
        let g = self.state.lock();
        let direct = g.chunk_map.map_logical_stripes(logical)?.len();
        match g.chunk_map.raid56_set(logical) {
            Ok(_) => Ok(direct + 1),
            Err(FsError::Unsupported) => Ok(direct),
            Err(error) => Err(error),
        }
    }

    /// Read `len` bytes at btrfs *logical* address `logical`. The range must lie
    /// within a single chunk (true for any node or single extent read).
    pub async fn read_logical(&self, logical: u64, len: usize) -> Result<Vec<u8>, FsError> {
        // Resolve both physical copies under the lock, then release it before
        // I/O. A plain logical read can retry transport failure; callers with a
        // checksum (notably read_node and the data-csum path) retry corruption.
        let mut buf = vec![0u8; len];
        let copies = self.logical_read_copies(logical)?;
        let mut last = FsError::NotFound;
        for copy in 0..copies {
            match self.read_logical_copy(logical, &mut buf, copy).await {
                Ok(()) => return Ok(buf),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Read a logical range from the first physical copy whose bytes match the
    /// supplied on-disk data checksum. Unlike [`Self::read_logical`], checksum
    /// failure is part of copy selection, so a readable-but-corrupt primary DUP
    /// stripe falls back to its mirror.
    pub(crate) async fn read_logical_checked(
        &self,
        logical: u64,
        len: usize,
        stored: &[u8],
    ) -> Result<Vec<u8>, FsError> {
        let mut buf = vec![0u8; len];
        let copies = self.logical_read_copies(logical)?;
        for copy in 0..copies {
            if self
                .read_logical_copy(logical, &mut buf, copy)
                .await
                .is_err()
            {
                continue;
            }
            let digest = crate::checksum::digest(self.csum_type, &buf)?;
            if digest.get(..stored.len()) == Some(stored) {
                return Ok(buf);
            }
        }
        Err(FsError::InvalidData)
    }

    /// Read one b-tree node (a `nodesize` block) at logical address `logical`,
    /// validating its self-recorded `bytenr` and, when
    /// [`verify_checksums`](Self::verify_checksums) is set, its checksum.
    pub async fn read_node(&self, logical: u64) -> Result<Vec<u8>, FsError> {
        self.read_node_shared(logical)
            .await
            .map(|arc| (*arc).clone())
    }

    /// [`Self::read_node`] without copying the node out of the cache.
    ///
    /// A cache hit here is an `Arc` bump rather than a `nodesize` memcpy. That
    /// matters because the commit path's hottest reader — the extent tree's
    /// path COW, re-run once per fixed-point round — descends the same
    /// internal nodes for every edit, and each descent used to copy 16 KiB per
    /// level. Callers that need to mutate a node still take `read_node` and
    /// get their own copy.
    pub async fn read_node_shared(&self, logical: u64) -> Result<Arc<Vec<u8>>, FsError> {
        // A block of the running batch is rewritten in place at the same
        // address by later operations, and another CPU can read it from the
        // device in the middle of that write (a reader takes no operation
        // lock). The torn image fails its checksum; by the time the read is
        // retried the writer has finished and published the new bytes in the
        // cache. A block that is genuinely bad fails every attempt.
        let mut last = FsError::InvalidData;
        for _ in 0..3 {
            match self.read_node_attempt(logical).await {
                Ok(node) => return Ok(node),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn read_node_attempt(&self, logical: u64) -> Result<Arc<Vec<u8>>, FsError> {
        // Serve from the node cache when nothing has written this address
        // since it was filled. A hit skips both the device read and the
        // full-node checksum verification; the clone is a memcpy against an
        // I/O plus a checksum over the whole node.
        let epoch = {
            let cache = self.nodes.lock();
            if let Some(hit) = cache.entries.get(&logical) {
                return Ok(hit.clone());
            }
            cache.epoch
        };
        let _ = epoch;

        let mut buf = vec![0u8; self.nodesize()];
        let copies = self.logical_read_copies(logical)?;
        for copy in 0..copies {
            if self
                .read_logical_copy(logical, &mut buf, copy)
                .await
                .is_err()
            {
                continue;
            }
            if format::le64(&buf, 48)? != logical {
                continue;
            }
            if self.verify_checksums
                && !crate::checksum::verify(
                    self.csum_type,
                    &buf[format::CSUM_SIZE..],
                    &buf[..format::CSUM_SIZE],
                )?
            {
                continue;
            }
            let shared = Arc::new(core::mem::take(&mut buf));
            // Only cache a node that passed BOTH checks above — a copy that
            // failed one is retried from another mirror, and caching it would
            // make a transient bad mirror permanent for this mount.
            let mut cache = self.nodes.lock();
            if cache.epoch == epoch {
                // A write landed while this read was in flight if the epoch
                // moved; the bytes in hand may already be stale, so drop them
                // rather than publish them.
                if cache.entries.len() >= NODE_CACHE_MAX {
                    // Crude but bounded, and the working set a commit revisits
                    // sits far below the cap — an LRU's bookkeeping would cost
                    // more here than the misses it saves.
                    cache.entries.clear();
                }
                cache.entries.insert(logical, shared.clone());
            }
            return Ok(shared);
        }
        Err(FsError::InvalidData)
    }

    // ── Mount ──────────────────────────────────────────────────────

    /// Mount with checksum verification enabled.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        Self::mount_opts(device, domain, true).await
    }

    /// Mount a volume from an explicit set of member devices. The first device
    /// is the requested source; additional devices with another FSID are
    /// ignored, matching registry-wide discovery.
    pub async fn mount_devices(
        devices: Vec<Arc<B>>,
        domain: DomainId,
    ) -> Result<Arc<Self>, FsError> {
        Self::mount_devices_opts(devices, domain, true).await
    }

    /// Mount and, if a subvolume is selected, root the volume at that subvolume
    /// instead of the default `FS_TREE`.
    pub async fn mount_subvol(
        device: Arc<B>,
        domain: DomainId,
        verify_checksums: bool,
        subvol: Option<Subvol>,
    ) -> Result<Arc<Self>, FsError> {
        let volume = Self::mount_opts(device, domain, verify_checksums).await?;
        if let Some(sel) = subvol {
            volume.switch_to_subvol(&sel).await?;
        }
        volume.recover_orphans().await?;
        Ok(volume)
    }

    /// Multi-device equivalent of [`Self::mount_subvol`].
    pub async fn mount_subvol_devices(
        devices: Vec<Arc<B>>,
        domain: DomainId,
        verify_checksums: bool,
        subvol: Option<Subvol>,
    ) -> Result<Arc<Self>, FsError> {
        let volume = Self::mount_devices_opts(devices, domain, verify_checksums).await?;
        if let Some(sel) = subvol {
            volume.switch_to_subvol(&sel).await?;
        }
        volume.recover_orphans().await?;
        Ok(volume)
    }

    /// Re-root the volume at the named/identified subvolume: resolve its tree in
    /// the root tree and cache its root directory inode. Subsequent `root()`
    /// calls start there.
    pub async fn switch_to_subvol(&self, sel: &Subvol) -> Result<(), FsError> {
        // A batch belongs to one subvolume: its accumulated COW descends from
        // that subvolume's tree, and the commit stamps the result into the
        // ROOT_ITEM named by `fs_tree_id`. Re-rooting with one open would
        // commit the previous subvolume's tree into the new subvolume's root
        // item. Log replay walks several roots in a row and is the path that
        // reaches this. The commit waits for any running operation of
        // another mount (see `op_lock`).
        {
            let _op = self.op_lock().lock().await;
            crate::write::flush_batch(self).await?;
        }
        // The resolution reads the root tree (and the trees on the path)
        // without the operation lock, as any reader does. Every commit
        // re-packs the root tree, so a commit landing meanwhile (another
        // mount's writes, the commit timer) can free and reuse the blocks of
        // the root tree sampled here: the reads then fail their parent
        // checks (`btree::verify_child`). Retry from the new root, as the
        // VFS read paths do; a failure against an unchanged root is real.
        let mut attempt = 0;
        let (subvol_id, subvol_root, subvol_level, subvol_flags, root_inode) = loop {
            let (root_tree, _) = self.root_tree_root();
            let resolved = async {
                let (id, root, level, flags) = match sel {
                    Subvol::Id(n) => {
                        let (bytenr, level, flags) =
                            crate::roots::find_root_with_flags(self, root_tree, *n).await?;
                        (*n, bytenr, level, flags)
                    }
                    Subvol::Name(path) => self.resolve_subvol_path(root_tree, path).await?,
                };
                let inode = self
                    .load_inode_in(root, format::FIRST_FREE_OBJECTID)
                    .await?;
                Ok::<_, FsError>((id, root, level, flags, inode))
            }
            .await;
            match resolved {
                Err(FsError::InvalidData)
                    if attempt < 4 && self.root_tree_root().0 != root_tree =>
                {
                    attempt += 1;
                }
                other => break other?,
            }
        };
        self.select_subvol(subvol_id, subvol_root, subvol_level, subvol_flags);
        self.view.lock().root_inode = Some(root_inode);
        Ok(())
    }

    /// Resolve a `subvol=PATH` from the top-level FS_TREE. Ordinary directory
    /// components stay in the current tree; a ROOT_ITEM component enters that
    /// subvolume at inode 256. The final component itself must be a subvolume.
    async fn resolve_subvol_path(
        &self,
        root_tree: u64,
        path: &str,
    ) -> Result<(u64, u64, u8, u64), FsError> {
        let mut components = path.split('/').peekable();
        let mut dir_ino = format::FIRST_FREE_OBJECTID;
        let (mut tree_root, _) = crate::roots::find_fs_tree(self, root_tree).await?;

        while let Some(name) = components.next() {
            if name.is_empty() || name == "." || name == ".." {
                return Err(FsError::Unsupported);
            }
            let key = BtrfsKey::new(
                dir_ino,
                format::DIR_ITEM_KEY,
                u64::from(crate::checksum::name_hash(name.as_bytes())),
            );
            let body = crate::btree::find_item(self, tree_root, &key)
                .await?
                .ok_or(FsError::NotFound)?;
            let entry = crate::dir::decode_dir_items(&body)?
                .into_iter()
                .find(|entry| entry.name == name)
                .ok_or(FsError::NotFound)?;

            match entry.location.item_type {
                format::ROOT_ITEM_KEY => {
                    let subvol_id = entry.location.objectid;
                    let (bytenr, level, flags) =
                        crate::roots::find_root_with_flags(self, root_tree, subvol_id).await?;
                    if components.peek().is_none() {
                        return Ok((subvol_id, bytenr, level, flags));
                    }
                    tree_root = bytenr;
                    dir_ino = format::FIRST_FREE_OBJECTID;
                }
                format::INODE_ITEM_KEY if components.peek().is_some() => {
                    let inode = self
                        .load_inode_in(tree_root, entry.location.objectid)
                        .await?;
                    if !inode.is_dir() {
                        return Err(FsError::NotFound);
                    }
                    dir_ino = entry.location.objectid;
                }
                _ => return Err(FsError::NotFound),
            }
        }
        Err(FsError::NotFound)
    }

    /// Mount, optionally disabling checksum verification (test bring-up only).
    pub async fn mount_opts(
        device: Arc<B>,
        domain: DomainId,
        verify_checksums: bool,
    ) -> Result<Arc<Self>, FsError> {
        Self::mount_devices_opts(alloc::vec![device], domain, verify_checksums).await
    }

    /// Mount from an explicit member set, optionally disabling checksum
    /// verification (test bring-up only).
    pub async fn mount_devices_opts(
        input: Vec<Arc<B>>,
        domain: DomainId,
        verify_checksums: bool,
    ) -> Result<Arc<Self>, FsError> {
        Self::mount_devices_with(input, domain, verify_checksums, false).await
    }

    /// [`Self::mount_devices_opts`] that never writes to any member (see
    /// [`BtrfsVolume::is_read_only`]). A volume with a pending fsync log tree
    /// is refused with `Unsupported` rather than mounted without its log.
    pub async fn mount_devices_read_only(
        input: Vec<Arc<B>>,
        domain: DomainId,
        verify_checksums: bool,
    ) -> Result<Arc<Self>, FsError> {
        Self::mount_devices_with(input, domain, verify_checksums, true).await
    }

    async fn mount_devices_with(
        input: Vec<Arc<B>>,
        domain: DomainId,
        verify_checksums: bool,
        read_only_requested: bool,
    ) -> Result<Arc<Self>, FsError> {
        let source_device = input.first().cloned().ok_or(FsError::NotFound)?;
        let mut scanned = Vec::new();
        for (index, device) in input.into_iter().enumerate() {
            let logical = device.logical_block_size() as usize;
            if !(512..=4096).contains(&logical) || !logical.is_power_of_two() {
                if index == 0 {
                    return Err(FsError::Unsupported);
                }
                continue;
            }
            let capacity = device
                .capacity_blocks()
                .checked_mul(logical as u64)
                .ok_or(FsError::InvalidData)?;
            if capacity < format::SUPERBLOCK_OFFSET + format::SUPERBLOCK_SIZE as u64 {
                if index == 0 {
                    return Err(FsError::InvalidData);
                }
                continue;
            }
            let io = Mutex::new(new_volume_io(logical, domain)?);
            let mut best: Option<(u64, Superblock, [u8; format::SUPERBLOCK_DEV_ITEM_SIZE], u64)> =
                None;
            let mut saw_unsupported = false;
            for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
                if offset + format::SUPERBLOCK_SIZE as u64 > capacity {
                    continue;
                }
                let mut candidate = vec![0u8; format::SUPERBLOCK_SIZE];
                if read_exact_from(&*device, &io, capacity, offset, &mut candidate)
                    .await
                    .is_err()
                {
                    continue;
                }
                if format::le64(&candidate, format::SUPERBLOCK_BYTENR_OFFSET) != Ok(offset) {
                    continue;
                }
                let candidate_csum = match Superblock::checksum_type(&candidate) {
                    Ok(kind) if crate::checksum::is_supported(kind) => kind,
                    Ok(_) => {
                        saw_unsupported = true;
                        continue;
                    }
                    Err(_) => continue,
                };
                if verify_checksums
                    && !matches!(
                        crate::checksum::verify(
                            candidate_csum,
                            &candidate[format::CSUM_SIZE..format::SUPERBLOCK_SIZE],
                            &candidate[..format::CSUM_SIZE],
                        ),
                        Ok(true)
                    )
                {
                    continue;
                }
                let decoded = match Superblock::decode(&candidate) {
                    Ok(sb) if sb.device_total_bytes <= capacity => sb,
                    Ok(_) => continue,
                    Err(FsError::Unsupported) => {
                        saw_unsupported = true;
                        continue;
                    }
                    Err(_) => continue,
                };
                if best
                    .as_ref()
                    .is_none_or(|(_, current, _, _)| decoded.generation > current.generation)
                {
                    let start = format::SUPERBLOCK_DEV_ITEM_OFFSET;
                    let mut dev_item = [0u8; format::SUPERBLOCK_DEV_ITEM_SIZE];
                    dev_item.copy_from_slice(
                        &candidate[start..start + format::SUPERBLOCK_DEV_ITEM_SIZE],
                    );
                    let flags = format::le64(&candidate, crate::rw_gate::OFF_SUPER_FLAGS)?;
                    best = Some((offset, decoded, dev_item, flags));
                }
            }
            match best {
                Some((offset, superblock, dev_item, flags)) => {
                    let member = Arc::new(VolumeDevice {
                        device,
                        capacity,
                        dev_item: IrqSafeSpinLock::new(dev_item),
                        io,
                    });
                    scanned.push((member, offset, superblock, flags));
                }
                None if index == 0 && saw_unsupported => return Err(FsError::Unsupported),
                None if index == 0 => return Err(FsError::InvalidData),
                None => {}
            }
        }

        let source_fsid = scanned
            .first()
            .map(|(_, _, sb, _)| sb.fsid)
            .ok_or(FsError::InvalidData)?;
        let source_geometry = scanned
            .first()
            .map(|(_, _, sb, _)| (sb.sectorsize, sb.nodesize, sb.csum_type))
            .ok_or(FsError::InvalidData)?;
        let mut devices = BTreeMap::new();
        let mut selected: Option<(u64, u64, Superblock, u64)> = None;
        let mut min_generation = u64::MAX;
        let mut max_generation = 0u64;
        let mut common_superblock: Option<Superblock> = None;
        let mut inconsistent_members = false;
        for (member, offset, candidate, flags) in scanned {
            if candidate.fsid != source_fsid {
                continue;
            }
            if (
                candidate.sectorsize,
                candidate.nodesize,
                candidate.csum_type,
            ) != source_geometry
            {
                return Err(FsError::InvalidData);
            }
            if devices.insert(candidate.devid, member).is_some() {
                return Err(FsError::InvalidData);
            }
            min_generation = min_generation.min(candidate.generation);
            max_generation = max_generation.max(candidate.generation);
            if let Some(common) = &common_superblock {
                inconsistent_members |= !same_common_superblock(common, &candidate);
            } else {
                common_superblock = Some(candidate.clone());
            }
            if selected
                .as_ref()
                .is_none_or(|(_, _, current, _)| candidate.generation > current.generation)
            {
                selected = Some((candidate.devid, offset, candidate, flags));
            }
        }
        let (source_devid, source_offset, superblock, super_flags) =
            selected.ok_or(FsError::InvalidData)?;
        if devices.len() > superblock.num_devices as usize {
            return Err(FsError::InvalidData);
        }
        // A member left behind by an interrupted prior commit is readable from
        // the newest mirrors, but must not participate in a new transaction.
        let degraded = devices.len() < superblock.num_devices as usize
            || min_generation != max_generation
            || inconsistent_members;
        let csum_type = superblock.csum_type;
        let read_only =
            read_only_requested || devices.values().any(|member| member.device.is_read_only());
        // `btrfs_check_features`: unknown incompat bits were already refused
        // by `Superblock::decode`. A compat_ro bit the writer does not maintain
        // permits a read-only mount and refuses a read-write one.
        if !read_only && superblock.compat_ro_unwritable() != 0 {
            // Named on the console (and kept for the root-rw failure banner):
            // the operator must see *which* feature stopped the write mount.
            crate::rw_gate::report_refused_mount(
                &superblock.fsid,
                crate::rw_gate::active_profile(),
                &crate::rw_gate::Refusal::CompatRo(superblock.compat_ro_unwritable()),
            );
            return Err(FsError::Unsupported);
        }
        // Linux's artificial dependency: block-group-tree requires no-holes
        // and a valid free-space tree (`btrfs_check_features`,
        // `btrfs_validate_super`).
        if superblock.has_block_group_tree()
            && (superblock.incompat_flags & format::INCOMPAT_NO_HOLES == 0
                || superblock.compat_ro_flags & format::COMPAT_RO_FREE_SPACE_TREE_VALID == 0)
        {
            return Err(FsError::InvalidData);
        }

        // Seed the chunk map so the chunk tree is reachable by logical address.
        let seed = ChunkMap::seed_from_sys_array(&superblock.sys_chunk_array)?;
        seed.map_logical(superblock.chunk_root)?;

        let core = Arc::new(VolCore {
            mmap_anchors: IrqSafeSpinLock::new(BTreeMap::new()),
            orphans: IrqSafeSpinLock::new(BTreeSet::new()),
            cache_generations: IrqSafeSpinLock::new(CacheGenerations::new()),
            device: source_device,
            magic: superblock.magic,
            nodesize: superblock.nodesize,
            sectorsize: superblock.sectorsize,
            domain,
            csum_type,
            verify_checksums,
            degraded,
            read_only: core::sync::atomic::AtomicBool::new(read_only),
            super_flags,
            rw_refusal: IrqSafeSpinLock::new(None),
            sharing_checked: core::sync::atomic::AtomicBool::new(false),
            txn_lock: Mutex::new(()),
            op_lock: Mutex::new(()),
            timer_started: core::sync::atomic::AtomicBool::new(false),
            frozen: core::sync::atomic::AtomicBool::new(false),
            devices: IrqSafeSpinLock::new(devices),
            staged_super: IrqSafeSpinLock::new(None),
            staged_count: core::sync::atomic::AtomicUsize::new(0),
            commit_holds: core::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "kernel-test")]
            crash_before_super: core::sync::atomic::AtomicBool::new(false),
            pinned: IrqSafeSpinLock::new(alloc::vec::Vec::new()),
            reader_roots: IrqSafeSpinLock::new(BTreeMap::new()),
            nodes: IrqSafeSpinLock::new(NodeCache::default()),
            aborted: core::sync::atomic::AtomicBool::new(false),
            quota_override: core::sync::atomic::AtomicBool::new(false),
            fs_batch: Mutex::new(None),
            last_view_dropped: commit_on_last_drop::<B>,
            drop_commit_tried: core::sync::atomic::AtomicBool::new(false),
            state: IrqSafeSpinLock::new(VolState {
                superblock,
                superblock_source: (source_devid, source_offset),
                chunk_map: seed,
                subvols: BTreeMap::new(),
                alloc_floor: 0,
            }),
        });
        let volume = Self::new_view(core, read_only_requested);

        // Complete the chunk map and locate the FS tree now that the volume can
        // read nodes.
        volume.finish_mount().await?;
        if !volume.core_read_only() {
            volume.start_commit_timer();
        }
        volume.register_sysfs();
        Ok(volume)
    }

    /// A fresh mount over `core`, not yet rooted at any subvolume.
    fn new_view(core: Arc<VolCore<B>>, read_only: bool) -> Arc<Self> {
        Arc::new_cyclic(|self_weak| BtrfsVolume {
            core,
            self_weak: self_weak.clone(),
            view: IrqSafeSpinLock::new(ViewState {
                fs_tree_id: 0,
                root_inode: None,
            }),
            view_read_only: core::sync::atomic::AtomicBool::new(read_only),
            mount_options: IrqSafeSpinLock::new(crate::mount_opts::MountOptions::default()),
        })
    }

    /// An internal view of `core` rooted at tree `id`, for work the core does
    /// on behalf of whichever mount opened it: committing a batch staged
    /// through another mount, or the commit timer. `id` must be a tracked
    /// subvolume (every batch's tree is).
    pub(crate) fn view_for_tree(core: &Arc<VolCore<B>>, id: u64) -> Arc<Self> {
        let volume = Self::new_view(core.clone(), false);
        let mut view = volume.view.lock();
        if let Some(live) = core.state.lock().subvols.get_mut(&id) {
            live.mounts += 1;
        }
        view.fs_tree_id = id;
        drop(view);
        volume
    }

    /// The filesystem-wide state this mount is a view of.
    pub fn core(&self) -> &Arc<VolCore<B>> {
        &self.core
    }

    /// The core itself is read-only (no mount of it may write).
    pub(crate) fn core_read_only(&self) -> bool {
        self.read_only.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Held across one mutating operation (see the field).
    pub(crate) fn op_lock(&self) -> &Mutex<()> {
        &self.op_lock
    }

    /// Serialises closing one transaction against opening the next.
    pub(crate) fn txn_lock(&self) -> &Mutex<()> {
        &self.txn_lock
    }

    /// Start the core's commit timer once.
    fn start_commit_timer(self: &Arc<Self>) {
        if !self
            .timer_started
            .swap(true, core::sync::atomic::Ordering::AcqRel)
        {
            crate::write::spawn_commit_timer(&self.core);
        }
    }

    /// Another mount of an already-mounted filesystem (Linux
    /// `btrfs_get_tree_subvol` finding the existing `fs_info`): a new view over
    /// the same core, rooted at `subvol` or the default subvolume. Shares the
    /// running transaction, allocator, superblock commit and commit timer with
    /// every other mount of `core`.
    ///
    /// A read-write request against a core that was mounted read-only makes
    /// the core writable first ([`Self::make_writable`]).
    pub async fn mount_view(
        core: &Arc<VolCore<B>>,
        subvol: Option<Subvol>,
        read_only: bool,
    ) -> Result<Arc<Self>, FsError> {
        let volume = Self::new_view(core.clone(), read_only);
        if !read_only {
            volume.ensure_sharing_checked().await?;
            volume.make_writable()?;
        }
        volume.select_default_root().await?;
        if let Some(selector) = &subvol {
            volume.switch_to_subvol(selector).await?;
        }
        volume.recover_orphans().await?;
        Ok(volume)
    }

    /// Flip a read-only core to read-write, as `btrfs_reconfigure` does when
    /// any mount of a read-only superblock asks for rw. Refused when a member
    /// device itself refuses writes, the filesystem is degraded, or the
    /// superblock carries a compat_ro feature the writer does not maintain.
    /// A pending tree-log cannot exist here: a read-only mount refuses one.
    pub(crate) fn make_writable(self: &Arc<Self>) -> Result<(), FsError> {
        if !self.core_read_only() {
            return Ok(());
        }
        if let Some(why) = self.rw_refusal.lock().clone() {
            let sb = self.superblock();
            crate::rw_gate::report(&sb.fsid, crate::rw_gate::active_profile(), &why);
            return Err(FsError::ReadOnly);
        }
        if self.degraded
            || self.superblock().compat_ro_unwritable() != 0
            || self.superblock().log_root != 0
            || self
                .devices
                .lock()
                .values()
                .any(|member| member.device.is_read_only())
        {
            return Err(FsError::ReadOnly);
        }
        self.read_only
            .store(false, core::sync::atomic::Ordering::Release);
        self.start_commit_timer();
        Ok(())
    }

    /// Run [`crate::rw_gate`] once per core and remember the verdict. A
    /// writable core that is refused turns read-only (logged); a read-only
    /// one keeps the verdict for [`Self::make_writable`].
    async fn apply_rw_gate(&self) {
        let profile = crate::rw_gate::active_profile();
        let sb = self.superblock();
        let verdict = match crate::rw_gate::check_superblock(&sb, self.super_flags, profile) {
            Ok(()) if self.core_read_only() => crate::rw_gate::check_trees_basic(self).await,
            Ok(()) => {
                let verdict = crate::rw_gate::check_trees(self).await;
                self.sharing_checked
                    .store(true, core::sync::atomic::Ordering::Release);
                verdict
            }
            Err(why) => Err(why),
        };
        let Err(why) = verdict else {
            return;
        };
        if !self.core_read_only() {
            self.read_only
                .store(true, core::sync::atomic::Ordering::Release);
            crate::rw_gate::report(&sb.fsid, profile, &why);
        }
        *self.rw_refusal.lock() = Some(why);
    }

    /// Publish `/sys/fs/btrfs/<uuid>/quota_override`, the control surface
    /// Linux gives `BTRFS_FS_QUOTA_OVERRIDE` (`fs/btrfs/sysfs.c`).
    ///
    /// The store handler requires CAP_SYS_RESOURCE, as Linux's does:
    ///
    /// ```text
    /// if (!capable(CAP_SYS_RESOURCE))
    ///         return -EPERM;
    /// ...
    /// if (knob > 1)
    ///         return -EINVAL;
    /// ```
    ///
    /// Note this is a SECOND capability check, not the same one as the
    /// bypass: turning the knob on is an administrative act, and using it is a
    /// per-write one. A privileged administrator can enable it and
    /// unprivileged writers still get no bypass.
    ///
    /// The closures hold a `Weak`. A strong reference here would make the
    /// sysfs tree own every filesystem ever mounted, and unmount would never
    /// release one; a dead `Weak` simply makes the attribute inert.
    fn register_sysfs(self: &Arc<Self>) {
        use narf_filesystem::sysfs::{get_or_create_child, kobject_add_writable_attr, sysfs_root};
        let fsid = self.state.lock().superblock.fsid;
        let dir = {
            let root = sysfs_root();
            let fs = get_or_create_child(&root, "fs");
            let btrfs = get_or_create_child(&fs, "btrfs");
            get_or_create_child(&btrfs, &format_fsid(&fsid))
        };
        let show_ref = Arc::downgrade(self);
        let store_ref = Arc::downgrade(self);
        kobject_add_writable_attr(
            &dir,
            "quota_override",
            move || match show_ref.upgrade() {
                Some(vol) => alloc::format!("{}\n", u8::from(vol.quota_override())),
                None => alloc::string::String::from("0\n"),
            },
            move |data| {
                // EPERM before EINVAL, as Linux checks in that order: whether
                // you may set it does not depend on what you are setting.
                if !narf_filesystem::caller_capable(CAP_SYS_RESOURCE) {
                    return Err(FsError::OperationNotPermitted);
                }
                let text = core::str::from_utf8(data)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                // `kstrtoul` then `if (knob > 1) return -EINVAL;`.
                let knob: u64 = text.parse().map_err(|_| FsError::InvalidData)?;
                if knob > 1 {
                    return Err(FsError::InvalidData);
                }
                if let Some(vol) = store_ref.upgrade() {
                    vol.set_quota_override(knob != 0);
                }
                Ok(())
            },
        );
    }

    /// Walk the chunk tree to complete the logical→physical map, then read the
    /// root tree to find the default FS tree. Requires the b-tree engine.
    async fn finish_mount(self: &Arc<Self>) -> Result<(), FsError> {
        let (chunk_root, root_tree, root_level) = {
            let g = self.state.lock();
            (
                g.superblock.chunk_root,
                g.superblock.root,
                g.superblock.root_level,
            )
        };
        let _ = root_level;

        // 1. Collect every CHUNK_ITEM from the chunk tree and add it to the map.
        //    Chunk items are keyed (FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM, logical).
        let chunks = crate::btree::collect_for(
            self,
            chunk_root,
            format::FIRST_FREE_OBJECTID, // 256 == BTRFS_FIRST_CHUNK_TREE_OBJECTID
            format::CHUNK_ITEM_KEY,
        )
        .await?;
        {
            let mut g = self.state.lock();
            for (key, body) in &chunks {
                g.chunk_map.insert_chunk_item(key.offset, body)?;
            }
        }

        // 1b. Block-group tree (`load_global_roots` for objectid 11): load its
        //     root and cross-check every block group against its chunk, as
        //     `btrfs_read_block_groups` does. Without the feature the items sit
        //     in the extent tree and are read lazily by the writer.
        if let crate::block_group::BgHome::BlockGroupTree { root, .. } =
            crate::block_group::bg_home(self, root_tree).await?
        {
            let chunk_items: Vec<(u64, Vec<u8>)> = chunks
                .iter()
                .map(|(key, body)| (key.offset, body.clone()))
                .collect();
            crate::block_group::validate_block_groups(self, root, true, &chunk_items).await?;
        }

        // 1c. Before anything can write (log replay below, the commit timer,
        //     any VFS operation): the read-write safety gate. A refusal makes
        //     this core read-only for its lifetime, and later read-write
        //     mounts of it are refused.
        self.apply_rw_gate().await;

        // 2. Find the FS_TREE root item (5, ROOT_ITEM, *) in the root tree and
        //    extract its root node address + level.
        let (fs_root, fs_level, fs_flags) =
            crate::roots::find_root_with_flags(self, root_tree, format::FS_TREE_OBJECTID).await?;
        self.select_subvol(format::FS_TREE_OBJECTID, fs_root, fs_level, fs_flags);

        // 2b. Replay a pending fsync tree-log (crash recovery) before anything
        //     reads the fs tree. The replay commits into the fs tree and publishes
        //     the recovered roots via `commit_roots`, so later steps see them.
        if self.superblock().log_root != 0 && !self.supports_writes() {
            // Replay mutates the fs tree and superblock, so it is permitted
            // only when the core is writable. A read-only core mounts the
            // committed trees and leaves the log alone (Linux `nologreplay`):
            // the state as of the last full commit, consistent but without
            // the fsyncs made since, and the log still there for the next
            // writable mount (Linux's or NARF's) to replay. Refusing instead
            // would leave a root that went down uncleanly unbootable
            // read-only, the mode meant to be safe on it. `make_writable`
            // and the rw gate keep refusing writes while the log exists.
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "btrfs: WARNING: unreplayed fsync log (log_root {:#x}); read-only mount \
                 without replay: files fsynced after the last commit show their \
                 committed state until a read-write mount replays the log",
                self.superblock().log_root
            );
            return self.select_default_root().await;
        }
        crate::write::replay_log(self).await?;
        self.select_default_root().await?;
        self.recover_orphans().await
    }

    /// Root this mount at the top-level tree, cache its root inode, then honour
    /// the on-disk default subvolume. Steps 3–4 of mount, shared with
    /// [`Self::mount_view`].
    async fn select_default_root(self: &Arc<Self>) -> Result<(), FsError> {
        // A lock-free read of the root tree, which a concurrent commit may
        // re-pack and reuse (see `switch_to_subvol`): retry from the live
        // root tree when that is what failed.
        let mut attempt = 0;
        loop {
            let (root_tree, _) = self.root_tree_root();
            match self.select_default_root_from(root_tree).await {
                Err(FsError::InvalidData)
                    if attempt < 4 && self.root_tree_root().0 != root_tree =>
                {
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    async fn select_default_root_from(self: &Arc<Self>, root_tree: u64) -> Result<(), FsError> {
        let (fs_root, fs_level, fs_flags) =
            crate::roots::find_root_with_flags(self, root_tree, format::FS_TREE_OBJECTID).await?;
        self.select_subvol(format::FS_TREE_OBJECTID, fs_root, fs_level, fs_flags);

        // 3. Cache the root-directory inode so the synchronous `root()` path has
        //    it without I/O.
        let root_inode = self.load_inode(format::FIRST_FREE_OBJECTID).await?;
        self.view.lock().root_inode = Some(root_inode);

        // 4. Honor the on-disk default subvolume, if one is set to a subvolume
        //    other than FS_TREE (an explicit `subvolid=`/`subvol=` overrides this
        //    afterwards in `mount_subvol`).
        if let Some(id) = self.default_subvol_id(root_tree).await? {
            if id != format::FS_TREE_OBJECTID {
                self.switch_to_subvol(&Subvol::Id(id)).await?;
            }
        }
        Ok(())
    }

    /// The objectid of the on-disk default subvolume, from the root tree's
    /// `ROOT_TREE_DIR` "default" `DIR_ITEM`. `None` if unset.
    async fn default_subvol_id(&self, root_tree: u64) -> Result<Option<u64>, FsError> {
        let key = BtrfsKey::new(
            format::ROOT_TREE_DIR_OBJECTID,
            format::DIR_ITEM_KEY,
            u64::from(crate::checksum::name_hash(b"default")),
        );
        let body = match crate::btree::find_item(self, root_tree, &key).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let entry = crate::dir::decode_dir_items(&body)?
            .into_iter()
            .find(|e| e.name == "default");
        match entry {
            Some(e) if e.location.item_type == format::ROOT_ITEM_KEY => {
                Ok(Some(e.location.objectid))
            }
            _ => Ok(None),
        }
    }

    /// Read and decode the inode item `(ino, INODE_ITEM, 0)` from the default
    /// FS tree.
    pub async fn load_inode(&self, ino: u64) -> Result<InodeItem, FsError> {
        let (fs_root, _) = self.fs_tree_root();
        self.load_inode_in(fs_root, ino).await
    }

    /// Read and decode the inode item `(ino, INODE_ITEM, 0)` from the tree
    /// rooted at logical `tree_root` (a subvolume's fs tree, or the default).
    pub async fn load_inode_in(&self, tree_root: u64, ino: u64) -> Result<InodeItem, FsError> {
        if tree_root == 0 {
            return Err(FsError::NotFound);
        }
        let key = BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0);
        let body = crate::btree::find_item(self, tree_root, &key)
            .await?
            .ok_or(FsError::NotFound)?;
        InodeItem::decode(&body)
    }

    /// Cached root-directory inode (available after mount completes).
    pub fn root_inode(&self) -> Option<InodeItem> {
        self.view.lock().root_inode
    }

    /// The session allocation floor — writes seed their allocator from at least
    /// this to avoid colliding with earlier same-session writes.
    pub fn alloc_floor(&self) -> u64 {
        self.state.lock().alloc_floor
    }

    /// Raise the session allocation floor after a write.
    pub fn set_alloc_floor(&self, v: u64) {
        let mut g = self.state.lock();
        g.alloc_floor = g.alloc_floor.max(v);
    }

    // ── Writes (Phase 7 COW path) ──────────────────────────────────

    /// Write `src` at physical device byte offset `offset` (block-granular,
    /// read-modify-write for partial leading/trailing blocks).
    pub(crate) async fn write_physical_on(
        &self,
        devid: u64,
        offset: u64,
        src: &[u8],
    ) -> Result<(), FsError> {
        if self.core_read_only() {
            return Err(FsError::ReadOnly);
        }
        let member = self.member(devid)?;
        write_exact_to(
            &*member.device,
            &member.io,
            member.capacity,
            offset,
            src,
            false,
        )
        .await
    }

    /// Write `src` at btrfs *logical* address `logical` (single-chunk range).
    pub async fn write_logical(&self, logical: u64, src: &[u8]) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        self.write_logical_unchecked(logical, src).await.map(|_| ())
    }

    /// Root-tree transaction write used only to change the mounted subvolume's
    /// own read-only flag. Clearing that flag must be able to commit while the
    /// current live subvolume is still read-only; ordinary mutations continue
    /// to go through [`Self::write_logical`] and its writeability check.
    async fn write_logical_unchecked(&self, logical: u64, src: &[u8]) -> Result<u64, FsError> {
        // Every node write funnels through here, so this is the one place the
        // node cache has to be invalidated.
        //
        // The epoch moves on BOTH sides of the write, and both are load
        // bearing. Before, so no reader can take a hit on bytes this write is
        // about to replace. After, because a reader that missed and started
        // its device read while the write was still in flight may hold
        // pre-write bytes; without the second bump its epoch check would pass
        // and it would publish them as current.
        let _ = self.invalidate_nodes(logical, src.len());
        let mut done = 0usize;
        while done < src.len() {
            let at = logical
                .checked_add(done as u64)
                .ok_or(FsError::InvalidData)?;
            let (locations, contiguous, raid56) = {
                let g = self.state.lock();
                let raid56 = match g.chunk_map.raid56_set(at) {
                    Ok(set) => Some(set),
                    Err(FsError::Unsupported) => None,
                    Err(error) => return Err(error),
                };
                (
                    g.chunk_map.map_logical_stripes(at)?,
                    g.chunk_map.max_contiguous(at)?,
                    raid56,
                )
            };
            let take = (src.len() - done).min(contiguous as usize);
            if let Some(set) = raid56 {
                self.write_raid56(at, &src[done..done + take], &set).await?;
            } else {
                for location in locations {
                    self.write_physical_on(
                        location.devid,
                        location.physical,
                        &src[done..done + take],
                    )
                    .await?;
                }
            }
            done += take;
        }
        Ok(self.invalidate_nodes(logical, src.len()))
    }

    /// Keep a multi-stage operation (truncate's tail zeroing then its size
    /// change, a write's EOF-tail zeroing then the write) in one transaction:
    /// until the returned guard drops, filling the batch does not commit it,
    /// so a crash can expose all of the operation or none of it. The caller
    /// commits a batch left full afterwards (`write::flush_if_full`).
    pub(crate) fn hold_commits(&self) -> CommitHold<'_> {
        self.commit_holds
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        CommitHold(&self.commit_holds)
    }

    /// Whether a [`Self::hold_commits`] guard is live.
    pub(crate) fn commits_held(&self) -> bool {
        self.commit_holds
            .load(core::sync::atomic::Ordering::Acquire)
            != 0
    }

    /// Hold a completed commit's superblock image in memory instead of writing
    /// it, and report whether the batch is now long enough to force out.
    pub(crate) fn stage_superblock(&self, raw: alloc::vec::Vec<u8>, root_admin: bool) -> bool {
        *self.staged_super.lock() = Some((raw, root_admin));
        let staged = self
            .staged_count
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel)
            + 1;
        staged >= MAX_STAGED_COMMITS
    }

    /// Make every write that has already returned durable on disk.
    ///
    /// This is `fsync`'s contract, stated as a requirement rather than as a
    /// description of how commits happen to work. Two things can be
    /// outstanding, and both are discharged here, in this order:
    ///
    ///  1. operations accumulated into a batch that has not committed — their
    ///     tree blocks are on disk but no superblock names them yet;
    ///  2. a committed transaction whose superblock is staged in memory.
    ///
    /// Both halves are needed and neither is sufficient. Writing the staged
    /// superblock without committing the batch publishes a tree that predates
    /// the writes this call was made for; committing the batch without writing
    /// the superblock leaves the result in memory.
    ///
    /// Putting both here rather than at the call sites is what keeps the
    /// contract from depending on someone remembering: every durability path
    /// — `fsync`, unmount, a full staged-superblock quota — is this one
    /// function.
    ///
    /// `smoke_btrfs_fsync_survives_a_later_crash` holds this to account: it
    /// fsyncs, crashes the following commit, and requires the fsynced data
    /// back. Deferring commits without doing the work here turns that red.
    /// [`Self::sync_to_disk`] from outside any operation (`fsync`, `syncfs`):
    /// waits for the running operation, so the commit it forces cannot land
    /// between another CPU's tree reads and its staging.
    pub async fn sync_to_disk_exclusive(&self) -> Result<(), FsError> {
        let _op = self.op_lock().lock().await;
        self.reap_orphans().await?;
        self.sync_to_disk().await
    }

    /// `syncfs`: [`Self::sync_to_disk_exclusive`] plus a trailing device
    /// flush, so the superblock mirrors (written without FUA) are durable as
    /// well. Safe from a pre-shutdown hook while the block devices still run:
    /// it waits for the running operation, takes no IRQ-masking lock across
    /// I/O, and on a read-only or aborted filesystem only flushes.
    pub async fn sync_fs(&self) -> Result<(), FsError> {
        if !self.core_read_only() && !self.aborted.load(core::sync::atomic::Ordering::Acquire) {
            self.sync_to_disk_exclusive().await?;
        }
        self.flush().await
    }

    pub fn sync_to_disk(&self) -> crate::write::BoxFut<'_, ()> {
        alloc::boxed::Box::pin(async move {
            crate::write::flush_batch(self).await?;
            self.write_staged_super().await
        })
    }

    /// Push the staged superblock, if any, through to the device — the second
    /// half of [`Self::sync_to_disk`], on its own.
    ///
    /// A commit calls this rather than `sync_to_disk` when it has filled the
    /// staged-superblock quota. It must not go the long way round: the batch
    /// this commit came from was taken before it started, so there is nothing
    /// of its own left to flush, and calling back into the batch machinery
    /// from inside a commit makes the two mutually recursive for no gain.
    pub(crate) async fn write_staged_super(&self) -> Result<(), FsError> {
        let staged = self.staged_super.lock().take();
        let Some((raw, root_admin)) = staged else {
            // Nothing outstanding; the barrier is all that is owed (fsync of
            // data already covered by a durable superblock).
            return self.flush().await;
        };
        // Every staged commit's nodes were written before this point. The
        // superblock writer issues the one pre-flush that makes them durable
        // before the FUA primary (`write_all_supers`).
        let written = if root_admin {
            self.write_superblock_root_admin(&raw).await
        } else {
            self.write_superblock(&raw).await
        };
        if let Err(error) = written {
            // Keep the image: it is still what the in-memory trees describe.
            // The filesystem is now in its error state and takes no writes.
            *self.staged_super.lock() = Some((raw, root_admin));
            return Err(error);
        }
        self.staged_count
            .store(0, core::sync::atomic::Ordering::Release);
        // Only now, exactly as `btrfs_finish_extent_commit` runs only after
        // `write_all_supers`.
        self.unpin_all();
        Ok(())
    }

    /// Test-only: make the next commit stop after writing its nodes, leaving
    /// the superblock pointing at the previous tree — the state a crash mid
    /// commit produces.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn arm_crash_before_super(&self) {
        self.crash_before_super
            .store(true, core::sync::atomic::Ordering::Release);
    }

    /// Consume the armed crash, if any.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn take_crash_before_super(&self) -> bool {
        self.crash_before_super
            .swap(false, core::sync::atomic::Ordering::AcqRel)
    }

    /// Withhold `[start, start + len)` from allocation until [`Self::unpin_all`].
    pub(crate) fn pin_extent(&self, start: u64, len: u64) {
        if len != 0 {
            self.pinned.lock().push((start, len));
        }
    }

    /// The currently pinned ranges, for the allocator to subtract.
    pub(crate) fn pinned_ranges(&self) -> alloc::vec::Vec<(u64, u64)> {
        self.pinned.lock().clone()
    }

    /// The roots lock-free readers are walking from, as `(addr, nodesize)`
    /// ranges the allocator must not hand out.
    pub(crate) fn reader_root_ranges(&self) -> alloc::vec::Vec<(u64, u64)> {
        let n = self.nodesize() as u64;
        self.reader_roots.lock().keys().map(|&a| (a, n)).collect()
    }

    /// Release every pinned extent. The caller must have made a superblock
    /// durable that no longer references any of them — that ordering is the
    /// entire point of pinning, so calling this earlier reintroduces exactly
    /// the corruption the set prevents.
    pub(crate) fn unpin_all(&self) {
        self.pinned.lock().clear();
    }

    /// Publish a node this volume has just written, so the read that follows
    /// it does not have to fetch back bytes we are already holding.
    ///
    /// A commit writes its new nodes and then immediately reads part of the
    /// tree back — `total_block_group_used` re-reads the freshly written
    /// extent tree so the superblock's `bytes_used` can never drift from the
    /// block groups. Every one of those reads is a guaranteed MISS, because
    /// the write that produced the node invalidated it moments earlier: the
    /// cache is defeated precisely where it would help most.
    ///
    /// This is safe in a way a speculative fill is not — the bytes are what
    /// was just written, not what was read from somewhere and might be stale.
    /// It must still be called AFTER the write completes, so the write's own
    /// trailing invalidation cannot remove the entry it just published.
    fn cache_written_node(&self, logical: u64, buf: &[u8], epoch: u64) {
        if buf.len() != self.nodesize() {
            return; // not a metadata node
        }
        let mut cache = self.nodes.lock();
        // `epoch` is what this write left behind. If it has moved, another
        // write has touched the cache since — publishing now could put our
        // bytes over newer ones, so decline. Same trade as a racing fill:
        // a missed publish, never a wrong answer.
        if cache.epoch != epoch {
            return;
        }
        if cache.entries.len() >= NODE_CACHE_MAX {
            cache.entries.clear();
        }
        cache.entries.insert(logical, Arc::new(buf.to_vec()));
    }

    /// Write one metadata node and keep it cached.
    pub async fn write_node(&self, logical: u64, buf: &[u8]) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        let epoch = self.write_logical_unchecked(logical, buf).await?;
        self.cache_written_node(logical, buf, epoch);
        Ok(())
    }

    /// [`Self::write_node`] for the root-admin path.
    pub(crate) async fn write_node_root_admin(
        &self,
        logical: u64,
        buf: &[u8],
    ) -> Result<(), FsError> {
        // Root-admin skips only the subvolume's own RDONLY flag; a read-only
        // or aborted filesystem takes no writes from anyone.
        if self.degraded
            || self.core_read_only()
            || self.aborted.load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(FsError::ReadOnly);
        }
        let epoch = self.write_logical_unchecked(logical, buf).await?;
        self.cache_written_node(logical, buf, epoch);
        Ok(())
    }

    /// Drop every cached node the byte range `[logical, logical + len)`
    /// touches, and advance the epoch.
    ///
    /// A cached entry at `a` covers `[a, a + nodesize)`, so the scan starts a
    /// node below `logical`: an entry beginning just under the range still
    /// overlaps it, and skipping those would leave exactly the partially
    /// overwritten nodes cached.
    ///
    /// Chunk relocation writes by physical address without coming through
    /// here, and deliberately needs no invalidation — it copies each logical
    /// block's bytes unchanged to new backing, so cached contents stay
    /// correct. Superblock writes likewise: they are never read as nodes.
    fn invalidate_nodes(&self, logical: u64, len: usize) -> u64 {
        // Decompressed data extents in the written range are stale too, for
        // every mount (view) of the shared core.
        crate::decompress_cache::invalidate(
            crate::decompress_cache::VolumeRef::key_of(Arc::as_ptr(self.core())),
            logical,
            len,
        );
        let node = self.nodesize() as u64;
        let end = logical.saturating_add(len as u64);
        let from = logical.saturating_sub(node.saturating_sub(1));
        let mut cache = self.nodes.lock();
        let stale: alloc::vec::Vec<u64> = cache
            .entries
            .range(from..end)
            .map(|(&addr, _)| addr)
            .collect();
        for addr in stale {
            cache.invalidate(addr);
        }
        cache.epoch = cache.epoch.wrapping_add(1);
        cache.epoch
    }

    /// Read-modify-write one data slice and its P/Q parity. The caller splits
    /// writes at stripe boundaries, and writable mounts require every declared
    /// member, so all peer data is available without degraded reconstruction.
    async fn write_raid56(
        &self,
        logical: u64,
        src: &[u8],
        set: &crate::chunk::Raid56Set,
    ) -> Result<(), FsError> {
        let delta = logical
            .checked_sub(set.logical_start)
            .ok_or(FsError::InvalidData)?;
        let target = (delta / set.stripe_len) as usize;
        let within = delta % set.stripe_len;
        if target >= set.data.len() || src.len() as u64 > set.stripe_len - within {
            return Err(FsError::InvalidData);
        }

        let mut data = Vec::with_capacity(set.data.len());
        for (index, location) in set.data.iter().enumerate() {
            if index == target {
                data.push(src.to_vec());
            } else {
                let mut bytes = vec![0u8; src.len()];
                self.read_physical_on(location.devid, location.physical + within, &mut bytes)
                    .await?;
                data.push(bytes);
            }
        }
        let slices: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let (p, q) = crate::raid56::syndromes(&slices, set.parity.len() == 2)?;

        let location = set.data.get(target).ok_or(FsError::InvalidData)?;
        self.write_physical_on(location.devid, location.physical + within, src)
            .await?;
        for (index, location) in set.parity.iter().enumerate() {
            let parity = if index == 0 {
                p.as_slice()
            } else {
                q.as_slice()
            };
            self.write_physical_on(location.devid, location.physical + within, parity)
                .await?;
        }
        Ok(())
    }

    /// Overwrite every superblock copy with `raw` (a full 4096-byte block whose
    /// `bytenr`/checksum are those of the primary at 64 KiB) and flush.
    ///
    /// btrfs keeps up to three copies (`btrfs_sb_offset`): the primary at 64 KiB,
    /// then mirrors at 64 MiB and 256 GiB, each written only when it fits within
    /// the filesystem. Every copy records its own physical offset in `bytenr@48`
    /// (so its checksum differs), and a real kernel picks the copy with the
    /// newest generation — so all copies must advance together on each commit or
    /// `btrfs check` reports a mismatch. The order is Linux `write_all_supers`
    /// (see [`Self::write_all_supers`]): pre-flush, FUA primary, mirrors.
    ///
    /// Gated on the filesystem, not this mount: the superblock is the core's,
    /// and a commit or `fsync` may reach it through any mount, including a
    /// read-only view of a writable filesystem.
    pub async fn write_superblock(&self, raw: &[u8]) -> Result<(), FsError> {
        if self.core_read_only()
            || self.degraded
            || self.aborted.load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(FsError::ReadOnly);
        }
        self.write_superblock_unchecked(raw).await
    }

    /// Superblock half of [`Self::write_node_root_admin`].
    pub(crate) async fn write_superblock_root_admin(&self, raw: &[u8]) -> Result<(), FsError> {
        if self.degraded
            || self.core_read_only()
            || self.aborted.load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(FsError::ReadOnly);
        }
        self.write_superblock_unchecked(raw).await
    }

    async fn write_superblock_unchecked(&self, raw: &[u8]) -> Result<(), FsError> {
        let result = self.write_all_supers(raw).await;
        if result.is_err() {
            // `btrfs_handle_fs_error` after a failed `write_all_supers`: the
            // trees in memory are ahead of anything durable, so the only
            // honest state is the filesystem error state — read-only.
            self.abort_transaction();
        }
        result
    }

    /// Linux `write_all_supers` (`fs/btrfs/disk-io.c`):
    ///
    /// 1. `barrier_all_devices` → `write_dev_flush` / `wait_dev_flush`: a
    ///    pre-flush on every member, waited for, so every tree and data block
    ///    of the transaction (all submitted and completed by now) is durable
    ///    before any superblock names it. A failed flush fails the commit
    ///    before a single superblock byte is written.
    /// 2. `write_dev_supers` / `wait_dev_supers`: on each member the primary
    ///    copy with `REQ_FUA`, then the mirrors without it (they become
    ///    durable with the next transaction's pre-flush). A failed mirror is
    ///    tolerated; a failed primary counts against the device, and the
    ///    commit fails once more devices fail than `num_devices - 1`.
    async fn write_all_supers(&self, raw: &[u8]) -> Result<(), FsError> {
        if raw.len() != format::SUPERBLOCK_SIZE {
            return Err(FsError::InvalidData);
        }
        // Common transaction fields are shared, while the embedded dev_item
        // remains unique to each device.
        let members: Vec<(u64, Arc<VolumeDevice<B>>)> = self
            .devices
            .lock()
            .iter()
            .map(|(&devid, member)| (devid, member.clone()))
            .collect();
        for (_, member) in &members {
            member.device.flush_result().await.map_err(FsError::Io)?;
        }
        let max_errors = members.len().saturating_sub(1);
        let mut errors = 0usize;
        let mut primary_ok = None;
        for (devid, member) in &members {
            let mut device_ok = true;
            // Linux `write_dev_supers`: a mirror is written only below the
            // device's btrfs `total_bytes` (`commit_total_bytes`), never merely
            // because the partition behind it is larger.
            let dev_total = format::le64(&*member.dev_item.lock(), 8).unwrap_or(0);
            let fits_below = dev_total.min(member.capacity);
            for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
                if offset + format::SUPERBLOCK_SIZE as u64 >= fits_below
                    && offset != format::SUPERBLOCK_OFFSET
                {
                    continue; // this mirror doesn't fit on this member
                }
                if offset + format::SUPERBLOCK_SIZE as u64 > member.capacity {
                    continue;
                }
                let mut copy = raw.to_vec();
                let b = format::SUPERBLOCK_BYTENR_OFFSET;
                copy[b..b + 8].copy_from_slice(&offset.to_le_bytes());
                let d = format::SUPERBLOCK_DEV_ITEM_OFFSET;
                copy[d..d + format::SUPERBLOCK_DEV_ITEM_SIZE]
                    .copy_from_slice(&*member.dev_item.lock());
                crate::checksum::stamp_block(self.csum_type, &mut copy)?;
                let primary = offset == format::SUPERBLOCK_OFFSET;
                if self.core_read_only() {
                    return Err(FsError::ReadOnly);
                }
                let written = write_exact_to(
                    &*member.device,
                    &member.io,
                    member.capacity,
                    offset,
                    &copy,
                    primary,
                )
                .await;
                if primary && written.is_err() {
                    device_ok = false;
                    break;
                }
            }
            if device_ok {
                primary_ok.get_or_insert(*devid);
            } else {
                errors += 1;
            }
        }
        if errors > max_errors {
            return Err(FsError::Io(BlockError::IOError));
        }
        let devid = primary_ok.ok_or(FsError::NotFound)?;
        self.state.lock().superblock_source = (devid, format::SUPERBLOCK_OFFSET);
        Ok(())
    }

    /// Flush every member's volatile write cache, waiting for completion
    /// (`blkdev_issue_flush`). The durability barrier of `fsync` and of every
    /// commit.
    pub async fn flush(&self) -> Result<(), FsError> {
        let members: Vec<Arc<VolumeDevice<B>>> = self.devices.lock().values().cloned().collect();
        for member in members {
            member.device.flush_result().await.map_err(FsError::Io)?;
        }
        Ok(())
    }

    /// Read the selected raw superblock and normalize it to primary-copy form.
    /// Transaction code can therefore heal a damaged primary without knowing
    /// which mirror supplied the mounted generation.
    pub async fn read_raw_superblock(&self) -> Result<Vec<u8>, FsError> {
        // A staged image is newer than anything on disk, and the next commit
        // must build on it — reading the stale on-disk copy would roll the
        // generation and root pointers backwards.
        if let Some((raw, _)) = self.staged_super.lock().as_ref() {
            return Ok(raw.clone());
        }
        let (devid, source) = self.state.lock().superblock_source;
        let mut raw = vec![0u8; format::SUPERBLOCK_SIZE];
        self.read_physical_on(devid, source, &mut raw).await?;
        if source != format::SUPERBLOCK_OFFSET {
            let at = format::SUPERBLOCK_BYTENR_OFFSET;
            raw[at..at + 8].copy_from_slice(&format::SUPERBLOCK_OFFSET.to_le_bytes());
            crate::checksum::stamp_block(self.csum_type, &mut raw)?;
        }
        Ok(raw)
    }

    /// Point raw-superblock reads at a currently assembled member. Device
    /// removal can otherwise leave the cached source devid referring to the
    /// member that was just detached even though every survivor has the same
    /// committed generation.
    fn select_live_superblock_source(&self) -> Result<(), FsError> {
        let devid = self
            .devices
            .lock()
            .keys()
            .next()
            .copied()
            .ok_or(FsError::NotFound)?;
        self.state.lock().superblock_source = (devid, format::SUPERBLOCK_OFFSET);
        Ok(())
    }

    /// Clear the cached superblock's log-root pointer after a tree-log has been
    /// replayed and the on-disk pointer zeroed.
    pub fn clear_log_root(&self) {
        let mut g = self.state.lock();
        g.superblock.log_root = 0;
        g.superblock.log_root_level = 0;
    }

    /// The transaction accumulating operations that have not committed yet.
    pub(crate) fn fs_batch(&self) -> &Mutex<Option<crate::write::FsBatch>> {
        self.core.fs_batch()
    }

    /// Publish an fs-tree root produced *inside* an open batch.
    ///
    /// The batch's nodes are already on disk, so a read taken between two of
    /// its operations must descend from the new root or it would miss the
    /// first operation's result. Only the superblock still names the pre-batch
    /// root, which is the ordinary COW invariant: a crash before the batch
    /// commits falls back to that tree, and every block it references is still
    /// there. What keeps them there is that a batch never returns anything it
    /// frees — freed blocks go back to the free-space tree only at commit, so
    /// until then the allocator, which reads that tree, cannot reach them.
    /// (The pinned set covers the window after that: from commit until the
    /// superblock naming the new tree is durable.)
    ///
    /// Deliberately narrower than [`Self::commit_roots`]: it must NOT advance
    /// `superblock.generation`, because every operation of the batch derives
    /// its generation from that field and they all have to agree.
    pub(crate) fn advance_fs_root(&self, new_fs_root: u64, new_fs_level: u8) {
        let id = self.fs_tree_id();
        if let Some(live) = self.state.lock().subvols.get_mut(&id) {
            live.root = new_fs_root;
            live.level = new_fs_level;
        }
    }

    /// The live root of subvolume `id` when some mount tracks it.
    pub(crate) fn live_subvol_root(&self, id: u64) -> Option<u64> {
        self.state.lock().subvols.get(&id).map(|live| live.root)
    }

    /// Sample the live root of subvolume `id` (this mount's when `None`) and
    /// pin it against reuse until the returned [`RootPin`] drops, atomically:
    /// the root is read and pinned under the same lock every root update
    /// takes, so it cannot be retired, committed and reallocated in between.
    /// `None` when no mount tracks `id`.
    pub(crate) fn pin_live_root(&self, id: Option<u64>) -> Option<RootPin<B>> {
        let id = id.unwrap_or_else(|| self.fs_tree_id());
        let g = self.state.lock();
        let root = g.subvols.get(&id)?.root;
        *self.core.reader_roots.lock().entry(root).or_insert(0) += 1;
        drop(g);
        Some(RootPin {
            core: self.core.clone(),
            root,
        })
    }

    /// Publish a committed root for a tree other than this mount's (a
    /// snapshot source or destination, a new subvolume), so mounts of it
    /// observe the commit. A tree no mount has selected is not tracked.
    pub(crate) fn publish_subvol_root(&self, id: u64, root: u64, level: u8) {
        if let Some(live) = self.state.lock().subvols.get_mut(&id) {
            live.root = root;
            live.level = level;
        }
    }

    /// Re-root this mount at `id`. A subvolume another mount already tracks
    /// keeps its live root: that one may be newer than the root tree (a batch
    /// staged through the other mount), and the root tree can never be newer
    /// than it.
    fn select_subvol(&self, id: u64, root: u64, level: u8, flags: u64) {
        let mut view = self.view.lock();
        let mut g = self.state.lock();
        let previous = view.fs_tree_id;
        if let Some(live) = g.subvols.get_mut(&previous) {
            live.mounts = live.mounts.saturating_sub(1);
        }
        let live = g.subvols.entry(id).or_insert(LiveSubvol {
            root,
            level,
            flags,
            mounts: 0,
        });
        live.mounts += 1;
        view.fs_tree_id = id;
    }

    /// After a COW commit, publish the new roots into the live volume so
    /// subsequent reads through this handle observe the write.
    pub(crate) fn commit_roots(
        &self,
        new_root_tree: u64,
        new_fs_root: u64,
        new_fs_level: u8,
        new_generation: u64,
        new_fs_tree_flags: Option<u64>,
        incompat_flags_add: u64,
    ) {
        // Lock order is view before state (see `select_subvol`).
        let id = self.fs_tree_id();
        let mut g = self.state.lock();
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
        g.superblock.incompat_flags |= incompat_flags_add;
        let live = g.subvols.entry(id).or_insert(LiveSubvol {
            root: new_fs_root,
            level: new_fs_level,
            flags: 0,
            mounts: 0,
        });
        live.root = new_fs_root;
        live.level = new_fs_level;
        if let Some(flags) = new_fs_tree_flags {
            live.flags = flags;
        }
    }

    /// Register a freshly-allocated chunk's `logical→physical` mapping so writes
    /// and reads can reach it (used by the chunk-growth path).
    pub fn add_chunk_mapping(&self, logical: u64, length: u64, devid: u64, physical: u64) {
        self.state
            .lock()
            .chunk_map
            .add_entry(logical, length, devid, physical);
    }

    /// Register a complete freshly allocated chunk item, including all member
    /// stripes and its RAID profile.
    pub(crate) fn add_chunk_item_mapping(&self, logical: u64, chunk: &[u8]) -> Result<(), FsError> {
        self.state.lock().chunk_map.add_chunk_item(logical, chunk)
    }

    /// Publish replacement geometry for an existing logical chunk after its
    /// new physical contents and COWed chunk tree are durable.
    pub(crate) fn replace_chunk_item_mapping(
        &self,
        logical: u64,
        chunk: &[u8],
    ) -> Result<(), FsError> {
        self.state
            .lock()
            .chunk_map
            .replace_chunk_item(logical, chunk)
    }

    /// Publish per-member allocation accounting before the superblock copies
    /// are emitted. Each copy retains its own embedded dev_item.
    pub(crate) fn set_device_bytes_used(&self, used: &BTreeMap<u64, u64>) -> Result<(), FsError> {
        for (&devid, &bytes) in used {
            let member = self.member(devid)?;
            let mut item = member.dev_item.lock();
            item[16..24].copy_from_slice(&bytes.to_le_bytes());
        }
        Ok(())
    }

    /// After a chunk-growth commit, publish the new chunk-tree + root-tree roots
    /// and generation into the live superblock.
    pub fn commit_chunk_root(
        &self,
        new_chunk_root: u64,
        new_root_tree: u64,
        new_generation: u64,
        total_bytes: u64,
        num_devices: u64,
        incompat_flags_add: u64,
    ) {
        let mut g = self.state.lock();
        g.superblock.chunk_root = new_chunk_root;
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
        g.superblock.total_bytes = total_bytes;
        g.superblock.num_devices = num_devices;
        g.superblock.incompat_flags |= incompat_flags_add;
    }

    /// Record the root-tree (and, after chunk growth, chunk-tree) root levels
    /// a commit wrote into the superblock.
    /// Publish a chunk-tree root a commit moved (chunk allocation).
    pub(crate) fn set_chunk_root(&self, root: u64, level: u8) {
        let mut g = self.state.lock();
        g.superblock.chunk_root = root;
        g.superblock.chunk_root_level = level;
    }

    pub(crate) fn set_superblock_levels(&self, root_level: u8, chunk_root_level: Option<u8>) {
        let mut g = self.state.lock();
        g.superblock.root_level = root_level;
        if let Some(level) = chunk_root_level {
            g.superblock.chunk_root_level = level;
        }
    }

    /// Replace the complete cached system chunk array after balance rewrites
    /// one or more SYSTEM mappings.
    pub(crate) fn commit_sys_chunk_array(&self, array: Vec<u8>) -> Result<(), FsError> {
        if array.len() > format::SYS_CHUNK_ARRAY_SIZE {
            return Err(FsError::NoSpace);
        }
        self.state.lock().superblock.sys_chunk_array = array;
        Ok(())
    }
}

/// Compare the shared part of two member superblocks. The checksum and embedded
/// dev_item fields are intentionally member-specific; every other decoded field
/// must describe the same transaction before the array is safe to write.
fn same_common_superblock(left: &Superblock, right: &Superblock) -> bool {
    left.fsid == right.fsid
        && left.magic == right.magic
        && left.generation == right.generation
        && left.root == right.root
        && left.chunk_root == right.chunk_root
        && left.log_root == right.log_root
        && left.log_root_level == right.log_root_level
        && left.total_bytes == right.total_bytes
        && left.bytes_used == right.bytes_used
        && left.num_devices == right.num_devices
        && left.compat_ro_flags == right.compat_ro_flags
        && left.incompat_flags == right.incompat_flags
        && left.sectorsize == right.sectorsize
        && left.nodesize == right.nodesize
        && left.csum_type == right.csum_type
        && left.root_level == right.root_level
        && left.chunk_root_level == right.chunk_root_level
        && left.sys_chunk_array == right.sys_chunk_array
}

/// The run of whole device blocks the next request covers, starting at byte
/// `absolute` and wanting `remaining` bytes: `(lba, blocks, offset of
/// `absolute` within the run, bytes of the caller's range inside the run)`.
/// Pure: the unit of the request-shape tests.
pub(crate) fn io_run(
    absolute: u64,
    remaining: usize,
    block_size: usize,
    scratch: usize,
) -> (u64, usize, usize, usize) {
    let bs = block_size as u64;
    let lba = absolute / bs;
    let in_run = (absolute % bs) as usize;
    let copy = remaining.min(scratch - in_run);
    let blocks = (in_run + copy).div_ceil(block_size);
    (lba, blocks, in_run, copy)
}

/// Write `src` at physical byte offset `offset` in as few requests as the
/// scratch buffer allows (one per 64 KiB run of whole blocks), reading and
/// merging the existing contents only when the range starts or ends inside a
/// block. A superblock copy or a tree node is therefore a single request,
/// whatever the device's logical block size.
async fn write_exact_to<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    limit: u64,
    offset: u64,
    src: &[u8],
    fua: bool,
) -> Result<(), FsError> {
    let end = offset
        .checked_add(src.len() as u64)
        .ok_or(FsError::InvalidData)?;
    if end > limit {
        return Err(FsError::InvalidData);
    }
    let mut done = 0usize;
    while done < src.len() {
        let absolute = offset + done as u64;
        let guard = io.lock().await;
        let block_size = guard.block_size;
        let (lba, blocks, in_run, copy) = io_run(absolute, src.len() - done, block_size, guard.len);
        let run_bytes = blocks * block_size;
        let partial = in_run != 0 || copy != run_bytes;

        // For a partial run, fetch existing contents first so untouched bytes
        // are preserved.
        if partial {
            let read = BlockRequest {
                op: BlockOp::Read,
                lba,
                blocks: blocks as u32,
                buffer: guard
                    .cap
                    .derive::<Read>()
                    .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            device.submit(read).await.result.map_err(FsError::Io)?;
        }

        let buffer = guard
            .buffer()
            .ok_or(FsError::Io(BlockError::PermissionDenied))?;
        // SAFETY: `guard` serialises all submissions on this registered coherent
        // buffer of `guard.len >= run_bytes` bytes; we hold a strong Arc for the
        // copy.
        let dst = unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr(), run_bytes) };
        dst[in_run..in_run + copy].copy_from_slice(&src[done..done + copy]);

        let write = BlockRequest {
            op: BlockOp::Write { fua },
            lba,
            blocks: blocks as u32,
            buffer: guard
                .cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        device.submit(write).await.result.map_err(FsError::Io)?;
        done += copy;
        drop(guard);
    }
    Ok(())
}

/// Read `dst.len()` bytes at physical byte offset `offset`, one scratch-sized
/// run of whole blocks per request through the volume's serialised buffer.
async fn read_exact_from<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    limit: u64,
    offset: u64,
    dst: &mut [u8],
) -> Result<(), FsError> {
    let end = offset
        .checked_add(dst.len() as u64)
        .ok_or(FsError::InvalidData)?;
    if end > limit {
        return Err(FsError::InvalidData);
    }
    let mut done = 0usize;
    while done < dst.len() {
        let absolute = offset + done as u64;
        let guard = io.lock().await;
        let block_size = guard.block_size;
        let (lba, blocks, in_run, copy) = io_run(absolute, dst.len() - done, block_size, guard.len);
        let request = BlockRequest {
            op: BlockOp::Read,
            lba,
            blocks: blocks as u32,
            buffer: guard
                .cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        device.submit(request).await.result.map_err(FsError::Io)?;
        let buffer = guard
            .buffer()
            .ok_or(FsError::Io(BlockError::PermissionDenied))?;
        // SAFETY: `guard` serialises all submissions on this registered coherent
        // buffer, which is `guard.len >= blocks * block_size` bytes and stays
        // registered until the volume drops.
        let source = unsafe { core::slice::from_raw_parts(buffer.as_ptr(), blocks * block_size) };
        dst[done..done + copy].copy_from_slice(&source[in_run..in_run + copy]);
        done += copy;
        drop(guard);
    }
    Ok(())
}
