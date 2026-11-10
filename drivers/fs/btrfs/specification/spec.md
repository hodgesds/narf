# btrfs — Specification

## 1. Purpose & scope

The existing btrfs volume, subvolume and multi-device implementation. The driver README documents supported profiles and mutation operations.

## 2. Assumptions

Block devices are supplied by `narf-block`; the VFS owns mount attachment
and namespace policy.

## 3. Public interface

`register_fstypes()` registers `btrfs` in the shared named-mount registry.
It performs no device I/O. The constructor resolves a registered block source,
validates options and returns an unattached `Arc<dyn FsInstance>`.
Both legacy mount and fsconfig use this constructor. Existing volume/node APIs
are described in the [driver README](../README.md) and their Rust documentation.

Directory ownership and mode updates through `DirOps` use the same persistent
inode update path as `FileOps`. In particular, the ownership and mode assigned
by `mkdir(2)` are visible through both views and survive remounting; directory
setters propagate write errors instead of silently accepting an update.
`FileOps::stat`/`stat_async`, `statx_async` and `DirOps::dir_mode` preserve
all twelve inode permission bits (`0o7777`), including setuid, setgid and
sticky bits. Ownership is reported independently. Exec and namespace policy
still decide whether those bits confer privilege or restrict mutations.

Write safety (`rw_gate`):

```rust
pub mod rw_gate {
    pub const WRITER_INCOMPAT: u64;      // = format::SUPPORTED_INCOMPAT_FLAGS
    pub const WRITER_COMPAT_RO: u64;     // = format::WRITE_SUPPORTED_COMPAT_RO_FLAGS
    pub const ROOT_RW_INCOMPAT: u64;     // narrow production-root set
    pub enum Profile { Default, RootRw } // RootRw under narf.disks=root-rw
    pub enum Refusal { Incompat(u64), CompatRo(u64), FreeSpaceTreeInvalid,
        NoFreeSpaceTree, ChecksumType(u16), SectorSize(u32),
        NodeSize(u32), ErrorState, SuperFlags(u64), Generation, MultiDevice(u64),
        BalanceInProgress, ReplaceInProgress, RelocationInProgress,
        Snapshotted { root: u64, last_snapshot: u64 }, DeadRoot(u64),
        SharedTreeBlock { bytenr: u64, refs: u64, flags: u64, why: &'static str } }
    pub const WRITER_HANDLES_SHARED_TREES: bool; // update_ref_for_cow implemented
    pub fn active_profile() -> Profile;
    pub fn check_superblock(sb: &Superblock, super_flags: u64, p: Profile) -> Result<(), Refusal>;
    pub async fn check_trees(vol: &BtrfsVolume<B>) -> Result<(), Refusal>;
    pub fn check_root_item(id: u64, body: &[u8]) -> Result<(), Refusal>;
    pub fn check_tree_block_item(bytenr: u64, refs: u64, flags: u64, inline: &[u8],
        root_holders: u64) -> Result<(), Refusal>;
    pub async fn check_sharing(vol: &BtrfsVolume<B>) -> Result<(), Refusal>;
    pub fn supported_features(p: Profile) -> (Vec<&str>, Vec<&str>);
    pub fn last_refusal() -> Option<String>;
}
FsInstance::always_read_only() for BtrfsVolume == is_read_only()
pub mod interop { pub fn run(mode: &str) -> InitResult }        // test vehicle
pub mod harness {                                               // test-workload targeting
    pub fn is_harness_fsid(fsid: &str) -> bool;
    pub fn check_disposable(fsid: &str, root_uuid: Option<&str>, on_root: bool)
        -> Result<(), &'static str>;
    pub fn device_is_disposable(dev: &Arc<dyn BlockDeviceSync>, what: &str, on_root: bool) -> bool;
}
BtrfsVolume::sync_fs(&self) -> Result<(), FsError>  // syncfs: commit + superblock + flush
```

All write profiles apply the commit metadata reserve check before staging
another operation. Space pressure may commit a batch before `MAX_BATCH_OPS`;
the operation cap is an upper bound, not a promised transaction size. Explicit
sync commits the final partial batch. Tests inspecting committed tree roots
must sync successfully before checking their height.

Every node for one `(filesystem core, fs-tree id, inode)` retains shared inode
metadata, size, and mapping identity. Creation acquires that reference before
releasing the operation mutex. Mutators hold the mutex from their first tree
read to staging, and the commit they may force is inside that span, so it can
be held for hundreds of milliseconds.

No read-side operation takes the operation mutex: `read`, `lookup_async`,
`lookup_dir_async`, `stat_async`, `statx_async`, `enumerate_async` and the xattr
reads never wait for a mutator or a commit, as no Linux reader waits for a
transaction. Each namespace operation stages atomically and a read takes the
inode and its extents from one root, so it observes an operation whole or not
at all. Three rules replace the mutex on that side:

- **Space.** `begin_reader` opens a reader epoch before any root is sampled;
  what a commit releases stays withheld from the allocator until every reader
  that started before that commit has ended (`ReaderEpochs`).
- **Eviction.** `claim_for_eviction` counts an eviction before its last open
  check; `lookup_child` compares that count across resolving the name and
  publishing its anchor, and starts over if it moved.
- **Metadata.** `stat_async` and `statx_async` refresh metadata from the current
  tree, publishing it only if the inode's `update_seq` did not move and no
  mutation of the inode is in flight (odd). Writes and size changes publish
  shared metadata before releasing the mutex.

Content generations advance after acquiring that mutex and before changing
bytes or length, and again when the mutation ends. A fill runs beside the
mutation, so a generation sampled in between may tag old bytes; the second
advance keeps them from staying current. Shrinking truncate publishes EOF and
revokes mappings under the operation lock before retiring extents, and revokes
again afterwards (`truncate_pagecache`), since a fault past its EOF check is
excluded by no lock; a failed revoke restores the cached inode there.

File-content reads seek to the extent at or before the requested offset and
walk only the requested window. A small read must not collect the inode's
entire extent list. Reader epochs, checksum verification, the compressed-extent
cache and zero filling of holes still cover these reads.

Uncompressed reads covered entirely by valid data checksums retain windows up to
128 KiB in the shared 32 MiB extent cache. Keys include shared-core identity,
logical byte range, compression tag and file-extent generation. Reads never
widen their requested window to fill the cache. Logical writes invalidate
overlapping entries before and after I/O, and a fill crossing a write epoch
is not retained. Verification-disabled views and larger windows bypass this
uncompressed cache. The maximum cached disk span also bounds invalidation's
backward scan; it is enforced at insertion for both entry kinds.
Missing-checksum sectors (including pending writes before commit) remain
readable through the existing policy but never populate verified windows.
An 8,192-entry ceiling bounds bookkeeping for tiny ranges as well as payload
bytes.

Last-link unlink and file replacement remove the name and persist `nlink=0`
with a Linux `ORPHAN_ITEM` in the owning fs tree. Existing handles and private
or shared mappings retain the original inode, data and xattrs. They remain
readable/writable and their inode number cannot be reused. Reclamation runs
after the final node/mapping reference, during a subsequent operation, explicit
sync, timer pass, or writable-mount recovery; it removes the inode and orphan
record together and releases data through the ordinary COW/backref transaction.
Read-only mounts do not recover orphans. Final-view Drop only makes previously
accepted changes durable, leaving any unreaped orphan record for recovery.

## 4. Invariants

A commit maintains the free-space tree incrementally (`write/free_space.rs`,
Linux `btrfs_add_to_free_space_tree` / `btrfs_remove_from_free_space_tree`
run from the delayed refs): it reads only the leaves holding the items its
allocations and frees reach (the block group's `FREE_SPACE_INFO`, the
`FREE_SPACE_EXTENT` or `FREE_SPACE_BITMAP` items around each range), edits a
private copy of those items, and path-COWs the result, so the blocks read and
written are bounded by tree height × touched leaves, independent of the size
of the tree (`smoke_btrfs_commit_cost_tracks_change_not_tree_size`). Each block group
keeps the form its `FREE_SPACE_INFO.flags` selects; none is converted.
Extent-form frees merge with an adjacent free extent on either side, never
across a block-group boundary. Bitmap ranges are found by their ordered keys,
with coverage and body bounds checked across every bitmap boundary, and
`extent_count` moves by the delta the bits on either side of the range give
(Linux `modify_free_space_bitmap`). An allocation of space the tree does not
hold free, or a free of space it already does, fails the commit before
anything is written. The free-space tree's own new and replaced blocks are
metadata allocations and frees that edit it again, as the extent and
block-group trees' are. A commit records them the way Linux runs its delayed
refs (`btrfs_run_delayed_refs` under `commit_cowonly_roots`): the three path
COWs stay open, each pass records the blocks no earlier pass recorded — into
leaves that, once COWed, are edited in place — and the commit is complete
when a pass leaves none. A committed block is replaced at most once and no
address is handed out twice, so the passes end; a guard of 1024 passes fails
the commit before anything is written. (The earlier fixed point, which
recomputed all three trees from the committed ones every round until two
rounds agreed, did not settle within its 64 rounds on a filesystem of 320
block groups with three-level trees; `cargo xtask btrfs-host-rw --scenario
scale` reproduces that shape.) What the trees hold afterwards is a function
of the final block lists alone. Each new block's `METADATA_ITEM` key is
checked absent from the committed extent tree before it is inserted. Extent
and free-space leaves are kept dense: an overflowing leaf is split evenly
(or left full when everything added sorts after what it held), and a sparse
committed leaf an edit reaches absorbs its right sibling; the sparser those
trees, the more leaves the records of one commit's blocks reach. The on-disk
format is unchanged.

The allocator carves from one in-memory copy of the committed free-space tree
per filesystem (`allocator::FreeView`, Linux's per-block-group free-space
cache), read from disk on first use and advanced by each commit with exactly
the ranges that commit marked used and free in the tree. It is tied to the
tree root (address + generation) it mirrors and is re-read from disk whenever
that does not match: at mount, after a failed or aborted commit, after a
chunk allocation or any other transaction that changes block groups, and
after any path that writes the tree outside `commit_txn`. Pinned extents,
roots held by lock-free readers and superblock mirror stripes are free in the
view and withheld by each allocator, so the pinning rule is unchanged. With
`allocator::set_view_audit` (on in kernel-test builds and in
`verification/btrfs-host`) every commit re-reads the tree and fails on any
difference from the view.

Data extents are carved first-fit from the lowest address. Tree blocks are
carved next-fit: each from the lowest free space at or after the end of the
last one, across transactions, starting again from the bottom only when
nothing above fits (Linux allocates metadata from a cluster it works through,
`find_free_extent` with `meta_alloc_cluster`). The blocks one commit writes
then sit side by side, their `METADATA_ITEM`s share an extent-tree leaf, and
so do the items of the blocks the next commit replaces; filling the lowest
holes instead scatters both over as many leaves, each of which the commit has
to replace as well. The placement is a preference only: every address handed
out is free space of the right block-group type, as before.

A commit looks up only the block groups it allocates from or frees into, by
the key the chunk map gives (a block group is its chunk), and fails if the
tree does not hold exactly that item. The first commit of a mount writes the
superblock's `bytes_used` as the sum of every block group's `used`; later
commits move it by the net of the groups they changed (Linux
`btrfs_update_block_group`), and a failed commit makes the next one sum
again. With the audit on, every commit sums all block groups and fails if
moving the value does not give the same.
So what a small commit reads and writes follows the transaction: the leaves
of the extent, block-group, csum and free-space trees its records reach, each
once, and the (small, whole-repacked) root tree — not the number of block
groups, the size of those trees, or the number of recording passes
(`smoke_btrfs_commit_cost_tracks_change_not_tree_size`).

Tree blocks nothing references any more — replaced by a commit, or written
and replaced again inside one batch — are dropped from the node cache, which
is bounded by emptying it when it fills.

Metadata space is reserved before an operation is accepted, never inside a
commit (`write/reserve.rs`, Linux `btrfs_start_transaction` /
`btrfs_block_rsv_add`). An operation is staged only while the free metadata
space, after the operation's own fs-tree blocks, covers (a) twice the
*first-order* need of the batch with that operation in it — a bound on the
blocks the commit's own csum, extent, block-group and free-space edits can
allocate, `2 × height` per inserted item and `height` per modified one, with
the heights sampled when the batch opens — and (b) the global reserve: the
recorded size of the extent, csum, block-group and free-space trees, at least
256 blocks, at most 512 MiB and an eighth of the metadata space
(`btrfs_update_global_block_rsv`). The first-order share is a bound; the
doubling (for recording the commit's own blocks) and the global reserve are
sized, not proven, as in Linux, and a commit that still finds no space aborts
the transaction as before. Each commit reports the blocks it allocated beyond
its batch's reservation (`stats::max_reserve_overrun`).

An operation whose reservation does not fit is refused with `NoSpace` before
anything of it is staged, and reclaim runs for that operation, outside any
commit: the open batch is committed and its superblock written, which unpins
what earlier transactions freed, and the operation is retried
(`with_space_retry`, Linux `COMMIT_TRANS`); if it still does not fit, a
METADATA or DATA chunk is allocated in a transaction of its own and it is
retried again (`autogrow!` → `root_rw_grow`, Linux `ALLOC_CHUNK`); only then
does it return `ENOSPC`. (Linux tries the chunk before the commit; here the
batch has to close before a chunk can be allocated, so the commit comes
first.) After that commit, a METADATA chunk is allocated at once if the
metadata space, global reserve included, is within 2 MiB of 80% in use
(`alloc_metadata_ahead`, Linux `should_alloc_chunk`); otherwise a filesystem
whose free metadata barely exceeds the reserve would never reach the chunk
allocation and would run on short batches. A chunk is never allocated inside
`commit_txn`. Reclaiming orphans is
part of what is retried, so its `NoSpace` takes the same ladder, and it never
fails a sync or keeps the transaction timer from committing. `unlink`,
`rmdir` and the final eviction of an orphan may borrow the global reserve
when their reservation does not fit (Linux
`btrfs_start_transaction_fallback_global_rsv`, `evict_refill_and_join`), so a
full filesystem can still be emptied; the batch then commits at once.

`fsync` and `fdatasync`, on a file or a directory, both commit the open
transaction and write its superblock (`sync_to_disk_exclusive`). `fdatasync`
is not weaker: the size and extent items a write's data is read back through
live in the open batch until it commits, so a device flush alone makes
nothing of that write durable (`smoke_btrfs_fdatasync_survives_a_later_crash`;
Linux `btrfs_sync_file` ignores `datasync` too). Neither goes through a tree
log; `write::write_log` (hand-built items, for tests) is the only writer.

**Tree-log replay** (`write/log_replay.rs`, `write/tree_log.rs`). A
read-write mount of a filesystem whose superblock names a log
(`log_root != 0`: Linux, or NARF, fsynced and went down before the next
commit) replays it before anything else writes, as Linux
`btrfs_recover_log_trees` does and in both write profiles — a pending log is
not an `rw_gate` refusal. The log root tree's `ROOT_ITEM`s are keyed
`(BTRFS_TREE_LOG_OBJECTID = -6, ROOT_ITEM, subvolume id)`; every log block
must be owned by `-6` and carry generation `super.generation + 1`, as Linux
reads them. Stage by stage, with the Linux function each step is:

| step | Linux | here |
|---|---|---|
| pin the log's blocks and its not-yet-allocated data extents before any allocation | `process_one_buffer`, `btrfs_pin_extent_for_log_replay`, `btrfs_exclude_logged_extents` | `LogCore::pin`; `BtrfsVolume::pinned_ranges` subtracts them in every allocator |
| skip inodes logged with no links | `wc->ignore_cur_inode` | `replay_root` |
| xattrs absent from the log are deleted | `replay_xattr_deletes` | `replay_xattr_deletes` |
| directory entries inside a `DIR_LOG_INDEX` range but not in the log are unlinked | `replay_dir_deletes`, `find_dir_range`, `check_item_in_log` | `replay_dir_deletes` |
| inode items, with the `nbytes` / directory-size / `generation == 0` rules | `overwrite_item` | `overwrite_inode` |
| a regular file's extents beyond its size are dropped | `btrfs_drop_extents` in `replay_one_buffer` | `drop_extents` (`fileops::carve`) |
| logged `DIR_INDEX` items | `replay_one_dir_item`, `replay_one_name`, `delete_conflicting_dir_entry`, `insert_one_name` | `replay_dir_index` |
| logged `INODE_REF` / `INODE_EXTREF` items | `add_inode_ref`, `__add_inode_ref`, `inode_in_dir`, `unlink_refs_not_in_log`, `unlink_extrefs_not_in_log`, `unlink_old_inode_refs`, `backref_in_log` | `add_inode_ref`, `clear_for_ref`, `inode_in_dir`, `backref_in_log` |
| linking / unlinking one name | `btrfs_add_link`, `btrfs_unlink_inode`, `drop_one_dir_item` | `add_link`, `unlink`, `drop_one_dir_item` |
| file extents: drop what the item overlaps, insert it, take a reference on an extent that exists or allocate it (extent item, block group, free-space tree) | `replay_one_extent`, `btrfs_lookup_data_extent`, `btrfs_inc_extent_ref`, `btrfs_alloc_logged_file_extent` | `replay_one_extent`, `extent_exists`; the batch's `added_data` / `new_data` |
| checksums of each replayed range replace the csum tree's | `btrfs_lookup_csums_list` on the log, `btrfs_del_csums`, `btrfs_csum_file_blocks` | `replay_csums` → `tree_log::take_replayed_csums` in `commit_txn` |
| link counts from back references; an inode left with none is orphaned | `link_to_fixup_dir`, `fixup_inode_link_counts`, `count_inode_refs`, `count_inode_extrefs`, `btrfs_insert_orphan_item` | `fixup_inode_link_counts`, `count_refs` |
| commit; the committed superblock has `log_root = 0`; the log's space is released after it is written | `btrfs_commit_transaction`, `btrfs_free_log_root_tree` | `finish`; `tree_log::on_commit` (every commit clears `log_root` and moves the log pins to the pinned set) |

The replay is one transaction, as in Linux: it holds the operation lock and
`hold_commits`, stages on the global reserve (Linux replays with
`btrfs_start_transaction(root, 0)`), and `tree_log::on_commit` fails any
commit attempted before the last stage is done. Nothing is durable until the
one superblock that carries the replayed trees and `log_root = 0`, so a
crash at any write leaves either the log in place (replayed again by NARF or
by Linux — an intermediate commit would have advanced the generation past
what Linux accepts for the log's blocks) or the finished replay
(`smoke_btrfs_log_replay_survives_a_crash_at_any_write`). A replay that
fails aborts the filesystem without a superblock write and the mount fails
with the log intact.

Differences from Linux in replay, all refusing rather than guessing: a log
for a subvolume whose tree is still shared with a snapshot root
(`Unsupported`; privatising it would be a second transaction); a directory
entry or back reference naming another subvolume; a name or index
collision Linux resolves by a partial insert (`InvalidData`); a back
reference that would have to move to an `INODE_EXTREF`. A directory left
with no link is emptied and deleted in the replay instead of through an
orphan item (the writer's orphan reclaim handles files only); files get the
orphan item and are reclaimed by `recover_orphans` after the replay commits.
Qgroup counts are not maintained by replay.

**Tree-log writer** (`write/tree_log.rs`; Linux `btrfs_sync_file` →
`btrfs_log_dentry_safe` → `btrfs_log_inode`, then `btrfs_sync_log`).
`tree_log::fsync_inode` logs one regular file and makes the log durable
without committing the transaction. It is reached from `FileOps::fsync` /
`DirOps::fsync` and is switched off by default
(`write::set_fsync_via_log(false)`: every fsync still commits) until the
switch is removed.

NARF writes a file's data extents when `write` returns and stages the
fs-tree edits into the open transaction, whose tree blocks are on the device
but named by no superblock. What an fsync has to make durable is therefore
the difference between the subvolume tree at the last commit
(`SubvolBatch::base_root`) and the live tree, for one inode. The writer
computes exactly that from the two trees at every fsync; it keeps no
per-inode logging state (Linux's `logged_trans`, `last_unlink_trans`,
`BTRFS_INODE_NEEDS_FULL_SYNC`, modified-extent lists), so no mutation path
has to maintain any. The log of an inode is:

| logged | as Linux logs it in |
|---|---|
| its `INODE_ITEM`, as in the live tree | `fill_inode_item` (`LOG_INODE_ALL`) |
| every `INODE_REF` item | `copy_items` |
| every `XATTR_ITEM` (replay deletes the ones not logged) | `btrfs_log_all_xattrs` |
| every `EXTENT_DATA` item that is not byte-identical to the committed item of the same key; and every item reaching past the sector-aligned size, changed or not, because replay truncates to the size first | `btrfs_log_changed_extents` / `copy_items`; `btrfs_log_prealloc_extents` |
| with `NO_HOLES`, an explicit hole item over each range that has no item now and held data at the commit | `btrfs_log_holes` |
| one `EXTENT_CSUM` item (`-10`, in the subvolume's log tree) per logged data extent born in this transaction, from the checksums the transaction holds for its commit; extents the commit already has keep their committed checksums and replay only takes a reference | `log_extent_csums` → `log_csums` |
| for a file the last commit does not have: every directory above it that the commit does not have either, as `INODE_ITEM` + `INODE_REF` + xattrs and none of its entries | `btrfs_log_inode_parent` → `log_all_new_ancestors` (`LOG_INODE_EXISTS`) |

A file created since the commit thus comes back by name: replay's
`add_inode_ref` links each logged `INODE_REF` into its directory. A file
the commit has keeps its committed names, which is why its names must be
unchanged (below).

Writing (`log_inode`). The transaction's logs live in memory as item sets
per inode (`LogState`); a sync rebuilds the fsynced subvolume's log tree
from them and the log root tree's one leaf (`ROOT_ITEM`
`(-6, ROOT_ITEM, subvolume)`, laid out as `btrfs_add_log_tree` leaves it),
in blocks owned by `BTRFS_TREE_LOG_OBJECTID` at the transaction's
generation. The blocks come from the transaction's own allocator, as
Linux's come from `btrfs_alloc_tree_block`, and only while the free
metadata left still covers the reservation of the operations the
transaction has accepted (`ReserveGeometry::ordinary_need`). They, and the
logged data extents no committed tree accounts for, are withheld from every
allocator (`LogCore::pin`) until a commit's superblock has replaced the
log's, as Linux pins them until `btrfs_free_log` and the end of the commit
— including blocks a later sync of the same transaction superseded, and
data extents the file has since dropped: the log on the device may still
name them. Then `btrfs_sync_log`: the last committed superblock with
`log_root` / `log_root_level` set goes through `write_all_supers`, whose
pre-flush of every device makes the data and the log blocks durable before
the FUA superblock names them. If a commit's superblock is still staged it
is written first (the log's blocks carry `super.generation + 1`). Every
commit clears `log_root` (`on_commit`); a transaction that commits after a
log sync needs no log, and the next one starts a new log.

An fsync that finds nothing of the inode newer than the last commit issues
a flush and returns. Everything else commits the transaction instead
(`Fallback`, counted per reason in `stats::fsync_fallbacks`) — always
correct, as in Linux (`BTRFS_LOG_FORCE_COMMIT`, `btrfs_set_log_full_commit`):

- **a directory** (`DirOps::fsync`), a symlink or a special file — Linux
  logs directories (`log_directory_changes`); this writer does not;
- **names changed since the commit**: the file was renamed, linked or lost
  one of several links (Linux: `btrfs_log_new_name`, `last_unlink_trans` →
  `btrfs_log_all_parents`); also a new parent directory whose own name
  changed;
- **a name of a new file collides**: the name, or its directory index, was
  held by any inode at the commit (replay would unlink that inode's entry:
  Linux resolves it with `log_conflicting_inodes`), or is claimed by another
  inode already in this log;
- **inode number reused**: the number, or a parent's, belonged to a
  different inode at the commit, or to a different inode already in the log
  (creation time or type differ);
- **unlinked inode** (no link left, still open) — Linux skips it;
- **extended refs**: a name of the inode lives in an `INODE_EXTREF`;
- **unsupported items**: any item type other than inode item, refs, xattrs
  and file extents (verity, …), a single item larger than a leaf, a logged
  extent whose length disagrees with the transaction's record, overlapping
  checksum ranges;
- **size**: more than 2048 logged items for the inode, a log tree past 16
  leaves, more than 1024 log blocks in the transaction, more
  logged subvolumes than one leaf of log root items holds;
- **space**: the log blocks do not fit beside the transaction's
  reservation;
- **quotas enabled** (replay does not maintain qgroup counts), **no
  free-space tree** (nothing to withhold log blocks with), **read-only or
  aborted filesystem**, and **a failed earlier log write** of the same
  transaction.

Snapshot and subvolume creation, chunk allocation and every other
non-batched transaction commit and so end the log before they run.

Differences from Linux, and why they are sound:

- *The log is a diff against the commit, recomputed per fsync*, where Linux
  accumulates per-inode state. Same items on disk for the supported cases;
  nothing to keep in step with every mutation path.
- *A sync rewrites the subvolume's log tree* where Linux COWs the paths it
  changed. The tree on disk is an ordinary log tree either way; the size
  limits above bound the cost, and superseded blocks stay pinned as Linux's
  COWed-away log blocks do.
- *Every superblock copy is written* on a log sync, where Linux writes only
  the primary (`write_all_supers(fs_info, 1)`): NARF keeps all copies in
  lockstep, and a mount picks the highest generation among them.
- *Operations after an fsync do not touch the log.* Linux updates it on
  rename and unlink (`btrfs_log_new_name`, `btrfs_del_inode_ref_in_log`); here
  the log keeps the inode as it was fsynced, and the name checks above send
  any later fsync that would contradict it to a commit. After a crash the
  file is under the name it was fsynced under, with the content it was
  fsynced with — the state at the fsync, which is what fsync promises.

Durability: when `fsync` returns, the file's data, size, mode, xattrs and —
for a new file — its name in its directory, with any new directories above
it, survive a crash; later unsynced changes to it do not come back. Write a
temporary file, fsync it, rename it over the real one: after a crash at any
point the real name holds the old file or the new, whole (the temporary may
still exist under its own name).

Verification: `smoke_btrfs_replays_a_linux_written_log` replays
`testdata/fixture-linuxlog.img.sparse` (a log a real kernel wrote; regenerate
with `narf-btrfs-host --emit-linux-log-fixture`) to the tree Linux's own
replay yields; `cargo xtask btrfs-host-rw --scenario fsync-linux` has a real
kernel (the host's, under QEMU, no root needed) write logs with scripted and
random workloads, kills it, and replays each crashed image with that kernel
and with NARF: the trees must be identical, both must pass
`btrfs check --check-data-csum`, and the NARF-replayed image must mount on
Linux unchanged. `--scenario fsync-narf` runs the same scripts through NARF
with the log path on and copies the image at the crash point: a real Linux
kernel replays every NARF-written log, NARF replays a second copy, and the
same comparison and checks apply; it reports how many fsyncs were logged
and why the others committed. `--scenario fsync-sweep` records the device
writes of three scripts and rebuilds the image as a power cut after each
write would leave it, with and without the writes no flush had covered:
every image must replay under NARF to a state that keeps each fsync that
had returned, pass `btrfs check --check-data-csum`, and a spread of them is
also replayed by Linux to the identical tree. In the kernel,
`smoke_btrfs_fsync_goes_through_the_log` (new file, overwrite, append,
truncate, new directories, unsynced writes after the fsync; five fsyncs
cost five superblock writes and no commit),
`smoke_btrfs_fsync_burst_does_not_commit_per_fsync` (sixty
write-temp + fsync + rename), `smoke_btrfs_fsync_log_across_a_commit`,
`smoke_btrfs_fsync_falls_back_to_a_commit` and
`smoke_btrfs_own_log_replay_survives_a_crash_at_any_write` remount a copy of
the device taken at the crash point through replay. Without a bootable
kernel the Linux scenarios report themselves unverified, never passed.

Filesystem constructors execute without the registry lock held. Missing
sources return `FsError::NotFound`; failed construction publishes no mount.
Device ownership remains pinned by the returned filesystem instance.

A volume about to be mounted read-write runs `rw_gate` after the chunk map is
loaded and before anything can write (log replay, the commit timer, any VFS
operation), once per shared core (`registry`); a core mounted read-only
runs it without the sharing walk over every metadata extent item, which
runs before its first read-write request (`ensure_sharing_checked`); a
refusal makes the core
read-only for its lifetime, is logged, and makes later read-write mounts of
it fail. A read-write `mount -t btrfs` that cannot be honoured returns
`FsError::ReadOnly` (EROFS). A read-only core with an unreplayed fsync log
mounts the committed trees without replaying it (Linux `nologreplay`),
logs a warning, and leaves the log for the next writable mount. Data extents are allocated only from DATA block
groups and tree blocks only from METADATA ones. A write through an open file
uses the inode item from the tree, never the node's cached copy.

Subvolume trees are reference counted as Linux counts them: every committed
block a subvolume COW replaces first goes through `update_ref_for_cow`
(`backref.rs`), so a block or data extent another tree (a snapshot, a
reflink, a relocation tree) still references is never freed, and the extent
tree's inline and keyed backrefs always add up to each extent's `refs`.
Independently, every commit audits each tree block it is about to free
against the extent tree (refs 1, one inline TREE_BLOCK_REF, no unreleased
FULL_BACKREF or relocation flag) before writing anything, and aborts
read-only otherwise. A ROOT_ITEM's generation changes only when its root
block moves. A superblock copy and every tree node reach the device as one
request. Lock-free readers verify each child against its parent pointer
(generation, level, first key) and retry from the live root; the root they
sampled has no parent to check against, so it is pinned
(`BtrfsVolume::pin_live_root`) and the allocator never hands it out while
a reader walks from it. Under
`narf.disks=root-rw` the whole-tree growth/balance path never runs; a full
space allocates one SINGLE/DUP chunk by path COW instead
(`write::alloc_chunk`, Linux `btrfs_alloc_chunk`, placed below the device's
btrfs `total_bytes`) of the type that ran short (`write::root_rw_grow`),
only when every chunk of that type has the same SINGLE or DUP profile,
and a device with no hole left is ENOSPC. A batch never stages an operation
that would leave less free metadata than its own commit may need
(`write::commit_meta_reserve`: a 256-block floor plus one block per four
reference/block changes), so a commit does not run out of space; one that
still does aborts read-only. NARF's own
shared-root snapshot ioctl is refused, and full qgroups
are left inconsistent with a rescan pending instead of being recounted. The
last view of a writable core commits what it holds.

An operation that stages more than once — a truncate or fallocate that
zeroes a partial sector before changing the size, a write past EOF that
first zeroes the old last sector's tail (Linux `btrfs_cont_expand` →
`btrfs_truncate_block`, also when a compressed extent backs that sector) —
holds commits (`VolCore::hold_commits`) so its stages land in one
transaction; a batch it fills commits after it (`write::flush_if_full`).
An ENOSPC retry still syncs between attempts. A fallocate inside an inline
file's first sector preallocates nothing there.

Testing: besides the in-kernel smokes, `cargo xtask btrfs-host-rw` runs the
driver in a host process (`verification/btrfs-host`) against
`mkfs.btrfs --rootdir` fixtures shaped like a CachyOS root and
`testdata/fixture-snapshots.img.sparse`, mounted exactly as a
`narf.disks=root-rw` boot mounts them. A seeded random workload is checked
against a model through NARF, `btrfs check` (with data csums) and
`btrfs restore` of every subvolume and snapshot; the recorded
write/flush/FUA stream is replayed at bounded cut points (`--exhaustive`:
every flush) with volatile writes dropped or torn, and each crashed image
must pass `btrfs check` and remount with exactly a committed state. The
`regress-*` scenarios are minimal reproductions of bugs it found. The `scale`
scenario builds the shape of an installed root on a sparse image — 320
mostly-full 1 GiB DATA block groups with some 370,000 single-sector free
extents spread over them, three-level free-space and extent trees —
runs a desktop-like workload in small transactions (save-file
loop, log appends with fsync, bursts of creates and unlinks), and reports per
commit the nodes visited and written per tree, the recording passes, the
blocks allocated beyond the reservation and the wall time.

`cargo xtask btrfs-cycles [--cycles 50] [--seed N] [--jobs N]` runs the
in-kernel driver through many mount lifetimes in one boot per guest
(`src/cycles.rs`, entered as `narf.rootrw_interop=cycles`). The host builds a
CachyOS-shaped root (16 KiB nodes, crc32c, block-group + free-space tree,
`--compress zstd:1`, default `@` plus `@home`, `--rootdir` seeds) in a GPT
partition on NVMe with 512-byte LBAs and boots it under `narf.disks=root-rw`
(designated root, root-rw `rw_gate` profile). The guest detaches `/`, then
per cycle mounts `@` and `@home` through the `mount -t btrfs` constructor,
verifies every file and directory of all earlier cycles against a model,
runs a seeded workload (create inline/medium/multi-MiB files, overwrite,
append, truncate up/down, punch, fallocate, rename over, hard links,
mkdir/rmdir, fsync, write+fsync+rename replace), syncs, and drops every
reference: the shared core must be gone before the next mount reads the
volume back from disk. After the last cycle the host runs `btrfs check
--check-data-csum` and `btrfs restore` on every image and compares the
result with the manifest the guest printed. `--jobs` guests (direct
`-kernel` boot, `-smp 1`, 1 GiB each, own image copy, seed + job index) run
in parallel; the default run finishes in well under three minutes.

## 5. Architecture notes

The registration interface is shared by x86_64 and aarch64. Volume construction
uses the existing async block I/O implementation through the scheduler bridge.

## 6. Dependencies

`narf-filesystem`, `narf-block`, `narf-scheduler` and the driver runtime.

## 7. Stage assignment

Stage 4: persistent filesystem compatibility.

## 8. Open questions

The named mount path retains the implementation's existing format and option
limits; registration does not add support for further on-disk features.
