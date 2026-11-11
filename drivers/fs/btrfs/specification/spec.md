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
        NoFreeSpaceTree, LogTree(u64), ChecksumType(u16), SectorSize(u32),
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

A write does the same (`write::window_extents`, Linux `btrfs_drop_extents`
from a `btrfs_lookup_file_extent` at the range's start): it looks up the
extent item at or before its first sector and walks forward to its last, so
what it reads is the leaves holding the items it replaces, whatever the
number of extent items the file has. Of the old contents it reads only the
partial sectors at its edges — nothing when it covers whole sectors (Linux
`prepare_one_folio`). An overwrite of one page of a file with one extent per
page therefore costs what an overwrite of any page costs
(`smoke_btrfs_overwrite_cost_tracks_range_not_extent_count`, and the
`overwrite` scenario of `cargo xtask btrfs-host-rw`); before, each write
read every extent item of the file, so N page-sized writes into a file of N
single-page extents read N² items. Every write is still its own
synchronous operation — data written, items staged and the path's tree
blocks rewritten before it returns; there is no delayed allocation.
`truncate`, `fallocate` and hole punching still read all of the inode's
extent items.

Tree walks (`btree::Cursor`, `last_before`, `find_item`) hold the nodes on
their path by reference to the node cache and never copy one.

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
checked absent from the committed extent tree before it is inserted. In
every tree a leaf that overflows is split evenly, or left full when
everything added sorts after what it held (`write::retile_leaf`; Linux
`split_leaf` splits at the middle, and `push_leaf_left` keeps appends
dense). Filling the first leaf and spilling a remainder regardless of where
the new items went left one full and one nearly empty leaf after every
insert into the middle of a full leaf, and a file whose pages were first
written in a scattered order — a mapped file written back in page-frame
order — ended up with five extent items to a 16 KiB leaf instead of two
hundred. Leaves written that way stay as they are until their items are
deleted: only extent- and free-space-tree leaves are rejoined (a sparse
committed leaf an edit reaches absorbs its right sibling; the sparser those
trees, the more leaves the records of one commit's blocks reach), since
rejoining leaves of a subvolume tree means COWing a sibling that a snapshot
may share. The on-disk format is unchanged.

The node cache (4,096 nodes, 64 MiB at 16 KiB) is bounded in two
generations: fills and hits go to the young one, and when it holds half the
bound the old one is dropped and the young one takes its place. A node in
use survives any number of other fills
(`smoke_btrfs_node_cache_keeps_what_is_used`). It used to be emptied
outright when it filled, so one walk over more nodes than the bound left
nothing for the next.

CRC32C — every tree block written or read, every data sector — is computed
eight bytes a step (slicing-by-8, as Linux's generic `crc32c`), checked
against the byte-at-a-time definition
(`smoke_btrfs_crc32c_sliced_matches_bytewise`).

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
log: the driver replays a log at mount and can write one (`write_log`), but
`fsync` does not use it.

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
blocks allocated beyond the reservation and the wall time. The `overwrite`
scenario builds files of 1,000 to 16,000 single-page extents (one written
in a shuffled page order), overwrites pages at random and in file order,
and fails if the fs-tree nodes visited, the nodes read from the device or
(loosely) the time per overwrite grow with the file's extent count; it also
reports sequential-write throughput in 128 KiB and 4 KiB calls.

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
