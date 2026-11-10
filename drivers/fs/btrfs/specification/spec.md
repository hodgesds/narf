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

Free-space bitmap edits accumulate only in a private logical leaf. Each
changed block group's free-run count is recomputed after all allocations and
releases for that fixed-point round, before packing or publishing any node.
Bitmap ranges are found by their ordered keys, with coverage and body bounds
checked across every bitmap boundary. The on-disk format is unchanged.

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
`regress-*` scenarios are minimal reproductions of bugs it found.

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
