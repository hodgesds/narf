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

## 4. Invariants

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
