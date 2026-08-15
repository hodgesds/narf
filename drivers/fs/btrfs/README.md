# narf-drivers-fs-btrfs

A clean-room, read-write btrfs driver for single-device filesystems. It supports
Linux-interoperable COW file and namespace mutations, all four checksum types,
compressed reads, writable subvolumes, native subvolume/snapshot ioctls, and
both full and simple qgroup quota modes.
On-disk structures follow Linux's `include/uapi/linux/btrfs_tree.h` definitions;
no C code is copied.

Verified against a **realistic laptop-distro image** (`fixture-laptop`): non-mixed
block groups, `nodesize 16384`, btrfs-progs default features (free-space-tree /
`space_cache=v2`, `no-holes`, `extref`, skinny/big metadata), zstd, and a
Fedora/openSUSE-style `root` (default) + `home` subvolume layout — i.e. what a
real laptop's btrfs root looks like.

## Supported

- Single-device volumes, **SINGLE** and **DUP** chunk profiles. Both DUP copies
  are retained: metadata and checksummed data retry the second stripe after an
  I/O error or checksum failure.
- Power-of-two filesystem sectors and metadata nodes from **4 KiB through
  64 KiB**, independent of the backing device's 512-byte/4-KiB logical block
  size. Allocation, partial I/O and CSUM widths follow the mounted sectorsize.
- **CRC32C, xxhash64, SHA-256, and BLAKE2b-256** checksums, verified on the
  superblock, every tree node, and regular data. The COW writer emits the
  mounted volume's selected algorithm and its format-defined CSUM item width.
- Chunk-tree logical→physical mapping (`sys_chunk_array` seed + chunk-tree walk).
- The selected `FS_TREE`/subvolume: directory `lookup` (CRC32C name hash) and
  `readdir` (`DIR_INDEX`), inode stat, and COW mutations when its root item is
  writable.
- File reads: **inline**, **regular**, and **zlib/zstd/LZO-compressed** extents
  (LZO via a native port of the kernel's `lzo1x_decompress_safe` plus btrfs's
  sector-segmented framing); holes and preallocated ranges read as zeros (both
  explicit-hole and `no-holes` layouts).
- Incremental updates to full, exclusively-owned **zlib** extents preserve
  compression when it saves physical sectors, emitting Linux-compatible padded
  payloads, extent metadata and data checksums. Zstd/LZO updates currently fall
  back to uncompressed COW extents after decoding.
- **Symlinks** (target read via `FileOps::read`, so the VFS follows them), with
  Linux's exact one-leaf inline target limit enforced before mutation,
  **extended attributes** (read via `get_xattr` / `list_xattr` and written via
  `set_xattr` / `remove_xattr` over `XATTR_ITEM`, honouring
  `XATTR_CREATE`/`XATTR_REPLACE`), and **statx** (size/mode/uid/gid/nlink/ino/mtime).
- **Nested subvolumes**: a `ROOT_ITEM` directory entry is resolved through the
  root tree and entered at its own fs tree, so subvolumes and snapshots are
  navigable. A writable subvolume selected with `subvol=PATH` or `subvolid=N`
  supports the full COW mutation surface; `BTRFS_ROOT_SUBVOL_RDONLY` snapshots
  remain read-only.
- **Hardlinks** (shared inode number + `nlink`) and **special files**
  (char/block device nodes and FIFOs, typed via mode; `rdev` decoded into
  statx `rdev_major`/`rdev_minor`).
- **Incremental COW writes** (overwrite / partial / append / sparse grow of a file
  with **any number of extents** — tiled into ≤128 KiB data extents — including
  small inline files, re-tiled as regular extents). A random write replaces only
  its intersected extents and preserves all other data refs/checksums. Writes are
  **Linux-interoperable**: the resulting filesystem mounts read-write on a real
  kernel and passes `btrfs check` — see below.
- **Namespace mutations**: `create` (new empty regular file), `unlink` (freeing a
  file's data extent + checksums on its last link, else just decrementing
  `nlink`), `mkdir` (new empty
  directory), `rmdir` (of an empty directory), `rename` (same- or
  cross-directory, of a file or directory, atomically replacing an existing target
  — freeing a last-link target's data/checksums/xattrs, or removing just one name
  and decrementing `nlink` for a hardlinked target; packed same-parent hardlink
  refs are preserved; a directory cannot move into its own subtree), `symlink`
  (target stored inline), `mknod` /
  `create_socket` (char/block device — raw-kernel-`dev_t` `rdev` — FIFO, socket),
  and hard links (`link` / `link_to`, same- or cross-directory, appending to the
  shared `INODE_REF` and bumping `nlink`), each a COW mini-transaction that keeps
  the directory `i_size`, back-refs, extent tree and free-space tree consistent —
  Linux-interoperable and `btrfs check`-clean.
- Hash-colliding directory names share packed `DIR_ITEM` buckets and are handled
  record-by-record across lookup, create, unlink, rmdir, hard-link, same/cross-dir
  rename, overwrite, and tree-log reconstruction; unrelated collision peers are
  preserved byte-for-byte.
- Both mount entry points: root auto-mount factory (`fs_detect` → `FsType::Btrfs`)
  and `mount -t btrfs`, including `subvolid=N` / `subvol=PATH` (ordinary
  directories and nested subvolumes) to root at a specific subvolume. A plain mount honors the on-disk
  **default subvolume** (`ROOT_TREE_DIR`'s "default" entry).
- `BTRFS_IOC_SUBVOL_GETFLAGS` / `BTRFS_IOC_SUBVOL_SETFLAGS` on an explicitly
  mounted subvolume root, including Linux's distinct `BTRFS_SUBVOL_RDONLY` UAPI
  bit and persistent read-only/writable transitions.
- Legacy `BTRFS_IOC_SUBVOL_CREATE` and `BTRFS_IOC_SUBVOL_CREATE_V2` on a mounted
  directory, including read-only creation. The parent fs tree, new empty child
  tree, UUID index, root refs/backrefs, extent/free-space accounting and
  superblock are committed atomically.
- **Full qgroup quota trees** already enabled on disk: every commit exactly
  recounts referenced/exclusive metadata and data across level-0 roots, then
  propagates union/exclusivity through higher-level parent relations. V2
  subvolume and snapshot creation accept `BTRFS_SUBVOL_QGROUP_INHERIT`, install
  both relation directions and optional limits, and deletion removes the
  level-0 qgroup. `max_rfer` / `max_excl` hard limits reject the transaction
  atomically with `QuotaExceeded` (`EDQUOT`). The quota tree is whole-repacked;
  correctness is preferred over Linux's delayed-ref performance model.
- **Simple quotas** (`QUOTA_CTL_ENABLE_SIMPLE_QUOTA`) use Linux's permanent-owner
  model. Enabling records an `enable_gen`, sets the sticky `SIMPLE_QUOTA`
  incompat bit, creates zero-usage level-0 qgroups, and deliberately does not
  charge pre-enable extents or run a rescan. New data and metadata carry a
  permanent subvolume owner; allocation and final release apply incremental
  signed deltas with referenced and exclusive usage kept equal. Higher-level
  parents receive the sum of their unique level-0 descendants and enforce the
  same hard limits. Shared-root snapshots start at zero usage, auto-inherit the
  destination subvolume's direct parents when no explicit inheritance record is
  supplied, and charge only later private COW allocations. A deleted subvolume's
  nonzero qgroup remains until all extents it permanently owns receive their
  final debit. Disabling removes the quota tree but intentionally preserves the
  incompat bit and on-disk owner refs; a later full-qgroup enable accepts them.
- Quota administration through `BTRFS_IOC_QUOTA_CTL`,
  `QGROUP_CREATE`/`QGROUP_ASSIGN`/`QGROUP_LIMIT`, and
  `QUOTA_RESCAN`/`STATUS`/`WAIT`. Full-mode enable creates level-0 groups for
  every existing subvolume and completes an exact synchronous rescan; simple
  mode reports `SIMPLE_MODE` and rejects rescans, as Linux does. Disabling
  removes and reclaims the complete quota tree. Higher-level group creation,
  bidirectional assignment, limit replacement, unassignment and destruction
  are atomic with accounting updates in either mode.
- Legacy `BTRFS_IOC_SNAP_CREATE` and `BTRFS_IOC_SNAP_CREATE_V2`, including
  writable/read-only snapshots selected by source directory fd. Snapshot
  ancestry is recorded through `parent_uuid`; source data, metadata, UUID/root
  refs and the destination entry commit atomically. A snapshot outside its source
  is an **O(1)-metadata shared-root operation**: both root items name the same
  tree block and the extent tree gains one ordered inline `TREE_BLOCK_REF`;
  descendant metadata and data remain implicit. The first mutation of either side lazily
  materialises a private metadata tree and converts its payload references into
  ordered `EXTENT_DATA_REF`s, so subsequent source/snapshot writes COW
  independently. If the destination directory is inside the source being
  snapshotted, the transaction must also preserve the pre-insertion namespace;
  that edge case atomically rehomes the live source and is O(tree metadata).
- Legacy `BTRFS_IOC_SNAP_DESTROY` and V2 deletion by name or subvolume id.
  The parent namespace, root refs/item, UUID index, checksums, extent tree and
  free-space tree update in one transaction. A still-shared tree is detached by
  dropping only its root ref. The final holder walks and reclaims the old tree;
  shared data loses only the deleted root's backref and is reclaimed with its
  checksum/free space only after the final reference disappears.
  A target that still owns nested subvolumes returns `Busy`/`ENOTEMPTY`; deleting
  those children first and retrying removes the hierarchy bottom-up.
- **statfs** reports total/free blocks (free approximated from the superblock's
  `bytes_used`).

## Not supported (rejected loudly)

Each is rejected with a precise `Unsupported` / `NotFound` / `NoSpace` rather
than mis-read:

- RAID profiles / multi-device — any chunk profile other than SINGLE/DUP, or
  `num_devices != 1`.
- Unknown or unsupported incompat/compat-ro feature flags (including RAID56,
  RAID1C3/4, zoned, extent-tree-v2, stripe-tree, verity and block-group-tree).
- Mutations reached by traversing a child subvolume from its parent (mount that
  child explicitly to write it).
- A symlink target larger than Linux's inline item bound (Btrfs has no regular-
  extent symlink representation); a `rename`/`link` across subvolumes/volumes,
  or a `rename` that overwrites a non-empty-directory target.
- A sectorsize outside 4–64 KiB, or a nodesize that is not a power-of-two in
  `[sectorsize, 64 KiB]`.

## COW writes — full Linux interop

`FileOps::write` supports overwrite, partial write, append and grow of a regular
file in the mounted writable subvolume with **any number of existing extents** (an empty
freshly-`create`d file, a small **inline** file, or a multi-extent file). Each
write closes its sector-aligned byte range over intersected extents, reads and
re-tiles only that window into fresh extents of at most 128 KiB, and frees only
the replaced backing extents. Non-overlapping file items, physical refs and
checksums are preserved, so small random writes no longer scale with the whole
file. Existing intersected full zlib/zstd/LZO extents are decompressed; zlib
windows are recompressed when that reduces their sector-rounded physical size,
while zstd/LZO currently fall back to uncompressed output. Intersected shared or
partial extent references are read, dropped by exact backref identity, and COWed
without reclaiming other roots' data; a read-only or traversal-pinned subvolume
returns `ReadOnly`.
Namespace operations add, remove, link, and re-key files and directories in the
mounted writable subvolume through the same transaction. `unlink` frees all
data extents and checksums when the last link disappears; `rmdir` refuses a
non-empty directory with `Busy`; rename works within or across directories and
atomically replaces supported targets. `create` + `write` therefore compose
into a real new file and `mkdir` + `create` into a populated subdirectory.
Btrfs directories
carry `nlink == 1` (subdirectories are not counted), matching the on-disk
convention.

Each write is a genuine copy-on-write **mini-transaction** that produces a
filesystem a real Linux kernel mounts **read-write** and that `btrfs check`
reports clean — verified end to end (`NARF writes → host mount -o loop reads +
writes → btrfs check "no error found" → both files read back`). Per write it:

1. allocates + writes new data extents and their per-sector selected **data
   checksums** (CRC32C, xxhash64, SHA-256, or BLAKE2b-256; CSUM tree updated,
   old extent's csums removed);
2. path-COWs only the affected fs-tree paths (`EXTENT_DATA` repointed/resized,
   `INODE_ITEM` updated);
3. path-COWs the affected **extent-tree** paths — drops exact old data/metadata
   backrefs, records new data (`EXTENT_DATA_REF`) and metadata
   (`METADATA_ITEM` + `TREE_BLOCK_REF`) refs, and fixes block-group `used`;
4. on a `space_cache=v2` image, repacks the **free-space tree** — marks allocated
   ranges used and returns freed blocks to free space without merging across a
   block-group boundary;
5. repacks the checksum, root, and enabled quota trees as needed, repointing
   changed FS/CSUM/EXTENT/FREE_SPACE/QUOTA `ROOT_ITEM`s and generations;
6. writes a fresh superblock (generation + 1) last, atomically switching.

**Every tree may be any height**, up to `BTRFS_MAX_LEVEL` (8). The fs and extent
trees use path COW, rewriting only touched root-to-leaf paths. The smaller csum,
root, free-space, and enabled quota trees are still read as logical item sets and repacked into
as many `nodesize` leaves and internal levels as needed. The extent tree records
its own new blocks, so the transaction resolves the mutually-dependent extent
and whole-repacked tree block counts with a fixed point, reusing the same
allocation base each round and writing only the converged set.

**Chunk growth** (`write::grow_add_chunk`) allocates one new mixed
(DATA|METADATA, SINGLE) chunk at the end of the device, threading the change
through the chunk tree (new `CHUNK_ITEM` + bumped `DEV_ITEM`), device tree (new
`DEV_EXTENT`), extent tree (new `BLOCK_GROUP_ITEM`), free-space tree, and root
tree in one COW mini-transaction — so a real kernel mounts the grown image
read-write with the extra space and `btrfs check` reports it clean. It uses the
same multi-leaf machinery as `commit_txn`, so it works **even when the
chunk/dev/extent/root/free-space trees are already multi-leaf** (a large or
heavily-churned filesystem): the new chunk-tree blocks are placed in the **system
chunk** (kept reachable via `sys_chunk_array` at mount) while the dev/extent/root/
free-space blocks go at the start of the new chunk, and the extent/free-space leaf
counts are resolved by the same fixed point. Block-group `used` and free-space
accounting are charged **per block group**, so ordinary writes work correctly
across the new chunk boundary once the filesystem spans more than one chunk. Chunk
growth is **auto-triggered**: when a mutation's allocation runs out of chunk space
(`NoSpace`), the write path grows the filesystem by a chunk and retries, so writes
transparently keep succeeding until the device itself is full.

Images with a **free-space tree** (`space_cache=v2`) are supported for writes: the
free-space tree is maintained in lockstep. A block group tracks its free space in
whichever form it already uses — **`FREE_SPACE_EXTENT`** items (one per free
range), or a **`FREE_SPACE_BITMAP`** (one bit per sector, set = free) once btrfs
has converted it because it grew fragmented. Writes into a bitmap group toggle its
bits and recompute the group's `extent_count`; the allocator decodes a bitmap into
free ranges the same as extent items. On such an image **space is reclaimed** —
the allocator carves each new data extent / tree node from the free-space tree's
free ranges (first-fit, lowest address first, skipping *system* block groups,
which are reserved for the chunk tree), so blocks freed by earlier transactions
are reused instead of leaked. Blocks freed by the *current* transaction are not
yet in the tree, so they stay unavailable until it commits — preserving COW.
(Without a free-space tree the allocator falls back to appending past the
extent-tree high-water; freed space is then not reused.)

Mount validates every **superblock copy** that fits, selects the valid copy with
the newest generation (preferring the primary on a tie), and normalizes a
selected mirror before the next transaction so that commit heals a damaged or
stale primary. Every copy is then rewritten on each commit: btrfs keeps up to three
(the primary at 64 KiB, then mirrors at 64 MiB and 256 GiB), and a real kernel
recovers from whichever copy has the newest generation — so on a device large
enough to carry a mirror, all copies must advance together or `btrfs check`
reports a mismatch. `write_superblock` writes each copy that fits within the
filesystem, stamping its own physical `bytenr` and checksum; a grown chunk is
placed clear of the reserved band around each mirror so writing a mirror never
overlaps chunk data. Images large enough to contain the 64 MiB mirror are
therefore writable without leaving superblock copies out of sync.

**fsync / tree-log.** Every mutation is a synchronous commit — it flips the
superblock to a new generation and flushes the device before returning — so a
file's data is durable the moment `write` returns and `FileOps::fsync` only
re-issues a device-flush barrier (there is no deferred transaction to force out).
The **tree-log** is therefore used for crash *recovery*, not deferred durability:
`replay_log` runs once at mount, and if the superblock names an unreplayed log
(`log_root != 0`, as a crash between an fsync and the next commit leaves it) it
preloads every mapped subvolume log, merges each into its own fs tree with
path-COW commits, and zeroes the pointer only after all roots recover. `write_log`
produces such a log — the mounted subvolume's log tree plus the `log_root` tree
mapping `subvolid → log`, in currently-free space (like btrfs's
pinned log extents, deliberately not recorded in the extent/free-space trees) —
so the write+replay round-trip is exercised in-kernel
(`smoke_btrfs_tree_log_replay` and the nested-subvolume replay smoke). Ordinary
logged items are upserted, while modern
`DIR_LOG_INDEX` authoritative ranges replay missing entries through the normal
unlink/rmdir transactions. Logged directory indexes also reconstruct their
hash-keyed `DIR_ITEM` twins; log-only range markers never leak into the FS tree.
Log emission targets the mounted subvolume, and replay applies every
`subvolid -> log` mapping before clearing the superblock pointer. Ordinary
mutations in any writable mounted subvolume remain synchronous full commits and
do not depend on the log for durability.

Bound (fails loudly): trees grow to at most `BTRFS_MAX_LEVEL` (8) levels. Trees
taller than two levels are exercised in-kernel (`smoke_btrfs_tall_tree` writes and
reads back a three-level fs tree); host `btrfs check` in CI covers up to two
levels — a taller tree has the identical on-disk node format, just stacked. The
write-interop guarantee is CI-enforced: `cargo xtask test` runs host `btrfs check`
on the NARF-written image when `btrfs-progs` is available — on a plain image, a
`space_cache=v2` image (including a multi-level fs tree), and a **96 MiB image
carrying the 64 MiB superblock mirror, a bitmap-tracked block group, and an extent
tree it splits multi-leaf and then grows a chunk on top of**.

## Test fixtures

`testdata/fixture.img.sparse` (uncompressed) and the zlib, zstd, and LZO fixtures
are committed, compact (`NARFBTR1`) sparse encodings of small `mkfs.btrfs`
images. They hold the
same tree — `hello.txt` (with a `user.narf` xattr), `big.dat`, `subdir/note.txt`,
`link.txt` (a symlink), and `snap/inside.txt` where `snap` is a nested
subvolume — and exercise uncompressed, zlib, zstd, and LZO read/COW paths.
`fixture-manyfiles.img.sparse` is a separate 32 MiB image of 400 small files
whose FS tree spans multiple b-tree levels.
`fixture-{xxhash,sha256,blake2}.img.sparse` are genuine mkfs images of the same
small tree using each alternate checksum algorithm; they exercise verified
mounts, COW writes, tree-log replay, remounts, and algorithm-specific CSUM item
widths.
`fixture-nestedsubvol.img.sparse` has a normal directory followed by nested
subvolumes (`container/outer/inner`) for multi-component `subvol=` mounts plus a
read-only sibling used to verify root flags and mutation rejection.
`fixture-defaultsubvol.img.sparse` verifies that a plain mount honours the
root-tree `default` entry. `fixture-laptop.img.sparse` covers a realistic
non-mixed, 16 KiB-node, zstd-compressed distro layout with `root` and `home`
subvolumes and current btrfs-progs default features.
`fixture-sector8k.img.sparse` is a genuine 8 KiB-sector/node image used for
cross-sector reads, partial COW writes, remount, and checksum verification.
`fixture-quota.img.sparse` is a Linux-created full-qgroup image with level-0
`0/5` assigned to `1/100`; tests cover recounting, V2 create/snapshot
inheritance, hierarchy relations, hard-limit `EDQUOT`, and lifecycle cleanup.
`fixture-squota.img.sparse` is a Linux-created simple-quota image with
post-enable data carrying an `EXTENT_OWNER_REF` and `0/5` assigned to `1/200`.
Tests cover Linux-image compatibility, incremental owner accounting, hierarchy
propagation, destination-parent inheritance, shared-root snapshot isolation,
orphan-owner final debits, hard-limit atomicity, remount durability, disable
semantics, and transition back to full qgroups.
The ordinary no-quota fixture also exercises the complete quota administration
lifecycle in both modes: enable, full-mode rescan, create/assign/limit,
unassign/destroy, disable, and remount.
`fixture-fst.img.sparse` is the same small layout as `fixture.img.sparse` but with
a **free-space tree** (`space_cache=v2`), exercising the write path's free-space-
tree maintenance. `fixture-mirror.img.sparse` is a **96 MiB** mixed + free-space-
tree image — large enough that mkfs wrote the **64 MiB superblock mirror** — used
to exercise updating every superblock copy in lockstep (mounted read-write over a
writable sparse-backed device so it costs only its payload in RAM).
`fixture-bitmap.img.sparse` is the same 96 MiB layout with one data block group
deliberately **fragmented** (via a loop mount) so its free space is a
`FREE_SPACE_BITMAP`; it is also the boot smoke's NVMe image, so host `btrfs check`
validates the bitmap path end to end. The kernel tests reconstruct the full
zero-filled image at runtime and mount it under a `RamBlockDevice`.

Regenerate with `testdata/regen_fixture.sh` (needs `mkfs.btrfs` + `btrfs`).
Pinned so the layout can't silently drift:

```
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
           -O ^free-space-tree,^no-holes --rootdir <staging> <image>
```

btrfs-progs pinned at **v6.17.1** (update `regen_fixture.sh`'s header if you
regenerate with a newer one). The parser rejects every assumption it cannot
meet, so a drifted mkfs default fails loudly rather than mis-reading.

Run the tests with `cargo xtask test --subsystem drivers/fs/btrfs`.
