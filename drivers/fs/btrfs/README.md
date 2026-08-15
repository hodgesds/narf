# narf-drivers-fs-btrfs

A partial btrfs driver: read-only mount / `ls` / `cat`, plus a narrowly-scoped
basic copy-on-write file overwrite. On-disk structures are decoded per the
authoritative kernel definitions in
`/usr/src/linux/include/uapi/linux/btrfs_tree.h`; this is an independent Rust
implementation (no C is copied).

Verified against a **realistic laptop-distro image** (`fixture-laptop`): non-mixed
block groups, `nodesize 16384`, btrfs-progs default features (free-space-tree /
`space_cache=v2`, `no-holes`, `extref`, skinny/big metadata), zstd, and a
Fedora/openSUSE-style `root` (default) + `home` subvolume layout — i.e. what a
real laptop's btrfs root looks like.

## Supported

- Single-device volumes, **SINGLE** and **DUP** chunk profiles. Both DUP copies
  are retained: metadata and checksummed data retry the second stripe after an
  I/O error or checksum failure.
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
- **Symlinks** (target read via `FileOps::read`, so the VFS follows them),
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
  **fully Linux-interoperable**: the
  resulting filesystem mounts read-write on a real kernel and passes `btrfs check`
  — see below.
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
- Legacy `BTRFS_IOC_SNAP_CREATE` and `BTRFS_IOC_SNAP_CREATE_V2`, including
  writable/read-only snapshots selected by source directory fd. Snapshot
  ancestry is recorded through `parent_uuid`; source data, metadata, UUID/root
  refs and the destination entry commit atomically. Until shared delayed refs
  land, snapshot creation eagerly gives every disk extent private storage, so
  source and snapshot are independently writable but creation is O(tree + data)
  rather than the usual O(1) shared-root operation.
- Legacy `BTRFS_IOC_SNAP_DESTROY` and V2 deletion by name or subvolume id.
  The parent namespace, root refs/item, UUID index, checksums, extent tree and
  free-space tree update in one transaction. Every child metadata/data extent
  is proven exclusive before reclamation; an externally shared snapshot is
  rejected until shared delayed refs are supported.
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
  child explicitly to write it). Snapshot creation or deletion of a child that
  itself contains nested subvolume mount points is not yet supported.
  `SUBVOL_CREATE_V2` / `SNAP_CREATE_V2` qgroup inheritance is not supported.
- A symlink target `>= sectorsize`; a `rename`/`link` across subvolumes/volumes,
  or a `rename` that overwrites a non-empty-directory target.
- `sectorsize != 4096` or a `nodesize` that is not a power-of-two ≥ sectorsize.

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
while zstd/LZO currently fall back to uncompressed output. An intersected disk
extent must be exclusively and wholly owned; an intersected **shared/partial**
extent returns `Unsupported`; a read-only or traversal-pinned subvolume returns
`ReadOnly`.
`DirOps::create` / `unlink` / `mkdir` /
`rmdir` / `rename` add, remove and re-key regular files and empty directories in
the mounted writable subvolume through the same transaction (`unlink` frees the file's
data extent + checksums when its last link goes away; `rmdir` refuses a non-empty
directory with `Busy`; same-directory `rename` re-keys a file or directory to a
free name, refusing overwrite), so `create` + `write` compose into a real new
file and `mkdir` + `create` into a populated subdirectory. btrfs directories
carry `nlink == 1` (subdirectories are not counted), matching the on-disk
convention.

Each write is a genuine copy-on-write **mini-transaction** that produces a
filesystem a real Linux kernel mounts **read-write** and that `btrfs check`
reports clean — verified end to end (`NARF writes → host mount -o loop reads +
writes → btrfs check "no error found" → both files read back`). Per write it:

1. allocates + writes a new data extent and its per-sector selected **data
   checksums** (CRC32C, xxhash64, SHA-256, or BLAKE2b-256; CSUM tree updated,
   old extent's csums removed);
2. rebuilds the fs leaf (`EXTENT_DATA` repointed/resized, `INODE_ITEM` updated);
3. rebuilds the **extent tree** leaf — frees the old data extent + old COWed
   metadata blocks, records the new data extent (`EXTENT_DATA_REF`) and every new
   metadata block (skinny `METADATA_ITEM` + `TREE_BLOCK_REF`), and fixes the block
   group's `used`;
4. on a `space_cache=v2` image, rebuilds the **free-space tree** leaf — marks the
   new extent's range used and returns the freed blocks to free space, merging
   with neighbours but never across a block-group boundary;
5. rebuilds the root leaf (FS/CSUM/EXTENT/FREE_SPACE `ROOT_ITEM`s repointed, incl.
   generation);
6. writes a fresh superblock (generation + 1) last, atomically switching.

**Every tree may be any height** — the fs, extent, csum, root and free-space trees
are each read into one logical leaf, edited, then re-packed into as many real
`nodesize` leaves as needed, with internal nodes stacked over them level by level
up to a single root of arbitrary height (`BTRFS_MAX_LEVEL` = 8), so a file /
directory / extent / checksum set can outgrow a single leaf — or a single internal
node — as it does on a laptop-scale root (`btrfs check` validates the split
trees). The extent tree records its own new blocks (a self-reference), so how many
leaves it and the free-space tree need depends on the block count they produce;
the commit resolves this with a **fixed point** over the leaf counts — re-handing-
out node addresses from the same base each round until they stabilise, then
writing only the converged set. This replaces the delayed-ref loop real btrfs uses
and keeps the transaction closed-form.

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
overlaps chunk data. A ≥64 MiB image is therefore fully writable.

**fsync / tree-log.** Every mutation is a synchronous commit — it flips the
superblock to a new generation and flushes the device before returning — so a
file's data is durable the moment `write` returns and `FileOps::fsync` only
re-issues a device-flush barrier (there is no deferred transaction to force out).
The **tree-log** is therefore used for crash *recovery*, not deferred durability:
`replay_log` runs once at mount, and if the superblock names an unreplayed log
(`log_root != 0`, as a crash between an fsync and the next commit leaves it) it
merges the log's items into the fs tree in one path-COW commit and zeroes the
pointer. `write_log` produces such a log — the subvolume's log tree plus the
`log_root` tree mapping `FS_TREE → log`, in currently-free space (like btrfs's
pinned log extents, deliberately not recorded in the extent/free-space trees) —
so the write+replay round-trip is exercised in-kernel
(`smoke_btrfs_tree_log_replay`). Ordinary logged items are upserted, while modern
`DIR_LOG_INDEX` authoritative ranges replay missing entries through the normal
unlink/rmdir transactions. Logged directory indexes also reconstruct their
hash-keyed `DIR_ITEM` twins; log-only range markers never leak into the FS tree.
Log emission/replay remains scoped to the top-level FS tree; ordinary mutations
in an explicitly mounted subvolume are synchronous full commits and need no log.

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

`testdata/fixture.img.sparse` (uncompressed) and `testdata/fixture-zlib.img.sparse`
(`--compress zlib`) are committed, compact (`NARFBTR1`) sparse encodings of small
`mkfs.btrfs` images (a 16 MiB image is ~90 KiB of non-zero data). Both hold the
same tree — `hello.txt` (with a `user.narf` xattr), `big.dat`, `subdir/note.txt`,
`link.txt` (a symlink), and `snap/inside.txt` where `snap` is a nested
subvolume. `fixture-manyfiles.img.sparse` is a separate 32 MiB image of 400
small files whose FS tree spans multiple b-tree levels.
`fixture-{xxhash,sha256,blake2}.img.sparse` are genuine mkfs images of the same
small tree using each alternate checksum algorithm; they exercise verified
mounts, COW writes, tree-log replay, remounts, and algorithm-specific CSUM item
widths.
`fixture-nestedsubvol.img.sparse` has a normal directory followed by nested
subvolumes (`container/outer/inner`) for multi-component `subvol=` mounts plus a
read-only sibling used to verify root flags and mutation rejection.
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
