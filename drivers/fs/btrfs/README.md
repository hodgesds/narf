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

- Single-device volumes, **SINGLE** and **DUP** chunk profiles.
- **CRC32C** checksums, verified on the superblock and every tree node.
- Chunk-tree logical→physical mapping (`sys_chunk_array` seed + chunk-tree walk).
- The default `FS_TREE` subvolume: directory `lookup` (CRC32C name hash) and
  `readdir` (`DIR_INDEX`), inode stat.
- File reads: **inline**, **regular**, and **zlib/zstd/LZO-compressed** extents
  (LZO via a native port of the kernel's `lzo1x_decompress_safe` plus btrfs's
  sector-segmented framing); holes and preallocated ranges read as zeros (both
  explicit-hole and `no-holes` layouts).
- **Symlinks** (target read via `FileOps::read`, so the VFS follows them),
  **extended attributes** (read via `get_xattr` / `list_xattr` and written via
  `set_xattr` / `remove_xattr` over `XATTR_ITEM`, honouring
  `XATTR_CREATE`/`XATTR_REPLACE`), and **statx** (size/mode/uid/gid/nlink/ino/mtime).
- **Nested subvolumes** (read-only): a `ROOT_ITEM` directory entry is resolved
  through the root tree and entered at its own fs tree, so subvolumes and
  snapshots are navigable.
- **Hardlinks** (shared inode number + `nlink`) and **special files**
  (char/block device nodes and FIFOs, typed via mode; `rdev` decoded into
  statx `rdev_major`/`rdev_minor`).
- **COW writes** (overwrite / partial / append / grow of an uncompressed
  single-extent file) that are **fully Linux-interoperable**: the resulting
  filesystem mounts read-write on a real kernel and passes `btrfs check` — see
  below.
- **Namespace mutations**: `create` (new empty regular file), `unlink` (freeing a
  file's data extent + checksums on its last link, else just decrementing
  `nlink`), `mkdir` (new empty
  directory), `rmdir` (of an empty directory), `rename` (same- or
  cross-directory, of a file or directory, atomically replacing an existing target
  — freeing a clobbered file's data + checksums, and refusing to move a directory
  into its own subtree), `symlink` (target stored inline), `mknod` /
  `create_socket` (char/block device — raw-kernel-`dev_t` `rdev` — FIFO, socket),
  and hard links (`link` / `link_to`, same- or cross-directory, appending to the
  shared `INODE_REF` and bumping `nlink`), each a COW mini-transaction that keeps
  the directory `i_size`, back-refs, extent tree and free-space tree consistent —
  Linux-interoperable and `btrfs check`-clean.
- Both mount entry points: root auto-mount factory (`fs_detect` → `FsType::Btrfs`)
  and `mount -t btrfs`, including `subvolid=N` / `subvol=NAME` (single-component
  name) to root at a specific subvolume. A plain mount honors the on-disk
  **default subvolume** (`ROOT_TREE_DIR`'s "default" entry).
- **statfs** reports total/free blocks (free approximated from the superblock's
  `bytes_used`).

## Not supported (rejected loudly)

Each is rejected with a precise `Unsupported` / `NotFound` / `NoSpace` rather
than mis-read:

- RAID profiles / multi-device — any chunk profile other than SINGLE/DUP, or
  `num_devices != 1`.
- Non-CRC32C checksums (xxhash/sha256/blake2).
- Writes into a nested subvolume (only the default subvolume is writable);
  multi-component `subvol=a/b` paths.
- A symlink target `>= sectorsize`; a `rename`/`link` across subvolumes/volumes,
  or a `rename` that overwrites a hardlinked or non-empty-directory target; any
  name in a hash-colliding `DIR_ITEM`; `rmdir` of a directory carrying xattrs.
- `sectorsize != 4096` or a `nodesize` that is not a power-of-two ≥ sectorsize.

## COW writes — full Linux interop

`FileOps::write` supports overwrite, partial write, append and grow of a regular,
uncompressed file in the default subvolume that is either **empty** (e.g. freshly
`create`d — the write allocates its first data extent) or a single-`EXTENT_DATA`
file (inline, compressed or multi-extent files, and nested-subvolume writes
return `Unsupported` / `ReadOnly`). `DirOps::create` / `unlink` / `mkdir` /
`rmdir` / `rename` add, remove and re-key regular files and empty directories in
the default subvolume through the same transaction (`unlink` frees the file's
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

1. allocates + writes a new data extent and its per-sector CRC32C **data
   checksums** (CSUM tree updated, old extent's csums removed);
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

**Every tree may be multi-leaf** — the fs, extent, csum, root and free-space trees
are each read into one logical leaf, edited, then re-packed into as many real
`nodesize` leaves as needed under an internal root, so a file / directory / extent
/ checksum set can outgrow a single leaf, as it does on a laptop-scale root
(`btrfs check` validates the split trees). The extent tree records its own new
blocks (a self-reference), so how many leaves it and the free-space tree need
depends on the block count they produce; the commit resolves this with a **fixed
point** over the leaf counts — re-handing-out node addresses from the same base
each round until they stabilise, then writing only the converged set. This
replaces the delayed-ref loop real btrfs uses and keeps the transaction
closed-form.

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
free-space tree leaf is maintained in lockstep (extent-mode tracking only).

Every **superblock copy** is rewritten on each commit: btrfs keeps up to three
(the primary at 64 KiB, then mirrors at 64 MiB and 256 GiB), and a real kernel
recovers from whichever copy has the newest generation — so on a device large
enough to carry a mirror, all copies must advance together or `btrfs check`
reports a mismatch. `write_superblock` writes each copy that fits within the
filesystem, stamping its own physical `bytenr` and checksum; a grown chunk is
placed clear of the reserved band around each mirror so writing a mirror never
overlaps chunk data. A ≥64 MiB image is therefore fully writable.

Bounds (all fail loudly): each tree grows to at most **two levels** (a third →
`NoSpace`); no space reclaim (freed logical addresses aren't reused); and a
`FREE_SPACE_BITMAP` block group is out of scope. The write-interop guarantee is
CI-enforced: `cargo xtask test` runs host `btrfs check` on the NARF-written image
when `btrfs-progs` is available — on a plain image, a `space_cache=v2` image
(including a multi-level fs tree), and a **96 MiB image carrying the 64 MiB
superblock mirror whose extent tree it splits multi-leaf and then grows a chunk
on top of**.

## Test fixtures

`testdata/fixture.img.sparse` (uncompressed) and `testdata/fixture-zlib.img.sparse`
(`--compress zlib`) are committed, compact (`NARFBTR1`) sparse encodings of small
`mkfs.btrfs` images (a 16 MiB image is ~90 KiB of non-zero data). Both hold the
same tree — `hello.txt` (with a `user.narf` xattr), `big.dat`, `subdir/note.txt`,
`link.txt` (a symlink), and `snap/inside.txt` where `snap` is a nested
subvolume. `fixture-manyfiles.img.sparse` is a separate 32 MiB image of 400
small files whose FS tree spans multiple b-tree levels.
`fixture-fst.img.sparse` is the same small layout as `fixture.img.sparse` but with
a **free-space tree** (`space_cache=v2`), exercising the write path's free-space-
tree maintenance. `fixture-mirror.img.sparse` is a **96 MiB** mixed + free-space-
tree image — large enough that mkfs wrote the **64 MiB superblock mirror** — used
to exercise updating every superblock copy in lockstep (mounted read-write over a
writable sparse-backed device so it costs only its payload in RAM). The kernel
tests reconstruct the full zero-filled image at runtime and mount it under a
`RamBlockDevice`.

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
