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
  **extended attributes** (`get_xattr` / `list_xattr` over `XATTR_ITEM`), and
  **statx** (size/mode/uid/gid/nlink/ino/mtime).
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
- **Namespace mutations**: `create` (new empty regular file), `unlink` (of an
  unshared regular file, freeing its data extent + checksums), `mkdir` (new empty
  directory), `rmdir` (of an empty directory), `rename` (same- or
  cross-directory, of a file or directory, atomically replacing an existing target
  — freeing a clobbered file's data + checksums, and refusing to move a directory
  into its own subtree), `symlink` (target stored inline), and `mknod` /
  `create_socket` (char/block device — raw-kernel-`dev_t` `rdev` — FIFO, socket),
  each a COW mini-transaction that keeps the directory `i_size`, back-refs, extent
  tree and free-space tree consistent — Linux-interoperable and `btrfs check`-clean.
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
  xattr *writes*; multi-component `subvol=a/b` paths.
- Hard-link creation; a symlink target `>= sectorsize`; a `rename` across
  subvolumes/volumes, or one that overwrites a hardlinked or non-empty-directory
  target; `unlink` of a hardlinked inode (`nlink > 1`) or a name in a
  hash-colliding `DIR_ITEM`; `rmdir` of a directory carrying xattrs.
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

Because the extent leaf must record its own new block, this is only tractable
when the fs/csum/root/extent (and free-space, if present) trees are each a
**single leaf** (a fresh small image); larger allocations are pre-computed so the
transaction is closed-form, sidestepping the delayed-ref loop real btrfs uses.

Images with a **free-space tree** (`space_cache=v2`) are supported for writes: the
free-space tree leaf is maintained in lockstep (extent-mode tracking only). Bounds
(all fail loudly): single-leaf trees only, **no node splitting** (`NoSpace` on a
full leaf), no new-chunk allocation, no space reclaim (freed logical addresses
aren't reused), a `FREE_SPACE_BITMAP` block group is out of scope, and a **64 MiB
superblock mirror** is out of scope for writes (so the 128 MiB laptop-scale
fixture is read-only). The write-interop guarantee is CI-enforced: `cargo xtask
test` runs host `btrfs check` on the NARF-written image when `btrfs-progs` is
available — on both a plain and a `space_cache=v2` image.

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
tree maintenance. The kernel tests reconstruct the full zero-filled image at
runtime and mount it under a `RamBlockDevice`.

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
