# narf-drivers-fs-btrfs

A partial btrfs driver: read-only mount / `ls` / `cat`, plus a narrowly-scoped
basic copy-on-write file overwrite. On-disk structures are decoded per the
authoritative kernel definitions in
`/usr/src/linux/include/uapi/linux/btrfs_tree.h`; this is an independent Rust
implementation (no C is copied).

## Supported

- Single-device volumes, **SINGLE** and **DUP** chunk profiles.
- **CRC32C** checksums, verified on the superblock and every tree node.
- Chunk-tree logical→physical mapping (`sys_chunk_array` seed + chunk-tree walk).
- The default `FS_TREE` subvolume: directory `lookup` (CRC32C name hash) and
  `readdir` (`DIR_INDEX`), inode stat.
- File reads: **inline**, **regular**, and **zlib/zstd-compressed** extents; holes
  and preallocated ranges read as zeros (both explicit-hole and `no-holes`
  layouts).
- **Symlinks** (target read via `FileOps::read`, so the VFS follows them),
  **extended attributes** (`get_xattr` / `list_xattr` over `XATTR_ITEM`), and
  **statx** (size/mode/uid/gid/nlink/ino/mtime).
- Basic **COW write**: a full, same-size overwrite of an existing uncompressed
  single-regular-extent file — see below.
- Both mount entry points: root auto-mount factory (`fs_detect` → `FsType::Btrfs`)
  and `mount -t btrfs`.

## Not supported (rejected loudly)

Each is rejected with a precise `Unsupported` / `NotFound` / `NoSpace` rather
than mis-read:

- LZO compression — `EXTENT_DATA.compression == 2` (zlib and zstd are
  supported).
- RAID profiles / multi-device — any chunk profile other than SINGLE/DUP, or
  `num_devices != 1`.
- Non-CRC32C checksums (xxhash/sha256/blake2).
- Subvolumes / snapshots beyond the default `FS_TREE`; xattr *writes*.
- `sectorsize != 4096` or a `nodesize` that is not a power-of-two ≥ sectorsize.

## Basic COW write — scope and limits

`FileOps::write` supports only a **full, same-size overwrite** (offset 0,
`len == size`) of an existing regular, uncompressed, single-extent file; every
other write (partial, append, grow/shrink, inline file, compressed, multi-extent)
returns `ReadOnly` / `Unsupported`.

The write is genuine copy-on-write: a fresh data extent is allocated above the
extent-tree high-water mark, the fs tree and root tree are COWed (old nodes left
byte-for-byte intact on disk), and a new superblock (generation + 1) is written
last to switch atomically. This driver can therefore remount its own image and
read the new data back.

Deliberate limitations of this "basic" path (it is **not** written for interop
with a live Linux kernel):

- No new-chunk allocation — a full covering chunk yields `NoSpace`.
- The **extent tree** and **csum tree** are not updated, so the new extent is
  unaccounted and carries no data checksum. NARF does not verify data checksums
  on read, so read-back is correct; a Linux kernel that verifies data csums
  would not.

## Test fixtures

`testdata/fixture.img.sparse` (uncompressed) and `testdata/fixture-zlib.img.sparse`
(`--compress zlib`) are committed, compact (`NARFBTR1`) sparse encodings of small
`mkfs.btrfs` images (a 16 MiB image is ~90 KiB of non-zero data). Both hold the
same tree — `hello.txt` (with a `user.narf` xattr), `big.dat`, `subdir/note.txt`,
and `link.txt` (a symlink). The kernel tests reconstruct the full zero-filled
image at runtime and mount it under a `RamBlockDevice`.

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
