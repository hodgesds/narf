# SquashFS Linux compatibility audit

Audited against `origin/main` `ba89584b16c17500b84608dda90734a4de64b5df`
and Linux `/usr/src/linux` `9bd577abc6fc`.

## Call-chain and reference method

Semcode MCP resolved the existing NARF chain as:

```text
detect_filesystem (block/src/fs_detect.rs)
  <- try_mount_root_with (filesystem/src/root_mount.rs)
  -> is_squashfs
```

It also traced `ext_factory` and `sys_mount` to establish the two integration
paths used by existing block filesystems. The audit found SquashFS magic
detection and `FsType::SquashFs` already present, but no driver crate, root
factory, classic mount builder, or VFS tests. The implementation fills those
gaps without changing a VFS trait.

Linux call chains used as the primary behavioral reference:

- `squashfs_fill_super` (`super.c`) for version, size, root, compressor and
  table validation, plus Linux `statfs` values.
- `squashfs_read_data`/`squashfs_read_metadata` (`block.c`) for the two-byte
  metadata header and bounded decompression.
- `squashfs_read_inode` (`inode.c`) for all compact/extended inode layouts,
  ID resolution, fragment rules, sparse accounting, symlinks and devices.
- `squashfs_readdir` (`dir.c`) for header count bounds, signed inode-number
  deltas, name lengths and directory-entry types.
- `squashfs_readpage_block` (`file.c`) and `squashfs_frag_lookup`
  (`fragment.c`) for contiguous compressed data blocks, holes and packed
  tails.
- `squashfs_get_id`, `squashfs_xattr_lookup`, and `squashfs_xattr_get`
  (`id.c`, `xattr_id.c`, `xattr.c`) for owner and xattr indirection.

## Compatibility matrix

| Surface | Linux behavior | NARF result |
|---|---|---|
| Superblock/version | magic `hsqs`, version 4.0, block/log/root bounds | Implemented with checked device/`bytes_used` bounds |
| Metadata streams | 8 KiB blocks, compressed or raw, records may cross blocks | Implemented; zero/oversize/truncated blocks rejected |
| Inodes | compact + extended file, dir, link, device, FIFO, socket | Implemented |
| Directories | 1..=256 entries/header, signed inode delta, 256-byte names | Implemented; optional indexes validated/skipped |
| Data blocks | contiguous compressed extents, raw bit, sparse zero block | Implemented |
| Fragments | indexed packed tail blocks | Implemented |
| Symlinks | target inline in inode metadata | Implemented, 4096-byte Linux page-size bound |
| UID/GID | 16-bit index into compressed u32 ID table | Implemented |
| xattrs | user/trusted/security, inline and out-of-line values | Implemented read/list; writes return read-only |
| stat/statx | stable inode, mode, owners, nlink, mtime, rdev | Implemented; wall time preserved through statx |
| statfs | used blocks rounded by fs block, zero free, inode count, name 256 | Implemented |
| Mutations | read-only filesystem (`EROFS`) | All fallible mutation hooks return `FsError::ReadOnly` |
| zlib | common squashfs-tools default | Implemented with bounded no_std decoder |
| LZ4 legacy | options record version 1 and raw LZ4 blocks | Implemented with bounded NARF LZ4 decoder |
| LZMA/LZO/XZ/Zstd | valid format compressor IDs | Rejected at mount as `Unsupported`; never misdecoded |
| Export lookup table | optional NFS inode lookup acceleration | Tolerated; not consumed |
| Arbitrary byte names | Linux preserves non-UTF-8 names | Explicit gap: rejected by NARF's UTF-8 VFS boundary |
| Mount options | `errors=`, decompressor thread selection | `ro`, `errors=continue`, `threads=single`; other claims rejected |

## Verification

The checked-in fixture is produced by Linux squashfs-tools 4.6.1 and inspected
with `unsquashfs`. It covers compressed metadata/data/fragments and IDs,
nested directories, symlink, FIFO, sparse multi-block data and fragment tails.
Kernel tests mount it on `RamBlockDevice`, traverse/read it, verify metadata,
statx/statfs and read-only errors, then mutate copies to exercise corrupt
magic, version/log, device bounds, root references, metadata headers, and an
unsupported compressor.

The fixture-authoring tool available in this environment has only gzip and was
built without xattrs. LZ4's shared block decoder already has independent NARF
kernel tests; a generated LZ4/xattr SquashFS image remains a recorded coverage
gap rather than a false claim.
