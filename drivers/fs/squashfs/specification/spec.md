# Specification: SquashFS Filesystem Driver

## 1. Purpose & scope

Provide Linux-compatible, read-only access to SquashFS 4.0 block images for
immutable roots, recovery media, and appliance/container images.

In scope: bounded superblock and table validation, compact and extended
inodes, directories, regular files, sparse blocks, fragments, symlinks,
special inode metadata, ID lookup, xattrs, stat/statx/statfs, root
auto-detection, and classic Linux mount dispatch. Writes and image authoring
are out of scope because SquashFS is an offline-authored read-only format.

## 2. Assumptions

- The backing `BlockDevice` has a power-of-two 512..=4096-byte logical block.
- SquashFS is version 4.0 and little-endian.
- Paths exposed to NARF are valid UTF-8; an image containing a non-UTF-8
  directory name is rejected when that directory is read.
- The filesystem compressor is zlib or LZ4. Other valid compressor IDs are
  rejected with `FsError::Unsupported` before the mount is published.

## 3. Public interface

- `SquashfsVolume<B: BlockDevice>::mount(device, domain)` validates and mounts
  one volume and implements `narf_filesystem::FsInstance`.
- `SquashfsNode<B>` implements both `FileOps` and `DirOps` for decoded inodes.
- `mount_squashfs(authority, path, device, domain)` attaches a mounted volume.
- `register_initcalls()` registers `FsType::SquashFs` with the root-mount
  factory and registers the `squashfs` classic mount builder.

The implementation does not add or alter a VFS trait.

## 4. Invariants

- Every on-disk addition and multiplication is checked before indexing or I/O.
- No read crosses `s_bytes_used`, and `s_bytes_used` cannot exceed device
  capacity.
- Metadata decompression is capped at 8192 bytes and data decompression at the
  validated filesystem block size (maximum 1 MiB).
- Metadata cursors can advance only through validated non-empty blocks.
- ID, fragment, and xattr index pointers must be monotonic and precede their
  uncompressed index table.
- Root mount is published only after the root inode decodes as a directory.
- Every mutating file/directory operation that can report an error returns
  `FsError::ReadOnly`.
- One async mutex serializes use of the per-volume registered DMA buffer; no
  IRQ-safe spinlock is held across block I/O.

## 5. Architecture notes

The codec is architecture-neutral and uses explicit little-endian field
decoding. Both x86_64 and aarch64 use the same cap-bound block I/O and bounded
decompression path. LZ4 reuses NARF's no_std bounded block decoder; zlib uses
the pure-Rust no_std `miniz_oxide` allocator API with an output limit.

## 6. Dependencies

`narf-block`, `narf-filesystem`, `narf-io`, `narf-capabilities`,
`narf-driver-runtime`, `narf-scheduler`, `narf-memory` (LZ4 decoder), and
`miniz_oxide` (zlib decoder).

## 7. Stage assignment

Stage 4 Compatibility. SquashFS is a common Linux immutable-root and live
image format and uses the existing Stage-4 block/VFS surfaces.

## 8. Open questions

- Add bounded no_std XZ and Zstandard decoders when suitable dependencies are
  accepted for the kernel workspace.
- Add a fixture authored by an xattr-enabled squashfs-tools build; the local
  4.6.1 tool used for the current fixture was compiled without xattr support.
- NARF's VFS is UTF-8, while Linux SquashFS preserves arbitrary filename
  bytes. A future byte-path compatibility layer could avoid rejecting those
  names.
