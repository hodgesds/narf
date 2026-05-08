# Specification: ISO 9660 Filesystem Driver

## 1. Purpose & scope

This driver provides a clean-room implementation of the ISO 9660 (ECMA-119) filesystem standard for NARF.

- **Scope:** Read-only access to ISO 9660 volumes, support for Joliet and Rock Ridge extensions, integration with NARF VFS.
- **Out of Scope:** Multi-session discs (initial implementation), CD-audio, UDF support (separate driver).

## 2. Assumptions

- Underlying block device provides `BlockCap` with 2048-byte sector support (standard for ISO 9660).
- The system recognizes the "CD001" signature at sector 16.

## 3. Public interface

The driver implements `narf_filesystem::FsInstance`, with per-node `FileOps` and `DirOps`.

### Key Structs

- `Iso9660Volume<B: BlockDevice>`: mounted volume, owns the cached
  PVD, `DomainId`, and the per-mount registered DMA scratch buffer.
  Constructed via `Iso9660Volume::mount(device, domain) -> Arc<Self>`.
- `Iso9660Node<B: BlockDevice>`: combined file/dir node returned by
  `root()` / `lookup_async` / `lookup_dir_async`. Carries the
  on-disc extent LBA + length plus the cached `Stat`.

### DMA / cap-bound I/O

A single `Cap<DmaBuffer, Write>` is minted at `mount()` via
`narf_io::register_with_cap` and stored on the volume. Every
sector op derives a `Read` cap from it (no `Cap::bootstrap()` in
hot paths). Sector size is fixed at 2048 (ECMA-119 §6.1.2); the
driver requires the underlying `BlockDevice::logical_block_size()`
to be 2048 and rejects the mount with `FsError::Unsupported`
otherwise.

## 4. Invariants

- **Read-Only:** All mutation operations (write, create, unlink) return `FsError::ReadOnly` or `Unsupported`.
- **Descriptor Sequence:** The driver must correctly follow the Volume Descriptor sequence until the Volume Descriptor Set Terminator is reached.

## 5. Architecture notes

- **Async-First:** Leverages NARF's async I/O for non-blocking directory traversal.
- **Contiguous extents (§6.5.1, §7.6.3):** Files are laid out as a
  single contiguous run of logical sectors starting at
  `extent_location`; byte position = `extent_lba * 2048 + offset`.
  No FAT-style cluster chains, no multi-extent fragmentation
  decoding in the first wave (the multi-extent flag is recognised
  but extra extents beyond the first are not followed yet).
- **Directory walk (§9.1.1):** Records never cross a sector
  boundary. A `length == 0` byte means "skip to the next sector".

## 5a. Deferred extensions

- **Joliet (Microsoft SVD):** SVD sectors are tolerated during the
  descriptor walk but not parsed. Long names + Unicode are reported
  via the PVD's 8.3 form for now.
- **Rock Ridge (IEEE P1282):** System Use fields (`SP`, `NM`, `PX`,
  `SL`, …) are not parsed. POSIX-shaped names, owners, permissions,
  and symlinks remain on the deferred list.
- **El Torito boot record:** Type-0 descriptors are skipped. Boot
  loaders consume the boot catalogue out-of-band.
- **Multi-session / multi-extent:** Single-session, single-extent
  files only. The `MULTI_EXTENT` flag is recognised in `flags::`
  but the second + later extents are not followed.

## 6. Dependencies

- `narf-block`: For block I/O.
- `narf-filesystem`: For VFS traits.
- `narf-lib`: For base primitives.

## 7. Stage assignment

- **Stage 4:** Necessary for bootable installer media.

## 8. Open questions

- **Suspense (Rock Ridge):** Should we implement full RRIP parsing in the first wave? (Target: basic RRIP support for filenames).

## References

This implementation is derived solely from the following public documentation:

1. [ECMA-119 Standard (ISO 9660)](https://www.ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf)
2. [OSDev Wiki: ISO 9660](https://wiki.osdev.org/ISO_9660)
