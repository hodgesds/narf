# Specification: ext2 Filesystem Driver

## 1. Purpose & scope

A clean-room implementation of the Second Extended Filesystem (ext2) for
NARF.

- **Scope:** Read/write access to ext2 volumes, integration with NARF's VFS
  (`narf_filesystem::FsInstance`), persistent inode data/mode/owner metadata,
  directory mutation, symlinks, and cap-bound DMA block I/O via `narf_io` +
  `narf_block`. Ext4 volumes with `metadata_csum` / `csum_seed` are accepted
  after their superblock CRC32C is verified. Clean volumes whose write-side
  feature set is supported mount read/write; inode, classic-directory,
  bitmap, group-descriptor, HTREE, and primary-superblock mutations regenerate
  the corresponding CRC32C before returning.
- **Out of Scope (this iteration):** journal writes (ext3+), HTREE leaf
  splitting/rebalancing and multi-level insertion, extended attributes,
  `fsck`-style repair, and
  extents-tree writes.

## 2. Assumptions

- The underlying block device exposes a `BlockDevice` whose
  `logical_block_size()` divides 1024. (The ext2 superblock starts at
  byte 1024; with a 512-byte LBS the superblock sits at LBA 2; with a
  1024-byte or 4096-byte LBS it sits at LBA 1 or LBA 0 respectively.)
- The VFS wrapper handles path resolution and capability derivation.
- Memory for metadata + data buffers comes from heap `Vec<u8>` slices
  copied through the volume's registered cap-bound `DmaBuffer`.

## 3. Public interface

The driver implements `narf_filesystem::FsInstance` for `Ext2Volume`.
Per-node ops live on `Ext2Node`, which implements both `FileOps` and
`DirOps`.

### Key Structs

- `Ext2Volume<B: BlockDevice>`: Root structure for a mounted volume.
- `Ext2Node<B: BlockDevice>`: Inode-backed node providing `read`,
  `write`, `truncate`, persistent `set_perms`/`set_owners`, directory
  metadata mutation, `lookup_async`, `lookup_dir_async`, and
  `enumerate_async`.

## 4. Invariants

- **Magic check:** Mount fails if `s_magic != 0xEF53`.
- **Block 0 of group 0** holds the superblock (at offset 1024) and is
  never returned as data.
- **Cap-bound I/O:** Exactly one `Cap<DmaBuffer, Write>` is minted at
  mount and reused; the cap is unregistered when the volume is dropped.
- **No `Cap::bootstrap()` in hot paths.** All sector reads derive from
  the volume cap via `Cap::derive::<Read>()`.
- **Indirect block walks bounded** by the inode's `i_blocks` / file
  size; cycles in the indirect chain return `FsError::Io(IOError)`.
- **Whole-inode mutations are serialized per volume.** Every data or metadata
  read/modify/write starts from the current on-disk inode, so independent open
  handles cannot restore stale mode or owner fields.
- **Root metadata is real inode metadata.** Mount loads inode 2 and every
  successful inode-2 write refreshes the synchronous `FsInstance::root()`
  snapshot.
- **Checksummed ext4 fails closed.** A volume carrying
  `metadata_csum` verifies its superblock, group descriptors, inodes, and each
  bitmap, classic-directory leaf, or HTREE index block before mutation. Writers
  install dependent bitmap/directory checksums first, then the
  group-descriptor/superblock checksum that names them. Unknown
  read-only-compatible features, a dirty JBD2 log, and a non-empty orphan file
  keep the volume read-only. One-level HTREE insertion into an existing leaf
  and deletion from existing one-level HTREE leaves are supported; a full
  leaf or multi-level mutation is rejected before mutation.

## 5. Architecture notes

- **Async-First:** All I/O is async on the `BlockDevice` trait.
- **Write scope.** Legacy direct/indirect block allocation, inode metadata,
  classic directory mutation, checksum-aware bitmaps/descriptors, and writes
  inside an already mapped extent persist. Extent-tree growth/truncation,
  HTREE leaf splitting/multi-level insertion, and dirty-journal commit remain
  unsupported. Existing one-level HTREE leaves accept checksum-safe insertion
  and deletion without changing the index.
  If the JBD2 superblock and orphan file are both clean, stale `RECOVER` and
  `ORPHAN_PRESENT` flags are cleared with a regenerated superblock checksum.
- **Block-size flexibility.** Block size is `1024 << s_log_block_size`;
  the driver does not hard-code 4096.

## 6. Dependencies

- `narf-block` — block I/O
- `narf-filesystem` — VFS traits
- `narf-io` — DMA buffer + capability registry
- `narf-capabilities` — cap-bound authority
- `narf-driver-runtime` — `DomainId`

## 7. Stage assignment

- **Stage 4:** Compatibility — ext2 is needed to boot from / read disks
  produced by Linux.

## 8. Open questions

- Endianness flexibility — ext2 on-disk is little-endian; this driver
  reads all multi-byte fields with `u*::from_le_bytes`.
- Block size > 4 KiB volumes — supported by the layout math but not yet
  exercised in the test image (1024 is the test image's block size).

## References

This implementation is derived solely from the following public sources:

1. Card, Ts'o, Tweedie. _Design and Implementation of the Second
   Extended Filesystem_.
   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
2. Rusling, _The Second Extended File System: Internal Layout_,
   kernelnewbies.org wiki.
3. OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>

No GPL/LGPL source code (Linux `fs/ext2/*`, GRUB, e2fsprogs, FreeBSD
ext2) was consulted.
