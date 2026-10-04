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

`register_fstypes()` installs `ext2`, `ext3`, `ext4` in the shared named-mount
registry without constructing a volume. Both mount syscall APIs invoke the
registered constructor with a block source and options, then attach its returned
`Arc<dyn FsInstance>` in the caller's namespace.

The driver implements `narf_filesystem::FsInstance` for `Ext2Volume`.
Per-node ops live on `Ext2Node`, which implements both `FileOps` and
`DirOps`.

### Key Structs

- `Ext2Volume<B: BlockDevice>`: Root structure for a mounted volume.
  `Ext2Volume::iget(ino)` (Linux `iget_locked`) returns the one live
  `Arc<Ext2Node>` of an inode, reading it from disk only on an inode-cache
  miss; lookups, `create`/`mkdir`/`symlink`, `as_dir` and `root()` all go
  through it. `testing::hard_link_image` (doc-hidden) builds byte-level test
  volumes for this crate and the syscall layer.
- `Ext2Node<B: BlockDevice>`: Inode-backed node providing `read`,
  `write`, `truncate`, persistent `set_perms`/`set_owners`, directory
  metadata mutation, `lookup_async`, `lookup_dir_async`, and
  `enumerate_async`.
- The per-volume DMA scratch pool is a bounded async resource. Exhaustion
  registers the filesystem task's waker; returning a buffer wakes one waiter.
  Dropping a waiting future removes its own registration.

## 4. Invariants

- **Magic check:** Mount fails if `s_magic != 0xEF53`.
- **Block 0 of group 0** holds the superblock (at offset 1024) and is
  never returned as data.
- **Cap-bound I/O:** A fixed pool of `Cap<DmaBuffer, Write>` values is minted
  at mount and reused; every cap is unregistered when the volume is dropped.
- **Scratch waitqueue:** No caller busy-polls an exhausted scratch pool.
  Buffer return publishes the free cap before waking one registered waiter;
  cancelled waiters cannot leave permanent registrations behind.
- **No `Cap::bootstrap()` in hot paths.** All sector reads derive from
  the volume cap via `Cap::derive::<Read>()`.
- **Indirect block walks bounded** by the inode's `i_blocks` / file
  size; cycles in the indirect chain return `FsError::Io(IOError)`.
- **Whole-inode mutations are serialized per volume.** Every data or metadata
  read/modify/write starts from the current on-disk inode, so independent open
  handles cannot restore stale mode or owner fields.
- **One in-memory inode per on-disk inode.** The volume's icache maps an
  inode number to a `Weak<Ext2Node>`; at most one node per inode is live, so
  every name (hard links included) and every open of a file share one node.
  Every inode write goes through `write_inode_slot`, which refreshes the live
  node's cached inode, so the cached copy never trails the disk. A node
  removes its own entry when its last `Arc` drops (only if the entry still
  names it); `free_inode` unhashes the number first so a reused number never
  resolves to the freed inode's node.
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
- **Allocation metadata is serialized and quarantined by group.** Bitmap,
  group-descriptor, and superblock-counter updates cannot interleave. A block
  group whose bitmap checksum fails is skipped without mutation, allowing a
  large volume to continue allocating from independently valid groups. Inode
  allocation also monotonically advances ext4's `bg_itable_unused` boundary
  before the updated group-descriptor checksum is persisted, so Linux does not
  classify newly initialized inode slots as deleted.

## 5. Architecture notes

- **Async-First:** All I/O is async on the `BlockDevice` trait.
- **Folio-native reads:** 1/2/4 KiB filesystem blocks are retained as slices
  of the unified 4 KiB page-cache folio. Directory lookup, enumeration, and
  emptiness checks consume one retained block view at a time and stop early;
  they never flatten `inode.size` into a slab allocation. If a folio cannot be
  allocated under pressure, the same interface falls back to one fallibly
  allocated filesystem-block buffer, bounded independently of directory size.
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
- **Damaged-group containment.** Allocation scans treat a checksum-invalid
  bitmap as unavailable space in that group; targeted frees still fail closed
  because silently leaking a known allocation is safer than clearing an
  unverified bitmap bit.

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
