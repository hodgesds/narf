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
- **Out of Scope (this iteration):** fast commits (written or replayed), HTREE
  rebalancing on delete, `largedir` (a third HTREE level), converting a
  linear directory to an index (`make_indexed_dir`), and `fsck`-style
  repair.

## 2. Assumptions

- The underlying block device exposes a `BlockDevice` whose
  `logical_block_size()` divides 1024. (The ext2 superblock starts at
  byte 1024; with a 512-byte LBS the superblock sits at LBA 2; with a
  1024-byte or 4096-byte LBS it sits at LBA 1 or LBA 0 respectively.)
- The VFS wrapper handles path resolution and capability derivation.
- Variable-size metadata and data buffers use heap `Vec<u8>` slices copied
  through the volume's registered cap-bound `DmaBuffer`. Fixed 1024-byte
  primary-superblock counter/feature updates use bounded stack scratch so
  inode teardown under global pressure does not require slab growth.

## 3. Public interface

`register_fstypes()` installs `ext2`, `ext3`, `ext4` in the shared named-mount
registry without constructing a volume. Both mount syscall APIs invoke the
registered constructor with a block source and options, then attach its returned
`Arc<dyn FsInstance>` in the caller's namespace.

The constructor takes the whole `MountRequest`:
- **One volume per device** (`registry::mount`, Linux `get_tree_bdev`). A
  second mount of the same device shares the first one's volume; one that
  would change its read-only state fails with EBUSY.
- **A read-only request** (`MS_RDONLY`, or `ro` in the data) mounts without
  writing a byte.
- **A read-write request the volume cannot honour** fails as Linux's does:
  - EINVAL for a read-only-compatible feature Linux does not know
    (`ext4_feature_set_ok`);
  - a read-only mount without error for the READONLY feature;
  - EROFS for a filesystem Linux would write and NARF does not, or a device
    `narf.disks=` keeps read-only. libmount then retries read-only.
- **The write gate** (`volume::sb_state::rw_refusal`) decides. Each refusal
  is logged and recorded in `narf_filesystem::rw_refusal` for the
  `narf.disks=root-rw` failure banner.
- **Remount** (`reconfigure_sb_async`): `SB_RDONLY` (or `ro`) writes
  everything back, flushes and marks the filesystem clean; clearing it runs
  the gate again over the on-disk superblock.

The driver implements `narf_filesystem::FsInstance` for `Ext2Volume`.
Per-node ops live on `Ext2Node`, which implements both `FileOps` and
`DirOps`.

FITRIM (`fstrim`, #1166) is the first discard caller: `Ext2Volume::fitrim`
scans the block bitmaps for free blocks in the requested byte range,
coalesces contiguous free runs of at least `minlen`, and issues one
`BlockDevice::discard` per run. It is reachable as the Linux FITRIM
ioctl (`0xC018_5879`, `struct fstrim_range` — see `src/fitrim.rs`) on
both a file fd (`FileOps::ioctl_user`) and a directory fd
(`DirOps::ioctl_async`, the path `fstrim(8)` uses on the mount point).
A device without `BlockFeature::Discard` fails the ioctl with
`EOPNOTSUPP` rather than reporting a trim that never happened.

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
- File and directory `fsync` finish queued last-reference inode teardown
  and report device-flush errors. `syncfs` through either kind of descriptor
  writes dirty pages of all live inodes in the volume before that teardown
  and flush. Open unlinked inodes remain allocated until their last reference
  drops; a sync must not reclaim a file still open or mapped.

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
- **File data lives in the inode's page cache.** Each node owns a
  `FileMapping` keyed by `(incarnation << 32) | ino`; the incarnation makes a
  freed-but-open inode's pages unreachable from a new inode reusing the
  number. Regular-file `read` copies out of it (`->read_folio` =
  `read_file_page`, straight from the blocks, never through the block-device
  mapping, holes and post-EOF bytes zero); `write` is write-through
  (`generic_perform_write` copying into the cached folio, then
  `write_file_page` writing the touched blocks from it before returning), so
  readers and mappings see the bytes at once and the disk has them when
  `write` returns. Write-through rather than Linux's dirty-and-writeback
  keeps every POSIX/Linux-observable result (read-after-write, mmap
  coherence, durability after `fsync`) while needing no writeback for
  `write(2)`; only stores through mappings dirty pages. `mmap_fault` returns
  that exact `FileMapping` folio (and conservatively marks it dirty because
  hardware PTE dirty-bit harvesting is not yet wired), so hard-link aliases,
  `read(2)`, and `write(2)` all observe one physical page. A failed block
  write leaves the page dirty for writeback. Its direct mmap fault returns an
  asynchronous cache-fill future; the common FileOps fault bridge parks the
  caller on that fill's waker and retries after publication, never
  spin-polling a folio owned by another task. `fsync` writes back dirty pages
  and flushes the device cache. `truncate` first publishes the smaller size
  and revokes every mapped page wholly beyond it, then zeroes the new last
  block's tail in the cache and on disk (`block_truncate_page`) and drops
  every page past the new EOF (`truncate_inode_pages`); directories are read
  through the block-device mapping, where `dir_mut` maintains them.
- **Root metadata is real inode metadata.** Mount loads inode 2 and every
  successful inode-2 write refreshes the synchronous `FsInstance::root()`
  snapshot.
- **Checksummed ext4 fails closed.** A volume carrying
  `metadata_csum` verifies its superblock, group descriptors, inodes, and each
  bitmap, classic-directory leaf, or HTREE index block before mutation. Writers
  install dependent bitmap/directory checksums first, then the
  group-descriptor/superblock checksum that names them. Unknown
  read-only-compatible features keep the volume read-only. One-level HTREE insertion into an existing leaf
  and deletion from existing one-level HTREE leaves are supported; a full
  leaf or multi-level mutation is rejected before mutation.
- **Directory names hash as Linux hashes them** (`htree::ext4fs_dirhash`,
  `fs/ext4/hash.c::__ext4fs_dirhash`): legacy, half-MD4 and TEA, each
  signed or unsigned, checked against e2fsprogs' `dx_hash`. The low bit is
  cleared and the readdir EOF cookie (`EXT4_HTREE_EOF_32BIT << 1`) is never
  returned. A lookup adds `s_hash_unsigned` to the root's base version as
  `dx_probe` does: 3 when `s_flags` says unsigned, 0 when it says signed,
  and the platform's `char` signedness when it says neither (signed on
  x86_64, unsigned on aarch64). `DxRoot::parse` refuses what `dx_probe`
  refuses: an on-disk version other than 0-2, `unused_flags` bit 0, and
  more than one dx-node level (two need `largedir`, which is refused at
  mount).
- **A crash is never hidden** (Linux `ext4_setup_super`). A read-write
  mount bumps `s_mnt_count`, sets `s_mtime` and records the hash
  signedness in one superblock write, with FUA and a flush, before any
  other write. Remount read-only and the last unmount (`Drop`, polled once
  in place) restore the mount-time `s_state` after a full write-back,
  adding `EXT4_ERROR_FS` if an error was recorded. `syncfs` never marks the
  filesystem clean.
  - With a journal (the next bullet): `EXT4_VALID_FS` stays set, and
    `RECOVER` (and `ORPHAN_PRESENT` with an orphan file) is set while
    mounted read-write. The unmount commits, checkpoints and empties the log
    before clearing them. After a crash, recovery replays the log.
  - Without one (`^has_journal`, or `noload` on a filesystem that does not
    need recovery): metadata is written in place in no-journal order,
    `EXT4_VALID_FS` is cleared while mounted, and a stale
    `RECOVER`/`ORPHAN_PRESENT` the gate found clean is repaired. After a
    crash, `e2fsck -p` sees an unclean filesystem and checks it fully.
- **Metadata goes through the journal** on a journaled read-write mount
  (`volume/jbd.rs`; `fs/jbd2/commit.c`, `checkpoint.c`, `data=ordered`):
  - A metadata write lands in the running transaction (whole blocks, the
    latest copy of each), which every read consults first. The device keeps
    the committed state until the commit.
  - File data and the zero-fill of freshly allocated blocks go to the
    device directly, inside the operation that writes them, so they are on
    the device before the commit that references them.
  - Each operation holds `inode_update_lock`, which is the jbd2 handle: a
    commit runs only between operations.
  - A commit writes the descriptors and copies, flushes, writes the commit
    block with FUA, checkpoints (writes every block home, flushes) and
    moves the log tail past it (FUA).
  - It happens when an operation starts and the transaction is at its
    limit (a quarter of the log, at most 4 MiB), on `fsync`/`syncfs`,
    every 5 s (`JBD2_DEFAULT_MAX_COMMIT_AGE`), and at remount read-only and
    unmount.
  - The journal features are ext4's (`ext4_set_journal_csum_feature_set`:
    csum v3 under `metadata_csum`, none without; 64-bit tags on a 64-bit
    filesystem). A v1 journal superblock cannot carry them: EINVAL.
  - Blocks freed in a transaction are not allocated again before it
    commits, and `fitrim` skips them.
  - A failed commit write aborts the journal (`jbd2_journal_abort`): the
    volume goes read-only, `RECOVER` stays set, and nothing more is
    written; the next mount recovers the last committed state. So does a
    filesystem error that stops writing (`narf.disks=root-rw`,
    `errors=remount-ro` or `panic`; `ext4_handle_error`), before the error
    is recorded, so the failed operation's partial changes never commit.
  - Whole device sectors go out several per request, so a journal block
    (a commit block above all) is one write, as Linux submits it.
  - LINUX-GAPs: one transaction at a time, committed and checkpointed in
    one go (no committing/running overlap, no lazy checkpoint, so no
    revoke records are ever needed); `commit=` is accepted but the interval
    stays 5 s; an operation larger than the whole log fails with ENOSPC
    (Linux splits large truncates across transactions, an orphan record
    holding the inode in between); fast commits are not written.
- **Orphans are recorded and finished as Linux does it** (`volume/orphan.rs`;
  `fs/ext4/orphan.c`):
  - An inode whose last link goes while it is still open is recorded in
    the unlink's transaction (`ext4_orphan_add`), and only with a journal:
    in a free slot of the orphan file (each block ends with
    `EXT4_ORPHAN_BLOCK_MAGIC` and a crc32c over its block number and
    entries, seeded with the orphan inode's checksum seed), or, with no
    orphan file or a full one, at the head of the `s_last_orphan` list,
    linked through `i_dtime`. Its release at the last close removes it
    (`ext4_orphan_del`) in the same transaction that frees it, with a
    directory's `bg_used_dirs_count` (`ext4_free_inode`).
  - `rmdir` of a directory still open (a cwd) empties it (`i_size = 0`) and
    records it the same way; nothing can be created in it (ENOENT, as
    `IS_DEADDIR`). A directory a `rename` replaces is released likewise.
  - At mount `ext4_init_orphan_info` reads every orphan file block; a bad
    magic or checksum fails the mount with EIO before anything is written.
  - Then `ext4_orphan_cleanup`, in Linux's order: nothing on a device that
    cannot be written ("write access unavailable"), nothing with unknown
    read-only-compatible features, and with `EXT4_ERROR_FS` nothing but,
    on a read-write mount, clearing the list. Otherwise the list, head
    first, then every orphan file slot: an inode with no links is deleted,
    one with links (an interrupted truncate) is cut to `i_size` with the
    rest of its last block zeroed. A slot or list entry naming an
    unallocated, unreadable or untruncatable inode is a filesystem error
    ("bad orphan inode"); on the list it ends the walk.
  - A read-only mount of a writable device writes for the duration ("orphan
    cleanup on readonly fs"), through the journal, which is flushed before
    writing stops. Then `ext4_mark_recovery_complete` clears `RECOVER` and
    `ORPHAN_PRESENT`; an orphan file entry still there is EFSCORRUPTED and
    fails the mount.
  - Remount read-only while an unlinked inode is open is EBUSY
    (`s_remove_count`); remount read-write over an unprocessed orphan list
    or file is EINVAL ("Please umount/remount instead"). The unmount keeps
    `ORPHAN_PRESENT` while the orphan file is not empty.
  - LINUX-GAP: on a read-only mount of a filesystem NARF's write gate
    refuses for a feature Linux writes, or whose journal still needs
    recovery under `noload`, the cleanup is skipped and `RECOVER` /
    `ORPHAN_PRESENT` stay set while an orphan is recorded, for Linux.
- **The write gate** refuses a read-write mount, and writes nothing, for:
  - an unknown or unwritable read-only-compatible feature;
  - legacy `gdt_csum`;
  - a default directory hash other than 0-2.

  Orphans are not refused: the mount finishes them (above).

  Under `narf.disks=root-rw` it also refuses a filesystem with
  `EXT4_ERROR_FS` or without `EXT4_VALID_FS`. LINUX-GAP: Linux mounts those
  with a warning; NARF writes a production root only after e2fsck has seen
  it.
- **Errors are recorded** (`fs_error`, Linux `__ext4_error`). This sets:
  - `EXT4_ERROR_FS` and `s_error_count`;
  - the first and last error's time, inode, block and function;
  - the `EXT4_ERR_*` code.

  Under `root-rw`, or with `s_errors=remount-ro`, the mount stops writing.
  `s_errors=panic` panics.
- **Allocation metadata is serialized and quarantined by group.** Bitmap,
  group-descriptor, and superblock-counter updates cannot interleave. A block
  group whose bitmap checksum fails is skipped without mutation, allowing a
  large volume to continue allocating from independently valid groups. Inode
  allocation also monotonically advances ext4's `bg_itable_unused` boundary
  before the updated group-descriptor checksum is persisted, so Linux does not
  classify newly initialized inode slots as deleted.
- **Allocation starts at its goal** (`ext4_mb_new_blocks` with a goal):
  - Order: the goal's group from the goal block, then every later group,
    wrapping around.
  - A group whose descriptor counts nothing free is skipped without reading
    its bitmap.
  - Inodes are taken from groups in order, after `EXT4_FIRST_INO`
    (`s_first_ino`). LINUX-GAP: no Orlov spreading of directories.
- **Lazily initialized groups** (`BLOCK_UNINIT`, `INODE_UNINIT`, with a
  descriptor checksum) are used only after every initialized group.
  - Their bitmap is never read: it is computed as `ext4_init_block_bitmap`
    computes it. That covers the superblock copy (`ext4_bg_has_super`,
    `sparse_super` / `sparse_super2`), the descriptor table and reserved GDT
    blocks, the group's own bitmaps and inode table when they lie inside it,
    and the padding past a short last group.
  - The computed bitmap must agree with the descriptor's free count; if it
    does not, the group is skipped.
  - The first allocation writes the bitmap and clears the flag.
  - An inode allocated in a group whose block bitmap is uninitialized
    initializes it first (`__ext4_new_inode`).
  - Freeing anything in such a group is `Corrupted`.
- **Group count** is `DIV_ROUND_UP(blocks_count - first_data_block,
  blocks_per_group)`, as `ext4_fill_super` computes it.
- **HTREE inserts split as Linux does** (`dir_mut.rs`, `ext4_dx_add_entry`).
  - `dx_probe` checks every index level: the root's `limit` equals what
    the block holds (`dx_root_limit`), each node opens with a fake dirent
    spanning the block and has `dx_node_limit`, `count` is within `limit`,
    child blocks lie inside the directory, and the `dx_tail` checksum
    holds. Damage is `Corrupted`, a bad checksum `BadChecksum`.
  - A full leaf splits at `do_split`'s point: from the highest hash down,
    entries move while they fill at most half a block. The new block is
    indexed with the first moved hash, plus one when that hash continues
    from the block before (`continued`).
  - A full index node splits in two when the root has room. A full root at
    `indirect_levels` 0 moves into a new node and the root indexes it
    (0 → 1). A full tree at the maximum depth (two levels without
    `largedir`) is ENOSPC before any write.
  - Without a journal: the new block, then the inode that maps it, then
    the one index block that makes it reachable (the commit), then the old
    block shrinks. Before the commit a failure frees the block and restores
    the inode; after it the error is recorded.
  - LINUX-GAP: a full one-block linear directory grows linearly; it is not
    converted to an index (`make_indexed_dir`).
- **Namespace changes keep a no-journal-safe order** (`dir_mut.rs`).
  - A new inode is written before its dirent, which is the commit. A
    failure before it clears the inode slot, then frees its data block.
  - `link` raises and writes the link count before the new name exists,
    so a crash can leave the count too high (e2fsck lowers it), never a
    name the count does not cover.
  - A rename onto an existing name repoints that dirent in place
    (`ext4_setent`), so the name exists throughout. The old name goes
    next, then the replaced inode's link, then a moved directory's `..`,
    written with the dx root's checksum when the directory is indexed.
  - Link limits are Linux's. `link` of an inode at `EXT4_LINK_MAX` (65000)
    links is EMLINK. So is `mkdir`, or a rename moving a directory, into a
    directory at that limit, unless `dir_nlink` lets an indexed directory
    go on at a count of 1 (`EXT4_DIR_LINK_MAX`, `ext4_inc_count`). `rmdir`
    and a rename leave a parent at 1 or 2 alone (`ext4_dec_count`).
- **Extent trees grow to any depth** (`volume/extent_write.rs`, Linux
  `ext4_ext_insert_extent`), up to `EXT4_MAX_EXTENT_DEPTH` (5).
  - A full leaf gets a sibling, indexed from the deepest index level with
    room. Every full level between gets a new node holding the new child
    and the entries right of the path (`ext4_ext_split`).
  - When every level is full, the root's entries move to a new block and
    the root indexes it, one level deeper (`ext4_ext_grow_indepth`).
  - An index key equals its child's first key, corrected upward while the
    child is its parent's first entry (`ext4_ext_correct_indexes`).
- **Extent blocks are checked before a change** (`__ext4_ext_check`):
  magic, depth, `eh_max` within what the node holds, `eh_entries` within
  `eh_max`, no empty index, entries in order and inside the filesystem, the
  first key equal to the parent's, and below the root the tail checksum.
  - Structural damage is `Corrupted` (EFSCORRUPTED), a bad checksum
    `BadChecksum` (EFSBADCRC); both are recorded with `fs_error`.
  - The tail checksum covers the header and `eh_max` entry slots and sits
    right after them (`EXT4_EXTENT_TAIL_OFFSET`), not at the block's end:
    the two differ at 2 KiB blocks.
  - LINUX-GAP: reads do not verify extent blocks. Linux verifies once per
    buffer and caches the result; NARF has no per-buffer verified state, and
    a CRC of every extent block on every mapping lookup is too costly.
- **Extent inserts allocate first and commit once.** Every block the
  change needs (the caller's data block, new tree nodes) is allocated
  before anything is written. New nodes are written, then the one node that
  makes them reachable (the commit: an index block, or the inode for a
  root change), then the old nodes lose what moved, then keys above are
  corrected.
  - Before the commit, a failure frees every block it took, the data block
    too, and leaves the inode as it was. After it, the error is recorded
    and the inode, counting the new blocks, is still written.
  - A crash between the commit and the trim leaves entries reachable from
    two nodes, which e2fsck repairs; no entry is ever unreachable.
- **Blocks are freed after nothing maps them** (`volume/free_list.rs`).
  Truncate, punch and unlink, for extent trees and block maps alike, write
  the trimmed nodes bottom-up, then the inode, and only then free. A crash
  in between leaks blocks e2fsck reclaims; a block is never free while an
  inode on disk still maps it, so it cannot end up shared by two files.
  Frees are collected as runs and applied one bitmap and descriptor write
  per group per run.
- **`i_blocks` is 32 bits of sectors.** It is stored as Linux stores a
  count that fits (`ext4_inode_blocks_set`): `l_i_blocks_high` zero,
  `HUGE_FILE_FL` clear. A sum past 32 bits is EFBIG.
  - LINUX-GAP: on a huge_file volume, an inode already using the high half
    or `HUGE_FILE_FL` (a file holding 2 TiB or more) is refused a rewrite
    with EFBIG, rather than having its count corrupted.
- **A failed write still persists a changed block map.** When the first
  page of a write fails after its block was allocated and mapped, the inode
  is written anyway, so `i_blocks` counts the block.

## 5. Architecture notes

- **Async-First:** All I/O is async on the `BlockDevice` trait.
- **Folio-native reads:** 1/2/4 KiB filesystem blocks are retained as slices
  of the unified 4 KiB page-cache folio. Directory lookup, enumeration, and
  emptiness checks consume one retained block view at a time and stop early;
  they never flatten `inode.size` into a slab allocation. If a folio cannot be
  allocated under pressure, the same interface falls back to one fallibly
  allocated filesystem-block buffer, bounded independently of directory size.
- **Write scope.** Legacy direct/indirect block allocation, inode metadata,
  classic directory mutation, checksum-aware bitmaps/descriptors, extent
  trees of any depth (growth, unwritten conversion, truncation, punch), and
  HTREE inserts with leaf and index splits up to two index levels persist.
  Without a journal, a stale `RECOVER` flag is cleared with a regenerated
  superblock checksum, and a stale `ORPHAN_PRESENT` once nothing is
  recorded as an orphan.
- **The journal is recovered at mount, as Linux does it** (`journal.rs`;
  `fs/jbd2/recovery.c`, `fs/jbd2/journal.c`, `ext4_load_journal`). Before
  any inode but the journal's own is read:
  - The journal inode must be live and regular (EFSCORRUPTED) and its
    superblock valid, in `journal_check_superblock`'s order (EINVAL;
    EFSBADCRC for its checksum). An external journal is EOPNOTSUPP.
  - `RECOVER` clear: the log is wiped (`jbd2_journal_wipe`), and marked empty
    when the device can be written.
  - `RECOVER` set: the three passes (SCAN, REVOKE, REPLAY) write every
    complete, un-revoked transaction home, then flush. They verify csum v2/v3
    descriptor, revoke, commit and tag checksums and the v1 transaction
    checksum, tell a stale log from a corrupt one by commit time, accept a
    torn commit block, restore escaped blocks, wrap at `s_maxlen` and carry
    64-bit block numbers. Any recovery error fails the mount; a corrupt
    committed transaction is EFSCORRUPTED. The log restarts two ids past the
    last good one, and `journal_reset` rewrites its tail.
  - This happens on a read-only mount too. Only a device that cannot be
    written refuses it, with EROFS ("try mounting with noload"), writing
    nothing. `noload` / `norecovery` skip the journal: a read-only mount
    then sees the filesystem as it is on disk; a read-write mount of one
    that needs recovery is EINVAL.
  - Error fields the replay overwrote in the superblock are put back, and
    an error recorded in the journal (`s_errno`) becomes `EXT4_ERROR_FS`
    (`ext4_clear_journal_err`).
  - The replayed log is marked empty. After the orphan cleanup,
    `ext4_mark_recovery_complete` flushes the journal and, on a read-only
    mount, clears `RECOVER` and `ORPHAN_PRESENT` (orphans, above).
  - LINUX-GAPs:
    - Fast commits are not replayed: a dirty journal with `FAST_COMMIT` is
      EOPNOTSUPP, before anything is written.
    - A pass that reads more block headers than one lap of the log holds
      ends with EFSCORRUPTED (Linux would loop).
    - Recovery holds at most 2^20 revoke records (ENOMEM beyond).
    - On a read-only device an `s_errno` is noted in memory only; Linux
      attempts the superblock write.
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
