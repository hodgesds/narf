# tmpfs / ramfs Linux compatibility audit

Audit date: 2026-07-31
NARF base: `fea49cb23bfde5b052849abdfaf64e6c74b8fb85` (`origin/main`)
Linux reference: local `/usr/src/linux`, version 7.0-rc3

## Scope and method

This audit covers the filesystem objects, classic and fd-based mount APIs,
capacity/error reporting, inode/data lifetime, and Linux-visible metadata for
NARF's `tmpfs` and `ramfs` mounts. The reference is the checked-out Linux tree,
not remembered behavior:

- `/usr/src/linux/mm/shmem.c`: `shmem_default_max_blocks`,
  `shmem_default_max_inodes`, `shmem_parse_one`, `shmem_reconfigure`,
  `shmem_statfs`, shmem inode/file/directory operations, and xattr accounting.
- `/usr/src/linux/fs/ramfs/inode.c`: `ramfs_get_inode`, `ramfs_mknod`,
  `ramfs_tmpfile`, `ramfs_parse_param`, `ramfs_fill_super`, and ramfs operations.
- `/usr/src/linux/Documentation/filesystems/tmpfs.rst`: user-visible limits,
  remount behavior, swap/THP/NUMA/quota options, xattrs, and ramfs differences.
- `/usr/src/linux/include/uapi/linux/magic.h`: `TMPFS_MAGIC` (`0x01021994`)
  and `RAMFS_MAGIC` (`0x858458f6`).

Semcode MCP analysis at the NARF base commit established these relevant call
chains before implementation:

- classic mount: `sys_mount` -> filesystem-type dispatch -> `FsInstance` mount;
- new mount API: `sys_fsopen` -> `sys_fsconfig` -> `build_fs` -> `sys_fsmount`
  -> `sys_move_mount`;
- capacity: `sys_statfs` / `sys_fstatfs` -> `fill_statfs_for_path` ->
  `FsInstance::statfs`;
- unnamed files: `open_impl` -> `DirOps::supports_tmpfile` / `DirOps::tmpfile`;
- anonymous generic storage: `new_anon_file` had no indexed tmpfs mount caller.

That last result mattered: fixing only `new_anon_file` would not make
`O_TMPFILE` use or charge the mounted tmpfs. The implementation instead makes
`MemDir::tmpfile` allocate against its own superblock.

## Findings and implemented compatibility

| Linux-visible area | Before | Implemented result |
| --- | --- | --- |
| Filesystem identity | `tmpfs` and `ramfs` were aliases for unlimited generic `MemFs` | Distinct `TmpFs` and `RamFs` instances and names; correct statfs magic; both advertised as `nodev` in `/proc/filesystems` |
| Mount options | classic `mount(2)` dropped `data`; fsconfig accepted options as no-ops | classic mount and fsconfig retain/apply options; malformed or unsupported tmpfs policies return `EINVAL` |
| Defaults | generic root 0755, no capacity | tmpfs root 01777; block/inode defaults are half managed RAM pages; ramfs root 0755 and unlimited |
| Sizing | no per-mount limits | `size`, `nr_blocks`, and `nr_inodes` enforce per-superblock limits and return `ENOSPC` through create/write/pwrite/writev/fallocate paths |
| `statfs` | zero-capacity synthetic default | live allocated/free block and inode counts; unlimited ramfs reports Linux-shaped zero totals |
| Sparse files | dense `Vec<u8>` made truncate growth allocate and risk allocator failure/panic | sparse 4-KiB page map; holes read as zero; truncate growth is allocation-free; shrink and drop release charged pages |
| Inode lifetime | no accounting | root/files/dirs/links/special nodes/FIFOs/unnamed files are charged; unlink does not release a still-open inode; hard links share one charge |
| File operations | basic read/write/truncate | `SEEK_DATA`, `SEEK_HOLE`, preallocation, `KEEP_SIZE`, hole punch, and zero range |
| Namespace operations | cross-directory memfs rename/link rejected | same-superblock cross-directory rename and hard link, `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, replacement checks, and directory-cycle rejection |
| Node types | FIFO only; char/block unsupported | regular, directory, symlink, socket, FIFO, character, and block nodes with stable inode/type/rdev metadata |
| `O_TMPFILE` | generic unaccounted anonymous fallback | same-filesystem tmpfile with inode/block accounting and later `linkat(AT_EMPTY_PATH)` identity preservation |
| Ownership/mode | root options and directory owners disappeared from path stat | root `mode`, `uid`, `gid`; mkdir/create mode+umask and owner initialization; directory owners visible to stat/statx/access |
| Xattrs | generic memfile xattrs unsupported | regular-file `user.*`, `trusted.*`, and `security.*` create/replace/get/list/remove |
| Remount | accepted without changing an instance | tmpfs live size/inode reconfiguration, rejecting limits below use; ramfs remains non-resizable |

Ramfs deliberately ignores unknown mount parameters, following
`ramfs_parse_param`; tmpfs rejects options whose behavior NARF cannot honestly
provide. NARF has no swap-backed shmem implementation, so every tmpfs behaves
as `noswap`. `huge=never` and `mpol=default|local` describe current behavior;
other THP and NUMA policies are rejected instead of silently lying.

## Verification added

- Filesystem kernel smokes cover option parsing, default metadata, sparse block
  accounting, block/inode exhaustion, unlink/open lifetime, hard links,
  cross-directory operations, special nodes, xattrs, remount, and ramfs
  identity/unlimited behavior.
- Mount syscall smokes pass a real `mount(2)` data pointer and inspect the
  resulting root metadata/statfs; a separate ramfs mount pins its identity.
- New-mount-API ABI smokes prove `FSCONFIG_SET_STRING` reaches tmpfs creation
  and that an unsupported policy fails at `FSCONFIG_CMD_CREATE`.
- `/proc/filesystems` tests require both tmpfs and ramfs with `nodev` prefixes.

## Remaining gaps

These are explicit implementation gaps, not claimed compatibility:

1. NARF tmpfs pages are kernel-heap pages, not unified VM/page-cache objects.
   Consequently shared file mappings, coherent `MAP_SHARED`, memory-pressure
   reclaim, swap, shmem counters, and Linux's internal shmem mount are absent.
2. Transparent huge pages, nontrivial NUMA policies, tmpfs quotas, POSIX ACLs,
   idmapped mounts, casefolding, and fscrypt are not implemented. Unsupported
   mount policies are rejected.
3. Xattrs are currently regular-file-only and do not consume the inode-space
   budget as Linux shmem xattrs do. Directory/symlink xattrs and LSM policy
   hooks remain absent.
4. Timestamp and link-count fidelity is incomplete: atime/ctime, directory
   link counts, hard-link `st_nlink`, and per-mount `st_dev` are not fully
   modeled.
5. Tmpfs write exhaustion is all-or-error for one VFS write call; Linux may
   expose a short write after partial progress in some allocation-failure
   cases.
6. Mount-option rendering in `/proc/mounts`/mountinfo does not yet reproduce
   Linux `show_options`, and generic VFS `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`,
   and `MS_NOEXEC` enforcement remains mount-layer work.
7. `noswap` cannot be relaxed because no swap path exists. Remount validates
   accepted policy spellings but does not add a behavior NARF lacks.

Closing item 1 requires a page-cache/VM design rather than another `MemFs`
patch; items 2 and 6 likewise cross subsystem interfaces. They should remain
separate reviewed changes instead of being represented by accepted no-op
options.
