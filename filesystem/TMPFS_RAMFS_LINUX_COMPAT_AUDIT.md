# tmpfs / ramfs Linux compatibility audit

Original audit: 2026-07-31 (NARF `fea49cb2`, Linux 7.0-rc3).
Second pass: 2026-09-15 (NARF `707822df`, Linux 7.0-rc7 at `/usr/src/linux`).

## Scope and method

This audit covers the filesystem objects, classic and fd-based mount APIs,
capacity/error reporting, inode/data lifetime, and Linux-visible metadata for
NARF's `tmpfs` and `ramfs` mounts. The reference is the checked-out Linux tree,
not remembered behavior:

- `/usr/src/linux/mm/shmem.c`: `shmem_default_max_blocks`,
  `shmem_default_max_inodes`, `shmem_parse_one`, `shmem_reconfigure`,
  `shmem_show_options`, `shmem_statfs`, `shmem_inode_acct_blocks`,
  `shmem_reserve_inode`, `shmem_free_inode`, `shmem_xattr_handler_set`,
  and the four `shmem_*_inode_operations` tables.
- `/usr/src/linux/mm/shmem_quota.c`: `shmem_acquire_dquot` (where the
  mount's default quota hard limits are stamped onto a new id).
- `/usr/src/linux/lib/cmdline.c`: `memparse`.
- `/usr/src/linux/mm/filemap.c`: `generic_perform_write` (short writes).
- `/usr/src/linux/fs/xattr.c`: `setxattr_copy`, `import_xattr_name`,
  `xattr_permission`, `xattr_resolve_name`, `simple_xattr_set`,
  `simple_xattr_space`, `removexattr`.
- `/usr/src/linux/fs/posix_acl.c`: `posix_acl_create`,
  `posix_acl_update_mode`, `simple_set_acl`, `vfs_remove_acl`.
- `/usr/src/linux/fs/inode.c`: `touch_atime` / `relatime_need_update`.
- `/usr/src/linux/fs/super.c`: `get_anon_bdev`.
- `/usr/src/linux/fs/ramfs/inode.c` and
  `Documentation/filesystems/tmpfs.rst`.
- `/usr/src/linux/include/uapi/linux/magic.h`: `TMPFS_MAGIC` (`0x01021994`)
  and `RAMFS_MAGIC` (`0x858458f6`).

## Implemented compatibility

### First pass (2026-07-31)

| Linux-visible area | Before | Implemented result |
| --- | --- | --- |
| Filesystem identity | `tmpfs` and `ramfs` were aliases for unlimited generic `MemFs` | Distinct `TmpFs` and `RamFs` instances and names; correct statfs magic; both advertised as `nodev` in `/proc/filesystems` |
| Mount options | classic `mount(2)` dropped `data`; fsconfig accepted options as no-ops | classic mount and fsconfig retain/apply options; malformed or unsupported tmpfs policies return `EINVAL` |
| Defaults | generic root 0755, no capacity | tmpfs root 01777; block/inode defaults are half managed RAM pages; ramfs root 0755 and unlimited |
| Sizing | no per-mount limits | `size`, `nr_blocks`, and `nr_inodes` enforce per-superblock limits |
| `statfs` | zero-capacity synthetic default | live allocated/free block and inode counts; unlimited ramfs reports Linux-shaped zero totals |
| Sparse files | dense `Vec<u8>` | sparse 4-KiB page map; holes read as zero; truncate growth is allocation-free |
| Inode lifetime | no accounting | every node type charged; unlink does not release a still-open inode; hard links share one charge |
| File operations | basic read/write/truncate | `SEEK_DATA`, `SEEK_HOLE`, preallocation, `KEEP_SIZE`, hole punch, zero range |
| Namespace operations | cross-directory memfs rename/link rejected | same-superblock cross-directory rename and hard link, `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, replacement checks, directory-cycle rejection |
| Node types | FIFO only | regular, directory, symlink, socket, FIFO, character, and block nodes |
| `O_TMPFILE` | generic unaccounted anonymous fallback | same-filesystem tmpfile with accounting and `linkat(AT_EMPTY_PATH)` identity |
| Ownership/mode | root options and directory owners disappeared from path stat | root `mode`/`uid`/`gid`; mkdir/create mode+umask; directory owners visible to stat/statx/access |
| Xattrs | unsupported | regular-file `user.*`, `trusted.*`, `security.*` |
| Remount | accepted without changing an instance | live size/inode reconfiguration; ramfs remains non-resizable |

### Second pass (2026-09-15)

| Linux-visible area | Before | Implemented result |
| --- | --- | --- |
| `memparse` | a re-implemented suffix table: `1kB` accepted, `0x100000` rejected | Linux's `simple_strtoull(.., 0)` plus ONE `K M G T P E` suffix, so base-0 hex/octal work and a two-letter unit is a bad value |
| `size=N%` | capped at 100%, and computed as `N * pages / 100` | no ceiling (`size=200%` is legal); Linux's `(N << PAGE_SHIFT) * totalram / 100` then rounded up to pages, which differs from the shortcut by a block |
| `mode=` | range-checked | masked with `07777`, as `result.uint_32 & 07777` does |
| `nr_blocks` / `nr_inodes` | unbounded | rejected above `LONG_MAX` and `ULONG_MAX / BOGO_INODE_SIZE` |
| bare `quota` | enabled usrquota only | `QTYPE_MASK_USR | QTYPE_MASK_GRP` — both |
| `{usr,grp}quota_{block,inode}_hardlimit=` | absent (mount failed) | parsed, range-checked, and stamped onto every id as `shmem_acquire_dquot` does |
| `usrjquota` / `grpjquota` / `jqfmt` | accepted | rejected — they are ext-family options, not tmpfs ones |
| Remount errno | ENOSPC for "too small for current use" | EINVAL: every `shmem_reconfigure` rejection is `invalfc()` |
| Remount quota rules | none | "Cannot enable quota on remount" and "Cannot change global quota limit on remount" |
| Inode accounting | a count | Linux's byte-denominated inode space (`BOGO_INODE_SIZE` per inode), so `f_ffree` is `free_ispace / BOGO_INODE_SIZE` |
| Quota limit units | 4-KiB blocks | bytes, as `dqb_bhardlimit` is, so a sub-page limit denies the first page |
| `show_options` | a bare `rw` in `/proc/mounts` | `shmem_show_options`: `size=`k, `nr_inodes=`, `mode=`, `uid=`, `gid=`, `inode{32,64}`, `noswap`, quota state and hard limits, in both `/proc/mounts` and mountinfo's super-options column |
| Xattr inode types | regular files only; a directory's went to a path-keyed side table | every inode type — directory, symlink, socket, FIFO, device node — with `xattr_permission`'s `user.*` restriction |
| Xattr accounting | free | `simple_xattr_space()` = `40 + size + strlen(name)` charged against the same inode space, returned with the inode by `shmem_free_inode` |
| Xattr errnos | EINVAL for most refusals | ERANGE (empty/over-long name), E2BIG (`XATTR_SIZE_MAX`), EOPNOTSUPP (unresolvable namespace), EPERM/ENODATA for `trusted.*` without CAP_SYS_ADMIN, EEXIST/ENODATA for `XATTR_CREATE|XATTR_REPLACE` together |
| `removexattr` of an absent access ACL | ENODATA | 0 — `removexattr` routes both ACL names to `vfs_remove_acl` → `set_posix_acl(type, NULL)` → `simple_set_acl(NULL)`, which never asks whether an ACL was cached |
| Short writes | all-or-nothing | `generic_perform_write`'s `if (!written) return status;` — a write that fills the mount returns a short count and the NEXT one reports ENOSPC/EDQUOT |
| `st_nlink` | always 1 | real link counts; `2 + subdirectories` for a directory (which is what `find`'s leaf optimisation reads); **0** for an unlinked `O_TMPFILE` inode |
| `st_dev` | always 0 | a distinct anonymous device per superblock (`get_anon_bdev`, `new_encode_dev`) |
| atime / ctime | mtime copied into all three | three separate stamps: mtime+ctime on a data change, ctime alone on a metadata change, atime under `relatime_need_update`. Directories gained timestamps at all |
| POSIX default ACLs | `posix_acl_create` implemented but never called; directories had no ACL storage | directories hold `system.posix_acl_default`; `mkdir` and `open(O_CREAT)` inherit it, and it REPLACES the umask rather than combining with it |

Ramfs deliberately ignores unknown mount parameters, following
`ramfs_parse_param`, and has no `show_options` (its `super_operations`
leaves the slot empty), so it contributes no options to `/proc/mounts`.
Tmpfs rejects options whose behavior NARF cannot honestly provide. NARF has
no swap-backed shmem implementation, so every tmpfs behaves as `noswap`.
`huge=never` and `mpol=default|local` describe current behavior; other THP
and NUMA policies are rejected instead of silently lying.

## Verification

Kernel smokes under `filesystem/tmpfs` and `syscall_abi` cover option
parsing (including every `memparse` shape and range check), remount errnos
and quota rules, `show_options`, xattrs on every inode type, xattr
inode-space accounting and flag semantics, short writes at both ENOSPC and
EDQUOT, link counts across create/link/unlink/rename/mkdir/rmdir/tmpfile,
the three timestamps and the relatime rule, per-mount device numbers, and
default-ACL inheritance end-to-end through `mkdir`/`open(O_CREAT)` with a
umask that would visibly bite if inheritance were not happening.

Each new smoke was run against a deliberately stubbed mechanism and
confirmed to fail with the expected message before being kept.

## Remaining gaps

These are explicit implementation gaps, not claimed compatibility:

1. NARF tmpfs pages are kernel-heap pages, not unified VM/page-cache
   objects. Consequently coherent shared file mappings, memory-pressure
   reclaim, swap, shmem counters, and Linux's internal shmem mount are
   absent. Closing this requires a page-cache/VM design rather than another
   `MemFs` patch.
2. Transparent huge pages, nontrivial NUMA policies, idmapped mounts,
   casefolding (`CONFIG_UNICODE`), and fscrypt are not implemented.
   Unsupported mount policies are rejected rather than accepted as no-ops.
3. Generic VFS `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV` and `MS_NOEXEC`
   enforcement remains mount-layer work, and `/proc/mounts` therefore
   prints `rw` for the per-mount flags regardless of how the mount was
   made. The filesystem-specific half of that line is now correct.
4. `noswap` cannot be relaxed because no swap path exists. Remount
   validates accepted policy spellings but does not add a behavior NARF
   lacks.
5. `set_posix_acl`'s `inode_owner_or_capable()` check, and
   `posix_acl_update_mode`'s `in_group_or_capable()` S_ISGID drop, need a
   credential the `FileOps`/`DirOps` methods do not carry. NARF keeps the
   S_ISGID bit (Linux's answer for the common case of an owner acting on
   their own file) and never widens the rwx bits.
6. S_ISGID inheritance from a parent directory (`inode_init_owner`) is not
   modelled; a new inode takes the creating task's fsuid/fsgid.
7. `memparse`'s shift overflow is rejected with EINVAL rather than wrapping
   as C does, so `size=16E` fails instead of silently meaning "unlimited".
