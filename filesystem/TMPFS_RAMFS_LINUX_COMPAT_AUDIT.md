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

### Third pass (2026-09-15) — the VFS checks tmpfs depends on

These are `fs/namei.c` / `fs/xattr.c` rules rather than `mm/shmem.c`
ones, but tmpfs is where their absence showed: `/tmp` is mode 01777 and
`/run` is a shared group tree, so both depend entirely on checks NARF was
not making.

| Linux-visible area | Before | Implemented result |
| --- | --- | --- |
| `may_create` / `may_delete` | no check at all — `unlink`, `rmdir`, `rename`, `link`, `symlink`, `mknod` and `open(O_CREAT)` went straight to the filesystem | `inode_permission(dir, MAY_WRITE \| MAY_EXEC)` on the parent, EACCES when refused |
| Sticky bit | did nothing, so any task could delete any other user's file in `/tmp` | `__check_sticky`: the victim's owner, the directory's owner, or CAP_FOWNER (tested with respect to the victim's ids), EPERM otherwise |
| `inode_init_owner` | a new inode always took the creator's fsgid | a setgid parent hands down its group, and a new SUBDIRECTORY inherits S_ISGID so the tree stays shared |
| ACL writes | unchecked — any task that could name an inode could rewrite its ACL, and through `posix_acl_update_mode` its mode | `set_posix_acl`'s `inode_owner_or_capable`, EPERM |
| Ordinary xattr writes/reads | unchecked | `xattr_permission`'s closing `inode_permission(inode, mask)`, EACCES, plus the sticky-directory `user.*` rule |
| `mknod` umask | ignored | applied — `mode_strip_umask` defers umask stripping on a POSIX-ACL filesystem rather than skipping it, and `shmem_mknod` reaches `posix_acl_create` through `simple_acl_create` |
| `MS_RDONLY` / `MS_NODEV` / `MS_NOEXEC` | accepted and dropped | translated into the mount's `MNT_*` set (`path_mount`), replaced wholesale by `MS_REMOUNT` (`do_reconfigure_mnt`), copied by a namespace clone, and enforced: `mnt_want_write` → EROFS on every write-shaped syscall, `may_open`'s device arm → EACCES on a `nodev` mount, `path_noexec` → EACCES from `do_open_execat` |
| Per-mount options in `/proc/mounts` | a flat `rw` | the real flags, in the column `show_vfsmnt`/`show_mountinfo` put them in — separate from the filesystem's `show_options` text |
| `chattr` inode flags | not modelled at all — `FS_IOC_GETFLAGS`/`SETFLAGS` were unhandled, so `chattr +i` had nowhere to be stored and nothing to enforce it | `FS_IMMUTABLE_FL` and `FS_APPEND_FL` stored per inode, changed only with `CAP_LINUX_IMMUTABLE` by the owner (`fileattr_set_prepare`, `may_fileattr_set`), and enforced at every VFS site that consults them: `inode_permission`, `may_open`'s `O_APPEND`/`O_TRUNC` arms, `may_delete`, `may_setattr`, `may_write_xattr` and `vfs_link` |
| Privilege-bit hygiene | a write left a set-user-ID binary set-user-ID; `mknod` of a device node needed no privilege; a caller-supplied S_ISGID was masked off every create, so `mode_strip_sgid` had nothing to guard | `file_remove_privs`/`setattr_should_drop_suidgid` on write and truncate, `vfs_mknod`'s CAP_MKNOD gate for character and block nodes only, `vfs_create`'s full `S_IALLUGO` mode with `mode_strip_sgid` guarding it, and `posix_acl_update_mode`'s `in_group_or_capable` answered through a syscall-layer hook instead of a hardcoded `true` |
| set-user-ID / set-group-ID execution | not implemented at all — the bits were inert, which is also why `MS_NOSUID` had nothing to suppress | `bprm_fill_uid`, with every guard: `mnt_may_suid`, `task_no_new_privs`, a re-checked execute permission, `S_ISGID` only in company with `S_IXGRP`, and nothing conferred through a `#!` script. A set-user-ID-**root** binary additionally regenerates its permitted set from the bounding set (`handle_privileged_root`), without which it would reach uid 0 holding no capabilities |

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

The third pass adds smokes for the sticky bit (a stranger refused with
EPERM, the victim's owner allowed), directory write permission across
every namespace operation, setgid group and S_ISGID propagation, and the
EPERM/EACCES split between ACL and ordinary xattr writes.

Each new smoke was run against a deliberately stubbed mechanism and
confirmed to fail with the expected message before being kept. The xattr
smoke additionally opens its target for writing first: the gate ends at
`inode_permission`, so a caller who CAN write the file should be allowed
to set an attribute, and without that guard the test would have asserted
the opposite — which is what its first version did, having staged the
mode before an ACL write that reset it.

### Shared mappings (2026-09-15)

| Linux-visible area | Before | Implemented result |
| --- | --- | --- |
| `MAP_SHARED` coherence (tmpfs FILES; `memfd_create` has its own frame-backed store and was already coherent) | each mapping got a PRIVATE frame copied in at fault time and back out on `msync`/`fsync`, so a store through the mapping was invisible to `read(2)` and a `write(2)` was invisible to an already-faulted mapping forever | tmpfs pages are physical frames and `FileOps::mmap_fault` hands the file's OWN frame to the address space, so there is one copy as on Linux (the folio `shmem_get_folio` returns is the page `filemap_map_pages` installs). `MAP_PRIVATE` keeps its copy semantics — `sys_mmap` reaches the demand path only for `MAP_SHARED` |

Verified end to end by
`verification/data/musl-demo/tmpfs_share_smoke_x86_64.c`, which passes on
the host's real Linux kernel and on NARF, and fails with `mapped store not
visible to read(2)` when the private-copy path is restored.

## Remaining gaps

These are explicit implementation gaps, not claimed compatibility:

1. Memory-pressure reclaim, swap, shmem counters, and Linux's internal
   shmem mount are absent. tmpfs pages are now physical frames and a
   `MAP_SHARED` mapping aliases the file's own page
   (`filesystem/specification/tmpfs-shared-mappings.md`), so shared file
   mappings are coherent; what remains is the reclaim/swap half, which
   needs a VM design rather than another `MemFs` patch.

   The one divergence that came with it: a page truncated away while
   mapped is RETIRED rather than freed — its frame is kept, and kept
   charged, until the inode dies — where Linux calls
   `unmap_mapping_range` and lets later accesses take SIGBUS. NARF has no
   reverse map from a file range to its mappings and no
   cross-address-space PTE invalidation, and freeing the frame would hand
   the buddy allocator a page userspace can still write.
2. Transparent huge pages, nontrivial NUMA policies, idmapped mounts,
   casefolding (`CONFIG_UNICODE`), and fscrypt are not implemented.
   Unsupported mount policies are rejected rather than accepted as no-ops.
3. `MS_REC` and `MS_RELATIME` are accepted and dropped — there is no mount
   propagation to recurse over and no per-inode atime policy to relax.
   (`MS_NOSUID` is now enforced: `bprm_fill_uid` consults `mnt_may_suid`
   before granting a set-user-ID transition.)
4. `noswap` cannot be relaxed because no swap path exists. Remount
   validates accepted policy spellings but does not add a behavior NARF
   lacks.
5. `memparse`'s shift overflow is rejected with EINVAL rather than wrapping
   as C does, so `size=16E` fails instead of silently meaning "unlimited".
   This is a deliberate divergence: the wrap turns an over-large size into
   a silent "unlimited", which is a worse answer than refusing the mount.
