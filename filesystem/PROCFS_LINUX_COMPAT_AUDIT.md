# Linux procfs compatibility audit

Status: compatibility audit of the implemented procfs surface, 2026-07-31.

Target: present Linux-shaped procfs metadata and text formats to unmodified
Linux userspace without inventing kernel state that NARF does not track. This
is an audit of NARF's supported procfs slice, not a claim that every Linux
procfs node exists.

Primary format reference:
[Linux kernel procfs documentation](https://docs.kernel.org/filesystems/proc.html).

## Compatibility boundary

NARF's procfs is a synthetic VFS projection over scheduler, interrupt, memory,
mount, device, namespace, and fd-table providers. The relevant path is:

1. `register_proc()` mounts `ProcFs` during filesystem init.
2. VFS `resolve_async()` walks `ProcRoot`, per-PID directories, and registered
   dynamic subtrees.
3. procfs provider hooks query userspace task and namespace state.
4. Linux syscall adapters expose the resulting `FileOps` through
   `open(2)`, `read(2)`, `readlink(2)`, `stat(2)`, and `getdents64(2)`.

Semcode call-chain analysis covered all four seams. In particular:

- `register_proc` reaches the mount registry through `insert_into`.
- `resolve_async` reaches Linux syscall consumers through the userspace VFS
  path helpers and delegates to `resolve_async_ext`.
- `lookup_registry` feeds root and sysctl lookup plus aggregate generators.
- `task_info` feeds the per-PID status/stat/maps renderers.
- In systemd, `pidfd_get_pid_fdinfo` consumes `/proc/self/fdinfo`, while
  `mount_load_proc_self_mountinfo` feeds mount-unit enumeration.

## Audited surface

| Surface | Status | Compatibility notes |
| --- | --- | --- |
| procfs filesystem type | compatible | The mount type is `proc`, matching Linux mount tables and `/proc/filesystems`. |
| `/proc/self`, `/proc/thread-self` | compatible | Directory entries are symlinks, `st_size` is zero, and `readlink` uses the caller buffer size rather than `st_size`. |
| `/proc/<pid>/{exe,cwd,root,fd/*}` | compatible shape | Magic links report symlink mode with zero `st_size`; targets come from task/fd hooks. |
| `/proc/{uptime,loadavg,stat}` | compatible implemented fields | Uptime includes aggregate CPU idle time; loadavg's final field is a visible PID; stat includes per-vector interrupt and softirq rows. |
| `/proc/filesystems` | compatible shape | Pseudo filesystems use Linux's `nodev NAME` form and each filesystem appears once. |
| `/proc/<pid>/status` memory rows | compatible accounting shape | VmSize/VmData/VmStk use VMA extents; VmRSS uses resident pages instead of mirroring virtual size. |
| `/proc/<pid>/fdinfo/<fd>` | compatible implemented fields | Baseline `pos`, `flags`, `mnt_id`, and `ino` fields come from the live fd entry and backing VFS object. Provider absence produces neutral values rather than fabricated identity. |
| `/proc/<pid>/mountinfo`, `/proc/mounts` | compatible implemented fields | Rows use the `proc` filesystem name and task-visible mount/chroot projection. Optional Linux fields are omitted when NARF has no corresponding state. |
| `/proc/<pid>/ns/*` | compatible implemented flavours | Link text, symlink metadata, followed `open(2)` to an nsfs-like fd, and `setns(2)` work for UTS, network, IPC, PID, mount, user, and enabled cgroup namespaces. Initial namespaces retain stable identities; `O_PATH|O_NOFOLLOW` opens the link itself. |
| registered stub and bus nodes | compatible discovery shape | Existing proc stubs and `/proc/bus` are registered during procfs boot instead of being test-only unreachable code. |

## Findings corrected

- The generic `readlink` adapter sized its kernel staging buffer from
  `stat().size`. Linux procfs magic links intentionally report a zero size, so
  valid links returned an empty target. It now sizes from the caller's
  `bufsiz`, and procfs magic links report Linux's zero size.
- `ProcFs::name()` returned `procfs`, leaking a NARF-internal name into mount
  tables. It now returns Linux's `proc`.
- Static root files shadowed dynamic registrations for `stat` and
  `filesystems`, creating dead generators and duplicate directory entries.
  Each now has one authoritative implementation.
- `/proc/filesystems` omitted `nodev`; `/proc/uptime` fabricated zero idle
  time; `/proc/loadavg` used task count as a PID; and `/proc/stat` omitted
  available interrupt detail.
- `VmRSS` mirrored `VmSize`, while `VmData` and `VmStk` treated absolute
  addresses as byte counts. The renderer now derives all four rows from
  resident pages and VMA spans.
- Root directory enumeration mislabeled `self` as a directory and depended on
  a shadowed registration to expose `stat`.
- Boot registered neither the already-implemented proc stubs nor `/proc/bus`.
- The userspace `container` feature did not forward the filesystem feature,
  so procfs could publish zero namespace limits while namespace syscalls were
  active. The feature now propagates, and enabled builds omit limits for which
  NARF has no authoritative accounting provider.
- Namespace magic links now mint retained namespace descriptors through the
  normal open path, including stable initial mount and cgroup namespace
  identities. The same bridge also completes pidfd namespace ioctls.
- `fdinfo` now receives the live offset, open-file status flags, mount ID, and
  backing inode in the same provider snapshot as the fd link target.

## Remaining gaps

- Dynamic proc directory iteration currently interns generated names for the
  lifetime of the kernel because `DirEntry` carries a borrowed string. Removing
  that leak requires a VFS directory-entry ownership change rather than a
  procfs-only patch.
- Linux exposes many optional and subsystem-specific proc nodes that NARF does
  not implement. Missing nodes must remain absent or return a Linux-shaped
  error; adding plausible-looking fabricated data is not compatible behavior.

## Test gates

Changes to this surface must pass:

- `cargo fmt --all -- --check`
- host unit tests and both bare-metal clippy targets
- the procfs, procfs/pid_ext, procfs/aggregate, procsys, and syscall ABI smokes
- the full x86_64 and aarch64 kernel-test CI jobs
- the feature matrix, especially `linux-compat,container`

Any new text field needs a format assertion, and any dynamic value needs a test
that distinguishes it from a constant or a mislabeled unit.
