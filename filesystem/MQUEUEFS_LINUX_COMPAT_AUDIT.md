# Mqueuefs Linux compatibility audit

Audit scope: NARF's POSIX message-queue syscalls, fd semantics, IPC-namespace
isolation, the `mqueue` mount backend, VFS metadata/readiness, and notification
delivery.

The authoritative comparison tree is the local Linux checkout at
`/usr/src/linux`, commit `9bd577abc6fcf9c07995705220487f743e074de0`.
Load-bearing references are `ipc/mqueue.c`, `ipc/mq_sysctl.c`,
`include/uapi/linux/mqueue.h`, `include/linux/ipc_namespace.h`, and
`tools/testing/selftests/mqueue/`.

## Method

The audit followed both directions of the interface:

1. Linux `do_mq_open`/`mqueue_file_open` through the hidden per-IPC-namespace
   mount, inode creation, status reads, poll, unlink, send/receive,
   notification, and get/set attributes.
2. NARF syscall dispatch into `userspace/src/mqueue.rs`, fd-table hooks, mount
   dispatch, VFS `FileOps`/`DirOps`, namespace selection, signal delivery, and
   statfs translation.
3. Linux mqueue selftests for defaults, limit validation, priorities, and
   queue lifecycle.
4. Semcode MCP call-chain analysis at base commit
   `61b059d3aae9fb75dcaf0c16fdcbb59d0d94d6a1` for `sys_mq_open`,
   `sys_mq_unlink`, `sys_mq_timedsend`, `sys_mq_timedreceive`, and `build_fs`.
   It confirmed that all mq syscalls terminated in private global maps while
   both classic mount and the new mount API dispatched `mqueue` to an unrelated
   empty `MemFs`. It also showed that fd-to-queue resolution was centralized at
   `FileOps::mq_queue_id`, which is now the shared open-description seam.

## Implemented compatibility

| Surface | Linux contract | NARF result |
|---|---|---|
| Shared object model | Syscalls and mounted mqueuefs resolve the same inodes | Both use `filesystem::mqueuefs`; mounted names are live, not an empty `MemFs`. |
| IPC namespaces | Each IPC namespace owns an independent queue name table and mounts that view | Registry keys include the current `IpcNamespace::id`; mounts capture the caller's namespace. The initial namespace uses key 0. |
| Root and statfs | Root mode 01777, `MQUEUE_MAGIC` 0x19800202 | Root reports 01777 and statfs selects the Linux magic. |
| Queue metadata | Stable inode, creator uid/gid/mode, size 80 | Creation applies fsuid/fsgid and umask; lookup preserves identity and metadata. |
| Queue status file | Read reports QSIZE/NOTIFY/SIGNO/NOTIFY_PID with Linux widths | Byte count and active notification are rendered in Linux's exact text shape with offset-aware reads. |
| Directory operations | Named queues enumerate, resolve, create, and unlink | `DirOps` exposes the live namespace and shares unlink lifetime with `mq_unlink`. |
| Descriptor lifetime | Unlink hides the name while open mqd references remain usable | Name map owns an `Arc`; open descriptions retain the queue after removal. Recreating the name yields a distinct queue. |
| Open flags | Access mode is enforced; every mq fd is close-on-exec | Send on O_RDONLY and receive on O_WRONLY return EBADF. `mq_open` always installs `FD_CLOEXEC`, as Linux's `FD_ADD(O_CLOEXEC, ...)` does. |
| Nonblocking state | O_NONBLOCK belongs to the open file description | State is atomic on the shared open object, is independent between opens, survives dup/fork, and stays synchronized with mq_setattr/fcntl. |
| Attributes and limits | Defaults 10/8192; positive bounded attrs; only O_NONBLOCK settable | Defaults and Linux unprivileged/hard ceilings are checked; reserved output is zero; invalid setattr bits fail EINVAL. |
| Ordering and priorities | Highest priority first, FIFO within equal priority, priority less than 32768 | Send rejects `prio >= MQ_PRIO_MAX`; receive preserves priority/FIFO order. |
| Blocking/timeouts | Blocking descriptors sleep; timeout is absolute CLOCK_REALTIME; nonblock returns EAGAIN | Full/empty operations park without holding an IRQ-safe lock, wake on readiness, recheck state, and return ETIMEDOUT at the absolute deadline. |
| Poll | Readable when nonempty, writable below max | Queue files return POLLIN/POLLOUT and advance edge tokens on empty/full transitions. |
| Notification | One registration per queue; empty-to-nonempty is one-shot | `mq_notify` supports cancellation, EBUSY arbitration, SIGEV_NONE, and one-shot SIGEV_SIGNAL delivery; close removes an owned registration. |
| Error paths | Linux errno for bad fd, size, priority, names, permissions, and uaccess | Typed backend errors map to EBADF/EMSGSIZE/EINVAL/ENOENT/EEXIST/EACCES/ENOSPC; uaccess failures use EFAULT. |

## Remaining differences

These are explicit gaps rather than a blanket conformance claim.

### High priority

1. **SIGEV_THREAD netlink cookie protocol.** Linux treats SIGEV_THREAD as a
   libc protocol over an AF_NETLINK socket and a 32-byte cookie. NARF rejects
   SIGEV_THREAD until its netlink layer exposes that transport. Linux's
   mqueue implementation itself rejects other notification methods.
2. **Resource accounting.** Linux charges pinned queue storage to
   `RLIMIT_MSGQUEUE` per real user and maintains ucounts. NARF validates queue
   geometry and per-namespace queue count but does not charge byte ownership to
   rlimits/ucounts.
3. **Signal interruption and detailed siginfo.** Blocking operations wake for
   ordinary pending signals through the task scheduler, but the mq path does
   not yet explicitly return EINTR/restart codes, and SIGEV_SIGNAL currently
   queues the signal bit without Linux's SI_MESGQ siginfo payload/sigval.

### Medium priority

1. **Writable `/proc/sys/fs/mqueue`.** Linux exposes five per-IPC-namespace
   controls (`queues_max`, `msg_max`, `msgsize_max`, `msg_default`, and
   `msgsize_default`). NARF currently uses the Linux defaults as constants and
   has no writable procfs control nodes.
2. **Full capability/LSM policy.** Linux's CAP_SYS_RESOURCE bypass, audit
   records, security hooks, RLIMIT ownership, and user-namespace id mapping are
   richer. NARF applies fsuid/fsgid DAC and sticky-root unlink policy; uid 0 is
   the existing POSIX compatibility proxy rather than a new authority source.
3. **Generic pathname credential threading.** `mq_open` performs full DAC
   checks and `mq_unlink` enforces the sticky-root owner rule. Generic VFS
   opening or unlinking through a mounted queue pathname retains correct
   metadata and lifetime, but the current `FileOps::access(mask)` and
   `DirOps::unlink(name)` interfaces do not carry an `Accessor`; those
   secondary paths therefore cannot repeat the same credential checks yet.

## Regression coverage

Kernel smokes cover shared syscall/mount visibility, stable inode and 80-byte
metadata, exact status text, poll readiness, priority/FIFO ordering,
unlink-while-open lifetime, mode/umask/ownership, access modes, CLOEXEC,
per-open attributes/nonblocking state, priority bounds, expired absolute
timeouts, and one-shot signal notification.

The repository merge gates remain authoritative. This audit does not equate a
focused compatibility suite with exhaustive Linux selftest parity.
