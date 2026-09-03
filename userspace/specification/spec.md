# userspace — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 covered the
> Process abstraction + bootstrap + stable user-ABI promise;
> v1.0 locks the syscall versioning wire format that the
> drivers framework SDK mirrors, the PT_INTERP bootstrap, the
> POSIX-shim scope, and fork/exec semantics.

## 1. Purpose & scope

**Owns:** Process (and thread) abstraction at kernel level, ELF loader,
vDSO-like async-ring bootstrap page, relibc glue, minimal POSIX shim
surface that relibc needs.

**Does NOT own:** A specific shell / init / service manager. Those are
applications above NARF.

## 2. Assumptions

- `capabilities/` mints per-task cap tables.
- `ipc/` provides the ring pairs that a new process inherits.
- `memory/` allocates user address space and (optionally) a user PKU key.
- `scheduler/` schedules user tasks identically to kernel tasks (both
  are Futures).

## 3. Public interface

```rust
pub struct Process { /* cap table root, VM root, threads */ }
pub fn spawn_process(elf: &Elf, caps: CapBundle) -> Cap<Process, Own>;
pub fn exec_into(proc: &Process, arg0: &str, argv: &[&str], env: &[&str]);
```

`load_user_process_with_root` is the kernel-boot counterpart to an exec under
an already-established process root: it resolves a filesystem-backed
`PT_INTERP` beneath an explicit mounted-root prefix, and the caller installs
that same root on the reserved task before making it runnable. This permits a
dynamic service manager to be the direct PID 1 without a userspace chroot
launcher.

Architecture syscall reverse tables are unambiguous: every published wire
number resolves through `Syscall::from_raw` to a single canonical variant. On
aarch64, generic-ABI numbers such as `openat`, `newfstatat`, and `pipe2` are
not also assigned to legacy variants that the generic ABI omitted. Legacy
operations with NARF-private numbers remain available through that extension
ABI. The sole forward-only alias is `Syscall::raw(EpollWait)` on aarch64:
internal four-argument callers emit generic `epoll_pwait` number 22, whose
zero-sigmask behavior shares the same handler; reverse lookup canonically
returns `EpollPwait`.

The Linux new-mount compatibility surface includes `open_tree_attr(2)` at
wire number 467 on x86_64 and aarch64. It preserves Linux's error ordering:
the exceptional null-attribute/nonzero-size pair is rejected before path
lookup, while all other `mount_attr` validation follows successful tree
acquisition. Attribute failure publishes no descriptor and retains no detached
mount object. Extensible-record size, user-copy, trailing-byte, flag, atime,
propagation, and idmapped-mount errors use Linux errno values.

Linux `statx(2)` returns a stable `STATX_MNT_ID` whenever the resolved path
has a covering NARF mount, even when the request mask names only basic fields.
This is a deliberately useful Linux-permitted superset: service managers use
the mount ID together with type and inode to decide whether inherited API
filesystems are already mounted. `STATX_ATTR_MOUNT_ROOT` is advertised on
every response and set exactly when the resolved path is the visible mount
root, which is the modern systemd API-filesystem mount probe.

Linux `munmap(addr, len)` rejects an unaligned address or zero length and
rounds a non-page-multiple length upward. It removes only the overlapping
range, splitting VMAs as needed so a surviving prefix or suffix retains its
backing, permissions, and file-mapping lifetime reference. This does not alter
the v1 native `OpCode::Munmap` contract: that base-only ring operation still
removes the whole VMA beginning at `inline[0]` through its compatibility
bridge; changing it requires the ABI versioning process in `abi/` §4.

Linux-compatible anonymous private `mmap(2)` records lazy zero-backed VMAs;
the mapping syscall does not walk unrelated regions or allocate resident data
pages. Anonymous `MAP_SHARED` mappings eagerly allocate registry-owned frames,
retain them through the VMA and any fork aliases, and immediately remove their
internal shmem name; the last alias unmap reclaims the backing without retaining
one public registry entry per completed mapping until process exit.
The native mmap entry validates a page-aligned byte offset before descriptor
lookup, resolves non-anonymous descriptors before `do_mmap`-style validation,
rejects an exact zero length with `EINVAL`, and distinguishes fixed-address
misalignment (`EINVAL`), range exhaustion (`ENOMEM`), and the protected
low-address floor (`EPERM`) in Linux order.

File/device mapping publication holds the address-space transaction and that
address space's owner bucket while it atomically retires overlapping owners
and registers the new external owner. A `FILE_DEMAND` fault that observes
newly-published VMA metadata blocks on the same per-address-space transaction
until the file reference is visible; unrelated address spaces do not share
that lock. Deferred PTE
materialization and error rollback carry an opaque memory publication receipt;
a concurrent identical-address replacement makes the receipt stale and cannot
be materialized, removed, or registered by the losing syscall.

`mremap(2)` supports no-op resize, real tail shrink, in-place lazy grow,
`MREMAP_MAYMOVE`, disjoint `MREMAP_FIXED`, and `MREMAP_DONTUNMAP`. Private
relocation transfers resident backing without copying it; DONTUNMAP leaves a
lazy anonymous source range and transfers its lock contract to the
destination. One-Region base-page shared mappings support ordinary shrink,
in-place grow, MAYMOVE/FIXED relocation and equal-length DONTUNMAP, plus the
historical `old_len == 0` duplication form. Ordinary relocation transfers kept
backing and resident leaves, leaves a grown tail lazy, and releases a truncated
tail only after source invalidation. DONTUNMAP and legacy duplication instead
keep the backing owned by both VMAs; resident leaves move for DONTUNMAP and
clone for duplication. File-demand slices and SysV attachment/nattch state are
fallibly prepared and published atomically with every memory outcome,
including fixed target retirement and a later source-tail shrink on failure.
Huge, swapped, and cross-Region shared moves still fail explicitly.
Parameter checks precede VMA lookup as on Linux. Every accepted lookup,
resource-limit decision, resize, and move shares one address-space transaction,
so a CLONE_VM peer cannot replace the source between validation and mutation.
Growth checks locked bytes first (`EAGAIN`), then page-rounded `RLIMIT_AS` and
private-writable non-stack `RLIMIT_DATA` (`ENOMEM`), including Linux's
soft-DATA-zero/hard-limit compatibility rule. Fixed replacement conditionally
takes the global shared-backing transaction only when the target overlaps
borrowed backing; file/SysV owner rows are retired on success and on typed
post-punch failure, and eager locked-tail population runs after all IRQ-safe
transactions are released.

Linux-compatible `brk(2)` likewise changes only the address-space break and
its single anonymous heap VMA. Growth appends lazy zero-backed page slots and
does not allocate, zero, or materialize resident frames in syscall context;
first touch uses the ordinary user-reserve-aware demand-fault path. Shrink
retires only the rounded tail. Validation, `RLIMIT_DATA`/`RLIMIT_AS` and
inherited-memory-lock admission, VMA mutation, and break publication share one
address-space transaction, so CLONE_VM peers cannot publish a stale break.
Requests below the arena base, a metadata-allocation or overlap failure, and a
failed tail teardown return the previous break as required by the Linux syscall
ABI. `RLIMIT_DATA` includes the main executable's file-backed data span and is
checked against the byte-precise request before page alignment; `RLIMIT_AS`
charges page-rounded VMA growth but not NARF's synthetic stack-guard entry.

`mlock(2)` and `munlock(2)` round byte intervals outward to pages, reject a
non-empty range containing any unmapped page, and split VMAs so LOCKED applies
exactly to the visited request prefix; as on Linux, a later hole does not undo
flags already applied to earlier VMAs. A zero length is a successful no-op.
Plain `mlock` publishes LOCKED before eagerly populating anonymous and
file-demand pages, and population failure does not roll that flag back.
Malformed/wrapping range arithmetic returns `EINVAL`, an uncovered range
returns `ENOMEM`, and eager-population failure returns `EAGAIN`.
`mlock2(MLOCK_ONFAULT)` records LOCKED without populating lazy pages;
their ordinary first fault supplies backing that reclaim must then retain.
`munlock` clears the marker without discarding resident contents.
`mlockall(MCL_CURRENT|MCL_ONFAULT)` applies the same lazy pinning to existing
VMAs. `MCL_FUTURE` is address-space state shared by CLONE_VM tasks: ordinary
new mappings and `brk` growth inherit its eager or on-fault mode, while each
subsequent `mlockall` replaces the prior future policy. A CURRENT-only call
therefore clears an older future policy, FUTURE-only leaves current VMA lock
bits unchanged, and `munlockall` clears both in one address-space transaction.
Fork children start with neither current nor future memory locks. Eager
population performed for CURRENT or inherited FUTURE locking is best-effort
after the lock flags are published, matching Linux; stack guards and hardware
huge mappings are lock-exempt.

The family enforces the caller's process-shared `RLIMIT_MEMLOCK` against
virtual locked bytes, including lazy ONFAULT pages. Invalid flags precede the
authority check; a zero limit without authenticated lock authority returns
`EPERM`, `mlock`/CURRENT-limit excess returns `ENOMEM`, and locked `mmap` or
`mremap` admission returns `EAGAIN` before any fixed target is replaced.
`MAP_LOCKED` selects eager mode. Locked `brk` growth that exceeds the limit
returns the unchanged break. Rlimits are shared by CLONE_THREAD tasks, copied
by process fork/clone, and retired only when the process is reaped. Device/PFN
mappings, vDSO/vvar, kernel control rings, guards, and hardware huge mappings
are lock-exempt; inaccessible PROT_NONE reservations are not populated.
`setrlimit` validation and replacement are one process-table transaction.
`prlimit64` copies a proposed limit before PID/permission validation, returns
`ESRCH` for a nonexistent target, and requires the caller's real uid+gid to
match all representable target real/effective/saved IDs unless the target is
the exact caller. It retains the target task through the operation and
atomically snapshots the old value with any successful update. Automatic
stack expansion uses the faulting task's process-shared `RLIMIT_STACK`,
`RLIMIT_AS`, and `RLIMIT_MEMLOCK`; limit failure leaves its guard and PTEs
unchanged and reaches userspace through the Linux stack-fault `ENOMEM`/SIGSEGV
path.

Linux job-control state is process-shared. `setsid(2)` rejects an existing
process-group leader with `EPERM` without mutation; otherwise SID, PGID, and
controlling-terminal detachment publish under one fixed-order transaction and
the returned SID is translated into the caller's visible PID space. PTY
`TIOCSCTTY` accepts either endpoint, preserves Linux's same-session idempotent
success ordering, requires a detached session leader, applies the fd read-mode
check after ownership checks, and publishes raw session plus foreground group
together. PTY control IDs remain stable internal task identities and are
translated only by the querying `TIOCGPGRP`/`TIOCGSID` syscall. A slave query
requires that slave to be the caller's controlling tty; a master query bypasses
that ownership check. `TIOCSPGRP` on either endpoint requires the caller to
control the slave and distinguishes `ENOTTY`, `EFAULT`, `EINVAL`, `ESRCH`, and
`EPERM` in Linux order. NARF has no authenticated ambient `CAP_SYS_ADMIN`
bridge, so tty stealing and the unreadable-fd privileged bypass fail closed
with `EPERM`; emulated capset masks and uid zero never authorize them.

`mprotect(2)` requires a page-aligned address, rounds a nonzero length
upward, and validates complete coverage across base and hardware-huge VMAs
before changing any permission. `madvise(MADV_DONTNEED|MADV_FREE)` applies the
same length rounding and full-coverage rule to base-page mappings before
discarding resident private backing. Both treat a page-aligned zero-length
request as a successful no-op; failed hole validation leaves every mapped
fragment unchanged. `mincore(2)` samples the complete range under one coherent
address-space metadata snapshot, reports lazy pages as nonresident and
hardware-huge pages as resident base-page equivalents, and returns `ENOMEM`
for any hole without quadratically cloning a VMA's complete backing list once
per queried page.
`msync(2)` validates its complete rounded mapping, rejects unknown flags and
the mutually exclusive `MS_ASYNC|MS_SYNC` combination, then flushes retained
shared-file pages. `madvise(2)` accepts unimplemented performance-only hints
as no-ops, but unknown advice and semantic state controls such as DONTFORK or
WIPEONFORK fail with `EINVAL` until their observable behavior exists.

The Linux-compatibility syscall surface includes stored `prctl(2)` process
state required by service managers and brokers. Capability-shaped controls
such as `PR_SET_KEEPCAPS` round-trip according to the Linux ABI but do not mint
or retain NARF capabilities; authority remains capability-object based.
`SO_PEERSEC` and `SO_PEERPIDFD` report `ENOPROTOOPT` while NARF has no Linux
Security Module label provider or retained peer pidfd; the compatibility layer
never fabricates security identity. Supplementary groups are stored per task,
inherited across fork/clone, replaced and queried by `setgroups(2)` and
`getgroups(2)`, and captured on Unix endpoints at listen/connect/socketpair
time. `SO_PEERGROUPS` returns that immutable peer snapshot, translated into
the reader's user namespace; an undersized option buffer returns `ERANGE`.
AF_UNIX stream clients may bind a local pathname or abstract address before
`connect(2)`; binding does not put the socket into listening state. Connected
stream receive operations honor `MSG_PEEK` without consuming queued bytes.
Connected AF_UNIX `SOCK_SEQPACKET` and datagram socketpairs retain one record
per send; receive consumes at most one record and reports truncation through
the existing `MSG_TRUNC` result path. Per-record `SCM_RIGHTS` and
`SCM_CREDENTIALS` remain associated with that record; credentials snapshot the
sender's effective identity at send time. `SO_PEERCRED` snapshots connection
identity at `connect`/`listen`/`socketpair`. Stored credentials are
host-absolute and are translated into the receiving task's PID/user namespace,
with unmapped uid/gid values reported as the overflow id.
Invalid SCM_RIGHTS descriptors fail `sendmsg` with `EBADF` without sending the
payload. A received descriptor retains the sender's file status flags, including
`O_NONBLOCK`; sender fd-slot flags are not copied, and `FD_CLOEXEC` is set only
when the receiver requests `MSG_CMSG_CLOEXEC`. Insufficient ancillary space
reports `MSG_CTRUNC`. On byte-stream Unix
sockets, rights are associated with the first byte of their `sendmsg`; they are
delivered only by a receive that reaches that byte, and an ordinary
`read`/`recv` consumes and discards them rather than exposing them to a later
`recvmsg`.
Epoll readiness callbacks run without holding the parent epoll instance lock,
including during edge-state write-back for nested epoll sets.
Epoll interest records retain a weak reference to the watched open file
description. Descriptor-number reuse cannot retarget an existing watch, a
duplicate descriptor keeps the watch live after the original descriptor
closes, and final close invalidates the watch without the epoll instance
artificially retaining the file. `EPOLLERR` and `EPOLLHUP` are delivered
regardless of the registered interest mask, matching Linux epoll semantics.
`poll(2)` and `ppoll(2)` likewise report `POLLERR`, `POLLHUP`, and
`POLLNVAL` without requiring those bits in the requested event mask.
`select(2)` and `pselect6(2)` use Linux's distinct fd-set mapping: hangup and
error make a requested read set ready, error makes a requested write set
ready, and only priority/OOB data makes a requested exception set ready.
Their return value counts ready result-set bits (so one descriptor ready in
two sets contributes two), and an invalid selected descriptor returns `EBADF`.
Bad fd-set, timeout, signal-mask, or pselect argpack pointers return `EFAULT`;
negative descriptor counts, invalid timeout fields, and an invalid non-null
signal-mask size return `EINVAL`. Descriptor counts are signed 32-bit values
and positive counts are clamped to the process fdtable's current `max_fds`,
not libc's `FD_SETSIZE`; only the native-word-rounded prefix of each set is
accessed. Empty sets still perform an interruptible timeout wait. `pselect6`
installs its validated temporary signal mask atomically for the whole wait and
restores the prior mask on readiness, timeout, or post-handler `sigreturn`.
Both raw syscalls retain nanosecond deadline precision and best-effort write
the remaining timeout back without replacing the syscall's primary result if
that write-back faults.
An epoll wait accepts at most `maxevents` entries. Only entries actually
returned to the caller advance edge-trigger tokens, acknowledge provider-local
readiness, take an exclusive claim, or disarm `EPOLLONESHOT`; additional ready
entries remain pending for a later wait. Successive waits round-robin through
ready level-triggered entries when the ready set exceeds `maxevents`.
Poll and epoll pass the file-description offset to offset-sensitive readiness
providers; `/dev/kmsg` is readable only while unread snapshot bytes remain.
Edge-triggered epoll also records provider-local monotonic state tokens.
Connected socket rings advance their token only on readiness transitions
(empty to non-empty, full to non-full, and closure), so reads and writes that
leave readiness unchanged do not synthesize edges. A drain followed by new
data before the next `epoll_wait` remains a deliverable edge even though both
sampled readiness masks contain `POLL_IN`.
Blocking stream `send(2)` and `sendmsg(2)` park on the connected ring's durable
writable readiness when no byte fits, then re-execute after space or closure is
published. `O_NONBLOCK` and `MSG_DONTWAIT` return `EAGAIN` immediately.
`sendmmsg(2)` returns an already-transmitted prefix without retrying it; when
its first message would block it follows the same park-or-`EAGAIN` rule.
Native `read(2)`, `write(2)`, `readv(2)`, and `writev(2)` resolve the
descriptor and required access mode before user-range or iovec import,
including zero-length operations. Scalar buffers and every imported iovec are
validated before I/O, vector counts above 1024 return `EINVAL`, and effective
length is capped at Linux `MAX_RW_COUNT`. Transfers use bounded kernel staging,
preserve exact filesystem errors before progress, return an accepted prefix
after progress, and distinguish blocking, `O_NONBLOCK`/`EAGAIN`, interrupting
signals/`EINTR`, and broken-pipe `SIGPIPE`/`EPIPE`. A writev no larger than
`PIPE_BUF` reaches a pipe as one write transaction across iovec boundaries.
Anonymous-pipe and named-FIFO reads hold their queue prefix until the complete
guarded scalar or vector user copy succeeds, so a protection change racing
validation cannot consume unread bytes. NARF's byte queues do not retain Linux
pipe-buffer/write boundaries, so the selected prefix is one logical buffer:
an iovec fault after an earlier copied fragment still leaves that whole prefix
queued, matching Linux's rule that the currently faulting pipe buffer is not
consumed. Fanotify removes a selected event on a copy fault as Linux does, but
reserves its object-fd numbers invisibly and publishes those fds only after the
complete metadata copy succeeds; EFAULT therefore cannot leak an object fd.

Each fd slot references a separate shared open-file-description object for
file position and mutable status flags. `dup*`, `F_DUPFD`, fork inheritance,
and `SCM_RIGHTS` alias that object, while `FD_CLOEXEC` remains per descriptor;
independent opens create independent descriptions. Consequently `lseek`,
sequential I/O, readiness-at-offset, `/proc/*/fdinfo`, and `F_GETFL/F_SETFL`
observe changes made through any alias. Stdin is `O_RDONLY`, stdout/stderr are
`O_WRONLY`, and sockets/socketpairs are `O_RDWR`; constructors do not rely on
type-based access-mode exceptions. Sequential transfer syscalls pin these
descriptions, lock distinct implicit positions in stable address order (or an
alias once), snapshot positions only after locking, and commit directly to the
pinned descriptions rather than a numeric fd that may have been closed and
reused. Independent `O_APPEND` opens share an inode/FileOps append lock held
across EOF selection and write, while their ordinary positions remain
independent.

The native send-family preserves Linux validation and errno ordering.
`send(2)` validates a non-empty payload range before descriptor lookup;
`sendmsg(2)` and `sendmmsg(2)` reject the kernel-only compat-control flag
before distinguishing `EBADF` from `ENOTSOCK`, then import the complete native
message header, address, iovec array, ancillary data, and payload without
discarding user-copy failures. More than 1024 vectors returns `EMSGSIZE` and an
unrepresentable ancillary length returns `ENOBUFS`. `sendmmsg` resolves its
socket even when `vlen` is zero, caps `vlen` to 1024, returns the exact first
message or `msg_len` write-back error when no message completed, and suppresses
a later error only in favor of the number of already-completed messages.
`sendfile(2)` imports and later writes back its optional 64-bit offset even
when the transfer result is an error. It validates the readable input fd and
explicit-offset seekability before resolving the writable output fd, rejects
an append-mode output, clamps successful transfers to Linux `MAX_RW_COUNT`,
and advances input and output positions only by bytes accepted by the sink.
Exact filesystem, `EAGAIN`, broken-pipe/`SIGPIPE`, and user-copy errors are
preserved; zero count still performs fd and mode validation. NARF stream
inputs currently fail closed because their `FileOps` do not expose Linux's
transactional `splice_read` source operation.
`copy_file_range(2)` likewise serializes and commits implicit positions through
the pinned descriptions. Explicit `loff_t` imports and write-backs use guarded
user copies, so an unmapped or concurrently protected offset word returns
`EFAULT` rather than silently supplying zero or reporting success.
`splice(2)` returns zero for zero length before inspecting flags, descriptors,
or offsets. Nonzero calls reject bits outside `SPLICE_F_ALL`, resolve input
then output, reject a pipe-side offset with `ESPIPE` before user access, import
`off_out` then `off_in`, and only then validate read/write modes and the
one-pipe-required shape. Explicit non-pipe offsets are advanced only by the
accepted prefix and are written back after a nonnegative result. Endpoint
`O_NONBLOCK` implies `SPLICE_F_NONBLOCK`; empty/full live pipes park or return
`EAGAIN`, while a closed sink raises `SIGPIPE` and returns `EPIPE`. Pipe moves
are transactional: a short sink consumes only the accepted source prefix.
Linux `vmsplice(2)` preserves the kernel entry-point's observable validation
order: unknown flags are rejected before descriptor lookup; descriptor and
access-mode errors precede iovec import; a valid descriptor's iovec copy and
per-segment range errors precede the non-pipe and full-pipe checks. A NULL
zero-segment iovec and any imported zero-total vector return zero before pipe
identity or readiness is sampled. A valid nonblocking transfer into a full
pipe returns `EAGAIN` only after those validations have succeeded. `O_PATH`
remains part of the stored open-file status and represents neither readable nor
writable mode, so `vmsplice` returns `EBADF` before importing its iovec. Both
anonymous-pipe and named-FIFO read ends copy then commit each destination
segment: a failed user copy cannot consume that segment's queued prefix, and a
failure after earlier segments returns only the already-copied byte count.
Native `getdents(2)` and `getdents64(2)` resolve the descriptor before touching
the output range and distinguish `EBADF` from `ENOTDIR`. They snapshot a bounded
directory batch per call, including the synchronous iterator fallback, so both
wire formats retain linear full-directory traversal. Backend failures retain
their Linux errno instead of becoming a false end-of-directory. A first record
that cannot fit returns `EINVAL`; a first copy fault returns `EFAULT`; after any
complete record, a later size, allocation, or copy failure returns the completed
byte prefix and advances the directory cursor only through that prefix. The
unsigned `count` argument is truncated to its native 32-bit ABI width.
System V semaphore operations use Linux's default 500-operation `SEMOPM`
boundary and validation order: `E2BIG`/zero-count validation precedes sembuf
import, import faults are `EFAULT`, and `semtimedop(2)` imports its timeout
first but validates its fields after the sembufs. Multi-operation changes are
atomic. An imported `sem_num` outside the selected set returns `EFBIG` before
the permission check. Only `SEM_UNDO` and `IPC_NOWAIT` affect `sem_flg`; Linux's
other extension bits are accepted and ignored. A first `SEM_UNDO` flag,
including on a zero operation, fallibly prepares the complete per-set
adjustment array after set-id lookup but before member and permission checks;
allocation failure therefore returns Linux's `ENOMEM` precedence. Blocking operations park
interruptibly unless their blocking sembuf has `IPC_NOWAIT`; relative timed
waits retain one absolute deadline across park/re-execution. Imported operation
arrays and message payloads remain
kernel-owned across that wait, so later user-memory mutation cannot alter an
in-flight operation. Semaphore waiters are appended and evaluated in queue
order after each relevant mutation, but an older operation that remains
unsatisfied is skipped as on Linux. Eligible operations commit their semvals,
`SEM_UNDO`, `sempid`, timestamp, and terminal result while the semaphore-state
lock is still held; task wakeups occur after unlocking. Each task owns one
replaceable durable waker, so repeated polls are deduplicated, a completion
that precedes waker registration is observed on the registration recheck, and
scheduler migration is transparent. Infinite waits have no polling deadline;
timed waits return `EAGAIN`, signals return `EINTR`, and removal returns
`EIDRM`, with the first terminal transition winning. `SEM_UNDO` adjustments are
accumulated per process, atomically committed with the operation, shared by
`CLONE_SYSVSEM`, cleared by `SETVAL`/`SETALL`, and reversed when the final
sharing process exits. Exit applies every adjustment for one semaphore set
before scanning its wait queue, so no operation observes a member-wise
intermediate state.
Semaphores retain Linux's per-member `sempid`: successful `semop` entries,
including zero waits, `SETVAL`, every member of `SETALL`, and exit-time undo
publish the responsible process, which `GETPID` translates into the querying
task's PID namespace. `GETNCNT` and `GETZCNT` count retained operations by only
the first blocking sembuf from their most recent atomic evaluation;
interruption, timeout, successful retry, task exit, or set removal retires that
waiter state. The counts are exact per-set integer state updated with queue
linkage, so reads are O(1); they are not approximate per-CPU telemetry. System V
message send imports the type and payload before queue lookup, reports copy
faults as `EFAULT`, and reports payload or queue-record allocation failure as
`ENOMEM` without partial publication. Queues enforce
Linux's default 16-KiB byte and zero-length-message count limit; full blocking
sends park, while `IPC_NOWAIT` returns `EAGAIN`. Receive supports Linux type
selection, `IPC_NOWAIT`, `MSG_NOERROR`, `MSG_EXCEPT`, and `MSG_COPY`; an
oversize receive without `MSG_NOERROR` returns `E2BIG` without dequeueing.
Normal receives select and unlink the exact record in one locked queue
transaction before copying the type and payload to userspace in Linux order;
an ordinary `EFAULT` therefore consumes the selected message, while `MSG_COPY`
retains it.
Message queues and their sender/receiver wait records share one publication
transaction: an operation is linked before its observed condition can change,
and removal publishes `EIDRM` before the id disappears. Queue changes retain a
recheck edge beside one replaceable task waker, so completion before waker
registration, repeated polls, and scheduler migration are lossless without the
generic 1-ms I/O polling deadline; wakers fire only after the state lock is
released. Queue removal wakes staged semaphore, sender, and receiver waits with
`EIDRM`.
Native `semctl(2)` and `msgctl(2)` implement architecture-correct IPC-64
`IPC_STAT` layouts and full-structure-before-lookup `IPC_SET` import ordering;
owner, creator, mode, supplementary-group, queue-limit, metadata timestamp,
message count/byte count, and last-sender/receiver fields follow Linux.
`semctl(2)` also implements `IPC_INFO`, `SEM_INFO`, `SEM_STAT`, and
`SEM_STAT_ANY`: information calls report Linux's default SEMMNI/SEMMSL/SEMMNS,
SEMOPM, SEMVMX, and undo limits together with namespace-local live usage;
indexed-stat returns the full semaphore-set id, and `SEM_STAT_ANY` alone
bypasses ordinary read-mode checks. Semaphore creation accepts 32,000 members
per set, admits at most 32,000 live sets and 1,024,000,000 members per
namespace, and reports `ENOSPC` at the resource boundaries.
`msgctl(2)` also implements `IPC_INFO`, `MSG_INFO`, `MSG_STAT`, and
`MSG_STAT_ANY`: information calls snapshot only the caller's IPC namespace and
return its highest internal queue index, indexed-stat returns the full queue id,
and `MSG_STAT_ANY` alone bypasses ordinary read-mode checks. Queue information
uses Linux's native 32-byte `msginfo` layout and default MSGMNI/MSGMNB/MSGMAX
limits. Creation admits at most 32,000 live queues per namespace and reports
`ENOSPC` at that boundary. Last-sender and last-receiver identities are retained
as outer process ids and translated into the querying task's PID namespace at
copyout.
Shared-memory, semaphore, and message identifiers and key lookups are scoped
to the caller's current IPC namespace. Ordinary clone/fork inheritance shares
the same namespace object and tables; `CLONE_NEWIPC` creates fresh empty tables
with independent per-family id allocation, so equal numeric ids in different
namespaces never alias. `CLONE_NEWIPC|CLONE_SYSVSEM` is rejected with `EINVAL`.
The final task/ns-fd reference removes semaphore and message objects and wakes
their waiters with `EIDRM`; shared-memory ids disappear at namespace teardown
while already-attached VMAs retain their backing until final detach.
System V shared-memory attachment follows Linux's native 64-bit ABI and
validation order. `shmat(2)` validates signed ids and address shape first,
rounds `SHM_RND` addresses to `SHMLBA`, requires a non-null address for
`SHM_REMAP`, ignores otherwise unknown attach bits, and checks the requested
read/write/execute permission before mapping. A fixed attach rejects overlap
with `EINVAL` unless `SHM_REMAP` is present; replacement, registration, and
materialization maintain exact rollback and backing-lifetime accounting.
`SHM_RDONLY` and `SHM_EXEC` produce the corresponding shared VMA permissions.
Attachments retain their original detach address across VMA splits and partial
replacement. A single mm-level transaction serializes SysV VMA creation,
fixed-range punching, attachment publication/removal, and `shm_nattch` changes
across `CLONE_VM` siblings. `munmap(2)`, `MAP_FIXED`, `SHM_REMAP`, and an
`MREMAP_FIXED` destination replacement update `shm_nattch`; a
later `shmdt(2)` removes every surviving VMA fragment belonging to the selected
logical attachment. Fork duplicates each inherited attachment and its count,
whereas `CLONE_VM` processes share one mm-level attachment; exec and final
process exit close the old address space's attachments. Segment backing belongs
to the IPC object rather than its creator process. `IPC_RMID` removes the public id and key immediately but
defers backing destruction until the final attachment closes. Native
`shmctl(2)` imports the complete `shmid64_ds` before an `IPC_SET` lookup,
resolves and permission-checks `IPC_STAT` before copyout, and reports owner,
mode, size, creator/last-operation pids, attach count, and timestamps at their
architecture ABI offsets. `IPC_INFO` reports the configured eager-backing
SHMMAX/SHMMNI/SHMALL limits; `SHM_INFO` aggregates namespace-local live ids and
resident pages; `SHM_STAT` returns the full indexed id, while `SHM_STAT_ANY`
alone bypasses the read-mode check. `SHM_LOCK` and `SHM_UNLOCK` enforce Linux's
owner/creator rule and `RLIMIT_MEMLOCK` error classes, retain per-user charges
until delayed backing destruction, expose `SHM_LOCKED`, and make registry
frames ineligible for explicit NUMA migration. `ShmemSyscallVtable` exposes
the backing limit, per-frame lock query, and whole-handle charged lock/unlock
operations needed to keep those semantics coupled to backing lifetime.
AF_UNIX listeners likewise advance a readable token whenever `connect(2)`
queues an accept-ready endpoint. Accepting the final pending endpoint followed
by a new connection before the next epoll scan remains a deliverable
`EPOLLIN|EPOLLET` edge even though both sampled masks contain `POLL_IN`.
Readable and writable tokens are independent and epoll correlates each token
only with its matching ready bit; a hidden receive-and-drain cycle cannot
manufacture `EPOLLOUT` on a continuously writable socket.
Eventfd advances the same directional tokens on zero-to-nonzero and
saturated-to-writable transitions. A counter drain/refill between epoll scans
therefore remains a deliverable `EPOLLIN` edge.
Anonymous pipes advance readable and writable tokens on empty-to-nonempty,
full-to-space, and peer-close transitions. Timerfd advances its readable token
when an armed deadline creates the first pending expiration.
Inotify advances its readable token only when its event queue changes from
empty to nonempty, preserving a drain/refill edge without retriggering merely
because another event joined an already-readable queue.
Signalfd uses a per-task pending-set generation that advances only when the
set changes from empty to nonempty, including the allocation-free IRQ raise
path.
Queued-signal syscalls import the complete native kernel `siginfo` prefix before
publishing pending state. `rt_sigqueueinfo` and `rt_tgsigqueueinfo` require a
readable non-null info pointer and preserve Linux's `EFAULT`-before-argument
validation ordering; invalid targets and signals report `ESRCH` and `EINVAL`
respectively without delivery. `pidfd_send_signal` rejects unsupported flags
before fd resolution, validates non-null `si_signo`, checks that the pidfd still
names a live target (including signal 0 probes), and never queues a payload or
pending bit after a failed import or validation.
Explicit stream shutdown publishes the same readiness notification as final
descriptor close; a peer parked in an infinite poll/epoll wait wakes to
`POLL_IN|POLL_HUP` and can consume EOF.
Connected unnamed AF_UNIX peers, including `socketpair(2)` endpoints, report a
minimal `sockaddr_un` containing only `sa_family` from `getpeername(2)`;
truncated output still reports the full address length.
`open(2)`/`openat(2)` reject an empty pathname with `ENOENT` before cwd
normalization; an empty path never aliases the current directory. Linux path
and descriptor failures return their specific errno rather than a bare `-1`:
in particular `openat(2)` reports `EFAULT`, `EMFILE`, and mapped filesystem
errors, while `newfstatat(2)` distinguishes `EFAULT`, `ENOENT`, `EBADF`,
`ENOTDIR`, and invalid flag `EINVAL`.
The chmod/chown syscall families resolve relative `*at` paths through a real
directory fd, reject invalid flags and dirfd shapes with Linux errnos, and
follow the final symlink unless `AT_SYMLINK_NOFOLLOW` selects the link inode.
Legacy `fchmodat` always uses zero flags; `fchmodat2` supports
`AT_EMPTY_PATH`, including `AT_FDCWD` naming cwd. Chmod preserves all `07777`
mode bits. Chown preserves a field requested as `(uid_t)-1` and clears setuid
and setgid on non-directories. Successful disk-backed metadata calls return
only after persistence; failures do not emit an attribute notification.
Credential-based authorization of these mutations is not yet enforced by the
Linux-compatibility shim; capability-based filesystem authority remains the
security boundary.
`clock_gettime(2)` accepts realtime/monotonic coarse clocks and process/thread
CPU clocks. Coarse clocks currently use the precise source; CPU clocks use the
calling task's accumulated user and kernel accounting.
`sched_setscheduler(2)` accepts Linux's `SCHED_RESET_ON_FORK` modifier on every
otherwise-supported policy; the cooperative scheduler retains compatibility
state without assigning Linux real-time scheduling authority.
`sched_yield(2)` returns success after checking pending signals. An own-stack
task transfers to the executor when another runnable task, deferred wake, due
timer, or staged cross-CPU wake can use the CPU; when the caller is the sole
runnable task it returns directly because an executor round could only select
that same task. Queue contention conservatively preserves the transfer.
Anonymous pipes implement `FIONREAD` on both ends and report the shared
immediately-readable byte count. Writes and final endpoint closure publish a
readiness notification so parked `poll`/`epoll` waiters wake without unrelated
system activity. A write after the final reader closes raises `SIGPIPE` and
returns `EPIPE`. Blocking pipe reads and writes use FIFO exclusive readiness
waits: one consumable transition wakes one blocked syscall, while all ordinary
poll and persistent epoll observers still wake. This mirrors Linux's
`wait_event_interruptible_exclusive` pipe queues and avoids a reader or writer
thundering herd without changing readiness or errno semantics. Final endpoint
closure uses the corresponding wake-all path so every blocked peer runs to
observe EOF or `EPIPE`.
Readiness wakeups are being consolidated behind a single durable per-descriptor
cell (`narf_lib::readiness::Readiness`): registering a waiter and checking the
current readiness are fused under one lock, so a `poll`/`epoll` waiter can never
register after the edge it was waiting for — the lost-wakeup race is
unrepresentable rather than merely guarded by a re-checked generation and a
fallback tick. Every readiness change wakes all intersecting ordinary waiters
and the oldest intersecting exclusive waiter intrinsically (there is no
per-source "does this notify" flag to drift out of sync), and the level mask and
the edge sequence advance together under that same lock. The wake this delivers
is required to be durable end-to-end: a readiness
source firing from IRQ context re-queues the stable, task-id-addressed run slot
with a lossless atomic, never an allocation-bearing waker drop deferred through
a bounded queue — so a readiness edge is never dropped and then recovered only
by a coarse fallback tick.
Legacy `clone(2)` honors `CLONE_PIDFD` by installing a pidfd in the parent and
writing its descriptor through the overloaded `parent_tid` pointer argument.
Both legacy `clone(2)` and `clone3(2)` create resumable user tasks on x86_64
and aarch64 through the same architecture-neutral process/lifecycle path; the
architecture boundary is limited to Linux's register ordering, saved return
register/stack fields, and the user TLS register (`IA32_FS_BASE` or
`TPIDR_EL0`). The child resumes after the syscall with zero while the parent
receives its PID/TID. `clone3` enforces Linux's 64-byte v0 minimum, one-page
maximum, zero-only unknown tail, paired stack fields, valid exit signal, and
flag dependency rules before allocating or publishing a child. These failures
surface as Linux `EINVAL`, `EFAULT`, or `E2BIG`; task exhaustion is `EAGAIN`
and address-space construction failure is `ENOMEM`. Requested `set_tid` PID
injection is refused with `EPERM` because no checkpoint/restore capability is
present on this syscall interface.
On both architectures, each user task enters and resumes EL0/CPL3 with a
dedicated scheduler-owned kernel stack. Timer preemption retains the complete
trap continuation, FP/SIMD image, address space, and TLS value; a TLS value of
zero is restored explicitly rather than treated as an unpublished sentinel.
On aarch64, switch-out reads live `TPIDR_EL0` because EL0 may update it without
a syscall, fork/clone inherit that live value and FPSIMD image, and exec clears
both in line with Linux arm64 `copy_thread`/`flush_thread` semantics.
Private futex wait queues are keyed by `(address-space identity, user address)`;
`CLONE_VM` threads share wakes, while unrelated processes that map the same
virtual address cannot consume one another's `FUTEX_WAKE_PRIVATE` events.
Classic `FUTEX_WAIT` returns `EAGAIN` when the user word no longer equals the
expected value; a stale wait is never reported as a successful wake.

Linux NUMA compatibility reports live topology rather than a structural
single-node stub: `getcpu(2)` returns the current logical CPU and its
SRAT proximity node, while `move_pages(2)` walks the caller's page tables,
reports physical placement, and can replace resident private backing on
another node. `migrate_pages(2)` moves the caller's resident private pages
between node masks. Fault-time `set_mempolicy(2)` and `mbind(2)` placement
is intersected with the task's cgroup-v2 `cpuset.mems.effective` mask;
`get_mempolicy(MPOL_F_MEMS_ALLOWED)` reports that effective constraint.
`get_mempolicy(2)` rejects unknown/conflicting flags, undersized nodemask
buffers, and addresses supplied without `MPOL_F_ADDR`; address+node
queries fault in valid lazy pages and report their actual SRAT node.
`MPOL_F_STATIC_NODES` preserves physical node identities across cpuset
changes; `MPOL_F_RELATIVE_NODES` maps user-mask ordinals into the current
`cpuset.mems.effective` set and folds oversized ordinals as Linux does.
Both use Linux UAPI bits 15 and 14. `MPOL_PREFERRED_MANY` chooses the
nearest member of its preferred set by SLIT distance and falls back only
after preferred nodes are exhausted.
`MPOL_WEIGHTED_INTERLEAVE` distributes new base-page and hardware-huge-page
allocations according to the global per-node weights, while still intersecting
the policy mask with `cpuset.mems`. Weights are configured through Linux's
`/sys/kernel/mm/mempolicy/weighted_interleave/nodeN` ABI.
Automatic mode consumes real local-node HMAT access-bandwidth coordinates,
reduces them to bounded integer ratios, and is controlled by the sibling
`auto` attribute. A manual node-weight write disables automatic mode.
Ordinary and weighted interleave sequence positions are task-owned, survive
CPU migration, and are reclaimed with the task; CPU-local allocator state
does not determine a process's placement cycle.
`MPOL_F_NUMA_BALANCING` is accepted only with `MPOL_BIND` or
`MPOL_PREFERRED_MANY`. A bounded periodic scan protects one eligible base page
per task every 256 running timer ticks. Its next access restores the mapping
and, when the accessing CPU's node is inside the effective policy/cpuset mask,
migrates the private page there. Shared, locked, lazy, and policy-ineligible
pages are not sampled; allocation failure restores the original mapping.
`mbind(MPOL_MF_MOVE)` immediately conforms resident private pages in the
range, `MPOL_MF_STRICT` reports remaining misplacement as `EIO`, and
`MPOL_MF_MOVE_ALL` requires authority NARF does not grant ambiently.
`set_mempolicy_home_node(2)` updates the distance anchor of existing
MPOL_BIND or MPOL_PREFERRED_MANY ranges and returns `ENOENT` when no
eligible policy overlaps.
`move_pages(2)` migrates registry-owned shared-memory base pages by replacing
every live address-space alias under one rollback-capable transaction and
committing the shared-object backing last. Device/DMA shared mappings remain
non-migratable without an owner-specific quiesce protocol.
Removing a shared-memory handle rejects new attachments immediately but keeps
each already-mapped backing page registered and movable until its final
address-space alias is unmapped. Alias release occurs only after leaf teardown
and cross-CPU TLB invalidation; the final release returns the frame to the
allocator.
Anonymous private `mmap(MAP_HUGETLB)` supports Linux's default/explicit
2 MiB and explicit 1 GiB encodings when boot-reserved backing is available.
Mappings use hardware PD/PDPT leaves on x86_64 and L2/L1 block descriptors
on aarch64; allocation honors the effective task/range mempolicy and
`cpuset.mems`. A multi-leaf mapping precomputes the per-leaf policy sequence
and acquires the huge pool once; exhaustion rolls back the complete vector
before `mmap` returns `ENOMEM`. `move_pages`, `migrate_pages`, and
`mbind(MPOL_MF_MOVE)`
migrate complete hardware leaves between per-node pools while preserving
contents; `mprotect` operates at the selected hugepage granularity, `munmap`
returns backing to its per-node pool, and `fork` eagerly copies private huge
mappings on their original nodes. File-backed hugetlbfs and shared huge
mappings fail explicitly because NARF has no hugetlbfs or shared-huge refcount
contract.
The procfs task snapshot includes both base-page and hardware huge-page
regions with effective policy and per-node residency for
`/proc/<pid>/numa_maps`.
Basic procfs task snapshots obtain virtual size, resident pages, writable data,
and stack size from allocation-free address-space aggregates. Per-region VMA
materialisation is query-gated to `/proc/<pid>/maps` and `numa_maps`, so a
metadata or liveness read cannot require contiguous kernel memory proportional
to the target's VMA count.
Linux `readlink(2)` and `readlinkat(2)` size their kernel staging read from
the caller's `bufsiz`; they never treat `st_size` as the target length.
This is required for procfs magic links, whose Linux-compatible stat metadata
has a zero size even when `readlink` returns a non-empty target.
The `container` Cargo feature enables namespace support in both userspace and
`narf-filesystem`; procfs must therefore never publish zero namespace limits
in a build where the namespace syscalls are enabled.
Opening a followed `/proc/<pid>/ns/<flavour>` magic link installs an `NsFd`
that retains the named namespace and is accepted by `setns(2)`. An
`O_PATH|O_NOFOLLOW` open retains symlink-node semantics. Initial UTS, network,
IPC, PID, mount, user, and enabled cgroup namespaces have stable nonzero
identities even before a task unshares them.
Sysfs exposes Linux memory blocks under `/sys/devices/system/memory/memoryN`
and each block's `nodeN/memoryN` membership from allocator RAM ranges
classified by SRAT; CPU topology is never used to infer memory membership.
Runtime hotplug creates newly discovered `memoryN` objects after allocator
commit. Offline blocks retain their identity and node membership, while
`state` and `online` query live topology across offline/online cycles.
Only CPU- or memory-bearing `nodeN` directories are instantiated; unused
architectural slots remain advertised through `possible` without appearing as
phantom nodes to Linux perf's directory-based topology reader. Membership is a
Linux-compatible `nodeN/memoryM -> ../../memory/memoryM` symlink.

Bootstrap: every new process receives two ring pairs (submit + complete)
for the kernel ABI plus a read-only config page with capability
handles to its parent-granted services. Additional ring pairs for
inter-service communication are obtained by presenting `Cap<RingPair,
Alloc>` to the kernel's ring-pair allocator. The bootstrap config page
includes one `Cap<RingPair, Alloc>` as a pre-granted capability.

**Maximum ring pairs per process: 64 (default; system-wide tunable).**
Exhaustion fails subsequent allocations with `Err(RingPairBudget)`.

The stack-daemon launcher keeps `StackAttachReply::admin` in kernel memory and
may bind it to an `AF_NETLINK`/`NETLINK_ROUTE` fd owned by the current task.
The fd is resolved through that task's table and the typed `SocketFile`; no raw
`AdminHandle` or capability slot is accepted through the Linux syscall ABI.
A public native cap-bearing operation remains unavailable until submissions
are validated against a real per-task capability table.

### 3.1 Linux perf-event compatibility

With `linux-compat`, the slow syscall table exposes Linux
`perf_event_open(2)`. The returned fd implements the counting subset of the
Linux perf-event ABI: `read(2)` according to `attr.read_format` and
`PERF_EVENT_IOC_{ENABLE,DISABLE,RESET,ID}`. Group members opened against a
perf-event leader participate in group-format reads and group-flag lifecycle
ioctls. `enable_on_exec` events are registered weakly by target task and the
shared successful `execve`/`execveat` commit path activates the leader and all
members; failed exec attempts do not activate them. The process group-dead
observer stops task-targeted leader groups before the monitoring process reads
their terminal values. This is a compatibility adapter over `observability/`
PMU authority, not an independent counter subsystem.

For task targets, `PERF_COUNT_SW_CPU_CLOCK` derives exact time from the
target's user and syscall CPU-time ledgers. For per-CPU targets it derives
exact user time from scheduler continuation brackets and exact non-idle time
from the per-CPU idle ledger; kernel-only time is their difference.
`PERF_COUNT_SW_TASK_CLOCK` uses the corresponding per-task ledgers. Matching
Linux, privilege exclusion flags do not split software CPU/task clocks:
`cpu-clock`, `cpu-clock:u`, and `cpu-clock:k` (likewise `task-clock`) count the
same scheduled time. Hardware `exclude_kernel` and
`exclude_user` selectors program x86 USR/OS or aarch64 PMCCFILTR/PMEVTYPER
P/U exclusions on allocation and preserve them across overflow rearming.
Pinned task groups are scheduled atomically before flexible groups and are
never multiplexed; failure to place the complete group enters Linux's
observable error state, for which `read(2)` returns EOF. Only a group leader
may select `pinned` or `exclusive`. An exclusive hardware group runs only
while no hardware event outside that group owns a counter on the CPU.

A shared mapping of a perf fd exposes one Linux-shaped
`perf_event_mmap_page` metadata page followed by a power-of-two data area.
The metadata seqlock publishes the count and enabled/running times; `index`
remains zero because direct userspace PMU reads are unavailable. The file
owns all mapped frames, whose lifetime is retained by §3.2 even after fd
close.

On x86_64, sampled hardware events arm the owned GP counter for
interrupt-on-overflow and route LVT-PC through the normal IRQ dispatcher. The
hard-IRQ handler acknowledges/reloads the counter and captures task, IP, time,
the complete Linux-numbered user register file, up to 8 KiB of resident user
stack, counter identity, and the overflow's exact period into a bounded
64-entry per-CPU ring without allocation or user faults. Normal
syscall context drains those slots into `PERF_RECORD_SAMPLE`/`LOST` records,
advances `data_head` with release ordering, and wakes poll/epoll readers.
If that IRQ ring is full, loss is aggregated by the event ID active on each
overflowed physical counter, so later counter reuse cannot transfer loss to a
different event.
Task-scoped samples are admitted by task/inheritance ownership; system-wide
samples are admitted by the pending slot's source CPU matching the event's
owning CPU, without requiring a synthetic target task.
Committed exec, comm-change, fork/clone-process, and process-exit paths emit
Linux `PERF_RECORD_COMM`, `FORK`, and `EXIT` records when their corresponding
attribute bits are selected. Variable records are eight-byte aligned;
`sample_id_all` appends the selected TID/TIME/ID/STREAM_ID/CPU/IDENTIFIER
identity fields in Linux order. `wakeup_events` counts committed records and
wakes readers at the requested threshold. With the `watermark` attribute,
the same union member is instead compared against the exact unread byte count
after each committed record. `PERF_EVENT_IOC_PAUSE_OUTPUT`
atomically suppresses record commits while leaving the event enabled, and
resuming makes subsequent records visible again. Ring-capacity failures
increment the event's loss counter; reads selecting `PERF_FORMAT_LOST` return
that real counter for each standalone or grouped event rather than a constant.
`PERF_EVENT_IOC_SET_OUTPUT` redirects records to another compatible perf
event's mapped ring while retaining loss accounting on the source event; the
target must describe the same task and CPU context, and `-1` detaches it.
`PERF_EVENT_IOC_REFRESH` is accepted only for non-inherited sampling events.
Its argument adds real-overflow credits and enables the event; each hardware
overflow consumes one credit, and consuming the last credit synchronously
stops the PMU event and exposes `POLLHUP`. A later refresh clears the terminal
readiness and adds a new budget. A zero argument retains Linux's effectively
unlimited behavior.
`PERF_SAMPLE_READ` appends the event's authoritative counter snapshot using
the same standalone or group `read_format` layout as fd `read(2)`, including
enabled/running scaling times, IDs, and loss fields when selected.
Sample records also serialize `ADDR`, `CALLCHAIN`, `RAW`, `REGS_USER`,
`STACK_USER`, `WEIGHT`, `DATA_SRC`, `TRANSACTION`, `PHYS_ADDR`,
`DATA_PAGE_SIZE`, and `WEIGHT_STRUCT` in Linux
field order. Counting PMUs provide no sampled memory address or load/store
metadata, so those fields carry Linux's unavailable value (`0`). Callchains
start at the exact interrupted IP and walk validated, monotonically increasing
x86 RBP or aarch64 X29 frames only within the captured stack. The register and
stack payload also gives upstream perf the real input needed for offline DWARF
and symbol unwind; mapping records name the corresponding ELF images.
`CODE_PAGE_SIZE` is resolved against the sampled
task's registered address-space mapping and reports its real 4 KiB, 2 MiB, or
1 GiB hardware leaf size (or `0` when the IP is unmapped). The two weight
union views are mutually exclusive.
On x86_64, `PERF_EVENT_IOC_PERIOD` synchronously validates and installs a new
nonzero hardware sampling period while the event is disabled. Updating a live
or remotely active x86_64 event returns an error until a synchronous cross-CPU
PMU control path exists; NARF does not defer the update and report false
success.
On aarch64, fixed-period `PERF_COUNT_HW_CPU_CYCLES` sampling uses the
architectural 64-bit cycle counter, a firmware-discovered level-sensitive
PMUv3 PPI, and the same deferred mmap-ring producer. The end-to-end QEMU gate
requires a real PMCCNTR overflow, GICv3 dispatch, PMOVS acknowledgement, and
visible mmap sample. Instructions, cache misses, branch instructions, branch
misses, and raw architectural event numbers are admitted only when the
corresponding PMCEID bit proves that the PMUv3 implementation supports them.
Their programmable-counter overflows use the same PPI and deferred producer.
Frequency mode adjusts the real next-overflow reload period from observed
overflow timing. `PERF_EVENT_IOC_PERIOD` synchronously rearms an active
current-CPU aarch64 counter or validates a disabled/switched-out event against
a temporary real counter. A remotely active event returns an error until a
synchronous IPI rendezvous exists. Sampling periods below 10,000 events return
an error to prevent an interrupt storm.
Successful `mmap(2)` commits emit `PERF_RECORD_MMAP` or `MMAP2` for executable
and/or data VMAs selected by `mmap`, `mmap2`, and `mmap_data`. File mappings
carry the fd's recorded path and stable filesystem inode; anonymous mappings
are named `//anon`. MMAP2 reports the actual single NARF VFS device namespace
as 0:0 and generation zero because the VFS does not yet version inode
identities. Request-only controls such as `MAP_FIXED` are not leaked as VMA
flags. The ELF loader retains the exact committed PT_LOAD address, rounded
length, file offset, protection, and PIE/interpreter bias until the shared
exec commit emits initial program and interpreter records. The committed
main-stack VMA is emitted as `[stack]`; guard and kernel-private TLS mappings
are not exposed.
Unsupported sample layouts and platforms without a routed PMU overflow IRQ
fail explicitly.

Task-scoped x86_64 and aarch64 hardware events are scheduler-attributed: a switch hook
allocates and programs a counter in the destination CPU's PMU bank immediately
before entering the target continuation, then stops, folds, and releases it
immediately after every yield or preemption. Migration therefore carries the
accumulated value while never reusing an origin CPU's MSR identity. PMU slot
allocation, sampling overflow state, and LVT-PC routing are per logical CPU;
the switch-in path installs the shared PMI vector in each destination CPU
before arming its first sampled counter. When enabled task counting events
outnumber the remaining physical slots, the user-mode timer tick rotates their
allocation order at a 1 ms quantum. A rotation occurs only while an eligible
event is waiting, folds the exact stopped counter values, and keeps
`time_running` separate from `time_enabled`. Sampling events carry the exact
hardware `period_left` across rotation and migration; the first overflow after
resume reports that shortened period, then reloads the configured full period.
`inherit` extends
that task set at every process or thread clone and removes the child at its
thread-exit callback; concurrently running descendants therefore receive
independent per-CPU slots whose counts feed the original event. Software CPU
and task clocks normalize the architecture's slice and syscall ledgers into
scheduled time, sum every live descendant, and retire each final value before
the exit sweep removes those ledgers, so short-lived threads remain in the
terminal count. Live reads include the current un-folded slice
and syscall span; timer preemption folds the slice and pauses the syscall span
across the off-CPU interval. Frequency mode
starts from the calibrated TSC-rate estimate and, after each real overflow,
adjusts the following reload period from observed elapsed time toward
`sample_freq`; each correction is bounded to fourfold to prevent a delayed
drain from creating an interrupt storm. `PERF_SAMPLE_PERIOD` reports the period
that caused that overflow, not the next adaptive period. Per-CPU events on SMP
still require remote-CPU PMU calls and fail explicitly.
`PERF_TYPE_TRACEPOINT` subscribes to real `narf-tracing` typed events and
dynamic-probe fires by numeric ID. Producers enter a bounded allocation-free
per-CPU queue; payloads up to 256 bytes become `PERF_SAMPLE_RAW`, while
oversize/full-queue events increment the matching event's loss count. Upstream
perf discovers this source as `narf_trace` and selects it with `id=<config>`.
Arbitrary Linux kprobe/uprobe PMU types remain unsupported and fail explicitly;
NARF does not patch a probe merely because an event fd was opened.
`sigtrap` sampling requires a task target plus `remove_on_exec`; each overflow
queues SIGTRAP with `TRAP_PERF` and the exact `sig_data`. Cgroup, filter, and
BPF features fail explicitly.
`exclude_guest` is accepted because NARF never executes nested guest context.
The `ksymbol` and `bpf_event` record selectors are also accepted as empty
domains: NARF has neither a runtime kernel-symbol loader nor a BPF VM, so no
such lifecycle event can occur. A software-dummy event selecting only that
empty BPF sideband domain may also request watermark wakeups: with no possible
records, every watermark has the same observable empty-ring semantics. This
does not suppress an implemented event.
The adapter must not synthesize plausible values for an unavailable hardware
event. The audited command matrix and remaining gaps live in
`observability/PERF_LINUX_COMPAT_AUDIT.md`.

Linux perf wire definitions are owned by the separate
`narf-linux-perf-uapi` crate, transcribed through `PERF_ATTR_SIZE_VER9` from
Linux `include/uapi/linux/perf_event.h`. Defining a UAPI value does not admit
it: userspace accepts only implemented attribute bits and exact event
backends. Software events are currently limited to `PERF_COUNT_SW_DUMMY`.
Hardware events require x86_64 and a real programmable PMU. Task-scoped events
follow scheduler execution across CPUs; per-CPU events currently require a
uniprocessor target matching the calling CPU.

### 3.2 Shared file-mapping lifetime

A successful file/device-backed `MAP_SHARED` mapping retains an
`Arc<dyn FileOps>` independently of the descriptor table. Closing the fd does
not invalidate mapped frames. The owner reference is keyed by a stable
address-space incarnation rather than PID: a real fork copies the bucket,
`CLONE_VM` processes share it without duplication, and task migration is
irrelevant. It mirrors `MAP_FIXED` region splitting and is released by
`munmap(2)` or final address-space teardown after leaf invalidation. This
registry lives in userspace compatibility code so address-space regions do not
gain a filesystem dependency.

When `FileOps::mmap_lifetime` returns a per-object owner, the same registry
retains it beside the file reference and clones it across fork and VMA splits.
This permits a multiplexed device such as DRM to remove a closed GEM handle
and quiesce its host resource immediately while deferring DMA-page reuse until
the final mapping disappears.

Generic filesystem mappings that cannot expose page-cache frames retain one
canonical fallback page per open-file description and file offset, plus an
exact clean-byte snapshot. `fsync(2)` and `msync(2)` compare against that
snapshot, write each changed canonical page once even when it has overlapping
aliases, and advance the snapshot only after the full page write succeeds.
Clean pages perform no filesystem write; the comparison is byte-exact rather
than hash-based so collision cannot suppress persistence.

The equivalent internal bridge for `AF_NETLINK`/`NETLINK_NETFILTER` accepts
only a live `NetfilterAdminHandle` whose immutable namespace id equals the
socket creator's network namespace. It rejects other netlink protocols,
cross-namespace replay, revoked handles, and insufficient operation rights;
no raw capability slot crosses the Linux socket ABI.

AF_INET and AF_NETLINK sockets retain the creator's network-namespace object,
not only its numeric id. Accepted sockets inherit that same object.
Task exit removes the task-table reference, while namespace fds and sockets
keep the namespace live; kernel network teardown runs only after the final
reference closes. Per-namespace IPv4 loopback TCP/UDP delivery uses
namespace-keyed endpoint tables, so identical loopback endpoints coexist and
cannot exchange traffic across namespaces.

### 3.3 BPF XDP program compatibility

`BPF_PROG_LOAD` accepts Linux program type 6 (`BPF_PROG_TYPE_XDP`) and records
that type as object identity distinct from tracing programs even though both
execute atomically. Only an XDP program may attach to `BPF_XDP`; tracing,
raw-tracepoint, and sleepable programs receive `EINVAL` on a valid XDP target.
The runtime context is kernel-constructed packet `data` / `data_end`, not a
caller-supplied `ctx_in`. `BPF_PROG_TEST_RUN` copies Linux `data_in` into a
kernel-owned frame and passes only that immutable slice to `BpfProg::run_xdp`;
non-zero `ctx_in`/`ctx_out`, flags, CPU selection, and batch mode are rejected.
Zero repeat means one run; packet size and repeat are capped at 64 KiB and 1024
so the synchronous privileged syscall remains bounded. The current read-only
XDP contract copies the unchanged packet to `data_out`, publishes the actual
size and average duration, and returns `ENOSPC` after copying a short output
prefix. Packet reads and their verifier/runtime contract are owned by
`bpf/specification/spec.md` §3.15.

## 4. Invariants & safety properties

- No ambient authority: a new process has only the caps explicitly granted.
- **PKU and PKS are entirely independent hardware mechanisms** that
  happen to share a numeric range (0..15). A user process holding
  PKU key 3 and a kernel driver in PKS domain 3 do **not** interact —
  the hardware enforces them on disjoint accesses (Ring 3 data vs.
  supervisor data). The earlier wording "user PKU matches kernel PKS
  domain IDs only where explicitly shared" was misleading. What is
  *actually* shared is memory: a region can be mapped with both a
  user-accessible PKU key and a kernel-accessible PKS key, granting
  both rings independent access. The keys themselves do not unify.
  The kernel-side shadow lives in `DomainId::USERSPACE_K` regardless
  of which user PKU key the user side uses.
- relibc never performs a syscall the kernel hasn't explicitly wired up.
- Synchronous syscall bridges poll async filesystem operations with the current
  stackful task's executor waker. `Pending` closes kernel-time accounting,
  sleeps the task, and resumes only after filesystem/I/O completion wakes it;
  the executor's durable runnable bit prevents a wake racing with sleep from
  being lost. Resume republishes the task's `UserTaskCtx` before continuing the
  syscall. Kernel-test contexts and architectures without own-stack user tasks
  retain a bounded spin-pump fallback, but the x86_64 runtime path has no poll
  count or repeated self-yield loop.

### 4.1 Stable user-space ABI promise

**NARF commits to the Linux "do not break user-space" principle.**
Once a syscall number lands in `Syscall` and is called by a binary
in narf-libc, its v0 wire ABI — argument shape, return semantics,
side effects observable to the caller — is stable indefinitely.

**Mechanisms for evolving the surface without breaking pre-existing
binaries:**

1. **Mint a new syscall number** when the new operation is
   conceptually distinct (e.g. `read` vs `pread64`).
2. **Mint a new version of an existing syscall** when extending the
   semantics of the same conceptual operation (e.g. tightening
   error reporting, broadening permitted argument values, adding a
   typed flag bits field). Versioning happens via the upper 8 bits
   of the 32-bit syscall number — see below.

**Wire format.** A raw syscall number is `(version << 24) | num`:

| bits   | field        | notes                                       |
|--------|--------------|---------------------------------------------|
| 0..23  | syscall id   | canonical number (16M slots; ~234 used)     |
| 24..31 | ABI version  | 0 = canonical wire ABI; 1..255 = overrides  |

`narf_userspace::{syscall_pack, syscall_number, syscall_version,
SYS_VERSION_SHIFT}` are the helpers. Pre-versioning binaries encode
`version=0` implicitly (the upper bits are zero), so they keep
dispatching to the v0 handler forever. New binaries opt in to a v1
ABI at compile time by packing `1` into bits 24..31; the kernel's
dispatch (`SyscallTable::dispatch_ctx_versioned`) probes the v1
handler first and falls through to v0 when no override exists for
the requested version.

**What's allowed under this promise:**

- Adding new syscall numbers (with reserved-zero argument fields
  the new path checks for).
- Adding new versions of existing syscalls.
- Adding new flag bits to existing typed flag arguments **only when
  zero is the prior caller's "I don't know about this bit" value**
  and the kernel rejects unknown bits (so a pre-existing caller
  that happens to set the bit gets a typed error instead of silently
  surprising behavior).
- Tightening reserved-zero fields to typed errors (callers that
  previously sent zero are unaffected).
- Loosening previously-rejected argument values (callers that sent
  the rejected values were already broken; loosening them turns
  failures into successes).

**What's not allowed:**

- Changing the meaning of an existing argument or return value at
  the same `(syscall, version)`.
- Removing a syscall number once published (it stays as a permanent
  no-op or tombstone if obsolete).
- Reusing a previously-published syscall number for a different op.

The `Syscall` enum is therefore append-only across the kernel's
lifetime; tombstoning an obsolete syscall is fine, removing the
number is not.

## 5. Architecture notes

### x86_64
- User CS/SS + `sysret` for slow-path return; rings bypass it on fast path.
- Stack red-zone honoured.
### aarch64
- EL0 entry; `eret`; TPIDR_EL0 for TLS.
- The scheduler owns TTBR0 context save/activation/restoration around each user
  future poll. Trap-back longjmp returns with the task's tagged TTBR0 still
  installed; `UserTaskFuture` does not rewrite or flush it before returning to
  the executor. This preserves lifetime-scoped process-ASID translations and
  leaves exactly one component responsible for restoring the incoming root.

## 6. Dependencies

- **Consumes:** `capabilities/`, `ipc/`, `memory/`, `scheduler/`, `abi/`,
  `arch/`, `frame/`, `net/` (stack-daemon attach protocol for a
  userspace network stack), `filesystem/` (per-task root caps).
- **Provides to:** everything running outside the kernel.

## 7. Stage assignment

Stage 4.

## 8. Resolved decisions

### 8.1 POSIX shim scope (resolved)

**Decision (was open):** **native-first ABI with relibc as a
thin compat layer**, not full POSIX compatibility.

The native NARF userspace ABI is the ring-pair model in §3.
relibc lives on top, translating POSIX calls (`read`, `write`,
`open`, `mmap`, …) into NARF submissions. Programs that link
against relibc compile from POSIX source unchanged; programs
that link against `narf-userspace-runtime` (a thin
typed-async crate) skip the POSIX layer entirely.

**Rationale:** full POSIX compatibility (every syscall, every
flag, every edge case) is the long-tail cost that has dominated
every "POSIX-on-microkernel" project. By making NARF-native
the primary ABI and relibc the bridge, we keep the surface
area honest. Production NARF code should target the native
ABI; relibc is for porting existing code.

### 8.2 Dynamic linking (resolved)

**Decision (was open):** **dynamic linker ships in v1.0** —
the `narf-ld.so` interpreter referenced via `PT_INTERP` (see
§8.4). Static-only would force every userspace binary to
re-include relibc + the runtime, multiplying image size; for
hundreds-of-applications scaling the dynamic linker is not
optional.

The dynamic linker is the same Shiva-style relocation engine
the driver framework's loader uses (`drivers/spec` §14). One
implementation, two consumers.

### 8.3 fork/exec semantics (resolved)

**Decision (was open):** **spawn-only**. NARF does not
implement Linux-compatible `fork()`. The
posix_spawn-equivalent native primitive is
`spawn_process(elf, caps)` in §3.

**Rationale:** `fork()` requires copy-on-write of the parent
address space, which interacts badly with cap tables (does
the child get a copy of every cap? clones are an explicit
operation in NARF, not implicit copies), with PKS/MTE domain
state (each domain's PKRS/TCF would need cloning), and with
the bootstrap ring pairs (you'd have two processes sharing a
ring and immediately diverging). The semantic mess is not
worth Linux source-compatibility for the small set of
programs that genuinely need fork-without-exec.

relibc's `fork()` returns `Err(ENOSYS)`. POSIX programs that
call `posix_spawn` work; programs that `fork(); exec()` are
patched (typically by replacing with `posix_spawn`).
`vfork()` is similarly unsupported. This is a known porting
cost for legacy code; the alternative is unsoundness in the
cap+domain model.

### 8.4 PT_INTERP capability bootstrap (resolved)

**Decision (was open):** **NARF ships `narf-ld.so`**, the
custom program interpreter referenced by every userspace ELF's
`PT_INTERP`. The interpreter is the Shiva-inspired model:

1. Kernel loads ELF, sets up address space, jumps to interp's
   entry point (not the program's).
2. Interpreter runs in user mode with bootstrap caps (provided
   via the kernel-mapped config page from `abi/spec` §3.1).
3. Interpreter resolves relocations against shared libraries
   (loaded via further bootstrap caps), populates the GOT,
   installs the program's cap table, allocates submission +
   completion rings.
4. Interpreter jumps to the program's `_start`.

This **moves the ABI bootstrap currently in `abi/spec` §3.1
into user mode**. The kernel's only role is loading the
interpreter and minting one bootstrap cap; everything else is
user code that can be debugged, traced, and updated without
kernel changes.

The interpreter is the same code path the driver loader uses
(see `drivers/spec` §11), just running in user mode instead of
kernel mode. One relocation engine, two callers.

## 9. ABI versioning

Syscall versioning per §4.1 is the canonical ABI-version
pattern across the kernel — all subsequent specs (`drivers/`,
`capabilities/`, etc.) mirror it.

`USERSPACE_ABI_MAJOR = 1`, `USERSPACE_ABI_MINOR = 0`.

The Syscall enum is **append-only** indefinitely (§4.1). Removed
entries become tombstones (returns `Err(ENOSYS)`) but keep
their number reserved.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
