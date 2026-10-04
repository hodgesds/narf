# filesystem — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> mount + node-cap surface; v1.0 locks the persistent-FS
> first target, the POSIX-semantics scope, xattrs, directory
> atomicity, encryption layer, and the system-caps tooling
> filesystem.

## 1. Purpose & scope

**Owns:**

- Path resolution (UTF-8 strings against a capability-rooted tree).
- Node abstraction — file, directory, symlink, special — as a typed
  capability.
- File operations (open, read, write, seek, stat, fsync, truncate).
- Directory operations (readdir, create, unlink, rename, link).
- Mount tree — a node can have another filesystem mounted over it,
  crossing boundaries requires a `Cap<MountPoint, Traverse>`.
- Page cache (by default enabled; per-fs opt-out).
- Filesystem driver interface — the trait concrete filesystems
  implement.

**Does NOT own:**

- Concrete on-disk formats (ext-like, btrfs, FAT, virtiofs) — those live in
  `drivers/fs/<name>/`.
- Block layer — `block/`.
- Process-scoped "current directory" — that's a `userspace/` concept
  (a task holds a cap to its working directory).
- Process namespace selection and syscall argument copying — these belong to
  `userspace/`. This crate supplies the shared procfs/sysfs/devtmpfs backends.

## 2. Assumptions

- `block/` supplies block devices for backing storage.
- `capabilities/` mints `Cap<FileNode, R>` tokens.
- `memory/` supplies cache storage and path-resolution working memory.
- `crypto/` provides hashing primitives for content-addressed or
  verified filesystems (e.g. dm-verity-style integrity, Stage 4+).
- There is no global root. Each task has a **root cap**
  (`Cap<FileNode, Traverse>`) that defines what it can reach.

## 3. Public interface

### 3.0a Filesystem type and device registration

`FileSystemType` describes a mountable type, separately from an instantiated
`FsInstance`. `lookup_fstype(name) -> Option<FileSystemType>` returns a copy
without calling filesystem code. `FileSystemType::init(&MountRequest)` builds
an instance; the caller attaches it with its namespace and mount flags.
`MountRequest` carries the requested type/subtype, resolved source, filesystem
options, creator uid/gid and whether this is the initial mount namespace.

- `register_fs_type(FileSystemType)` registers a contextual constructor.
- `register_fstype(name, FsBuilder)` adapts the existing source/options
  callback; `register_block_fstype` also records the block-device requirement.
- Duplicate registration replaces the descriptor. Exact names precede
  explicitly enabled `name.subtype` matches. Aliases are separate entries.
- `registered_fstypes()` snapshots this same catalog for `/proc/filesystems`,
  including unmounted types and the correct `nodev` classification.
- Registration and lookup never probe devices or construct instances. Callback
  execution must occur outside registry and syscall context locks. Builtin
  descriptors are installed lazily; driver registration happens at boot or
  Linux ABI installation before those syscalls are exposed.
- Root-device format detection retains its separate `FsType` factory map;
  that map chooses a driver from on-disk signatures, not a userspace type name.

`devfs::register_provider(DeviceProvider)` registers a named device family with
file lookup, directory lookup and enumeration callbacks. Replacement is
idempotent; `unregister_provider` removes the family from every devtmpfs view.
Callbacks run outside the provider lock. Builtin nodes have one descriptor
for type, construction and visibility; `iter` and `enumerate` expose the same
live entries, with duplicate names suppressed. Static names precede providers,
then the block registry, then udev-created runtime nodes. Existing USB serial,
video and RFCOMM installation wrappers adapt to this provider API.

`sysfs::register_provider(SysfsProvider)` registers a named boot population
callback. `populate_all()` snapshots callbacks and invokes them without its
lock. Providers support explicit refresh after probes and use the existing
kobject/class registration API. Every sysfs mount shares that live graph;
mounting a new view never repopulates it or emits device ADD events.

### 3.0 Root-device orchestration

`root_mount::try_mount_root` and `try_mount_root_with` apply every explicit
`root=` selector strictly, including `UUID=` via immutable block-volume
metadata. A selected LUKS1/LUKS2 container is opened through block's installed
credential provider, its inner filesystem is detected and mounted, and the
adapter is registered as `cryptroot`. Missing credentials and authenticated
unlock failures surface as `RootMountError::LuksUnlock`; they never fall
through to an unrelated disk.

### 3.1 Path and node types

```rust
pub struct Path<'a>(&'a str);              // UTF-8; '/' separator; no '.' / '..' by default
pub struct NodeRef;                        // opaque, held via Cap
pub enum NodeKind { File, Dir, Symlink, Special }

pub type FileCap    = Cap<NodeRef, FileRights>;      // Read | Write | ReadWrite | Append
pub type DirCap     = Cap<NodeRef, DirRights>;       // Traverse | Create | Remove
pub type SymlinkCap = Cap<NodeRef, ReadLink>;
```

### 3.2 Path resolution

```rust
pub fn resolve(
    root: &DirCap,
    path: Path<'_>,
    flags: ResolveFlags,                   // FollowSymlinks | NoMount | CreateParents
    cap:   &Cap<Traverse, _>,
) -> impl Future<Output = Result<NodeRef, FsError>>;

pub struct Dentry { /* opaque VFS parent/name + positive/negative inode state */ }

pub fn resolve_dentry(
    root: Arc<Dentry>,
    path: &str,
) -> Result<Arc<dyn FileOps>, FsError>;

pub fn resolve_cached_dentry(
    root: Arc<Dentry>,
    path: &str,
) -> Option<Result<Arc<dyn FileOps>, FsError>>; // None => reference walk

pub fn resolve_async_dentry(
    root: Arc<Dentry>,
    path: &str,
) -> FsFuture<'_, Arc<dyn FileOps>>;

pub fn resolve_directory_dentry_async(
    root: Arc<Dentry>,
    path: &str,
) -> FsFuture<'_, Arc<Dentry>>;

pub fn resolve_absolute_single_mount(
    abs: &str,
    f: impl FnOnce(&dyn FsInstance, &str, u64) -> R,
) -> Option<R>; // filesystem-relative path + covering mount id

pub fn resolve_absolute_single_mount_with_root(
    abs: &str,
    f: impl FnOnce(&dyn FsInstance, Arc<Dentry>, &str, u64) -> R,
) -> Option<R>; // canonical root + relative path + covering mount id

pub fn resolve_absolute_with_root(
    abs: &str,
    f: impl FnOnce(&dyn FsInstance, Arc<Dentry>, &str) -> R,
) -> Option<R>; // canonical mount root + filesystem-relative path

pub fn with_mount_root(
    path: &str,
    f: impl FnOnce(&dyn FsInstance, Arc<Dentry>) -> R,
) -> Option<R>; // exact mount + canonical root

pub trait DirOps {
    fn dcache_identity(&self) -> (usize, u64, u64); // superblock, inode namespace, inode
    fn rcu_walkable(&self) -> bool;
}

pub fn begin_path_mutation(
    parent: &dyn DirOps,
    names: &[&str],
) -> PathMutationGuard; // empty names invalidates every child
```

- Resolution is **always scoped to `root`**. There is no path escape.
- Symlinks resolved up to a documented bound (default 40) to block
  cycles.
- Crossing a mount boundary requires the resolver's cap chain to
  include the `MountPoint` traverse right.
- Path strings are UTF-8; NARF does not emulate byte-pathname
  filesystems transparently (a compat FS in `drivers/fs/` may do so).
- `resolve_absolute_single_mount` returns `None` when `abs` is a synthetic
  ancestor of a deeper mount; otherwise its callback may walk the returned
  filesystem without rechecking the mount table between components.
- Every mount namespace publishes an immutable routing snapshot through QSBR.
  A mount attachment owns one canonical root dentry; a reader selects one
  coherent snapshot, upgrades its weak filesystem and root references, and
  leaves the read section before calling `DirOps` or a caller closure. Attach,
  overmount, move, and detach remain serialized by the namespace writer lock.
  `FsInstance::root` runs before that lock when attaching, and a detached
  filesystem, root, or replaced snapshot is never destroyed under the lock.
  Path walkers use `resolve_absolute_with_root`; metadata-only callers may use
  `resolve_absolute` without receiving the canonical root.
- `Dentry` is the VFS name object, not a synonym for `DirOps` or `FileOps`.
  It has stable parent/name identity while hashed, carries either positive
  inode-operation references or an explicit negative state, and has a
  per-dentry sequence. A mount owns its root dentry. Child dentries retain a
  referenced parent, while the bounded global hash is the lookup index.
  Replacing, renaming, or unlinking a name first unhashes its dentry and
  advances that sequence; old bucket snapshots and their objects are reclaimed
  only after a QSBR grace period.
- Path resolution first attempts an RCU dentry walk. Hash buckets are immutable
  QSBR publications keyed by directory identity and component name. Each step
  samples the child sequence and then validates the parent sequence, forming
  the same interlocking validation chain as `__d_lookup_rcu`; the final child
  is converted to owned `Arc` references only after its sequence validates.
  Intermediate dentries stay borrowed from the pinned hash snapshots, so the
  fast walk performs no per-component reference-count stores.
  A miss, symlink, non-directory component, concurrent mutation, or `DirOps`
  implementation that returns `false` from `rcu_walkable` restarts through
  ordinary reference walk. No RCU guard spans `.await`, and no filesystem
  lookup callback runs inside the RCU fast path.
- `rcu_walkable` defaults to `false` and must itself be wait-free and free of
  filesystem callbacks when overridden. Immutable implementations may opt in.
  Mutable implementations may opt in only when every insertion, removal, link,
  and rename holds `PathMutationGuard` from before the first visible change
  through final publication. Guard construction unhashes every alias of each
  named dentry (or every child when `names` is empty); unrelated hash chains
  survive. The guard holds no lock and may cross `.await`; per-chain active
  writer counts and generations close the no-existing-dentry race and make
  overlapping readers retry. Reference walk publishes merged file/directory
  positive dentries and negative dentries only when its pre/post chain token
  validates.
  Local initramfs, memfs, ext2, btrfs, FAT, MINIX, exFAT, UDF, SquashFS, and
  ISO 9660 participate. Remote, synthetic-dynamic, and externally revalidated
  filesystems retain reference walk until they provide an equivalent validity
  contract; this is the NARF equivalent of Linux returning `-ECHILD` from an
  RCU lookup that cannot safely complete locklessly.
- `dcache_identity` is the inode-alias key used by the dcache and must be
  wait-free. Its default object address is valid for filesystems that retain
  one `DirOps` object per inode. A participating backend that creates fresh
  wrappers on lookup returns a stable `(superblock identity, inode namespace,
  inode identity)` triple instead, so mutation through any wrapper unhashes
  every cached alias. The namespace is zero for ordinary filesystems and
  distinguishes inode-number domains such as btrfs subvolumes.

### 3.3 File operations (async)

```rust
pub fn open(dir: &DirCap, name: &str, intent: OpenIntent, cap: …) -> impl Future<Output = FileCap>;
pub fn read (f: &FileCap, offset: u64, buf: &mut [u8])        -> impl Future<Output = usize>;
pub fn write(f: &FileCap, offset: u64, buf: &[u8])             -> impl Future<Output = usize>;
pub fn fsync(f: &FileCap)                                      -> impl Future<Output = ()>;
pub fn stat (n: &Cap<NodeRef, Stat>)                           -> impl Future<Output = NodeStat>;
pub fn truncate(f: &FileCap, len: u64)                         -> impl Future<Output = ()>;
pub trait DirOps {
    fn create_with_attrs(
        &self,
        name: &str,
        perms: u16,
        uid: u32,
        gid: u32,
    ) -> FsFuture<'_, Arc<dyn FileOps>>;
}
pub trait FileOps {
    fn has_flush(&self) -> bool;
    fn poll_readiness(&self) -> u32;
    fn poll_readiness_at(&self, offset: u64) -> u32;
    fn poll_edge_token(&self) -> (u64, u64);
    fn acknowledge_poll_readiness(&self, readiness: u32);
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError>;
    fn mmap_lifetime(&self, offset: u64, len: usize) -> Option<Arc<dyn MmapLifetime>>;
    fn mmap_is_ram(&self) -> bool;
    fn supports_mmap_fault(&self) -> bool;
    fn mmap_backing_identity(&self) -> usize;
    fn mmap_fault(&self, offset: u64) -> Result<u64, FsError>;
    fn mmap_cache_generation(&self) -> Option<u64>;
    fn open_instance(&self) -> Option<Arc<dyn FileOps>>;
    fn open_instance_checked(&self, write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError>;
    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness>;
    fn arm_readiness(&self, task_id: u64, interest: u32, waker: &Waker)
        -> Option<Poll<u32>>;
    fn arm_readiness_exclusive(&self, task_id: u64, interest: u32, waker: &Waker)
        -> Option<Poll<u32>>;
    fn disarm_readiness(&self, task_id: u64) -> bool;
    fn drm_execbuf_fence(&self) -> Option<Arc<dyn DrmFence>>;
    fn drm_execbuf_context(&self, ring_idx: u32) -> Option<u64>;
    fn tty_fg_pgrp(&self) -> Option<u64>;
    fn tty_session(&self) -> Option<u64>;
    fn set_tty_fg_pgrp(&self, pgrp: u64) -> bool;
    fn tty_acquire_controlling(
        &self,
        arg: usize,
        readable: bool,
    ) -> Result<bool, FsError>;
}

pub trait DrmFence: Send + Sync {
    fn is_signalled(&self) -> bool;
    fn wait(&self, timeout_ms: u64) -> bool;
    fn context(&self) -> Option<u64>;
}

pub enum FileType {
    File,
    Dir,
    Symlink,
    Special, // Linux character device: S_IFCHR / DT_CHR
    Block,   // Linux block device: S_IFBLK / DT_BLK
    Socket,
    Fifo,
}
pub fn install_mmap_truncate_hook(hook: fn(&dyn FileOps, u64) -> Result<(), FsError>);
pub fn unmap_mapping_range(file: &dyn FileOps, new_len: u64) -> Result<(), FsError>;
```

`DirOps::create_with_attrs` publishes a new inode with the requested owner and
mode as one create operation when the backend supports it. The default adapts
legacy backends by creating first and applying both metadata updates; tmpfs /
`MemFs` initialises the inode and its quota charge atomically before insertion.

All operations submit through `abi/` rings when crossing the
kernel↔user boundary; kernel-internal callers invoke directly.
An open file that is healthy but temporarily has no readable data returns
`FsError::WouldBlock`; `Ok(0)` is reserved for a real end-of-file. The syscall
layer maps `WouldBlock` to `EAGAIN` for `O_NONBLOCK` or parks and re-executes a
blocking read. File operations do not expose a separate readiness predicate
for callers to re-classify a zero-byte result.
`poll_readiness_at` defaults to `poll_readiness`; offset-sensitive device
descriptions such as `/dev/kmsg` override it so EOF is not reported readable.
`poll_edge_token` defaults to `(0, 0)`; stateful readiness providers advance
one component whenever an edge-relevant source changes so `EPOLLET` cannot
lose a drain/refill transition between readiness scans.
`acknowledge_poll_readiness` defaults to a no-op and is called only after an
epoll instance accepts an event for delivery. It lets a source retire a
per-open-file change edge without allowing a passive nested-epoll readiness
query to consume an event owned by its inner monitor.
`arm_readiness_exclusive` is used only by a blocking I/O syscall. Its default
delegates to ordinary `arm_readiness`; providers backed by a Linux-style
exclusive wait queue override it so one consumable event wakes one syscall.
Poll and epoll continue to use non-exclusive `arm_readiness` and persistent
registration, respectively, and therefore all observe the event.
`open_instance_checked` runs after open permission checks, accepts whether
write access was requested, and can reject the open. It defaults to calling
`open_instance`; `O_PATH` bypasses per-open setup. Procfs map nodes use it to
capture namespace and credential state without lookup/stat side effects.
`open_instance` defaults to `None`. Clone devices return a fresh open-file
object so lookup/stat and `O_PATH` remain side-effect free; the Linux open path
calls it only after access checks. `/dev/pts/ptmx` returns a fresh PTY master
and `/dev/fuse` returns a fresh FUSE daemon connection. The stable `/dev/fuse`
clone node is mode 0666 so unprivileged filesystem and desktop-portal daemons
can open it, matching Linux distribution tmpfiles/udev policy.

Named FIFO handles share durable data-readiness state and direction-specific
peer-presence cells. `FifoShared::unread_bytes()` snapshots the shared queue
length for `FIONREAD` on either end; the syscall layer performs the guarded
four-byte user copy and reports `EFAULT` on failure. `FifoHandle::arm_peer`/`disarm_peer` key waiters by task;
the handle snapshots the counterpart edge before publishing its own open count,
so a peer that opens and closes before the waiter runs still completes the
blocking `open`. A read-only handle opened before any writer suppresses
`POLLHUP` until its own writer-presence snapshot changes, matching Linux's
per-file `f_pipe`/`w_counter` rule. Data reads/writes arm the per-file readiness cell. Anonymous pipes and named
FIFOs use `pipe_buffer::PipeBufs` and `pipe_queue::Queue`: a bounded buffer-slot
ring with retained page references and a sleepable mutex. Queue guards publish
atomic length/fullness/capacity snapshots before releasing the mutex. Pipe
payload copies never hold the readiness publication spinlock.
`FifoHandle::{read_to_user,vmsplice_to_user,write_from_user}` are async operations
whose guarded-copy callbacks run under the payload mutex and commit one page
buffer at a time. Reads discard a truncated packet tail; splice actors retain
it. Errors after a committed prefix return its length. Allocation failure is
`FsError::OutOfMemory` (`ENOMEM`), distinct from `NoSpace` (`ENOSPC`). The last
FIFO handle discards queued data and restores the default capacity before a
new opener can observe the inode. `FifoShared::queue` and `notify_transfer`
allow anonymous/named transfers to use one ordered transaction.

`PipeBufs` owns a bounded descriptor ring; owned payloads use allocator pages
with reference-counted descriptors and one reusable drained page. Imported
buffers carry `UserPagePin` references and cannot acquire append rights.
`fill_from` implements the single-copy buffered-provider fallback into fresh
pipe pages. `with_front_raw` exposes a retained pointer only for a callback's
duration, avoiding Rust references over externally mutable imported pages.
`FifoHandle::packetized`/`set_packetized` reflect O_DIRECT on an open description.
`notify_transfer(event, transferred)` publishes the changed direction and relays
exclusive waiters when work remains. Nonzero transfers smaller than `PIPE_BUF`
also request a revalidated scheduler handoff to the selected peer at syscall
exit; page-sized/bulk transfers use ordinary targeted wakes. Final close wakes
every affected blocker.

`FileOps::splice_read_page(offset, max)` returns a retained `SplicePage`, EOF
(`Ok(None)`), or an error. `Unsupported` selects buffered I/O directly into
nonmergeable pipe pages. Memfd and tmpfs retain their actual RAM pages under
the backing object's lock; overlay forwards the operation to its active file.
`FileOps::mmap_is_ram()` defaults to false. A true implementation promises
that both mmap backing methods expose ordinary allocator frames retired via
`free_frame`, permitting independent page pins. Device/PFN providers must
retain the false default; the syscall layer records this distinction in
`RegionPerms::PINNABLE_RAM`.


`DevFs` identifies itself as `devtmpfs`. Character and block nodes remain
distinct through VFS stat and readdir translation, carry Linux `st_rdev`
values, and expose stable non-zero inode identities. The root accepts runtime
device-node, directory, and symlink creation plus rename/removal. Dynamic
device nodes preserve type, mode, uid/gid, rdev, and inode across lookups;
dynamic directories preserve mode and inode identity. This covers
udev coldplug nodes, `/dev/{char,block}/MAJOR:MINOR`, and journald's
`/dev/log -> /run/systemd/journal/dev-log`; static device aliases retain
precedence over dynamic names and absent optional hardware nodes are not
advertised by readdir.

devtmpfs's `/dev/ptmx` is `DevTmpfsPtmx`, a `c 5:2` node (0666, root-owned,
chown/chmod persist) beside an empty `/dev/pts` mountpoint. Every devpts mount
is an independent instance (Linux 4.7+): `DevPtsFs::from_options(options,
mounter_uid, mounter_gid, reserve)` parses `uid=`, `gid=` (mounter-namespace
ids via `install_pty_id_map_hook`), `mode=` (default 0600), `ptmxmode=`
(default 0000), `max=` (`<= NR_UNIX98_PTY_MAX`) and `newinstance`, anything
else `FsError::InvalidData`; `show_options` prints them as
`devpts_show_options` does and `reconfigure` resets then re-parses all but
`reserve` (`reserve` is set for a mount in the initial mount namespace).
Each instance (`PtsFsInfo`) owns its lowest-free index space below `max`, its
`ptmx` node (inode 2, mounter-owned, mode `ptmxmode`) and its anonymous
`st_dev`; a pts node is inode `index + 3` with `uid=`/`gid=`/`mode=` applied
at creation. `ptmx_open(fsi)` fails `FsError::NoSpace` past `max` or past
`kernel.pty.max` (less `kernel.pty.reserve` unless `reserve`); `pty_limit`,
`pty_reserve`, `pty_nr` and their setters back the `kernel.pty.*` sysctls.
Opening a `c 5:2` that is not an instance's own `ptmx` goes through
`ptmx_open_beside(node, pts_dir)`: the root of a devpts mounted at `pts` in
the node's directory, else `FsError::NoDevice` (`ENODEV`). A master reports
the identity of the node it was opened through. A pty is identified
system-wide by `tty_id()` / `as_pty_master_id()` (`pty_by_id`, `pty_index`),
since indices repeat across instances. Boot mounts one instance at
`/dev/pts` with systemd's `mode=620,gid=5` (`boot_devpts`).
The Linux open path treats `/dev/tty` as the caller's controlling-terminal
multiplexer: it selects the recorded console or PTY slave, preserves the 5:0
path-node identity, and reports `ENXIO` for a detached session. `O_PATH`
continues to open only the side-effect-free path node.
PTY master and slave endpoints share one locked control record containing raw
stable kernel session and foreground-process-group identities. The filesystem
never translates those identities into a PID namespace: the querying syscall
does so at delivery time. `tty_acquire_controlling` serializes the cross-crate
process/PTY transaction and publishes session plus foreground group together;
`tty_session`, `tty_fg_pgrp`, and `set_tty_fg_pgrp` expose the raw control
record to the Linux-compat syscall policy. Non-PTY objects retain the default
`None`/`false` behavior.

With `linux-compat`, `MqueueFs::new(ipc_namespace_id)` exposes the same live
queue objects used by `mq_open`/`mq_unlink`/send/receive/notify/getsetattr.
Queue names are scoped by IPC namespace; every mount captures the namespace
visible to its creator. The root is mode 01777 and queue nodes retain stable
inode, owner, creation mode, Linux's fixed 80-byte stat size, exact status-file
text, and poll readiness. An unlink removes only the name; open descriptions
retain the queue until their final reference drops. `O_NONBLOCK` and access
mode belong to each open description and therefore remain shared across
dup/fork but independent across separate `mq_open` calls. The public typed
surface is `MqueueFs`, `MqueueOpenOptions`, `MqueueAttr`,
`MqueueNotification`, and `MqueueError` plus the operations in
`filesystem::mqueuefs`.

### 3.3.1 cgroup-v2 cpuset placement

`cpuset.cpus.effective` is pushed into scheduler CPU affinity.
`cpuset.mems.effective` is the parent-effective/requested intersection
and is pushed into the scheduler's per-task allowed-node table on attach
and every local policy update. Empty requests inherit the parent; an
explicit request with an empty intersection is rejected.
The legacy cgroup-v1 `cpuset.memory_migrate` file is not exposed on the
cgroup-v2 mount. Effective-memory-mask changes affect subsequent placement;
they do not implicitly migrate already-resident pages.

### 3.3.2 cgroup-v2 compatibility surface

`CgroupFs` exposes one unified hierarchy. Core and controller attributes use
stable, non-zero inode identities, kernfs-style zero `st_size`, Linux file
modes, and identical synchronous/asynchronous directory snapshots. Root-only
and non-root-only controller files follow the Linux cftype placement rules.
The root owns state for every registered controller even before delegation, so
hierarchical accounting reaches the root while limit files remain absent there.
`cgroup.events` advances its `POLLPRI` generation and emits inotify
`IN_MODIFY` whenever its `populated` value changes, including changes caused
by descendants. Kernel-side content changes cross the filesystem/userspace
dependency boundary through `set_modify_notifier(fn(&str))`; the boot-installed
notifier queues the event for watches on the absolute `cgroup.events` path.
The callback runs after the filesystem notifier lock is released.

`cgroup.subtree_control` validates a write atomically, applies repeated
controller operations in input order (the last operation wins), enforces the
no-internal-process rule, and refuses to withdraw a controller still delegated
by a child. Cgroup-namespace paths are relative to the namespace root and use
`..` components for visible sibling cgroups. The writable `cgroup.type`
transition rejects populated groups and domain-controller conflicts.
`fork_thread_inherit(parent_tid, parent_tgid, child_tid)` inherits a creating
thread's css-set override, while
`attach_thread_by_path(path, parent_tid, parent_tgid, child_tid)` implements
`CLONE_INTO_CGROUP|CLONE_THREAD`: the destination must share the source's
threaded domain or the call fails with `EOPNOTSUPP`. `thread_exited(tid)`
removes per-thread membership and controller charges. General migration of an
existing process's complete thread group and automatic threaded-subtree type
propagation are not yet provided.

Pressure Stall Information is optional. The `cgroup-psi` feature exposes
`cgroup.pressure` plus `cpu.pressure`, `memory.pressure`, and `io.pressure`;
without it, no PSI cgroup ABI is present. The current PSI implementation
reports Linux-shaped zero counters and does not yet implement pressure-trigger
writes or poll notifications.

The memory-controller allocator hook is nonblocking in every allocation
context. Crossing `memory.high` commits the charge and publishes a capped,
coalesced background-reclaim request. Breaching `memory.max` publishes the
same non-OOM-authorized work and returns the allocator's exhaustion result.
Fallible callers map that result to `ENOMEM`; syscall paths that collapse
allocation exhaustion into another internal error must preserve it before
performing their Linux errno mapping. The hook never invokes shrinkers, waits,
or selects an OOM victim inline because its caller may hold an IRQ-safe lock
that those paths need. Hierarchical current counters use atomic reservation
with rollback, so concurrent charges cannot individually pass a stale max
check and overrun the limit. Background reclaim is currently global rather
than cgroup-keyed; deferred throttling and scoped memcg OOM require stable
allocation-owner attribution and remain follow-up work.

`/proc/numastat` exposes live per-node allocation events supplied by
`memory/`: hit, miss, foreign, interleave-hit, local, and other counters.
`/proc/<pid>/numa_maps` reports each registered base-page or hardware
huge-page region's effective policy, resident base-page equivalents grouped
by SRAT node, and actual translation-leaf size.
`/sys/devices/system/node/nodeN/{meminfo,numastat,vmstat}` exposes stable
managed totals, live free/used pages, and the corresponding node-local
event counters. Each node directory exposes Linux-compatible `cpuM` symlinks,
with reciprocal `cpuM/nodeN` links under `/sys/devices/system/cpu`; consumers
such as `perf stat --per-node` use the symlink type and name to construct the
CPU-to-node aggregation map. If firmware supplies no CPU-affinity table and
exactly one node exists, all online CPUs belong to node 0; multi-node systems
never infer missing proximity.
`/sys/kernel/mm/mempolicy/weighted_interleave/nodeN` exposes writable
decimal weights in Linux's inclusive range 1..=255. Changes affect new
`MPOL_WEIGHTED_INTERLEAVE` allocations and never migrate existing pages.
The sibling `auto` attribute accepts Linux boolean strings; enabling it
recomputes weights from parsed HMAT bandwidth and fails if no usable
bandwidth coordinates exist. Writing `nodeN` selects manual mode.
`/sys/kernel/notes` is a binary sysfs attribute containing the exact
linker-retained GNU build-ID note for the running NARF kernel. Linux perf
uses this note to identify kernel samples in persisted `perf.data`.
`/proc/buddyinfo` reports live per-order free-block counts, while
`/proc/zoneinfo` uses stable per-node managed totals and live NUMA events.

### 3.4 Directory operations

```rust
pub fn readdir(d: &DirCap) -> impl Stream<Item = DirEntry>;
pub fn create_file(d: &DirCap, name: &str, cap: …) -> impl Future<Output = FileCap>;
pub fn mkdir(d: &DirCap, name: &str, cap: …)       -> impl Future<Output = DirCap>;
pub fn unlink(d: &DirCap, name: &str, cap: …)      -> impl Future<Output = ()>;
pub fn rename(src: &DirCap, src_name: &str, dst: &DirCap, dst_name: &str, cap: …) -> impl Future<Output = ()>;

pub struct FsQuotaInherit {
    pub flags: u64,
    pub parents: Vec<u64>,
    pub limit: [u64; 5],
}

pub trait DirOps {
    fn dir_owners(&self) -> (u32, u32);
    fn set_dir_owners(&self, uid: u32, gid: u32);
    async fn set_dir_owners_async(&self, uid: u32, gid: u32) -> Result<(), FsError>;
    async fn set_dir_mode_async(&self, perms: u16) -> Result<(), FsError>;
    async fn snapshot_async(
        &self,
        source: Arc<dyn DirOps>,
        name: &str,
        readonly: bool,
    ) -> Result<(), FsError>;
    async fn snapshot_with_quota_async(
        &self,
        source: Arc<dyn DirOps>,
        name: &str,
        readonly: bool,
        quota: FsQuotaInherit,
    ) -> Result<(), FsError>;
}
```

Directory-owner accessors default to root ownership and a no-op setter for
read-only/synthetic filesystems. Writable in-memory filesystems preserve the
values through mount-root `uid=`/`gid=`, mkdir inheritance, path stat,
directory-fd stat, and access checks. Disk-backed filesystems override the
asynchronous setters so `mkdir`, `chmod`, and ownership changes are persisted
before the syscall completes; the default async implementations retain the
synchronous setter behaviour for in-memory and synthetic filesystems. Mode
setters carry Linux's low 12 `S_IALLUGO` bits (`07777`). A writable overlay
copies up a lower-only directory before applying asynchronous mode or owner
updates; a persistence or copy-up failure is returned to the syscall layer.

### 3.5 Mount

```rust
pub fn mount(on: &DirCap, fs: Cap<FsInstance, Attach>, opts: MountOpts) -> Cap<MountPoint, _>;
pub fn unmount(mp: Cap<MountPoint, Own>) -> impl Future<Output = ()>;

pub trait FsInstance {
    fn statfs(&self) -> impl Future<Output = Result<FsStat, FsError>>;
    fn reconfigure(&self, options: &str) -> Result<(), FsError>;
}
```

Persistent-format drivers may expose a typed assembly entry point in addition
to the generic mount registry. Btrfs provides
`BtrfsVolume::mount_devices(Vec<Arc<B>>, DomainId)` and the corresponding
`mount_devices_opts` / `mount_subvol_devices` variants. The first member selects
the FSID; other supplied or registry-discovered devices are matched by FSID and
on-disk devid. A complete generation-consistent set may be writable. A missing
or stale member set is read-only and succeeds only when the selected profile can
reconstruct every block needed by mount and later I/O.

The typed btrfs administration surface is:

```rust
pub struct BalanceProfiles {
    pub data: Option<ChunkProfile>,
    pub metadata: Option<ChunkProfile>,
    pub system: Option<ChunkProfile>,
}

impl<B: BlockDevice> BtrfsVolume<B> {
    pub async fn add_device(&self, device: Arc<B>) -> Result<u64, FsError>;
    pub async fn remove_device(&self, devid: u64) -> Result<(), FsError>;
    pub async fn replace_device(&self, devid: u64, target: Arc<B>) -> Result<(), FsError>;
    pub async fn balance_profiles(&self, targets: BalanceProfiles)
        -> Result<BalanceStats, FsError>;
}
```

Add commits the member's `DEV_ITEM` and superblocks; new chunks are allocated by
the normal profile-aware growth path. Replace copies allocated device extents
while retaining devid, UUID, and stripe offsets. Remove performs a synchronous
balance evacuation before deleting the member. Profile conversion operates on
complete DATA/METADATA/SYSTEM allocation classes, preserves every chunk's
logical address, and commits replacement `CHUNK_ITEM`s, physical device extents,
block-group flags, the system chunk array, and member superblocks atomically.
Insufficient members return `Busy`; insufficient crash-safe destination space
returns `NoSpace`. Linux lifecycle/balance ioctls and their filter/progress/
pause/cancel ABI are not part of this typed interface yet.

A mount is just another capability; removing it closes access via
that path. Existing open caps on nodes across the mount continue to
work (refcount-style) until they too are released.

#### 3.5.1 Linux tmpfs and ramfs

`TmpFs` is a distinct Linux-compatible in-memory filesystem instance, rather
than an alias for unlimited `MemFs`. `TmpFsOptions` parses `size=`,
`nr_blocks=`, `nr_inodes=`, `mode=`, `uid=`, `gid=`, `noswap`, `inode32`,
`inode64`, `huge=never`, and the allocation policies NARF can truthfully
honour (`mpol=default|local`). Default block and inode limits are half of
managed RAM pages; a zero limit means unlimited. Files are sparse page-indexed
objects: truncate growth creates holes, allocated pages drive `stat.blocks`
and `statfs`, and the mount enforces block/inode limits with
`FsError::NoSpace`. `reconfigure` permits supported live limit changes but
rejects a limit below current use. Since NARF has no swap-backed shmem path,
all mounts have `noswap` behaviour even when the option is omitted.

`RamFs` shares the in-memory inode and sparse-data semantics but is always
unlimited, unswappable, and non-resizable. It accepts `mode=` and, matching
Linux ramfs's historical parser, ignores unknown mount parameters. Its
filesystem name and magic remain distinct from tmpfs (`ramfs`, 0x858458f6;
tmpfs, 0x01021994).

Both filesystems support regular files, directories, symlinks, FIFOs,
character/block special nodes, sockets, hard links and cross-directory atomic
rename within one instance, `O_TMPFILE`, sparse `SEEK_DATA`/`SEEK_HOLE`, hole
punch/zero-range/preallocation, and regular-file `user.*`, `trusted.*`, and
`security.*` xattrs. Inodes and allocated pages remain charged until the last
directory entry/open reference drops.

In-memory directories participate in the VFS RCU dentry cache. Their
authoritative entry maps remain writer-locked, while every name-set mutation is
announced by `PathMutationGuard`; therefore a warmed read takes neither that
map lock nor a mount-table lock. Cache buckets are bounded, dentries hold their
parent name objects and inode-operation references, overlapping mutations are
rejected, named mutations invalidate only affected aliases, and retained child
references obey the same open-after-unlink lifetime rule as ordinary node
handles.

Linux-compat mount namespaces hold a private snapshot of the mount table.
Mount, bind-mount, and unmount operations after `CLONE_NEWNS` mutate that
snapshot only. Private tables permit mount stacking; path resolution and
unmount select the most recently attached mount at an equal path.
Every attachment receives a nonzero mount ID, and `mount_id_at` reports the
newest visible mount so Linux `name_to_handle_at(2)` can expose mount identity.
Open file descriptions retain the mount ID visible at open time, including for
`name_to_handle_at(AT_EMPTY_PATH)`, even when a later mount covers that path.
`list_mountinfo` preserves attachment order and reports the covered or nearest
ancestor mount ID as each entry's parent for `/proc/<pid>/mountinfo`.
The procfs view hides mounts outside the queried task's root and projects that
root to `/`, so a chrooted task never sees backing prefixes such as `/mnt`.
The procfs task-info hook takes a `TaskInfoQuery`: ordinary liveness,
`stat`, `status`, `statm`, `cmdline`, and `comm` requests use allocation-free
aggregate memory counters and leave the VMA vector empty; only `maps` and
`numa_maps` request the potentially large per-region detail snapshot.
This per-task mountinfo projection is wired for every Linux-compat build,
independently of optional container namespaces: service managers use
`CLONE_NEWNS` for sandboxing and must observe private stacked file binds before
they remount them read-only.
`/proc/mounts` and `/proc/<pid>/mounts` render `show_vfsmnt` rows from the
same per-task view (the namespace hook's seven tab-separated fields, else
`list_mountinfo`): options are `rw`/`ro` (mount or superblock read-only), then
the superblock options, then the mount options, then `show_options`. Device
and fstype are octal-escaped with `mangle()`'s set (`" \t\n\\#"`) and mount
points with `seq_path_root`'s (`" \t\n\\"`), in both those files and
`mountinfo`. The mountinfo hook is global state; `MountinfoHookGuard::install`
installs one for a scope and restores the previous hook on drop.
An already-open `/proc/<pid>/mountinfo` file reports a `POLLPRI` edge after an
attach, detach, or move in that task's visible mount namespace; unrelated
namespace mutations do not advance its generation. This lets libmount rescan
the same view synchronously after a mount helper exits. Each successful table
mutation also fires the boot-installed readiness wake hook after releasing the
mount-table lock, so a blocked poll/epoll monitor is scheduled before a
concurrent mount-helper `SIGCHLD` can be processed.
Recursive bind mounts rebase every visible descendant mount beneath the new
target, preserving nested API mounts such as cgroup2 beneath a bound `/sys`.
A recursive bind whose normalized source and target are identical stacks the
root only; its descendants are already attached at the required paths.
Nested `unshare(CLONE_NEWNS)` and `clone(CLONE_NEWNS)` copy the caller's
current private table rather than rebuilding from the global registry.
`clone_tree_at` exposes an arbitrary directory subtree as a detached
filesystem root for Linux `open_tree(2)` / `open_tree_attr(2)` and later
`move_mount(2)`. `open_tree_attr(2)` validates the extensible Linux
`mount_attr` record and its trailing extension bytes before publishing the
descriptor; an attribute failure leaves no visible or retained detached tree.
An `OPEN_TREE_CLONE` detached object retains the visible descendant
mounts beneath that root; attaching it rebases those mount paths beneath
the new target.
Classic `MS_MOVE` relocates the topmost source mount to the target without
changing its filesystem object.

### 3.6 Filesystem driver interface

```rust
pub trait Filesystem: Send + Sync {
    fn fs_kind(&self) -> FsKind;
    async fn resolve_step(&self, parent: NodeId, name: &str) -> Result<NodeId, FsError>;
    async fn read (&self, node: NodeId, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;
    async fn write(&self, node: NodeId, offset: u64, buf: &[u8])     -> Result<usize, FsError>;
    /* … */
}

pub trait DirOps: Send + Sync {
    fn dir_owners(&self) -> (u32, u32);
    fn set_dir_owners(&self, uid: u32, gid: u32);
    async fn set_dir_owners_async(&self, uid: u32, gid: u32) -> Result<(), FsError>;
    async fn set_dir_mode_async(&self, perms: u16) -> Result<(), FsError>;
    async fn fsync(&self, data_only: bool) -> Result<(), FsError>;
    async fn syncfs(&self) -> Result<(), FsError>;
    async fn ioctl_async(&self, cmd: u32, arg: u64, input: &[u8], out_size: usize)
        -> Result<FsIoctlReply, FsError>;
    async fn snapshot_async(
        &self,
        source: Arc<dyn DirOps>,
        name: &str,
        readonly: bool,
    ) -> Result<(), FsError>;
    async fn snapshot_with_quota_async(
        &self,
        source: Arc<dyn DirOps>,
        name: &str,
        readonly: bool,
        quota: FsQuotaInherit,
    ) -> Result<(), FsError>;
    /* … */
}

pub trait FsInstance: Send + Sync {
    fn root(&self) -> Arc<dyn DirOps>;
    fn name(&self) -> &str;
    fn backing_identity(&self) -> usize;
    async fn statfs(&self) -> Result<FsStat, FsError>;
    fn reconfigure(&self, options: &str) -> Result<(), FsError>;
}
```

Filesystems run in their own PKS/MTE domain (Stage 4) and communicate
with `filesystem/` core via Narf-Ring.

Every future returned through `FileOps`, `DirOps`, or `FsInstance` obeys the
standard wake contract: before returning `Poll::Pending`, it registers the
current task waker with the event or resource that can make progress. Reply,
I/O completion, disconnect, cancellation, and resource release publish their
state before waking the waiter. Registration and readiness inspection are
ordered under one lock or an equivalent register-then-recheck protocol, so a
wake racing with the transition to sleep cannot be lost. Futures do not
self-wake merely to obtain another poll; synchronous Linux-compat callers park
their stackful task and resume only when this wake contract fires.

For a shared device mapping, `mmap_frames` supplies borrowed physical pages
and `mmap_lifetime` may supply a narrower per-object owner. The compatibility
VMA registry clones that owner across fork and VMA splits and drops it after
the last unmap. Multiplexed devices must return the specific backing owner;
retaining only the open file is insufficient when an object handle can close
while the file remains live.

For a generic shared file mapping, `mmap_cache_generation` may identify the
file as generic (mutually exclusive with `mmap_frames`/`mmap_fault`) and opt it
into bounded retention of clean fallback pages after their final unmap. The
generation changes after every byte or length mutation; an idle page is reused
only while its recorded generation matches. The cache keeps only a weak file
reference, never discards a dirty page, and files returning `None` retain the
conservative final-unmap reclamation behavior.

`supports_mmap_fault` is the side-effect-free capability check for direct
demand backing. It is deliberately separate from `mmap_fault`: a refusal at
an offset beyond the current EOF must not make `mmap(2)` select the generic
copy fallback for the whole VMA. A filesystem shrinking such a direct-mapped
file calls `unmap_mapping_range` before retiring its cache folios; userspace
installs the VMA-owning hook during common boot, while standalone filesystem
tests with no userspace mappings safely observe a no-op.
`mmap_backing_identity` identifies the live object owning those pages;
forwarding wrappers preserve the underlying value so a truncate issued by the
backing filesystem still finds and revokes VMAs owned by the wrapper.

Ordinary unlocked generic shared mappings are demand-backed: VMA publication
records absent page slots and first access resolves the canonical cache page.
`MAP_LOCKED` and blocking `MAP_POPULATE` retain eager materialization; combining
`MAP_POPULATE` with `MAP_NONBLOCK` suppresses the prefault as on Linux.

`backing_identity` identifies the backing filesystem object rather than a
mount attachment. Bind-mount adapters preserve their source value so a VFS
consumer can recognise aliases of the same `(filesystem, inode)` pair.

### 3.7 Page cache (optional per fs)

- Default behaviour: read-modify-write path goes through a unified
  page cache sized by `memory/` policy.
- The cache's native resident unit is `CacheFolio`: a physically
  contiguous, naturally aligned run of `2^order` base pages. `PageKey`
  remains a base-page index `(fs_id, inode, page_off)`; inode 0 is the
  filesystem's block-device mapping (Linux's `bdev` inode). A lookup returns
  a retained `FolioRef`; its `FolioSlice` views keep the allocation alive
  without copying or holding the cache lock.
- **The fill protocol is the cache's, not the filesystem's.**
  `PageCache::get_or_fill(key, order, fill)` (Linux `filemap_read_folio`)
  does lookup → miss coalescing → fill → publish: the first miss installs a
  *fill ticket* for exactly the folio's page range under the cache lock,
  concurrent misses on any covered page park on it, the caller's async
  `fill` runs unlocked, and the folio replaces the ticket only if the ticket
  is still the one it installed. A failed or dropped fill removes its ticket
  and wakes its waiters. `Filled::published()` is `false` when the caller's
  own fill was invalidated mid-read: the bytes are a valid read for that
  caller but were never cached and must not be handed out as the shared
  copy. `OutOfMemory` (no folio frame) lets the caller degrade to a bounded
  uncached read.
- **Invalidation is per key.** `PageCache::invalidate_range(fs, inode,
  first, end)` (Linux `invalidate_mapping_pages`) drops the clean resident
  folios overlapping the range *and* removes the overlapping fill tickets,
  so a fill refuses to publish exactly when its own pages were written while
  it read them; writes elsewhere never void it. There is no volume-global
  generation. Dirty folios are kept.
- `BlockMapping` is the typed facade for a filesystem's bdev mapping
  (metadata keyed by device page). Its folios are never modified in place —
  a device write invalidates the pages it covers — which is what makes
  zero-copy `&[u8]` views of them sound. Raw insertion
  (`__insert_folio_for_test`) is test-only; production publication goes
  through `get_or_fill`.
- `FileMapping` is one inode's page cache (Linux `struct address_space`):
  the single set of folios through which `read(2)`, `write(2)` and every
  `MAP_SHARED` mapping of the inode see its bytes; a filesystem keeps one per
  in-memory inode. Its folios are updated in place, so it never hands out
  `&[u8]`: `FileFolio::read`/`write`/`zero` copy. `get_or_fill` is the same
  protocol as above (the filesystem's `->read_folio` is the `fill`);
  `mark_dirty`/`take_dirty` drive writeback; `remove_from(page)` is
  `truncate_inode_pages` (`PageCache::remove_range`: removes dirty folios and
  voids fills too — the bytes cease to exist). `FileFolio::mmap_frame`
  returns the physical cache page and acquires one external alias reference;
  failed PTE publication or later unmap releases it through the shared-frame
  hook. One strong folio hold spans all aliases, so a borrowed user PTE can
  never outlive or race reclaim of its cache frame.
- Reclaim evicts only clean folios whose sole reference is the cache's own.
  A folio someone holds is in use *as the cache's copy* (a writer updating
  it, a reader copying out, a user mapping) — evicting it would let the next
  lookup refill a second, divergent copy (Linux reclaim likewise fails to
  freeze such a folio's refcount).
- Lock order / reclaim: the cache lock is an `IrqSafeSpinLock` never held
  across `.await` or while waking; allocation under it relies on
  `narf_memory::reclaim::GLOBAL_ALLOC_RUNS_SHRINKERS == false`, which the
  page cache `const`-asserts and memory's
  `smoke_global_alloc_failure_has_no_inline_reclaim_or_retry` pins. The
  shrinker entry points (`shrink`, `reclaimable`) only `try_lock` the cache,
  so reclaim can never deadlock against it. Registry order is
  `PAGE_CACHE_REGISTRY` → cache lock. The mapped-folio physical registry
  does not nest with either and drops its last strong hold after unlocking.
- Capacity, watermark reclaim, and shrinker counts are expressed in base
  pages, not folio heads. CLOCK recency and dirty/writeback state are per
  folio; reclaim never splits a folio and never evicts a dirty folio or a
  fill ticket. `PageCache::take_dirty(fs, inode, first, end)` hands dirty
  folios to writeback and clears their dirty bit (a failed writeback
  re-marks with `mark_dirty`).
- Order-zero allocation is the guaranteed fast path. Higher-order allocation
  is opportunistic: callers must fall back to a smaller folio or a bounded
  uncached read when contiguous memory is unavailable. Cache metadata locks
  never span backing-store I/O or `.await`.
- Opt-out: `MountOpts { direct: true }` bypasses the cache for that
  mount — useful for virtiofs-backed host passthrough where the host
  already caches.
- Cache eviction: LRU-ish with a "recently used" second chance;
  explicit pressure hook from `memory/`.

### 3.8 Linux FUSE compatibility

`FuseConnection` implements the Linux FUSE 7.36 message transport used
by `/dev/fuse` and `virtiofs`. Each open of `/dev/fuse` owns one
connection; reads return exactly one complete request and writes match
replies by the non-zero `unique` identifier.

`FUSE_DEV_IOC_CLONE` replaces a fresh `/dev/fuse` endpoint with another
daemon endpoint on the source fd's connection. Cloned endpoints share
request and reply queues, and closing one endpoint leaves the connection
live until the final daemon endpoint closes.

When `FUSE_PASSTHROUGH` is negotiated, `FUSE_DEV_IOC_BACKING_OPEN` and
`FUSE_DEV_IOC_BACKING_CLOSE` manage connection-scoped backing-file IDs.
An `OPEN` or `CREATE` reply carrying `FOPEN_PASSTHROUGH` and a live
`backing_id` routes file reads and writes directly to that backing file;
metadata and lifecycle operations remain on the FUSE connection. Unknown
IDs, non-zero backing-map flags/padding, and passthrough without successful
capability negotiation are rejected.

Dropping an initialized `FuseFs` sends exactly one forced `FUSE_DESTROY`
request with an empty body, retires registered passthrough backings, and
does not retain an unobserved reply slot. Failed INIT and already-disconnected
connections do not send DESTROY.

Every `/dev/fuse` or direct `FuseFs` connection is represented at
`/sys/fs/fuse/connections/<id>`. Its `waiting` attribute reports queued plus
in-flight requests, and writing `abort` disconnects the daemon and completes
parked callers with `ENOTCONN`. Writable `max_background` and
`congestion_threshold` attributes use Linux's defaults of 12 and 9, accept
16-bit unsigned limits, and reflect non-zero daemon values negotiated in
FUSE_INIT 7.13 or newer. The directory is removed when the connection object
is finally reclaimed.

Reply-bearing operations submitted from non-awaitable teardown paths are
tracked as background work. At most `max_background` such operations are
visible to the daemon at once; completions promote deferred operations in FIFO
order. `congestion_threshold` defines the connection's observable congestion
state, and `waiting` includes deferred background work.

NARF advertises Linux's `FUSE_NO_OPEN_SUPPORT` and
`FUSE_NO_OPENDIR_SUPPORT` negotiation bits. An `ENOSYS` response to the first
`OPEN` or `OPENDIR` is cached for the connection; subsequent file and
directory operations use the implicit handle zero and omit the matching
`RELEASE` or `RELEASEDIR` request.

When `FUSE_REQUEST_TIMEOUT` is negotiated with a non-zero timeout, the value is
clamped to Linux's 15-second minimum and every subsequent request is
deadline-bound using the monotonic timer wheel. An
expired queued or in-flight request aborts the entire connection, retires all
queued transport work, and completes parked callers with a connection error,
matching Linux's connection-level timeout behavior.

- An empty blocking read parks in the syscall layer; a non-blocking
  read reports `EAGAIN`.
- A daemon buffer smaller than the next complete request reports
  `EINVAL` without consuming or truncating that request.
- Dropping an unsent VFS future removes its queued request and reply
  slot. Dropping a request already delivered to the daemon queues
  `FUSE_INTERRUPT` naming the original unique ID; late replies are ignored.
- Directory traffic uses `OPENDIR`, `READDIR`, and `RELEASEDIR`, which
  are distinct from regular-file `OPEN` and `RELEASE`.
- The bridge supports lookup, getattr/setattr, create, mknod, mkdir,
  unlink, rmdir, same- and cross-directory rename/link, symlink, open, read,
  write, flush, fsync/fdatasync, extended attributes, access checks,
  readlink, statfs, readdir, release,
  forget, and initialization.
- Anonymous files use `FUSE_TMPFILE`; `linkat(AT_EMPTY_PATH)` materialises
  them with `FUSE_LINK` on the same connection. Cross-filesystem
  materialisation reports `EXDEV`.

`FsInstance::statfs` is the asynchronous filesystem-capacity interface.
Its `FsStat` result is translated to Linux `struct statfs`; FUSE mounts
source those values from `FUSE_STATFS`, while other filesystems retain
the conservative synthetic default.

`FileOps::flush` runs on descriptor close when `FileOps::has_flush` reports
an implementation hook, and `FileOps::fsync` backs Linux
`fsync(2)`/`fdatasync(2)`. FUSE files translate these to `FUSE_FLUSH` and
`FUSE_FSYNC`; non-FUSE implementations default to success and skip the
no-op future when they have no volatile backing state. Directory descriptors
forward the same operation through `DirOps`; FUSE opens a directory
handle, issues `FUSE_FSYNCDIR` with the data-only flag when requested,
and releases the handle.
`FileOps::syncfs` and `DirOps::syncfs` back Linux `syncfs(fd)`, which
validates the descriptor and flushes its backing filesystem. FUSE sends
`FUSE_SYNCFS` to the mount's root node with the Linux zeroed request body.
If the daemon replies `ENOSYS`, that call succeeds and the connection
suppresses subsequent `FUSE_SYNCFS` requests, matching Linux.

`DirOps::rename_to` and `DirOps::link_to` express atomic operations
between two directories of one filesystem. FUSE translates the target
directory inode into `fuse_rename_in.newdir` / the `FUSE_LINK` request
node and uses `FUSE_RENAME2` when Linux `RENAME_*` flags are present.
Operations spanning distinct connections or mounts report `EXDEV`.

`FileOps` exposes set/get/list/remove extended-attribute operations.
FUSE uses the Linux two-request size-probe convention for GETXATTR and
LISTXATTR and preserves XATTR_CREATE/XATTR_REPLACE flags. Filesystems
without native xattrs retain the userspace side-table fallback.

`FileOps::access` carries Linux R_OK/W_OK/X_OK bits to filesystems that
perform daemon-side authorization. FUSE translates it to `FUSE_ACCESS`;
the syscall layer falls back to the inode owner/mode check only when the
filesystem reports that native access checks are unsupported.

`FileOps::get_lock` and `FileOps::set_lock` carry inclusive byte ranges,
lock owner IDs, type, and blocking intent. FUSE maps these to GETLK,
SETLK, and SETLKW with the daemon file handle; local filesystems retain
the kernel advisory-lock table fallback.

`FileOps::fallocate`, `seek`, and `copy_file_range_to` expose native
range operations. FUSE maps these to FALLOCATE, LSEEK (for SEEK_DATA /
SEEK_HOLE), and COPY_FILE_RANGE when both files share one connection;
the syscall layer retains truncate/zero, generic seek, and buffered-copy
fallbacks for filesystems that return `Unsupported`.

`FileOps::ioctl_async` and `DirOps::ioctl_async` carry Linux
`_IOC`-described input and output buffers. Open-directory wrappers forward
the latter so filesystem-specific directory ioctls retain their inode context.
FUSE maps file ioctls to restricted `FUSE_IOCTL`,
copies no more than the encoded `_IOC_SIZE`, rejects oversized replies,
and rejects `FUSE_IOCTL_RETRY`; daemon-selected retry iovecs are reserved
for the separately privileged CUSE unrestricted-ioctl contract.

`DirOps::snapshot_async` receives a source directory already resolved from the
calling process's fd table. This keeps process-local descriptor lookup in the
syscall layer while allowing a filesystem to validate same-instance ancestry
and commit a native snapshot below the destination directory. The default is
`Unsupported`. `snapshot_with_quota_async` carries the same resolved source plus
filesystem-native hierarchical quota parents and the Linux-compatible five-word
limit record. Drivers without native quota inheritance return `Unsupported`
without creating the snapshot.

`FsError::QuotaExceeded` is the storage-independent hard-quota failure and maps
to Linux `EDQUOT`. It remains distinct from `FsError::NoSpace`/`ENOSPC`, so a
caller can distinguish policy exhaustion from exhausted backing storage.
`FsError::OperationNotPermitted` represents an operation prohibited by object
state and maps to Linux `EPERM`; it remains distinct from access-mode or
credential denial (`PermissionDenied`/`EACCES`) and a read-only filesystem
(`ReadOnly`/`EROFS`). Memfd seal violations use this variant.
Device ioctl implementations may also return `BadAddress` (`EFAULT`),
`OutOfMemory` (`ENOMEM`), `NotImplemented` (`ENOSYS`), and `AlreadyExists`
(`EEXIST`). These remain distinct from `InvalidData` (`EINVAL`) and
`Unsupported`, whose direct-ioctl meaning is an unknown command (`ENOTTY`), so
Linux UAPI error precedence survives the `FileOps` boundary.

`FileOps::drm_prime_export_file(handle)` and
`FileOps::drm_prime_import_file(dma_buf)` are the type-erased VFS handoff for
per-open DRM GEM namespaces. The syscall layer owns descriptor allocation;
the DRM file owns handle lookup/import and may recover its driver-specific
dma-buf through `FileOps::as_any`. Drivers without a per-open implementation
return `Unsupported` and retain the card-global compatibility hook.

`FileOps::drm_execbuf_fence()` hands the descriptor-owning syscall layer the
exact driver-owned completion object from the calling task's successful DRM
EXECBUFFER. `DrmFence` supplies readiness, bounded wait, and an optional
ordered-context key; `drm_execbuf_context(ring_idx)` supplies the matching key
for a new submission so a same-ring input fence can rely on queue ordering
without a synchronous wait. Drivers that do not produce device fences return
`None` and retain the pre-signalled compatibility behavior.

FUSE file handles register `POLL` once with a stable kernel handle and
cache the daemon's `revents`. `FUSE_NOTIFY_POLL` invalidates that
registration so the next readiness query re-polls the daemon. Poll
requests never leave ordinary reply slots behind.

`FUSE_INIT` uses the Linux 7.45 64-byte extended request/reply layout. The
client advertises only implemented protocol features, accepts compatible
short legacy replies by zero-extending them, intersects daemon flags with
that set, and records the negotiated minor version and write limit on the
connection. Major versions other than 7 and protocol minors before 7.5
are rejected. A failed, malformed, disconnected, or timed-out INIT aborts
the mount instead of publishing a partially initialized filesystem.
Protocol 7.45 peers use `FUSE_COPY_FILE_RANGE_64` so successful copies
can report byte counts beyond `u32`; older peers retain the original
reply shape.
`FileOps::statx_async` preserves the daemon's `FUSE_STATX` mask, birth
time, attributes, ownership, device numbers, and nanosecond timestamps;
malformed timestamps are rejected.
`FileOps::bmap` forwards logical-block translation through `FUSE_BMAP`.
`setup_mapping` and `remove_mappings` implement virtiofs DAX window
management through `FUSE_SETUPMAPPING` and batched `FUSE_REMOVEMAPPING`;
requests must be 4 KiB aligned, use only READ/WRITE flags, and respect
Linux's one-page removal-entry limit.
FUSE writes are split into requests no larger than the negotiated
`max_write`; each request advances the file offset, an oversized daemon
reply is rejected as invalid data, and a short reply ends the write with
the accumulated byte count.
When `FUSE_MAX_PAGES` is negotiated, reads and writes are also bounded by
the daemon's `max_pages` in 4 KiB pages. Large reads advance their offset
across requests, stop on a short reply, and reject replies larger than
the requested chunk.

Every request header is stamped with the calling task's translated
filesystem uid/gid and visible process id through a boot-installed
request-context provider. Kernel-only callers retain the zero-valued
fallback when no userspace provider is installed.

Daemon `INVAL_INODE`, `INVAL_ENTRY`, and `DELETE` notifications are
wire-validated and accepted. They require no cache mutation while the
FUSE bridge remains uncached; adding inode, dentry, or page caching must
attach the corresponding invalidation before enabling that cache.
`STORE` retains daemon-provided ranges per connection and `RETRIEVE`
answers with a one-way `FUSE_NOTIFY_REPLY` carrying the matching bytes.
`RESEND`, `INC_EPOCH`, and `PRUNE` are wire-validated; epoch changes are
tracked and prune drops the requested number of retained ranges.

When the daemon negotiates `DO_READDIRPLUS`, directory enumeration uses
`READDIRPLUS`, validates each combined entry/dirent record, and emits an
immediate `FORGET` for the otherwise-uncached lookup reference. Daemons
without the capability continue to receive ordinary `READDIR`.

Pending inode lookup releases are coalesced into Linux `BATCH_FORGET`
messages when the daemon reads its queue. Coalescing respects the daemon
buffer size, preserves each `(nodeid, nlookup)` pair, and never creates a
reply slot because forget operations are one-way.

Wire structures in `filesystem::fuse` are `#[repr(C)]` shapes matching
Linux UAPI field order and width. Malformed or short replies fail with
`FsError::InvalidData`; a disconnected daemon fails pending requests
without leaving callers parked indefinitely.
FUSE reply slots retain the awaiting task's waker. Daemon reply and connection
disconnect atomically publish a terminal reply, take that waker, and wake it;
request cancellation removes the slot and its registration.

### 3.9 Linux synthetic filesystem projections

With `linux-compat`, sysfs exposes only interfaces backed by a NARF authority.
Block devices have canonical kobjects at
`/sys/devices/virtual/block/<name>`; `/sys/class/block` and `/sys/block` are
discovery views. Block `add` uevents and `/sys/dev/block/<major>:<minor>`
links name the canonical device kobject, so systemd-udevd can construct an
`sd_device`, apply filesystem-identification rules, and satisfy fstab UUID
mount dependencies. Partition events with a discovered filesystem UUID carry
both the existing `DEVLINKS=/dev/disk/by-uuid/<uuid>` path and the matching
`SYSTEMD_ALIAS`; systemd device units are driven by the udev database rather
than by probing whether the devfs symlink resolves.
`/sys/class/net/<dev>` is populated from the network stack's interface list
(installed net snapshot hook) and refreshed from a `Stage::Late` initcall, after
the NIC drivers have probed. Each device carries Linux's net-sysfs attributes —
`ifindex` and `iflink` (the rtnetlink ifindex udev keys its database on),
`type` (`ARPHRD_ETHER`/`ARPHRD_LOOPBACK`), `addr_len`, `dev_id`, `address`,
`broadcast`, `operstate` (`unknown` for `lo`), `mtu`, `flags` (`dev->flags`,
never the volatile `IFF_RUNNING`; `IFF_PROMISC`/`IFF_ALLMULTI` while the
snapshot's `NetIfaceInfo::promisc`/`allmulti` report a non-zero
`dev->promiscuity`/`dev->allmulti`), a writable `uevent` with `INTERFACE` and
`IFINDEX` — and the `subsystem` link; `mtu`, `operstate` and `flags` read live
state.
The bounded boot udev replay begins at the first completed late device
projection and never advances past already-queued ADD events when another
projection completes. This lets independently registered DRM and block
devices share one coldplug window without replaying incomplete early-boot
kobjects or dropping the graphical master before systemd-udevd starts.
The perf discovery projection is
`/sys/bus/event_source/devices/{cpu,software,narf_trace}`: it publishes PMU type numbers,
the online CPU mask, and architecture-correct raw CPU PMU `format/*` bitfields
(x86 event/unit-mask controls or the aarch64 16-bit architectural event
number). On aarch64, `events/*` publishes the architectural cycles,
instructions, cache-miss, branch, and branch-miss aliases only when the
corresponding PMCEID bit is set. Model-specific event aliases must not be
published until derived from the detected PMU. `narf_trace` publishes Linux
tracepoint type 2 and a 64-bit `id` config field for authoritative typed-event
or dynamic-probe IDs.

Procfs advertises the Linux filesystem type `proc`. Its magic links
(`/proc/self`, `/proc/thread-self`, and per-task `exe`, `cwd`, `root`, `fd`,
and namespace links) report symlink mode with `st_size == 0`, matching Linux;
callers must use `readlink(2)` rather than infer a target length from stat
metadata. In a container-enabled build, following a per-task namespace magic
link through `open(2)` produces an nsfs-like descriptor that retains the
namespace object for `setns(2)`; `O_PATH|O_NOFOLLOW` instead opens the symlink
node itself. The proc fd provider returns one `ProcFdSnapshot` containing the
link target plus live offset, status flags, mount ID, and inode identity, so
`fd/` and `fdinfo/` project the same open file description.
For user namespaces, `/proc/<pid>/uid_map` and `gid_map` expose parent-to-child
id ranges, while `setgroups` reads `allow` or `deny` and accepts the one-way
`deny` transition before `gid_map` is installed. Their inode owners use the
target task's kernel-global effective UID/GID, including before child maps
exist. The procfs/userspace hooks identify files with
`NsIdMapFile::{UidMap,GidMap,Setgroups}` and supply inode owners and a fallible
per-open `FileOps` factory. Open descriptors retain the target namespace and
opener credentials across namespace changes and target exit. Writes reject
nonzero offsets; map reads translate the second column into the opener's
namespace (the target's parent for self-reads).
`/proc/filesystems` uses the `nodev NAME` form for synthetic filesystems.
`/proc/uptime` reports aggregate idle time across CPUs, and per-task status
memory fields are derived from VMA extents and resident page counts. Procfs
values that have no authoritative NARF provider remain absent rather than
fabricated measurements.
`/proc/net/tcp` rows follow Linux `get_tcp4_sock` column order through the
congestion-window and slow-start-threshold tail. Timer, probe, RTO, delayed-ACK,
and congestion values come from the TCP snapshot hook; identity values remain
zero until an authoritative socket-owner provider is installed.
`/proc/net/sockstat` and `sockstat6` expose Linux's line and field names and
derive protocol in-use, TIME-WAIT, and allocation counts from the same
namespace-scoped socket snapshots as the protocol tables.
`/proc/net/netstat` emits positionally paired `TcpExt`, `IpExt`, and
`MPTcpExt` header/value rows. `/proc/net/snmp6` uses Linux's one-counter-per-line
format. Both consume the namespace-scoped SNMP snapshot and leave unavailable
extended statistics at zero.
The supported surface and known partial projections are tracked in
`filesystem/PROCFS_LINUX_COMPAT_AUDIT.md`.

Efivarfs exposes firmware variables as
`VariableName-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Each regular file has
mode 0644 and its byte stream begins with the little-endian four-byte EFI
attribute word followed by the variable data. Complete-file writes preserve
append and authenticated-write attribute bits and are serialized with the
firmware backend. Directory enumeration, create, unlink, `uid=`/`gid=`,
`QueryVariableInfo`-backed `statfs`, stable inode identities, GUID
case-insensitive lookup, and Linux's default-immutable protection for unknown
variables are supported. `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS` expose and change
`FS_IMMUTABLE_FL`.

An efivarfs mount is rejected when EFI Runtime Services and their persistent
memory mappings were not installed by the boot path. NARF never substitutes a
volatile in-memory store for firmware persistence. The audited behavior and
the boot/runtime-service dependency are tracked in
`filesystem/EFIVARFS_LINUX_COMPAT_AUDIT.md`.

### 3.10 Overlay filesystem compatibility

`OverlayFs::new(name, upper, lowers)` constructs a writable Linux-style
overlay, with `lowers[0]` the highest-priority lower layer.
`OverlayFs::new_read_only(name, lowers)` constructs the lower-only read-only
form; every mutation through it returns `FsError::ReadOnly`. Lookups and
directory enumeration apply top-down object-type masking, merge directories,
consume whiteouts from every layer, and stop below an opaque directory.

Writable overlays lazily copy missing upper parent directories before the
first descendant mutation. Regular-file copy-up is chunked and preserves
data, owner, mode, mtime, and supported xattrs. Lower-file rename and hard
link copy the source up first; unlink/rmdir/rename retain a whiteout whenever
a lower object would otherwise reappear. With redirect directories disabled,
renaming a lower or merged directory returns `FsError::CrossDevice` (EXDEV),
matching Linux's default behavior.

NARF backing filesystems encode a whiteout as a hidden zero-length
`.wh.<name>` file and opacity as `.wh..wh..opq`; these are internal storage
details and never appear through `DirOps`. The mount handler consumes Linux's
`mount(2)` data string (`lowerdir=`, `upperdir=`, `workdir=`), retains the old
source-string ABI only as a fallback, supports escaped colons in legacy
`lowerdir=`, requires upper/work together, and supports a lower-only
read-only mount. The audited compatibility matrix and explicit remaining
gaps live in `filesystem/OVERLAYFS_LINUX_COMPAT_AUDIT.md`.

### 3.11 SquashFS compatibility

The `narf-drivers-fs-squashfs` crate provides a read-only, block-backed
SquashFS 4.0 `FsInstance`. It registers the existing
`narf_block::fs_detect::FsType::SquashFs` for root auto-mount and the
`squashfs` token for classic Linux mount dispatch. Compact and extended
inodes, directories, symlinks, sparse data blocks, packed fragments, ID
metadata, xattrs, stable inode identities, statx and statfs are decoded with
strict `s_bytes_used` and decompression bounds. Every fallible mutation hook
returns `FsError::ReadOnly`.

### 3.12 EFI System Partition bootstrap mount

`root_mount::try_mount_efi_system_partition()` attaches one FAT filesystem at
both NARF's `/boot` and `/mnt/boot`, which is visible as `/boot` to the installed
CachyOS PID 1 rooted at `/mnt`. It does so only when the registered GPT
partition metadata has the UEFI EFI System Partition type GUID; it does not
encode a block device name, partition label, or filesystem UUID. The nested
attachment may precede the `/mnt` root attachment during boot, so mountinfo
derives parentage from the finished tree rather than requiring parent-first
registration. The boot initcall runs before PID 1 so systemd observes the
existing fstab target through its mount table. After late block sysfs
population, boot marks a bounded replay window and queues canonical
`/devices/virtual/block/<name>` ADD events. udevd replays only that finished
projection, not arbitrary earlier bring-up events; this lets it create the ESP
UUID device unit even if its userspace trigger helper is unavailable during
early setup.

Zlib and legacy LZ4 images are supported. LZMA, LZO, XZ and Zstandard images
are rejected at mount with `FsError::Unsupported` until bounded no_std
decoders are available. The complete compatibility matrix and fixture
coverage are recorded in
`drivers/fs/squashfs/SQUASHFS_LINUX_COMPAT_AUDIT.md`.

### 3.13 Pid sysctls

`procfs::sys_kernel` owns `kernel.pid_max` and serves `kernel.ns_last_pid`
for the pid allocator in narf-userspace:

```rust
pub const PID_MAX_MIN: u32;       // RESERVED_PIDS + 1 = 301
pub const PID_MAX_LIMIT: u32;     // 4 Mi
pub fn pid_max() -> u32;          // the allocator's live, exclusive bound
pub fn set_pid_max(n: u32) -> Result<(), FsError>;   // [PID_MAX_MIN, PID_MAX_LIMIT]
pub fn install_ns_last_pid_hooks(read: fn() -> i64, write: fn(&str) -> Result<(), FsError>);
pub fn parse_dointvec_minmax(v: &str, min: i64, max: i64) -> Result<i64, FsError>;
```

`pid_max` writes are `proc_dointvec_minmax` over `[301, 4194304]`.
`ns_last_pid` is registered 0666 in every build; the installed hooks resolve
the caller's pid namespace and perform the capability check. Before the hooks
are installed it reads `0` and refuses writes.

## 4. Invariants & safety properties

- **No ambient root.** A task that holds no `Cap<FileNode, _>` can
  access no files, period.
- **No path escape.** Resolving `a/../../b` never escapes `root`;
  the resolver treats `..` as node-local navigation only.
- **Symlink bound** prevents cycles.
- **Cross-FS operations** (e.g. rename across mounts) are not
  transparent — they return an error that forces the caller to
  copy + unlink explicitly.
- **Cap invariants** — a `FileCap` with `Read` cannot be used for
  writes; rename requires both source and destination to be held
  with sufficient rights.
- A filesystem driver crashing in its domain fails open operations
  with `FsError::FsDomainFault` but does not take down `filesystem/`
  core.
- **File / directory operations follow the `abi/` §3.1 cancellation
  protocol.** A `read` / `write` Future that is dropped mid-I/O
  requests cancellation; the filesystem driver either aborts the
  in-flight `block/` request (preferred for read; `block/` honours
  this) or, for a write already committed to log/journal, returns
  `CancelRequested` and the caller must await the actual commit.
  Partial writes report bytes-durable in the `Cancelled` completion
  so callers can seek past them without re-reading. The FS core
  never releases a `FileCap`'s backing inode ref until all in-flight
  submissions against it have drained terminal completions.

## 5. Architecture notes

Arch-neutral at the spec level. Two arch-touches:

- Page-cache backing uses `memory/`'s huge-page support where
  beneficial.
- Direct I/O paths respect the host bus's alignment constraints
  (surfaced by `block/`).

## 6. Dependencies

- **Consumes:** `block/` (storage), `capabilities/`, `memory/` (cache
  + working mem), `ipc/` (driver transport), `crypto/` (integrity,
  Stage 4+), `time/` (mtime/ctime/atime), `tracing/` (per-op timing),
  `scheduler/`, `rcu/` (QSBR for immutable mount-routing snapshots and the
  non-sleeping dentry fast path). A walk that may await leaves QSBR first and
  continues through owned references; sleepable RCU is not held across
  filesystem I/O.
- **Provides to:** `userspace/` (the file-shaped ABI), `process/` (log
  storage for audit trails), future daemons (package manager,
  session manager, etc.).

## 7. Stage assignment

| Stage | Lands                                                               |
| ----- | ------------------------------------------------------------------- |
| 3     | VFS core (trait, resolution, open/read/write/stat), initramfs in-memory FS, virtiofs glue skeleton. |
| 4     | virtiofs and persistent compatibility drivers (including ext2 and btrfs), unified page cache, rename/link, native snapshot interface, `crypto/` integrity option. |
| post-1.0 | NARF-native filesystem and quota policy, ACL-like caps, and broader on-disk-format coverage. |

## 8. Resolved decisions

### 8.1 Persistent FS first target (resolved)

**Decision:** **NARF-native FS, "narffs"**, designed alongside
the kernel. ext4 port and littlefs adoption were both
considered; both are technically reasonable but neither
matches NARF's invariants:

- ext4 has too much POSIX legacy that doesn't fit the cap
  model (UID/GID, perms bits semantics).
- littlefs is great for embedded but lacks features needed
  for general-purpose use (xattrs, large file support,
  per-file encryption without bolt-ons).

narffs is a copy-on-write FS with:
- Per-file encryption built in (consumes
  `Cap<Key<Aes256Gcm>, Use>` from `crypto/`).
- xattrs as a first-class feature (no separate inode
  walk).
- Atomic rename via copy-on-write (every write is
  on a fresh extent until commit).
- B-tree-of-B-trees layout (Linux btrfs-shaped) for good
  scaling.

**Implementation status:** narffs remains the native-format target, not the
first persistent driver that landed. Compatibility drivers now implement ext2,
FAT-family formats, and read-write btrfs behind the same VFS
traits. Btrfs supplies the currently implemented native snapshot backend;
its compatibility driver also maintains already-enabled full qgroup trees,
enforces referenced/exclusive hard limits, supports V2 qgroup inheritance, and
implements full-qgroup enable/disable/rescan/create/assign/limit ioctls. It also
implements Linux simple quotas: post-enable extents have permanent owners,
usage updates incrementally with referenced equal to exclusive, shared-root
snapshots begin uncharged, and hierarchy inheritance and hard limits work in
simple mode. Simple-quota rescans are invalid and disabling preserves the
on-disk incompat bit and owner refs. Btrfs also assembles member devices by
FSID/devid; reads, writes, and grows SINGLE/DUP/RAID0/1/1C3/1C4/10/5/6 chunks;
and performs read-only degraded parity recovery. Its typed administration
surface adds/removes/replaces members, evacuates allocated devices, and
synchronously converts DATA/METADATA/SYSTEM profiles with
logical-address-preserving relocation. Linux lifecycle/balance ioctl dispatch
and asynchronous filtered balance controls remain future work, as does narffs.

### 8.2 POSIX semantics scope (resolved)

**Decision:** **NARF-native cap-strict semantics by default;
POSIX compat shim in `userspace/` for `relibc`**.

Native API:
- File access via `Cap<FileNode, Read | Write | Append>`.
- No UID/GID — caps replace ambient identity.
- No `seek` global state; reads/writes carry explicit
  offset.
- No symlink-following ambiguity; either `O_NOFOLLOW`-equivalent
  or explicit `read_link` then re-resolve.

POSIX compat in relibc emulates seek state, errno mapping,
default symlink-follow. Programs that link `relibc` see
POSIX-ish semantics; native programs see the cap-strict
form.

### 8.3 Case sensitivity (resolved)

**Decision:** **mandatory case-sensitive at the FS core**.
Compatibility filesystems (FAT, NTFS, HFS+) implement
case-folding internally but expose case-sensitive comparison
at the FS-trait boundary. Two files differing only in case
are distinct files at the cap layer.

### 8.4 xattrs (resolved)

**Decision:** **xattrs are first-class**, used for:
- Integrity tags (per-file content hash, signature).
- Encryption metadata (key id, IV).
- Per-file caps (audit info, compression hints).
- `tracing/` correlation metadata.

The `Cap<FileNode, _>` rights include
`ReadXattr | WriteXattr` so xattrs can be access-controlled
distinct from data. Reserved namespaces:

- `narf.*` — NARF-internal, restricted.
- `user.*` — application data, freely writable with
  `Write` rights.
- `security.*` — capability system, restricted.
- `trusted.*` — equivalent to Linux; restricted to
  privileged caps.

### 8.5 Directory atomicity (resolved)

**Decision:** **`filesystem/` core enforces atomic-rename
contract**; FS drivers must provide it. Specifically:

- `rename(old, new)` is atomic across crashes — either
  succeeds entirely or leaves the FS as-if-unchanged.
- Same for `link`, `unlink`, `mkdir`, `rmdir`.

narffs achieves this via CoW + atomic root-pointer flip.
ext4-port achieves it via journal. FAT achieves it via —
well, FAT can't fully; the FAT driver explicitly declares
`atomic_dir_ops = false` and the VFS rejects rename calls
that would cross-device on a non-atomic FS.

### 8.6 Encryption layer (resolved)

**Decision:** **per-file in `filesystem/`** (see `block/spec`
§8.4). Full-device encryption is a degenerate case of
per-file with one key applied uniformly.

### 8.7 System-caps tooling FS (resolved)

**Decision:** **a thin read-only `capfs` mount at
`/sys/narf/`** exposing the cap registry for tooling
discovery.

`/sys/narf/caps/<name>` returns the `CapKind` integer + the
list of holders (process IDs). Read-only; intended for
tooling like `narf-capdump` to enumerate the system without
querying `observability/` directly.

Mounted by default at boot; can be unmounted by privileged
process if not needed (production hardening).

## 9. ABI versioning

`filesystem/` exports through SDK at `@v0`:

- `Cap<FileNode, _>`, `Cap<DirNode, _>`, `Cap<MountPoint, _>`,
  `Cap<FsInstance, _>` (driver-side).
- `FileSystemOp` enum and result types.
- xattr namespace allowlist (frozen at v1.0; new namespaces
  are minor bumps).

`FILESYSTEM_ABI_MAJOR = 1`, `FILESYSTEM_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
