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
- POSIX namespace (`/proc`, `/sys`, `/dev`) — NARF does not replicate
  those; diagnostics come from `observability/` peek API.

## 2. Assumptions

- `block/` supplies block devices for backing storage.
- `capabilities/` mints `Cap<FileNode, R>` tokens.
- `memory/` supplies cache storage and path-resolution working memory.
- `crypto/` provides hashing primitives for content-addressed or
  verified filesystems (e.g. dm-verity-style integrity, Stage 4+).
- There is no global root. Each task has a **root cap**
  (`Cap<FileNode, Traverse>`) that defines what it can reach.

## 3. Public interface

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
```

- Resolution is **always scoped to `root`**. There is no path escape.
- Symlinks resolved up to a documented bound (default 40) to block
  cycles.
- Crossing a mount boundary requires the resolver's cap chain to
  include the `MountPoint` traverse right.
- Path strings are UTF-8; NARF does not emulate byte-pathname
  filesystems transparently (a compat FS in `drivers/fs/` may do so).

### 3.3 File operations (async)

```rust
pub fn open(dir: &DirCap, name: &str, intent: OpenIntent, cap: …) -> impl Future<Output = FileCap>;
pub fn read (f: &FileCap, offset: u64, buf: &mut [u8])        -> impl Future<Output = usize>;
pub fn write(f: &FileCap, offset: u64, buf: &[u8])             -> impl Future<Output = usize>;
pub fn fsync(f: &FileCap)                                      -> impl Future<Output = ()>;
pub fn stat (n: &Cap<NodeRef, Stat>)                           -> impl Future<Output = NodeStat>;
pub fn truncate(f: &FileCap, len: u64)                         -> impl Future<Output = ()>;
pub trait FileOps {
    fn poll_readiness(&self) -> u32;
    fn poll_readiness_at(&self, offset: u64) -> u32;
    fn poll_edge_token(&self) -> (u64, u64);
    fn acknowledge_poll_readiness(&self, readiness: u32);
    fn open_instance(&self) -> Option<Arc<dyn FileOps>>;
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
```

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
`open_instance` defaults to `None`. Clone devices return a fresh open-file
object so lookup/stat and `O_PATH` remain side-effect free; the Linux open path
calls it only after access checks. `/dev/pts/ptmx` returns a fresh PTY master
and `/dev/fuse` returns a fresh FUSE daemon connection. The stable `/dev/fuse`
clone node is mode 0666 so unprivileged filesystem and desktop-portal daemons
can open it, matching Linux distribution tmpfiles/udev policy.

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

The root `/dev/ptmx` is the relative symlink `pts/ptmx`. Mounting `devpts`
installs `DevPtsFs`, whose root exposes the live Unix98 slave registry and a
5:2 clone node rather than an empty in-memory filesystem. The current devpts
implementation uses one global registry; per-mount instances and mount-option
policy are not part of this interface yet.
The Linux open path treats `/dev/tty` as the caller's controlling-terminal
multiplexer: it selects the recorded console or PTY slave, preserves the 5:0
path-node identity, and reports `ENXIO` for a detached session. `O_PATH`
continues to open only the side-effect-free path node.

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

`cgroup.subtree_control` validates a write atomically, applies repeated
controller operations in input order (the last operation wins), enforces the
no-internal-process rule, and refuses to withdraw a controller still delegated
by a child. Cgroup-namespace paths are relative to the namespace root and use
`..` components for visible sibling cgroups. The writable `cgroup.type`
transition rejects populated groups and domain-controller conflicts; complete
per-thread placement and threaded-subtree propagation are not yet provided.

Pressure Stall Information is optional. The `cgroup-psi` feature exposes
`cgroup.pressure` plus `cpu.pressure`, `memory.pressure`, and `io.pressure`;
without it, no PSI cgroup ABI is present. The current PSI implementation
reports Linux-shaped zero counters and does not yet implement pressure-trigger
writes or poll notifications.

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
This per-task mountinfo projection is wired for every Linux-compat build,
independently of optional container namespaces: service managers use
`CLONE_NEWNS` for sandboxing and must observe private stacked file binds before
they remount them read-only.
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
filesystem root for Linux `open_tree(2)` and later `move_mount(2)`.
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

`backing_identity` identifies the backing filesystem object rather than a
mount attachment. Bind-mount adapters preserve their source value so a VFS
consumer can recognise aliases of the same `(filesystem, inode)` pair.

### 3.7 Page cache (optional per fs)

- Default behaviour: read-modify-write path goes through a unified
  page cache sized by `memory/` policy.
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

`FileOps::flush` runs on descriptor close and `FileOps::fsync` backs
Linux `fsync(2)`/`fdatasync(2)`. FUSE files translate these to
`FUSE_FLUSH` and `FUSE_FSYNC`; non-FUSE implementations default to
success when they have no volatile backing state. Directory descriptors
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

### 3.9 Linux synthetic filesystem projections

With `linux-compat`, sysfs exposes only interfaces backed by a NARF authority.
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
`/proc/filesystems` uses the `nodev NAME` form for synthetic filesystems.
`/proc/uptime` reports aggregate idle time across CPUs, and per-task status
memory fields are derived from VMA extents and resident page counts. Procfs
values that have no authoritative NARF provider remain absent rather than
fabricated measurements.
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

Zlib and legacy LZ4 images are supported. LZMA, LZO, XZ and Zstandard images
are rejected at mount with `FsError::Unsupported` until bounded no_std
decoders are available. The complete compatibility matrix and fixture
coverage are recorded in
`drivers/fs/squashfs/SQUASHFS_LINUX_COMPAT_AUDIT.md`.

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
  `scheduler/`, `rcu/` (**Sleepable** RCU for dentry-equivalent cache
  and mount-tree walks that may await I/O mid-traversal).
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
