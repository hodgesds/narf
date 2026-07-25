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

- Concrete on-disk formats (ext-like, FAT, virtiofs) — those live in
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
}
```

All operations submit through `abi/` rings when crossing the
kernel↔user boundary; kernel-internal callers invoke directly.
`poll_readiness_at` defaults to `poll_readiness`; offset-sensitive device
descriptions such as `/dev/kmsg` override it so EOF is not reported readable.

### 3.3.1 cgroup-v2 cpuset placement

`cpuset.cpus.effective` is pushed into scheduler CPU affinity.
`cpuset.mems.effective` is the parent-effective/requested intersection
and is pushed into the scheduler's per-task allowed-node table on attach
and every local policy update. Empty requests inherit the parent; an
explicit request with an empty intersection is rejected.
`cpuset.memory_migrate` accepts `0` or `1`. When enabled, attach and
effective-memory-mask changes migrate each member address space's resident
private base pages and complete hardware huge leaves away from disallowed
nodes; shared mappings remain unmoved without explicit MOVE_ALL authority.

`/proc/numastat` exposes live per-node allocation events supplied by
`memory/`: hit, miss, foreign, interleave-hit, local, and other counters.
`/proc/<pid>/numa_maps` reports each registered base-page or hardware
huge-page region's effective policy, resident base-page equivalents grouped
by SRAT node, and actual translation-leaf size.
`/sys/devices/system/node/nodeN/{meminfo,numastat,vmstat}` exposes stable
managed totals, live free/used pages, and the corresponding node-local
event counters.
`/proc/buddyinfo` reports live per-order free-block counts, while
`/proc/zoneinfo` uses stable per-node managed totals and live NUMA events.

### 3.4 Directory operations

```rust
pub fn readdir(d: &DirCap) -> impl Stream<Item = DirEntry>;
pub fn create_file(d: &DirCap, name: &str, cap: …) -> impl Future<Output = FileCap>;
pub fn mkdir(d: &DirCap, name: &str, cap: …)       -> impl Future<Output = DirCap>;
pub fn unlink(d: &DirCap, name: &str, cap: …)      -> impl Future<Output = ()>;
pub fn rename(src: &DirCap, src_name: &str, dst: &DirCap, dst_name: &str, cap: …) -> impl Future<Output = ()>;
```

### 3.5 Mount

```rust
pub fn mount(on: &DirCap, fs: Cap<FsInstance, Attach>, opts: MountOpts) -> Cap<MountPoint, _>;
pub fn unmount(mp: Cap<MountPoint, Own>) -> impl Future<Output = ()>;
```

A mount is just another capability; removing it closes access via
that path. Existing open caps on nodes across the mount continue to
work (refcount-style) until they too are released.

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
    async fn fsync(&self, data_only: bool) -> Result<(), FsError>;
    async fn syncfs(&self) -> Result<(), FsError>;
    /* … */
}
```

Filesystems run in their own PKS/MTE domain (Stage 4) and communicate
with `filesystem/` core via Narf-Ring.

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

`FileOps::ioctl_async` carries Linux `_IOC`-described input and output
buffers to remote filesystems. FUSE maps it to restricted `FUSE_IOCTL`,
copies no more than the encoded `_IOC_SIZE`, rejects oversized replies,
and rejects `FUSE_IOCTL_RETRY`; daemon-selected retry iovecs are reserved
for the separately privileged CUSE unrestricted-ioctl contract.

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
| 4     | virtiofs driver, simple persistent FS (candidate: a Rust-native fs — littlefs-ish or a NARF-specific design), unified page cache, rename/link, `crypto/` integrity option. |
| post-1.0 | Copy-on-write filesystems, snapshots, quotas, ACL-like caps.      |

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

ext4 / FAT / NTFS support comes later as separate
read-write driver crates implementing the same FS trait.

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
