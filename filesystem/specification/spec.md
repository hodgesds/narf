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
```

All operations submit through `abi/` rings when crossing the
kernel↔user boundary; kernel-internal callers invoke directly.

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
