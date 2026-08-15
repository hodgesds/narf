# Extending the filesystem / VFS

Crate: `narf-filesystem` (`filesystem/`). Reference implementation:
`filesystem/src/memfs.rs`.

A filesystem in NARF is three traits: an **`FsInstance`** (the mount object),
which hands out a root **`DirOps`** (directory operations), whose entries are
**`FileOps`** (file operations). You implement all three on your own types,
then hand an `Arc<dyn FsInstance>` to the mount registry. This is a
**type-level seam** (pattern 2 in the [README](README.md)): there is no
global install slot — each mount owns its instance.

## The traits

### `FsInstance` — the mount object

Defined by `filesystem/src/lib.rs::FsInstance`.

```rust
pub trait FsInstance: Send + Sync + 'static {
    /// Root directory of this filesystem.
    fn root(&self) -> Arc<dyn DirOps>;
    /// Filesystem type name, e.g. "tmpfs" (shown in /proc/mounts).
    fn name(&self) -> &str;
}
```

Both methods are **required**. Optional methods expose a file-rooted bind
mount, stable backing identity, `statfs`, and live reconfiguration.

### `DirOps` — directory operations

Defined by `filesystem/src/lib.rs::DirOps`. The core shape is:

```rust
pub trait DirOps: Send + Sync {
    // ── Required ──
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>>;
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a>;

    // ── Default-provided (override as needed) ──
    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> { None }
    fn enumerate(&self, cursor: usize, max: usize)
        -> alloc::vec::Vec<(alloc::string::String, FileType)>; // default walks iter()
    fn lookup_async<'a>(&'a self, name: &'a str)
        -> FsFuture<'a, Arc<dyn FileOps>>;   // default: wraps lookup()
    fn lookup_dir_async<'a>(&'a self, name: &'a str)
        -> FsFuture<'a, Arc<dyn DirOps>>;    // default: wraps lookup_dir()
    fn enumerate_async<'a>(&'a self, cursor: usize, max: usize)
        -> FsFuture<'a, alloc::vec::Vec<(alloc::string::String, FileType)>>;
    fn snapshot_async<'a>(&'a self, source: Arc<dyn DirOps>, name: &'a str,
        readonly: bool) -> FsFuture<'a, ()>;                         // default: Unsupported
    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()>;          // default: Unsupported
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>>; // default: Unsupported
    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>>;    // default: Unsupported
    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()>;           // default: Unsupported
    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str)
        -> FsFuture<'a, Arc<dyn FileOps>>;   // default: Unsupported
    fn rename<'a>(&'a self, _old: &'a str, _new: &'a str) -> FsFuture<'a, ()>; // default: Unsupported
    fn rename_to<'a>(&'a self, old: &'a str, dst: &'a dyn DirOps,
        new: &'a str, flags: u32) -> FsFuture<'a, ()>;               // default: Unsupported
    fn link_to<'a>(&'a self, old: &'a str, dst: &'a dyn DirOps,
        new: &'a str) -> FsFuture<'a, ()>;                           // default: Unsupported
}
```

Only `lookup` and `iter` are **required**. A read-only filesystem overrides
nothing else — the default write methods all resolve to
`FsError::Unsupported`. Disk-backed drivers normally implement matching sync
and async lookup/enumeration plus whichever mutation methods they advertise;
see the [filesystem conformance checklist](../../filesystem/specification/testing-requirements.md).

### `FileOps` — file operations

Defined by `filesystem/src/lib.rs::FileOps`.

```rust
pub trait FileOps: Send + Sync {
    // ── Required ──
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize>;
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize>;
    fn stat(&self) -> Stat;
    // ...plus ~30 default-provided methods
}
```

`read`, `write`, and `stat` are **required**; everything else has a default.
The defaults you are most likely to override:

| Method | Default | When to override |
| --- | --- | --- |
| `ino(&self) -> u64` | `0` | stable on-disk inode numbers |
| `stat_async` / `statx_async` | sync stat / `Unsupported` | disk or remote metadata |
| `truncate` | `Unsupported` | resizable files |
| `fsync` / `syncfs` | success | durability barriers |
| `ioctl_async` | `Unsupported` | remote/filesystem-specific ioctls |
| `poll_readiness(&self) -> u32` | `POLL_IN\|POLL_OUT` | pollable streams |
| `as_dir(&self) -> Option<Arc<dyn DirOps>>` | `None` | a node that is also a directory |
| `mmap_frames` / `mmap_fault` | `Unsupported` | file/device-backed mmap |
| `rdev(&self) -> u64` | `0` | char/block device major:minor |

The remaining defaults (`owners`, `set_owners`, `set_perms`, `tty_*`,
`pidfd_target_pid`, `mq_queue_id`, `inotify_instance`, `landlock_ruleset`,
`as_any`, …) are integration hooks for specific kernel
subsystems and default to a safe no-op, `None`, or `Unsupported`; a plain
filesystem ignores them. Check the trait itself before implementing a driver:
the compatibility surface grows as new syscalls land.

`read` returns `Err(FsError::WouldBlock)` for a healthy open stream with no
data available. `Ok(0)` is exclusively EOF; the syscall layer maps
`WouldBlock` to `EAGAIN` for `O_NONBLOCK` or parks a blocking caller.

### Supporting types

```rust
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FsError>> + Send + 'a>>;

pub enum FsError {
    NotFound, PermissionDenied, Io(BlockError), InvalidPath,
    CrossDevice, Busy, ReadOnly, NoSpace, Unsupported, InvalidData,
    BrokenPipe, BadFd, WouldBlock,
}

pub struct Stat {
    pub size: u64,
    pub blocks: u64,
    pub mode: Mode,
    pub mtime_cycles: u64,
}

pub enum FileType { File, Dir, Symlink, Special, Block, Socket, Fifo }
```

## The mount registry

The shared registry is a control-plane `IrqSafeSpinLock<Vec<Mount>>`, reached
through `registry()`:

```rust
pub fn registry() -> &'static VfsRegistry;
```

Mounting is **capability-gated**. You need a `Cap<MountPoint, Grant>`, which
the kernel mints once at boot:

```rust
pub fn bootstrap_mount_authority() -> Cap<MountPoint, Grant>;
```

`VfsRegistry` methods:

```rust
pub fn mount<F: FsInstance>(
    &self, authority: &Cap<MountPoint, Grant>, path: &str, fs: F,
) -> Result<Cap<MountPoint, Write>, FsError>;

pub fn mount_arc(
    &self, authority: &Cap<MountPoint, Grant>, path: &str, fs: Arc<dyn FsInstance>,
) -> Result<Cap<MountPoint, Write>, FsError>;

pub fn bind_mount(
    &self, authority: &Cap<MountPoint, Grant>, source: &str, target: &str,
) -> Result<Cap<MountPoint, Write>, FsError>;
```

The returned `Cap<MountPoint, Write>` is the umount handle. A revoked
`authority` returns `FsError::PermissionDenied` before any side effect
(`mount` checks `authority.check_live()` via the `From<CapError>` impl).

## Reference implementation: `MemFs`

`filesystem/src/memfs.rs` is the canonical in-tree implementation and the
best template to copy.

- `struct MemFs { name: &'static str, root: Arc<MemDir> }`
- `struct MemDir { entries: IrqSafeSpinLock<BTreeMap<String, Entry>> }`
- `impl DirOps for MemDir` implements the full read/write
  surface — a good example of overriding `create`/`mkdir`/`unlink`/etc.
- `impl FsInstance for MemFs` is straightforward:

```rust
fn root(&self) -> Arc<dyn DirOps> { Arc::clone(&self.root) as Arc<dyn DirOps> }
fn name(&self) -> &str { self.name }
```

## Worked example: a minimal read-only filesystem crate

A read-only FS that exposes a single file `hello` containing `"hi\n"`. Note
how few methods you actually implement — `read`/`write`/`stat` on the file,
`lookup`/`iter` on the dir, `root`/`name` on the instance.

```rust
#![no_std]
extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::pin::Pin;
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat,
};

const BODY: &[u8] = b"hi\n";

struct HelloFile;

impl FileOps for HelloFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let off = offset as usize;
            if off >= BODY.len() { return Ok(0); }
            let n = core::cmp::min(buf.len(), BODY.len() - off);
            buf[..n].copy_from_slice(&BODY[off..off + n]);
            Ok(n)
        })
    }
    fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat { size: BODY.len() as u64, blocks: 1, mode: Mode::default(), mtime_cycles: 0 }
    }
    // everything else uses the trait defaults (read-only ⇒ Unsupported/None).
}

struct HelloDir;

impl DirOps for HelloDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        if name == "hello" { Some(Arc::new(HelloFile) as Arc<dyn FileOps>) } else { None }
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::once(DirEntry {
            name: "hello",
            file_type: FileType::File,
        }))
    }
    // lookup_dir/create/mkdir/unlink/… all default to None / Unsupported.
}

pub struct HelloFs { root: Arc<HelloDir> }

impl HelloFs {
    pub fn new() -> Self { Self { root: Arc::new(HelloDir) } }
}

impl FsInstance for HelloFs {
    fn root(&self) -> Arc<dyn DirOps> { self.root.clone() as Arc<dyn DirOps> }
    fn name(&self) -> &str { "hellofs" }
}
```

Mount it (needs the boot-minted authority cap):

```rust
let auth = narf_filesystem::bootstrap_mount_authority(); // in practice, passed in from boot
let fs: Arc<dyn FsInstance> = Arc::new(HelloFs::new());
narf_filesystem::registry().mount_arc(&auth, "/hello", fs)?;
```

## Gotchas

### Register both root detection and `mount -t` when needed

`register_fstype(name, builder)` makes an out-of-tree filesystem reachable as
`mount -t <name>` without editing the syscall dispatcher. The builder receives
the source and option strings and returns `Arc<dyn FsInstance>`; built-in mount
arms retain priority over the fallback registry.

Block filesystems that may be selected as the boot root also register an
`FsFactory` with `root_mount::register_fs_factory(FsType::..., factory)`.
Btrfs and SquashFS demonstrate both registrations in their `src/lib.rs` files.
Register from a `Stage::Subsys` initcall so both paths are ready before late
root discovery.

### `FsFuture` shape

`FsFuture<'a, T>` is `Pin<Box<dyn Future<Output = Result<T, FsError>> + Send
+ 'a>>`. Every async method allocates a boxed future. Your future must be
`Send`. The borrow `'a` ties the future to `&self` (and to `buf`/`name`
args), so returned futures cannot outlive the call.

### File operations run outside the fd-table lock

The read/write/readv/writev and directory-enumeration syscall paths snapshot an
`Arc<dyn FileOps>` plus handle state under the fd-table lock, release the lock,
and only then call the filesystem. Preserve that ordering in new syscall paths:
filesystem objects such as proc fd views legitimately consult the fd table, and
calling them while holding its non-reentrant lock deadlocks.

### `no_std`

`narf-filesystem` is `#![no_std]` with `alloc`. Use `alloc::{boxed, sync,
vec, string}`; there is no `std`.
