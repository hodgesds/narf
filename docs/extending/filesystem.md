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

`filesystem/src/lib.rs:782`

```rust
pub trait FsInstance: Send + Sync + 'static {
    /// Root directory of this filesystem.
    fn root(&self) -> Arc<dyn DirOps>;
    /// Filesystem type name, e.g. "tmpfs" (shown in /proc/mounts).
    fn name(&self) -> &str;
}
```

Both methods are **required**. That is the entire trait — a filesystem is
just "give me your root directory and your name."

### `DirOps` — directory operations

`filesystem/src/lib.rs:678`

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
    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()>;          // default: Unsupported
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>>; // default: Unsupported
    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>>;    // default: Unsupported
    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()>;           // default: Unsupported
    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str)
        -> FsFuture<'a, Arc<dyn FileOps>>;   // default: Unsupported
    fn rename<'a>(&'a self, _old: &'a str, _new: &'a str) -> FsFuture<'a, ()>; // default: Unsupported
}
```

Only `lookup` and `iter` are **required**. A read-only filesystem overrides
nothing else — the default write methods all resolve to
`FsError::Unsupported`. (Method line numbers, in order: `lookup` `:680`,
`lookup_dir` `:687`, `iter` `:694`, `enumerate` `:706`, `lookup_async`
`:723`, `lookup_dir_async` `:730`, `enumerate_async` `:736`, `unlink` `:747`,
`create` `:752`, `mkdir` `:757`, `rmdir` `:762`, `symlink` `:768`, `rename`
`:774`.)

### `FileOps` — file operations

`filesystem/src/lib.rs:346`

```rust
pub trait FileOps: Send + Sync {
    // ── Required ──
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize>;
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize>;
    fn stat(&self) -> Stat;
    // ...plus ~30 default-provided methods
}
```

`read` (`:351`), `write` (`:355`), and `stat` (`:359`) are **required**;
everything else has a default. The defaults you are most likely to override:

| Method | Line | Default | When to override |
| --- | --- | --- | --- |
| `ino(&self) -> u64` | `:371` | `0` | give files stable inode numbers |
| `truncate` | `:382` | `Unsupported` | resizable files |
| `ioctl(&self, cmd, arg) -> Result<u64, FsError>` | `:461` | `Unsupported` | device-like nodes |
| `poll_readiness(&self) -> u32` | `:411` | `POLL_IN\|POLL_OUT` | pollable streams |
| `read_should_block(&self) -> bool` | `:538` | `false` | blocking streams (pipes, ttys) |
| `as_dir(&self) -> Option<Arc<dyn DirOps>>` | `:523` | `None` | a node that is also a directory |
| `mmap_frames(&self, off, len) -> Result<Vec<u64>, FsError>` | `:485` | `Unsupported` | file-backed mmap |
| `rdev(&self) -> u64` | `:532` | `0` | char/block device major:minor |

The remaining defaults (`owners`, `set_owners`, `set_perms`, `tty_*`,
`pidfd_target_pid`, `mq_queue_id`, `inotify_instance`, `landlock_ruleset`,
`as_any`, …, `:389`–`:648`) are integration hooks for specific kernel
subsystems and default to a safe no-op/`None`; a plain filesystem ignores
them.

### Supporting types

```rust
// filesystem/src/lib.rs:327
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FsError>> + Send + 'a>>;

// filesystem/src/lib.rs:293
pub enum FsError {
    NotFound, PermissionDenied, Io(BlockError), InvalidPath,
    Busy, ReadOnly, NoSpace, Unsupported, InvalidData,
}

// filesystem/src/lib.rs:190
pub struct Stat {
    pub size: u64,
    pub blocks: u64,
    pub mode: Mode,
    pub mtime_cycles: u64,
}

// filesystem/src/lib.rs:177
pub enum FileType { File, Dir, Symlink, Special }
```

## The mount registry

The registry is a single global `IrqSafeSpinLock<Vec<Mount>>`
(`filesystem/src/lib.rs:1032`), reached through `registry()`:

```rust
// filesystem/src/lib.rs:1038
pub fn registry() -> &'static VfsRegistry;
```

Mounting is **capability-gated**. You need a `Cap<MountPoint, Grant>`, which
the kernel mints once at boot:

```rust
// filesystem/src/lib.rs:1165 — TCB-only; called once at boot.
pub fn bootstrap_mount_authority() -> Cap<MountPoint, Grant>;
```

`VfsRegistry` methods:

```rust
// filesystem/src/lib.rs:1202 — mount a value you own by move
pub fn mount<F: FsInstance>(
    &self, authority: &Cap<MountPoint, Grant>, path: &str, fs: F,
) -> Result<Cap<MountPoint, Write>, FsError>;

// filesystem/src/lib.rs:1227 — mount a pre-boxed Arc<dyn FsInstance>
pub fn mount_arc(
    &self, authority: &Cap<MountPoint, Grant>, path: &str, fs: Arc<dyn FsInstance>,
) -> Result<Cap<MountPoint, Write>, FsError>;

// filesystem/src/lib.rs:1255 — bind an existing subtree to a second path
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
  (`memfs.rs:416`)
- `struct MemDir { entries: IrqSafeSpinLock<BTreeMap<String, Entry>> }`
  (`memfs.rs:250`)
- `impl DirOps for MemDir` (`memfs.rs:262`) implements the full read/write
  surface — a good example of overriding `create`/`mkdir`/`unlink`/etc.
- `impl FsInstance for MemFs` (`memfs.rs:482`) is trivially:

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
        // Build DirEntry values per the definition in filesystem/src/lib.rs.
        Box::new(core::iter::once(DirEntry::new("hello", FileType::File)))
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

> Check the exact `DirEntry` constructor / field shape against
> `filesystem/src/lib.rs` (it lives near `FileType`); the snippet above
> assumes a `DirEntry::new(name, kind)` — adjust to the real signature.

## Gotchas

### `sys_mount` fstype dispatch is a hardcoded match — no fstype registry

The registry (`mount_arc` etc.) is fully open: any crate can mount an
`Arc<dyn FsInstance>` at boot. **But** the `mount(2)` syscall path cannot
reach your filesystem, because `sys_mount` dispatches on the fstype *string*
with a hardcoded `if`/`match` chain and there is **no `register_fstype`
hook**:

```
userspace/src/handlers.rs:14492  if fstype == "bind" || (flags & MS_BIND) != 0 { … bind_mount … }
userspace/src/handlers.rs:14504  if fstype == "tmpfs" || fstype == "ramfs" { … MemFs … }
userspace/src/handlers.rs:14528  match fstype.as_str() { "fat" | "vfat" | … => mount_fat, _ => None }
```

**Signal for the parent:** to make a new fstype mountable *via the syscall*
(e.g. `mount -t hellofs …`), you must edit
`userspace/src/handlers.rs::sys_mount` to add a dispatch arm. Extending via a
custom crate works only for the **programmatic** `registry().mount_arc(...)`
path (boot code, initcalls). A string-keyed fstype registry would close this
gap but does not exist today.

### `FsFuture` shape

`FsFuture<'a, T>` is `Pin<Box<dyn Future<Output = Result<T, FsError>> + Send
+ 'a>>`. Every async method allocates a boxed future. Your future must be
`Send`. The borrow `'a` ties the future to `&self` (and to `buf`/`name`
args), so returned futures cannot outlive the call.

### Lock reentrancy: `FileOps::read` must not touch the fd table

`sys_read` holds the fd-table lock across `entry.ops.read(...)`
(`userspace/src/handlers.rs:1356`). If your `FileOps::read`/`write`
implementation calls back into `fd::with_table` it will **deadlock** on the
same lock. The kernel works around this for fanotify by handling those reads
*before* taking the lock (`handlers.rs:1329` documents exactly this). Rule:
your `FileOps` methods operate on their own state only; they must not
re-enter the fd layer.

### `no_std`

`narf-filesystem` is `#![no_std]` with `alloc`. Use `alloc::{boxed, sync,
vec, string}`; there is no `std`.
