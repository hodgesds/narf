# Extending: mountable filesystem-type registry

Status: closes the "fstype dispatch is closed" gap.

## The gap

The VFS traits in `filesystem/src/lib.rs` — `FsInstance`, `DirOps`,
`FileOps` — are all implementable from an out-of-tree crate. You can
build a complete filesystem without touching the core. But until now the
one thing you could *not* do out-of-tree was make that filesystem
**mountable**: `sys_mount` (`userspace/src/handlers.rs`) dispatched on
the `fstype` string through a hardcoded `if`/`match` chain
(`bind` / `tmpfs` / `ramfs` / `fat` / …). Adding a new `mount -t <name>`
target meant editing that closed match arm.

The **fstype registry** closes that gap. A crate registers a
constructor for its fstype at initcall time and the filesystem becomes
mountable by name — no edit to `sys_mount`.

## API

Defined in `filesystem/src/fs_registry.rs`, re-exported from the crate
root (`narf_filesystem`):

```rust
/// Constructor for a mountable filesystem type.
/// - `source`: the mount source string (block-device name, label, or an
///   already-chroot-resolved absolute path — the same value the built-in
///   arms of `sys_mount` receive).
/// - `data`: the mount options / `data` string (NARF passes options via
///   the source/data arg). May be empty.
pub type FsBuilder =
    fn(source: &str, data: &str) -> Result<Arc<dyn FsInstance>, FsError>;

/// Register a mountable filesystem type under `name`.
/// Last-writer-wins: re-registering the same name replaces the builder.
pub fn register_fstype(name: &'static str, builder: FsBuilder);

/// Look up the constructor registered for `name`, if any.
pub fn lookup_fstype(name: &str) -> Option<FsBuilder>;
```

The table is a `static IrqSafeSpinLock<Vec<…>>`, `no_std`, mirroring the
`install_*_hook` fn-pointer registration pattern used elsewhere in the
crate (e.g. `devfs::install_console_signal_hook`). Registration is a
boot/initcall control-plane event, so an `IrqSafeSpinLock` is the right
weight.

## How `sys_mount` consults it

The registry is a **fallback**. The built-in fstype arms
(`bind`, `tmpfs`/`ramfs`, `fat`) keep priority and their behaviour is
unchanged. Only after those arms fail to match — and before the
block-device fallthrough — does `sys_mount` call `lookup_fstype`:

```rust
if let Some(builder) = narf_filesystem::lookup_fstype(fstype.as_str()) {
    return match builder(source_resolved.as_str(), source_resolved.as_str()) {
        Ok(fs) => match narf_filesystem::registry().mount_arc(&auth, target.as_str(), fs) {
            Ok(_h) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(fail),
        },
        Err(_) => ctx.set_return(fail),
    };
}
```

Because registered types are consulted *after* the built-ins,
registering a name that shadows a built-in (e.g. `"tmpfs"`) has no effect
on mount behaviour — the built-in wins.

## Worked example: a custom fstype crate

```rust
#![no_std]
extern crate alloc;

use alloc::sync::Arc;
use narf_filesystem::{register_fstype, FsError, FsInstance, MemFs};

/// Build one instance of `myfs`. Here we back it with an in-memory
/// `MemFs`; a real driver would consult `source` (a block-device name)
/// and parse `data` (comma-separated mount options).
fn build_myfs(source: &str, data: &str) -> Result<Arc<dyn FsInstance>, FsError> {
    let _ = (source, data);
    Ok(Arc::new(MemFs::new("myfs")) as Arc<dyn FsInstance>)
}

/// Call this once at boot / initcall time (before any `mount -t myfs`).
pub fn init() {
    register_fstype("myfs", build_myfs);
}
```

After `init()` runs, userspace can mount it like any built-in:

```sh
mount -t myfs none /mnt/my
```

`sys_mount` finds no built-in arm for `myfs`, falls through to
`lookup_fstype("myfs")`, calls `build_myfs`, and `mount_arc`s the
returned `FsInstance` at `/mnt/my`.

## Scope note

Only the mount *dispatch* is made extensible — deliberately. Things that
are compile-time by nature (syscall wire numbers, `CapKind`, the buddy
allocator) are intentionally left as-is; making them runtime-pluggable
would add cost without a real out-of-tree use case.
