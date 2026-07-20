//! Mountable-filesystem-type registry.
//!
//! `sys_mount` (in `userspace/src/handlers.rs`) historically dispatched
//! on the `fstype` *string* through a hardcoded `if`/`match` chain
//! (`bind`/`tmpfs`/`ramfs`/`fat`/…). That closed the door on adding a
//! new mountable fstype from an out-of-tree crate: the VFS traits
//! ([`crate::FsInstance`] / [`crate::DirOps`] / [`crate::FileOps`]) are
//! all implementable out-of-tree, but the *mount dispatch* was not.
//!
//! This module closes that gap. A third-party crate registers a
//! constructor for its fstype at initcall time:
//!
//! ```ignore
//! use narf_filesystem::{register_fstype, FsInstance, FsError, MemFs};
//! use alloc::sync::Arc;
//!
//! fn build_myfs(source: &str, data: &str) -> Result<Arc<dyn FsInstance>, FsError> {
//!     // `source` is the mount source string; `data` the options string.
//!     let _ = (source, data);
//!     Ok(Arc::new(MemFs::new("myfs")))
//! }
//!
//! // At initcall / driver-init time:
//! register_fstype("myfs", build_myfs);
//! ```
//!
//! after which `mount -t myfs <source> <target>` works with no edit to
//! `sys_mount`. `sys_mount` consults [`lookup_fstype`] only as a
//! *fallback* — the built-in arms keep priority, so registering a name
//! that shadows a built-in has no effect on mount behaviour.
//!
//! The registration table itself is an unguarded global mirroring the
//! `install_*_hook` fn-pointer pattern used elsewhere in this crate
//! (see `devfs::install_console_signal_hook`): registration is a boot /
//! initcall control-plane event, not a data-plane one, so an
//! `IrqSafeSpinLock<Vec<…>>` is the right weight.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{FsError, FsInstance};

/// Constructor for a mountable filesystem type.
///
/// - `source`: the mount source string (block-device name, label, or an
///   already-chroot-resolved absolute path — same value the built-in
///   arms of `sys_mount` receive).
/// - `data`: the mount options / `data` string (NARF passes options via
///   the source/data arg; see `sys_mount`). May be empty.
///
/// Returns the freshly built `Arc<dyn FsInstance>` to be `mount_arc`'d
/// at the target, or an [`FsError`] which `sys_mount` maps to the mount
/// failure return.
pub type FsBuilder = fn(source: &str, data: &str) -> Result<Arc<dyn FsInstance>, FsError>;

struct FsTypeEntry {
    name: &'static str,
    builder: FsBuilder,
}

static FSTYPES: IrqSafeSpinLock<Vec<FsTypeEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a mountable filesystem type under `name`.
///
/// Idempotent-ish: a second registration of the same `name` *replaces*
/// the previous builder (last-writer-wins) rather than accumulating a
/// duplicate, so an initcall that runs twice can't leave a stale entry.
pub fn register_fstype(name: &'static str, builder: FsBuilder) {
    let mut g = FSTYPES.lock();
    if let Some(e) = g.iter_mut().find(|e| e.name == name) {
        e.builder = builder;
        return;
    }
    g.push(FsTypeEntry { name, builder });
}

/// Look up the constructor registered for `name`, if any.
///
/// `sys_mount` calls this in its fallback region (after the built-in
/// fstype arms fail to match, before the block-device fallthrough).
pub fn lookup_fstype(name: &str) -> Option<FsBuilder> {
    FSTYPES
        .lock()
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.builder)
}
