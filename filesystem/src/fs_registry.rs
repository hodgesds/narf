//! One catalog of mountable filesystem types for all mount APIs.
//!
//! Lookup is side-effect free: it never opens a device or builds a superblock.
//! A copied descriptor owns the construction policy; callers invoke `init`
//! without holding the registry lock and attach the result in their namespace.

use crate::{FsError, FsInstance};
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

mod builtins;

/// Validated, kernel-owned inputs to a filesystem constructor.
#[derive(Debug)]
pub struct MountRequest<'a> {
    pub fs_type: &'a str,
    pub source: &'a str,
    pub options: &'a str,
    pub uid: u32,
    pub gid: u32,
    pub initial_namespace: bool,
}

/// Source/options constructor retained for drivers and external filesystems.
pub type FsBuilder = fn(source: &str, data: &str) -> Result<Arc<dyn FsInstance>, FsError>;
pub type FsInit = fn(&MountRequest<'_>) -> Result<Arc<dyn FsInstance>, FsError>;

#[derive(Clone, Copy, Debug)]
enum Constructor {
    Simple(FsBuilder),
    Context(FsInit),
}

/// Registered type, separate from a mounted `FsInstance`.
#[derive(Clone, Copy, Debug)]
pub struct FileSystemType {
    pub name: &'static str,
    pub requires_device: bool,
    /// Permit `name.subtype` lookups, e.g. `fuse.sshfs`.
    pub subtypes: bool,
    constructor: Constructor,
}

impl FileSystemType {
    pub const fn new(name: &'static str, init: FsInit) -> Self {
        Self {
            name,
            requires_device: false,
            subtypes: false,
            constructor: Constructor::Context(init),
        }
    }

    pub fn init(&self, request: &MountRequest<'_>) -> Result<Arc<dyn FsInstance>, FsError> {
        match self.constructor {
            Constructor::Simple(builder) => builder(request.source, request.options),
            Constructor::Context(init) => init(request),
        }
    }
}

// Lazy installation also makes the core catalog available to early boot and
// kernel tests. Initializing this Vec only copies descriptors, never calls init.
static FSTYPES: IrqSafeSpinLock<Option<Vec<FileSystemType>>> = IrqSafeSpinLock::new(None);

/// Register or replace a descriptor. Replacement never accumulates duplicates.
pub fn register_fs_type(fs_type: FileSystemType) {
    let mut guard = FSTYPES.lock();
    let types = guard.get_or_insert_with(builtins::types);
    if let Some(entry) = types.iter_mut().find(|entry| entry.name == fs_type.name) {
        *entry = fs_type;
    } else {
        types.push(fs_type);
    }
}

/// Register a source/options constructor for a filesystem without a block device.
pub fn register_fstype(name: &'static str, builder: FsBuilder) {
    register_fs_type(FileSystemType {
        name,
        requires_device: false,
        subtypes: false,
        constructor: Constructor::Simple(builder),
    });
}

/// Register a block-device filesystem. The builder resolves its source and
/// validates options; the metadata controls `/proc/filesystems`' nodev column.
pub fn register_block_fstype(name: &'static str, builder: FsBuilder) {
    register_fs_type(FileSystemType {
        name,
        requires_device: true,
        subtypes: false,
        constructor: Constructor::Simple(builder),
    });
}

/// Lookup a descriptor without running any filesystem code. Exact names win
/// over subtype matches. The returned copy can be initialized outside the lock.
pub fn lookup_fstype(name: &str) -> Option<FileSystemType> {
    let mut guard = FSTYPES.lock();
    let types = guard.get_or_insert_with(builtins::types);
    types
        .iter()
        .find(|entry| entry.name == name)
        .or_else(|| {
            let (base, subtype) = name.split_once('.')?;
            types
                .iter()
                .find(|entry| entry.subtypes && entry.name == base && !subtype.is_empty())
        })
        .copied()
}

/// Snapshot the same catalog used by mount and fsopen.
pub fn registered_fstypes() -> Vec<FileSystemType> {
    FSTYPES.lock().get_or_insert_with(builtins::types).clone()
}
