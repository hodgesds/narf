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
#[derive(Clone, Copy, Debug)]
pub struct MountRequest<'a> {
    pub fs_type: &'a str,
    pub source: &'a str,
    pub options: &'a str,
    pub uid: u32,
    pub gid: u32,
    /// The mounting task's `current_umask()`. The formats with no POSIX
    /// ownership on disk derive every inode's mode from it
    /// (`fat_fill_super`: `opts->fs_fmask = opts->fs_dmask =
    /// current_umask()`), so a constructor that cannot see it cannot report
    /// Linux's modes. `init_fs.umask` (0022) for a kernel-internal mount.
    pub umask: u16,
    pub initial_namespace: bool,
    /// The mount was requested read-only (`MS_RDONLY`, `fsconfig(ro)`, or a
    /// read-only kernel root). Device-backed constructors build a read-only
    /// superblock; a writable request against a device the disk policy keeps
    /// read-only is refused with [`FsError::ReadOnly`] (`EROFS`), which is
    /// what makes `mount(8)` retry read-only, as for a write-protected disk
    /// on Linux.
    pub read_only: bool,
}

/// Run a filesystem constructor's mount future to completion, from boot code
/// or from a `mount(2)` / `fsconfig(FSCONFIG_CMD_CREATE)` syscall.
///
/// The halting [`narf_scheduler::block_on`] panics inside an executor poll,
/// and a syscall is one: systemd's fstab mount units reach the constructors
/// through `mount(8)`. There the constructor spins
/// ([`narf_scheduler::block_on_spin`]), as the sync lookups of block-backed
/// filesystems do. Boot-time callers keep the idling wait.
///
/// The future is boxed: a syscall runs on the task's 32 KiB kernel stack,
/// and a filesystem's whole mount state machine (a btrfs mount of a shared
/// core with its tree walks) pinned inline in the waiting frame overflowed
/// it.
pub fn mount_wait<F: core::future::Future>(fut: F) -> F::Output {
    let fut = alloc::boxed::Box::pin(fut);
    if narf_scheduler::current_task_id() == narf_scheduler::TaskId::NONE {
        narf_scheduler::block_on(fut)
    } else {
        narf_scheduler::block_on_spin(fut)
    }
}

/// Map a device-backed mount `source` onto the block registry: a path whose
/// last component, after a `/dev/` directory, names a registered device
/// (`/dev/nvme0p2`, a chrooted `/mnt/dev/nvme0p2`) yields that name. A bare
/// registry name (`nvme0p2`) yields itself.
pub fn block_source_name(source: &str) -> Option<&str> {
    let name = match source.rsplit_once("/dev/") {
        Some((_, name)) => name,
        None if !source.contains('/') => source,
        None => return None,
    };
    (!name.is_empty() && !name.contains('/') && narf_block::find_block_device(name).is_some())
        .then_some(name)
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
        let normalized;
        let mut request_view;
        let request = if self.requires_device {
            match block_source_name(request.source) {
                Some(name) => {
                    // `blkdev_get_by_path(.., BLK_OPEN_WRITE)` on a
                    // write-protected disk is -EACCES/-EROFS on Linux and
                    // mount(8) retries read-only; the disk policy is NARF's
                    // write protection.
                    if !request.read_only && !narf_block::disk_policy::write_allowed(name) {
                        return Err(FsError::ReadOnly);
                    }
                    normalized = alloc::format!("/dev/{name}");
                    request_view = *request;
                    request_view.source = &normalized;
                    &request_view
                }
                None => request,
            }
        } else {
            request
        };
        let fs = match self.constructor {
            Constructor::Simple(builder) => builder(request.source, request.options),
            Constructor::Context(init) => init(request),
        }?;
        if request.read_only && self.requires_device {
            // The superblock itself is read-only (mountinfo's per-sb `ro`).
            crate::sb_flags::update(&fs, crate::sb_flags::RDONLY, crate::sb_flags::RDONLY);
        }
        Ok(fs)
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
/// Register a device-backed type whose constructor needs the mount context.
///
/// The `FsBuilder` shape (source + data only) cannot express the ownership
/// model of FAT, exFAT, ISO 9660 or UDF: those have no POSIX metadata on
/// disk, so Linux starts every inode from the MOUNTING TASK's uid, gid and
/// umask and lets `uid=`/`gid=`/`umask=` override. A constructor registered
/// here sees all three.
pub fn register_block_fstype_ctx(name: &'static str, init: FsInit) {
    register_fs_type(FileSystemType {
        name,
        requires_device: true,
        subtypes: false,
        constructor: Constructor::Context(init),
    });
}

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
