//! narf-filesystem — VFS core, path resolution, mount tree, initramfs.
//!
//! Spec: `filesystem/specification/spec.md`. Stage-3 scope per
//! `STAGE3.md` §"What deliberately does not land in Stage 3" / per-spec
//! §7: VFS trait surface, scoped path resolution, open/read/write/stat,
//! a read-only in-memory initramfs (CPIO newc), and a virtiofs mount
//! skeleton whose ops are `unimplemented!()` until Stage 4 wires the
//! DAX shared-region protocol.
//!
//! What lands in Stage 3:
//! - `NodeRef` / `DirNodeRef`: cap-type markers (→ `CapKind::FileNode` /
//!   `CapKind::DirNode`) so file/directory handles ride the same
//!   `Cap<T, R>` machinery the rest of the kernel uses.
//! - `FsInstance` trait: every concrete filesystem exposes `root()` +
//!   `name()`. Mounted instances are owned by `VfsRegistry`.
//! - `FileOps` / `DirOps`: async I/O contract. Returns
//!   `Pin<Box<dyn Future<Output = …> + '_>>` because trait-method
//!   `impl Future` is not object-safe — same trick `drivers/`'s
//!   `DriverFuture<'a>` uses.
//! - `Stat`: size / blocks / mode / mtime in monotonic cycles
//!   (`narf_time::Instant::as_cycles`).
//! - `FsError`: `NotFound`, `PermissionDenied`, `Io(BlockError)`,
//!   `InvalidPath`, `Busy`, `ReadOnly`, `Unsupported`. `From<CapError>`
//!   collapses revocation onto `PermissionDenied` so the cap-gated
//!   mount path surfaces a meaningful FS error.
//! - `resolve(root, path)`: walks an ASCII path segment-by-segment.
//!   Stage 3 rejects `..` (no parent traversal) and rejects leading
//!   `/` because the supplied `root` *is* the mount root — the
//!   no-ambient-root invariant from §4 of the spec.
//! - `VfsRegistry`: global, cap-gated `mount` / `unmount`. The
//!   authority is a `Cap<MountPoint, Grant>`; per-mount handle is a
//!   `Cap<MountPoint, Write>` — same authority/handle split the
//!   `drivers/` and `net/` registries use. Revoking the authority
//!   short-circuits `mount` with `FsError::PermissionDenied`.
//! - `Initramfs`: read-only in-memory FS built from a `&'static [u8]`
//!   CPIO newc archive. Files share storage with the archive — zero
//!   copy on `read`. The format choice is deliberate: CPIO newc has
//!   fixed-width hex headers that parse without an arithmetic crate
//!   (TAR's octal fields are easy too, but CPIO's `070701` magic +
//!   13 hex fields = trivially-skimmable).
//! - `VirtiofsMount`: skeleton `FsInstance` whose root's ops all
//!   `unimplemented!()`. Stage 4 wires the DAX shared-region transport
//!   from `drivers/virtio/` + `io/`.
//!
//! Non-goals for Stage 3 (Stage 4 / later):
//! - Symlinks + symlink-bound resolution (spec §3.2).
//! - Parent traversal (`..`) and Unicode normalisation (spec §4).
//! - Page cache (spec §3.7) — unified cache lands with virtiofs.
//! - Dentry cache wired to sleepable RCU (spec §6).
//! - virtiofs DAX protocol — only the skeleton ships now.
//! - Permission checking beyond the cap-gate stub at `mount` time.
//! - mmap, quotas, xattrs, rename, link, mkdir, unlink — Stage 4+.
//! - `block/`-backed loaders. The initramfs sits above `block/`'s API
//!   surface but does not consume it; the byte slice comes from the
//!   bootloader's initramfs region (Stage 4 hands that in).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bpffs;
#[cfg(feature = "cgroup")]
pub mod cgroupfs;
pub mod console_tty;
pub mod csprng;
pub mod devfs;
pub mod devfs_block;
pub mod devfs_input;
pub mod devfs_misc;
pub mod devfs_pty;
pub mod devfs_rtc;
pub mod fifo;
pub mod fs_registry;
pub mod fuse;
pub mod fuse_conn;
pub mod memfs;
#[cfg(feature = "linux-compat")]
pub mod mqueuefs;
pub mod ntty;
pub mod overlayfs;
pub mod page_cache;
#[cfg(feature = "linux-compat")]
pub mod procfs;
pub mod root_mount;
pub mod root_selector;
#[cfg(feature = "linux-compat")]
pub mod sysfs;
pub mod uevent;

mod cgroupfs_tests;
mod devfs_block_tests;
mod devfs_pty_tests;
mod e2e_tests;
mod fs_mount_e2e_tests;
mod memfs_tests;
#[cfg(feature = "linux-compat")]
mod mqueuefs_tests;
mod page_cache_tests;
mod procsys_e2e_tests;
mod random_e2e_tests;
mod sysfs_e2e_tests;
mod sysfs_tests;
mod tests;
mod uevent_e2e_tests;
#[cfg(feature = "cgroup")]
pub use cgroupfs::CgroupFs;
pub use devfs::{
    install_console_signal_hook, install_rfcomm_hooks, install_tty_usb_hooks, install_video_hooks,
    mount_default as mount_devfs_default, register_dri_dir, register_snd_dir, register_tpm,
    unregister_tpm, DevFs,
};
pub use devfs_input::{DevInputDir, DeviceKind, InputEventFile, UinputControlFile};
pub use fs_registry::{lookup_fstype, register_fstype, FsBuilder};
pub use fuse::{
    FuseInHeader, FuseInitFlag, FuseInitIn, FuseInitOut, FuseOpcode, FuseOutHeader,
    FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
};
pub use memfs::{
    new_anon_file as new_anon_memfile, new_file_with_perms_owner as new_memfile_with_perms_owner,
    MemFs,
};
#[cfg(feature = "linux-compat")]
pub use mqueuefs::{MqueueAttr, MqueueError, MqueueFs, MqueueNotification, MqueueOpenOptions};
pub use overlayfs::{OverlayFs, WHITEOUT_PREFIX};
pub use page_cache::{CachePage, Page, PageCache, PageKey, PAGE_SIZE};
#[cfg(feature = "linux-compat")]
pub use sysfs::{
    class_device_register, class_register, get_or_create_child, get_root,
    install_net_snapshot_hook, kobject_add_attr, kobject_add_bin_attr, kobject_add_uevent_attr,
    kobject_add_writable_attr, kobject_emit_uevent, sysfs_root, AttrShow, AttrStore, BinAttrRead,
    Kobject, NetIfaceInfo, SysFs, SysKobjDir,
};
pub use uevent::{
    current_seqnum as uevent_current_seqnum, emit as emit_uevent,
    emit_with_extras as emit_uevent_extras, UeventAction, UeventEnv, UeventReader,
};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use narf_block::BlockError;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── Cap-type markers ────────────────────────────────────────────────

/// Cap marker for a file node. Held as `Cap<NodeRef, R>` where `R`
/// is the rights tier (Stage 3 uses the base `Read` / `Write` /
/// `Grant` set). Maps to `CapKind::FileNode`.
#[derive(Debug)]
pub struct NodeRef;
impl CapType for NodeRef {
    const KIND: CapKind = CapKind::FileNode;
}

/// Cap marker for a directory node. Maps to `CapKind::DirNode`.
#[derive(Debug)]
pub struct DirNodeRef;
impl CapType for DirNodeRef {
    const KIND: CapKind = CapKind::DirNode;
}

/// Cap marker for a mount point. Maps to `CapKind::MountPoint`. The
/// `Grant`-rights flavour is the registry authority; `Write`-rights
/// flavours are returned per successful mount and authorise unmount.
#[derive(Debug)]
pub struct MountPoint;
impl CapType for MountPoint {
    const KIND: CapKind = CapKind::MountPoint;
}

/// Cap marker for a filesystem instance. Maps to `CapKind::FsInstance`.
/// Stage 3 doesn't mint `Cap<FsInstanceMarker, _>` outside the registry
/// itself, but the marker exists so Stage 4 can attach an
/// `FsInstance`-rooted `Cap<…, Attach>` per spec §3.5.
#[derive(Debug)]
pub struct FsInstanceMarker;
impl CapType for FsInstanceMarker {
    const KIND: CapKind = CapKind::FsInstance;
}

// ── Stat / FileType ─────────────────────────────────────────────────

/// File-type discriminant. Character and block devices are distinct because
/// Linux exposes them as `S_IFCHR`/`DT_CHR` and `S_IFBLK`/`DT_BLK`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    Symlink,
    /// Character device (`S_IFCHR`).
    Special,
    /// Block device (`S_IFBLK`).
    Block,
    /// AF_UNIX / AF_INET socket fd. Reported as `S_IFSOCK` so that
    /// `S_ISSOCK(st_mode)` consumers — notably systemd/sd-bus's
    /// `sd_is_socket()`, which gates SCM_RIGHTS fd-passing negotiation
    /// (`NEGOTIATE_UNIX_FD`) on it — recognise a socket fd. Without this a
    /// socket `fstat`s as a char device and elogind refuses to pass the
    /// session-controller fd in its CreateSession reply ("Not supported").
    Socket,
    /// Named pipe (S_IFIFO). Created by `mkfifo`/`mknod(S_IFIFO)`; the node
    /// is a filesystem inode that, when opened, connects every opener to ONE
    /// shared pipe buffer keyed by the node's identity (see the `fifo`
    /// module). Reported as `S_IFIFO` so `S_ISFIFO(st_mode)` consumers
    /// recognise it — systemd's `systemd-initctl.socket` opens `/run/initctl`
    /// as a FIFO and stat()s it to confirm.
    Fifo,
}

/// Stat result. `mode` is a stub: Stage 3 reports `(FileType, perms)`
/// where `perms` is a low-9-bit POSIX-style triplet only for parity
/// with what userspace will eventually expect — the kernel does no
/// permission check off it. `mtime_cycles` is monotonic-clock cycles
/// from `narf_time::Instant::as_cycles`; wall-clock time is Stage 4.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub blocks: u64,
    pub mode: Mode,
    pub mtime_cycles: u64,
}

/// Filesystem-wide capacity information returned by `statfs(2)`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FsStat {
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub block_size: u32,
    pub name_len: u32,
    pub fragment_size: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FileLock {
    pub start: u64,
    pub end: u64,
    pub type_: u32,
    pub pid: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FsMappingRange {
    pub memory_offset: u64,
    pub len: u64,
}

/// A file's ownership triplet for a POSIX access check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileOwner {
    pub uid: u32,
    pub gid: u32,
    /// Low 9 bits: rwxrwxrwx.
    pub perms: u16,
}

/// The accessing process's identity for a POSIX access check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Accessor {
    pub uid: u32,
    pub gid: u32,
}

/// The set of access bits being requested (R=4, W=2, X=1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessRequest {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// POSIX-2017 §B.2.1 access check: given a file's mode/uid/gid and
/// the accessor's identity, decide whether the requested operation
/// (one of read/write/exec) is permitted.
///
/// - UID 0 (root) is always allowed (POSIX privileged-process rule).
/// - Otherwise: pick owner / group / other triplet by matching uid
///   then gid, and AND with the requested-mode bits (R=4, W=2, X=1).
pub fn posix_access_ok(file: FileOwner, accessor: Accessor, want: AccessRequest) -> bool {
    if accessor.uid == 0 {
        // Root always has read+write; exec still requires *some*
        // exec bit on the file (matches Linux's get_acl_root path
        // where root gets X iff any exec bit is set, otherwise the
        // file is treated as data even for root).
        if want.exec && (file.perms & 0o111) == 0 {
            return false;
        }
        return true;
    }
    let triplet_shift = if accessor.uid == file.uid {
        6 // owner: bits 8..6
    } else if accessor.gid == file.gid {
        3 // group: bits 5..3
    } else {
        0 // other: bits 2..0
    };
    let bits = (file.perms >> triplet_shift) & 0o7;
    let mut want_bits = 0u16;
    if want.read {
        want_bits |= 0o4;
    }
    if want.write {
        want_bits |= 0o2;
    }
    if want.exec {
        want_bits |= 0o1;
    }
    (bits & want_bits) == want_bits
}

/// Combined `(FileType, perms)` mode word.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    pub file_type: FileType,
    /// Low 9 bits: rwxrwxrwx. Stage 3 ignores these on access — the
    /// cap on the open file is the real check.
    pub perms: u16,
}

impl Mode {
    pub const FILE_RO: Mode = Mode {
        file_type: FileType::File,
        perms: 0o444,
    };
    pub const FILE_RW: Mode = Mode {
        file_type: FileType::File,
        perms: 0o666,
    };
    pub const DIR_RO: Mode = Mode {
        file_type: FileType::Dir,
        perms: 0o555,
    };
    pub const DIR_RW: Mode = Mode {
        file_type: FileType::Dir,
        perms: 0o777,
    };
}

// ── Errors ─────────────────────────────────────────────────────────

/// Filesystem error surface. `Io` wraps `block/`'s error so a backing
/// store failure surfaces with context preserved.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    Io(BlockError),
    InvalidPath,
    Busy,
    ReadOnly,
    NoSpace,
    /// The backing FS doesn't implement this op (e.g. virtiofs skeleton
    /// pre-Stage-4).
    Unsupported,
    /// Data supplied by userspace was not parseable or out of range.
    /// Maps to POSIX `EINVAL`. Used by sysfs store callbacks.
    InvalidData,
    /// A write whose read side has gone away — a FIFO / pipe with no
    /// remaining readers. Maps to POSIX `EPIPE`; the syscall layer also
    /// raises SIGPIPE on the writer.
    BrokenPipe,
}

impl From<CapError> for FsError {
    /// Cap-side errors collapse to `PermissionDenied` at the FS layer.
    /// Spec §4: a revoked mount cap should refuse further access via
    /// that path. The distinction between `Revoked` and `RightsTooWeak`
    /// is preserved at the cap layer; FS callers only need "no".
    fn from(_: CapError) -> Self {
        FsError::PermissionDenied
    }
}

// ── Async trait future alias ───────────────────────────────────────
//
// `dyn FileOps`/`dyn DirOps` cannot host `impl Future`-returning
// methods (not object-safe), so we surface the same `Pin<Box<dyn …>>`
// shape `drivers/` uses for `DriverFuture<'a>`. Wave-N may swap to
// `async-trait`-style return-position-impl-trait once stabilised.

/// Future returned by every async file/dir op.
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FsError>> + Send + 'a>>;

/// Result of an asynchronous filesystem-backed ioctl.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsIoctlReply {
    pub result: i32,
    pub output: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FsStatxTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// Rich Linux statx metadata supplied by filesystems which preserve it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FsStatx {
    pub mask: u32,
    pub block_size: u32,
    pub attributes: u64,
    pub attributes_mask: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: FsStatxTimestamp,
    pub btime: FsStatxTimestamp,
    pub ctime: FsStatxTimestamp,
    pub mtime: FsStatxTimestamp,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
}

// ── Directory entry ────────────────────────────────────────────────

/// One entry returned by `DirOps::iter`. Stage 3 keeps the name as
/// `&'static str` because the only producer is the initramfs (whose
/// names live in the `&'static [u8]` archive). Stage 4 will widen this
/// to an owned `String` once persistent FSes appear.
#[derive(Copy, Clone, Debug)]
pub struct DirEntry {
    pub name: &'static str,
    pub file_type: FileType,
}

// ── FileOps / DirOps ───────────────────────────────────────────────

/// Per-file async op surface. Methods take `&self` because a file
/// node may be looked up concurrently from multiple tasks; per-file
/// state (e.g. an offset cursor) lives in the *handle*, not here.
pub trait FileOps: Send + Sync {
    /// Read up to `buf.len()` bytes starting at `offset`. Short reads
    /// (returning `< buf.len()`) signify EOF on Stage-3 in-memory
    /// FSes; Stage 4 disk-backed FSes may also short-read on a torn
    /// page boundary and the caller is expected to loop.
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize>;

    /// Write `buf` at `offset`. Returns `FsError::ReadOnly` for the
    /// initramfs and the virtiofs skeleton.
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize>;

    /// Synchronous stat — every Stage-3 FS knows its file size + mtime
    /// cheaply.
    fn stat(&self) -> Stat;

    /// Set the file's access/modification times, in wall-clock
    /// nanoseconds since the epoch (`None` = leave unchanged — the
    /// utimensat UTIME_OMIT slot). Backing for utime/utimes/utimensat.
    /// The default `Unsupported` keeps synthetic filesystems
    /// (procfs/devfs/sysfs) on their pre-mtime behavior; the syscall
    /// layer treats that as a lenient no-op success, like the old
    /// validate-only stubs, so `touch` on /dev nodes keeps working.
    fn set_times(&self, _atime_ns: Option<u64>, _mtime_ns: Option<u64>) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    /// Stable inode identity for this file, unique within its filesystem.
    /// Disk-backed filesystems return the real on-disk inode number;
    /// synthetic filesystems leave the default `0` (meaning "no stable
    /// inode"). Callers that need a Linux `st_ino` MUST use a real value
    /// here when non-zero — musl's dynamic linker dedups DSOs by
    /// `(st_dev, st_ino)`, so two distinct libraries that report the same
    /// inode collapse into one and the second's symbols vanish. A
    /// synthetic `size`-derived `st_ino` collides for same-size libs (the
    /// 8 same-size `libxcb-*.so` are the canonical failure), which is why
    /// this must come from the filesystem, not be fabricated downstream.
    fn ino(&self) -> u64 {
        0
    }

    /// Asynchronous stat — required for disk-backed or remote FS.
    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move { Ok(self.stat()) })
    }

    fn statx_async<'a>(&'a self, _flags: u32, _mask: u32) -> FsFuture<'a, FsStatx> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    /// Resize the file to exactly `len` bytes. Growing zero-fills;
    /// shrinking truncates.
    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// POSIX-2017 `struct stat` `st_uid` / `st_gid`. FSes that have
    /// no native owner concept (FAT, initramfs) keep the default
    /// (0, 0) — owned by root. ext2 / minix / virtiofs override.
    fn owners(&self) -> (u32, u32) {
        (0, 0)
    }

    /// Update `st_uid` / `st_gid`. Default returns Unsupported;
    /// FSes that persist owners override.
    fn set_owners<'a>(&'a self, _uid: u32, _gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Update the low-9 permission bits in `Stat::mode`. Default
    /// returns Unsupported; FSes that persist mode bits override.
    fn set_perms<'a>(&'a self, _perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Flush one open-file description's daemon-visible state.
    fn flush<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Commit file data and metadata (`data_only` models fdatasync).
    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Commit all dirty state belonging to this file's filesystem.
    fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn set_xattr<'a>(&'a self, _name: &'a str, _value: &'a [u8], _flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn get_xattr<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn remove_xattr<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    /// Ask the backing filesystem to authorize Linux R_OK/W_OK/X_OK bits.
    fn access<'a>(&'a self, _mask: u32) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn get_lock<'a>(&'a self, _owner: u64, _lock: FileLock) -> FsFuture<'a, FileLock> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn set_lock<'a>(&'a self, _owner: u64, _lock: FileLock, _wait: bool) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn fallocate<'a>(&'a self, _mode: u32, _offset: u64, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn seek<'a>(&'a self, _offset: u64, _whence: u32) -> FsFuture<'a, u64> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn copy_file_range_to<'a>(
        &'a self,
        _off_in: u64,
        _out: &'a dyn FileOps,
        _off_out: u64,
        _len: u64,
        _flags: u64,
    ) -> FsFuture<'a, u64> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn bmap<'a>(&'a self, _block: u64, _block_size: u32) -> FsFuture<'a, u64> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn setup_mapping<'a>(
        &'a self,
        _file_offset: u64,
        _len: u64,
        _flags: u64,
        _memory_offset: u64,
    ) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn remove_mappings<'a>(&'a self, _ranges: &'a [FsMappingRange]) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    /// POSIX-2017 `poll(2)` readiness query. Returns the OR of
    /// the POLL_* bits below for the events currently satisfied
    /// on this file. The default returns `POLL_IN | POLL_OUT`
    /// (always-ready) which matches the semantics for regular
    /// files (where read/write never block); FSes that can block
    /// (sockets, pipes, eventfds, ttys) override.
    fn poll_readiness(&self) -> u32 {
        POLL_IN | POLL_OUT
    }

    /// Readiness query for file descriptions whose current offset affects
    /// whether a read would block. The default preserves the ordinary
    /// object-wide readiness contract; offset-sensitive devices override it.
    fn poll_readiness_at(&self, _offset: u64) -> u32 {
        self.poll_readiness()
    }

    /// Monotonic source-local tokens for edge-triggered readiness.
    ///
    /// A readiness provider that can transition away from and back to the
    /// same readiness mask between two polls should advance one of these
    /// tokens on every state-changing I/O operation. Epoll uses the tokens
    /// to distinguish a new edge from a continuously-ready file. The default
    /// is stable for providers whose readiness is adequately represented by
    /// the current mask alone.
    fn poll_edge_token(&self) -> (u64, u64) {
        (0, 0)
    }

    /// Acknowledge readiness after an event multiplexer has actually delivered
    /// it to its caller. Passive readiness probes (notably a nested epoll's
    /// poll method) must not call this: some procfs sources expose a
    /// per-open-file change edge which is consumed only by the monitor that
    /// receives the event.
    fn acknowledge_poll_readiness(&self, _readiness: u32) {}

    /// Absolute monotonic-ns instant at which this file will *next*
    /// become readable purely on its own timed schedule, if any.
    ///
    /// Only time-driven files (a `timerfd`) return `Some`; everything
    /// else returns `None`. A blocking multiplexer (`epoll`) that parks
    /// the caller waiting for an explicit readiness *notify* has no other
    /// way to learn a timerfd's deadline — nothing signals a wake when a
    /// timer simply elapses — so it consults this to clamp its scheduler
    /// wake-up. Without it, a timerfd armed inside an `epoll` set with an
    /// infinite timeout never wakes the waiter (it parks forever); this is
    /// exactly what drives a Wayland compositor's repaint loop.
    fn poll_deadline(&self) -> Option<u64> {
        None
    }

    /// Whether a readiness transition on this file fires a
    /// `narf_net::readiness::notify`, so a parked `poll`/`epoll` waiter is
    /// woken promptly rather than only on a coarse fallback tick. Sockets
    /// (which `notify` on send/connect/data) override to `true`; "silent"
    /// sources — pipes, eventfds, ttys — leave it `false`, and a blocking
    /// `poll` over any of them must keep its prompt re-scan instead of
    /// parking (it would otherwise sleep out a finite timeout / miss the edge
    /// until the fallback). A `timerfd` returns `false` here but advertises a
    /// `poll_deadline`, which the park path clamps its wake-up to.
    fn readiness_notifies(&self) -> bool {
        false
    }

    /// Linux `ioctl(2)` dispatch for this file. `cmd` is the encoded
    /// request word (Linux `_IOC(dir, type, nr, size)`); `arg` is the
    /// raw user-pointer argument the syscall layer received.
    ///
    /// The default returns [`FsError::Unsupported`] which the syscall
    /// layer translates to `-ENOTTY` (25 — Linux's "inappropriate ioctl
    /// for device" errno) — matching the behaviour of opening a regular
    /// file and calling ioctl on it. Device-node FileOps (DRM card,
    /// TPM, watchdog) override to dispatch the device-specific number
    /// table.
    ///
    /// Implementations are responsible for their own user-pointer
    /// validation through the kernel `copy_from_user` /
    /// `copy_to_user` helpers; the syscall layer hands `arg` straight
    /// through without inspecting it.
    ///
    /// Linux ref: `fs/ioctl.c::do_vfs_ioctl` +
    /// `include/linux/fs.h::file_operations.unlocked_ioctl`.
    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<u64, FsError> {
        Err(FsError::Unsupported)
    }

    /// Asynchronous ioctl transport for remote filesystems such as FUSE.
    ///
    /// `input` and `out_size` are derived from Linux `_IOC_DIR/_IOC_SIZE`;
    /// `arg` is retained in the FUSE request for daemon compatibility but is
    /// never dereferenced by the filesystem layer.
    fn ioctl_async<'a>(
        &'a self,
        _cmd: u32,
        _arg: u64,
        _input: &'a [u8],
        _out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    /// `mmap(2)` device backing. For a `MAP_SHARED` mapping of this
    /// file, return the list of **physical page-frame addresses** that
    /// back the byte range `[offset, offset + len)` — one entry per
    /// 4 KiB page, in order. The syscall layer maps these frames
    /// *shared* (borrowed) into the caller's address space: writes go
    /// straight to the device's own memory, and the frames are never
    /// freed on `munmap`/exit (the device owns them).
    ///
    /// Both `offset` and `len` are page-aligned by the syscall layer
    /// before this is called. Returning a vec whose length isn't
    /// `len / 4096` is a contract violation the caller rejects.
    ///
    /// This is the keystone for graphics: a `/dev/fb0` framebuffer or a
    /// DRM dumb buffer returns the frames of its scanout/buffer here so
    /// userspace gets a direct CPU-drawable mapping.
    ///
    /// The default returns [`FsError::Unsupported`]; the syscall layer
    /// then falls back to its private-copy file-mapping path. Only
    /// device nodes whose memory is safe to alias into userspace
    /// override this.
    fn mmap_frames(&self, _offset: u64, _len: usize) -> Result<alloc::vec::Vec<u64>, FsError> {
        Err(FsError::Unsupported)
    }

    /// `mmap(2)` **demand** backing: return the physical frame that backs the
    /// single page at `offset`, populating it if this file is lazily backed.
    ///
    /// This is [`FileOps::mmap_frames`]'s per-page twin, and the difference is
    /// *when* it is asked. `mmap_frames` is answered once, at `mmap` time, so
    /// the mapping is a **snapshot**: a page the file backs afterwards is
    /// absent from userspace forever. This is answered from the page-fault
    /// handler, on the first user access to each page, so the mapping
    /// **tracks** the file. A file that can grow behind a live mapping must
    /// implement this one.
    ///
    /// `offset` is page-aligned by the syscall layer, and is a file offset —
    /// the mapping's own `mmap` offset plus the faulting page's distance from
    /// the mapping base. The returned address must be page-aligned and
    /// non-zero (zero is the address space's "unbacked" sentinel). Like
    /// `mmap_frames`, the frame is mapped **borrowed**: the region carries
    /// `RegionPerms::SHARED`, so `munmap` and address-space teardown clear the
    /// PTEs and never free it. The file owns it, and must keep owning it for
    /// as long as any mapping of the file can exist — which is what the
    /// syscall layer's mapping-held `Arc<dyn FileOps>` guarantees.
    ///
    /// Called from the demand-paging arm of the trap handler, i.e. with no
    /// address-space lock held and in a context that may allocate — but *not*
    /// one that may await, so an implementation must be synchronous.
    ///
    /// **Must be idempotent per offset**: two calls for the same offset must
    /// return the same frame. Two CPUs can fault the same page concurrently,
    /// and the address space keeps whichever answer it records first — a
    /// second, different frame would simply be dropped on the floor.
    ///
    /// The default returns [`FsError::Unsupported`], which is also how the
    /// syscall layer probes: a file that supports neither `mmap_frames` nor
    /// this falls through to the private-copy file-mapping path.
    fn mmap_fault(&self, _offset: u64) -> Result<u64, FsError> {
        Err(FsError::Unsupported)
    }

    /// Wave-76: if this file is a PTY master, return the slave index.
    /// Used by `sys_ioctl(TIOCGPTPEER)` to open a fresh slave fd
    /// without going through a downcast / Any dance. Default: `None`.
    fn as_pty_master_index(&self) -> Option<u32> {
        None
    }

    /// If this fd is a DRM master card node (`/dev/dri/cardN`), return its
    /// card index. Used by `sys_ioctl(DRM_IOCTL_PRIME_HANDLE_TO_FD)` to
    /// export a GEM handle as a fresh mmap-able dma-buf fd (the fd-alloc
    /// side lives in the syscall layer, mirroring TIOCGPTPEER). Default:
    /// not a DRM card.
    fn as_drm_card_index(&self) -> Option<u32> {
        None
    }

    /// If this fd is a DRM PRIME dma-buf (exported via
    /// `DRM_IOCTL_PRIME_HANDLE_TO_FD`), return the GEM handle it wraps. Used
    /// by `sys_ioctl(DRM_IOCTL_PRIME_FD_TO_HANDLE)` to re-import the buffer
    /// back to its handle (a compositor exports its render buffer then
    /// imports it to build a scannable KMS framebuffer). Default: not a
    /// PRIME dma-buf.
    fn as_prime_gem_handle(&self) -> Option<u32> {
        None
    }

    /// If this fd is a terminal a process can have as its controlling tty,
    /// return its stable id: [`TTY_ID_CONSOLE`] for the boot console, or
    /// the `/dev/pts/<N>` index for a PTY slave. `None` for non-ttys. Used
    /// by the job-control SIGTTIN/SIGTTOU check to match the fd against the
    /// caller's controlling terminal. Default: not a tty.
    fn tty_id(&self) -> Option<u32> {
        None
    }

    /// If this fd is a tty, return its foreground process-group id (0 when
    /// unset). A background process — one whose pgrp differs from this —
    /// that reads (or, with TOSTOP, writes) its controlling tty is sent
    /// SIGTTIN / SIGTTOU. Default: not a tty.
    fn tty_fg_pgrp(&self) -> Option<u64> {
        None
    }

    /// True when this tty has `TOSTOP` set (background writes raise
    /// SIGTTOU). Default off — background writes are allowed.
    fn tty_tostop(&self) -> bool {
        false
    }

    /// If this open file is a *directory* handle (from opening a path
    /// that resolves to a directory), return its [`DirOps`] so the
    /// `getdents64(2)` path can enumerate it. The fd's own `offset`
    /// field carries the read cursor. Default: not a directory.
    fn as_dir(&self) -> Option<Arc<dyn DirOps>> {
        None
    }

    /// Device number reported in `stat.st_rdev` for a device node
    /// (`FileType::Special`). Linux dev_t encoding: `(major << 8) | minor`
    /// for the common small-number range. Default 0 (not a device); device
    /// nodes (evdev, framebuffer, …) override it. libinput matches an
    /// opened evdev fd's `st_rdev` against udev's MAJOR:MINOR.
    fn rdev(&self) -> u64 {
        0
    }

    /// True when a blocking read on this fd (a pipe with an open writer
    /// and empty buffer) should park rather than return a spurious 0.
    fn read_should_block(&self) -> bool {
        false
    }

    /// True when a blocking write that made no progress (returned 0) should
    /// PARK the writer rather than hand userspace a spurious 0 — a pipe/FIFO
    /// whose buffer is full and still has an open reader (POSIX: a blocking
    /// write waits for room). Default false (a 0-byte write elsewhere is a
    /// real result, not a would-block).
    fn write_should_block(&self) -> bool {
        false
    }

    /// Pipe buffer capacity in bytes, for `fcntl(F_GETPIPE_SZ/F_SETPIPE_SZ)`.
    /// `None` for a non-pipe fd (fcntl then reports EINVAL, matching Linux).
    fn pipe_capacity(&self) -> Option<usize> {
        None
    }

    /// True when this fd is a non-seekable byte stream (pipe, socket,
    /// FIFO) rather than a regular file / block device. Linux `sendfile(2)`
    /// requires the *input* fd to be mmap-capable, so a stream source is
    /// rejected with `EINVAL` — callers (e.g. busybox `cat`) then fall back
    /// to a plain `read()`/`write()` loop, which correctly parks on an
    /// empty-but-open pipe instead of treating a transient 0-byte read as
    /// EOF. Regular files return the default `false`.
    fn is_stream(&self) -> bool {
        false
    }

    /// True when a blocking read on this fd should park on the *input
    /// waker* (woken by the serial/keyboard IRQ) rather than the 1ms
    /// re-poll used for pipes. The console (`/dev/console`, stdin) returns
    /// true when its byte ring is empty so an interactive shell truly
    /// sleeps until a keystroke instead of busy-polling with `read`+`usleep`.
    fn block_on_input(&self) -> bool {
        false
    }

    /// True when a non-blocking (`O_NONBLOCK`) read that finds no data ready
    /// should return `EAGAIN` immediately instead of being driven to
    /// completion by the blocking spin-pump. evdev device nodes
    /// (`InputEventFile`) block *internally* on an empty ring; a non-blocking
    /// reader — libinput opens evdev `O_NONBLOCK` — must get `EAGAIN` at once,
    /// not a multi-million-iteration `poll_blocking` busy-poll that then
    /// surfaces the wrong errno. Default `false` (regular files keep the
    /// blocking drive — Linux ignores `O_NONBLOCK` on regular files; sockets
    /// and pipes resolve on the first poll so they are unaffected either way).
    fn nonblock_read_eagain(&self) -> bool {
        false
    }

    /// If this file is a pidfd (from `pidfd_open`), return the target
    /// process's pid. Used by `pidfd_send_signal(2)` to resolve the
    /// fd to a pid without a downcast / Any dance. Default: `None`.
    fn pidfd_target_pid(&self) -> Option<u64> {
        None
    }

    /// PTY-layer: true on the `/dev/ptmx` clone-on-open file. When
    /// `sys_open` sees this it allocates a fresh `Pty` pair and
    /// installs the master in the caller's fd table instead of the
    /// singleton FileOps that DevDir::lookup returned. Linux calls
    /// the equivalent path `ptmx_open` in `drivers/tty/pty.c`.
    fn is_ptmx_clone(&self) -> bool {
        false
    }

    /// Return a fresh open-file instance for clone devices such as
    /// `/dev/ptmx` and `/dev/fuse`. Path lookup and stat operate on a stable
    /// device inode; only a successful `open(2)` allocates per-open state.
    fn open_instance(&self) -> Option<Arc<dyn FileOps>> {
        None
    }

    /// If this file is a named-pipe (FIFO) inode — created by
    /// `mkfifo`/`mknod(S_IFIFO)` — return its shared pipe buffer. Every
    /// `open()` of the same path resolves to the same FIFO node and thus
    /// the same `FifoShared`, so all openers rendezvous on one buffer keyed
    /// by node identity. `sys_open` uses this to build a per-open
    /// [`fifo::FifoHandle`] (which carries the O_RDONLY/O_WRONLY/O_RDWR
    /// direction and the peer-open blocking semantics) rather than
    /// installing the bare node — mirroring the `is_ptmx_clone` pattern.
    /// Default: not a FIFO.
    fn fifo_shared(&self) -> Option<Arc<fifo::FifoShared>> {
        None
    }

    /// If this file is a POSIX message-queue descriptor (from
    /// `mq_open`), return its queue id. Used by the `mq_*` syscalls to
    /// resolve the mqd to a queue without a downcast. Default: `None`.
    fn mq_queue_id(&self) -> Option<u64> {
        None
    }

    /// If this file is an inotify instance (from `inotify_init1`),
    /// return its instance id. Used by `inotify_add_watch` /
    /// `inotify_rm_watch` to resolve the fd. Default: `None`.
    fn inotify_instance(&self) -> Option<u64> {
        None
    }

    /// If this file is a fanotify group (from `fanotify_init`), return its
    /// group id. Used by `fanotify_mark` to resolve the fd. Default:
    /// `None`.
    fn fanotify_instance(&self) -> Option<u64> {
        None
    }

    /// If this file is a Landlock ruleset (from `landlock_create_ruleset`),
    /// return its ruleset id. Used by `landlock_add_rule` /
    /// `landlock_restrict_self` to resolve the fd. Default: `None`.
    fn landlock_ruleset(&self) -> Option<u64> {
        None
    }

    /// If this file is a filesystem context (from `fsopen` / `fspick`),
    /// return its context id. Used by `fsconfig` / `fsmount`. Default:
    /// `None`.
    fn fs_context_id(&self) -> Option<u64> {
        None
    }

    /// If this file is a detached mount (from `fsmount` / `open_tree`),
    /// return its mount-object id. Used by `move_mount`. Default: `None`.
    fn mount_object_id(&self) -> Option<u64> {
        None
    }

    /// If this file is the read end of a pipe, copy up to `max` queued
    /// bytes WITHOUT consuming them and return them. Used by `tee(2)` to
    /// duplicate pipe data between two pipes. Default `None` ⇒ not a
    /// peekable pipe read end.
    fn pipe_peek(&self, _max: usize) -> Option<alloc::vec::Vec<u8>> {
        None
    }

    /// Downcast hook. The default returns `None`; FileOps types that
    /// need to be recovered from an `Arc<dyn FileOps>` (today: the
    /// namespace-fd minted by `/proc/<pid>/ns/*`, so `setns(fd, …)` can
    /// pull the held namespace `Arc` back out) override this to return
    /// `Some(self)`. Kept out of the per-syscall hot path — only `setns`
    /// reaches for it.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }
}

// ── Controlling-tty ids ─────────────────────────────────────────

/// Stable [`FileOps::tty_id`] for the boot console (`/dev/console`,
/// stdin/out/err). A reserved high value so it never collides with a
/// `/dev/pts/<N>` PTY index (those count up from 0). The userspace
/// controlling-tty table uses the same value (`handlers::CTTY_CONSOLE`).
pub const TTY_ID_CONSOLE: u32 = 0xFFFF_FFFE;

// ── POSIX poll(2) event bits ────────────────────────────────────

/// `POLLIN` — data available to read.
pub const POLL_IN: u32 = 0x0001;
/// `POLLPRI` — urgent (out-of-band) data available.
pub const POLL_PRI: u32 = 0x0002;
/// `POLLOUT` — file is writable without blocking.
pub const POLL_OUT: u32 = 0x0004;
/// `POLLERR` — error condition (always set in revents).
pub const POLL_ERR: u32 = 0x0008;
/// `POLLHUP` — peer closed the connection / pipe end gone.
pub const POLL_HUP: u32 = 0x0010;
/// `POLLNVAL` — fd not open / invalid.
pub const POLL_NVAL: u32 = 0x0020;

/// Per-directory async op surface. `lookup` is synchronous because
/// the only Stage-3 directory implementation (initramfs) is a flat
/// in-memory map; Stage 4 backing-store directories will need an
/// async variant — `lookup_async` will land alongside virtiofs.
pub trait DirOps: Send + Sync {
    /// Real inode number of this directory, or 0 if the filesystem has no
    /// stable per-directory id (the synthetic default). The stat/statx
    /// handlers thread this into the Linux `st_ino` so a directory is
    /// distinguishable from its parent — systemd's `rm_rf` refuses to
    /// descend when a directory and its parent share `(st_dev, st_ino)`
    /// (its "you've hit a filesystem root" guard), so a constant 0 makes
    /// every temp subdir look like `/`. Mirrors [`FileOps::ino`].
    fn ino(&self) -> u64 {
        0
    }

    /// Resolve a single name component. Returns `None` if absent.
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>>;

    /// Look up a child as a directory (so multi-segment `resolve`
    /// can descend without round-tripping through `Arc<dyn FileOps>`).
    /// Stage 3 only has flat directories at the top level so the
    /// default returns `None`; the initramfs nests via `/`-in-name
    /// (CPIO encodes paths whole), not via subdirectory entries.
    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    /// Iterate this directory. Stage 3 returns a boxed iterator so the
    /// trait stays object-safe; an `impl Iterator` shape would force
    /// a GAT. Names are `&'static str` per `DirEntry`'s comment.
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a>;

    /// Snapshot up-to `max` entries starting at `cursor` and return
    /// them as `(owned_name, file_type)` pairs. Default impl walks
    /// `iter()` and clones each entry's `&'static str` to a `String`.
    /// Filesystems whose names live in non-static storage (e.g. the
    /// `MemFs` `BTreeMap<String, _>`) override this to return their
    /// real entries — `iter()` still returns empty for those, since
    /// the trait's `&'static str` payload can't be synthesised.
    ///
    /// Used by `sys_listdir` (kernel readdir surface). Cheap: a
    /// few dozen Strings per call at the typical scale.
    fn enumerate(
        &self,
        cursor: usize,
        max: usize,
    ) -> alloc::vec::Vec<(alloc::string::String, FileType)> {
        use alloc::string::ToString;
        self.iter()
            .skip(cursor)
            .take(max)
            .map(|de| (de.name.to_string(), de.file_type))
            .collect()
    }

    /// Resolve a single name component asynchronously. Default
    /// falls back to the sync `lookup`, so directories that only
    /// implement the sync side (procfs, devfs, initramfs) work
    /// transparently with async callers (resolve_async).
    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        let r = self.lookup(name).ok_or(FsError::NotFound);
        Box::pin(async move { r })
    }

    /// Look up a child as a directory asynchronously. Default
    /// falls back to the sync `lookup_dir`.
    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        let r = self.lookup_dir(name).ok_or(FsError::NotFound);
        Box::pin(async move { r })
    }

    /// Snapshot entries asynchronously.
    fn enumerate_async<'a>(
        &'a self,
        _cursor: usize,
        _max: usize,
    ) -> FsFuture<'a, alloc::vec::Vec<(alloc::string::String, FileType)>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// This directory's permission bits (low 12 bits of the mode).
    /// Default `0o755` (rwxr-xr-x) — deliberately NOT group/other-
    /// writable: dbus/systemd reject `XDG_RUNTIME_DIR` (and refuse to
    /// create a session bus) if a directory stats as world-writable,
    /// which a hardcoded `0o777` used to make every dir look. A writable
    /// filesystem (memfs) overrides with a `chmod`-settable value so
    /// `chmod(2)` on a directory reflects in `stat`.
    fn dir_mode(&self) -> u16 {
        0o755
    }

    /// Set this directory's permission bits. Default no-op (read-only
    /// filesystems ignore it); memfs stores it so `dir_mode` reflects it.
    fn set_dir_mode(&self, _perms: u16) {}

    /// Commit directory entries and metadata (`data_only` models
    /// `fdatasync(2)` on an open directory descriptor).
    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Commit all dirty state belonging to this directory's filesystem.
    fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    // ── Stage-4 r/w surface ──────────────────────────────────────

    /// Remove the file entry named `name` from this directory.
    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a new empty file named `name` and return a handle.
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create an S_IFSOCK node named `name` (the inode Linux materialises
    /// for a pathname AF_UNIX `bind()`), with the given permission bits.
    /// Default: unsupported — filesystems that can't hold a socket inode
    /// leave the bound path invisible (`bind` still succeeds; connection
    /// routing is independent of this node). tmpfs/memfs override it.
    fn create_socket<'a>(&'a self, _name: &'a str, _perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a device node named `name` of the given file type (char or
    /// block) with the Linux `dev_t` `rdev` (`(major << 8) | minor` in the
    /// common small-number encoding). Default: unsupported. devfs overrides it
    /// so `mknod`/`mknodat` from udev create a real `/dev/<name>` char/block
    /// node that `stat`s as `S_IFCHR`/`S_IFBLK` with the right `st_rdev`.
    /// Linux ref: `vfs_mknod` → `shmem_mknod` / `devtmpfs` (drivers/base/devtmpfs.c).
    fn mknod<'a>(
        &'a self,
        _name: &'a str,
        _file_type: FileType,
        _rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a new empty subdirectory named `name`.
    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Remove the empty subdirectory named `name`.
    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create a symlink entry named `name` pointing at the textual
    /// `target` path.
    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Rename the entry `old_name` to `new_name` within this
    /// directory.
    fn rename<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Atomically rename into `new_dir`. `flags` uses Linux RENAME_* bits.
    fn rename_to<'a>(
        &'a self,
        _old_name: &'a str,
        _new_dir: &'a dyn DirOps,
        _new_name: &'a str,
        _flags: u32,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Hard-link the entry `old_name` under `new_name` within this
    /// directory, aliasing the same backing node. Same-parent only —
    /// the same restriction `rename` carries, for the same reason (a
    /// cross-parent form needs a registry-aware two-lock walk).
    /// Filesystems without hard links keep the `Unsupported` default
    /// (POSIX: `link(2)` on such an fs → EPERM).
    fn link<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Hard-link a source entry into a potentially different directory.
    fn link_to<'a>(
        &'a self,
        _old_name: &'a str,
        _new_dir: &'a dyn DirOps,
        _new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Downcast hook for filesystem-specific multi-directory operations.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }

    /// Link an already-existing file node into this directory under
    /// `name`, aliasing the passed `Arc` (the inode gains a name; the
    /// caller's fd keeps its own reference to the same node). This is the
    /// materialisation step for `O_TMPFILE` + `linkat(AT_EMPTY_PATH)`:
    /// `open(dir, O_TMPFILE)` mints a nameless inode, the process writes
    /// to it, then `linkat` gives it a path. The default rejects it (a
    /// filesystem that can't hold an externally-minted node → EOPNOTSUPP,
    /// so the caller falls back to a named temp + rename); tmpfs/memfs
    /// override it to insert the node into its directory map. `Busy` if
    /// `name` already exists (linkat never replaces an existing name).
    fn link_node<'a>(&'a self, _name: &'a str, _node: Arc<dyn FileOps>) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Create an unnamed regular inode owned by this filesystem.
    ///
    /// The returned node can later be materialised with [`DirOps::link_node`].
    /// Filesystems which only support named creation retain the
    /// `Unsupported` default.
    fn tmpfile<'a>(&'a self, _mode: u32) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Whether this directory can hold an anonymous `O_TMPFILE` inode and
    /// later materialise it via [`DirOps::link_node`]. The open handler
    /// checks this before minting the nameless inode so a directory on a
    /// read-only / non-tmpfs backing (which can't `link_node`) reports
    /// `O_TMPFILE` unsupported up front (Linux: EOPNOTSUPP) instead of
    /// handing back an fd that can never be linked. Default `false`;
    /// tmpfs/memfs overrides to `true`.
    fn supports_tmpfile(&self) -> bool {
        false
    }
}

// ── FsInstance ─────────────────────────────────────────────────────

/// One mounted filesystem.
pub trait FsInstance: Send + Sync + 'static {
    /// Root directory. Path resolution starts here for any path under
    /// the mount.
    fn root(&self) -> Arc<dyn DirOps>;
    /// Human-readable name (for logging + lookups). Must remain
    /// stable across the FS's lifetime.
    fn name(&self) -> &str;

    /// Stable identity of the backing filesystem object.  This is distinct
    /// from an individual mount attachment: bind mounts must return the
    /// source filesystem's identity so VFS users can recognise two paths to
    /// the same inode.  The default is the concrete filesystem allocation;
    /// adapters that forward a source filesystem override it.
    fn backing_identity(&self) -> usize {
        self as *const Self as *const () as usize
    }

    /// The single file this mount exposes, when the mount root is a FILE
    /// rather than a directory (Linux `mount --bind <file> <file2>`). Default
    /// `None` — a normal directory-rooted filesystem. A resolver that lands on
    /// a mount's root (empty relative path) consults this first: `Some(file)`
    /// means the mount point itself IS that file. systemd's ProtectHostname= /
    /// ProtectKernelTunables= bind a read-only copy of a procfs control file
    /// (e.g. /proc/sys/kernel/domainname) over itself; without a real
    /// file-rooted mount the path never appears in /proc/self/mountinfo and
    /// systemd's recursive read-only remount loops 32× then fails EBUSY
    /// (226/EXIT_NAMESPACE).
    fn root_file(&self) -> Option<Arc<dyn FileOps>> {
        None
    }

    /// Query filesystem-wide capacity. Synthetic filesystems retain the
    /// conservative default used before this interface existed.
    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async {
            Ok(FsStat {
                block_size: 4096,
                name_len: 255,
                fragment_size: 4096,
                ..FsStat::default()
            })
        })
    }
}

// ── Path resolution ────────────────────────────────────────────────

/// Resolve a slash-separated relative path against `root`. Stage-3
/// rules (per spec §4):
///
/// - Reject leading `/` — `root` IS the mount root, no ambient root
///   exists for resolution to escape into.
/// - Reject `..` — parent traversal is Stage 4 (spec §3.2 calls out
///   resolver-scope guarantees that the Stage-3 walker doesn't yet
///   need to enforce because it can't walk up).
/// - Reject empty path. The caller already has `root`; opening an
///   empty path is a programming error, not "open the root".
/// - Empty segments (consecutive `/`) and a single trailing `/` are
///   tolerated — common in user-supplied paths.
/// - ASCII-only at the byte level. We don't reject non-ASCII (the
///   archive may carry UTF-8 names) but we don't normalise either.
///
/// Returns the file at the leaf. Stage 3 has no `lookup_dir` traffic
/// because the initramfs is single-level — every CPIO entry is a leaf
/// directly under the root.
pub fn resolve(root: Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn FileOps>, FsError> {
    if path.is_empty() {
        return Err(FsError::InvalidPath);
    }
    if path.as_bytes()[0] == b'/' {
        return Err(FsError::InvalidPath);
    }

    let mut current_dir = root;
    let mut last_component: Option<&str> = None;

    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        } // tolerate //
        if segment == ".." {
            return Err(FsError::InvalidPath);
        }
        if segment == "." {
            continue;
        } // tolerate .

        // Hold the previous "leaf candidate" — if there's another
        // segment after it, it has to have been a directory.
        if let Some(prev) = last_component.take() {
            match current_dir.lookup_dir(prev) {
                Some(d) => current_dir = d,
                None => return Err(FsError::NotFound),
            }
        }
        last_component = Some(segment);
    }

    let leaf = last_component.ok_or(FsError::InvalidPath)?;
    current_dir.lookup(leaf).ok_or(FsError::NotFound)
}

/// Resolve a relative path asynchronously, with POSIX-2017 (SUSv4)
/// semantics:
///
/// - `.` and empty components are skipped per §4.13.
/// - `..` walks up one level, clamped at `root` (Linux semantics — the
///   spec leaves above-root behaviour implementation-defined; clamping
///   matches what every UNIX shell expects). The mount-root is the
///   bound; `..` from `/foo` returns the mount-root, never escapes
///   the mount.
/// - Symlinks encountered mid-path are followed transparently per
///   §4.13. A 40-hop cap (the SUSv4 minimum guarantee for SYMLOOP_MAX)
///   bounds the recursion; exceeding it returns
///   `FsError::InvalidPath` (POSIX would name this `ELOOP`).
/// - An absolute symlink target restarts the walk from `root`.
pub fn resolve_async<'a>(root: Arc<dyn DirOps>, path: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
    resolve_async_ext(root, path, true)
}

/// Like [`resolve_async`] but returns the *final* path component as-is
/// when it is a symlink, instead of following it. Intermediate symlink
/// components are STILL followed (a symlink-to-directory mid-path is
/// normal). This is the resolution mode POSIX `readlink(2)`,
/// `lstat(2)` / `fstatat(AT_SYMLINK_NOFOLLOW)` and `open(O_NOFOLLOW)`
/// require: they must operate on the link itself, not its target.
pub fn resolve_async_nofollow<'a>(
    root: Arc<dyn DirOps>,
    path: &'a str,
) -> FsFuture<'a, Arc<dyn FileOps>> {
    resolve_async_ext(root, path, false)
}

/// Shared resolver body for [`resolve_async`] / [`resolve_async_nofollow`].
///
/// `follow_final` selects whether the last path component is followed
/// when it is a symlink: `true` is the classic follow-everything walk
/// (open / stat); `false` stops at and returns the final symlink node
/// itself (readlink / `*_NOFOLLOW`). Intermediate symlinks are followed
/// in both modes, and the SYMLOOP_MAX guard applies uniformly.
pub fn resolve_async_ext<'a>(
    root: Arc<dyn DirOps>,
    path: &'a str,
    follow_final: bool,
) -> FsFuture<'a, Arc<dyn FileOps>> {
    let initial = alloc::string::String::from(path);
    Box::pin(async move {
        if initial.is_empty() {
            return Err(FsError::InvalidPath);
        }
        if initial.as_bytes()[0] == b'/' {
            return Err(FsError::InvalidPath);
        }

        // Components left to consume, head-first so symlink targets can
        // splice in at the front of the remainder.
        let mut remaining: alloc::collections::VecDeque<alloc::string::String> = initial
            .split('/')
            .filter(|s| !s.is_empty())
            .map(alloc::string::String::from)
            .collect();
        if remaining.is_empty() {
            return Err(FsError::InvalidPath);
        }

        // POSIX-2017 SYMLOOP_MAX guaranteed minimum (§<limits.h>): 8.
        // We pick 40 to match Linux, which has been the de-facto
        // ceiling user code expects since the 2.6 series.
        const SYMLOOP_MAX: usize = 40;
        let mut symlinks_followed = 0usize;

        // Walk position. `parent_chain` remembers the prefix so `..`
        // can pop one level without re-resolving from root each time.
        let mut current_dir: Arc<dyn DirOps> = root.clone();
        let mut parent_chain: alloc::vec::Vec<Arc<dyn DirOps>> = alloc::vec::Vec::new();

        while let Some(seg) = remaining.pop_front() {
            if seg == "." {
                continue;
            }
            if seg == ".." {
                // Pop one level; if we're already at the mount-root,
                // .. is a no-op (POSIX root.. == root).
                if let Some(p) = parent_chain.pop() {
                    current_dir = p;
                }
                continue;
            }

            // Decide intermediate vs final by peeking the queue.
            let is_final = remaining.is_empty();

            // Always lookup as file first. Even an "intermediate"
            // segment may be a symlink-to-directory, which is reached
            // through the file-shape lookup.
            //
            // Carve-out for nested subdirs that are dir-only (no
            // FileOps shape) — e.g. `/dev/pts` exists only as a
            // `lookup_dir` target on the parent. `lookup_async`
            // returns `NotFound` for those, but they're legitimate
            // intermediate components, so swallow the NotFound and
            // fall through to the lookup_dir_async branch below.
            let f_result = current_dir.lookup_async(&seg).await;
            let f = match f_result {
                Ok(f) => f,
                Err(FsError::NotFound) if !is_final => {
                    let next = match current_dir.lookup_dir_async(&seg).await {
                        Ok(d) => d,
                        Err(FsError::Unsupported) => {
                            current_dir.lookup_dir(&seg).ok_or(FsError::NotFound)?
                        }
                        Err(e) => return Err(e),
                    };
                    parent_chain.push(current_dir);
                    current_dir = next;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let kind = f.stat_async().await?.mode.file_type;

            // A final symlink in NoFollow mode is the target of the walk:
            // hand back the link node itself so readlink / lstat /
            // *_NOFOLLOW operate on the link, not its target. Intermediate
            // symlinks are always followed (the branch below), so a
            // symlink-to-directory mid-path still resolves normally.
            if kind == FileType::Symlink && is_final && !follow_final {
                return Ok(f);
            }

            if kind == FileType::Symlink {
                if symlinks_followed >= SYMLOOP_MAX {
                    return Err(FsError::InvalidPath);
                }
                symlinks_followed += 1;
                // Read the target. POSIX symlink targets are bounded
                // by SYMLINK_MAX (typically 4096); we cap defensively
                // at a single page.
                let mut buf = alloc::vec![0u8; 4096];
                let n = f.read(0, &mut buf).await?;
                let target = core::str::from_utf8(&buf[..n]).map_err(|_| FsError::InvalidPath)?;
                let absolute = target.starts_with('/');
                let target_components: alloc::vec::Vec<alloc::string::String> = target
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(alloc::string::String::from)
                    .collect();
                if absolute {
                    // Restart from the mount-root for absolute targets.
                    parent_chain.clear();
                    current_dir = root.clone();
                }
                // Splice target components at the front of remaining.
                // Push in reverse so the first target component pops
                // off the queue next.
                for c in target_components.into_iter().rev() {
                    remaining.push_front(c);
                }
                continue;
            }

            if is_final {
                // Last component, ordinary file/dir. Hand back the
                // FileOps; the caller decides what to do with a Dir
                // (most likely an open-on-directory which different
                // syscalls treat differently).
                return Ok(f);
            }

            // Intermediate: must be a directory we can descend into.
            if kind != FileType::Dir {
                return Err(FsError::NotFound);
            }
            let next = match current_dir.lookup_dir_async(&seg).await {
                Ok(d) => d,
                Err(FsError::Unsupported) => {
                    current_dir.lookup_dir(&seg).ok_or(FsError::NotFound)?
                }
                Err(e) => return Err(e),
            };
            parent_chain.push(current_dir);
            current_dir = next;
        }
        // We consumed every component without returning. Path
        // resolved to current_dir (a directory). Re-route through
        // a dummy lookup so callers get back something concrete —
        // POSIX `open(".")` returns a fd to the directory itself.
        // Until DirOps→FileOps coercion exists, surface this as
        // InvalidPath; callers wanting "open the directory" route
        // through dirfd APIs instead.
        Err(FsError::InvalidPath)
    })
}

// ── Mount + VfsRegistry ────────────────────────────────────────────

/// One mount in the global mount table. Owns the `FsInstance` (so
/// dropping the mount drops the FS) and the path it's mounted at.
/// Path is stored as `&'static str` for Stage-3 simplicity — every
/// mount in the harness today is mount-once-at-boot.
pub struct Mount {
    pub path: alloc::string::String,
    pub fs: Arc<dyn FsInstance>,
    pub handle: Cap<MountPoint, Write>,
    id: u64,
}

impl fmt::Debug for Mount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mount")
            .field("path", &self.path.as_str())
            .field("fs", &self.fs.name())
            .finish_non_exhaustive()
    }
}

fn mountinfo_rows(mounts: &[Mount]) -> Vec<(u64, u64, String, String)> {
    mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| {
            let parent = mounts[..index]
                .iter()
                .filter(|candidate| {
                    mount.path == candidate.path
                        || candidate.path == "/"
                        || (mount.path.starts_with(candidate.path.as_str())
                            && mount.path.as_bytes().get(candidate.path.len()) == Some(&b'/'))
                })
                .max_by_key(|candidate| candidate.path.len())
                .map(|candidate| candidate.id)
                .unwrap_or(0);
            (
                mount.id,
                parent,
                mount.path.clone(),
                String::from(mount.fs.name()),
            )
        })
        .collect()
}

/// Global VFS mount registry. Mirrors the cap-gate pattern used by
/// `drivers/` + `net/`: an `IrqSafeSpinLock<Vec<Mount>>` is fine
/// because mount/unmount are control-plane events, not data-plane.
#[derive(Debug)]
pub struct VfsRegistry {
    inner: IrqSafeSpinLock<Vec<Mount>>,
    mountinfo_generation: core::sync::atomic::AtomicU64,
}

static REGISTRY: VfsRegistry = VfsRegistry {
    inner: IrqSafeSpinLock::new(Vec::new()),
    mountinfo_generation: core::sync::atomic::AtomicU64::new(1),
};

static NEXT_MOUNT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

// A mount-table mutation changes `/proc/<pid>/mountinfo` readiness. The
// userspace poller owns the scheduler wake mechanism, so keep that dependency
// one-way with a boot-installed callback (the same pattern as uevent wakeups).
static MOUNT_CHANGE_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the callback invoked after a visible mount-table mutation.
///
/// The callback is deliberately parameterless: a poll/epoll waiter must
/// re-query its own mountinfo file to determine whether its namespace changed.
/// Waking all readiness waiters mirrors the existing I/O readiness bridge and
/// prevents a mount helper's SIGCHLD from racing ahead of libmount's
/// `POLLPRI` processing.
pub fn install_mount_change_hook(hook: fn()) {
    MOUNT_CHANGE_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
}

fn notify_mount_change() {
    let raw = MOUNT_CHANGE_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if raw != 0 {
        // SAFETY: `install_mount_change_hook` stores only `fn()` values.
        let hook: fn() = unsafe { core::mem::transmute(raw) };
        hook();
    }
}

fn alloc_mount_id() -> u64 {
    NEXT_MOUNT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Reference the global VFS registry.
#[inline]
pub fn registry() -> &'static VfsRegistry {
    &REGISTRY
}

// ── Per-task mount namespaces (Linux unshare(CLONE_NEWNS)) ──────
//
// A `MountNamespace` is a snapshot of the global mount table that
// a task can hold privately. After `unshare_mountns`, subsequent
// mount/umount calls from that task affect only its private NS;
// other tasks continue to see the global registry. The default —
// every task at boot — points at the shared global registry.
//
// The full divergence semantics (resolve_absolute consults the
// caller's NS, fork inherits parent NS, exec preserves NS) are
// scaffolded here; the syscall path that wires the NS lookup at
// every mount-touching site lands as the consumer crates need
// per-task views (today every NARF task shares the global view —
// the work is structural until a multi-namespace workload appears).

/// Hook returning the next process-global namespace id. Installed by
/// userspace (which owns the shared `NsId` counter) so a
/// `MountNamespace` minted in this crate draws an id from the SAME
/// space as every other namespace flavour — required for ns-fd
/// identity. Until installed, mount namespaces report id 0.
static NS_ID_ALLOC_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the shared `NsId` allocator (userspace `alloc_ns_id`).
pub fn install_ns_id_alloc_hook(f: fn() -> u64) {
    NS_ID_ALLOC_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

fn alloc_mount_ns_id() -> u64 {
    let v = NS_ID_ALLOC_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        return 0;
    }
    // SAFETY: v was stored by install_ns_id_alloc_hook as a `fn() -> u64`
    // pointer; non-zero confirms it was installed.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, fn() -> u64>(v) };
    f()
}

/// Hook exporting a DRM GEM handle as an mmap-able dma-buf `FileOps`.
/// Installed by the gpu driver (which owns the card / dumb-buffer tables)
/// so `sys_ioctl(DRM_IOCTL_PRIME_HANDLE_TO_FD)` in the syscall layer — the
/// only layer that owns the fd table — can turn a `(card_index,
/// gem_handle)` pair into a shareable, CPU-mmap-able buffer fd. Until
/// installed, PRIME export reports `None` (ioctl → ENODEV).
static DRM_PRIME_EXPORT_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the DRM PRIME export hook (gpu `prime_export_fileops`).
pub fn install_drm_prime_export_hook(f: fn(u32, u32) -> Option<Arc<dyn FileOps>>) {
    DRM_PRIME_EXPORT_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

/// Export the dumb buffer named by `gem_handle` on card `card_index` as an
/// mmap-able dma-buf `FileOps`, or `None` if the handle is unknown or the
/// hook was never installed.
pub fn drm_prime_export(card_index: u32, gem_handle: u32) -> Option<Arc<dyn FileOps>> {
    let v = DRM_PRIME_EXPORT_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: v was stored by install_drm_prime_export_hook as exactly this
    // `fn(u32, u32) -> Option<Arc<dyn FileOps>>` pointer; non-zero confirms
    // it was installed.
    let f: fn(u32, u32) -> Option<Arc<dyn FileOps>> =
        unsafe { core::mem::transmute::<usize, fn(u32, u32) -> Option<Arc<dyn FileOps>>>(v) };
    f(card_index, gem_handle)
}

/// Snapshot-shaped mount table. Holds an owned Vec of mounts so a
/// per-task NS can diverge from the global registry without
/// affecting it.
#[derive(Debug)]
pub struct MountNamespace {
    /// Stable namespace id (nsfs inode in Linux), drawn from the
    /// process-global `NsId` counter via `NS_ID_ALLOC_HOOK`.
    id: u64,
    inner: IrqSafeSpinLock<Vec<Mount>>,
    mountinfo_generation: core::sync::atomic::AtomicU64,
}

impl MountNamespace {
    fn from_mounts(mounts: &[Mount]) -> Arc<Self> {
        let copied = mounts
            .iter()
            .map(|m| Mount {
                path: m.path.clone(),
                fs: m.fs.clone(),
                handle: Cap::<MountPoint, Write>::bootstrap(),
                id: alloc_mount_id(),
            })
            .collect();
        Arc::new(Self {
            id: alloc_mount_ns_id(),
            inner: IrqSafeSpinLock::new(copied),
            mountinfo_generation: core::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Build a private namespace seeded with the current global
    /// registry's mounts. The mounts share the underlying
    /// `Arc<dyn FsInstance>` — a bind-mount-style relationship,
    /// not a deep copy.
    pub fn snapshot_global() -> Arc<Self> {
        let g = REGISTRY.inner.lock();
        Self::from_mounts(&g)
    }

    /// Copy this namespace's current mount table into a new namespace.
    ///
    /// Linux `unshare(CLONE_NEWNS)` and `clone(CLONE_NEWNS)` copy the
    /// caller's current namespace, including mounts private to it.
    pub fn snapshot(&self) -> Arc<Self> {
        let g = self.inner.lock();
        Self::from_mounts(&g)
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Monotonic change counter for `/proc/<pid>/mountinfo` poll waiters in
    /// this namespace. It advances after every visible attach, detach, or
    /// move, matching Linux's `POLLPRI` mountinfo notification contract.
    pub fn mountinfo_generation(&self) -> u64 {
        self.mountinfo_generation
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// Resolve an absolute path against this namespace.
    pub fn resolve_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, &str) -> R,
    {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        // Clone the covering mount's `Arc<fs>` + relative path and RELEASE the
        // lock before running `f` — `f` can busy-block on block I/O and `inner`
        // is an IrqSafeSpinLock, so holding it across `f` deadlocks the box
        // (see VfsRegistry::resolve_absolute for the full rationale).
        let (fs, rel) = {
            let q = self.inner.lock();
            let mut best: Option<&Mount> = None;
            for m in q.iter() {
                let is_match = abs == m.path.as_str()
                    || m.path == "/"
                    || (abs.starts_with(m.path.as_str())
                        && abs.as_bytes().get(m.path.len()) == Some(&b'/'));
                if is_match && best.map(|b| b.path.len()).unwrap_or(0) <= m.path.len() {
                    best = Some(m);
                }
            }
            let m = best?;
            let rel = &abs[m.path.len()..];
            let rel = rel.strip_prefix('/').unwrap_or(rel);
            (m.fs.clone(), alloc::string::String::from(rel))
        };
        Some(f(&*fs, &rel))
    }

    /// Clone the filesystem object of the visible mount covering `abs`.
    ///
    /// Equal-length entries are mount stacks; the newest entry wins, matching
    /// `resolve_absolute`.
    pub fn fs_arc_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        let q = self.inner.lock();
        let mut best: Option<&Mount> = None;
        for m in q.iter() {
            let is_match = abs == m.path.as_str()
                || m.path == "/"
                || (abs.starts_with(m.path.as_str())
                    && abs.as_bytes().get(m.path.len()) == Some(&b'/'));
            if is_match && best.map(|b| b.path.len()).unwrap_or(0) <= m.path.len() {
                best = Some(m);
            }
        }
        best.map(|m| m.fs.clone())
    }

    /// Clone the visible directory subtree rooted at `abs`.
    pub fn clone_tree_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        self.resolve_absolute(abs, |fs, rel| {
            let mut root = fs.root();
            for component in rel.split('/').filter(|part| !part.is_empty()) {
                root = root.lookup_dir(component)?;
            }
            Some(Arc::new(BindMount {
                root,
                fs_name: String::from(fs.name()),
                backing_identity: fs.backing_identity(),
            }) as Arc<dyn FsInstance>)
        })
        .flatten()
    }

    /// List the mount paths in this namespace.
    pub fn list(&self) -> Vec<String> {
        let q = self.inner.lock();
        q.iter().map(|m| m.path.clone()).collect()
    }

    /// List `(mount_path, fs_name)` for every mount. Used by
    /// `/proc/mounts` + `/proc/filesystems` so the synthetic FS can
    /// surface the per-mount FsInstance name without exposing the
    /// internal `Mount` shape.
    pub fn list_with_names(&self) -> Vec<(String, String)> {
        let q = self.inner.lock();
        q.iter()
            .map(|m| (m.path.clone(), String::from(m.fs.name())))
            .collect()
    }

    /// Mount identity and hierarchy in attachment order.
    pub fn list_mountinfo(&self) -> Vec<(u64, u64, String, String)> {
        mountinfo_rows(&self.inner.lock())
    }

    /// ID of the newest visible mount covering `abs`.
    pub fn mount_id_at(&self, abs: &str) -> Option<u64> {
        let q = self.inner.lock();
        q.iter()
            .filter(|m| {
                abs == m.path
                    || m.path == "/"
                    || (abs.starts_with(m.path.as_str())
                        && abs.as_bytes().get(m.path.len()) == Some(&b'/'))
            })
            .max_by_key(|m| m.path.len())
            .map(|m| m.id)
    }

    /// Attach a filesystem to this private namespace. Unlike the boot-time
    /// registry, private namespaces permit stacking at the same path; the most
    /// recently attached mount is the visible one.
    pub fn mount_arc(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        fs: Arc<dyn FsInstance>,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        let handle = Cap::<MountPoint, Write>::bootstrap();
        self.inner.lock().push(Mount {
            path: String::from(path),
            fs,
            handle,
            id: alloc_mount_id(),
        });
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        notify_mount_change();
        Ok(handle)
    }

    /// Bind an arbitrary directory into this private namespace.
    pub fn bind_mount(
        &self,
        authority: &Cap<MountPoint, Grant>,
        source: &str,
        target: &str,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        let (source_fs, rel) = {
            let q = self.inner.lock();
            let source_mount = q
                .iter()
                .filter(|m| {
                    source == m.path
                        || m.path == "/"
                        || (source.starts_with(m.path.as_str())
                            && source.as_bytes().get(m.path.len()) == Some(&b'/'))
                })
                .max_by_key(|m| m.path.len())
                .ok_or(FsError::NotFound)?;
            (
                source_mount.fs.clone(),
                String::from(source[source_mount.path.len()..].trim_start_matches('/')),
            )
        };
        // A directory source binds as a subtree; a FILE source binds as a
        // single file (mount --bind of a file).
        let bind = build_bind_fs(&source_fs, &rel)?;
        self.mount_arc(authority, target, bind)
    }

    /// Detach the topmost mount at `path` from this private namespace.
    pub fn unmount(&self, path: &str) -> Result<(), FsError> {
        let mut q = self.inner.lock();
        let index = q
            .iter()
            .rposition(|m| m.path == path)
            .ok_or(FsError::NotFound)?;
        q.remove(index);
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        notify_mount_change();
        Ok(())
    }

    /// Move the topmost mount at `source` to `target`.
    pub fn move_mount(&self, source: &str, target: &str) -> Result<(), FsError> {
        let mut q = self.inner.lock();
        let index = q
            .iter()
            .rposition(|m| m.path == source)
            .ok_or(FsError::NotFound)?;
        q[index].path = String::from(target);
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        notify_mount_change();
        Ok(())
    }
}

/// Bootstrap the mount-authority cap. TCB-only path — the kernel
/// calls this once at boot and hands the result to whatever subsystem
/// actually mounts the initial root.
pub fn bootstrap_mount_authority() -> Cap<MountPoint, Grant> {
    Cap::<MountPoint, Grant>::bootstrap()
}

/// FsInstance adapter that exposes a directory from another filesystem as a
/// mount root. Used to implement `bind_mount` without copying the subtree.
struct BindMount {
    root: Arc<dyn DirOps>,
    fs_name: String,
    backing_identity: usize,
}

impl fmt::Debug for BindMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindMount")
            .field("fs_name", &self.fs_name)
            .finish_non_exhaustive()
    }
}

impl FsInstance for BindMount {
    fn root(&self) -> Arc<dyn DirOps> {
        self.root.clone()
    }
    fn name(&self) -> &str {
        // POSIX `mount(2)` / `proc(5)` both report bind mounts with
        // their source FS name; matches Linux's /proc/mounts shape
        // where a bind mount lists the source FS type, not "bind".
        &self.fs_name
    }
    fn backing_identity(&self) -> usize {
        self.backing_identity
    }
}

/// A directory with no entries — the `root()` of a [`FileMount`], whose real
/// content is a single file reached via [`FsInstance::root_file`], not children.
#[derive(Debug)]
struct EmptyDir;

impl DirOps for EmptyDir {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }
}

/// FsInstance adapter that exposes a single FILE (from another filesystem) as a
/// mount root — Linux `mount --bind <file> <target-file>`. Resolution that
/// lands on this mount's root returns the file via [`FsInstance::root_file`];
/// the directory `root()` is empty because a file mount has no children.
struct FileMount {
    file: Arc<dyn FileOps>,
    fs_name: String,
    // A file bind is another mount attachment to the *source* inode, not a
    // new filesystem.  Preserve that identity for inode-aware VFS users such
    // as pathname AF_UNIX, which must recognise the source and target as the
    // same socket node.
    backing_identity: usize,
}

impl fmt::Debug for FileMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileMount")
            .field("fs_name", &self.fs_name)
            .finish_non_exhaustive()
    }
}

impl FsInstance for FileMount {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(EmptyDir)
    }
    fn name(&self) -> &str {
        &self.fs_name
    }
    fn backing_identity(&self) -> usize {
        self.backing_identity
    }
    fn root_file(&self) -> Option<Arc<dyn FileOps>> {
        Some(self.file.clone())
    }
}

/// Build the `FsInstance` for binding the node at relative path `rel` within
/// `source_fs`: a directory leaf becomes a [`BindMount`], a FILE leaf a
/// [`FileMount`] (so `mount --bind <file> <target>` works, which systemd relies
/// on for read-only procfs-control-file protection). Every component but the
/// last must be a directory. Uses the sync `lookup`/`lookup_dir`; block-backed
/// filesystems drive their real I/O from those synchronously (see the ext2
/// driver's `lookup`/`lookup_dir`), so a DEEP bind source — systemd's
/// StateDirectory=, e.g. binding /var/lib/systemd/linger for logind — resolves.
fn build_bind_fs(
    source_fs: &Arc<dyn FsInstance>,
    rel: &str,
) -> Result<Arc<dyn FsInstance>, FsError> {
    let fs_name = String::from(source_fs.name());
    let comps: alloc::vec::Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    if comps.is_empty() {
        // Binding the source mount's root directory itself.
        return Ok(Arc::new(BindMount {
            root: source_fs.root(),
            fs_name,
            backing_identity: source_fs.backing_identity(),
        }));
    }
    let mut dir = source_fs.root();
    for c in &comps[..comps.len() - 1] {
        dir = dir.lookup_dir(c).ok_or(FsError::NotFound)?;
    }
    let last = comps[comps.len() - 1];
    // Dispatch on the leaf's actual type, not on which lookup succeeds: some
    // filesystems expose a directory as a Dir-typed FileOps via `lookup` too.
    // A directory leaf binds as a subtree (BindMount); anything else binds as a
    // single file (FileMount).
    if let Some(node) = dir.lookup(last) {
        if node.stat().mode.file_type == FileType::Dir {
            if let Some(d) = dir.lookup_dir(last) {
                return Ok(Arc::new(BindMount {
                    root: d,
                    fs_name,
                    backing_identity: source_fs.backing_identity(),
                }));
            }
        }
        return Ok(Arc::new(FileMount {
            file: node,
            fs_name,
            backing_identity: source_fs.backing_identity(),
        }));
    }
    // Some filesystems only expose child directories via `lookup_dir`.
    if let Some(d) = dir.lookup_dir(last) {
        return Ok(Arc::new(BindMount {
            root: d,
            fs_name,
            backing_identity: source_fs.backing_identity(),
        }));
    }
    Err(FsError::NotFound)
}

impl VfsRegistry {
    /// Monotonic change counter for global `/proc/<pid>/mountinfo` poll
    /// waiters. The userspace proc hook selects this only for tasks that have
    /// not unshared a private mount namespace.
    pub fn mountinfo_generation(&self) -> u64 {
        self.mountinfo_generation
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// Mount `fs` at `path`. The `authority` cap is checked live;
    /// a revoked authority returns `FsError::PermissionDenied`
    /// (via the `From<CapError>` impl) before any side effect.
    /// Mounting onto an already-occupied path stacks (Linux overmount
    /// semantics): the new mount shadows the ones below it, `resolve_absolute`
    /// selects the most-recently pushed mount at a path, and `unmount` pops the
    /// topmost — matching `MountNamespace`. systemd relies on this to bind a
    /// read-only copy of a procfs control file (e.g. /proc/sys/kernel/domainname
    /// under ProtectHostname=) over the existing one; rejecting the overmount
    /// with EBUSY failed service namespace setup with 226/EXIT_NAMESPACE.
    pub fn mount<F: FsInstance>(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        fs: F,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;

        let mut q = self.inner.lock();
        let handle: Cap<MountPoint, Write> = Cap::<MountPoint, Write>::bootstrap();
        let arc: Arc<dyn FsInstance> = Arc::new(fs);
        q.push(Mount {
            path: alloc::string::String::from(path),
            fs: arc,
            handle,
            id: alloc_mount_id(),
        });
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        notify_mount_change();
        Ok(handle)
    }

    /// Mount with a pre-built `Arc<dyn FsInstance>`. Used by the
    /// sys_mount path where the FS is constructed by a driver-side
    /// helper that already returns an Arc.
    pub fn mount_arc(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        fs: Arc<dyn FsInstance>,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;

        let mut q = self.inner.lock();
        let handle: Cap<MountPoint, Write> = Cap::<MountPoint, Write>::bootstrap();
        q.push(Mount {
            path: alloc::string::String::from(path),
            fs,
            handle,
            id: alloc_mount_id(),
        });
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        notify_mount_change();
        Ok(handle)
    }

    /// POSIX-2017 bind mount: register `target` as a synthetic mount
    /// whose root is the directory currently visible at the absolute
    /// path `source`. The bind doesn't copy any data — the synthetic
    /// FsInstance forwards root() / name() to the source DirOps.
    /// Useful for exposing a subtree of one filesystem at another
    /// path without remounting the whole volume (Linux's
    /// `mount --bind <source> <target>`).
    pub fn bind_mount(
        &self,
        authority: &Cap<MountPoint, Grant>,
        source: &str,
        target: &str,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        // Resolve the longest mount prefix first, then walk the remaining
        // directory components. Linux permits binding any directory, not only
        // a filesystem root; systemd relies on that while constructing a
        // service's private mount namespace.
        let q = self.inner.lock();
        let source_mount = q
            .iter()
            .filter(|m| {
                source == m.path
                    || m.path == "/"
                    || (source.starts_with(m.path.as_str())
                        && source.as_bytes().get(m.path.len()) == Some(&b'/'))
            })
            .max_by_key(|m| m.path.len())
            .ok_or(FsError::NotFound)?;
        let source_fs = source_mount.fs.clone();
        let rel = String::from(source[source_mount.path.len()..].trim_start_matches('/'));
        // Overmount is allowed: a bind onto an occupied path stacks (see `mount`).
        drop(q);
        // A directory source binds as a subtree; a FILE source binds as a
        // single file (mount --bind of a file).
        let bind = build_bind_fs(&source_fs, &rel)?;
        self.mount_arc(authority, target, bind)
    }

    /// List mount paths. Used by `/proc/mounts`-shaped surfaces and by
    /// statfs when the caller wants to know what's where. Returns
    /// owned Strings so the lock is released before the caller walks
    /// the result.
    pub fn list(&self) -> alloc::vec::Vec<alloc::string::String> {
        let q = self.inner.lock();
        q.iter().map(|m| m.path.clone()).collect()
    }

    /// List `(mount_path, fs_name)` for every mount. Used by
    /// `/proc/mounts` + `/proc/filesystems` so the synthetic FS can
    /// surface the per-mount FsInstance name without exposing the
    /// internal `Mount` shape.
    pub fn list_with_names(
        &self,
    ) -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)> {
        let q = self.inner.lock();
        q.iter()
            .map(|m| (m.path.clone(), alloc::string::String::from(m.fs.name())))
            .collect()
    }

    /// Mount identity and hierarchy in attachment order.
    pub fn list_mountinfo(
        &self,
    ) -> alloc::vec::Vec<(u64, u64, alloc::string::String, alloc::string::String)> {
        mountinfo_rows(&self.inner.lock())
    }

    /// ID of the visible mount covering `abs`.
    pub fn mount_id_at(&self, abs: &str) -> Option<u64> {
        let q = self.inner.lock();
        q.iter()
            .filter(|m| {
                abs == m.path
                    || m.path == "/"
                    || (abs.starts_with(m.path.as_str())
                        && abs.as_bytes().get(m.path.len()) == Some(&b'/'))
            })
            .max_by_key(|m| m.path.len())
            .map(|m| m.id)
    }

    /// Unmount the FS at `path`. The `handle` cap must be live and
    /// must be the one returned from the matching `mount`. A revoked
    /// handle surfaces as `PermissionDenied`. Holding the lock across
    /// the comparison guarantees the unmount and the handle-match are
    /// observed atomically — no two concurrent unmounts can race on
    /// the same slot.
    pub fn unmount(&self, handle: &Cap<MountPoint, Write>, path: &str) -> Result<(), FsError> {
        handle.check_live()?;

        let mut q = self.inner.lock();
        // Pop the TOPMOST mount at `path` (last pushed) and preserve the order
        // of the rest: with stacking, `rposition` + `remove` reveal the mount
        // directly below, matching Linux umount. `swap_remove` would reorder the
        // vec and corrupt which stacked mount resolves as visible.
        let pos = q
            .iter()
            .rposition(|m| m.path == path)
            .ok_or(FsError::NotFound)?;
        let m = q.remove(pos);
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        // Drop the FS Arc outside the lock to keep the critical
        // section short — important once page-cache eviction lands.
        drop(q);
        drop(m);
        notify_mount_change();
        Ok(())
    }

    /// Move a mounted filesystem from `source` to `target`.
    pub fn move_mount(
        &self,
        authority: &Cap<MountPoint, Grant>,
        source: &str,
        target: &str,
    ) -> Result<(), FsError> {
        authority.check_live()?;
        let mut q = self.inner.lock();
        let index = q
            .iter()
            .rposition(|m| m.path == source)
            .ok_or(FsError::NotFound)?;
        // Overmount is allowed: moving onto an occupied path stacks (see `mount`).
        q[index].path = String::from(target);
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        notify_mount_change();
        Ok(())
    }

    /// Run `f` against the named mount's `FsInstance`. Returns `None`
    /// if no mount matches. The registry lock is released BEFORE `f` runs:
    /// callers pass blocking closures (e.g. `sys_mount` drives
    /// `resolve_async` via the busy-spinning `poll_blocking`), and holding
    /// the `inner` IrqSafeSpinLock across a block-I/O wait deadlocks the box
    /// (see `resolve_absolute`). The cloned `Arc` keeps the FsInstance alive
    /// across a concurrent unmount.
    pub fn with_mount<R, F>(&self, path: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance) -> R,
    {
        let fs = {
            let q = self.inner.lock();
            // Topmost (last-pushed) mount at `path`, matching resolve_absolute.
            q.iter()
                .rev()
                .find(|m| m.path == path)
                .map(|m| m.fs.clone())
        }?;
        Some(f(&*fs))
    }

    /// Resolve a POSIX-shaped absolute path by finding the
    /// longest mount-prefix match and running `f` against the
    /// matching FS with the remaining suffix (leading `/`
    /// stripped). Returns `None` when no mount covers the path.
    ///
    /// Examples (with `/test` and `/test/sub` both mounted):
    ///   `/test/foo`     → `/test`     + `foo`
    ///   `/test/sub/bar` → `/test/sub` + `bar`
    ///   `/elsewhere`    → None
    pub fn resolve_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, &str) -> R,
    {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        // Select the covering mount under the lock, then CLONE its `Arc<fs>`
        // and the relative path and RELEASE the lock BEFORE running `f`. `f`
        // may block: the stat/open/execve resolvers drive `resolve_async` via
        // `poll_blocking`, which BUSY-SPINS on the backing block device's
        // completion IRQ. `inner` is an IrqSafeSpinLock (IRQs disabled while
        // held), so running `f` under it spins on an I/O IRQ that can never
        // fire on this CPU — and every other task that touches the mount table
        // (path resolution, statx mount-id, mount/umount) stalls behind it.
        // Under an SMP statx storm (systemd unit loading) that deadlocked the
        // whole box. The `Arc` keeps the FsInstance alive even if a concurrent
        // umount drops it from the table mid-resolve, matching Linux (an
        // in-flight op on an unmounted fs completes).
        let (fs, rel) = {
            let q = self.inner.lock();
            // Find the longest matching mount path. The root mount `/`
            // is a special case: every absolute path is under it, but
            // the "next byte must be `/`" predicate would reject e.g.
            // `/init` because byte 1 is `i` not `/`. Special-case "/"
            // so the root mount always matches as the fallback option.
            let mut best: Option<&Mount> = None;
            for m in q.iter() {
                let is_match = abs == m.path
                    || m.path == "/"
                    || (abs.starts_with(m.path.as_str())
                        && abs.as_bytes().get(m.path.len()) == Some(&b'/'));
                if is_match && best.map(|b| b.path.len()).unwrap_or(0) <= m.path.len() {
                    best = Some(m);
                }
            }
            let m = best?;
            let rel = &abs[m.path.len()..];
            // Strip the leading slash; if the absolute path equals the
            // mount path exactly, the relative is empty (caller's
            // problem — `resolve` rejects empty paths).
            let rel = rel.strip_prefix('/').unwrap_or(rel);
            (m.fs.clone(), alloc::string::String::from(rel))
        };
        Some(f(&*fs, &rel))
    }

    /// Clone the `Arc<dyn FsInstance>` of the mount covering `abs` (the
    /// longest-prefix match). Used by the new mount API's `open_tree` /
    /// `fspick` to grab an existing mount's filesystem object.
    pub fn fs_arc_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        let q = self.inner.lock();
        let mut best: Option<&Mount> = None;
        for m in q.iter() {
            let is_match = abs == m.path
                || m.path == "/"
                || (abs.starts_with(m.path.as_str())
                    && abs.as_bytes().get(m.path.len()) == Some(&b'/'));
            if is_match && best.map(|b| b.path.len()).unwrap_or(0) <= m.path.len() {
                best = Some(m);
            }
        }
        best.map(|m| m.fs.clone())
    }

    /// Clone the directory subtree rooted at `abs` as a detached filesystem.
    pub fn clone_tree_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        self.resolve_absolute(abs, |fs, rel| {
            let mut root = fs.root();
            for component in rel.split('/').filter(|part| !part.is_empty()) {
                root = root.lookup_dir(component)?;
            }
            Some(Arc::new(BindMount {
                root,
                fs_name: String::from(fs.name()),
                backing_identity: fs.backing_identity(),
            }) as Arc<dyn FsInstance>)
        })
        .flatten()
    }

    /// Resolve `abs` to its parent directory + leaf name and run
    /// `f(fs, parent_dir, leaf)` against the result. Used by
    /// directory-mutation syscalls (`unlink` / `mkdir` / `rmdir`)
    /// which need to walk to the parent and operate on the leaf.
    ///
    /// Splits at the LAST `/` of the relative-to-mount portion. So
    /// `/tmp/foo` against a `/tmp` mount produces `(parent=root,
    /// leaf="foo")`; `/tmp/sub/bar` produces `(parent=root.sub,
    /// leaf="bar")`. The walk uses `lookup_dir` for every parent
    /// segment and bails with `NotFound` if any intermediate is
    /// absent. Returns `None` when no mount covers `abs`.
    pub fn resolve_parent_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<dyn DirOps>, &str) -> R,
    {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        // Split at last `/`. Need at least one slash and a leaf.
        let last = abs.rfind('/')?;
        let parent_path = &abs[..last];
        let leaf = &abs[last + 1..];
        if leaf.is_empty() {
            return None;
        }
        // The parent path may be empty (e.g. abs == "/foo" → parent
        // == "/"). In that case we resolve against the root mount of
        // the leaf's mount; conceptually the parent is the mount
        // root itself.
        let parent_path = if parent_path.is_empty() {
            "/"
        } else {
            parent_path
        };
        // Resolve the mount + walk to the parent dir under the lock (the sync
        // `lookup_dir` walk does not block), then CLONE the fs `Arc` + parent
        // `DirOps` and RELEASE the lock BEFORE running `f` — `f` may block on
        // block I/O (create/mkdir on ext2), and holding the `inner`
        // IrqSafeSpinLock across that deadlocks the box (see `resolve_absolute`).
        let (fs, dir) = {
            let q = self.inner.lock();
            // Match the longest mount prefix against `parent_path`.
            let mut best: Option<&Mount> = None;
            for m in q.iter() {
                if (parent_path == m.path
                    || (parent_path.starts_with(m.path.as_str())
                        && parent_path.as_bytes().get(m.path.len()) == Some(&b'/')))
                    && best.map(|b| b.path.len()).unwrap_or(0) <= m.path.len()
                {
                    best = Some(m);
                }
            }
            let m = best?;
            let rel = &parent_path[m.path.len()..];
            let rel = rel.strip_prefix('/').unwrap_or(rel);
            // Walk segments to reach the parent dir.
            let mut dir = m.fs.root();
            for seg in rel.split('/') {
                if seg.is_empty() || seg == "." {
                    continue;
                }
                if seg == ".." {
                    return None;
                }
                dir = dir.lookup_dir(seg)?;
            }
            (m.fs.clone(), dir)
        };
        Some(f(&*fs, dir, leaf))
    }

    /// Resolve the parent directories of TWO absolute paths at once,
    /// requiring both to land on the SAME mount, and hand both
    /// `(dir, leaf)` pairs to `f`.
    ///
    /// This is what a cross-*directory* rename needs: `rename(2)` may
    /// only move a name between directories of one filesystem, so the
    /// same-mount check is the real `EXDEV` test. Returns `None` when
    /// either path fails to resolve or the two live on different
    /// mounts — the caller turns that into `-EXDEV`.
    ///
    /// Both walks happen under one registry lock so a concurrent
    /// mount/unmount can't move one path's mount out from under the
    /// other between the two resolutions.
    pub fn resolve_two_parents_absolute<R, F>(&self, a: &str, b: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<dyn DirOps>, &str, Arc<dyn DirOps>, &str) -> R,
    {
        fn split(abs: &str) -> Option<(&str, &str)> {
            if abs.is_empty() || abs.as_bytes()[0] != b'/' {
                return None;
            }
            let last = abs.rfind('/')?;
            let leaf = &abs[last + 1..];
            if leaf.is_empty() {
                return None;
            }
            let parent = &abs[..last];
            Some((if parent.is_empty() { "/" } else { parent }, leaf))
        }
        let (a_parent, a_leaf) = split(a)?;
        let (b_parent, b_leaf) = split(b)?;

        // Resolve BOTH parents + walk to their dirs under ONE lock (so a
        // concurrent mount/unmount can't move one path's mount between the two
        // resolutions — the atomicity `rename`'s EXDEV check needs), then CLONE
        // the shared fs `Arc` + both parent `DirOps` and RELEASE the lock before
        // running `f`. `f` performs the rename, which may block on block I/O;
        // holding the `inner` IrqSafeSpinLock across it deadlocks the box (see
        // `resolve_absolute`). Resolution atomicity is preserved; only `f` runs
        // unlocked.
        let (fs, a_dir, b_dir) = {
            let q = self.inner.lock();
            // Longest matching mount prefix, same rule as
            // `resolve_parent_absolute`.
            let best_mount = |parent_path: &str| -> Option<&Mount> {
                let mut best: Option<&Mount> = None;
                for m in q.iter() {
                    if (parent_path == m.path
                        || (parent_path.starts_with(m.path.as_str())
                            && parent_path.as_bytes().get(m.path.len()) == Some(&b'/')))
                        && best.map(|x| x.path.len()).unwrap_or(0) < m.path.len()
                    {
                        best = Some(m);
                    }
                }
                best
            };
            let ma = best_mount(a_parent)?;
            let mb = best_mount(b_parent)?;
            // Different mounts ⇒ a genuine cross-device move. Mount paths
            // are unique in the registry, so comparing them identifies the
            // mount.
            if ma.path != mb.path {
                return None;
            }
            let walk = |m: &Mount, parent_path: &str| -> Option<Arc<dyn DirOps>> {
                let rel = &parent_path[m.path.len()..];
                let rel = rel.strip_prefix('/').unwrap_or(rel);
                let mut dir = m.fs.root();
                for seg in rel.split('/') {
                    if seg.is_empty() || seg == "." {
                        continue;
                    }
                    if seg == ".." {
                        return None;
                    }
                    dir = dir.lookup_dir(seg)?;
                }
                Some(dir)
            };
            let a_dir = walk(ma, a_parent)?;
            let b_dir = walk(mb, b_parent)?;
            (ma.fs.clone(), a_dir, b_dir)
        };
        Some(f(&*fs, a_dir, a_leaf, b_dir, b_leaf))
    }

    /// Number of mounts.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff no FS is mounted.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

// ── Initramfs (CPIO newc reader) ───────────────────────────────────
//
// CPIO newc format: each entry is a 110-byte fixed-width header
// (magic "070701" + 13 ASCII-hex u32 fields), followed by `namesize`
// bytes of NUL-terminated name, padded to a 4-byte boundary, then
// `filesize` bytes of file data, also padded to a 4-byte boundary.
// Archive ends with a sentinel entry named "TRAILER!!!" (filesize 0).
//
// We parse the whole archive at construction time into a flat
// `Vec<InitramfsEntry>`; file data is borrowed by `&'static [u8]`
// from the source archive. No copy on read — the FileOps::read impl
// memcpys into the caller's buffer (the only copy is the unavoidable
// kernel→caller move).

/// One pre-parsed entry from the initramfs archive.
struct InitramfsEntry {
    /// Path as it appeared in the archive, `'static` because it
    /// borrows from the archive byte slice.
    name: &'static str,
    /// File contents, also borrowed from the archive.
    data: &'static [u8],
    /// File mode from the CPIO header (low bits = perms, high bits
    /// = file type per POSIX). Stage 3 only inspects the
    /// "is-it-a-regular-file" bit (0o100000).
    mode: u32,
    /// mtime as `(seconds since epoch)` from the CPIO header. Stage
    /// 3 stuffs this directly into `Stat::mtime_cycles` — the units
    /// disagree but the spec already calls mtime_cycles a stub for
    /// Stage 3 and Stage 4 introduces a real wall-clock conversion.
    mtime: u64,
}

impl fmt::Debug for InitramfsEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsEntry")
            .field("name", &self.name)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// Read-only in-memory filesystem backed by a CPIO newc archive.
pub struct Initramfs {
    name: &'static str,
    entries: Vec<InitramfsEntry>,
}

impl fmt::Debug for Initramfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Initramfs")
            .field("name", &self.name)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Parse error surfaced from `Initramfs::from_cpio`. The discriminant
/// is non-exhaustive so additional checks can land without breaking
/// callers' match arms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpioError {
    /// Header magic wasn't `070701`.
    BadMagic,
    /// Archive truncated mid-header or mid-data.
    Truncated,
    /// Header field wasn't valid ASCII hex.
    BadHex,
    /// Filename wasn't valid UTF-8.
    BadName,
}

impl Initramfs {
    /// Iterate every regular-file entry as `(name, data)` pairs.
    /// `name` is the path-as-it-appeared in the archive (CPIO has
    /// no directory hierarchy beyond what's encoded in slashes).
    /// External crates use this to scoop subtrees — e.g.
    /// `narf-firmware` walks `firmware/*` entries at boot.
    pub fn iter_files(&self) -> impl Iterator<Item = (&'static str, &'static [u8])> + '_ {
        self.entries
            .iter()
            .filter(|e| (e.mode & 0o170000) == 0o100000) // S_IFREG
            .map(|e| (e.name, e.data))
    }

    /// Parse a CPIO newc archive. The slice must outlive the
    /// `Initramfs` (we borrow names + file data straight from it);
    /// `&'static [u8]` is the natural Stage-3 lifetime because the
    /// bootloader places the initramfs in identity-mapped low RAM.
    pub fn from_cpio(name: &'static str, archive: &'static [u8]) -> Result<Self, CpioError> {
        let mut entries = Vec::new();
        let mut off = 0usize;

        loop {
            // 110-byte fixed header.
            if off + 110 > archive.len() {
                return Err(CpioError::Truncated);
            }
            let hdr = &archive[off..off + 110];
            if &hdr[..6] != b"070701" {
                return Err(CpioError::BadMagic);
            }

            // Field offsets per CPIO newc layout:
            //   6:14  c_ino,    14:22 c_mode,  22:30 c_uid,    30:38 c_gid,
            //  38:46  c_nlink,  46:54 c_mtime, 54:62 c_filesize, 62:70 c_devmajor,
            //  70:78  c_devminor, 78:86 c_rdevmajor, 86:94 c_rdevminor,
            //  94:102 c_namesize, 102:110 c_check.
            let mode = parse_hex8(&hdr[14..22])?;
            let mtime = parse_hex8(&hdr[46..54])? as u64;
            let filesize = parse_hex8(&hdr[54..62])? as usize;
            let namesize = parse_hex8(&hdr[94..102])? as usize;

            off += 110;

            // namesize includes the trailing NUL, so it must be at least 1.
            if namesize < 1 || off + namesize > archive.len() {
                return Err(CpioError::Truncated);
            }
            // Name includes the trailing NUL — drop it before UTF-8.
            let name_bytes = &archive[off..off + namesize - 1];
            let name_str = core::str::from_utf8(name_bytes).map_err(|_| CpioError::BadName)?;

            off += namesize;
            // Pad to 4-byte boundary, measured from start of header.
            // The header starts at `off - 110 - namesize` and the
            // name follows; total bytes-since-archive-start at the
            // end of the name is `off`. Round up to 4.
            off = (off + 3) & !3;

            // TRAILER!!! sentinel ends the archive.
            if name_str == "TRAILER!!!" {
                break;
            }

            if off + filesize > archive.len() {
                return Err(CpioError::Truncated);
            }
            let data = &archive[off..off + filesize];

            // Skip "." root entries — useful when produced by
            // `find . | cpio -o -H newc`. Not an error; just no
            // observable file to expose.
            if name_str != "." {
                entries.push(InitramfsEntry {
                    name: name_str,
                    data,
                    mode,
                    mtime,
                });
            }

            off += filesize;
            off = (off + 3) & !3;
        }

        Ok(Self { name, entries })
    }
}

/// Parse exactly 8 ASCII hex digits into a u32.
fn parse_hex8(bytes: &[u8]) -> Result<u32, CpioError> {
    if bytes.len() != 8 {
        return Err(CpioError::BadHex);
    }
    let mut acc = 0u32;
    for &b in bytes {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(CpioError::BadHex),
        };
        acc = (acc << 4) | (v as u32);
    }
    Ok(acc)
}

/// `FsInstance` impl: the root `DirOps` is built fresh on each call
/// because the lookup table is a borrowed slice of the FS itself.
/// `Arc<dyn DirOps>` wraps a thin handle that holds the entries via
/// shared `Arc` state.
impl FsInstance for Initramfs {
    fn root(&self) -> Arc<dyn DirOps> {
        // Stage-3 lifetime trick: build a fresh `InitramfsRoot` that
        // holds a raw pointer back into our `entries` Vec. Safe
        // because `Initramfs` lives inside the registry's `Arc<dyn
        // FsInstance>` — the entries Vec doesn't move until the FS
        // is dropped, and the FS isn't dropped while the registry
        // holds the Arc.
        //
        // SAFETY argument expanded inside `InitramfsRoot::lookup` /
        // `iter` where the pointer is dereffed.
        Arc::new(InitramfsRoot {
            entries_ptr: self.entries.as_ptr(),
            entries_len: self.entries.len(),
        })
    }
    fn name(&self) -> &str {
        self.name
    }
}

/// Thin handle exposing the initramfs as a `DirOps`. See the SAFETY
/// note in `Initramfs::root`.
struct InitramfsRoot {
    entries_ptr: *const InitramfsEntry,
    entries_len: usize,
}

// SAFETY: the pointer is to a `Vec` owned by an `Initramfs` held
// behind an `Arc<dyn FsInstance>` in the global registry; `Send` +
// `Sync` are sound because the underlying entries are immutable
// after `from_cpio` returns and the `&'static [u8]` data slices are
// trivially `Sync`.
// SAFETY: see paragraph above.
unsafe impl Send for InitramfsRoot {}
// SAFETY: see paragraph above.
unsafe impl Sync for InitramfsRoot {}

impl fmt::Debug for InitramfsRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsRoot")
            .field("entries_len", &self.entries_len)
            .finish_non_exhaustive()
    }
}

impl InitramfsRoot {
    /// Borrow the entries slice. SAFETY: as documented on the struct.
    fn entries(&self) -> &'static [InitramfsEntry] {
        // SAFETY: pointer + length come from a Vec owned by an
        // Initramfs that is alive for the duration of the registry
        // mount that produced this root. The `'static` lifetime here
        // is a white lie to the borrow checker — the actual lifetime
        // is "as long as the mount lives", which Stage 3 enforces by
        // not exposing `unmount-while-handle-live` (the FsFuture's
        // returned by `read` borrow `&'a self`, so the borrow checker
        // catches use-after-unmount in the normal case).
        // SAFETY: Valid memory or trusted environment
        unsafe { core::slice::from_raw_parts(self.entries_ptr, self.entries_len) }
    }
}

/// Strip the canonical "./" or "/" prefix a CPIO archive can
/// emit, depending on how `find` was invoked when packing.
fn canonicalize_cpio_name(raw: &str) -> &str {
    let s = raw.strip_prefix("./").unwrap_or(raw);
    s.strip_prefix('/').unwrap_or(s)
}

/// Walk every entry under `prefix` and report the immediate-child
/// names (one path component below `prefix`), deduplicated. For
/// each unique child, mark it as Dir if any deeper entry begins
/// with `prefix/child/`, else File.
///
/// Used by both [`InitramfsRoot::iter`] and the nested
/// `InitramfsDir` wrapper. Without this, `ls /` was returning the
/// raw CPIO flat-namespace entries (`firmware/blah.bin`,
/// `bin/sh`, etc.) as single dirents of `/`, which looked like a
/// recursive walk to the caller.
fn collect_immediate_children<'a>(
    entries: &'a [crate::InitramfsEntry],
    prefix: &str,
) -> Vec<(String, FileType)> {
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    // (child, has_subentries)
    let mut seen: BTreeMap<&'a str, bool> = BTreeMap::new();
    for e in entries.iter() {
        let canon = canonicalize_cpio_name(e.name);
        let rest = if prefix.is_empty() {
            Some(canon)
        } else if canon == prefix {
            None
        } else if let Some(r) = canon.strip_prefix(prefix) {
            r.strip_prefix('/')
        } else {
            None
        };
        let rest = match rest {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let (first, tail) = match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash + 1..]),
            None => (rest, ""),
        };
        let has_children = !tail.is_empty() || (rest == first && (e.mode & 0o170000 == 0o040000));
        match seen.get_mut(first) {
            Some(flag) => {
                *flag |= has_children;
            }
            None => {
                seen.insert(first, has_children);
            }
        }
    }
    seen.into_iter()
        .map(|(name, is_dir)| {
            (
                name.to_string(),
                if is_dir {
                    FileType::Dir
                } else {
                    FileType::File
                },
            )
        })
        .collect()
}

/// A subdirectory view onto the same CPIO entry table that
/// `InitramfsRoot` holds, but restricted to entries under
/// `prefix`. Returned by `InitramfsRoot::lookup_dir` and
/// `InitramfsDir::lookup_dir` so `ls /firmware` works.
struct InitramfsDir {
    entries: &'static [crate::InitramfsEntry],
    prefix: String,
}

impl fmt::Debug for InitramfsDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsDir")
            .field("prefix", &self.prefix)
            .field("n_entries", &self.entries.len())
            .finish()
    }
}

// `InitramfsDir` holds only a `&'static [InitramfsEntry]` and a `String`, both
// of which are already `Send` + `Sync` (the entries borrow immutable archive
// bytes), so the auto-derived impls suffice — no manual `unsafe impl` needed.

impl InitramfsDir {
    fn child_prefix(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            String::from(name)
        } else {
            let mut p = self.prefix.clone();
            p.push('/');
            p.push_str(name);
            p
        }
    }
}

impl DirOps for InitramfsDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let target = self.child_prefix(name);
        for e in self.entries.iter() {
            if canonicalize_cpio_name(e.name) == target {
                return Some(Arc::new(InitramfsFile {
                    data: e.data,
                    mode: e.mode,
                    mtime: e.mtime,
                }));
            }
        }
        // Synthesize virtual directory for implicit subdirectories —
        // same rationale as InitramfsRoot::lookup.
        let any_child = self.entries.iter().any(|e| {
            let canon = canonicalize_cpio_name(e.name);
            canon
                .strip_prefix(&target)
                .and_then(|r| r.strip_prefix('/'))
                .is_some()
        });
        if any_child {
            return Some(Arc::new(InitramfsFile {
                data: &[],
                mode: 0o040_755,
                mtime: 0,
            }));
        }
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let target = self.child_prefix(name);
        // Any entry whose canonical name == target/* or == target?
        let any_match = self.entries.iter().any(|e| {
            let canon = canonicalize_cpio_name(e.name);
            canon == target
                || canon
                    .strip_prefix(&target)
                    .and_then(|r| r.strip_prefix('/'))
                    .is_some()
        });
        if !any_match {
            return None;
        }
        Some(Arc::new(InitramfsDir {
            entries: self.entries,
            prefix: target,
        }))
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // The hierarchical view requires owned Strings (the
        // child-name extraction allocates). Return an empty
        // iterator here and let the framework call `enumerate`.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let all = collect_immediate_children(self.entries, &self.prefix);
        all.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

impl DirOps for InitramfsRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Match either bare name ("hello") or leading-slash-stripped
        // form ("/hello") — CPIO archives produced with `find ./` or
        // `find /` differ on the prefix; tolerating both keeps
        // archive-generation flexible.
        for e in self.entries().iter() {
            if canonicalize_cpio_name(e.name) == name {
                return Some(Arc::new(InitramfsFile {
                    data: e.data,
                    mode: e.mode,
                    mtime: e.mtime,
                }));
            }
        }
        // Synthesize a virtual directory entry for implicit directories —
        // CPIO archives produced without explicit directory entries (e.g.
        // `echo -e "bin/echo" | cpio …`) still need `lookup("bin")` to
        // return something with FileType::Dir so `resolve_async` can descend
        // into the directory for paths like `/bin/echo`.
        let any_child = self.entries().iter().any(|e| {
            let canon = canonicalize_cpio_name(e.name);
            canon
                .strip_prefix(name)
                .and_then(|r| r.strip_prefix('/'))
                .is_some()
        });
        if any_child {
            // Mode 0o040755 = drwxr-xr-x (directory)
            return Some(Arc::new(InitramfsFile {
                data: &[],
                mode: 0o040_755,
                mtime: 0,
            }));
        }
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        // A subdir exists if at least one entry's canonical name
        // starts with `name/` or is exactly `name` (an explicit
        // CPIO dir entry).
        let any_match = self.entries().iter().any(|e| {
            let canon = canonicalize_cpio_name(e.name);
            canon == name
                || canon
                    .strip_prefix(name)
                    .and_then(|r| r.strip_prefix('/'))
                    .is_some()
        });
        if !any_match {
            return None;
        }
        Some(Arc::new(InitramfsDir {
            entries: self.entries(),
            prefix: String::from(name),
        }))
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Hierarchical iteration needs owned Strings; let
        // `enumerate` do the work.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let all = collect_immediate_children(self.entries(), "");
        all.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

/// File handle into an initramfs entry.
struct InitramfsFile {
    data: &'static [u8],
    mode: u32,
    mtime: u64,
}

impl fmt::Debug for InitramfsFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsFile")
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl FileOps for InitramfsFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let off = offset as usize;
            if off >= self.data.len() {
                return Ok(0); // EOF
            }
            let n = core::cmp::min(buf.len(), self.data.len() - off);
            buf[..n].copy_from_slice(&self.data[off..off + n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.data.len() as u64,
            blocks: (self.data.len() as u64).div_ceil(512),
            mode: Mode {
                file_type: if self.mode & 0o170000 == 0o040000 {
                    FileType::Dir
                } else {
                    FileType::File
                },
                perms: (self.mode & 0o777) as u16,
            },
            mtime_cycles: self.mtime,
        }
    }
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Fs, "devfs-mount", || {
        mount_devfs_default();
        InitResult::Ok
    });
    // POSIX shm: mount an empty memfs at /dev/shm so shm_open just
    // becomes open("/dev/shm/<name>", flags). Sized for typical
    // C++ std::shared_memory + lock-free queue scratch — grows on
    // demand.
    narf_init::register(Stage::Fs, "devshm-mount", || {
        let auth = bootstrap_mount_authority();
        let _ = registry().mount(&auth, "/dev/shm", MemFs::new("shm"));
        // /tmp is also POSIX-required (mkstemp, std::tmpfile).
        let _ = registry().mount(&auth, "/tmp", MemFs::new("tmp"));
        InitResult::Ok
    });
    // /proc — synthetic per-process and system-wide read-only views.
    // /sys — kobject hierarchy; replaces the old empty MemFs stub with
    //         the real SysFs and pre-populates block/net/kernel subtrees.
    #[cfg(feature = "linux-compat")]
    narf_init::register(Stage::Fs, "procfs-mount", || {
        let auth = bootstrap_mount_authority();
        let _ = registry().mount(&auth, "/proc", procfs::ProcFs);
        let _ = registry().mount(&auth, "/sys", sysfs::SysFs::new());
        sysfs::populate_all();
        // Populate the system-wide `/proc/sys/{fs,kernel,vm}/*` sysctl
        // keys and the `/proc/{stat,vmstat,…}` aggregate views. Without
        // this a reader of e.g. `/proc/sys/fs/file-max` sees ENOENT.
        // (`/proc/sys/net/*` is registered separately by the net crate's
        // cross-crate init, which also installs its snapshot hooks.)
        procfs::sys_fs::register_all();
        procfs::sys_kernel::register_all();
        procfs::sys_vm::register_all();
        procfs::aggregate::register_all();
        procfs::stubs::register_all();
        procfs::bus::register_bus_proc();
        InitResult::Ok
    });

    // /sys/fs/cgroup — cgroup-v2 unified hierarchy. Mounted as an
    // independent prefix; `resolve_absolute` longest-prefix matching
    // routes /sys/fs/cgroup/* here and other /sys/* to sysfs, so this
    // does not require sysfs (linux-compat) to be present.
    #[cfg(feature = "cgroup")]
    narf_init::register(Stage::Fs, "cgroupfs-mount", || {
        cgroupfs::register_builtin_controllers();
        let auth = bootstrap_mount_authority();
        let _ = registry().mount(&auth, "/sys/fs/cgroup", cgroupfs::CgroupFs::new());
        InitResult::Ok
    });

    // /proc/pressure/{cpu,memory,io} — system-wide PSI. Needs procfs
    // (linux-compat) to register.
    #[cfg(all(feature = "cgroup-psi", feature = "linux-compat"))]
    narf_init::register(Stage::Fs, "proc-pressure", || {
        use cgroupfs::psi::Resource;
        procfs::register_proc(
            "pressure/cpu",
            alloc::sync::Arc::new(PressureFile(Resource::Cpu)),
        );
        procfs::register_proc(
            "pressure/memory",
            alloc::sync::Arc::new(PressureFile(Resource::Memory)),
        );
        procfs::register_proc(
            "pressure/io",
            alloc::sync::Arc::new(PressureFile(Resource::Io)),
        );
        InitResult::Ok
    });
}

/// `/proc/pressure/<axis>` backing — system-wide PSI, delegating to the
/// cgroup PSI renderer.
#[cfg(all(feature = "cgroup-psi", feature = "linux-compat"))]
#[derive(Debug)]
struct PressureFile(cgroupfs::psi::Resource);

#[cfg(all(feature = "cgroup-psi", feature = "linux-compat"))]
impl procfs::ProcFile for PressureFile {
    fn read(&self) -> alloc::vec::Vec<u8> {
        cgroupfs::psi::proc_pressure(self.0)
    }
}

/// Stage 3 placeholder for a virtiofs mount. Stage 4 wires the DAX
/// shared-region protocol (FUSE-over-virtio plus a host-shared
/// memory window mapped through `io/`'s coherent allocator) — at that
/// point this struct grows real fields (FUSE session id, DAX window
/// caps, queue refs) and the `unimplemented!()` ops below get real
/// bodies.
///
/// Kept in-tree at Stage 3 so the registry's `mount` API can already
/// take a virtiofs FS without churning when Stage 4 lands.
#[derive(Debug)]
pub struct VirtiofsMount {
    name: &'static str,
}

impl VirtiofsMount {
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl FsInstance for VirtiofsMount {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(VirtiofsRoot)
    }
    fn name(&self) -> &str {
        self.name
    }
}

#[derive(Debug)]
struct VirtiofsRoot;

// Stage-3 placeholder. The FUSE/DAX transport that backs virtiofs is
// Stage-4 work; until then the root looks like an empty, read-only
// directory rather than panicking on access. The `*_async` variants
// inherit the trait default of `FsError::Unsupported`, which is the
// correct shape for a callable-but-unbacked filesystem.
impl DirOps for VirtiofsRoot {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }
}
