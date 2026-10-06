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
//! - `FsError`: `NotFound`, `PermissionDenied`, `OperationNotPermitted`,
//!   `Io(BlockError)`, `InvalidPath`, `Busy`, `ReadOnly`, `Unsupported`. `From<CapError>`
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
//! - Linux-shaped two-mode pathname walking: mount routing and warmed dentry
//!   lookup use QSBR-published immutable snapshots; cache miss, symlink,
//!   mutation, or a blocking filesystem falls back to reference walk.
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
//! - virtiofs DAX protocol — only the skeleton ships now.
//! - Permission checking beyond the cap-gate stub at `mount` time.
//! - mmap, quotas, xattrs, rename, link, mkdir, unlink — Stage 4+.
//! - `block/`-backed loaders. The initramfs sits above `block/`'s API
//!   surface but does not consume it; the byte slice comes from the
//!   bootloader's initramfs region (Stage 4 hands that in).

#![no_std]
#![feature(allocator_api)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bpffs;
#[cfg(feature = "cgroup")]
pub mod cgroupfs;
pub mod console_tty;
pub mod csprng;
pub mod debugfs;
pub mod devfs;
pub mod devfs_block;
pub mod devfs_input;
pub mod devfs_misc;
pub mod devfs_pty;
pub mod devfs_rtc;
pub(crate) mod devfs_vt;
pub mod efivarfs;
pub mod fifo;
pub mod fs_registry;
pub mod fuse;
pub mod fuse_conn;
pub mod inode_id;
pub mod memfs;
pub mod mqueuefs;
pub mod ntty;
pub mod overlayfs;
pub mod page_cache;
mod pathwalk;
/// Shared page-buffer storage for Linux anonymous pipes and named FIFOs.
pub mod pipe_buffer;
/// Sleepable pipe ownership and lockless readiness snapshots.
pub mod pipe_queue;
pub mod posix_acl;
pub mod procfs;
pub mod root_mount;
pub mod root_selector;
pub mod sysfs;
pub mod uevent;
pub mod vt;

mod cgroupfs_tests;
mod debugfs_tests;
mod devfs_block_tests;
mod devfs_pty_tests;
mod e2e_tests;
mod fs_mount_e2e_tests;
mod memfs_tests;
mod mqueuefs_tests;
mod page_cache_tests;
mod posix_acl_tests;
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
pub use efivarfs::EfivarFs;
pub use fs_registry::{
    lookup_fstype, register_block_fstype, register_fs_type, register_fstype, registered_fstypes,
    FileSystemType, FsBuilder, FsInit, MountRequest,
};
pub use fuse::{
    FuseInHeader, FuseInitFlag, FuseInitIn, FuseInitOut, FuseOpcode, FuseOutHeader,
    FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION,
};
pub use memfs::{
    new_anon_file as new_anon_memfile, new_file_with_perms_owner as new_memfile_with_perms_owner,
    MemFs, RamFs, RamFsOptions, TmpFs, TmpFsOptions,
};
pub use mqueuefs::{MqueueAttr, MqueueError, MqueueFs, MqueueNotification, MqueueOpenOptions};
pub use overlayfs::{OverlayFs, OPAQUE_MARKER, WHITEOUT_PREFIX};
pub use page_cache::{
    BlockMapping, CacheFolio, FileFolio, FileMapping, Filled, FolioRef, FolioSlice, PageCache,
    PageKey, PAGE_SIZE,
};
pub use pathwalk::{begin_path_mutation, Dentry, PathMutationGuard};
pub use posix_acl::{
    posix_acl_create, posix_acl_permission, posix_acl_update_mode, AclCreate, AclDecision,
    AclEntry, AclType, PosixAcl, ACL_EXECUTE, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
    ACL_READ, ACL_USER, ACL_USER_OBJ, ACL_WRITE, XATTR_NAME_POSIX_ACL_ACCESS,
    XATTR_NAME_POSIX_ACL_DEFAULT,
};
pub use sysfs::{
    class_device_register, class_register, get_or_create_child, get_root,
    install_net_snapshot_hook, kobject_add_attr, kobject_add_bin_attr, kobject_add_uevent_attr,
    kobject_add_writable_attr, kobject_emit_uevent, sysfs_root, AttrShow, AttrStore, BinAttrRead,
    Kobject, NetDuplex, NetIfaceInfo, NetIfaceStats, NetPciParent, SysFs, SysKobjDir,
};
pub use uevent::{
    current_seqnum as uevent_current_seqnum, emit as emit_uevent,
    emit_with_extras as emit_uevent_extras, UeventAction, UeventEnv, UeventReader,
};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use narf_block::BlockError;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_rcu::{Atomic as RcuAtomic, Owned as RcuOwned};

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

/// `FS_IMMUTABLE_FL` (`include/uapi/linux/fs.h`) — "Immutable file".
///
/// The VFS refuses every write to such an inode, including by root:
/// `inode_permission` has "Nobody gets write access to an immutable file",
/// and the checks are spread across `may_delete`, `may_setattr`,
/// `may_write_xattr` and `vfs_link` besides. `chattr +i /etc/resolv.conf`
/// is the canonical use.
pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;

/// `FS_APPEND_FL` — "writes to file may only append".
///
/// Weaker than immutable: the data can grow but never be rewritten,
/// truncated, unlinked or re-permissioned. `may_open` enforces the open
/// half (`O_APPEND` required, `O_TRUNC` refused).
pub const FS_APPEND_FL: u32 = 0x0000_0020;

/// The flags a caller may not change without `CAP_LINUX_IMMUTABLE`
/// (`fs/file_attr.c::fileattr_set_prepare`).
pub const FS_PRIVILEGED_FL: u32 = FS_IMMUTABLE_FL | FS_APPEND_FL;

/// Inode attributes Linux reports in `struct stat` that [`Stat`] does not
/// carry.
///
/// They live in a separate struct rather than in `Stat` because `Stat` is
/// constructed as a literal in hundreds of places across every filesystem
/// and synthetic node in the tree; a filesystem that does not model these
/// keeps the `Default`, and the stat path falls back to exactly the values
/// it used before this existed.
///
/// Every field uses 0 for "this filesystem does not track it", which is
/// never a legal value for any of them: an inode that exists has at least
/// one link, a mounted filesystem has a nonzero anonymous device, and a
/// timestamp of 0 is the epoch (`shmem_get_inode` stamps
/// `inode_set_ctime_current`, so a real tmpfs inode is never at 0).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InodeAttrs {
    /// `st_nlink`. An `O_TMPFILE` inode legitimately reports 0 — Linux
    /// creates it with `inode->i_nlink == 0` and `linkat` is what raises
    /// it — so this is reported whenever the filesystem tracks links at
    /// all, which [`InodeAttrs::tracked`] records.
    pub nlink: u32,
    /// `st_dev` — the filesystem's anonymous device number
    /// (`get_anon_bdev`). Distinguishing mounts is what makes `rename`
    /// across them EXDEV, `find -xdev` prune, and `du -x` stop.
    pub dev: u64,
    /// `st_atim` in wall-clock nanoseconds since the epoch.
    pub atime_ns: u64,
    /// `st_ctim` in wall-clock nanoseconds since the epoch. Distinct from
    /// mtime: a `chmod` moves ctime and leaves mtime alone.
    pub ctime_ns: u64,
    /// `st_mtim` in wall-clock nanoseconds since the epoch, exactly as the
    /// filesystem stores it. When non-zero it takes precedence over
    /// [`Stat::mtime_cycles`], whose ns→cycles→ns round trip is not exact:
    /// an on-disk whole second came back a few nanoseconds short, and
    /// fontconfig's cache check compares `st_mtim` to the nanosecond.
    pub mtime_ns: u64,
    /// Whether this filesystem fills the struct at all. Without it a real
    /// `nlink` of 0 (an unlinked `O_TMPFILE` inode) is indistinguishable
    /// from "not tracked".
    pub tracked: bool,
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

/// Hook used to emit an inotify `IN_MODIFY` for a kernel-side content
/// change, registered by `userspace` at init.
///
/// `filesystem` cannot call into `userspace` (that is the dependency
/// direction), but some files change without any userspace write to hang
/// a notification off. `cgroup.events` is the load-bearing case: it flips
/// when a task enters or leaves a cgroup, and systemd watches it with
/// `inotify_add_watch(..., IN_MODIFY)` to learn a service's cgroup has
/// settled. With no event, `Type=forking` start jobs never complete.
static MODIFY_NOTIFIER: IrqSafeSpinLock<Option<fn(&str)>> = IrqSafeSpinLock::new(None);

/// Register the inotify-modify emitter. Called once from `userspace` init.
pub fn set_modify_notifier(f: fn(&str)) {
    *MODIFY_NOTIFIER.lock() = Some(f);
}

/// Emit `IN_MODIFY` for `abs_path` if a notifier is registered.
///
/// The guard is dropped before the call: the notifier reaches into the
/// inotify tables and must not run under this lock.
pub fn notify_modify(abs_path: &str) {
    let f = *MODIFY_NOTIFIER.lock();
    if let Some(f) = f {
        f(abs_path);
    }
}

/// Test-only: observe whether a notifier is installed.
#[doc(hidden)]
pub fn __modify_notifier_installed() -> bool {
    MODIFY_NOTIFIER.lock().is_some()
}

/// A file's ownership triplet for a POSIX access check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileOwner {
    pub uid: u32,
    pub gid: u32,
    /// Low 9 bits: rwxrwxrwx.
    pub perms: u16,
    /// Whether the inode is a DIRECTORY. Linux's override rules differ by
    /// type and the difference is not cosmetic: on a directory
    /// CAP_DAC_READ_SEARCH grants search, while on a regular file
    /// CAP_DAC_OVERRIDE cannot grant EXECUTE unless some execute bit is
    /// already set — so a privileged process still cannot run a data file.
    pub is_dir: bool,
}

/// The accessing process's identity for a POSIX access check.
///
/// `groups` is the supplementary group list, i.e. what `setgroups(2)`
/// installed. It is NOT optional decoration: Linux's group triplet test is
/// `in_group_p(i_gid)`, which matches the fsgid **or any supplementary
/// group**, and leaving it out silently demotes a process to the "other"
/// triplet for every file owned by a group it only holds supplementarily.
///
/// That is not hypothetical — it is what kept KDE off the screen. `narf` is
/// in `video` (gid 39) via /etc/group, but its primary gid is 1000, so
/// `/dev/dri/card0` (crw-rw---- root:video) fell through to other=`---` and
/// kwin's open failed with EACCES, reporting only "Failed to open drm device"
/// before taking the whole session down.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Accessor {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups from `setgroups(2)`. Empty is legal.
    pub groups: alloc::vec::Vec<u32>,
    /// CAP_DAC_OVERRIDE in the accessor's EFFECTIVE set.
    ///
    /// The privilege decision is made by the caller and carried here
    /// because this crate has no capability model — `narf_userspace` owns
    /// the credential. It used to be inferred from `uid == 0`, which was
    /// the only test available before POSIX capabilities were enforceable;
    /// that conflates two things Linux keeps apart, so a uid-0 task that
    /// deliberately dropped CAP_DAC_OVERRIDE stayed omnipotent and a
    /// non-root task granted it stayed locked out.
    pub dac_override: bool,
    /// CAP_DAC_READ_SEARCH in the accessor's EFFECTIVE set. Weaker than
    /// `dac_override`: it grants read and directory search, never write.
    pub dac_read_search: bool,
}

impl Accessor {
    /// An accessor with no supplementary groups.
    /// An accessor with no supplementary groups, whose DAC overrides are
    /// derived from `uid == 0`.
    ///
    /// That derivation is a CONVENIENCE for callers with no capability
    /// context (tests, and filesystems checking their own internal
    /// nodes) — not the production rule. The real path builds an
    /// `Accessor` from the task's effective capability set; see
    /// `narf_userspace`'s `current_accessor`.
    pub fn new(uid: u32, gid: u32) -> Self {
        Accessor {
            uid,
            gid,
            dac_override: uid == 0,
            dac_read_search: uid == 0,
            groups: alloc::vec::Vec::new(),
        }
    }

    /// Linux `in_group_p()`: true if `gid` is the fsgid or any
    /// supplementary group.
    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// The set of access bits being requested (R=4, W=2, X=1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessRequest {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// `fs/namei.c::generic_permission` — the POSIX discretionary check plus
/// the capability overrides that make a privileged process privileged.
///
/// ```text
/// ret = acl_permission_check(idmap, inode, mask);
/// if (ret != -EACCES) return ret;
/// if (S_ISDIR(inode->i_mode)) {
///         if (!(mask & MAY_WRITE) && capable(CAP_DAC_READ_SEARCH)) return 0;
///         if (capable(CAP_DAC_OVERRIDE))                           return 0;
///         return -EACCES;
/// }
/// mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
/// if (mask == MAY_READ && capable(CAP_DAC_READ_SEARCH))            return 0;
/// if ((!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO)) &&
///     capable(CAP_DAC_OVERRIDE))                                   return 0;
/// return -EACCES;
/// ```
///
/// and `acl_permission_check`:
///
/// ```text
/// if (!((mask & 7) * 0111 & ~mode)) {      /* everybody may */
///         if (no_acl_inode(inode))  return 0;
///         if (!IS_POSIXACL(inode))  return 0;
/// }
/// if (vfsuid_eq_kuid(vfsuid, current_fsuid())) {
///         mask &= 7; mode >>= 6;
///         return (mask & ~mode) ? -EACCES : 0;     /* owner is EXCLUSIVE */
/// }
/// if (IS_POSIXACL(inode) && (mode & S_IRWXG)) {
///         int error = check_acl(idmap, inode, mask);
///         if (error != -EAGAIN) return error;
/// }
/// mask &= 7;
/// if (mask & (mode ^ (mode >> 3)))
///         if (vfsgid_in_group_p(vfsgid)) mode >>= 3;
/// return (mask & ~mode) ? -EACCES : 0;
/// ```
///
/// Three details are easy to get wrong and all are load-bearing:
///
///   * the owner triplet is EXCLUSIVE. An owner whose user bits deny the
///     access is refused even when the group or other bits would allow it
///     — `chmod 044 file` locks its own owner out. A "most permissive
///     wins" reading silently grants what Linux refuses.
///   * the owner test comes BEFORE the ACL, so a named `ACL_USER` entry
///     for the owner is dead weight: the mode's user triplet decides.
///   * the previous implementation short-circuited on `accessor.uid == 0`
///     before looking at anything else. That was the only privilege test
///     available before capabilities were enforceable; it is now wrong in
///     both directions, and the fix is that the caller supplies the
///     capability decision in [`Accessor`].
///
/// This entry point passes no ACL, which is the `IS_POSIXACL(inode) ==
/// false` case. Callers that can produce the inode's
/// `system.posix_acl_access` — see [`acl_of_file`] — should use
/// [`posix_access_ok_with_acl`] instead.
pub fn posix_access_ok(file: FileOwner, accessor: &Accessor, want: AccessRequest) -> bool {
    posix_access_ok_with_acl(file, accessor, want, None)
}

/// [`posix_access_ok`], with the inode's ACCESS ACL supplied.
///
/// `acl == None` is Linux's `!IS_POSIXACL(inode)` — identical to
/// [`posix_access_ok`]. `acl == Some(..)` enables the
/// `fs/namei.c::check_acl` branch that `posix_access_ok` alone cannot
/// reach.
pub fn posix_access_ok_with_acl(
    file: FileOwner,
    accessor: &Accessor,
    want: AccessRequest,
    acl: Option<&PosixAcl>,
) -> bool {
    let mut mask = 0u32;
    if want.read {
        mask |= 0o4;
    }
    if want.write {
        mask |= 0o2;
    }
    if want.exec {
        mask |= 0o1;
    }
    match acl_permission_check(file, accessor, mask, acl) {
        AclDecision::Granted => return true,
        // `generic_permission` does `if (ret != -EACCES) return ret;`, so a
        // corrupt ACL (-EIO) is NOT overridable by CAP_DAC_OVERRIDE.
        AclDecision::Malformed => return false,
        AclDecision::Denied => {}
    }
    if file.is_dir {
        // DACs are overridable for directories.
        if mask & 0o2 == 0 && accessor.dac_read_search {
            return true;
        }
        return accessor.dac_override;
    }
    // Read alone is overridable by the weaker capability.
    if mask == 0o4 && accessor.dac_read_search {
        return true;
    }
    // Read/write are always overridable; EXECUTE only when the file
    // already carries at least one execute bit.
    if (mask & 0o1 == 0 || file.perms & 0o111 != 0) && accessor.dac_override {
        return true;
    }
    false
}

/// `fs/namei.c::acl_permission_check` — the discretionary half: the
/// owner/group/other triplet algebra plus the POSIX-ACL branch, with no
/// capability involvement.
fn acl_permission_check(
    file: FileOwner,
    accessor: &Accessor,
    mask: u32,
    acl: Option<&PosixAcl>,
) -> AclDecision {
    let mode = u32::from(file.perms & 0o777);
    // Cheap path: every class already carries the requested bits, so no
    // owner or group comparison is needed — but ONLY when there is no ACL
    // to narrow them. Linux guards this with `no_acl_inode(inode)` before
    // `IS_POSIXACL(inode)`; `acl == None` covers both.
    if ((mask & 7) * 0o111) & !mode == 0 && acl.is_none() {
        return AclDecision::Granted;
    }
    // Owner match is exclusive — see the note above.
    if accessor.uid == file.uid {
        let owner = mode >> 6;
        return if (mask & 7) & !owner == 0 {
            AclDecision::Granted
        } else {
            AclDecision::Denied
        };
    }
    // `if (IS_POSIXACL(inode) && (mode & S_IRWXG))`. The group-bit guard is
    // not an optimisation to be dropped. The mode's group triplet always
    // mirrors one ACL entry — the ACL_MASK if there is one, and the
    // ACL_GROUP_OBJ otherwise (posix_acl_equiv_mode and
    // __posix_acl_chmod_masq keep exactly that pair in step, and
    // posix_acl_valid forbids named entries without a mask). So
    // `mode & 0o070 == 0` means either every maskable entry is capped to
    // nothing or the sole group entry grants nothing; the remaining
    // ACL_USER_OBJ and ACL_OTHER entries mirror the mode's outer triplets,
    // which the code below already applies.
    if let Some(acl) = acl {
        if mode & 0o070 != 0 {
            // Linux's check_acl returns -EAGAIN only when there is no
            // cached ACL to consult; here there is one, so its verdict is
            // always final.
            return posix_acl_permission(acl, file, accessor, mask);
        }
    }
    let mut mode = mode;
    // Consult group membership only when the group and other bits actually
    // DIFFER in a requested bit (Linux's own optimisation).
    if (mask & 7) & (mode ^ (mode >> 3)) != 0 && accessor.in_group(file.gid) {
        mode >>= 3;
    }
    if (mask & 7) & !mode == 0 {
        AclDecision::Granted
    } else {
        AclDecision::Denied
    }
}

/// Read and decode one of an open file's POSIX ACLs.
///
/// The transport is the xattr the ACL is stored under
/// (`system.posix_acl_access` / `system.posix_acl_default`), which is how
/// the on-disk filesystems keep them: `fs/ext4/acl.c::ext4_get_acl`,
/// `fs/btrfs/acl.c::btrfs_get_acl` and friends all read that name and run
/// the bytes through `fs/posix_acl.c::posix_acl_from_xattr`.
///
/// `Ok(None)` is "this inode has no ACL" — Linux's
/// `get_inode_acl() == NULL` and its `!IS_POSIXACL(inode)`, which the
/// caller must treat as the plain mode-bit check. A filesystem with no
/// xattr support at all lands here too.
///
/// `Err` is a stored value that does NOT decode, and the caller must NOT
/// silently fall back to the mode bits: `fs/namei.c::check_acl` does
/// `if (IS_ERR(acl)) return PTR_ERR(acl)` and both
/// `acl_permission_check` and `generic_permission` pass anything that is
/// not `-EACCES` straight out, so a corrupt on-disk ACL fails the access
/// with the decode errno (`-EINVAL`, or `-EOPNOTSUPP` for an unknown
/// `a_version`) rather than degrading to a weaker check.
///
/// This is a different failure from [`AclDecision::Malformed`], which is
/// an ACL that DECODED but whose entry sequence is corrupt (`-EIO`).
pub async fn acl_of_file(file: &dyn FileOps, ty: AclType) -> Result<Option<PosixAcl>, FsError> {
    match file.get_xattr(ty.xattr_name()).await {
        Ok(raw) => PosixAcl::from_xattr(&raw),
        // No such attribute, or a filesystem with no xattr store: both are
        // "no ACL on this inode".
        Err(FsError::NotFound) | Err(FsError::Unsupported) => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`acl_of_file`] for a DIRECTORY.
///
/// Path resolution hands back `DirOps` for a directory, so the `FileOps`
/// form can never see one — and a directory is exactly where an ACL most
/// often matters, because every create and delete inside it is checked
/// against the directory's permissions.
pub async fn acl_of_dir(dir: &dyn DirOps, ty: AclType) -> Result<Option<PosixAcl>, FsError> {
    // A directory that can say "no ACL here" cheaply saves the whole
    // lookup — see [`DirOps::access_acl_present`].
    if ty == AclType::Access && dir.access_acl_present() == Some(false) {
        return Ok(None);
    }
    match dir.get_xattr(ty.xattr_name()).await {
        Ok(raw) => PosixAcl::from_xattr(&raw),
        Err(FsError::NotFound) | Err(FsError::Unsupported) => Ok(None),
        Err(e) => Err(e),
    }
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
    /// A writable file: readable by all, writable by its owner.
    ///
    /// This is the DEFAULT any writable node should reach for, and it is
    /// 0644 rather than 0666 on purpose. Virtual files are reported
    /// root-owned unless their `FileOps` overrides `owners()`, so a 0666
    /// mode hands the `other` write bit to every task on the system --- and
    /// for anything reachable by path that IS the access decision. Two live
    /// bugs came from this constant being 0666: every writable `/proc/sys`
    /// key, and `/proc/<pid>/comm`, were world-writable.
    ///
    /// Use [`Mode::FILE_RW_ALL`] only where Linux genuinely publishes a
    /// world-writable file.
    pub const FILE_RW: Mode = Mode {
        file_type: FileType::File,
        perms: 0o644,
    };
    /// A genuinely world-writable file, 0666.
    ///
    /// Rare, and it should be justified against Linux at each use. The one
    /// case in NARF is `/proc/<pid>/attr/*`, which Linux declares
    /// `ATTR(LSM, name, 0666)` because the LSM, not the mode, decides who
    /// may write a security label.
    pub const FILE_RW_ALL: Mode = Mode {
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
    /// The operation is forbidden by object state rather than filesystem
    /// access permissions. Maps to Linux `EPERM`; memfd seals use this so a
    /// sealed write is not confused with a read-only filesystem (`EROFS`).
    OperationNotPermitted,
    Io(BlockError),
    InvalidPath,
    /// Resolution gave up after SYMLOOP_MAX symlink hops. Maps to POSIX
    /// `ELOOP` (`fs/namei.c`: `if (unlikely(nd->total_link_count++ >=
    /// MAXSYMLINKS)) return ERR_PTR(-ELOOP);`).
    ///
    /// Distinct from [`FsError::InvalidPath`] on purpose. Both used to come
    /// back as one error, so a symlink cycle was reported as ENOENT — which
    /// tells a caller the path is free to create, when in fact something IS
    /// there and no amount of retrying or re-creating will resolve it. `ln -s
    /// a b; ln -s b a; cat a` is the canonical case, and shells, `find`, and
    /// package installers all branch on ELOOP to stop descending.
    SymlinkLoop,
    /// Operation would cross a filesystem/overlay boundary. Maps to EXDEV.
    CrossDevice,
    Busy,
    ReadOnly,
    NoSpace,
    /// `ENODEV`: no device behind the node, e.g. a `ptmx` with no devpts
    /// mounted at `pts` beside it (`devpts_ptmx_path`).
    NoDevice,
    /// Memory allocation failed, distinct from storage exhaustion (ENOMEM).
    OutOfMemory,
    /// A filesystem quota or qgroup hard limit would be exceeded. Maps to
    /// Linux `EDQUOT`, distinct from exhausted backing storage (`ENOSPC`).
    QuotaExceeded,
    /// A subsystem the operation depends on is not switched on for this
    /// filesystem. Maps to Linux `ENOTCONN`, which btrfs returns from every
    /// qgroup ioctl when quotas are disabled (`fs/btrfs/ioctl.c`:
    /// `if (!btrfs_qgroup_enabled(fs_info)) return -ENOTCONN;`).
    ///
    /// Distinct from [`FsError::NotFound`] on purpose. ENOENT says the object
    /// asked about does not exist, which invites a caller to create it;
    /// ENOTCONN says the machinery that would answer the question is off, and
    /// the fix is to enable it. `btrfs qgroup show` on a filesystem without
    /// quotas relies on telling those apart.
    NotConnected,
    /// No such process or process group — `ESRCH`. Job-control ioctls need
    /// it distinct from `OperationNotPermitted`: `TIOCSPGRP` answers ESRCH
    /// for a process group that does not exist and EPERM for one that
    /// exists in another session (`drivers/tty/tty_jobctrl.c:518-521`).
    NoSuchProcess,
    /// A userspace address supplied to an operation could not be accessed.
    /// Device ioctl bridges use this to preserve Linux's `EFAULT` instead of
    /// collapsing a bad pointer into `EINVAL`.
    BadAddress,
    /// The requested operation is known but unavailable in this
    /// implementation or device configuration. Maps to Linux `ENOSYS`, while
    /// [`FsError::Unsupported`] remains the VFS-level `ENOTTY`/`EOPNOTSUPP`
    /// dispatch signal.
    NotImplemented,
    /// The requested object or one-shot initialization already exists. Maps
    /// to Linux `EEXIST`.
    AlreadyExists,
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
    /// PCM underrun or overrun (EPIPE), without the SIGPIPE side effect of
    /// writing to a pipe or socket whose peer closed.
    StreamXrun,
    /// A suspended PCM stream needs RESUME or PREPARE (ESTRPIPE).
    StreamSuspended,
    /// The operation ran against a descriptor whose open mode forbids it —
    /// reading a write-only pipe end, writing a read-only one. Linux fails
    /// these with `EBADF` from the `f_mode` checks in
    /// `fs/read_write.c::vfs_read` / `vfs_write` (FMODE_READ/FMODE_WRITE),
    /// before the file op is ever called. Maps to `EBADF`.
    BadFd,
    /// Descriptor exists, but its device state forbids the operation
    /// (Linux EBADFD, distinct from EBADF). ALSA uses this for unconfigured,
    /// disconnected, or otherwise incorrectly sequenced PCM operations.
    BadFileState,
    /// Device has no implementation for this addressed facility (ENXIO).
    NoDeviceAddress,
    /// The file is open and healthy but has nothing to give right now — an
    /// eventfd whose counter is 0, an unexpired timerfd, an empty pipe with a
    /// live writer, an empty socket with a live peer.
    ///
    /// This is what Linux's file ops return directly (`-EAGAIN` from
    /// `fs/eventfd.c::eventfd_read`, `fs/pipe.c::pipe_read`, …), and the
    /// syscall layer turns it into `EAGAIN` for an `O_NONBLOCK` caller or a
    /// park for a blocking one.
    ///
    /// It replaces an older NARF convention where a file op signalled
    /// would-block as `Ok(0)` and declared it out-of-band via a
    /// separate opt-in. That split was the bug factory: `Ok(0)`
    /// IS end-of-file for every other file, so any consumer that did not also
    /// consult the opt-in silently converted "nothing yet" into "the fd
    /// closed". A spurious 0 of exactly this shape killed the KDE session bus
    /// through GLib's line-reader, and the opt-in was easy to test in
    /// isolation while nothing proved the syscall layer still honoured it.
    ///
    /// Maps to POSIX `EAGAIN`/`EWOULDBLOCK`.
    WouldBlock,
}

/// Type-erased owner retained for the lifetime of a shared device mapping.
/// Implementations use this for backing whose lifetime is narrower than the
/// open file itself (for example, one GEM resource on a long-lived DRM fd).
pub trait MmapLifetime: Send + Sync {}

impl<T: Send + Sync> MmapLifetime for T {}

/// Frames paired with their owner. Devices with replaceable storage acquire
/// both under one lock, preventing reconfiguration between an ownership
/// lookup and a frame lookup.
pub struct MmapBacking {
    pub frames: Vec<u64>,
    pub lifetime: Option<Arc<dyn MmapLifetime>>,
}

impl core::fmt::Debug for MmapBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmapBacking")
            .field("frames", &self.frames)
            .field("has_lifetime", &self.lifetime.is_some())
            .finish()
    }
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
///
/// Implementations which return `Poll::Pending` must retain the supplied
/// waker (or register it with the lower async primitive they await) and wake
/// it after publishing completion, failure, disconnect, or newly available
/// capacity. A filesystem future must not self-wake merely to request polling.
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FsError>> + Send + 'a>>;

/// Result of an asynchronous filesystem-backed ioctl.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsIoctlReply {
    pub result: i32,
    pub output: Vec<u8>,
}

/// Fault-contained userspace access for device ioctls, including nested
/// pointers. Implemented by the syscall boundary; devices never dereference
/// process addresses. The context is valid only during the calling syscall.
pub trait IoctlContext: Sync {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError>;
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError>;
    fn nonblocking(&self) -> bool;
    /// Resolve a descriptor in the calling process without exposing its table
    /// to a driver. The retained open description also handles dup/fork.
    fn file(&self, _fd: i32) -> Result<Arc<dyn FileOps>, FsError> {
        Err(FsError::BadFd)
    }
    fn process_id(&self) -> u32 {
        0
    }
}

/// Filesystem-native quota inheritance requested while creating a snapshot.
/// The five limit words use Linux qgroup order: flags, max referenced,
/// max exclusive, reserved referenced, reserved exclusive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsQuotaInherit {
    pub flags: u64,
    pub parents: Vec<u64>,
    pub limit: [u64; 5],
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
/// `Clone` but not `Copy`: the name may own its storage. Entries are
/// built once per readdir and consumed, so the copies this used to permit
/// were never load-bearing.
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// The entry's name.
    ///
    /// `Cow` rather than `&'static str`, which is what this was. A
    /// directory whose entries are computed — the procfs pid list,
    /// `/proc/<pid>/fd`, `/proc/<pid>/task` — cannot produce a `'static`
    /// name without leaking one, and that is exactly what every such
    /// directory did: `Box::leak`, once per entry, once per readdir,
    /// never freed.
    ///
    /// Borrowed covers the ~100 sites that name an entry with a literal,
    /// so the common case still allocates nothing; owned covers the
    /// computed ones and is freed with the entry.
    pub name: alloc::borrow::Cow<'static, str>,
    pub file_type: FileType,
}

// ── FileOps / DirOps ───────────────────────────────────────────────

/// Driver-owned completion primitive exposed through a DRM `sync_file`.
///
/// The VFS/syscall layer owns descriptors and poll integration, while the DRM
/// driver owns the hardware completion mechanism. Sharing this object keeps
/// one exact submission attached to the fd even when later EXECBUFFER calls
/// on the same DRM open produce newer fences.
pub trait DrmFence: Send + Sync {
    fn is_signalled(&self) -> bool;
    fn wait(&self, timeout_ms: u64) -> bool;

    /// Driver-private execution context used to elide a self-dependency wait:
    /// work submitted later to the same ordered ring already depends on this
    /// fence. Foreign contexts return a different key (or `None`) and wait.
    fn context(&self) -> Option<u64> {
        None
    }
}

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

    /// Update the low 12 permission/special bits in `Stat::mode`. Default
    /// returns Unsupported; FSes that persist mode bits override.
    fn set_perms<'a>(&'a self, _perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    /// Flush one open-file description's daemon-visible state.
    ///
    /// Implementations that override this hook must also override
    /// [`FileOps::has_flush`] so close can avoid allocating and polling the
    /// default no-op future for ordinary files.
    fn flush<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Whether [`FileOps::flush`] has observable work to perform.
    fn has_flush(&self) -> bool {
        false
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

    /// The inode's `FS_*_FL` flag word — `chattr`'s bits, read by
    /// `FS_IOC_GETFLAGS`.
    ///
    /// `cachestat(2)` — page-cache residency for pages `first..=last`
    /// (indices, not bytes) of this file.
    ///
    /// `None` means this filesystem keeps no page cache of its own, which
    /// the caller reports as all-zero. That is not a fabricated answer: a
    /// file the kernel does not cache genuinely has no cached pages, and a
    /// caller deciding whether to readahead should readahead.
    ///
    /// A filesystem that DOES cache must answer exactly, because the whole
    /// point of the syscall is to let userspace skip work it can prove is
    /// unnecessary — an over-report makes it skip a read it needed.
    fn cachestat_range(&self, _first: u64, _last: u64) -> Option<CacheStat> {
        None
    }

    /// Only [`FS_IMMUTABLE_FL`] and [`FS_APPEND_FL`] carry meaning here;
    /// both are enforced by the VFS rather than by the filesystem, which
    /// is why they live on the inode and are read from the syscall layer.
    /// Default 0 — a filesystem that does not model them has none set.
    fn inode_flags(&self) -> u32 {
        0
    }

    /// Replace the inode's `FS_*_FL` flag word (`FS_IOC_SETFLAGS`).
    ///
    /// `Unsupported` by default, which the ioctl reports as ENOTTY: a
    /// filesystem that cannot store the flags must not pretend the call
    /// worked, because userspace would then believe a file is immutable
    /// when nothing will enforce it.
    fn set_inode_flags(&self, _flags: u32) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    /// Link count, device number and the two timestamps [`Stat`] omits.
    /// Default is "not tracked", which leaves the stat path reporting what
    /// it did before: `st_nlink = 1`, `st_dev = 0`, and mtime standing in
    /// for atime and ctime.
    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs::default()
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

    /// The durable per-descriptor readiness cell backing blocking `poll`/
    /// `epoll` waits, if this file has one.
    ///
    /// `Some` opts the descriptor into the arm/notify wake path
    /// ([`narf_lib::readiness::Readiness`]): a parked waiter registers in the
    /// cell and is woken the instant `set` records a matching readiness edge —
    /// a durable, per-fd, IRQ-safe wake with no reliance on a fallback re-scan,
    /// and it subsumes `poll_readiness` (the cell's level `mask`), the epoll
    /// edge (ready-list membership fed by `set`/`notify`), and
    /// `readiness_notifies` (waking is intrinsic to every `set`). `None` (the
    /// default) keeps the legacy
    /// level-scan + generation-guard path, so descriptors migrate one at a
    /// time. Sockets, pipes, eventfds, mqueues, ttys — anything whose readiness
    /// transitions asynchronously — override this as they migrate; always-ready
    /// files (regular files) never need it.
    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        None
    }

    /// Arm a `poll`/`epoll` waiter (identified by `task_id`) on this file's
    /// durable readiness for `interest`, returning the
    /// [`Poll`](core::task::Poll) result of the register-then-check, or `None`
    /// if the file is still on the legacy path.
    ///
    /// The default delegates to [`Self::readiness`] — correct for a file whose
    /// readiness is one directly-owned cell (eventfd, pipe). A file whose
    /// readiness is COMPOSITE or lives behind a lock overrides this: an AF_UNIX
    /// socket's rx/tx `RingBuf` cells sit inside its state lock, so it locks,
    /// reaches each cell, and `arm`s them under the interest bits each covers.
    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        self.readiness().map(|r| r.arm(task_id, interest, waker))
    }

    /// Arm a blocking-I/O waiter with provider-selected exclusive semantics.
    /// The default preserves ordinary wake-all behavior; providers whose Linux
    /// wait queue is exclusive (notably anonymous pipes) override this so one
    /// consumable event wakes one blocked syscall while poll observers still
    /// all wake through [`Self::arm_readiness`].
    fn arm_readiness_exclusive(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        self.arm_readiness(task_id, interest, waker)
    }

    /// Register a PERSISTENT readiness waiter — the Linux `eppoll_entry` model,
    /// used by epoll to arm a per-fd ready-list waker at `EPOLL_CTL_ADD` that
    /// stays live for the fd's whole membership in the set (never consumed on
    /// readiness). Returns `Some(current_ready_bits)` if the file is on the
    /// durable readiness path (so the caller can seed an initial ready-list
    /// edge), `None` if it has no cell (timerfd / raw netlink / nested epoll —
    /// those fall back to the full-scan + rising-mask path). The default arms the
    /// single directly-owned cell; composite / behind-a-lock files (sockets)
    /// override to reconcile then persistently arm each of their cells.
    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.readiness()
            .map(|r| r.arm_persistent(id, interest, waker))
    }

    /// Remove `task_id`'s registration from this file's durable readiness.
    /// Returns whether the file is on the durable path at all. Default via
    /// [`Self::readiness`]; composite / behind-a-lock files override.
    fn disarm_readiness(&self, task_id: u64) -> bool {
        if let Some(r) = self.readiness() {
            r.disarm(task_id);
            true
        } else {
            false
        }
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

    /// Device ioctl with guarded pointer access and the open description's
    /// current O_NONBLOCK flag. Legacy implementations retain their dispatch.
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        _context: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move { self.ioctl(cmd, arg as usize) })
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

    /// Device-specific mapping checks before any VMA replacement or backing
    /// allocation. `len` is page-rounded; prot/flags are Linux mmap bits.
    fn validate_mmap(
        &self,
        _offset: u64,
        _len: usize,
        _prot: u32,
        _flags: u32,
    ) -> Result<u32, FsError> {
        Ok(_prot)
    }

    /// Maximum PROT_READ/WRITE/EXEC bits for this device offset. The mapping
    /// owner enforces this on later mprotect calls as well as initial mmap.
    fn mmap_max_prot(&self, _offset: u64) -> u32 {
        7
    }

    fn mmap_backing(&self, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        let lifetime = self.mmap_lifetime(offset, len);
        let frames = self.mmap_frames(offset, len)?;
        Ok(MmapBacking { frames, lifetime })
    }

    /// True only when mmap_frames/mmap_fault return ordinary allocator RAM
    /// retired via narf_memory::free_frame. Such backing supports independent
    /// user-page pins; device/PFN mappings must retain the false default.
    fn mmap_is_ram(&self) -> bool {
        false
    }

    /// Whether [`FileOps::mmap_fault`] is a supported backing path.
    ///
    /// This is an explicit capability rather than a speculative call to
    /// `mmap_fault`: a fault outside the current EOF is a valid refusal, not
    /// evidence that the file cannot supply cache folios for other offsets.
    fn supports_mmap_fault(&self) -> bool {
        false
    }

    /// Stable identity of the object whose direct mmap pages this operation
    /// exposes. Wrappers which forward `mmap_fault` and `truncate` to another
    /// file must forward this too, so truncation can find their VMA owners.
    fn mmap_backing_identity(&self) -> usize {
        self as *const Self as *const () as usize
    }

    /// Retain at most max bytes from the file page containing offset.
    /// None is EOF. Unsupported selects copy_splice_read-style buffered I/O.
    /// Providers acquire the physical retain while their backing lock excludes
    /// truncate/replacement, and must never return a fragment larger than max.
    fn splice_read_page(
        &self,
        _offset: u64,
        _max: usize,
    ) -> Result<Option<pipe_buffer::SplicePage>, FsError> {
        Err(FsError::Unsupported)
    }

    /// Optional backing owner paired with [`FileOps::mmap_frames`]. The
    /// syscall layer retains this object across VMA splits and fork, and drops
    /// it only after the last mapping disappears. A device whose frames are
    /// owned by the file itself may keep the default `None`; per-object
    /// backings must return their specific owner so handle close cannot recycle
    /// still-mapped pages.
    fn mmap_lifetime(
        &self,
        _offset: u64,
        _len: usize,
    ) -> Option<alloc::sync::Arc<dyn MmapLifetime>> {
        None
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
    /// The default returns [`FsError::Unsupported`]. Implementations must
    /// also return `true` from [`FileOps::supports_mmap_fault`]; the syscall
    /// layer uses that side-effect-free capability check when creating the
    /// initially unbacked VMA.
    fn mmap_fault(&self, _offset: u64) -> Result<u64, FsError> {
        Err(FsError::Unsupported)
    }

    /// Optional content generation for retaining generic `MAP_SHARED`
    /// fallback pages between mappings. `Some` declares that this file uses
    /// generic fallback mmap rather than `mmap_frames`/`mmap_fault`, and opts
    /// into the bounded cache; implementations must change the value after
    /// every mutation that can alter file bytes or length. The syscall layer
    /// reuses an idle page only when its recorded generation still matches.
    /// Files without such a coherent marker keep the conservative
    /// map-lifetime-only behavior.
    fn mmap_cache_generation(&self) -> Option<u64> {
        None
    }

    /// If this file is a PTY master, return its pty's system-wide id
    /// (`devfs_pty::pty_by_id`). Used by `sys_ioctl(TIOCGPTPEER)` to open a
    /// fresh slave fd without a downcast / Any dance. Default: `None`.
    fn as_pty_master_id(&self) -> Option<u32> {
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

    /// If this fd is a DRM render node (`/dev/dri/renderD1NN`), return the
    /// card index it renders for. Distinct from [`Self::as_drm_card_index`]
    /// (a modeset-capable master node): a render node carries no display
    /// authority but still needs the PRIME ioctls, because Mesa opens the
    /// render node for its GBM/EGL context and imports the compositor's
    /// scanout dma-buf there via `DRM_IOCTL_PRIME_FD_TO_HANDLE`. Default: not
    /// a DRM render node.
    fn as_drm_render_index(&self) -> Option<u32> {
        None
    }

    /// Drain the `OUT_FENCE_PTR` requests produced by this fd's last
    /// `DRM_IOCTL_MODE_ATOMIC` commit: `(user s32* pointer, fence deadline
    /// in CLOCK_MONOTONIC ns)` pairs, one per requesting CRTC. The syscall
    /// layer calls this right after a successful ATOMIC ioctl and mints one
    /// sync_file fd per pair (fd allocation is its domain — the same split
    /// as `VIRTGPU_EXECBUF_FENCE_FD_OUT`); the fence signals at the
    /// commit's simulated vblank. Default: no fences (not a DRM card).
    fn drm_take_out_fences(&self) -> alloc::vec::Vec<(u64, u64)> {
        alloc::vec::Vec::new()
    }

    /// Consume the calling task's fenced EXECBUFFER submission. The syscall
    /// layer calls this right after a successful EXECBUFFER to back the
    /// `VIRTGPU_EXECBUF_FENCE_FD_OUT` sync_file with the exact driver-owned
    /// completion object (falling back to a pre-signalled file on `None`).
    fn drm_execbuf_fence(&self) -> Option<Arc<dyn DrmFence>> {
        None
    }

    /// Ordered execution-context key for an EXECBUFFER ring. Used only by the
    /// syscall layer's FENCE_FD_IN handling; non-DRM files return `None`.
    fn drm_execbuf_context(&self, _ring_idx: u32) -> Option<u64> {
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

    /// Export one DRM GEM handle as a dma-buf-like file. DRM drivers whose
    /// GEM namespace is per-open override this instead of using the legacy
    /// card-global export hook below. Linux routes
    /// `DRM_IOCTL_PRIME_HANDLE_TO_FD` through the calling `drm_file` for the
    /// same reason: an integer handle is meaningful only in that open.
    fn drm_prime_export_file(
        &self,
        _gem_handle: u32,
    ) -> Result<alloc::sync::Arc<dyn FileOps>, FsError> {
        Err(FsError::Unsupported)
    }

    /// Import a PRIME dma-buf file into this DRM open and return its local GEM
    /// handle. The source stays type-erased at the VFS boundary; a driver can
    /// recover its own dma-buf implementation through [`FileOps::as_any`].
    fn drm_prime_import_file(
        &self,
        _dmabuf: &alloc::sync::Arc<dyn FileOps>,
    ) -> Result<u32, FsError> {
        Err(FsError::Unsupported)
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

    /// If this fd is a tty, return the owning session id in the kernel's
    /// stable task-id space (zero when unowned). The Linux-compat syscall
    /// layer translates it into the querying caller's PID namespace.
    fn tty_session(&self) -> Option<u64> {
        None
    }

    /// Replace this tty's foreground process group using a stable task-space
    /// id. Returns false for non-tty objects. Session/ownership validation is
    /// performed by the Linux-compat syscall layer before this mutation.
    fn set_tty_fg_pgrp(&self, _pgrp: u64) -> bool {
        false
    }

    /// Apply Linux `TIOCSCTTY` policy to this PTY endpoint and install the
    /// controlling-terminal state. `readable` is the open-file description's
    /// FMODE_READ equivalent. `Ok(false)` means this object is not a PTY.
    fn tty_acquire_controlling(&self, _arg: usize, _readable: bool) -> Result<bool, FsError> {
        Ok(false)
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

    /// True when a blocking write that made no progress (returned 0) should
    /// PARK the writer rather than hand userspace a spurious 0 — a pipe/FIFO
    /// whose buffer is full and still has an open reader (POSIX: a blocking
    /// write waits for room). Default false (a 0-byte write elsewhere is a
    /// real result, not a would-block).
    fn write_should_block(&self) -> bool {
        false
    }

    /// Pipe buffer capacity in bytes, for `fcntl(F_GETPIPE_SZ/F_SETPIPE_SZ)`.
    /// `None` for a non-pipe fd (`pipe_fcntl` then reports EBADF, matching
    /// Linux even though the descriptor itself is valid).
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

    /// Fallible per-open setup after DAC checks. `write` denotes write access;
    /// O_PATH does not call this hook. Defaults to the existing clone-device
    /// hook. Procfs uses this to capture namespaces and opener credentials.
    fn open_instance_checked(&self, _write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        Ok(self.open_instance())
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

    /// Whether this file can be waited on — Linux's `file_can_poll(f)`,
    /// i.e. `f->f_op->poll != NULL`.
    ///
    /// `do_epoll_ctl` refuses a target without it:
    ///
    /// ```text
    /// if (!file_can_poll(fd_file(tf)))
    ///         return -EPERM;
    /// ```
    ///
    /// which on Linux covers regular files and directories — a poll on those
    /// is always "ready", so registering one is a caller error rather than a
    /// no-op, and `epoll_ctl` says so.
    ///
    /// Defaults to TRUE, deliberately. File TYPE is not a usable proxy for
    /// this: inotify descriptors and the pollable procfs files
    /// (`/proc/self/mountinfo`, whose entire purpose is change notification)
    /// are `FileType::File` here and must stay addable. Defaulting to false
    /// and opting in would silently refuse every backend nobody remembered to
    /// audit, turning a missing override into an EPERM on something that
    /// works. Defaulting to true means a missed override leaves today's
    /// behaviour, and only the backends positively known to be unpollable —
    /// plain on-disk and in-memory file data — say so.
    fn can_poll(&self) -> bool {
        true
    }
}

/// Userspace-owned invalidation hook for shrinking a file which exposes its
/// page-cache folios through [`FileOps::mmap_fault`]. Filesystems call
/// [`unmap_mapping_range`] before removing those folios from their cache, so
/// no borrowed user PTE can outlive the frame it names.
type MmapTruncateHook = fn(&dyn FileOps, u64) -> Result<(), FsError>;

static MMAP_TRUNCATE_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the cross-layer `unmap_mapping_range` bridge. The userspace layer
/// owns VMA metadata and installs this once during common boot initialization.
pub fn install_mmap_truncate_hook(hook: MmapTruncateHook) {
    MMAP_TRUNCATE_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
}

/// Remove every mapped page wholly beyond `new_len` before a filesystem
/// retires the corresponding cache folios. With no userspace layer installed
/// (standalone filesystem tests), there cannot be a live userspace mapping,
/// so the operation is a no-op.
pub fn unmap_mapping_range(file: &dyn FileOps, new_len: u64) -> Result<(), FsError> {
    let raw = MMAP_TRUNCATE_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if raw == 0 {
        return Ok(());
    }
    // SAFETY: the only writer is `install_mmap_truncate_hook`, which stores
    // exactly an `MmapTruncateHook` function pointer.
    let hook: MmapTruncateHook = unsafe { core::mem::transmute(raw) };
    hook(file, new_len)
}

/// [`FileOps::can_poll`] for an inode belonging to a REAL filesystem — one
/// whose files are stored data rather than a synthetic view.
///
/// Linux decides this by which `file_operations` an open installs:
///
///   * `ext4_file_operations`, `btrfs_file_operations`, `fat_file_operations`
///     and `shmem_file_operations` set no `.poll`, and neither does
///     `ext4_dir_operations`. Stored bytes are always "ready", so there is
///     nothing to wait for and `epoll_ctl` says EPERM.
///   * Everything else stored in such a filesystem dispatches AWAY from it on
///     open — a FIFO to `pipefifo_fops`, a device node to the driver's ops, a
///     socket inode to the socket — all of which do have `.poll`. The
///     filesystem the inode lives in is irrelevant to those.
///
/// So the test is on the inode's own type, not on the filesystem. A blanket
/// `false` for a backend that can hold a FIFO — btrfs can, via `mknod` —
/// would refuse an epoll on something Linux polls happily.
///
/// Synthetic filesystems must NOT use this. procfs sets `.poll = proc_reg_poll`
/// on every file it serves, whether or not the file implements one, and kernfs
/// does the same for sysfs and cgroupfs; their files report `FileType::File`
/// and are pollable regardless. They keep the permissive default.
pub fn fs_inode_can_poll(file_type: FileType) -> bool {
    !matches!(file_type, FileType::File | FileType::Dir)
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

    /// Stable identity of this directory inode for dcache alias handling.
    ///
    /// The default is the trait object's data address and is correct when a
    /// filesystem returns the same `Arc<DirOps>` for an inode. A filesystem
    /// that manufactures wrappers on lookup must return `(superblock, inode
    /// namespace, inode)`-equivalent values without locking or blocking. The
    /// namespace is normally zero; filesystems such as btrfs use it to keep
    /// equal inode numbers in different subvolumes distinct. Equal identities
    /// cause mutation invalidation to unhash every dentry alias of that
    /// directory.
    fn dcache_identity(&self) -> (usize, u64, u64) {
        (self as *const Self as *const () as usize, 0, 0)
    }

    /// Whether this directory may be traversed from the VFS RCU dentry cache.
    ///
    /// The default is conservative: reference walk invokes `lookup*` normally.
    /// An immutable directory may return `true` directly. A mutable directory
    /// may return `true` only if every entry-set/name mutation is covered by a
    /// [`PathMutationGuard`] naming the changed dentries from before the first
    /// change until publication is complete. This method itself must be
    /// wait-free and side-effect-free. RCU walk never calls filesystem lookup
    /// methods and automatically falls back when a directory declines, a cache
    /// entry is absent, or a mutation overlaps the walk.
    fn rcu_walkable(&self) -> bool {
        false
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

    /// Set this directory's permission bits asynchronously. Disk-backed
    /// filesystems override this to persist the inode update; the default
    /// preserves the synchronous behaviour of synthetic filesystems.
    fn set_dir_mode_async<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.set_dir_mode(perms);
        Box::pin(async { Ok(()) })
    }

    /// POSIX owner ids for a directory inode. Writable filesystems override
    /// this so mount-root `uid=`/`gid=` and directory chown round-trip through
    /// path stat, fstat on directory fds, and access checks.
    fn dir_owners(&self) -> (u32, u32) {
        (0, 0)
    }

    /// Update a directory inode's POSIX owner ids. Read-only/synthetic
    /// filesystems retain the no-op default.
    fn set_dir_owners(&self, _uid: u32, _gid: u32) {}

    /// Update a directory inode's POSIX owner ids asynchronously.
    /// Disk-backed filesystems override this to persist the inode update.
    fn set_dir_owners_async<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        self.set_dir_owners(uid, gid);
        Box::pin(async { Ok(()) })
    }

    /// Commit directory entries and metadata (`data_only` models
    /// `fdatasync(2)` on an open directory descriptor).
    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Commit all dirty state belonging to this directory's filesystem.
    fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Asynchronous ioctl transport for an open directory descriptor. The
    /// syscall layer derives `input` and `out_size` from Linux `_IOC`; directory
    /// fd wrappers forward the request here exactly as ordinary files use
    /// [`FileOps::ioctl_async`].
    fn ioctl_async<'a>(
        &'a self,
        _cmd: u32,
        _arg: u64,
        _input: &'a [u8],
        _out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    /// Create a filesystem-native snapshot of `source` below this directory.
    ///
    /// The syscall layer resolves the source fd before calling this method, so
    /// filesystem drivers receive a stable directory object rather than a raw
    /// process-local descriptor. Drivers must reject cross-filesystem sources.
    fn snapshot_async<'a>(
        &'a self,
        _source: Arc<dyn DirOps>,
        _name: &'a str,
        _readonly: bool,
    ) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    /// Snapshot variant that attaches the new filesystem quota group to parent
    /// groups and optionally installs hard limits. Filesystems without native
    /// hierarchical quotas reject it without changing the namespace.
    fn snapshot_with_quota_async<'a>(
        &'a self,
        _source: Arc<dyn DirOps>,
        _name: &'a str,
        _readonly: bool,
        _quota: FsQuotaInherit,
    ) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
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

    /// Create an empty file with its final mode and owner.
    ///
    /// Backends that can initialise inode metadata atomically override this;
    /// the default preserves compatibility by applying the metadata after the
    /// ordinary create operation.
    fn create_with_attrs<'a>(
        &'a self,
        name: &'a str,
        perms: u16,
        uid: u32,
        gid: u32,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let file = self.create(name).await?;
            let _ = file.set_owners(uid, gid).await;
            let _ = file.set_perms(perms).await;
            Ok(file)
        })
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

    /// Cheap answer to "does this directory carry a `system.posix_acl_access`
    /// attribute?", or `None` for "ask me properly".
    ///
    /// `may_create`/`may_delete` run on every create and every delete, and
    /// each one needs the directory's ACL. Fetching it through `get_xattr`
    /// builds a boxed future and takes the attribute lock for a directory
    /// that almost never has an ACL, which puts an allocation on the path
    /// of every `unlink`, `mkdir` and `O_CREAT`.
    ///
    /// The default is `None` — "I do not know" — so a filesystem that does
    /// not override this keeps the full lookup and cannot silently lose ACL
    /// enforcement by forgetting to implement a hint.
    fn access_acl_present(&self) -> Option<bool> {
        None
    }

    /// This directory's `system.posix_acl_default`, raw, if it has one.
    ///
    /// Creating anything inside a directory with a default ACL is not a
    /// umask operation: `fs/posix_acl.c::posix_acl_create` replaces the
    /// umask entirely with the inherited ACL, narrows the creation mode
    /// through it, and copies the default itself onto a new
    /// SUBDIRECTORY so inheritance keeps propagating. The umask lives in
    /// the syscall layer, so the decision has to be made there — this is
    /// what lets it ask.
    ///
    /// `None` by default: a filesystem without POSIX ACLs inherits nothing
    /// and the caller applies its umask as before.
    fn default_acl(&self) -> Option<Vec<u8>> {
        None
    }

    /// The directory inode's modification time, in wall-clock nanoseconds
    /// since the epoch; 0 means the filesystem does not track one.
    ///
    /// [`Stat`] carries mtime, but a directory never goes through
    /// `FileOps::stat` — path resolution hands back `DirOps` — so the stat
    /// path synthesised a zero. Every directory therefore looked like the
    /// epoch to `ls -l`, `make` and `rsync`.
    fn dir_mtime_ns(&self) -> u64 {
        0
    }

    /// Link count, device number and timestamps for the DIRECTORY inode —
    /// see [`FileOps::inode_attrs`]. A directory's `st_nlink` is Linux's
    /// `2 + subdirectories` (itself, its `.`, and one `..` per child), and
    /// `find`'s leaf optimisation reads it to decide whether a directory
    /// can contain subdirectories at all.
    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs::default()
    }

    // ── extended attributes ───────────────────────────────────────────
    //
    // A directory is an inode, and on any filesystem with xattr support it
    // holds them: `setfattr` on a directory, an SELinux label on `/tmp`,
    // and `security.*` defaults for children all live here. `FileOps` alone
    // could not express that, because path resolution hands back a
    // `DirOps` for a directory and there is no `FileOps` to ask.
    //
    // Default `Unsupported`, which the syscall layer reads as "this
    // filesystem has no xattr store" and answers from its generic
    // side-table — the behaviour every directory had before.

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

    /// Filesystem-specific mount options, as Linux's
    /// `super_operations::show_options` renders them: a `,`-prefixed list
    /// appended to the mount's flags in `/proc/mounts` and to the super
    /// options field of `/proc/<pid>/mountinfo`.
    ///
    /// Empty by default — a filesystem with no `show_options` (ramfs, and
    /// every synthetic mount here) contributes nothing, which is exactly
    /// what Linux prints for one.
    fn show_options(&self) -> String {
        String::new()
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

    /// Reconfigure a live filesystem from its filesystem-specific option
    /// string (`mount -o remount` / `fsconfig(CMD_RECONFIGURE)`).
    fn reconfigure(&self, _options: &str) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }

    // ── Disk quota (quotactl) ──────────────────────────────────────
    // Filesystems that support per-id disk quotas (tmpfs with usrquota /
    // grpquota) implement these; the rest inherit `Unsupported` (ESRV/ENOSYS
    // shaped as `Unsupported` at the syscall boundary).

    /// `Q_QUOTAON` — begin enforcing `kind` quotas.
    fn quota_on(&self, _kind: QuotaKind) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_QUOTAOFF` — stop enforcing `kind` quotas.
    fn quota_off(&self, _kind: QuotaKind) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_GETQUOTA` — read one id's usage + limits.
    fn quota_get(&self, _kind: QuotaKind, _id: u32) -> Result<FsDqBlk, FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_GETNEXTQUOTA` — read the first id `>= id` that has an entry, with its
    /// usage + limits.
    fn quota_get_next(&self, _kind: QuotaKind, _id: u32) -> Result<(u32, FsDqBlk), FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_SETQUOTA` — set one id's limits/usage (only the fields flagged in
    /// `blk.valid`).
    fn quota_set(&self, _kind: QuotaKind, _id: u32, _blk: &FsDqBlk) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_GETINFO` — read a quota type's grace periods + flags.
    fn quota_get_info(&self, _kind: QuotaKind) -> Result<FsDqInfo, FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_SETINFO` — set a quota type's grace periods + flags.
    fn quota_set_info(&self, _kind: QuotaKind, _info: &FsDqInfo) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
    /// `Q_SYNC` — flush in-core quotas (a no-op for RAM-backed tmpfs).
    fn quota_sync(&self) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
}

/// Which quota a `quotactl` request targets. tmpfs supports user + group
/// (Linux `PRJQUOTA` is not implemented).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuotaKind {
    User,
    Group,
}

/// `QIF_*` field-valid flags (Linux `<linux/quota.h>`) — which fields of an
/// [`FsDqBlk`] a `Q_SETQUOTA` caller actually set, and which a `Q_GETQUOTA`
/// reply fills.
pub const QIF_BLIMITS: u32 = 1;
pub const QIF_SPACE: u32 = 2;
pub const QIF_ILIMITS: u32 = 4;
pub const QIF_INODES: u32 = 8;
pub const QIF_BTIME: u32 = 16;
pub const QIF_ITIME: u32 = 32;
pub const QIF_USAGE: u32 = QIF_SPACE | QIF_INODES;
pub const QIF_TIMES: u32 = QIF_BTIME | QIF_ITIME;
pub const QIF_ALL: u32 = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;

/// `IIF_*` field-valid flags for [`FsDqInfo`] on `Q_SETINFO`.
pub const IIF_BGRACE: u32 = 1;
pub const IIF_IGRACE: u32 = 2;
pub const IIF_FLAGS: u32 = 4;
pub const IIF_ALL: u32 = IIF_BGRACE | IIF_IGRACE | IIF_FLAGS;

/// One id's disk-quota state, in the filesystem's natural units: block limits
/// and usage are in **fs blocks** (4 KiB) and inode counts are absolute; the
/// `quotactl` syscall converts to/from Linux's 1-KiB quota-block ABI. `btime`/
/// `itime` are soft-limit grace deadlines in wall-clock seconds. `valid` is a
/// `QIF_*` mask.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FsDqBlk {
    pub blocks_hard: u64,
    pub blocks_soft: u64,
    pub blocks_used: u64,
    pub inodes_hard: u64,
    pub inodes_soft: u64,
    pub inodes_used: u64,
    pub btime: u64,
    pub itime: u64,
    pub valid: u32,
}

/// A quota type's grace periods + flags (Linux `struct if_dqinfo`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FsDqInfo {
    /// Block-limit grace period, seconds.
    pub bgrace: u64,
    /// Inode-limit grace period, seconds.
    pub igrace: u64,
    pub flags: u32,
    pub valid: u32,
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
    resolve_dentry(pathwalk::Dentry::detached_root(root), path)
}

/// Resolve relative to an existing VFS dentry root.
///
/// Mount-aware callers use this form so repeated walks share Linux-style
/// dentry identity instead of constructing a new root name object.
pub fn resolve_dentry(root: Arc<Dentry>, path: &str) -> Result<Arc<dyn FileOps>, FsError> {
    if path.is_empty() {
        return Err(FsError::InvalidPath);
    }
    if path.as_bytes()[0] == b'/' {
        return Err(FsError::InvalidPath);
    }

    if let Some(result) = resolve_cached_dentry(root.clone(), path) {
        return result;
    }

    let mut current = root;
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
            let current_dir = current.directory().ok_or(FsError::NotFound)?;
            let token = pathwalk::lookup_token(&current, prev);
            match current_dir.lookup_dir(prev) {
                Some(d) => {
                    current = token
                        .and_then(|token| {
                            pathwalk::cache_directory(&current, prev, token, d.clone())
                        })
                        .unwrap_or_else(|| pathwalk::reference_directory(&current, prev, d));
                }
                None => {
                    if let Some(token) = token {
                        if let Some(file) = current_dir.lookup(prev) {
                            let file_type = file.stat().mode.file_type;
                            let _ = pathwalk::cache_file(&current, prev, token, file, file_type);
                        } else {
                            pathwalk::cache_negative(&current, prev, token);
                        }
                    }
                    return Err(FsError::NotFound);
                }
            }
        }
        last_component = Some(segment);
    }

    let leaf = last_component.ok_or(FsError::InvalidPath)?;
    let current_dir = current.directory().ok_or(FsError::NotFound)?;
    let token = pathwalk::lookup_token(&current, leaf);
    let Some(file) = current_dir.lookup(leaf) else {
        if let Some(token) = token {
            if let Some(directory) = current_dir.lookup_dir(leaf) {
                let _ = pathwalk::cache_directory(&current, leaf, token, directory);
            } else {
                pathwalk::cache_negative(&current, leaf, token);
            }
        }
        return Err(FsError::NotFound);
    };
    if let Some(token) = token {
        let file_type = file.stat().mode.file_type;
        let _ = pathwalk::cache_file(&current, leaf, token, file.clone(), file_type);
    }
    Ok(file)
}

/// Attempt a complete lookup from warmed RCU dentries only.
///
/// `None` requests reference walk; it is not a lookup error. Symlinks,
/// uncached components, overlapping mutation, and non-participating
/// filesystems all return `None`. A returned `Result` is final for the sampled
/// namespace state and owns every node reference it exposes.
pub fn resolve_cached(
    root: Arc<dyn DirOps>,
    path: &str,
) -> Option<Result<Arc<dyn FileOps>, FsError>> {
    resolve_cached_dentry(pathwalk::Dentry::detached_root(root), path)
}

/// Dentry-root form of [`resolve_cached`], used by mount-aware path walkers.
pub fn resolve_cached_dentry(
    root: Arc<Dentry>,
    path: &str,
) -> Option<Result<Arc<dyn FileOps>, FsError>> {
    pathwalk::map_fast_file(pathwalk::resolve_file(root, path))
}

/// Resolve a directory-only relative walk. RCU cache hits call no filesystem
/// method; a miss performs the ordinary reference walk and warms each dentry.
fn resolve_directory_dentry(root: Arc<Dentry>, path: &str) -> Option<Arc<Dentry>> {
    match pathwalk::resolve_directory(root.clone(), path) {
        pathwalk::FastDirectory::Hit(directory) => return Some(directory),
        pathwalk::FastDirectory::Negative => return None,
        pathwalk::FastDirectory::Retry => {}
    }
    let mut current = root;
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return None;
        }
        let directory = current.directory()?;
        let token = pathwalk::lookup_token(&current, component);
        let Some(next) = directory.lookup_dir(component) else {
            if let Some(token) = token {
                if let Some(file) = directory.lookup(component) {
                    let file_type = file.stat().mode.file_type;
                    let _ = pathwalk::cache_file(&current, component, token, file, file_type);
                } else {
                    pathwalk::cache_negative(&current, component, token);
                }
            }
            return None;
        };
        current = token
            .and_then(|token| pathwalk::cache_directory(&current, component, token, next.clone()))
            .unwrap_or_else(|| pathwalk::reference_directory(&current, component, next));
    }
    Some(current)
}

fn resolve_directory_cached(root: Arc<Dentry>, path: &str) -> Option<Arc<dyn DirOps>> {
    resolve_directory_dentry(root, path)?.directory()
}

/// Resolve a directory path through the dentry/reference-walk state machine.
///
/// This is the directory-only counterpart of [`resolve_async_dentry`]. It is
/// used by create/rename callers so the `DirOps` they eventually mutate comes
/// from the canonical dentry rather than a fresh filesystem wrapper.
pub fn resolve_directory_dentry_async<'a>(
    root: Arc<Dentry>,
    path: &'a str,
) -> FsFuture<'a, Arc<Dentry>> {
    let path = String::from(path);
    Box::pin(async move {
        match pathwalk::resolve_directory(root.clone(), &path) {
            pathwalk::FastDirectory::Hit(directory) => return Ok(directory),
            pathwalk::FastDirectory::Negative => return Err(FsError::NotFound),
            pathwalk::FastDirectory::Retry => {}
        }

        let mut current = root;
        for component in path
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
        {
            if component == ".." {
                return Err(FsError::InvalidPath);
            }
            let directory = current.directory().ok_or(FsError::NotFound)?;
            let token = pathwalk::lookup_token(&current, component);
            let next = match directory.lookup_dir_async(component).await {
                Ok(directory) => directory,
                Err(FsError::Unsupported) => {
                    directory.lookup_dir(component).ok_or(FsError::NotFound)?
                }
                Err(FsError::NotFound) => {
                    // A miss from the directory-shaped hook does not prove
                    // the name absent: it may be a regular file. Preserve
                    // that positive dentry so failure classification can
                    // distinguish ENOTDIR from ENOENT. This is the mirror of
                    // the file resolver's final-directory handling below.
                    let file = match directory.lookup_async(component).await {
                        Ok(file) => Some(file),
                        Err(FsError::Unsupported) => directory.lookup(component),
                        Err(FsError::NotFound) => None,
                        Err(error) => return Err(error),
                    };
                    if let Some(file) = file {
                        if let Some(token) = token {
                            let file_type = file.stat_async().await?.mode.file_type;
                            let _ =
                                pathwalk::cache_file(&current, component, token, file, file_type);
                        }
                    } else if let Some(token) = token {
                        pathwalk::cache_negative(&current, component, token);
                    }
                    return Err(FsError::NotFound);
                }
                Err(error) => return Err(error),
            };
            current = token
                .and_then(|token| {
                    pathwalk::cache_directory(&current, component, token, next.clone())
                })
                .unwrap_or_else(|| pathwalk::reference_directory(&current, component, next));
        }
        Ok(current)
    })
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
    resolve_async_dentry_ext(pathwalk::Dentry::detached_root(root), path, true)
}

/// Mount-aware form of [`resolve_async`] that preserves dentry identity.
pub fn resolve_async_dentry<'a>(
    root: Arc<Dentry>,
    path: &'a str,
) -> FsFuture<'a, Arc<dyn FileOps>> {
    resolve_async_dentry_ext(root, path, true)
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
    resolve_async_dentry_ext(pathwalk::Dentry::detached_root(root), path, false)
}

/// Dentry-root form of [`resolve_async_nofollow`].
pub fn resolve_async_dentry_nofollow<'a>(
    root: Arc<Dentry>,
    path: &'a str,
) -> FsFuture<'a, Arc<dyn FileOps>> {
    resolve_async_dentry_ext(root, path, false)
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
    resolve_async_dentry_ext(pathwalk::Dentry::detached_root(root), path, follow_final)
}

pub fn resolve_async_dentry_ext<'a>(
    root: Arc<Dentry>,
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

        if let Some(result) = resolve_cached_dentry(root.clone(), &initial) {
            return result;
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
        let mut current = root.clone();
        let mut parent_chain: alloc::vec::Vec<Arc<Dentry>> = alloc::vec::Vec::new();

        while let Some(seg) = remaining.pop_front() {
            if seg == "." {
                continue;
            }
            if seg == ".." {
                // Pop one level; if we're already at the mount-root,
                // .. is a no-op (POSIX root.. == root).
                if let Some(p) = parent_chain.pop() {
                    current = p;
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
            let current_dir = current.directory().ok_or(FsError::NotFound)?;
            let file_token = pathwalk::lookup_token(&current, &seg);
            let f_result = current_dir.lookup_async(&seg).await;
            let f = match f_result {
                Ok(f) => f,
                Err(FsError::NotFound) if !is_final => {
                    let dir_token = pathwalk::lookup_token(&current, &seg);
                    let next = match current_dir.lookup_dir_async(&seg).await {
                        Ok(d) => d,
                        Err(FsError::Unsupported) => match current_dir.lookup_dir(&seg) {
                            Some(directory) => directory,
                            None => {
                                if let Some(token) = file_token {
                                    pathwalk::cache_negative(&current, &seg, token);
                                }
                                return Err(FsError::NotFound);
                            }
                        },
                        Err(FsError::NotFound) => {
                            if let Some(token) = file_token {
                                pathwalk::cache_negative(&current, &seg, token);
                            }
                            return Err(FsError::NotFound);
                        }
                        Err(e) => return Err(e),
                    };
                    let next_dentry = dir_token
                        .and_then(|token| {
                            pathwalk::cache_directory(&current, &seg, token, next.clone())
                        })
                        .unwrap_or_else(|| pathwalk::reference_directory(&current, &seg, next));
                    parent_chain.push(current);
                    current = next_dentry;
                    continue;
                }
                Err(FsError::NotFound) => {
                    // `DirOps` has split file- and directory-shaped lookup
                    // hooks, but the dcache has one Linux-shaped namespace.
                    // A miss from `lookup_async` alone therefore does not
                    // prove a negative dentry: the name may be a directory
                    // reachable through `lookup_dir_async`.  Publish that
                    // positive directory now so a caller's directory
                    // fallback can consume it without repeating the walk.
                    // Only cache Negative after both lookup shapes miss.
                    let directory = match current_dir.lookup_dir_async(&seg).await {
                        Ok(directory) => Some(directory),
                        Err(FsError::Unsupported) => current_dir.lookup_dir(&seg),
                        Err(FsError::NotFound) => None,
                        Err(error) => return Err(error),
                    };
                    if let Some(directory) = directory {
                        if let Some(token) = file_token {
                            let _ = pathwalk::cache_directory(&current, &seg, token, directory);
                        }
                    } else if let Some(token) = file_token {
                        pathwalk::cache_negative(&current, &seg, token);
                    }
                    return Err(FsError::NotFound);
                }
                Err(e) => return Err(e),
            };
            let kind = f.stat_async().await?.mode.file_type;
            if let Some(token) = file_token {
                let _ = pathwalk::cache_file(&current, &seg, token, f.clone(), kind);
            }

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
                    return Err(FsError::SymlinkLoop);
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
                    current = root.clone();
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
            let dir_token = pathwalk::lookup_token(&current, &seg);
            let next = match current_dir.lookup_dir_async(&seg).await {
                Ok(d) => d,
                Err(FsError::Unsupported) => {
                    current_dir.lookup_dir(&seg).ok_or(FsError::NotFound)?
                }
                Err(e) => return Err(e),
            };
            let next_dentry = dir_token
                .and_then(|token| pathwalk::cache_directory(&current, &seg, token, next.clone()))
                .unwrap_or_else(|| pathwalk::reference_directory(&current, &seg, next));
            parent_chain.push(current);
            current = next_dentry;
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
/// Mount-propagation type, the argument to Linux's `do_change_type`
/// (`mount --make-{shared,private,slave,unbindable}`). Exactly one is
/// selected per `mount(2)` call carrying a propagation flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MntPropagation {
    /// `MS_SHARED` — join/keep a peer group; mounts under it propagate to peers.
    Shared,
    /// `MS_PRIVATE` — leave any peer group; no propagation (the default).
    Private,
    /// `MS_SLAVE` — receive propagation from the master peer group but do not
    /// send. LINUX-GAP: NARF has no slave state yet, so this drops the mount to
    /// private (the safe subset) rather than wiring a one-way master link.
    Slave,
    /// `MS_UNBINDABLE` — private and additionally not bind-mountable. LINUX-GAP:
    /// the unbindable restriction is not tracked yet, so this behaves as private.
    Unbindable,
}

pub struct Mount {
    pub path: alloc::string::String,
    pub fs: Arc<dyn FsInstance>,
    /// Canonical root dentry for this attachment. Filesystem `root()` methods
    /// may construct a fresh wrapper on every call; retaining one object here
    /// gives the RCU dentry cache the stable root identity Linux gets from
    /// `vfsmount::mnt_root`.
    root: Arc<Dentry>,
    pub handle: Cap<MountPoint, Write>,
    id: u64,
    /// Per-mount VFS flags — Linux's `mnt_flags`, the `MNT_*` set that
    /// `path_mount` derives from the caller's `MS_*`. An atomic because
    /// `mount -o remount` changes them in place on a live mount.
    flags: core::sync::atomic::AtomicU64,
    /// Mount-propagation peer group — Linux's `struct mount.mnt_group_id`.
    /// `0` means "private" (no propagation, the default). A non-zero value
    /// is a peer-group id: every mount across every namespace that carries
    /// the SAME non-zero group id is a peer, and a mount/unmount under any
    /// one of them propagates to all the others (`MS_SHARED`). Atomic because
    /// `mount --make-shared`/`--make-private` flip it on a live mount.
    group_id: core::sync::atomic::AtomicU64,
}

/// Every `MNT_*` bit that has ever been set on any mount, OR-ed together.
///
/// The enforcement checks run on every write-shaped syscall, and looking
/// up which mount covers a path means walking the mount table under its
/// lock. On a system where no mount carries a restriction — the normal
/// case, and every case until something asks for one — that walk can never
/// change an answer, so this lets the checks return immediately.
///
/// Deliberately STICKY: unmounting the last restricted mount does not
/// clear it. A bit that is set when it need not be only costs a lookup;
/// one that is clear when it should not be would skip a check.
static SEEN_MNT_FLAGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Whether any mount has ever carried a restriction — see
/// [`SEEN_MNT_FLAGS`].
pub fn any_restricted_mounts() -> bool {
    SEEN_MNT_FLAGS.load(core::sync::atomic::Ordering::Relaxed) != 0
}

fn note_mnt_flags(flags: u64) {
    // The atime bits are recorded policy, never checked on a syscall path;
    // every ordinary `mount(2)` carries `relatime`, so letting them through
    // would put the mount-table walk back on every write.
    let flags = flags & mnt_flags::ENFORCED_MASK;
    if flags != 0 {
        SEEN_MNT_FLAGS.fetch_or(flags, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Linux `MNT_*` (`include/linux/mount.h`) — the per-MOUNT half of the
/// flag space, distinct from the per-superblock `SB_*` half.
///
/// These are properties of the attachment, not the filesystem: the same
/// tmpfs bind-mounted twice can be read-write at one path and read-only at
/// the other, which is exactly what systemd's service sandboxing relies on.
pub mod mnt_flags {
    /// `MNT_READONLY` — writes through this mount fail with EROFS.
    pub const READONLY: u64 = 1 << 0;
    /// `MNT_NOSUID` — set-user-ID and set-group-ID bits are ignored on
    /// execute.
    pub const NOSUID: u64 = 1 << 1;
    /// `MNT_NODEV` — device special files cannot be opened.
    pub const NODEV: u64 = 1 << 2;
    /// `MNT_NOEXEC` — nothing on this mount may be executed.
    pub const NOEXEC: u64 = 1 << 3;
    /// `MNT_NOSYMFOLLOW` — a symlink on this mount is never followed.
    ///
    /// `fs/namei.c:2036` checks it in the SAME breath as
    /// `LOOKUP_NO_SYMLINKS`, so a mount carrying it gives every walk the
    /// constraint `openat2`'s `RESOLVE_NO_SYMLINKS` asks for per call:
    /// encountering a symlink is -ELOOP, not a silent traversal.
    pub const NOSYMFOLLOW: u64 = 1 << 4;
    /// `MNT_NOATIME` — reads never update an inode's access time.
    pub const NOATIME: u64 = 1 << 5;
    /// `MNT_NODIRATIME` — reading a directory never updates its access time.
    pub const NODIRATIME: u64 = 1 << 6;
    /// `MNT_RELATIME` — the access time moves only when it is older than the
    /// modify/change time. `path_mount` sets it on every mount that asks for
    /// neither `noatime` nor `strictatime`; a mount carrying none of the three
    /// atime bits is `strictatime`.
    pub const RELATIME: u64 = 1 << 7;
    /// `MNT_ATIME_MASK` — the atime policy, which `path_mount` carries over
    /// unchanged when a remount names no atime flag.
    pub const ATIME_MASK: u64 = NOATIME | NODIRATIME | RELATIME;
    /// The bits a syscall path actually tests. See `note_mnt_flags`.
    pub const ENFORCED_MASK: u64 = READONLY | NOSUID | NODEV | NOEXEC | NOSYMFOLLOW;

    /// Render the set the way `/proc/mounts` does: `rw` or `ro` first,
    /// then each restriction that is on. `show_mountinfo` and `show_vfsmnt`
    /// both print this list, and userspace parses it — systemd compares it
    /// against the options a mount unit asked for.
    pub fn render(flags: u64) -> alloc::string::String {
        let mut out = alloc::string::String::from(if flags & READONLY != 0 { "ro" } else { "rw" });
        // Same order `show_mountinfo` emits them, and `nosymfollow` is in
        // that list — a mount unit that asked for it reads this back.
        // `fs/proc_namespace.c::show_vfsmnt_opts`: nosuid, nodev, noexec,
        // noatime, nodiratime, relatime, nosymfollow.
        for (bit, name) in [
            (NOSUID, ",nosuid"),
            (NODEV, ",nodev"),
            (NOEXEC, ",noexec"),
            (NOATIME, ",noatime"),
            (NODIRATIME, ",nodiratime"),
            (RELATIME, ",relatime"),
            (NOSYMFOLLOW, ",nosymfollow"),
        ] {
            if flags & bit != 0 {
                out.push_str(name);
            }
        }
        out
    }
}

/// Linux `SB_*` (`include/linux/fs.h`) — the per-SUPERBLOCK half of the
/// flag space: properties of the filesystem instance itself, shared by
/// every mount of it.
///
/// `fsconfig(FSCONFIG_SET_FLAG, "ro")` + `FSCONFIG_CMD_RECONFIGURE` (what
/// `mount -o remount,ro` does on util-linux 2.39+) and `mount(2)`'s
/// `MS_REMOUNT|MS_RDONLY` both land here through `reconfigure_super`, and
/// `__mnt_is_readonly` refuses writes through EVERY mount of a read-only
/// superblock, not just the one the caller named.
///
/// NARF's `FsInstance` has no superblock object to hang these on, so they
/// live in a table keyed by the instance's `Arc`. A `Weak` guards the key: a
/// freed instance whose address is reused never inherits its flags.
///
/// LINUX-GAP: a bind mount wraps its source in a new `FsInstance`
/// ([`BindMount`]), so it is a different key here — a read-only remount of
/// the superblock through the original mount does not reach an existing
/// bind of it.
pub mod sb_flags {
    use alloc::sync::{Arc, Weak};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;

    /// `SB_RDONLY`.
    pub const RDONLY: u64 = 1 << 0;
    /// `SB_SYNCHRONOUS`.
    pub const SYNCHRONOUS: u64 = 1 << 4;
    /// `SB_MANDLOCK`.
    pub const MANDLOCK: u64 = 1 << 6;
    /// `SB_DIRSYNC`.
    pub const DIRSYNC: u64 = 1 << 7;
    /// `SB_LAZYTIME`.
    pub const LAZYTIME: u64 = 1 << 25;
    /// `SB_I_VERSION`.
    pub const I_VERSION: u64 = 1 << 23;
    /// `MS_RMT_MASK` (`include/uapi/linux/mount.h`): the superblock flags a
    /// reconfiguration may change. `reconfigure_super` opens with
    /// `if (fc->sb_flags_mask & ~MS_RMT_MASK) return -EINVAL;` — so a
    /// `dirsync` passed to a remount is refused, not ignored.
    pub const RMT_MASK: u64 = RDONLY | SYNCHRONOUS | MANDLOCK | I_VERSION | LAZYTIME;

    type Entry = (Weak<dyn crate::FsInstance>, u64);
    static TABLE: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
    /// Bumped on every change so `/proc/<pid>/mountinfo` pollers see a
    /// superblock `ro`/`rw` flip the same way they see an attach.
    static GENERATION: AtomicU64 = AtomicU64::new(0);

    fn key(fs: &Arc<dyn crate::FsInstance>) -> *const () {
        Arc::as_ptr(fs) as *const ()
    }

    /// The instance's `s_flags` (only the bits above are modelled).
    pub fn of(fs: &Arc<dyn crate::FsInstance>) -> u64 {
        let k = key(fs);
        TABLE
            .lock()
            .iter()
            .find(|(w, _)| w.as_ptr() as *const () == k && w.strong_count() > 0)
            .map_or(0, |(_, flags)| *flags)
    }

    /// `WRITE_ONCE(sb->s_flags, (s_flags & ~mask) | (flags & mask))` — the
    /// last step of `reconfigure_super`.
    pub fn update(fs: &Arc<dyn crate::FsInstance>, flags: u64, mask: u64) {
        let k = key(fs);
        let mut table = TABLE.lock();
        table.retain(|(w, _)| w.strong_count() > 0);
        let next = match table.iter_mut().find(|(w, _)| w.as_ptr() as *const () == k) {
            Some((_, current)) => {
                *current = (*current & !mask) | (flags & mask);
                *current
            }
            None => {
                let value = flags & mask;
                table.push((Arc::downgrade(fs), value));
                value
            }
        };
        drop(table);
        if next & RDONLY != 0 {
            // Engage the write-path checks: `mnt_want_write` has to look.
            super::note_mnt_flags(super::mnt_flags::READONLY);
        }
        GENERATION.fetch_add(1, Ordering::AcqRel);
    }

    /// See [`GENERATION`].
    pub fn generation() -> u64 {
        GENERATION.load(Ordering::Acquire)
    }

    /// The superblock half of a mountinfo row: `rw`/`ro`, then
    /// `show_sb_opts`'s `,sync`, `,dirsync`, `,mand`, `,lazytime`.
    pub fn render(flags: u64) -> alloc::string::String {
        let mut out = alloc::string::String::from(if flags & RDONLY != 0 { "ro" } else { "rw" });
        for (bit, name) in [
            (SYNCHRONOUS, ",sync"),
            (DIRSYNC, ",dirsync"),
            (MANDLOCK, ",mand"),
            (LAZYTIME, ",lazytime"),
        ] {
            if flags & bit != 0 {
                out.push_str(name);
            }
        }
        out
    }

    /// `fs/fs_context.c::vfs_parse_sb_flag` — the generic keys every
    /// filesystem context consumes before the filesystem sees a parameter.
    /// Returns `(set, clear)` for a recognised key.
    pub fn parse_key(key: &str) -> Option<(u64, u64)> {
        Some(match key {
            "dirsync" => (DIRSYNC, 0),
            "lazytime" => (LAZYTIME, 0),
            "mand" => (MANDLOCK, 0),
            "ro" => (RDONLY, 0),
            "sync" => (SYNCHRONOUS, 0),
            "async" => (0, SYNCHRONOUS),
            "nolazytime" => (0, LAZYTIME),
            "nomand" => (0, MANDLOCK),
            "rw" => (0, RDONLY),
            _ => return None,
        })
    }
}

impl Mount {
    /// The flags a syscall path must enforce for this attachment: its own
    /// `MNT_*` set, plus `MNT_READONLY` when its superblock is read-only —
    /// Linux's `__mnt_is_readonly` (`mnt_flags & MNT_READONLY ||
    /// sb_rdonly(mnt->mnt_sb)`).
    pub fn effective_flags(&self) -> u64 {
        let flags = self.flags();
        if sb_flags::of(&self.fs) & sb_flags::RDONLY != 0 {
            flags | mnt_flags::READONLY
        } else {
            flags
        }
    }
}

impl Mount {
    /// This mount's `MNT_*` flags.
    pub fn flags(&self) -> u64 {
        self.flags.load(core::sync::atomic::Ordering::Acquire)
    }

    /// This mount's propagation peer-group id (`0` = private). See the
    /// `group_id` field and [`alloc_mount_group_id`].
    pub fn group_id(&self) -> u64 {
        self.group_id.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Whether this mount is shared (a member of a peer group). Mirrors
    /// Linux `IS_MNT_SHARED` (`fs/pnode.h`), which is exactly `mnt_group_id`
    /// being non-zero after `set_mnt_shared`.
    pub fn is_shared(&self) -> bool {
        self.group_id() != 0
    }

    /// Set (or clear, with `0`) this mount's peer-group id in place — Linux's
    /// `set_mnt_shared` / `change_mnt_propagation` on a live mount.
    pub fn set_group_id(&self, gid: u64) {
        self.group_id
            .store(gid, core::sync::atomic::Ordering::Release);
    }
}

impl fmt::Debug for Mount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mount")
            .field("path", &self.path.as_str())
            .field("fs", &self.fs.name())
            .finish_non_exhaustive()
    }
}

/// One `/proc/<pid>/mountinfo` row: `(id, parent, path, fstype, mount
/// options, super options)`.
///
/// The two option fields are the two halves Linux keeps apart and prints
/// in different columns: `mount options` is this ATTACHMENT's `MNT_*` set
/// (`rw`/`ro` plus `nosuid`/`nodev`/`noexec`), while `super options` is
/// the filesystem's own `show_options` string, already `,`-prefixed.
/// `struct cachestat` (`include/uapi/linux/mman.h`) — what `cachestat(2)`
/// reports for a range of a file.
///
/// ```text
/// struct cachestat {
///         __u64 nr_cache;             /* in the page cache */
///         __u64 nr_dirty;
///         __u64 nr_writeback;
///         __u64 nr_evicted;           /* evicted since the range was last read */
///         __u64 nr_recently_evicted;  /* ...and evicted recently */
/// };
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CacheStat {
    pub nr_cache: u64,
    pub nr_dirty: u64,
    pub nr_writeback: u64,
    pub nr_evicted: u64,
    pub nr_recently_evicted: u64,
}

pub type MountInfoRow = (u64, u64, String, String, String, String, String);

fn mountinfo_rows(mounts: &[Mount]) -> Vec<MountInfoRow> {
    mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| {
            // Mounts normally arrive parent-first, but boot-time discovery can
            // attach a known nested filesystem before its backing root is
            // available (the ESP at /mnt/boot before the distro root at
            // /mnt).  Parentage is a property of the finished mount tree, not
            // attachment order, so consider later ancestors too.  Equal-path
            // overmounts are the exception: their parent is the preceding
            // layer in that stack, never a layer attached above them later.
            let parent = mounts
                .iter()
                .enumerate()
                .filter(|(candidate_index, candidate)| {
                    if *candidate_index == index {
                        return false;
                    }
                    if mount.path == candidate.path {
                        return *candidate_index < index;
                    }
                    candidate.path == "/"
                        || (mount.path.starts_with(candidate.path.as_str())
                            && mount.path.as_bytes().get(candidate.path.len()) == Some(&b'/'))
                })
                .max_by_key(|(candidate_index, candidate)| (candidate.path.len(), *candidate_index))
                .map(|(_, candidate)| candidate.id)
                .unwrap_or(0);
            (
                mount.id,
                parent,
                mount.path.clone(),
                String::from(mount.fs.name()),
                mnt_flags::render(mount.flags()),
                mount.fs.show_options(),
                sb_flags::render(sb_flags::of(&mount.fs)),
            )
        })
        .collect()
}

/// The flags of the mount that covers `abs`, by the same longest-prefix,
/// last-wins rule `single_mount_lookup_resolution` uses — so the answer always
/// describes the mount a path operation on `abs` would actually reach.
fn mount_flags_for(mounts: &[Mount], abs: &str) -> Option<u64> {
    covering_mount(mounts, abs).map(Mount::effective_flags)
}

/// The mount covering `abs` by the longest-prefix + newest-wins rule that all
/// resolution uses. Shared by `mount_flags_for` / `mount_group_id_for`.
fn covering_mount<'a>(mounts: &'a [Mount], abs: &str) -> Option<&'a Mount> {
    let mut best: Option<&Mount> = None;
    for mount in mounts {
        if !mount_covers_path(&mount.path, abs) {
            continue;
        }
        let better = match best {
            None => true,
            // Equal-length paths: the LAST mount wins, as an overmount
            // shadows what it was stacked on.
            Some(current) => mount.path.len() >= current.path.len(),
        };
        if better {
            best = Some(mount);
        }
    }
    best
}

fn mount_group_id_for(mounts: &[Mount], abs: &str) -> Option<u64> {
    covering_mount(mounts, abs).map(|mount| mount.group_id())
}

#[inline]
fn mount_covers_path(mount_path: &str, abs: &str) -> bool {
    abs == mount_path
        || mount_path == "/"
        || (abs.starts_with(mount_path) && abs.as_bytes().get(mount_path.len()) == Some(&b'/'))
}

#[inline]
fn path_is_proper_descendant(path: &str, ancestor: &str) -> bool {
    path.len() > ancestor.len()
        && if ancestor == "/" {
            path.starts_with('/')
        } else {
            path.starts_with(ancestor) && path.as_bytes().get(ancestor.len()) == Some(&b'/')
        }
}

/// Immutable mount-routing state published to pathname readers with QSBR.
///
/// The authoritative [`Mount`] keeps mutable flags, propagation state and the
/// unmount capability. Path walking needs only these three fields. Keeping the
/// read copy this small also makes it impossible for a reader to mutate mount
/// topology without taking [`VfsRegistry::inner`].
#[derive(Clone)]
struct MountLookup {
    path: String,
    fs: Weak<dyn FsInstance>,
    root: Weak<Dentry>,
    id: u64,
}

struct MountLookupTable {
    mounts: Vec<MountLookup>,
}

struct MountResolution {
    fs: Arc<dyn FsInstance>,
    root: Arc<Dentry>,
    rel_start: usize,
    id: u64,
}

impl MountLookupTable {
    fn from_mounts(mounts: &[Mount]) -> Self {
        Self {
            mounts: mounts
                .iter()
                .map(|mount| MountLookup {
                    path: mount.path.clone(),
                    fs: Arc::downgrade(&mount.fs),
                    root: Arc::downgrade(&mount.root),
                    id: mount.id,
                })
                .collect(),
        }
    }
}

fn covering_mount_lookup<'a>(mounts: &'a [MountLookup], abs: &str) -> Option<&'a MountLookup> {
    let mut best: Option<&MountLookup> = None;
    for mount in mounts {
        if mount_covers_path(&mount.path, abs)
            && best.map(|old| old.path.len()).unwrap_or(0) <= mount.path.len()
        {
            best = Some(mount);
        }
    }
    best
}

/// Select the mount covering `abs` only when no deeper mount has `abs` as a
/// proper ancestor. The returned filesystem and relative path can therefore
/// be walked without consulting the mount table between components.
fn single_mount_lookup_resolution(mounts: &[MountLookup], abs: &str) -> Option<MountResolution> {
    if abs.is_empty() || abs.as_bytes()[0] != b'/' {
        return None;
    }
    let mount = covering_mount_lookup(mounts, abs)?;
    let path = if abs == "/" {
        abs
    } else {
        abs.trim_end_matches('/')
    };
    if mounts
        .iter()
        .any(|candidate| path_is_proper_descendant(&candidate.path, path))
    {
        return None;
    }
    let suffix = &abs[mount.path.len()..];
    let rel_start = abs.len() - suffix.strip_prefix('/').unwrap_or(suffix).len();
    Some(MountResolution {
        fs: mount.fs.upgrade()?,
        root: mount.root.upgrade()?,
        rel_start,
        id: mount.id,
    })
}

/// Global VFS mount registry. Writers serialize through the authoritative
/// table and publish an immutable routing snapshot. Pathname readers use QSBR
/// and never acquire the writer's IRQ-safe lock.
#[derive(Debug)]
pub struct VfsRegistry {
    inner: IrqSafeSpinLock<Vec<Mount>>,
    lookup: RcuAtomic<MountLookupTable>,
    mountinfo_generation: core::sync::atomic::AtomicU64,
}

static REGISTRY: VfsRegistry = VfsRegistry {
    inner: IrqSafeSpinLock::new(Vec::new()),
    lookup: RcuAtomic::null(),
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

/// Peer-group ids start at 1 so `0` can mean "private" on every mount — the
/// same convention Linux uses (`mnt_group_id == 0` is "no group").
static NEXT_MOUNT_GROUP_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Allocate a fresh, never-zero mount-propagation peer-group id — Linux's
/// `mnt_alloc_group_id`. `mount --make-shared` on a private mount calls this
/// to mint the group the mount (and its future ns-clones) will share.
pub fn alloc_mount_group_id() -> u64 {
    NEXT_MOUNT_GROUP_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
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

/// Hooks registering and retiring a namespace in the process-global
/// namespace tree, which userspace owns for the same reason it owns the id
/// counter: the tree spans every flavour, and half of them live above this
/// crate.
///
/// A namespace minted before the hooks are installed — boot-time mount
/// namespaces, in practice — is simply absent from the tree. That is the
/// same window in which `alloc_mount_ns_id` answers 0, so such a namespace
/// has no id to key on either; registering it would collapse every one of
/// them onto the same key.
static NS_TREE_ADD_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static NS_TREE_REMOVE_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the namespace-tree hooks (userspace `ns_tree_add`/`ns_tree_remove`).
pub fn install_ns_tree_hooks(
    add: fn(u64, u32, u64, alloc::sync::Weak<dyn NsObject>),
    remove: fn(u64),
) {
    NS_TREE_ADD_HOOK.store(add as usize, core::sync::atomic::Ordering::Release);
    NS_TREE_REMOVE_HOOK.store(remove as usize, core::sync::atomic::Ordering::Release);
}

/// `enum ns_type` bits for the two flavours this crate owns.
pub const NS_TYPE_MNT: u32 = 1 << 17;
pub const NS_TYPE_CGROUP: u32 = 1 << 25;

pub(crate) fn ns_tree_add(
    id: u64,
    ns_type: u32,
    owner_user_ns: u64,
    object: alloc::sync::Weak<dyn NsObject>,
) {
    if id == 0 {
        return;
    }
    let v = NS_TREE_ADD_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        return;
    }
    // SAFETY: v was stored by `install_ns_tree_hooks` as a
    // `fn(u64, u32, u64, Weak<dyn NsObject>)` pointer; non-zero confirms it
    // was installed.
    let f: fn(u64, u32, u64, alloc::sync::Weak<dyn NsObject>) = unsafe {
        core::mem::transmute::<usize, fn(u64, u32, u64, alloc::sync::Weak<dyn NsObject>)>(v)
    };
    f(id, ns_type, owner_user_ns, object);
}

pub(crate) fn ns_tree_remove(id: u64) {
    if id == 0 {
        return;
    }
    let v = NS_TREE_REMOVE_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        return;
    }
    // SAFETY: v was stored by `install_ns_tree_hooks` as a `fn(u64)`
    // pointer; non-zero confirms it was installed.
    let f: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(v) };
    f(id);
}

/// Hook answering "does the process on whose behalf we are running hold this
/// capability?". Installed by userspace, which owns the task table and the
/// capability sets; until then it answers **false** for everything.
///
/// Filesystem drivers deliberately have no access to the calling process —
/// `FsOps` carries no credential, and that is what keeps a driver from
/// growing its own idea of who is allowed to do what. A few Linux behaviours
/// nevertheless turn on the caller's privilege deep inside a driver rather
/// than at the syscall boundary; btrfs's `quota_override` is one
/// (`qgroup_reserve` tests `capable(CAP_SYS_RESOURCE)` per reservation). This
/// hook is how a driver asks that question without being handed a credential
/// it could then use for anything else.
///
/// Failing closed is the whole design. An uninstalled hook — a driver under
/// test, an early-boot path, a build without the syscall layer — must never
/// read as "privileged", because every caller of this is deciding whether to
/// SKIP an enforcement.
static CALLER_CAPABLE_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the caller-capability query (userspace `caller_capable`).
pub fn install_caller_capable_hook(f: fn(u32) -> bool) {
    CALLER_CAPABLE_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

/// Whether the process this work is being done for holds `cap`, in the
/// INITIAL user namespace — the question Linux's `capable()` asks.
///
/// False when no hook is installed. See [`install_caller_capable_hook`].
pub fn caller_capable(cap: u32) -> bool {
    let v = CALLER_CAPABLE_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        return false;
    }
    // SAFETY: v was stored by install_caller_capable_hook as a `fn(u32) -> bool`
    // pointer; non-zero confirms it was installed.
    let f: fn(u32) -> bool = unsafe { core::mem::transmute::<usize, fn(u32) -> bool>(v) };
    f(cap)
}

/// The caller's answer to `fs/inode.c::in_group_or_capable` for one inode.
///
/// `posix_acl_update_mode` needs it — setting an access ACL drops S_ISGID
/// unless the caller is in the file's group or holds CAP_FSETID over it —
/// and no `FileOps`/`DirOps` method carries a credential to compute it
/// with. Passing a hardcoded `true` was the documented gap: it kept the
/// bit in every case, including the one Linux clears it for.
///
/// Fails CLOSED, like [`CALLER_CAPABLE_HOOK`], but note that "closed" here
/// means DROPPING the setgid bit: with no hook installed the safe answer
/// is the one that removes privilege, not the one that keeps it.
static IN_GROUP_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the `in_group_or_capable` query (userspace's).
pub fn install_in_group_hook(f: fn(u32, u32) -> bool) {
    IN_GROUP_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

/// Whether the calling process is in `(uid, gid)`'s group, or holds
/// CAP_FSETID over that inode. `false` when no hook is installed.
pub fn caller_in_group_or_capable(uid: u32, gid: u32) -> bool {
    let v = IN_GROUP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        return false;
    }
    // SAFETY: v was stored by install_in_group_hook as a
    // `fn(u32, u32) -> bool` pointer; non-zero confirms it was installed.
    let f: fn(u32, u32) -> bool = unsafe { core::mem::transmute::<usize, fn(u32, u32) -> bool>(v) };
    f(uid, gid)
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

/// The user namespace owning a namespace-scoped resource — Linux's
/// `mnt_ns->user_ns`, fixed at creation by `copy_mnt_ns`.
///
/// `narf-filesystem` sits BELOW the namespace layer and cannot name
/// `UserNamespace`, so it holds the owner opaquely and the layer above
/// downcasts it back. Storing it IN the namespace, rather than in a side
/// table keyed by namespace id, gives the owner exactly the mount
/// namespace's lifetime: a table would keep every user namespace that ever
/// owned a mount namespace alive, and would have to be pruned from a place
/// that cannot see when the last reference goes away.
/// A namespace object, of any flavour, as the namespace tree holds it.
///
/// Defined in this crate rather than in `userspace` because two flavours —
/// mount and cgroup — live HERE and cannot name userspace types, while the
/// tree that holds them all lives above. A trait both sides can see is the
/// only thing that crosses.
///
/// `as_any` is what lets a holder recover the concrete namespace: the tree
/// stores one uniform handle, and a caller that needs `MountNamespace`
/// specifically downcasts. Keeping `id`/`ns_type` on the trait too means the
/// tree can answer a filtered query without upgrading a single weak
/// reference.
pub trait NsObject: Send + Sync + core::fmt::Debug {
    fn as_any(&self) -> &dyn core::any::Any;

    /// Recover the OWNING handle, not just a borrow.
    ///
    /// `as_any` is enough to ask what a namespace is; it is not enough to
    /// keep one alive. An ns-fd minted from a tree lookup has to hold the
    /// object, so the caller needs `Arc<ConcreteNs>` back out of
    /// `Arc<dyn NsObject>` — which needs an `Arc<dyn Any>` to downcast
    /// from, and `Arc::downcast` cannot manufacture one from `&dyn Any`.
    fn into_any_arc(
        self: alloc::sync::Arc<Self>,
    ) -> alloc::sync::Arc<dyn core::any::Any + Send + Sync>;
    /// This namespace's globally unique id.
    fn ns_id(&self) -> u64;
    /// The `enum ns_type` bit for this flavour.
    fn ns_type(&self) -> u32;
}

pub trait NsOwner: Send + Sync + core::fmt::Debug {
    fn as_any(&self) -> &dyn core::any::Any;

    /// The owner's namespace id, for the namespace-tree entry of anything it
    /// owns. Defaults to 0 — the tree's spelling for the initial user
    /// namespace — so an owner that predates the tree needs no change.
    fn ns_id(&self) -> u64 {
        0
    }
}

impl NsObject for MountNamespace {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn into_any_arc(
        self: alloc::sync::Arc<Self>,
    ) -> alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
        self
    }
    fn ns_id(&self) -> u64 {
        self.id
    }
    fn ns_type(&self) -> u32 {
        NS_TYPE_MNT
    }
}

impl Drop for MountNamespace {
    fn drop(&mut self) {
        // Retire the tree entry: an entry outliving its namespace would
        // answer a lookup with an id nothing can be reached through.
        ns_tree_remove(self.id);
    }
}

/// Where a mount namespace keeps its mount table.
///
/// The INITIAL mount namespace is not a snapshot of the global registry —
/// it IS the global registry. Giving it `Owned` storage seeded from
/// `REGISTRY` would fork the table at boot: a later `mount(2)` through the
/// registry would be invisible to the namespace object, and the two would
/// drift apart silently. `VfsRegistry` and a namespace's private storage
/// are the same two fields, so the initial namespace can borrow the
/// registry outright.
///
/// See `userspace/specification/namespace-tree.md` R30.
#[derive(Debug)]
enum MountStore {
    /// Private storage, as `copy_mnt_ns` gives an `unshare(CLONE_NEWNS)`.
    Owned(VfsRegistry),
    /// `init_mnt_ns` — the live global mount table.
    Registry,
}

/// Snapshot-shaped mount table. Holds an owned Vec of mounts so a
/// per-task NS can diverge from the global registry without affecting it —
/// except for the initial namespace, which borrows the registry
/// ([`MountStore`]).
#[derive(Debug)]
pub struct MountNamespace {
    /// Stable namespace id (nsfs inode in Linux), drawn from the
    /// process-global `NsId` counter via `NS_ID_ALLOC_HOOK`.
    id: u64,
    /// `mnt_ns->user_ns`: the user namespace of the task that created this
    /// one. `mount(2)` is gated on CAP_SYS_ADMIN *here*, not in the host
    /// namespace. `None` is the initial user namespace — every mount
    /// namespace built before any `unshare(CLONE_NEWUSER)`.
    owner: Option<Arc<dyn NsOwner>>,
    store: MountStore,
}

/// `MNT_NS_INIT_ID` (`include/uapi/linux/nsfs.h:78`) — the initial mount
/// namespace's reserved id.
///
/// Duplicated here rather than imported because the reserved-id block lives
/// with the namespace tree in `narf-userspace`, which sits ABOVE this crate.
/// `smoke_ns_init_ids_agree_across_crates` asserts the two agree.
pub const NS_INIT_ID_MNT: u64 = 8;

/// `init_mnt_ns` — the initial mount namespace.
///
/// Borrows the global registry rather than snapshotting it, so a `mount(2)`
/// through either is visible through both. Never dropped, like every
/// initial namespace.
static INITIAL_MOUNT_NS: IrqSafeSpinLock<Option<Arc<MountNamespace>>> = IrqSafeSpinLock::new(None);

/// The initial mount namespace, created on first use and never dropped.
///
/// Every flavour NARF implements needs a real object behind its initial
/// tree entry: an entry whose weak handle cannot be upgraded is
/// indistinguishable from a stale one
/// (`userspace/specification/namespace-tree.md` R30).
/// Re-state the initial mount namespace in the tree.
///
/// [`initial_mount_ns`] memoises, so it registers only on its first call;
/// the boot path needs a way to restore the entry after a test has reset
/// the tree. `ns_tree_add` is an idempotent insert keyed by id.
pub fn register_initial_mount_ns() {
    let ns = initial_mount_ns();
    ns_tree_add(
        NS_INIT_ID_MNT,
        NS_TYPE_MNT,
        0,
        Arc::downgrade(&ns) as alloc::sync::Weak<dyn NsObject>,
    );
}

pub fn initial_mount_ns() -> Arc<MountNamespace> {
    // The `Arc` is cloned out and the guard dropped before returning, so no
    // caller can drop a `MountNamespace` — and re-enter `ns_tree_remove` —
    // while this lock is held.
    let mut g = INITIAL_MOUNT_NS.lock();
    if let Some(ns) = g.as_ref() {
        return ns.clone();
    }
    let ns = Arc::new(MountNamespace {
        id: NS_INIT_ID_MNT,
        owner: None,
        store: MountStore::Registry,
    });
    ns_tree_add(
        NS_INIT_ID_MNT,
        NS_TYPE_MNT,
        0,
        Arc::downgrade(&ns) as alloc::sync::Weak<dyn NsObject>,
    );
    *g = Some(ns.clone());
    ns
}

impl MountNamespace {
    /// The table this namespace reads and writes.
    ///
    /// One accessor rather than a branch in each of the twenty-odd methods
    /// below: the two storage shapes are the same type, so only the
    /// *address* differs.
    fn store(&self) -> &VfsRegistry {
        match &self.store {
            MountStore::Owned(v) => v,
            MountStore::Registry => &REGISTRY,
        }
    }

    fn from_mounts(mounts: &[Mount], owner: Option<Arc<dyn NsOwner>>) -> Arc<Self> {
        let copied: Vec<Mount> = mounts
            .iter()
            .map(|m| Mount {
                path: m.path.clone(),
                fs: m.fs.clone(),
                root: m.root.clone(),
                handle: Cap::<MountPoint, Write>::bootstrap(),
                id: alloc_mount_id(),
                // A namespace clone copies the mount's flags with it:
                // `copy_mnt_ns` duplicates each mount, restrictions and all.
                flags: core::sync::atomic::AtomicU64::new(m.flags()),
                // Propagation: the clone INHERITS the source mount's peer-group
                // id, so a shared mount's copy is a genuine PEER of the source
                // across the two namespaces — Linux `clone_mnt` for a same-
                // user_ns clone (`mnt_group_id = old->mnt_group_id`, then spliced
                // into the peer ring; fs/namespace.c). This is exactly what makes
                // a service sandbox's /run a peer of the host /run so mounts
                // under it propagate both ways. LINUX-GAP: a clone into a
                // DIFFERENT user namespace should instead become a SLAVE
                // (group_id 0, one-way host->child); NARF has no slave state yet,
                // so cross-user_ns clones are treated as peers. Service sandboxes
                // are mount namespaces in the same user namespace, so the peer
                // path is the one that matters here.
                group_id: core::sync::atomic::AtomicU64::new(m.group_id()),
            })
            .collect();
        let id = alloc_mount_ns_id();
        let owner_id = owner.as_ref().map_or(0, |o| o.ns_id());
        let lookup = RcuAtomic::new(MountLookupTable::from_mounts(&copied));
        // Registration happens AFTER the `Arc` exists: the tree holds a weak
        // handle, and there is nothing to downgrade until the object is built.
        let ns = Arc::new(Self {
            id,
            owner,
            store: MountStore::Owned(VfsRegistry {
                inner: IrqSafeSpinLock::new(copied),
                lookup,
                mountinfo_generation: core::sync::atomic::AtomicU64::new(1),
            }),
        });
        ns_tree_add(
            id,
            NS_TYPE_MNT,
            owner_id,
            Arc::downgrade(&ns) as alloc::sync::Weak<dyn NsObject>,
        );
        ns
    }

    /// Build a private namespace seeded with the current global
    /// registry's mounts. The mounts share the underlying
    /// `Arc<dyn FsInstance>` — a bind-mount-style relationship,
    /// not a deep copy.
    pub fn snapshot_global() -> Arc<Self> {
        Self::snapshot_global_owned_by(None)
    }

    /// [`Self::snapshot_global`] recording the creating task's user
    /// namespace, per `copy_mnt_ns`'s `new_ns->user_ns = get_user_ns(user_ns)`.
    pub fn snapshot_global_owned_by(owner: Option<Arc<dyn NsOwner>>) -> Arc<Self> {
        let g = REGISTRY.inner.lock();
        Self::from_mounts(&g, owner)
    }

    /// The user namespace this mount namespace belongs to, if it is not the
    /// initial one. The caller downcasts through [`NsOwner::as_any`].
    pub fn owner(&self) -> Option<&Arc<dyn NsOwner>> {
        self.owner.as_ref()
    }

    /// Copy this namespace's current mount table into a new namespace.
    ///
    /// Linux `unshare(CLONE_NEWNS)` and `clone(CLONE_NEWNS)` copy the
    /// caller's current namespace, including mounts private to it.
    pub fn snapshot(&self) -> Arc<Self> {
        self.snapshot_owned_by(None)
    }

    /// [`Self::snapshot`] recording the creating task's user namespace. The
    /// owner is the UNSHARING task's, not the parent namespace's — a task
    /// that unshares a user namespace and then a mount namespace owns the
    /// result even though it copied a table it did not own.
    pub fn snapshot_owned_by(&self, owner: Option<Arc<dyn NsOwner>>) -> Arc<Self> {
        let g = self.store().inner.lock();
        Self::from_mounts(&g, owner)
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Monotonic change counter for `/proc/<pid>/mountinfo` poll waiters in
    /// this namespace. It advances after every visible attach, detach, or
    /// move, matching Linux's `POLLPRI` mountinfo notification contract.
    pub fn mountinfo_generation(&self) -> u64 {
        self.store()
            .mountinfo_generation
            .load(core::sync::atomic::Ordering::Acquire)
            .wrapping_add(sb_flags::generation())
    }

    /// Resolve an absolute path against this namespace.
    pub fn resolve_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, &str) -> R,
    {
        let mount = self.store().lookup_covering_mount(abs)?;
        Some(f(&*mount.fs, &abs[mount.rel_start..]))
    }

    /// Resolve an absolute path and pass the mount's canonical root dentry.
    /// Path-walking callers should prefer this over calling `fs.root()` so
    /// repeated walks share the same RCU dentry identity.
    pub fn resolve_absolute_with_root<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<Dentry>, &str) -> R,
    {
        let mount = self.store().lookup_covering_mount(abs)?;
        Some(f(&*mount.fs, mount.root, &abs[mount.rel_start..]))
    }

    /// Resolve an absolute path whose remaining component walk cannot cross
    /// another mount, returning the covering mount id alongside the usual
    /// filesystem-relative path. The registry lock is released before `f`.
    pub fn resolve_absolute_single_mount<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, &str, u64) -> R,
    {
        let mount = self.store().lookup_single_mount(abs)?;
        Some(f(&*mount.fs, &abs[mount.rel_start..], mount.id))
    }

    /// Root-aware form of [`Self::resolve_absolute_single_mount`] for
    /// pathname walkers that need the attachment's canonical root dentry.
    pub fn resolve_absolute_single_mount_with_root<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<Dentry>, &str, u64) -> R,
    {
        let mount = self.store().lookup_single_mount(abs)?;
        Some(f(&*mount.fs, mount.root, &abs[mount.rel_start..], mount.id))
    }

    /// Resolve `abs` to its parent directory + leaf within THIS namespace's
    /// mount table, and run `f(fs, parent_dir, leaf)`.
    ///
    /// The namespace-aware twin of [`VfsRegistry::resolve_parent_absolute`],
    /// and it has to exist for the same reason [`Self::resolve_absolute`]
    /// does. Without it every directory-MUTATION syscall (rename, unlink,
    /// rmdir, symlink) resolves against the GLOBAL registry while open/read
    /// resolve against the task's namespace — so a task in a private mount
    /// namespace can create a file it then cannot rename or remove, because
    /// the parent is visible to one call and not the other.
    ///
    /// That asymmetry is what stopped udev dead: `systemd-udevd` runs with
    /// `PrivateMounts=yes`, and `sd-device` publishes each database entry by
    /// writing `/run/udev/data/.#<id><random>` and renaming it onto
    /// `/run/udev/data/<id>`. The write succeeded and the rename returned
    /// ENOENT, so no device was ever recorded.
    pub fn resolve_parent_absolute<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<dyn DirOps>, &str) -> R,
    {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        let last = abs.rfind('/')?;
        let leaf = &abs[last + 1..];
        if leaf.is_empty() {
            return None;
        }
        let parent_path = &abs[..last];
        let parent_path = if parent_path.is_empty() {
            "/"
        } else {
            parent_path
        };
        let mount = self.store().lookup_covering_mount(parent_path)?;
        let dir = resolve_directory_cached(mount.root, &parent_path[mount.rel_start..])?;
        Some(f(&*mount.fs, dir, leaf))
    }

    /// Namespace-scoped twin of [`VfsRegistry::resolve_two_parents_absolute`],
    /// for cross-DIRECTORY rename. Same contract: both parents must land on
    /// the same mount (that same-mount check IS the EXDEV test), both routes
    /// come from one immutable snapshot so a concurrent mount cannot move one
    /// path out from under the other, and the RCU guard is released before
    /// either filesystem walk or `f` because those operations may block on I/O.
    ///
    /// Without this, a cross-directory rename inside a private mount
    /// namespace resolves against the global registry and fails, exactly as
    /// same-directory rename did before `resolve_parent_absolute` gained a
    /// namespace-aware twin.
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
        let guard = narf_rcu::pin();
        let lookup = self.store().lookup.load(&guard);
        let mounts = &lookup.as_ref()?.mounts;
        let ma = covering_mount_lookup(mounts, a_parent)?;
        let mb = covering_mount_lookup(mounts, b_parent)?;
        if ma.id != mb.id {
            return None;
        }
        let rel_start = |mount: &MountLookup, parent: &str| {
            let suffix = &parent[mount.path.len()..];
            parent.len() - suffix.strip_prefix('/').unwrap_or(suffix).len()
        };
        let fs = ma.fs.upgrade()?;
        let root = ma.root.upgrade()?;
        let a_rel_start = rel_start(ma, a_parent);
        let b_rel_start = rel_start(mb, b_parent);
        drop(guard);

        let walk = |parent: &str, start: usize| -> Option<Arc<dyn DirOps>> {
            resolve_directory_cached(root.clone(), &parent[start..])
        };
        let a_dir = walk(a_parent, a_rel_start)?;
        let b_dir = walk(b_parent, b_rel_start)?;
        Some(f(&*fs, a_dir, a_leaf, b_dir, b_leaf))
    }

    /// Clone the filesystem object of the visible mount covering `abs`.
    ///
    /// Equal-length entries are mount stacks; the newest entry wins, matching
    /// `resolve_absolute`.
    pub fn fs_arc_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        self.store()
            .lookup_covering_mount(abs)
            .map(|mount| mount.fs)
    }

    /// Clone the visible directory subtree rooted at `abs`.
    pub fn clone_tree_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        let mount = self.store().lookup_covering_mount(abs)?;
        let root = resolve_directory_cached(mount.root, &abs[mount.rel_start..])?;
        Some(Arc::new(BindMount {
            root,
            fs_name: String::from(mount.fs.name()),
            backing_identity: mount.fs.backing_identity(),
        }) as Arc<dyn FsInstance>)
    }

    /// List the mount paths in this namespace.
    pub fn list(&self) -> Vec<String> {
        let q = self.store().inner.lock();
        q.iter().map(|m| m.path.clone()).collect()
    }

    /// List `(mount_path, fs_name)` for every mount. Used by
    /// `/proc/mounts` + `/proc/filesystems` so the synthetic FS can
    /// surface the per-mount FsInstance name without exposing the
    /// internal `Mount` shape.
    pub fn list_with_names(&self) -> Vec<(String, String)> {
        let q = self.store().inner.lock();
        q.iter()
            .map(|m| (m.path.clone(), String::from(m.fs.name())))
            .collect()
    }

    /// The `MNT_*` flags of the mount covering `abs`, by the same
    /// longest-prefix rule resolution uses, or `None` when no mount covers
    /// it.
    pub fn flags_at(&self, abs: &str) -> Option<u64> {
        let q = self.store().inner.lock();
        mount_flags_for(&q, abs)
    }

    /// The propagation peer-group id of the mount covering `abs` (`0` =
    /// private), or `None` when no mount covers it. Used by tests and by the
    /// mountinfo/statmount surfaces.
    pub fn group_id_at(&self, abs: &str) -> Option<u64> {
        let q = self.store().inner.lock();
        mount_group_id_for(&q, abs)
    }

    /// Paths of every mount in this namespace whose peer-group id is exactly
    /// `gid` (which must be non-zero). These are the local members of a peer
    /// group — mount propagation attaches a copy of a new child mount at each.
    pub fn mount_paths_with_group(&self, gid: u64) -> Vec<String> {
        if gid == 0 {
            return Vec::new();
        }
        let q = self.store().inner.lock();
        q.iter()
            .filter(|m| m.group_id() == gid)
            .map(|m| m.path.clone())
            .collect()
    }

    /// `(path, group_id)` of the mount covering `abs` in this namespace, by the
    /// longest-prefix + newest-wins rule. Used to find a just-attached mount's
    /// PARENT mount (call with the new mount's parent directory) to decide
    /// whether propagation applies.
    pub fn covering_mount_info(&self, abs: &str) -> Option<(String, u64)> {
        let q = self.store().inner.lock();
        covering_mount(&q, abs).map(|m| (m.path.clone(), m.group_id()))
    }

    /// The stored `MNT_*` flags (no superblock contribution) of the topmost
    /// mount at exactly `path` — what a read-modify-write of the
    /// attachment's own flags must start from.
    pub fn mount_flags_exact(&self, path: &str) -> Option<u64> {
        let q = self.store().inner.lock();
        q.iter().rev().find(|m| m.path == path).map(Mount::flags)
    }

    /// Replace the `MNT_*` flags of the mount at exactly `path` — Linux's
    /// `do_reconfigure_mnt`, which changes an existing attachment rather
    /// than creating one.
    pub fn set_flags_at(&self, path: &str, flags: u64) -> bool {
        let q = self.store().inner.lock();
        let Some(mount) = q.iter().rev().find(|m| m.path == path) else {
            return false;
        };
        mount
            .flags
            .store(flags, core::sync::atomic::Ordering::Release);
        note_mnt_flags(flags);
        self.store()
            .mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        true
    }

    /// Namespace-scoped `do_change_type` — see
    /// [`VfsRegistry::change_propagation_at`]. Operates on this namespace's own
    /// table (its private mounts), which is where a service that unshared
    /// CLONE_NEWNS issues `mount --make-shared`.
    pub fn change_propagation_at(&self, path: &str, prop: MntPropagation, recursive: bool) -> bool {
        self.store().change_propagation_at(path, prop, recursive)
    }

    /// Mount identity and hierarchy in attachment order.
    pub fn list_mountinfo(&self) -> Vec<MountInfoRow> {
        mountinfo_rows(&self.store().inner.lock())
    }

    /// ID of the newest visible mount covering `abs`.
    pub fn mount_id_at(&self, abs: &str) -> Option<u64> {
        self.store()
            .lookup_covering_mount(abs)
            .map(|mount| mount.id)
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
        self.mount_arc_with_flags(authority, path, fs, 0)
    }

    /// [`Self::mount_arc`] with the mount's `MNT_*` flags — see
    /// [`mnt_flags`].
    pub fn mount_arc_with_flags(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        fs: Arc<dyn FsInstance>,
        flags: u64,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        let root = pathwalk::Dentry::root(fs.root());
        let handle = Cap::<MountPoint, Write>::bootstrap();
        let store = self.store();
        let mut mounts = store.inner.lock();
        mounts.push(Mount {
            path: String::from(path),
            fs,
            root,
            handle,
            id: alloc_mount_id(),
            flags: core::sync::atomic::AtomicU64::new(flags),
            // A freshly created mount is PRIVATE (no peer group) until
            // `mount --make-shared` marks it, exactly as Linux mounts start
            // with `mnt_group_id == 0`. Propagation of a new mount UNDER an
            // already-shared parent is handled by the attach path, not here.
            group_id: core::sync::atomic::AtomicU64::new(0),
        });
        store.publish_lookup_locked(&mounts);
        note_mnt_flags(flags);
        store
            .mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(mounts);
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
        let source_mount = self
            .store()
            .lookup_covering_mount(source)
            .ok_or(FsError::NotFound)?;
        let rel = String::from(&source[source_mount.rel_start..]);
        // A directory source binds as a subtree; a FILE source binds as a
        // single file (mount --bind of a file).
        let bind = build_bind_fs(&source_mount.fs, source_mount.root, &rel)?;
        self.mount_arc(authority, target, bind)
    }

    /// Detach the topmost mount at `path` from this private namespace.
    pub fn unmount(&self, path: &str) -> Result<(), FsError> {
        let store = self.store();
        let mut q = store.inner.lock();
        let index = q
            .iter()
            .rposition(|m| m.path == path)
            .ok_or(FsError::NotFound)?;
        let mount = q.remove(index);
        store.publish_lookup_locked(&q);
        store
            .mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        // Linux removes the attachment under namespace_lock, then releases
        // mount references after namespace_unlock for the same reason: final
        // filesystem/dentry destructors may take unrelated locks or wake work.
        drop(mount);
        notify_mount_change();
        Ok(())
    }

    /// Move the topmost mount at `source` to `target`.
    pub fn move_mount(&self, source: &str, target: &str) -> Result<(), FsError> {
        let store = self.store();
        let mut q = store.inner.lock();
        let index = q
            .iter()
            .rposition(|m| m.path == source)
            .ok_or(FsError::NotFound)?;
        q[index].path = String::from(target);
        store.publish_lookup_locked(&q);
        store
            .mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        notify_mount_change();
        Ok(())
    }
}

/// Bootstrap the mount-authority cap. TCB-only path — the kernel
/// calls this once at boot and hands the result to whatever subsystem
/// actually mounts the initial root.
/// Test support: ensure a root filesystem exists and `path` is a directory
/// inside it, so `mount(2)`'s target check has something to resolve.
///
/// `do_mount` calls `user_path_at` before `path_mount`, so a target that
/// does not resolve is -ENOENT and nothing else runs. On a real system the
/// mount point exists because the rootfs image shipped it; the kernel-test
/// image mounts no root at all, so the fixture has to provide one.
///
/// The root filesystem instance is held here and RE-MOUNTED if it goes
/// missing, rather than rebuilt. That distinction is the whole trick: the
/// mount smokes reset the registry between cases, so a root mounted once
/// vanishes and later targets cannot be created — but rebuilding it on each
/// reset yields a fresh, empty MemFs that has lost every directory made so
/// far. Re-mounting the SAME instance keeps the tree across resets.
#[doc(hidden)]
pub fn __test_ensure_mount_target(path: &str) {
    static ROOT_FS: IrqSafeSpinLock<Option<Arc<dyn FsInstance>>> = IrqSafeSpinLock::new(None);

    // The kernel-test image DOES have a root: `boot-initramfs`, and it is
    // read-only — `mkdir` on it returns `Unsupported`, exactly as on a real
    // read-only initramfs. So the fixture supplies the writable root a real
    // system would have pivoted to.
    //
    // As an OVERLAY, not a plain MemFs over "/". Shadowing the initramfs
    // hides its contents: a bare MemFs root made
    // `smoke_module_load_real_ko_round_trip` and
    // `..._staged_ko_is_relocatable_for_this_arch` start skipping, because
    // `/lib/modules/narf_test_module.ko` stopped resolving. Writes land in
    // the upper MemFs, reads fall through to the initramfs below, so created
    // mount points and shipped image content both exist.
    //
    // Built once and RE-MOUNTED if it goes missing, rather than rebuilt: the
    // mount smokes reset the registry between cases, and a rebuilt overlay
    // would come back with an empty upper, losing every directory made so
    // far.
    let fs = {
        let mut slot = ROOT_FS.lock();
        if slot.is_none() {
            let lower = registry().fs_arc_at("/").map(|f| f.root());
            let upper = Arc::new(MemFs::new("test-root-upper"));
            let lowers = lower.into_iter().collect::<alloc::vec::Vec<_>>();
            let overlay =
                crate::overlayfs::OverlayFs::new("test-rootfs", FsInstance::root(&*upper), lowers);
            *slot = Some(Arc::new(overlay) as Arc<dyn FsInstance>);
        }
        slot.as_ref().map(Arc::clone)
    };
    let Some(fs) = fs else { return };
    let writable_root = registry()
        .fs_arc_at("/")
        .map(|f| f.name() == "test-rootfs")
        .unwrap_or(false);
    if !writable_root {
        let auth = bootstrap_mount_authority();
        let _ = registry().mount_arc(&auth, "/", fs);
    }

    // Create the directory inside the mount that COVERS the path, not in the
    // root filesystem. A target under an existing mount (mounting at
    // "/cjail/x" when a tmpfs is mounted at "/cjail") would otherwise be
    // created in the root and immediately shadowed, so the handler's own
    // lookup — longest-prefix-first — would still not find it.
    registry().resolve_absolute(path, |fs, rel| {
        let mut dir = fs.root();
        for comp in rel.split('/').filter(|c| !c.is_empty()) {
            if let Some(d) = dir.lookup_dir(comp) {
                dir = d;
                continue;
            }
            match crate::procfs::poll_once(dir.mkdir(comp)) {
                Some(Ok(d)) => dir = d,
                _ => return,
            }
        }
    });
}

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
    fn rcu_walkable(&self) -> bool {
        true
    }

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
    source_root: Arc<Dentry>,
    rel: &str,
) -> Result<Arc<dyn FsInstance>, FsError> {
    let fs_name = String::from(source_fs.name());
    let comps: alloc::vec::Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    let source_root_dir = source_root.directory().ok_or(FsError::NotFound)?;
    if comps.is_empty() {
        // Binding the source mount's root directory itself.
        return Ok(Arc::new(BindMount {
            root: source_root_dir,
            fs_name,
            backing_identity: source_fs.backing_identity(),
        }));
    }
    let mut dir = source_root_dir;
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
    /// Publish a pathname-routing snapshot while the authoritative table is
    /// locked. This is the role of Linux's namespace writer lock plus
    /// `mount_lock` sequence publication: readers see one topology generation.
    /// Publication itself is a pointer swap; the displaced table is reclaimed
    /// after a QSBR grace period, so no destructor runs under `inner`.
    fn publish_lookup_locked(&self, mounts: &[Mount]) {
        let next = RcuOwned::new(MountLookupTable::from_mounts(mounts));
        let guard = narf_rcu::pin();
        self.lookup.store(next, &guard);
    }

    /// Pin the covering mount from one immutable table version. The returned
    /// `Arc` legitimizes the result before the RCU read section ends, exactly
    /// as Linux converts an RCU-walk mount into a referenced path before a
    /// filesystem callback may block.
    fn lookup_covering_mount(&self, abs: &str) -> Option<MountResolution> {
        if abs.is_empty() || abs.as_bytes()[0] != b'/' {
            return None;
        }
        // A detach can retire the authoritative mount after an RCU reader has
        // sampled the old routing table but before its weak references are
        // legitimized. That is Linux's `legitimize_mnt` failure case: leave
        // RCU and retry against the newly published topology, which may reveal
        // a mount that was underneath an overmount.
        for _ in 0..3 {
            let guard = narf_rcu::pin();
            let table = self.lookup.load(&guard);
            let table = table.as_ref()?;
            let mount = covering_mount_lookup(&table.mounts, abs)?;
            let suffix = &abs[mount.path.len()..];
            let rel_start = abs.len() - suffix.strip_prefix('/').unwrap_or(suffix).len();
            if let (Some(fs), Some(root)) = (mount.fs.upgrade(), mount.root.upgrade()) {
                return Some(MountResolution {
                    fs,
                    root,
                    rel_start,
                    id: mount.id,
                });
            }
        }
        // The static global registry starts with a const null RCU cell. Before
        // its first mutation there is no table to publish and it is empty, so
        // there cannot be a covering mount.
        None
    }

    fn lookup_single_mount(&self, abs: &str) -> Option<MountResolution> {
        for _ in 0..3 {
            let guard = narf_rcu::pin();
            let table = self.lookup.load(&guard);
            if let Some(resolution) = single_mount_lookup_resolution(&table.as_ref()?.mounts, abs) {
                return Some(resolution);
            }
        }
        None
    }

    fn lookup_exact_mount(&self, path: &str) -> Option<(Arc<dyn FsInstance>, Arc<Dentry>)> {
        for _ in 0..3 {
            let guard = narf_rcu::pin();
            let lookup = self.lookup.load(&guard);
            let mount = lookup
                .as_ref()?
                .mounts
                .iter()
                .rev()
                .find(|mount| mount.path == path)?;
            if let (Some(fs), Some(root)) = (mount.fs.upgrade(), mount.root.upgrade()) {
                return Some((fs, root));
            }
        }
        None
    }

    /// Monotonic change counter for global `/proc/<pid>/mountinfo` poll
    /// waiters. The userspace proc hook selects this only for tasks that have
    /// not unshared a private mount namespace.
    pub fn mountinfo_generation(&self) -> u64 {
        self.mountinfo_generation
            .load(core::sync::atomic::Ordering::Acquire)
            .wrapping_add(sb_flags::generation())
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
        self.mount_with_flags(authority, path, fs, 0)
    }

    /// [`Self::mount`] with the mount's `MNT_*` flags — see [`mnt_flags`].
    pub fn mount_with_flags<F: FsInstance>(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        fs: F,
        flags: u64,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        let handle: Cap<MountPoint, Write> = Cap::<MountPoint, Write>::bootstrap();
        let arc: Arc<dyn FsInstance> = Arc::new(fs);
        let root = pathwalk::Dentry::root(arc.root());
        let mut q = self.inner.lock();
        q.push(Mount {
            path: alloc::string::String::from(path),
            fs: arc,
            root,
            handle,
            id: alloc_mount_id(),
            flags: core::sync::atomic::AtomicU64::new(flags),
            // A freshly created mount is PRIVATE (no peer group) until
            // `mount --make-shared` marks it, exactly as Linux mounts start
            // with `mnt_group_id == 0`. Propagation of a new mount UNDER an
            // already-shared parent is handled by the attach path, not here.
            group_id: core::sync::atomic::AtomicU64::new(0),
        });
        self.publish_lookup_locked(&q);
        note_mnt_flags(flags);
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
        self.mount_arc_with_flags(authority, path, fs, 0)
    }

    /// [`Self::mount_arc`] with the mount's `MNT_*` flags — see
    /// [`mnt_flags`].
    pub fn mount_arc_with_flags(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        fs: Arc<dyn FsInstance>,
        flags: u64,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        let handle: Cap<MountPoint, Write> = Cap::<MountPoint, Write>::bootstrap();
        let root = pathwalk::Dentry::root(fs.root());
        let mut q = self.inner.lock();
        q.push(Mount {
            path: alloc::string::String::from(path),
            fs,
            root,
            handle,
            id: alloc_mount_id(),
            flags: core::sync::atomic::AtomicU64::new(flags),
            // A freshly created mount is PRIVATE (no peer group) until
            // `mount --make-shared` marks it, exactly as Linux mounts start
            // with `mnt_group_id == 0`. Propagation of a new mount UNDER an
            // already-shared parent is handled by the attach path, not here.
            group_id: core::sync::atomic::AtomicU64::new(0),
        });
        self.publish_lookup_locked(&q);
        note_mnt_flags(flags);
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
        let source_mount = self
            .lookup_covering_mount(source)
            .ok_or(FsError::NotFound)?;
        let rel = String::from(&source[source_mount.rel_start..]);
        // A directory source binds as a subtree; a FILE source binds as a
        // single file (mount --bind of a file).
        let bind = build_bind_fs(&source_mount.fs, source_mount.root, &rel)?;
        self.mount_arc(authority, target, bind)
    }

    /// Mount a writable overlay at `path`: the directory currently visible at
    /// `path` becomes the read-only lower layer and `upper` (a writable FS such
    /// as a `TmpFs`) is the writable upper. Reads fall through to the existing
    /// content while writes land in `upper`. This is the correct shape for
    /// making a read-only-root subtree writable WITHOUT hiding its contents — a
    /// plain tmpfs overmount would shadow them. (Concretely: an empty tmpfs over
    /// `/home/narf` hid the distro user's populated `~/.config`, so KConfig /
    /// ksycoca failed and the Plasma session died with a black screen.)
    pub fn mount_overlay<F: FsInstance>(
        &self,
        authority: &Cap<MountPoint, Grant>,
        path: &str,
        name: &'static str,
        upper: F,
    ) -> Result<Cap<MountPoint, Write>, FsError> {
        authority.check_live()?;
        // Capture the directory currently at `path` as the overlay LOWER, using
        // the same longest-mount-prefix resolution as `bind_mount`. It is held
        // as a direct `Arc<dyn DirOps>`, independent of the mount table, so the
        // overmount below does not shadow the lower from the overlay's own view
        // (and there is no resolve-through-the-mount recursion).
        let source_mount = self.lookup_covering_mount(path).ok_or(FsError::NotFound)?;
        let rel = String::from(&path[source_mount.rel_start..]);
        let lower = build_bind_fs(&source_mount.fs, source_mount.root, &rel)?.root();
        // `upper.root()` (a `MemDir` Arc) owns the tmpfs tree AND its superblock
        // (`MemDir.superblock: Arc<MemSuper>`), so the `upper` FsInstance wrapper
        // may drop here without losing the tree or its quota accounting.
        let overlay = OverlayFs::new(name, upper.root(), alloc::vec![lower]);
        self.mount_arc(authority, path, Arc::new(overlay))
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

    /// The `MNT_*` flags of the mount covering `abs` in this namespace.
    pub fn flags_at(&self, abs: &str) -> Option<u64> {
        let q = self.inner.lock();
        mount_flags_for(&q, abs)
    }

    /// The propagation peer-group id of the mount covering `abs` (`0` =
    /// private) in this namespace, or `None` when no mount covers it.
    pub fn group_id_at(&self, abs: &str) -> Option<u64> {
        let q = self.inner.lock();
        mount_group_id_for(&q, abs)
    }

    /// Paths of every mount in this registry whose peer-group id is exactly
    /// `gid` (non-zero). See [`MountNamespace::mount_paths_with_group`].
    pub fn mount_paths_with_group(&self, gid: u64) -> Vec<String> {
        if gid == 0 {
            return Vec::new();
        }
        let q = self.inner.lock();
        q.iter()
            .filter(|m| m.group_id() == gid)
            .map(|m| m.path.clone())
            .collect()
    }

    /// `(path, group_id)` of the mount covering `abs` — see
    /// [`MountNamespace::covering_mount_info`].
    pub fn covering_mount_info(&self, abs: &str) -> Option<(String, u64)> {
        let q = self.inner.lock();
        covering_mount(&q, abs).map(|m| (m.path.clone(), m.group_id()))
    }

    /// See [`MountNamespace::mount_flags_exact`].
    pub fn mount_flags_exact(&self, path: &str) -> Option<u64> {
        let q = self.inner.lock();
        q.iter().rev().find(|m| m.path == path).map(Mount::flags)
    }

    /// Replace the `MNT_*` flags of the mount at exactly `path`.
    pub fn set_flags_at(&self, path: &str, flags: u64) -> bool {
        let q = self.inner.lock();
        let Some(mount) = q.iter().rev().find(|m| m.path == path) else {
            return false;
        };
        mount
            .flags
            .store(flags, core::sync::atomic::Ordering::Release);
        note_mnt_flags(flags);
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        true
    }

    /// `fs/namespace.c::do_change_type` — change the propagation type of the
    /// mount at `path` (and, when `recursive`, every mount beneath it). Returns
    /// `false` when no mount exists at `path` (the caller maps that to ENOENT,
    /// as `do_change_type` does when `path_mounted` fails).
    ///
    /// `MS_SHARED` mints a fresh peer-group id for any affected mount that is
    /// still private (Linux `invent_group_ids` + `set_mnt_shared`, distinct id
    /// per mount so each mountpoint propagates independently). The other types
    /// drop the mount out of its peer group — full one-way slave and unbindable
    /// semantics are the LINUX-GAP noted on [`MntPropagation`].
    pub fn change_propagation_at(&self, path: &str, prop: MntPropagation, recursive: bool) -> bool {
        let q = self.inner.lock();
        let mut found = false;
        for m in q.iter() {
            let affected =
                m.path == path || (recursive && path_is_proper_descendant(&m.path, path));
            if !affected {
                continue;
            }
            found = true;
            match prop {
                MntPropagation::Shared => {
                    if m.group_id() == 0 {
                        m.set_group_id(alloc_mount_group_id());
                    }
                }
                MntPropagation::Private | MntPropagation::Slave | MntPropagation::Unbindable => {
                    m.set_group_id(0)
                }
            }
        }
        drop(q);
        if found {
            self.mountinfo_generation
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            notify_mount_change();
        }
        found
    }

    /// Mount identity and hierarchy in attachment order.
    pub fn list_mountinfo(&self) -> alloc::vec::Vec<MountInfoRow> {
        mountinfo_rows(&self.inner.lock())
    }

    /// ID of the visible mount covering `abs`.
    pub fn mount_id_at(&self, abs: &str) -> Option<u64> {
        self.lookup_covering_mount(abs).map(|mount| mount.id)
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
        self.publish_lookup_locked(&q);
        self.mountinfo_generation
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        drop(q);
        // Linux removes the attachment under namespace_lock, then releases
        // mount references after namespace_unlock. Keep arbitrary filesystem
        // and dentry destructors out of this IRQ-safe writer critical section.
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
        self.publish_lookup_locked(&q);
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
        let (fs, _root) = self.lookup_exact_mount(path)?;
        Some(f(&*fs))
    }

    /// Run `f` against an exact mount and its canonical root dentry.
    /// Path-walking callers should prefer this over calling `fs.root()`.
    pub fn with_mount_root<R, F>(&self, path: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<Dentry>) -> R,
    {
        let (fs, root) = self.lookup_exact_mount(path)?;
        Some(f(&*fs, root))
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
        let mount = self.lookup_covering_mount(abs)?;
        Some(f(&*mount.fs, &abs[mount.rel_start..]))
    }

    /// Resolve an absolute path and pass the mount's canonical root dentry.
    /// Path-walking callers should prefer this over calling `fs.root()` so
    /// repeated walks share the same RCU dentry identity.
    pub fn resolve_absolute_with_root<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<Dentry>, &str) -> R,
    {
        let mount = self.lookup_covering_mount(abs)?;
        Some(f(&*mount.fs, mount.root, &abs[mount.rel_start..]))
    }

    /// Namespace-aware counterpart of
    /// [`VfsRegistry::resolve_absolute_single_mount`].
    pub fn resolve_absolute_single_mount<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, &str, u64) -> R,
    {
        let mount = self.lookup_single_mount(abs)?;
        Some(f(&*mount.fs, &abs[mount.rel_start..], mount.id))
    }

    /// Root-aware form of [`Self::resolve_absolute_single_mount`] for
    /// pathname walkers that need the attachment's canonical root dentry.
    pub fn resolve_absolute_single_mount_with_root<R, F>(&self, abs: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn FsInstance, Arc<Dentry>, &str, u64) -> R,
    {
        let mount = self.lookup_single_mount(abs)?;
        Some(f(&*mount.fs, mount.root, &abs[mount.rel_start..], mount.id))
    }

    /// Clone the `Arc<dyn FsInstance>` of the mount covering `abs` (the
    /// longest-prefix match). Used by the new mount API's `open_tree` /
    /// `fspick` to grab an existing mount's filesystem object.
    pub fn fs_arc_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        self.lookup_covering_mount(abs).map(|mount| mount.fs)
    }

    /// Clone the directory subtree rooted at `abs` as a detached filesystem.
    pub fn clone_tree_at(&self, abs: &str) -> Option<Arc<dyn FsInstance>> {
        let mount = self.lookup_covering_mount(abs)?;
        let root = resolve_directory_cached(mount.root, &abs[mount.rel_start..])?;
        Some(Arc::new(BindMount {
            root,
            fs_name: String::from(mount.fs.name()),
            backing_identity: mount.fs.backing_identity(),
        }) as Arc<dyn FsInstance>)
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
        let mount = self.lookup_covering_mount(parent_path)?;
        let dir = resolve_directory_cached(mount.root, &parent_path[mount.rel_start..])?;
        Some(f(&*mount.fs, dir, leaf))
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
    /// Both routes come from one immutable registry snapshot so a concurrent
    /// mount/unmount cannot move one path's mount out from under the other
    /// between the two resolutions. Filesystem walks happen after unpinning.
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

        let guard = narf_rcu::pin();
        let lookup = self.lookup.load(&guard);
        let mounts = &lookup.as_ref()?.mounts;
        let ma = covering_mount_lookup(mounts, a_parent)?;
        let mb = covering_mount_lookup(mounts, b_parent)?;
        if ma.id != mb.id {
            return None;
        }
        let rel_start = |mount: &MountLookup, parent: &str| {
            let suffix = &parent[mount.path.len()..];
            parent.len() - suffix.strip_prefix('/').unwrap_or(suffix).len()
        };
        let fs = ma.fs.upgrade()?;
        let root = ma.root.upgrade()?;
        let a_rel_start = rel_start(ma, a_parent);
        let b_rel_start = rel_start(mb, b_parent);
        drop(guard);

        let walk = |parent: &str, start: usize| -> Option<Arc<dyn DirOps>> {
            resolve_directory_cached(root.clone(), &parent[start..])
        };
        let a_dir = walk(a_parent, a_rel_start)?;
        let b_dir = walk(b_parent, b_rel_start)?;
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
    entries: Arc<[InitramfsEntry]>,
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

        Ok(Self {
            name,
            entries: entries.into(),
        })
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

/// `FsInstance` impl: each root handle shares the immutable entry table.
impl FsInstance for Initramfs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(InitramfsRoot {
            entries: self.entries.clone(),
        })
    }
    fn name(&self) -> &str {
        self.name
    }
}

struct InitramfsRoot {
    entries: Arc<[InitramfsEntry]>,
}

impl fmt::Debug for InitramfsRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsRoot")
            .field("entries_len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl InitramfsRoot {
    fn entries(&self) -> &[InitramfsEntry] {
        &self.entries
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
    entries: Arc<[crate::InitramfsEntry]>,
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
    fn rcu_walkable(&self) -> bool {
        true
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let target = self.child_prefix(name);
        for e in self.entries.iter() {
            if canonicalize_cpio_name(e.name) == target {
                return Some(Arc::new(InitramfsFile {
                    data: e.data,
                    mode: e.mode,
                    mtime: e.mtime,
                    ino: initramfs_ino(&target),
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
                ino: initramfs_ino(&target),
            }));
        }
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let target = self.child_prefix(name);
        // A subdirectory exists if some entry lives UNDER `target/`, or if
        // `target` is itself an explicit CPIO directory entry.
        //
        // The second arm must check the mode. Without it any entry whose name
        // equals `target` matched — including a plain FILE — so `lookup_dir`
        // answered "yes, a directory" for a regular file. Path walking did not
        // notice, because it asks for a file at the last component. An overlay
        // does: `lower_file_async` treats "the lower has a directory by this
        // name" as "therefore not a file" and stops, so a file in an initramfs
        // lower became invisible through an overlay while resolving fine
        // directly. That is what hid /lib/modules/*.ko once the mount-target
        // fixture put an overlay over the boot initramfs.
        let any_match = self.entries.iter().any(|e| {
            let canon = canonicalize_cpio_name(e.name);
            (canon == target && (e.mode & 0o170000) == 0o040000)
                || canon
                    .strip_prefix(&target)
                    .and_then(|r| r.strip_prefix('/'))
                    .is_some()
        });
        if !any_match {
            return None;
        }
        Some(Arc::new(InitramfsDir {
            entries: self.entries.clone(),
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
        let all = collect_immediate_children(&self.entries, &self.prefix);
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
    fn rcu_walkable(&self) -> bool {
        true
    }

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
                    ino: initramfs_ino(name),
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
                ino: initramfs_ino(name),
            }));
        }
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        // A subdir exists if at least one entry's canonical name starts with
        // `name/`, or is exactly `name` AND is an explicit CPIO dir entry.
        // The mode check is the operative half — see the note on
        // `InitramfsDir::lookup_dir`: without it a regular file answers
        // `lookup_dir`, which makes that file invisible underneath an overlay.
        let any_match = self.entries().iter().any(|e| {
            let canon = canonicalize_cpio_name(e.name);
            (canon == name && (e.mode & 0o170000) == 0o040000)
                || canon
                    .strip_prefix(name)
                    .and_then(|r| r.strip_prefix('/'))
                    .is_some()
        });
        if !any_match {
            return None;
        }
        Some(Arc::new(InitramfsDir {
            entries: self.entries.clone(),
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
    /// `st_ino`, from the entry's canonical path — see [`initramfs_ino`].
    ino: u64,
}

/// The initramfs superblock's `st_dev` (Linux unpacks initramfs into rootfs,
/// one anonymous-device superblock).
static INITRAMFS_DEV: crate::inode_id::LazyAnonDev = crate::inode_id::LazyAnonDev::new();

/// Stable inode number for the initramfs entry at canonical `path`.
///
/// Linux unpacks the archive into rootfs and numbers each created inode with
/// `get_next_ino`; NARF re-creates the file object on every lookup, so the
/// number is derived from the path instead (32-bit FNV-1a, never 0 or 1 —
/// 1 is the root, `rootfs`'s first inode).
// LINUX-GAP: path-derived, so two paths could collide (~2^-32), and a
// hardlink in the archive gets its own number instead of sharing one.
fn initramfs_ino(path: &str) -> u64 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in path.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    if hash <= 1 {
        hash = hash.wrapping_add(2);
    }
    u64::from(hash)
}

impl fmt::Debug for InitramfsFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitramfsFile")
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl FileOps for InitramfsFile {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            dev: INITRAMFS_DEV.get(),
            ..Default::default()
        }
    }

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
    #[cfg(feature = "cgroup-psi")]
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
#[cfg(feature = "cgroup-psi")]
#[derive(Debug)]
struct PressureFile(cgroupfs::psi::Resource);

#[cfg(feature = "cgroup-psi")]
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
