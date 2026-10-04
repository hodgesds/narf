//! Batch B — the Linux 5.2 "new mount API":
//! `fsopen` / `fsconfig` / `fsmount` / `move_mount` / `open_tree` /
//! `open_tree_attr` / `fspick` / `mount_setattr`.
//!
//! These decompose `mount(2)` into fd-addressed steps. NARF layers them on
//! the existing VFS registry, reusing the same fstype→backend dispatch
//! (`build_fs`) `sys_mount` uses, so the classic and new-API paths recognize
//! exactly the same filesystems:
//!
//! ```text
//!   fsopen("tmpfs")            → fs-context fd
//!   fsconfig(fd, SET_STRING, "size", "64M") → retains a tmpfs option
//!   fsconfig(fd, CMD_CREATE)   → builds the configured TmpFs in the context
//!   fsmount(fd)                → detached-mount fd holding that fs
//!   move_mount(mfd, "", AT_FDCWD, "/mnt/x")  → registry().mount_arc(...)
//! ```
//!
//! `open_tree` / `open_tree_attr` / `fspick` grab an existing mount's fs via
//! `registry().fs_arc_at`. Mount attributes are ABI-validated but accepted as
//! `mount_setattr` applies the four attributes NARF's mount table carries
//! (RDONLY / NOSUID / NODEV / NOEXEC), which are the same `MNT_*` bits
//! `mount(2)` sets from `MS_*` and the same ones `mnt_want_write` and the
//! exec path already enforce. The atime family and NOSYMFOLLOW are
//! validated and then have nowhere to go — see `apply_mount_attr`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, FsInstance, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use crate::fd;
use crate::handlers::{
    apply_chroot, copy_from_user_vec, copy_user_cstr_checked, current_change_propagation,
    current_clone_mount_subtree, current_clone_tree_at, current_fs_arc_at, current_mount_arc,
    current_mount_flags_exact, current_mount_list, current_set_mount_flags, current_task_id,
    fd_path_for_task, mount_admin, parse_proc_self_fd, resolve_at_path, resolve_cwd_path,
    stat_path_dir_aware,
};
use crate::syscall::{SyscallReturn, TrapContext};

use crate::errno::to_ret as err;
use crate::errno::*;

fn ok(v: u64) -> SyscallReturn {
    SyscallReturn::ok(v)
}

// fsconfig(2) commands.
const FSCONFIG_SET_FLAG: u64 = 0;
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_SET_BINARY: u64 = 2;
const FSCONFIG_SET_PATH: u64 = 3;
const FSCONFIG_SET_PATH_EMPTY: u64 = 4;
const FSCONFIG_SET_FD: u64 = 5;
const FSCONFIG_CMD_CREATE: u64 = 6;
const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
/// Like CMD_CREATE but refuses to reuse an existing superblock. Every NARF
/// CMD_CREATE builds a fresh instance, so the two behave identically here.
const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;
// fsopen / fsmount / open_tree CLOEXEC bits.
const FSOPEN_CLOEXEC: u64 = 0x0000_0001;
const FSMOUNT_CLOEXEC: u64 = 0x0000_0001;
// fspick(2) flags (`include/uapi/linux/mount.h`).
const FSPICK_CLOEXEC: u64 = 0x0000_0001;
const FSPICK_SYMLINK_NOFOLLOW: u64 = 0x0000_0002;
const FSPICK_NO_AUTOMOUNT: u64 = 0x0000_0004;
const FSPICK_EMPTY_PATH: u64 = 0x0000_0008;
// move_mount(2) flags.
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x0000_0004;
const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x0000_0040;
const MOVE_MOUNT_SET_GROUP: u64 = 0x0000_0100;
const MOVE_MOUNT_BENEATH: u64 = 0x0000_0200;
const MOVE_MOUNT__MASK: u64 = 0x0000_0377;
const AT_FDCWD: i32 = -100;
const OPEN_TREE_CLOEXEC: u64 = 0o2000000; // O_CLOEXEC
const OPEN_TREE_CLONE: u64 = 0x0000_0001;
const OPEN_TREE_NAMESPACE: u64 = 0x0000_0002;
const AT_SYMLINK_NOFOLLOW: u64 = 0x0000_0100;
const AT_NO_AUTOMOUNT: u64 = 0x0000_0800;
const AT_EMPTY_PATH: u64 = 0x0000_1000;
const AT_RECURSIVE: u64 = 0x0000_8000;

const MOUNT_ATTR_SIZE_VER0: usize = 32;
const MOUNT_ATTR__ATIME: u64 = 0x0000_0070;
const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
const MOUNT_ATTR_STRICTATIME: u64 = 0x0000_0020;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
/// The four attributes NARF's mount table can actually carry, as
/// `filesystem::mnt_flags`. `mount(2)` already translates the matching
/// `MS_*` bits into these and enforces them (`mnt_want_write` refuses a
/// read-only mount, exec and suid consult the rest), so `mount_setattr`
/// setting them is the same knob reached from the newer syscall.
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
/// `MOUNT_ATTR_NOSYMFOLLOW` — a symlink on this mount is never followed.
/// `fs/namei.c` checks it in the same breath as `RESOLVE_NO_SYMLINKS`, so
/// the resolver honours both through one check.
const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;
const MOUNT_SETATTR_VALID_FLAGS: u64 = 0x0030_00ff;
const MOUNT_SETATTR_PROPAGATION_FLAGS: u64 = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20);
const PAGE_SIZE: usize = 4096;

/// A filesystem context under construction (fsopen / fspick).
struct FsContext {
    fsname: String,
    created: Option<Arc<dyn FsInstance>>,
    options: BTreeMap<String, Option<String>>,
    /// `fc->sb_flags` / `fc->sb_flags_mask`: what `vfs_parse_sb_flag` took
    /// out of the parameter stream (`ro`, `rw`, `sync`, ...). They never
    /// reach the filesystem; `reconfigure_super` applies them to the
    /// superblock.
    sb_flags: u64,
    sb_mask: u64,
    uid: u32,
    gid: u32,
    phase: CtxPhase,
}

/// `enum fs_context_phase` (`include/linux/fs_context.h`), reduced to the
/// states the syscalls can observe. Each fsconfig/fsmount step is legal in
/// exactly one phase and answers -EBUSY in the others (`fs/fsopen.c`):
/// a second CMD_CREATE, a parameter after CMD_CREATE, CMD_RECONFIGURE on an
/// fsopen context and a second fsmount are all -EBUSY on Linux 6.18.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CtxPhase {
    /// fsopen: parameters accepted, CMD_CREATE pending.
    CreateParams,
    /// A constructor is running with the context lock released.
    Creating,
    /// CMD_CREATE succeeded; only fsmount is legal.
    AwaitingMount,
    /// fspick, or after fsmount (`vfs_clean_context`): parameters and
    /// CMD_RECONFIGURE accepted.
    ReconfParams,
    /// A CMD_CREATE / CMD_RECONFIGURE failed; the context is dead.
    Failed,
}

/// Is `fd_no` an open descriptor at all? Used to split "no such descriptor"
/// (-EBADF) from "a descriptor of the wrong kind" (-EINVAL): `fs/fsopen.c`
/// tests `f_op != &fscontext_fops` only after `fd_empty(f)`.
fn fd_open(task: u64, fd_no: u32) -> bool {
    fd::with_table(task, |t| t.get(fd_no).is_some()).unwrap_or(false)
}

/// `strndup_user` answers an over-long string with -EINVAL, where
/// `copy_user_cstr_checked` gives the pathname answer (-ENAMETOOLONG).
fn strndup_errno(errno: i64) -> i64 {
    if errno == ENAMETOOLONG {
        EINVAL
    } else {
        errno
    }
}

/// `user_path_at(dfd, path, LOOKUP_EMPTY?, ...)` to the host (chroot-applied)
/// path NARF's mount table is keyed by. `raw` empty names `dfd` itself, which
/// the caller has already allowed (`AT_EMPTY_PATH` and friends); AT_FDCWD
/// then names the cwd. Errors are positive errno values.
fn resolve_at_mount_path(task: u64, dfd: u64, raw: &str) -> Result<String, i64> {
    let joined = if raw.is_empty() {
        if dfd as i32 == AT_FDCWD {
            String::from(".")
        } else {
            u32::try_from(dfd as i32)
                .ok()
                .and_then(|fd| fd_path_for_task(task, fd))
                .ok_or(EBADF)?
        }
    } else {
        resolve_at_path(task, dfd as i64, raw).map_err(|e| -e)?
    };
    let resolved = resolve_cwd_path(task, &joined);
    Ok(if resolved.len() > 1 {
        String::from(resolved.trim_end_matches('/'))
    } else {
        resolved
    })
}

/// `path_mounted()` after a successful lookup: Ok when `path` is the root
/// of a mount, -ENOENT when it names nothing, -EINVAL when it names
/// something that is not a mountpoint. Errors are positive errno values.
fn require_mountpoint(path: &str) -> Result<(), i64> {
    if current_mount_list().iter().any(|m| m == path) {
        return Ok(());
    }
    Err(if stat_path_dir_aware(path).is_some() {
        EINVAL
    } else {
        ENOENT
    })
}

/// A detached mount (fsmount / open_tree) awaiting move_mount.
#[derive(Clone)]
struct MountObject {
    fs: Arc<dyn FsInstance>,
    descendants: alloc::vec::Vec<(String, Arc<dyn FsInstance>)>,
}

static CONTEXTS: IrqSafeSpinLock<Option<BTreeMap<u64, FsContext>>> = IrqSafeSpinLock::new(None);
static MOUNTS: IrqSafeSpinLock<Option<BTreeMap<u64, MountObject>>> = IrqSafeSpinLock::new(None);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn with_contexts<R>(f: impl FnOnce(&mut BTreeMap<u64, FsContext>) -> R) -> R {
    let mut g = CONTEXTS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}
fn with_mounts<R>(f: impl FnOnce(&mut BTreeMap<u64, MountObject>) -> R) -> R {
    let mut g = MOUNTS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// Per-detached-mount attributes pending from `mount_setattr(fd, AT_EMPTY_PATH)`,
/// keyed by the same id as [`MOUNTS`]. NARF applies mount flags at the mount
/// POINT, but the new-mount-API sets a mount read-only (etc.) while it is still
/// detached, before `move_mount` gives it a path. Record it here and apply it in
/// `sys_move_mount` once the mount is attached.
///
/// The value is the detached mount's accumulated `MNT_*` set, not the last
/// request: `fsmount(fd, 0, MOUNT_ATTR_NODEV)` followed by
/// `mount_setattr(fd, "", AT_EMPTY_PATH, {RDONLY})` is a `nodev,ro` mount,
/// and keeping only the second request dropped the `nodev`.
static MOUNT_ATTRS: IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> = IrqSafeSpinLock::new(None);
fn with_mount_attrs<R>(f: impl FnOnce(&mut BTreeMap<u64, u64>) -> R) -> R {
    let mut g = MOUNT_ATTRS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// Fold `attr` into the detached mount `mid`'s pending flags.
fn record_detached_attr(mid: u64, attr: &MountAttr) {
    with_mount_attrs(|m| {
        let flags = mount_attr_to_mnt_flags(m.get(&mid).copied().unwrap_or(0), attr);
        m.insert(mid, flags);
    });
}

fn context_of(task: u64, fd_no: u32) -> Option<u64> {
    fd::with_table(task, |t| t.get(fd_no).and_then(|e| e.ops.fs_context_id())).flatten()
}
fn mount_of(task: u64, fd_no: u32) -> Option<u64> {
    fd::with_table(task, |t| t.get(fd_no).and_then(|e| e.ops.mount_object_id())).flatten()
}

/// Convenience wrapper for filesystem consumers without mount options.
pub fn build_fs(fsname: &str) -> Option<Arc<dyn FsInstance>> {
    build_fs_with_options(fsname, "", 0, 0).ok().flatten()
}

/// Construct from the shared type registry, outside all mount/context locks.
pub fn build_fs_with_options(
    fsname: &str,
    options: &str,
    uid: u32,
    gid: u32,
) -> Result<Option<Arc<dyn FsInstance>>, FsError> {
    build_fs_from_source(fsname, "", options, uid, gid)
}

fn build_fs_from_source(
    fsname: &str,
    source: &str,
    options: &str,
    uid: u32,
    gid: u32,
) -> Result<Option<Arc<dyn FsInstance>>, FsError> {
    crate::handlers::mount_types::register_mount_types();
    let Some(fs_type) = narf_filesystem::lookup_fstype(fsname) else {
        return Ok(None);
    };
    let source = apply_chroot(source);
    fs_type
        .init(&narf_filesystem::MountRequest {
            fs_type: fsname,
            source: &source,
            options,
            uid,
            gid,
            initial_namespace: crate::handlers::current_mount_namespace().is_none(),
        })
        .map(Some)
}

/// Errors from filesystem construction/attachment are independent of the ABI.
pub(crate) fn mount_error_errno(error: FsError) -> i64 {
    match error {
        FsError::NotFound => ENOENT,
        FsError::Busy => EBUSY,
        FsError::PermissionDenied | FsError::OperationNotPermitted => EPERM,
        FsError::NoSpace => ENOSPC,
        FsError::Unsupported => EOPNOTSUPP,
        _ => EINVAL,
    }
}

fn context_options(context: &FsContext) -> String {
    let mut rendered = String::new();
    for (key, value) in context
        .options
        .iter()
        .filter(|(key, _)| key.as_str() != "source")
    {
        if !rendered.is_empty() {
            rendered.push(',');
        }
        rendered.push_str(key);
        if let Some(value) = value {
            rendered.push('=');
            rendered.push_str(value);
        }
    }
    rendered
}

/// The filesystem-specific half of a reconfiguration. The superblock keys
/// (`ro`, `rw`, `sync`, ...) were already taken out of the stream when they
/// were set — see [`FsContext::sb_flags`]. `noswap` is tmpfs's own:
/// `shmem_reconfigure` refuses to switch it ON by reconfiguration ("Cannot
/// disable swap on remount") but accepts a repeat on a noswap instance.
/// NARF's tmpfs takes it only at creation, and systemd's credentials fs
/// repeats it before its read-only reconfigure (`exec-credential.c`), so it
/// is dropped here. LINUX-GAP: a first-time `noswap` on reconfigure is
/// accepted rather than refused.
fn filesystem_reconfigure_options(context: &FsContext) -> String {
    context
        .options
        .iter()
        .filter(|(key, _)| key.as_str() != "source" && key.as_str() != "noswap")
        .fold(String::new(), |mut rendered, (key, value)| {
            if !rendered.is_empty() {
                rendered.push(',');
            }
            rendered.push_str(key);
            if let Some(value) = value {
                rendered.push('=');
                rendered.push_str(value);
            }
            rendered
        })
}

/// `fs/super.c::reconfigure_super`, shared by `fsconfig(CMD_RECONFIGURE)`
/// and `mount(2)`'s `MS_REMOUNT` (`do_remount`), in its order:
///
/// ```text
/// if (fc->sb_flags_mask & ~MS_RMT_MASK) return -EINVAL;
/// ...
/// if (fc->ops->reconfigure) { retval = fc->ops->reconfigure(fc); ... }
/// WRITE_ONCE(sb->s_flags, ((sb->s_flags & ~fc->sb_flags_mask) |
///                          (fc->sb_flags & fc->sb_flags_mask)));
/// ```
///
/// `fs_options` is the filesystem's own parameter string (the superblock
/// keys already taken out). A filesystem that takes no parameters rejects
/// any: `vfs_parse_fs_param`'s `"%s: Unknown parameter '%s'"` -EINVAL,
/// which NARF's filesystems report as `FsError::Unsupported` from
/// `reconfigure`. Errors are positive errno values.
///
/// LINUX-GAP: a read-write -> read-only transition does not run
/// `sb_prepare_remount_readonly` (NARF does not count a superblock's
/// writers), so it never answers -EBUSY for a file still open for write.
pub(crate) fn reconfigure_super(
    fs: &Arc<dyn FsInstance>,
    sb_flags: u64,
    sb_mask: u64,
    fs_options: &str,
) -> Result<(), i64> {
    use narf_filesystem::sb_flags as sb;
    if sb_mask & !sb::RMT_MASK != 0 {
        return Err(EINVAL);
    }
    // `reconfigure_super` always calls the filesystem's `->reconfigure`: a
    // devpts remount with no options resets every option to its default
    // (`devpts_reconfigure`). A filesystem with no reconfigure op ignores an
    // empty parameter list; given parameters it rejects them.
    match fs.reconfigure(fs_options) {
        Ok(()) => {}
        Err(FsError::Unsupported) if fs_options.is_empty() => {}
        Err(FsError::NoSpace) => return Err(ENOSPC),
        Err(_) => return Err(EINVAL),
    }
    if sb_mask != 0 {
        sb::update(fs, sb_flags, sb_mask);
    }
    Ok(())
}

/// `fs/fs_context.c::vfs_parse_monolithic_sep` over a legacy `mount(2)`
/// `data` string: split on commas (a double-quoted value may contain one),
/// hand each key to `vfs_parse_sb_flag`, and keep the rest for the
/// filesystem. Returns `(sb_set, sb_clear, fs_options)`.
pub(crate) fn split_monolithic_options(data: &str) -> (u64, u64, String) {
    let (mut set, mut clear) = (0u64, 0u64);
    let mut rest = String::new();
    let mut in_quote = false;
    let mut start = 0usize;
    let bytes = data.as_bytes();
    let take = |item: &str, set: &mut u64, clear: &mut u64, rest: &mut String| {
        if item.is_empty() {
            return;
        }
        let key = item.split_once('=').map_or(item, |(key, _)| key);
        match narf_filesystem::sb_flags::parse_key(key) {
            Some((s, c)) => {
                *set = (*set | s) & !c;
                *clear = (*clear | c) & !s;
            }
            None => {
                if !rest.is_empty() {
                    rest.push(',');
                }
                rest.push_str(item);
            }
        }
    };
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b',' if !in_quote => {
                take(&data[start..i], &mut set, &mut clear, &mut rest);
                start = i + 1;
            }
            _ => {}
        }
    }
    take(&data[start..], &mut set, &mut clear, &mut rest);
    (set, clear, rest)
}

// ── fd-backed handles ───────────────────────────────────────────────
struct FsContextFile {
    id: u64,
}
struct MountObjectFile {
    id: u64,
    /// The inode the fd names. Linux `fsmount` and `open_tree` hand back
    /// `dentry_open(path, O_PATH)` of the mount's root (`fs/namespace.c`),
    /// so the fd `fstat`s as that directory, not as an anonymous inode.
    root: narf_filesystem::inode_id::InodeId,
}

/// `(st_dev, st_ino)` of a directory, as `stat(2)` of it reports.
fn dir_identity(dir: &Arc<dyn narf_filesystem::DirOps>) -> narf_filesystem::inode_id::InodeId {
    narf_filesystem::inode_id::InodeId {
        dev: dir.inode_attrs().dev,
        ino: dir.ino(),
    }
}

macro_rules! stub_fileops {
    ($ty:ty, $hook:ident) => {
        impl FileOps for $ty {
            fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
                alloc::boxed::Box::pin(async { Err(FsError::InvalidData) })
            }
            fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> FsFuture<'a, usize> {
                alloc::boxed::Box::pin(async { Err(FsError::InvalidData) })
            }
            fn stat(&self) -> Stat {
                Stat {
                    size: 0,
                    blocks: 0,
                    mode: Mode::FILE_RW,
                    mtime_cycles: 0,
                }
            }
            fn $hook(&self) -> Option<u64> {
                Some(self.id)
            }
            /// Linux `fsopen`/`fspick` use `anon_inode_getfd("[fscontext]")`:
            /// the one shared `anon_inodefs` inode.
            fn ino(&self) -> u64 {
                narf_filesystem::inode_id::anon_inode().ino
            }
            fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
                narf_filesystem::inode_id::anon_inode().attrs()
            }
        }
    };
}
stub_fileops!(FsContextFile, fs_context_id);

impl FileOps for MountObjectFile {
    fn ino(&self) -> u64 {
        self.root.ino
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.root.attrs()
    }

    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(FsError::InvalidData) })
    }

    fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::DIR_RO,
            mtime_cycles: 0,
        }
    }

    fn mount_object_id(&self) -> Option<u64> {
        Some(self.id)
    }
}

fn install_fd(file: Arc<dyn FileOps>, cloexec: bool) -> Option<u32> {
    let flags = if cloexec { fd::FD_CLOEXEC } else { 0 };
    fd::install(
        current_task_id(),
        fd::FdEntry {
            ops: file,
            offset: 0,
            flags,
            status_flags: 0,
        },
    )
}

fn validate_open_tree_flags(flags: u64) -> Result<(), i64> {
    const ALLOWED: u64 = AT_EMPTY_PATH
        | AT_NO_AUTOMOUNT
        | AT_RECURSIVE
        | AT_SYMLINK_NOFOLLOW
        | OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC
        | OPEN_TREE_NAMESPACE;
    if flags & !ALLOWED != 0 {
        return Err(EINVAL);
    }
    if flags & AT_RECURSIVE != 0 && flags & (OPEN_TREE_CLONE | OPEN_TREE_NAMESPACE) == 0 {
        return Err(EINVAL);
    }
    if flags & OPEN_TREE_CLONE != 0 && flags & OPEN_TREE_NAMESPACE != 0 {
        return Err(EINVAL);
    }
    // NARF has task-private mount tables but no mount-namespace file object
    // matching Linux's OPEN_TREE_NAMESPACE return contract yet.
    if flags & OPEN_TREE_NAMESPACE != 0 {
        return Err(EOPNOTSUPP);
    }
    Ok(())
}

/// Copy and validate Linux's extensible `struct mount_attr`.
///
/// This mirrors `wants_mount_setattr()` / `copy_struct_from_user()` errno
/// behavior: a short version is EINVAL, a version larger than one page is
/// E2BIG, an inaccessible byte is EFAULT, and a non-zero unknown extension is
/// E2BIG. Attribute values are validated even though NARF currently treats
/// the supported per-mount settings as compatibility no-ops.
/// The parsed, validated `struct mount_attr`.
#[derive(Clone, Copy)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
}

impl MountAttr {
    /// `if (attr.attr_set == 0 && attr.attr_clr == 0 && attr.propagation ==
    /// 0) return 0;` — "Don't bother walking through the mounts if this is a
    /// nop." The path is then never resolved, so it cannot fail either.
    fn is_nop(&self) -> bool {
        self.attr_set == 0 && self.attr_clr == 0 && self.propagation == 0
    }
}

fn validate_mount_attr(ptr: u64, size: usize, idmap_replace: bool) -> Result<MountAttr, i64> {
    if size > PAGE_SIZE {
        return Err(E2BIG);
    }
    if size < MOUNT_ATTR_SIZE_VER0 {
        return Err(EINVAL);
    }
    // `if (!may_mount()) return -EPERM;` — after the size checks and before
    // the struct is read, which is where `wants_mount_setattr` puts it.
    // `may_mount()` is `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)`: the
    // MOUNT namespace's owner, not the host, so a container that unshared
    // its own mount namespace may still change attributes inside it.
    if !mount_admin(current_task_id()) {
        return Err(EPERM);
    }
    // SAFETY: copy_from_user_vec validates the complete caller-provided range
    // and converts guarded-copy faults into errno without dereferencing it here.
    let bytes = unsafe { copy_from_user_vec(ptr, size) }.map_err(|_| EFAULT)?;
    if bytes[MOUNT_ATTR_SIZE_VER0..].iter().any(|&byte| byte != 0) {
        return Err(E2BIG);
    }

    let field = |offset: usize| {
        u64::from_ne_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("mount_attr field has fixed width"),
        )
    };
    let attr_set = field(0);
    let attr_clr = field(8);
    let propagation = field(16);
    let userns_fd = field(24);

    if propagation & !MOUNT_SETATTR_PROPAGATION_FLAGS != 0
        || (propagation & MOUNT_SETATTR_PROPAGATION_FLAGS).count_ones() > 1
    {
        return Err(EINVAL);
    }
    if (attr_set | attr_clr) & !MOUNT_SETATTR_VALID_FLAGS != 0 {
        return Err(EINVAL);
    }
    if attr_clr & MOUNT_ATTR__ATIME != 0 {
        if attr_clr & MOUNT_ATTR__ATIME != MOUNT_ATTR__ATIME
            || !matches!(
                attr_set & MOUNT_ATTR__ATIME,
                0 | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME
            )
        {
            return Err(EINVAL);
        }
    } else if attr_set & MOUNT_ATTR__ATIME != 0 {
        return Err(EINVAL);
    }

    if (attr_set | attr_clr) & MOUNT_ATTR_IDMAP != 0 {
        if attr_clr & MOUNT_ATTR_IDMAP != 0 && !idmap_replace {
            return Err(EINVAL);
        }
        // `build_mount_idmapped`: "Removal of idmappings is equivalent to
        // setting nop_mnt_idmap" — a clear without a set returns 0 before
        // `userns_fd` is looked at (probed on 6.18: open_tree_attr(CLONE)
        // clearing IDMAP with a closed userns_fd succeeds). NARF mounts are
        // never idmapped, so there is nothing to remove.
        if attr_clr & MOUNT_ATTR_IDMAP != 0 && attr_set & MOUNT_ATTR_IDMAP == 0 {
            return Ok(MountAttr {
                attr_set,
                attr_clr,
                propagation,
            });
        }
        if userns_fd > i32::MAX as u64 {
            return Err(EINVAL);
        }
        // NARF does not expose Linux user-namespace fds, so a numerically
        // valid descriptor cannot satisfy the proc-ns-file requirement.
        let exists = fd::with_table(current_task_id(), |table| {
            table.get(userns_fd as u32).is_some()
        })
        .unwrap_or(false);
        return Err(if exists { EINVAL } else { EBADF });
    }

    Ok(MountAttr {
        attr_set,
        attr_clr,
        propagation,
    })
}

struct ReturnCapture<'a> {
    inner: &'a mut dyn TrapContext,
    ret: Option<SyscallReturn>,
}

impl TrapContext for ReturnCapture<'_> {
    fn args(&self) -> &crate::syscall::SyscallArgs {
        self.inner.args()
    }

    fn set_return(&mut self, ret: SyscallReturn) {
        self.ret = Some(ret);
    }

    fn user_rsp(&self) -> u64 {
        self.inner.user_rsp()
    }

    fn rip(&self) -> u64 {
        self.inner.rip()
    }

    fn set_rip(&mut self, rip: u64) {
        self.inner.set_rip(rip);
    }

    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        self.inner.redirect_to_kernel(rip, rsp)
    }
}

fn discard_open_tree_fd(task: u64, fd_no: u32) {
    let mount_id = mount_of(task, fd_no);
    fd::with_table(task, |table| table.close(fd_no));
    if let Some(mount_id) = mount_id {
        with_mounts(|mounts| mounts.remove(&mount_id));
    }
}

/// `fsopen(fsname, flags)` → fs-context fd.
///
/// `fs/fsopen.c::SYSCALL_DEFINE2(fsopen)`, in order:
///
/// ```text
/// if (!may_mount())               return -EPERM;
/// if (flags & ~FSOPEN_CLOEXEC)    return -EINVAL;
/// fs_name = strndup_user(_fs_name, PAGE_SIZE);   /* -EFAULT / -EINVAL */
/// fs_type = get_fs_type(fs_name);
/// if (!fs_type)                   return -ENODEV;
/// ```
///
/// This accepted any flags, any name (reporting a faulting pointer as
/// -EINVAL) and deferred an unknown fstype to CMD_CREATE, so a caller probing
/// "does this kernel have fstype X" with fsopen got a context back for
/// anything.
pub fn sys_fsopen(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    if !mount_admin(current_task_id()) {
        ctx.set_return(err(EPERM));
        return;
    }
    if a.arg1 as u32 as u64 & !FSOPEN_CLOEXEC != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let fsname = match copy_user_cstr_checked(a.arg0, PAGE_SIZE) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(err(strndup_errno(errno)));
            return;
        }
    };
    // `get_fs_type`: the same dispatch CMD_CREATE builds from, so the two
    // agree on which names exist ("" included — it names no filesystem).
    let (uid, gid) = crate::handlers::current_fs_ids();
    crate::handlers::mount_types::register_mount_types();
    if narf_filesystem::lookup_fstype(&fsname).is_none() {
        ctx.set_return(err(ENODEV));
        return;
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_contexts(|m| {
        m.insert(
            id,
            FsContext {
                fsname,
                created: None,
                options: BTreeMap::new(),
                sb_flags: 0,
                sb_mask: 0,
                uid,
                gid,
                phase: CtxPhase::CreateParams,
            },
        )
    });
    match install_fd(Arc::new(FsContextFile { id }), a.arg1 & FSOPEN_CLOEXEC != 0) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => {
            // `fs/namespace.c` and `fs/fsopen.c` publish these descriptors with
            // `FD_PREPARE`, i.e. `get_unused_fd_flags`: a table at
            // RLIMIT_NOFILE is -EMFILE. -EBADF here would blame the caller's
            // fd arguments, which had already resolved successfully.
            ctx.set_return(err(EMFILE));
        }
    }
}

/// `fsconfig(fd, cmd, key, value, aux)`.
///
/// `fs/fsopen.c::SYSCALL_DEFINE5(fsconfig)` validates in this order, and
/// every step was missing or out of place here:
///
/// ```text
/// switch (cmd) {            /* argument shape, before the fd is touched */
/// case FSCONFIG_SET_FLAG:   if (!_key || _value || aux)        return -EINVAL;
/// case FSCONFIG_SET_STRING: if (!_key || !_value || aux)       return -EINVAL;
/// case FSCONFIG_SET_BINARY: if (!_key || !_value || aux <= 0 || aux > 1M) ...
/// case FSCONFIG_SET_PATH[_EMPTY]: if (!_key || !_value ||
///                                     (aux != AT_FDCWD && aux < 0)) ...
/// case FSCONFIG_SET_FD:     if (!_key || _value || aux < 0)    return -EINVAL;
/// case FSCONFIG_CMD_CREATE[_EXCL] / _RECONFIGURE:
///                           if (_key || _value || aux)         return -EINVAL;
/// default:                                                     return -EOPNOTSUPP;
/// }
/// if (fd_empty(f))                          return -EBADF;
/// if (fd_file(f)->f_op != &fscontext_fops)  return -EINVAL;
/// param.key = strndup_user(_key, 256);      /* -EFAULT / -EINVAL */
/// SET_STRING: strndup_user(_value, 256); SET_BINARY: memdup_user_nul;
/// SET_PATH*: getname_flags(); SET_FD: fget(aux) or -EBADF;
/// vfs_fsconfig_locked(): phase checks -> -EBUSY
/// ```
///
/// An unknown command used to return 0, and CMD_CREATE_EXCL was one of them:
/// a caller asking for an exclusive superblock was told it had one while
/// nothing was built. All of the above was probed on Linux 6.18.
pub fn sys_fsconfig(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let (cmd, key_ptr, value_ptr) = (a.arg1 as u32 as u64, a.arg2, a.arg3);
    let aux = a.arg4 as i32;
    let bad_shape = match cmd {
        FSCONFIG_SET_FLAG => key_ptr == 0 || value_ptr != 0 || aux != 0,
        FSCONFIG_SET_STRING => key_ptr == 0 || value_ptr == 0 || aux != 0,
        FSCONFIG_SET_BINARY => key_ptr == 0 || value_ptr == 0 || aux <= 0 || aux > 1024 * 1024,
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            key_ptr == 0 || value_ptr == 0 || (aux != AT_FDCWD && aux < 0)
        }
        FSCONFIG_SET_FD => key_ptr == 0 || value_ptr != 0 || aux < 0,
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL | FSCONFIG_CMD_RECONFIGURE => {
            key_ptr != 0 || value_ptr != 0 || aux != 0
        }
        _ => {
            ctx.set_return(err(EOPNOTSUPP));
            return;
        }
    };
    if bad_shape {
        ctx.set_return(err(EINVAL));
        return;
    }
    let fd_no = a.arg0 as u32;
    let id = match context_of(task, fd_no) {
        Some(id) => id,
        None => {
            ctx.set_return(err(if fd_open(task, fd_no) { EINVAL } else { EBADF }));
            return;
        }
    };
    // Copy the key and value exactly as the kernel stages them.
    let key = if key_ptr != 0 {
        match copy_user_cstr_checked(key_ptr, 256) {
            Ok(key) => Some(key),
            Err(errno) => {
                ctx.set_return(err(strndup_errno(errno)));
                return;
            }
        }
    } else {
        None
    };
    let value: Option<String> = match cmd {
        FSCONFIG_SET_STRING => match copy_user_cstr_checked(value_ptr, 256) {
            Ok(value) => Some(value),
            Err(errno) => {
                ctx.set_return(err(strndup_errno(errno)));
                return;
            }
        },
        FSCONFIG_SET_BINARY => {
            // `memdup_user_nul(_value, aux)`: a blob of exactly `aux` bytes.
            // SAFETY: copy_from_user_vec validates the whole user range.
            match unsafe { copy_from_user_vec(value_ptr, aux as usize) } {
                Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
                Err(_) => {
                    ctx.set_return(err(EFAULT));
                    return;
                }
            }
        }
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            // `getname_flags`: an empty name is -ENOENT unless the
            // _EMPTY form passed LOOKUP_EMPTY.
            match copy_user_cstr_checked(value_ptr, 4096) {
                Ok(path) if path.is_empty() && cmd == FSCONFIG_SET_PATH => {
                    ctx.set_return(err(ENOENT));
                    return;
                }
                Ok(path) => Some(path),
                Err(errno) => {
                    ctx.set_return(err(errno));
                    return;
                }
            }
        }
        FSCONFIG_SET_FD => {
            // `param.file = fget(aux); if (!param.file) -> -EBADF`.
            if !fd_open(task, aux as u32) {
                ctx.set_return(err(EBADF));
                return;
            }
            None
        }
        _ => None,
    };
    match cmd {
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => {
            // Materialize the filesystem named by fsopen. `vfs_cmd_create`:
            // `if (fc->phase != FS_CONTEXT_CREATE_PARAMS) return -EBUSY;`,
            // and a failed `vfs_get_tree` leaves the context FAILED.
            // Claim the context, then release its IRQ-safe lock before the
            // constructor can wait for I/O or consult task namespace state.
            let inputs = with_contexts(|m| {
                let c = m.get_mut(&id)?;
                if c.phase != CtxPhase::CreateParams {
                    return Some(Err(()));
                }
                c.phase = CtxPhase::Creating;
                Some(Ok((
                    c.fsname.clone(),
                    c.options
                        .get("source")
                        .and_then(Clone::clone)
                        .unwrap_or_default(),
                    context_options(c),
                    c.uid,
                    c.gid,
                )))
            });
            let (name, source, options, uid, gid) = match inputs {
                Some(Ok(inputs)) => inputs,
                Some(Err(())) => {
                    ctx.set_return(err(EBUSY));
                    return;
                }
                None => {
                    ctx.set_return(err(EBADF));
                    return;
                }
            };
            let built = build_fs_from_source(&name, &source, &options, uid, gid);
            let r = with_contexts(|m| {
                let c = m.get_mut(&id)?;
                c.phase = if matches!(built, Ok(Some(_))) {
                    CtxPhase::AwaitingMount
                } else {
                    CtxPhase::Failed
                };
                match built {
                    Ok(Some(fs)) => {
                        if c.sb_mask != 0 {
                            narf_filesystem::sb_flags::update(&fs, c.sb_flags, c.sb_mask);
                        }
                        c.created = Some(fs);
                        Some(Ok(true))
                    }
                    Ok(None) => Some(Ok(false)),
                    Err(error) => Some(Err(error)),
                }
            });
            match r {
                Some(Ok(true)) => ctx.set_return(ok(0)),
                Some(Ok(false)) => ctx.set_return(err(ENODEV)),
                Some(Err(error)) => ctx.set_return(err(mount_error_errno(error))),
                None => ctx.set_return(err(EBADF)),
            }
        }
        // CMD_RECONFIGURE applies retained options to the selected live fs.
        // `vfs_cmd_reconfigure`: only from FS_CONTEXT_RECONF_PARAMS (fspick,
        // or after fsmount), else -EBUSY; a failure leaves the context FAILED.
        FSCONFIG_CMD_RECONFIGURE => {
            let result = with_contexts(|m| {
                let context = m.get_mut(&id)?;
                if context.phase != CtxPhase::ReconfParams {
                    return Some(Err(None));
                }
                let fs = context.created.clone()?;
                let options = filesystem_reconfigure_options(context);
                let result = reconfigure_super(&fs, context.sb_flags, context.sb_mask, &options);
                match result {
                    // `vfs_clean_context`: the filesystem's parameters and
                    // `sb_flags` are dropped, the phase returns to taking
                    // parameters. `sb_flags_mask` is NOT reset there, so a
                    // second bare CMD_RECONFIGURE re-applies the masked bits
                    // from the now-zero `sb_flags` — Linux's behaviour too.
                    Ok(()) => {
                        context.options.clear();
                        context.sb_flags = 0;
                    }
                    Err(_) => context.phase = CtxPhase::Failed,
                }
                Some(result.map_err(Some))
            });
            match result {
                Some(Ok(())) => ctx.set_return(ok(0)),
                Some(Err(None)) => ctx.set_return(err(EBUSY)),
                Some(Err(Some(errno))) => ctx.set_return(err(errno)),
                None => ctx.set_return(err(EBADF)),
            }
        }
        // Retain configuration options for CMD_CREATE/CMD_RECONFIGURE.
        // Parameters are accepted only while the context takes them:
        // `if (fc->phase != FS_CONTEXT_CREATE_PARAMS && fc->phase !=
        // FS_CONTEXT_RECONF_PARAMS) return -EBUSY;`.
        _ => {
            let Some(key) = key else {
                ctx.set_return(err(EINVAL));
                return;
            };
            let r = with_contexts(|m| {
                let context = m.get_mut(&id)?;
                if !matches!(
                    context.phase,
                    CtxPhase::CreateParams | CtxPhase::ReconfParams
                ) {
                    return Some(false);
                }
                // `vfs_parse_fs_param` offers every key to
                // `vfs_parse_sb_flag` first: `ro`/`rw`/`sync`/... are
                // superblock flags, consumed here, and the filesystem never
                // sees them as parameters.
                match narf_filesystem::sb_flags::parse_key(&key) {
                    Some((set, clear)) => {
                        context.sb_flags = (context.sb_flags | set) & !clear;
                        context.sb_mask |= set | clear;
                    }
                    None => {
                        context.options.insert(key, value);
                    }
                }
                Some(true)
            });
            ctx.set_return(match r {
                Some(true) => ok(0),
                Some(false) => err(EBUSY),
                None => err(EBADF),
            });
        }
    }
}

/// `fsmount(fs_fd, flags, attr_flags)` → detached-mount fd.
///
/// `fs/namespace.c::SYSCALL_DEFINE3(fsmount)`, in order:
///
/// ```text
/// if (!may_mount())                              return -EPERM;
/// if ((flags & ~(FSMOUNT_CLOEXEC)) != 0)         return -EINVAL;
/// if (attr_flags & ~FSMOUNT_VALID_FLAGS)         return -EINVAL;
/// switch (attr_flags & MOUNT_ATTR__ATIME) {
/// case STRICTATIME: case NOATIME: case RELATIME(0): break;
/// default:                                       return -EINVAL; }
/// if (fd_empty(f))                               return -EBADF;
/// if (fd_file(f)->f_op != &fscontext_fops)       return -EINVAL;
/// if (!fc->root)                                 return -EINVAL;
/// if (fc->phase != FS_CONTEXT_AWAITING_MOUNT)    return -EBUSY;
/// ...  vfs_clean_context(fc);  /* -> FS_CONTEXT_RECONF_PARAMS */
/// ```
///
/// None of the flag checks or the phase test existed, and `attr_flags` was
/// dropped: `fsmount(fd, 0, MOUNT_ATTR_RDONLY)` produced a writable mount.
pub fn sys_fsmount(ctx: &mut dyn TrapContext) {
    const FSMOUNT_VALID_FLAGS: u64 = MOUNT_ATTR_RDONLY
        | MOUNT_ATTR_NOSUID
        | MOUNT_ATTR_NODEV
        | MOUNT_ATTR_NOEXEC
        | MOUNT_ATTR__ATIME
        | 0x0000_0080 // MOUNT_ATTR_NODIRATIME
        | MOUNT_ATTR_NOSYMFOLLOW;
    let a = *ctx.args();
    let task = current_task_id();
    if !mount_admin(task) {
        ctx.set_return(err(EPERM));
        return;
    }
    let flags = a.arg1 as u32 as u64;
    let attr_flags = a.arg2 as u32 as u64;
    if flags & !FSMOUNT_CLOEXEC != 0
        || attr_flags & !FSMOUNT_VALID_FLAGS != 0
        || !matches!(
            attr_flags & MOUNT_ATTR__ATIME,
            0 | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME
        )
    {
        ctx.set_return(err(EINVAL));
        return;
    }
    let fd_no = a.arg0 as u32;
    let id = match context_of(task, fd_no) {
        Some(id) => id,
        None => {
            ctx.set_return(err(if fd_open(task, fd_no) { EINVAL } else { EBADF }));
            return;
        }
    };
    let fs = with_contexts(|m| {
        let c = m.get_mut(&id)?;
        // fsconfig(CMD_CREATE) wasn't called (or failed): no root.
        let Some(fs) = c.created.clone() else {
            return Some(Err(EINVAL));
        };
        if c.phase != CtxPhase::AwaitingMount {
            return Some(Err(EBUSY));
        }
        c.phase = CtxPhase::ReconfParams;
        Some(Ok(fs))
    });
    let fs = match fs {
        Some(Ok(fs)) => fs,
        Some(Err(errno)) => {
            ctx.set_return(err(errno));
            return;
        }
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let root = dir_identity(&fs.root());
    let mid = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_mounts(|m| {
        m.insert(
            mid,
            MountObject {
                fs,
                descendants: alloc::vec::Vec::new(),
            },
        )
    });
    // The detached mount carries `attr_flags` from birth. NARF applies mount
    // flags at the mount POINT, so record them the way
    // `mount_setattr(fd, AT_EMPTY_PATH)` does and let `move_mount` land them.
    // `fsmount`'s atime switch is total — `MOUNT_ATTR_RELATIME` (0) is
    // `mnt_flags |= MNT_RELATIME` — so the whole atime field is replaced,
    // which is what clearing `MOUNT_ATTR__ATIME` first expresses.
    record_detached_attr(
        mid,
        &MountAttr {
            attr_set: attr_flags,
            attr_clr: MOUNT_ATTR__ATIME,
            propagation: 0,
        },
    );
    match install_fd(
        Arc::new(MountObjectFile { id: mid, root }),
        flags & FSMOUNT_CLOEXEC != 0,
    ) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => {
            // `fs/namespace.c` and `fs/fsopen.c` publish these descriptors with
            // `FD_PREPARE`, i.e. `get_unused_fd_flags`: a table at
            // RLIMIT_NOFILE is -EMFILE. -EBADF here would blame the caller's
            // fd arguments, which had already resolved successfully.
            ctx.set_return(err(EMFILE));
        }
    }
}

/// `move_mount(from_dfd, from_path, to_dfd, to_path, flags)`.
///
/// `fs/namespace.c::SYSCALL_DEFINE5(move_mount)` resolves the TARGET before
/// it looks at the source at all:
///
/// ```text
/// if (!may_mount())                                   return -EPERM;
/// if (flags & ~MOVE_MOUNT__MASK)                      return -EINVAL;
/// if (BENEATH and SET_GROUP both set)                 return -EINVAL;
/// to_name = getname_maybe_null(to_pathname, T_EMPTY_PATH ? AT_EMPTY_PATH : 0);
/// ... to_dfd / filename_lookup(to_dfd, to_name)       /* -EBADF/-ENOENT */
/// from_name = getname_maybe_null(from_pathname, F_EMPTY_PATH ? ...);
/// if (!from_name && from_dfd >= 0) { fd_empty -> -EBADF;
///         return vfs_move_mount(&f_path, &to_path); }
/// filename_lookup(from_dfd, from_name) ... vfs_move_mount()
/// ```
///
/// So a closed source fd with a missing target is -ENOENT, an empty name
/// without its `*_EMPTY_PATH` flag is -ENOENT, and a descriptor that is not a
/// mount is `do_move_mount`'s -EINVAL — all probed on Linux 6.18. This
/// handler used to answer EBADF first for every source fd it did not own,
/// EINVAL for a faulting or relative target, and had no privilege check.
///
/// LINUX-GAP: the target is not required to exist (see sys_mount's doc for
/// why the flat mount table cannot yet answer that for every fixture).
pub fn sys_move_mount(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    if !mount_admin(task) {
        ctx.set_return(err(EPERM));
        return;
    }
    let flags = a.arg4 as u32 as u64;
    if flags & !MOVE_MOUNT__MASK != 0
        || flags & (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)
            == (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)
    {
        ctx.set_return(err(EINVAL));
        return;
    }
    // `getname_maybe_null`: with the *_EMPTY_PATH flag a NULL or empty name
    // means "the dfd itself"; without it an empty name is -ENOENT.
    let copy_name = |ptr: u64, empty_ok: bool| -> Result<String, i64> {
        if empty_ok && ptr == 0 {
            return Ok(String::new());
        }
        let name = copy_user_cstr_checked(ptr, 4096)?;
        if name.is_empty() && !empty_ok {
            return Err(ENOENT);
        }
        Ok(name)
    };
    let to_path = match copy_name(a.arg3, flags & MOVE_MOUNT_T_EMPTY_PATH != 0) {
        Ok(name) => name,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    // mount(8) commonly creates the target directory as an O_PATH fd and
    // gives move_mount() its `/proc/self/fd/N` magic-link spelling.  Resolve
    // that spelling before applying the task root, just as sys_mount does:
    // attaching it literally below procfs makes the syscall report success
    // while systemd's subsequent /proc/self/mountinfo scan cannot find its
    // `Where=` path.
    let target_path = parse_proc_self_fd(to_path.as_str())
        .and_then(|fd| fd_path_for_task(task, fd))
        .filter(|path| path.starts_with('/'))
        .unwrap_or(to_path);
    // A relative target resolves against `to_dfd`, as for any *at call.
    let target = match resolve_at_mount_path(task, a.arg2, &target_path) {
        Ok(target) => target,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    let from_path = match copy_name(a.arg1, flags & MOVE_MOUNT_F_EMPTY_PATH != 0) {
        Ok(name) => name,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    let auth = narf_filesystem::bootstrap_mount_authority();
    // from_dfd is normally the detached-mount fd from fsmount / open_tree.
    let from_fd = a.arg0 as u32;
    let mid = match mount_of(task, from_fd) {
        Some(id) => id,
        None if !from_path.is_empty() => {
            // The path form moves an ATTACHED mount, as `mount(MS_MOVE)` does:
            // -ENOENT for a source that names nothing, -EINVAL for one that
            // is not the root of a mount.
            let source = match resolve_at_mount_path(task, a.arg0, &from_path) {
                Ok(source) => source,
                Err(errno) => {
                    ctx.set_return(err(errno));
                    return;
                }
            };
            if let Err(errno) = require_mountpoint(&source) {
                ctx.set_return(err(errno));
                return;
            }
            ctx.set_return(
                match crate::handlers::current_move_mount(&auth, &source, &target) {
                    Ok(()) => ok(0),
                    Err(FsError::Busy) => err(EBUSY),
                    Err(_) => err(EINVAL),
                },
            );
            return;
        }
        // An open descriptor that is not a mount NARF can move is
        // `do_move_mount`'s "not a mount" -EINVAL; a closed one is -EBADF.
        None => {
            ctx.set_return(err(if fd_open(task, from_fd) {
                EINVAL
            } else {
                EBADF
            }));
            return;
        }
    };
    let mount = match with_mounts(|m| m.get(&mid).cloned()) {
        Some(mount) => mount,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    if current_mount_arc(&auth, &target, mount.fs).is_err() {
        ctx.set_return(err(EBUSY));
        return;
    }
    // Apply any attrs recorded by `mount_setattr(fd, AT_EMPTY_PATH)` while this
    // mount was detached — it now has a mount point, so the flags can land.
    // Best-effort: an unattachable attr must not undo the successful attach
    // (Linux applied it at mount_setattr time; NARF defers to here).
    if let Some(flags) = with_mount_attrs(|m| m.remove(&mid)) {
        let _ = current_set_mount_flags(&target, flags);
    }
    for (relative, fs) in mount.descendants {
        let child_target = if target == "/" {
            alloc::format!("/{}", relative.trim_start_matches('/'))
        } else {
            alloc::format!("{}{}", target.trim_end_matches('/'), relative)
        };
        if current_mount_arc(&auth, &child_target, fs).is_err() {
            ctx.set_return(err(EBUSY));
            return;
        }
    }
    // The complete detached tree has been attached; consume it.
    with_mounts(|m| m.remove(&mid));
    ctx.set_return(ok(0));
}

/// `open_tree(dfd, path, flags)` → an O_PATH fd to `path`, or a detached
/// mount fd when `OPEN_TREE_CLONE` requests a clone for `move_mount`.
pub fn sys_open_tree(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    if let Err(errno) = validate_open_tree_flags(a.arg2) {
        ctx.set_return(err(errno));
        return;
    }
    // `vfs_open_tree`: `if (detached && !may_mount()) return -EPERM;` after
    // the flag checks and before the lookup — a plain O_PATH open_tree needs
    // no privilege, a clone does (probed on 6.18).
    if a.arg2 & OPEN_TREE_CLONE != 0 && !mount_admin(task) {
        ctx.set_return(err(EPERM));
        return;
    }
    // `user_path_at`: a faulting name is -EFAULT (it was reported as
    // -EINVAL), and an empty one is -ENOENT unless AT_EMPTY_PATH asked for
    // LOOKUP_EMPTY.
    let raw_path = match copy_user_cstr_checked(a.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    if raw_path.is_empty() && a.arg2 & AT_EMPTY_PATH == 0 {
        ctx.set_return(err(ENOENT));
        return;
    }
    // Mount-object fds returned by open_tree are valid dirfds for another
    // open_tree lookup. systemd first opens the mount covering `/run`, then
    // addresses `run` relative to that detached mount root.
    if !raw_path.starts_with('/') {
        if let Some(base_mount) =
            mount_of(task, a.arg0 as u32).and_then(|mid| with_mounts(|m| m.get(&mid).cloned()))
        {
            let mut dir = base_mount.fs.root();
            let mut found = true;
            for component in raw_path
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
            {
                dir = match dir.lookup_dir(component) {
                    Some(next) => next,
                    None => {
                        found = false;
                        break;
                    }
                };
            }
            if !found && a.arg2 & OPEN_TREE_CLONE != 0 {
                ctx.set_return(err(ENOENT));
                return;
            }
            // The fd names the looked-up directory, as Linux's
            // `dentry_open(&path, O_PATH)` does.
            let root = dir_identity(&dir);
            let mid = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            with_mounts(|m| m.insert(mid, base_mount));
            match install_fd(
                Arc::new(MountObjectFile { id: mid, root }),
                a.arg2 & OPEN_TREE_CLOEXEC != 0,
            ) {
                Some(n) => ctx.set_return(ok(n as u64)),
                None => {
                    // `fs/namespace.c` and `fs/fsopen.c` publish these descriptors with
                    // `FD_PREPARE`, i.e. `get_unused_fd_flags`: a table at
                    // RLIMIT_NOFILE is -EMFILE. -EBADF here would blame the caller's
                    // fd arguments, which had already resolved successfully.
                    ctx.set_return(err(EMFILE));
                }
            }
            return;
        }
    }
    // Linux's non-cloning open_tree form is an O_PATH acquisition, not a
    // detached mount object. systemd uses it for automount-triggering path
    // walking, then passes the returned directory fd to mkdirat() while
    // creating mount points. Reuse the real openat resolver so dirfd,
    // chroot, FD_CLOEXEC and fd-path identity have their normal semantics.
    // A detached mount-object fd and AT_EMPTY_PATH retain the specialized
    // handling below.
    if a.arg2 & OPEN_TREE_CLONE == 0 && !raw_path.is_empty() {
        const O_PATH: u64 = 0o10000000;
        const O_NOFOLLOW: u64 = 0o400000;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
        let flags = O_PATH
            | (a.arg2 & OPEN_TREE_CLOEXEC)
            | if a.arg2 & AT_SYMLINK_NOFOLLOW != 0 {
                O_NOFOLLOW
            } else {
                0
            };
        crate::handlers::handler_sys_openat::sys_openat_with_flags(ctx, flags);
        return;
    }
    // open_tree is an *at syscall: an empty path names dfd itself when the
    // caller supplies the fd-addressed form, and a relative path is resolved
    // below dfd. systemd uses this to clone the private root it has just
    // bind-mounted without reopening it by pathname.
    let visible_path = if raw_path.starts_with('/') {
        raw_path.clone()
    } else {
        let base = match u32::try_from(a.arg0)
            .ok()
            .and_then(|fd| fd_path_for_task(current_task_id(), fd))
            .filter(|path| path.starts_with('/'))
        {
            Some(path) => path,
            None => {
                ctx.set_return(err(EBADF));
                return;
            }
        };
        if raw_path.is_empty() || raw_path == "." {
            base
        } else if base == "/" {
            alloc::format!("/{raw_path}")
        } else {
            alloc::format!("{}/{raw_path}", base.trim_end_matches('/'))
        }
    };
    // Both pathname forms above are in the caller's visible namespace:
    // fd_path_of() deliberately strips the task's chroot prefix. Resolve
    // them back to the backing mount-table path before cloning the tree.
    let path = apply_chroot(&visible_path);
    let mount = match if a.arg2 & OPEN_TREE_CLONE != 0 {
        current_clone_mount_subtree(&path)
            .map(|(fs, descendants)| MountObject { fs, descendants })
            .or_else(|| {
                raw_path
                    .is_empty()
                    .then(|| current_fs_arc_at(&path))
                    .flatten()
                    .map(|fs| MountObject {
                        fs,
                        descendants: alloc::vec::Vec::new(),
                    })
            })
    } else {
        current_clone_tree_at(&path)
            .and_then(|_| current_fs_arc_at(&path))
            .map(|fs| MountObject {
                fs,
                descendants: alloc::vec::Vec::new(),
            })
    } {
        Some(mount) => mount,
        None => {
            ctx.set_return(err(ENOENT));
            return;
        }
    };
    let root = dir_identity(&mount.fs.root());
    let mid = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_mounts(|m| m.insert(mid, mount));
    match install_fd(
        Arc::new(MountObjectFile { id: mid, root }),
        a.arg2 & OPEN_TREE_CLOEXEC != 0,
    ) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => {
            with_mounts(|mounts| mounts.remove(&mid));
            ctx.set_return(err(EMFILE));
        }
    }
}

/// `open_tree_attr(dfd, path, flags, attr, size)` → an O_PATH or detached
/// mount fd with atomically requested mount attributes.
///
/// After `vfs_open_tree`, `wants_mount_setattr` validates the attributes and
/// `do_mount_setattr` applies them to the new file's path — a clone's
/// detached mount, or for the O_PATH form the mount the path must be the
/// root of (-EINVAL otherwise, probed on 6.18). The attributes used to be
/// validated and then dropped.
pub fn sys_open_tree_attr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    if a.arg3 == 0 && a.arg4 != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }

    // Linux prepares the open-tree file first and publishes its descriptor
    // only after mount-attribute validation succeeds. NARF's fd table API
    // installs immediately, so capture the result and discard that private,
    // not-yet-observable descriptor on any later validation error.
    let mut capture = ReturnCapture {
        inner: ctx,
        ret: None,
    };
    sys_open_tree(&mut capture);
    let opened = capture.ret.unwrap_or_else(SyscallReturn::invalid_op);
    if opened.status != SyscallReturn::OK || (opened.value as i64) < 0 {
        capture.inner.set_return(opened);
        return;
    }

    let task = current_task_id();
    let fd_no = opened.value as u32;
    if a.arg3 != 0 {
        let applied = validate_mount_attr(a.arg3, a.arg4 as usize, a.arg2 & OPEN_TREE_CLONE != 0)
            .and_then(|attr| {
                if attr.is_nop() {
                    return Ok(());
                }
                if let Some(mid) = mount_of(task, fd_no) {
                    // Detached: land the attributes when move_mount attaches it.
                    record_detached_attr(mid, &attr);
                    return Ok(());
                }
                let path = resolve_at_mount_path(task, u64::from(fd_no), "")?;
                require_mountpoint(&path)?;
                apply_mount_attr(&path, &attr)
            });
        if let Err(errno) = applied {
            discard_open_tree_fd(task, fd_no);
            capture.inner.set_return(err(errno));
            return;
        }
    }
    capture.inner.set_return(opened);
}

/// `fspick(dfd, path, flags)` → fs-context fd for an existing mount (for
/// reconfiguration). The context starts already "created" with that fs.
///
/// `fs/fsopen.c::SYSCALL_DEFINE3(fspick)`:
///
/// ```text
/// if (!may_mount())                               return -EPERM;
/// if (flags & ~(FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW |
///               FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH)) return -EINVAL;
/// ret = user_path_at(dfd, path, lookup_flags, &target);   /* -EFAULT/-ENOENT */
/// if (target.mnt->mnt_root != target.dentry)      return -EINVAL;
/// ```
///
/// This checked neither privilege nor flags, reported a faulting or relative
/// path as -EINVAL, and handed back the COVERING filesystem for any path
/// below a mount instead of refusing a non-mountpoint (probed on 6.18).
pub fn sys_fspick(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    if !mount_admin(task) {
        ctx.set_return(err(EPERM));
        return;
    }
    let flags = a.arg2 as u32 as u64;
    if flags & !(FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH)
        != 0
    {
        ctx.set_return(err(EINVAL));
        return;
    }
    let raw = match copy_user_cstr_checked(a.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    if raw.is_empty() && flags & FSPICK_EMPTY_PATH == 0 {
        ctx.set_return(err(ENOENT));
        return;
    }
    let path = match resolve_at_mount_path(task, a.arg0, &raw)
        .and_then(|path| require_mountpoint(&path).map(|()| path))
    {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    let fs = match current_fs_arc_at(&path) {
        Some(fs) => fs,
        None => {
            ctx.set_return(err(ENOENT));
            return;
        }
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let fsname = String::from(fs.name());
    with_contexts(|m| {
        m.insert(
            id,
            FsContext {
                fsname,
                created: Some(fs),
                options: BTreeMap::new(),
                sb_flags: 0,
                sb_mask: 0,
                uid: 0,
                gid: 0,
                phase: CtxPhase::ReconfParams,
            },
        )
    });
    match install_fd(Arc::new(FsContextFile { id }), flags & FSPICK_CLOEXEC != 0) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => {
            // `fs/namespace.c` and `fs/fsopen.c` publish these descriptors with
            // `FD_PREPARE`, i.e. `get_unused_fd_flags`: a table at
            // RLIMIT_NOFILE is -EMFILE. -EBADF here would blame the caller's
            // fd arguments, which had already resolved successfully.
            ctx.set_return(err(EMFILE));
        }
    }
}

/// `mount_setattr(dfd, path, flags, attr, size)`.
/// `SYSCALL_DEFINE5(mount_setattr, int dfd, const char __user *path,
/// unsigned int flags, struct mount_attr __user *uattr, size_t usize)`.
///
/// This used to validate and then return 0 without touching anything, which
/// is the worst of the three possible answers: a caller that asked for
/// `MOUNT_ATTR_RDONLY` was told it succeeded and got a writable mount. The
/// four attributes NARF's mount table carries are applied now; the rest are
/// accepted-and-unapplied for the reason stated below, which is the same
/// reason `mount(2)` already documents for `MS_RELATIME`.
///
/// The target is found as `user_path_at(dfd, path, ...)` then
/// `do_mount_setattr`'s `if (!path_mounted(path)) return -EINVAL;`: a
/// missing path (including an empty one without AT_EMPTY_PATH) is -ENOENT,
/// an existing non-mountpoint -EINVAL, and a relative path resolves against
/// `dfd` (probed on 6.18). It used to resolve every path against the cwd,
/// treat "" as the cwd, and report a non-mountpoint as -ENOENT.
pub fn sys_mount_setattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    const ALLOWED_FLAGS: u64 = AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if a.arg2 & !ALLOWED_FLAGS != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let attr = match validate_mount_attr(a.arg3, a.arg4 as usize, false) {
        Ok(attr) => attr,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    // `if (attr.attr_set == 0 && attr.attr_clr == 0 && attr.propagation == 0)
    // return 0; /* Tell caller to not bother. */` — a no-op request does not
    // resolve the path, so it cannot fail on it either.
    if attr.is_nop() {
        ctx.set_return(ok(0));
        return;
    }
    let task = current_task_id();
    // `AT_EMPTY_PATH`: the target is the mount referred to by the fd (arg0),
    // not a path. systemd's new-mount-API sandbox sets a DETACHED fsmount /
    // open_tree mount read-only/nosuid/etc. this way BEFORE `move_mount`
    // attaches it. Resolving the empty name as a path would apply the attrs to
    // the wrong mount (or fail), which aborted namespacing with EXIT_NAMESPACE
    // for every ProtectProc / PrivateDevices service — the logind/userdbd
    // failure. NARF applies mount flags at the mount POINT, so record the attrs
    // against the detached mount now and apply them in `sys_move_mount`. Any
    // other fd names the path it was opened on, below.
    if a.arg2 & AT_EMPTY_PATH != 0 {
        if let Some(mid) = mount_of(task, a.arg0 as u32) {
            record_detached_attr(mid, &attr);
            ctx.set_return(ok(0));
            return;
        }
    }
    let raw = match copy_user_cstr_checked(a.arg1, 4096) {
        Ok(p) => p,
        Err(errno) => {
            // `copy_user_cstr_checked` reports a POSITIVE errno and `err`
            // negates it, so pass it through rather than negating twice.
            ctx.set_return(err(errno));
            return;
        }
    };
    if raw.is_empty() && a.arg2 & AT_EMPTY_PATH == 0 {
        ctx.set_return(err(ENOENT));
        return;
    }
    let path = match resolve_at_mount_path(task, a.arg0, &raw)
        .and_then(|path| require_mountpoint(&path).map(|()| path))
    {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(err(errno));
            return;
        }
    };
    // The propagation half is `do_change_type`'s, the same one mount(2)
    // reaches with MS_SHARED & co; `validate_mount_attr` has already held it
    // to at most one of the four types.
    if attr.propagation != 0 {
        let prop = match attr.propagation {
            p if p == 1 << 20 => narf_filesystem::MntPropagation::Shared,
            p if p == 1 << 19 => narf_filesystem::MntPropagation::Slave,
            p if p == 1 << 18 => narf_filesystem::MntPropagation::Private,
            _ => narf_filesystem::MntPropagation::Unbindable,
        };
        let _ = current_change_propagation(&path, prop, a.arg2 & AT_RECURSIVE != 0);
    }
    match apply_mount_attr(&path, &attr) {
        Ok(()) => ctx.set_return(ok(0)),
        Err(errno) => ctx.set_return(err(errno)),
    }
}

/// `build_mount_kattr` + `mount_setattr_commit`: translate `MOUNT_ATTR_*` to
/// `mnt_flags` and write them onto the mount at exactly `path`.
///
/// `MOUNT_ATTR_NOSYMFOLLOW` reaches the same resolver check `openat2`'s
/// `RESOLVE_NO_SYMLINKS` does, which is how Linux implements it too
/// (`fs/namei.c:2036` tests them together).
///
/// The atime policy is an ENUM in the uapi (`MOUNT_ATTR_RELATIME` is 0), so
/// `build_mount_kattr` handles it apart from the bits: when `attr_clr`
/// carries the whole `MOUNT_ATTR__ATIME` (validated above), both
/// `MNT_RELATIME` and `MNT_NOATIME` are cleared and exactly the one
/// `attr_set` names is set — nothing for `STRICTATIME`. `NODIRATIME` is an
/// ordinary bit. They are recorded and reported (mountinfo, statmount);
/// LINUX-GAP: NARF's filesystems do not maintain `atime` from reads, so the
/// policy has nothing to relax.
fn apply_mount_attr(path: &str, attr: &MountAttr) -> Result<(), i64> {
    let current = current_mount_flags_exact(path).ok_or(ENOENT)?;
    let next = mount_attr_to_mnt_flags(current, attr);
    if next == current {
        return Ok(());
    }
    if current_set_mount_flags(path, next) {
        Ok(())
    } else {
        Err(ENOENT)
    }
}

/// The pure half of [`apply_mount_attr`]: `(mnt_flags & ~attr_clr) |
/// attr_set` in `MNT_*` space. `attr_clr` goes first, so a bit named in
/// both ends up SET — the order `mount_setattr_commit` uses.
fn mount_attr_to_mnt_flags(current: u64, attr: &MountAttr) -> u64 {
    use narf_filesystem::mnt_flags;
    const MOUNT_ATTR_NODIRATIME: u64 = 0x0000_0080;
    const PAIRS: [(u64, u64); 6] = [
        (MOUNT_ATTR_RDONLY, mnt_flags::READONLY),
        (MOUNT_ATTR_NOSUID, mnt_flags::NOSUID),
        (MOUNT_ATTR_NODEV, mnt_flags::NODEV),
        (MOUNT_ATTR_NOEXEC, mnt_flags::NOEXEC),
        (MOUNT_ATTR_NODIRATIME, mnt_flags::NODIRATIME),
        (MOUNT_ATTR_NOSYMFOLLOW, mnt_flags::NOSYMFOLLOW),
    ];
    let (mut set, mut clr) = (0u64, 0u64);
    for (uapi, mnt) in PAIRS {
        if attr.attr_clr & uapi != 0 {
            clr |= mnt;
        }
        if attr.attr_set & uapi != 0 {
            set |= mnt;
        }
    }
    if attr.attr_clr & MOUNT_ATTR__ATIME != 0 {
        clr |= mnt_flags::RELATIME | mnt_flags::NOATIME;
        match attr.attr_set & MOUNT_ATTR__ATIME {
            0 => set |= mnt_flags::RELATIME,
            MOUNT_ATTR_NOATIME => set |= mnt_flags::NOATIME,
            _ => {} // MOUNT_ATTR_STRICTATIME
        }
    }
    (current & !clr) | set
}
