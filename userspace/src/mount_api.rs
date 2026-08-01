//! Batch B — the Linux 5.2 "new mount API":
//! `fsopen` / `fsconfig` / `fsmount` / `move_mount` / `open_tree` /
//! `fspick` / `mount_setattr`.
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
//! `open_tree` / `fspick` grab an existing mount's fs via
//! `registry().fs_arc_at`. `mount_setattr` is accepted (NARF doesn't model
//! per-mount RO/NOSUID attributes at this layer, matching how `sys_mount`
//! swallows the `MS_*` flags).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, FsInstance, MemFs, Mode, RamFs, Stat, TmpFs};
use narf_lib::sync::IrqSafeSpinLock;

use crate::fd;
use crate::handlers::{
    apply_chroot, copy_user_cstr, current_clone_mount_subtree, current_clone_tree_at,
    current_fs_arc_at, current_mount_arc, current_task_id, fd_path_for_task, parse_proc_self_fd,
};
use crate::syscall::{SyscallReturn, TrapContext};

// ── errno (negated-long convention) ─────────────────────────────────
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const EBUSY: i64 = 16;
const EINVAL: i64 = 22;
const ENODEV: i64 = 19;
const ENOSPC: i64 = 28;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}
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
// fsopen / fsmount / open_tree CLOEXEC bits.
const FSOPEN_CLOEXEC: u64 = 0x0000_0001;
const FSMOUNT_CLOEXEC: u64 = 0x0000_0001;
const OPEN_TREE_CLOEXEC: u64 = 0o2000000; // O_CLOEXEC
const OPEN_TREE_CLONE: u64 = 0x0000_0001;

/// A filesystem context under construction (fsopen / fspick).
struct FsContext {
    fsname: String,
    created: Option<Arc<dyn FsInstance>>,
    options: BTreeMap<String, Option<String>>,
    uid: u32,
    gid: u32,
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

fn context_of(task: u64, fd_no: u32) -> Option<u64> {
    fd::with_table(task, |t| t.get(fd_no).and_then(|e| e.ops.fs_context_id())).flatten()
}
fn mount_of(task: u64, fd_no: u32) -> Option<u64> {
    fd::with_table(task, |t| t.get(fd_no).and_then(|e| e.ops.mount_object_id())).flatten()
}

// procfs / sysfs / cgroupfs backends are compiled only when their crate
// feature is enabled. When it isn't, `mount -t proc|sysfs|cgroup2` still
// succeeds against an empty in-memory directory so systemd's mount unit
// passes (it degrades gracefully when the contents are absent).
#[cfg(feature = "linux-compat")]
fn real_procfs() -> Option<Arc<dyn FsInstance>> {
    Some(Arc::new(narf_filesystem::procfs::ProcFs))
}
#[cfg(not(feature = "linux-compat"))]
fn real_procfs() -> Option<Arc<dyn FsInstance>> {
    Some(Arc::new(MemFs::new("proc")))
}

#[cfg(feature = "linux-compat")]
fn real_sysfs() -> Option<Arc<dyn FsInstance>> {
    Some(Arc::new(narf_filesystem::SysFs::new()))
}
#[cfg(not(feature = "linux-compat"))]
fn real_sysfs() -> Option<Arc<dyn FsInstance>> {
    Some(Arc::new(MemFs::new("sysfs")))
}

#[cfg(feature = "cgroup")]
fn real_cgroupfs() -> Option<Arc<dyn FsInstance>> {
    Some(Arc::new(narf_filesystem::CgroupFs::new()))
}
#[cfg(not(feature = "cgroup"))]
fn real_cgroupfs() -> Option<Arc<dyn FsInstance>> {
    Some(Arc::new(MemFs::new("cgroup2")))
}

/// Build an `FsInstance` for a known filesystem type, or return `None` for a
/// genuinely unsupported / garbage fstype (the caller maps `None` to
/// `-ENODEV`, matching Linux).
///
/// The dispatch is shared by both the classic `mount(2)` path and the new
/// mount API (fsopen → fsconfig(CMD_CREATE) → fsmount → move_mount) so the two
/// entry points recognize exactly the same set of filesystems.
///
/// Three classes of fstype are handled:
///   * real NARF backends — tmpfs → `TmpFs`, ramfs → `RamFs`, proc → `ProcFs`,
///     sysfs → `SysFs`, devtmpfs → `DevFs`, cgroup2 → `CgroupFs`,
///     devpts → `DevPtsFs`, bpf → `BpfFs`.
///   * pseudo-filesystems systemd mounts during early boot for which NARF has
///     no real semantics (securityfs, debugfs, tracefs, configfs, fusectl,
///     pstore, efivarfs, hugetlbfs, …). These get a
///     minimal empty in-memory directory so the mountpoint exists and is
///     statable/traversable; systemd degrades gracefully when the contents
///     are absent.
///   * everything else — `None` → `-ENODEV`.
pub fn build_fs(fsname: &str) -> Option<Arc<dyn FsInstance>> {
    build_fs_with_options(fsname, "", 0, 0).ok().flatten()
}

/// Build a filesystem while applying its Linux filesystem-specific mount
/// options and mount-creator ownership.
pub fn build_fs_with_options(
    fsname: &str,
    options: &str,
    uid: u32,
    gid: u32,
) -> Result<Option<Arc<dyn FsInstance>>, FsError> {
    // Map a known pseudo-fstype to a stable &'static str name so `MemFs::new`
    // (which takes &'static str) reflects the requested type in listings.
    let empty =
        |name: &'static str| -> Option<Arc<dyn FsInstance>> { Some(Arc::new(MemFs::new(name))) };
    Ok(match fsname {
        // In-memory data filesystems.
        "tmpfs" => Some(Arc::new(TmpFs::from_options(options, uid, gid)?)),
        "ramfs" => Some(Arc::new(RamFs::from_options(options, uid, gid)?)),
        "memfs" => empty("memfs"),
        "shmfs" | "shm" => Some(Arc::new(TmpFs::from_options(options, uid, gid)?)),

        // Real synthetic backends. procfs/sysfs/cgroupfs are compiled only
        // with their respective features; without them the mount still
        // succeeds against an empty directory so systemd's mount unit passes.
        "proc" | "procfs" => real_procfs(),
        "sysfs" => real_sysfs(),
        "devtmpfs" | "devfs" => Some(Arc::new(narf_filesystem::DevFs::new())),
        "cgroup2" | "cgroup" => real_cgroupfs(),
        // bpffs: a real filesystem, not an empty directory. `BPF_OBJ_PIN`
        // refuses any parent that is not one, so mounting a `MemFs` here would
        // make `mount -t bpf` succeed and every pin into it fail with EPERM.
        "bpf" | "bpffs" => Some(Arc::new(narf_filesystem::bpffs::BpfFs::new())),

        // devpts shares the live Unix98 PTY registry with /dev/pts.
        "devpts" => Some(Arc::new(narf_filesystem::devfs_pty::DevPtsFs)),

        // POSIX message queues: the mount and mq_* syscalls share the calling
        // task's IPC-namespace registry, as Linux mqueue_get_tree does.
        "mqueue" => Some(crate::mqueue::mount_current_namespace()),

        // Pseudo-filesystems with no NARF semantics: an empty, statable,
        // writable directory is enough for systemd's mount unit to succeed.
        "securityfs" => empty("securityfs"),
        "debugfs" => empty("debugfs"),
        "tracefs" => empty("tracefs"),
        "configfs" => empty("configfs"),
        "fusectl" => empty("fusectl"),
        "pstore" => empty("pstore"),
        "efivarfs" => empty("efivarfs"),
        "hugetlbfs" => empty("hugetlbfs"),
        "binfmt_misc" => empty("binfmt_misc"),
        "autofs" => empty("autofs"),

        _ => None,
    })
}

fn context_options(context: &FsContext) -> String {
    let mut rendered = String::new();
    for (key, value) in &context.options {
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

// ── fd-backed handles ───────────────────────────────────────────────
struct FsContextFile {
    id: u64,
}
struct MountObjectFile {
    id: u64,
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
        }
    };
}
stub_fileops!(FsContextFile, fs_context_id);

impl FileOps for MountObjectFile {
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
    fd::with_table(current_task_id(), |t| {
        t.open(fd::FdEntry {
            ops: file,
            offset: 0,
            flags,
            status_flags: 0,
        })
    })
}

/// `fsopen(fsname, flags)` → fs-context fd.
pub fn sys_fsopen(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fsname = match copy_user_cstr(a.arg0, 256) {
        Some(s) if !s.is_empty() => s,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (uid, gid) = crate::handlers::current_fs_ids();
    with_contexts(|m| {
        m.insert(
            id,
            FsContext {
                fsname,
                created: None,
                options: BTreeMap::new(),
                uid,
                gid,
            },
        )
    });
    match install_fd(Arc::new(FsContextFile { id }), a.arg1 & FSOPEN_CLOEXEC != 0) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `fsconfig(fd, cmd, key, value, aux)`.
pub fn sys_fsconfig(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match context_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    match a.arg1 {
        FSCONFIG_CMD_CREATE => {
            // Materialize the filesystem named by fsopen.
            let r = with_contexts(|m| {
                let c = m.get_mut(&id)?;
                let options = context_options(c);
                match build_fs_with_options(&c.fsname, &options, c.uid, c.gid) {
                    Ok(Some(fs)) => {
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
                Some(Err(FsError::NoSpace)) => ctx.set_return(err(ENOSPC)),
                Some(Err(_)) => ctx.set_return(err(EINVAL)),
                None => ctx.set_return(err(EBADF)),
            }
        }
        // CMD_RECONFIGURE applies retained options to the selected live fs.
        FSCONFIG_CMD_RECONFIGURE => {
            let result = with_contexts(|m| {
                let context = m.get(&id)?;
                let fs = context.created.as_ref()?;
                Some(fs.reconfigure(&context_options(context)))
            });
            match result {
                Some(Ok(())) => ctx.set_return(ok(0)),
                Some(Err(FsError::NoSpace)) => ctx.set_return(err(ENOSPC)),
                Some(Err(_)) => ctx.set_return(err(EINVAL)),
                None => ctx.set_return(err(EBADF)),
            }
        }
        // Retain configuration options for CMD_CREATE/CMD_RECONFIGURE. The
        // string/path/binary forms validate that user pointers are readable.
        FSCONFIG_SET_STRING | FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY | FSCONFIG_SET_BINARY => {
            let key = copy_user_cstr(a.arg2, 256);
            let value = copy_user_cstr(a.arg3, 4096);
            if let (Some(key), Some(value)) = (key, value) {
                let found = with_contexts(|m| {
                    m.get_mut(&id)
                        .map(|context| context.options.insert(key, Some(value)))
                        .is_some()
                });
                ctx.set_return(if found { ok(0) } else { err(EBADF) });
            } else {
                ctx.set_return(err(EINVAL));
            }
        }
        // FSCONFIG_SET_FLAG (value-less key) and FSCONFIG_SET_FD (numeric aux)
        // carry no user string to validate; accept them.
        FSCONFIG_SET_FLAG | FSCONFIG_SET_FD => {
            if let Some(key) = copy_user_cstr(a.arg2, 256) {
                let found = with_contexts(|m| {
                    m.get_mut(&id)
                        .map(|context| context.options.insert(key, None))
                        .is_some()
                });
                ctx.set_return(if found { ok(0) } else { err(EBADF) });
            } else {
                ctx.set_return(err(EINVAL));
            }
        }
        _ => ctx.set_return(ok(0)),
    }
}

/// `fsmount(fs_fd, flags, attr_flags)` → detached-mount fd.
pub fn sys_fsmount(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let id = match context_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let fs = with_contexts(|m| m.get(&id).and_then(|c| c.created.clone()));
    let fs = match fs {
        Some(fs) => fs,
        None => {
            // fsconfig(CMD_CREATE) wasn't called.
            ctx.set_return(err(EINVAL));
            return;
        }
    };
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
    match install_fd(
        Arc::new(MountObjectFile { id: mid }),
        a.arg1 & FSMOUNT_CLOEXEC != 0,
    ) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `move_mount(from_dfd, from_path, to_dfd, to_path, flags)`.
pub fn sys_move_mount(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    // from_dfd is the detached-mount fd from fsmount / open_tree.
    let mid = match mount_of(task, a.arg0 as u32) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let to_path = match copy_user_cstr(a.arg3, 4096) {
        Some(s) if !s.is_empty() && s.starts_with('/') => s,
        _ => {
            ctx.set_return(err(EINVAL));
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
    let target = apply_chroot(&target_path);
    let auth = narf_filesystem::bootstrap_mount_authority();
    if current_mount_arc(&auth, &target, mount.fs).is_err() {
        ctx.set_return(err(EBUSY));
        return;
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
    let raw_path = match copy_user_cstr(a.arg1, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
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
            let mid = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            with_mounts(|m| m.insert(mid, base_mount));
            match install_fd(
                Arc::new(MountObjectFile { id: mid }),
                a.arg2 & OPEN_TREE_CLOEXEC != 0,
            ) {
                Some(n) => ctx.set_return(ok(n as u64)),
                None => ctx.set_return(err(EBADF)),
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
    let mid = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_mounts(|m| m.insert(mid, mount));
    match install_fd(
        Arc::new(MountObjectFile { id: mid }),
        a.arg2 & OPEN_TREE_CLOEXEC != 0,
    ) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `fspick(dfd, path, flags)` → fs-context fd for an existing mount (for
/// reconfiguration). The context starts already "created" with that fs.
pub fn sys_fspick(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let path = match copy_user_cstr(a.arg1, 4096) {
        Some(s) if !s.is_empty() && s.starts_with('/') => s,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let fs = match narf_filesystem::registry().fs_arc_at(&path) {
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
                uid: 0,
                gid: 0,
            },
        )
    });
    match install_fd(Arc::new(FsContextFile { id }), a.arg2 & FSOPEN_CLOEXEC != 0) {
        Some(n) => ctx.set_return(ok(n as u64)),
        None => ctx.set_return(err(EBADF)),
    }
}

/// `mount_setattr(dfd, path, flags, attr, size)`.
pub fn sys_mount_setattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    // struct mount_attr is 32 bytes; reject obviously-wrong sizes. NARF
    // doesn't enforce per-mount RO/NOSUID/... at this layer (same as the
    // MS_* bits sys_mount accepts), so a well-formed call just succeeds.
    let size = a.arg4 as usize;
    if size == 0 || size > 64 {
        ctx.set_return(err(EINVAL));
        return;
    }
    ctx.set_return(ok(0));
}
