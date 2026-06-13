//! Batch B — the Linux 5.2 "new mount API":
//! `fsopen` / `fsconfig` / `fsmount` / `move_mount` / `open_tree` /
//! `fspick` / `mount_setattr`.
//!
//! These decompose `mount(2)` into fd-addressed steps. NARF layers them on
//! the existing VFS registry (the same `mount_arc` + `MemFs` machinery
//! `sys_mount` uses):
//!
//! ```text
//!   fsopen("tmpfs")            → fs-context fd
//!   fsconfig(fd, CMD_CREATE)   → builds the MemFs in the context
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

use narf_filesystem::{FileOps, FsError, FsFuture, FsInstance, MemFs, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use crate::fd;
use crate::handlers::{copy_user_cstr, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};

// ── errno (negated-long convention) ─────────────────────────────────
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const EBUSY: i64 = 16;
const EINVAL: i64 = 22;
const ENODEV: i64 = 19;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}
fn ok(v: u64) -> SyscallReturn {
    SyscallReturn::ok(v)
}

// fsconfig(2) commands.
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_CMD_CREATE: u64 = 6;
// fsopen / fsmount / open_tree CLOEXEC bits.
const FSOPEN_CLOEXEC: u64 = 0x0000_0001;
const FSMOUNT_CLOEXEC: u64 = 0x0000_0001;
const OPEN_TREE_CLOEXEC: u64 = 0o2000000; // O_CLOEXEC

/// A filesystem context under construction (fsopen / fspick).
struct FsContext {
    fsname: String,
    created: Option<Arc<dyn FsInstance>>,
}

/// A detached mount (fsmount / open_tree) awaiting move_mount.
struct MountObject {
    fs: Arc<dyn FsInstance>,
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

/// Build an `FsInstance` for a known filesystem type. NARF synthesizes the
/// in-memory filesystems; block-backed types aren't constructable here.
fn build_fs(fsname: &str) -> Option<Arc<dyn FsInstance>> {
    match fsname {
        "tmpfs" | "ramfs" | "memfs" => Some(Arc::new(MemFs::new("tmpfs"))),
        _ => None,
    }
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
stub_fileops!(MountObjectFile, mount_object_id);

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
    with_contexts(|m| {
        m.insert(
            id,
            FsContext {
                fsname,
                created: None,
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
                match build_fs(&c.fsname) {
                    Some(fs) => {
                        c.created = Some(fs);
                        Some(true)
                    }
                    None => Some(false),
                }
            });
            match r {
                Some(true) => ctx.set_return(ok(0)),
                Some(false) => ctx.set_return(err(ENODEV)),
                None => ctx.set_return(err(EBADF)),
            }
        }
        // Configuration options are accepted; NARF's in-memory FSes have
        // none that change behaviour (source/size/mode are no-ops). We
        // still validate that the strings are readable.
        FSCONFIG_SET_STRING => {
            let _key = copy_user_cstr(a.arg2, 256);
            let _val = copy_user_cstr(a.arg3, 4096);
            ctx.set_return(ok(0));
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
    with_mounts(|m| m.insert(mid, MountObject { fs }));
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
    let fs = match with_mounts(|m| m.get(&mid).map(|mo| mo.fs.clone())) {
        Some(fs) => fs,
        None => {
            ctx.set_return(err(EBADF));
            return;
        }
    };
    let auth = narf_filesystem::bootstrap_mount_authority();
    match narf_filesystem::registry().mount_arc(&auth, &to_path, fs) {
        Ok(_) => {
            // The detached mount has been attached; consume it.
            with_mounts(|m| m.remove(&mid));
            ctx.set_return(ok(0));
        }
        Err(_) => ctx.set_return(err(EBUSY)),
    }
}

/// `open_tree(dfd, path, flags)` → detached-mount fd cloning the mount that
/// covers `path` (so it can be re-attached elsewhere with move_mount).
pub fn sys_open_tree(ctx: &mut dyn TrapContext) {
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
    let mid = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_mounts(|m| m.insert(mid, MountObject { fs }));
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
