//! `bpf(2)` — `BPF_OBJ_PIN` (6) and `BPF_OBJ_GET` (7).
//!
//! Pinning is what lets a BPF object outlive the process that made it. A
//! loader creates a map, pins it at `/sys/fs/bpf/…`, and exits; a later process
//! reopens the *same* map by path. Every real loader — libbpf, `bpftool`,
//! systemd's `BPFProgram=` units — is built on that handoff, so it is the
//! difference between `bpf(2)` being usable by one process and being usable as
//! a system service.
//!
//! ## The reference model
//!
//! An object's lifetime is `Arc`-counted, and there are exactly two kinds of
//! holder:
//!
//! ```text
//!   Arc<ProgFile|MapFile|LinkFile>
//!     ├─ fd table entry   (one strong ref per open fd)
//!     └─ BpfPin in bpffs  (one strong ref per pinned name)
//! ```
//!
//! `BPF_OBJ_PIN` clones the fd's `Arc` into a [`narf_filesystem::bpffs::BpfPin`];
//! `BPF_OBJ_GET` clones the pin's `Arc` into a new fd. Neither is a copy of the
//! object — both name one allocation — so closing every fd while a pin exists
//! leaves the object fully alive and reachable, and `unlink`ing the last pin
//! while no fd is open frees it. A `Weak` in the pin would break the first
//! half; a pin that never dropped would break the second.
//!
//! No new privilege gate lives here. `sys_bpf`'s [`super::task_may_load_bpf`]
//! already refuses the whole syscall to an unprivileged task, and adding a
//! second, weaker check at this command would be a way *around* that one rather
//! than a reinforcement of it. Nothing here mints a capability either: the
//! filesystem's own mount authority is what created the bpffs mount, long
//! before this handler sees a path.
//!
//! ## Errnos, and where Linux puts them
//!
//! | condition                                | errno   | Linux site |
//! |------------------------------------------|---------|------------|
//! | `bpf_fd` names nothing                    | EBADF   | `bpf_prog_get` |
//! | `bpf_fd` names a non-BPF (or BTF) fd      | EINVAL  | `bpf_fd_probe_obj` |
//! | bad `pathname` pointer                    | EFAULT  | `getname` |
//! | a parent path component is missing        | ENOENT  | `user_path_create` |
//! | the target directory is not bpffs         | EPERM   | `bpf_obj_do_pin` |
//! | the name is already taken (`PIN`)         | EEXIST  | `user_path_create` |
//! | the path is not a pin (`GET`)             | EACCES  | `bpf_inode_type` |
//! | the path does not exist (`GET`)           | ENOENT  | `user_path_at` |
//! | reserved `file_flags` / stray `path_fd`   | EINVAL  | `CHECK_ATTR` |
//! | `BPF_F_PATH_FD` / `BPF_F_RDONLY|WRONLY`   | ENOTSUP | — see LINUX-GAPs |
//!
//! One deliberate ordering divergence: Linux's `user_path_create` reports
//! `EEXIST` *before* the "is this bpffs?" check, so pinning onto an existing
//! name in a tmpfs directory is `EEXIST` there and `EPERM` here. Reproducing
//! Linux's order would mean a generic existence probe running ahead of the
//! bpffs downcast — and that probe would then be the thing producing `EEXIST`
//! for the ordinary case too, leaving `BpfDir::pin_object`'s own duplicate
//! check untested behind it. The order below keeps exactly one producer of
//! `EEXIST`.

#[allow(unused_imports)]
use super::*;

use alloc::string::String;
use alloc::sync::Arc;

use narf_bpf::link::LinkFile;
use narf_bpf::map::MapFile;
use narf_bpf::prog::ProgFile;
use narf_filesystem::bpffs::{as_bpf_dir, BpfDir};

// Errnos this module returns. Spelled out locally rather than widening
// `handlers/mod.rs`'s set or reaching into `sys_bpf.rs`'s private ones — the
// bpf handlers are edited by different agents and a shared private constant is
// a merge conflict waiting for a reason.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EBADF_: i64 = 9;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
/// Linux's userspace-visible `EOPNOTSUPP`, which equals `ENOTSUP` (95).
const ENOTSUP: i64 = 95;

/// `union bpf_attr`, zero-extended. Same rule and bound as `sys_bpf.rs`.
const ATTR_BUF: usize = 256;

/// `PATH_MAX`.
const PATH_MAX: usize = 4096;

// `struct { … }` (BPF_OBJ_* commands) field offsets within `union bpf_attr`:
//
//     __aligned_u64 pathname;    /*  0 */
//     __u32         bpf_fd;      /*  8 */
//     __u32         file_flags;  /* 12 */
//     __s32         path_fd;     /* 16 */
const OB_PATHNAME: usize = 0;
const OB_BPF_FD: usize = 8;
const OB_FILE_FLAGS: usize = 12;
const OB_PATH_FD: usize = 16;
/// `offsetofend(union bpf_attr, path_fd)` — where `CHECK_ATTR(BPF_OBJ)` starts
/// requiring zeroes.
const OB_END: usize = 20;

/// `BPF_F_RDONLY` / `BPF_F_WRONLY` — a mode restriction on the fd `OBJ_GET`
/// returns.
const BPF_F_RDONLY: u32 = 1 << 3;
const BPF_F_WRONLY: u32 = 1 << 4;
/// `BPF_F_PATH_FD` — resolve `pathname` relative to `path_fd` rather than cwd.
const BPF_F_PATH_FD: u32 = 1 << 14;

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64_at(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Copy the caller's `union bpf_attr` into a zeroed buffer of our own.
fn read_attr(attr_uptr: u64, size: usize) -> Result<[u8; ATTR_BUF], i64> {
    if attr_uptr == 0 || size == 0 || size > ATTR_BUF {
        return Err(-EINVAL);
    }
    let mut buf = [0u8; ATTR_BUF];
    // SAFETY: caller-supplied pointer, range-validated inside `copy_from_user`,
    // which opens and closes the SMAP window and converts a fault into
    // `Err(EFAULT)` rather than a kernel panic.
    unsafe { copy_from_user(&mut buf[..size], attr_uptr) }.map_err(|e| -(e as i64))?;
    Ok(buf)
}

/// Linux's `CHECK_ATTR`: every `bpf_attr` byte past the command's last field
/// must be zero, so a future kernel that adds a field there can tell a caller
/// which meant it from one that sent stack garbage.
fn check_attr_tail(attr: &[u8; ATTR_BUF], size: usize) -> Result<(), i64> {
    if size > OB_END && attr[OB_END..size].iter().any(|b| *b != 0) {
        return Err(-EINVAL);
    }
    Ok(())
}

/// The `pathname` / `file_flags` / `path_fd` validation both commands share,
/// returning the resolved absolute path.
///
/// `extra_flag_mask` is the set of flags the command tolerates at all
/// (`CHECK_ATTR`'s `~mask` test); everything outside it is `EINVAL`.
fn common_path(attr: &[u8; ATTR_BUF], size: usize, allowed_flags: u32) -> Result<String, i64> {
    check_attr_tail(attr, size)?;

    let file_flags = u32_at(attr, OB_FILE_FLAGS);
    if file_flags & !allowed_flags != 0 {
        return Err(-EINVAL);
    }
    // Linux: "path_fd has to be accompanied by BPF_F_PATH_FD". A stray
    // `path_fd` with the flag clear is garbage, not a silently-ignored field.
    if file_flags & BPF_F_PATH_FD == 0 && u32_at(attr, OB_PATH_FD) != 0 {
        return Err(-EINVAL);
    }
    // LINUX-GAP: `BPF_F_PATH_FD` (Linux 6.5) resolves `pathname` against an
    // open directory fd instead of the cwd. NARF's path resolution takes an
    // absolute or cwd-relative string; threading a dirfd through it is the
    // `*at(2)` rework, not a flag. `ENOTSUP` rather than "ignore the flag and
    // resolve against cwd", which would silently pin into the wrong directory.
    if file_flags & BPF_F_PATH_FD != 0 {
        return Err(-ENOTSUP);
    }

    let path_uptr = u64_at(attr, OB_PATHNAME);
    // `copy_user_cstr` walks user memory a page at a time looking for the NUL;
    // bulk-reading `PATH_MAX` would fault on a path that ends near the end of
    // a mapping. A null pointer, a fault, or a missing NUL all land here.
    let raw = copy_user_cstr(path_uptr, PATH_MAX).ok_or(-EFAULT)?;
    // `resolve_cwd_path`, never `apply_chroot` directly: the latter skips both
    // the cwd join and `//` normalisation, which is how `pivot_root(".", ".")`
    // and systemd's `/run//systemd` paths broke before.
    Ok(resolve_cwd_path(current_task_id(), &raw))
}

/// Which BPF object class an fd holds, if any.
///
/// Linux's `bpf_fd_probe_obj` tries program, then map, then link, and returns
/// `-EINVAL` when the fd is none of them. A BTF fd is deliberately *not* in
/// that list — a BTF blob has no pinned representation on Linux either — so it
/// falls through to the same `EINVAL` as an ordinary file fd.
// LINUX-GAP: `BPF_OBJ_PIN` of a BTF fd is `EINVAL` on Linux and here.
fn is_pinnable(ops: &Arc<dyn narf_filesystem::FileOps>) -> bool {
    let Some(any) = ops.as_any() else {
        return false;
    };
    any.downcast_ref::<ProgFile>().is_some()
        || any.downcast_ref::<MapFile>().is_some()
        || any.downcast_ref::<LinkFile>().is_some()
}

/// Run `f` against the bpffs directory that owns `path`'s last component.
///
/// `Err(-ENOENT)` when the parent path resolves to nothing, `Err(-EPERM)` when
/// it resolves to a directory that is not bpffs — Linux's
/// `dir->i_op != &bpf_dir_iops` arm.
fn with_bpf_parent<R>(path: &str, f: impl FnOnce(&BpfDir, &str) -> R) -> Result<R, i64> {
    // The GLOBAL registry, matching `sys_unlink`: NARF's per-task mount
    // namespaces are applied by `resolve_cwd_path`'s chroot re-rooting, and the
    // unlink that drops a pin goes through this same table — a pin created
    // against one view and dropped against another would leak.
    let outcome = narf_filesystem::registry().resolve_parent_absolute(path, |_fs, dir, leaf| {
        as_bpf_dir(&*dir).map(|d| f(d, leaf))
    });
    match outcome {
        Some(Some(r)) => Ok(r),
        Some(None) => Err(-EPERM),
        None => Err(-ENOENT),
    }
}

pub(crate) fn bpf_obj_pin(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < OB_FILE_FLAGS + 4 {
        return -EINVAL;
    }

    // The fd is resolved BEFORE the path, matching `bpf_obj_pin_user`: a caller
    // probing with a bad fd must hear about the fd, not about its pathname.
    let fd = u32_at(&attr, OB_BPF_FD);
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return -EBADF_,
    };
    if !is_pinnable(&ops) {
        return -EINVAL;
    }

    // Linux's `bpf_obj_pin` tolerates only `BPF_F_PATH_FD` here.
    let path = match common_path(&attr, size, BPF_F_PATH_FD) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // `pin_object` takes a strong reference; the fd keeps its own. This clone
    // IS the pin's reference — the object now outlives `close(fd)`.
    match with_bpf_parent(&path, |dir, leaf| dir.pin_object(leaf, Arc::clone(&ops))) {
        Ok(Ok(_pin)) => 0,
        Ok(Err(narf_filesystem::FsError::Busy)) => -EEXIST,
        // An empty / `.` / `..` / slash-bearing leaf. `resolve_parent_absolute`
        // already rejects most of these by returning `None`; the rest are
        // `EINVAL`, as Linux's `lookup_one_qstr_excl` reports for a bad final
        // component.
        Ok(Err(_)) => -EINVAL,
        Err(e) => e,
    }
}

pub(crate) fn bpf_obj_get(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < OB_FILE_FLAGS + 4 {
        return -EINVAL;
    }
    // Linux: `attr->bpf_fd != 0` is `EINVAL` — this command takes no fd, and a
    // non-zero one means the caller filled in the wrong union member.
    if u32_at(&attr, OB_BPF_FD) != 0 {
        return -EINVAL;
    }

    let path = match common_path(
        &attr,
        size,
        BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_PATH_FD,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // LINUX-GAP: `BPF_F_RDONLY` / `BPF_F_WRONLY` on the returned fd. Linux
    // honours them and the fd then refuses the other direction. NARF's
    // `MapFile` has one mode, so accepting the flag would hand back a fully
    // writable fd to a caller that asked for a read-only one — a lie about
    // privilege, which is the one class of lie worth an errno. Same answer
    // `BPF_MAP_GET_FD_BY_ID` gives for `open_flags`.
    if u32_at(&attr, OB_FILE_FLAGS) & (BPF_F_RDONLY | BPF_F_WRONLY) != 0 {
        return -ENOTSUP;
    }

    // Two failure shapes, and Linux distinguishes them: a path that does not
    // resolve is `ENOENT` (`user_path_at`), a path that resolves to something
    // which is not a BPF object is `EACCES` (`bpf_inode_type`). Collapsing them
    // would make a loader's probe for a pin indistinguishable from a probe that
    // landed on a directory.
    let obj = match with_bpf_parent(&path, |dir, leaf| {
        (dir.pinned_object(leaf), dir.has_entry(leaf))
    }) {
        Ok((Some(obj), _)) => obj,
        // Present but not a pin (a bpffs subdirectory).
        Ok((None, true)) => return -EACCES,
        Ok((None, false)) => return -ENOENT,
        // Not bpffs at all. `with_bpf_parent` reports that as the `EPERM` a
        // *pin* wants; for `OBJ_GET` the equivalent Linux answer depends on
        // whether the path exists, so re-ask the generic VFS.
        Err(e) if e == -EPERM => {
            return if path_exists(&path) { -EACCES } else { -ENOENT };
        }
        Err(e) => return e,
    };

    // A *new fd holding its own reference*: the object now survives this fd's
    // close only if the pin (or another fd) still holds it.
    match fd::with_table(current_task_id(), |t| {
        t.open(crate::fd::FdEntry {
            ops: obj,
            offset: 0,
            // As `bpf_prog_new_fd` / `bpf_map_new_fd`: `O_CLOEXEC`, because a
            // leaked bpf fd is a leaked capability.
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}

/// Whether an absolute path names anything at all, of any type.
///
/// Only reached for a path whose parent is *not* bpffs, to tell Linux's
/// `EACCES` ("that exists, and is not a BPF object") from `ENOENT`.
fn path_exists(path: &str) -> bool {
    narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, dir, leaf| {
            poll_blocking(dir.lookup_async(leaf))
                .map(|r| r.is_ok())
                .unwrap_or(false)
                || poll_blocking(dir.lookup_dir_async(leaf))
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}
