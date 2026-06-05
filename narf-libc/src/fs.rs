//! Filesystem-shaped libc surface: `chdir`, `getcwd`.
//!
//! Stage-4 Tier-2 first cut: thin wrappers over
//! `narf_user_runtime::{chdir, getcwd}`. The kernel-side handlers
//! (in `userspace/src/handlers.rs`) own the per-task cwd state.
//! These shims add a NUL-terminated-input convention on top of the
//! kernel's (ptr, len) shape — `chdir` walks the C string for its
//! length, and `getcwd` returns POSIX's `(buf | NULL)` instead of
//! the byte-count the kernel hands back.

use crate::errno;
use crate::string::strlen;

/// POSIX `chdir(3)`: change the calling task's working directory
/// to `path`. Returns 0 on success, -1 on error (with errno set
/// to `EINVAL` on a malformed path or kernel rejection).
///
/// # Safety
/// `path` must be a NUL-terminated C string in the calling task's
/// address space. We walk the buffer with `strlen` to find the
/// length the kernel-side syscall expects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
    if path.is_null() {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    // SAFETY: caller guarantees `path` is NUL-terminated; `strlen`
    // walks until the NUL.
    let len = unsafe { strlen(path) };
    if len == 0 {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    // SAFETY: `path[0..len]` lives inside the caller's NUL-
    // terminated string; `from_raw_parts` borrows it for the
    // duration of the call.
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(path, len) };
    let s = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            errno::set_errno(errno::EINVAL);
            return -1;
        }
    };
    let r = narf_user_runtime::chdir(s);
    if r != 0 {
        errno::set_errno(errno::EINVAL);
        return -1;
    }
    0
}

/// POSIX `getcwd(3)`: copy the calling task's working directory
/// into `buf`. Returns `buf` on success, NULL on error (with
/// errno set to `ERANGE` when `size` is too small).
///
/// # Safety
/// `buf` must be writable for at least `size` bytes. The kernel
/// writes a NUL-terminated string; the resulting byte count
/// (excluding NUL) is bounded by `size - 1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    if buf.is_null() || size == 0 {
        errno::set_errno(errno::EINVAL);
        return core::ptr::null_mut();
    }
    // SAFETY: caller declared `buf` is writable for at least
    // `size` bytes — the trait's contract.
    let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(buf, size) };
    let r = narf_user_runtime::getcwd(slice);
    if r < 0 {
        errno::set_errno(errno::ERANGE);
        return core::ptr::null_mut();
    }
    buf
}

// ── <sys/stat.h> mode constants + macros ────────────────────────────
//
// Numeric values match Linux's `<sys/stat.h>` so a libc consumer
// can `#include <sys/stat.h>` and get the same bits.

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFBLK: u32 = 0o060000;

/// `S_ISREG(mode)` — non-zero if mode names a regular file.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn S_ISREG(mode: u32) -> i32 {
    ((mode & S_IFMT) == S_IFREG) as i32
}

/// `S_ISDIR(mode)` — non-zero if mode names a directory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn S_ISDIR(mode: u32) -> i32 {
    ((mode & S_IFMT) == S_IFDIR) as i32
}

/// `S_ISCHR(mode)` — non-zero if mode names a character special file.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn S_ISCHR(mode: u32) -> i32 {
    ((mode & S_IFMT) == S_IFCHR) as i32
}

/// `S_ISFIFO(mode)` — non-zero if mode names a FIFO.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn S_ISFIFO(mode: u32) -> i32 {
    ((mode & S_IFMT) == S_IFIFO) as i32
}

/// `S_ISLNK(mode)` — non-zero if mode names a symlink.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn S_ISLNK(mode: u32) -> i32 {
    ((mode & S_IFMT) == S_IFLNK) as i32
}

// ── chmod / umask ────────────────────────────────────────────────
//
// NARF's kernel surface exposes no per-file permission bits — every
// file is universally read/write. The C-shaped chmod is retained
// for ABI compatibility (real programs `chmod()` their state files
// even when the underlying FS ignores mode); umask is now per-task
// kernel state so the round-trip is consistent across syscall
// boundaries.

/// `chmod(path, mode)` — legacy POSIX mode set. Forwards to the
/// SYS_CHMOD body in the kernel, which reshapes onto the fchmodat
/// handler. Mode bits aren't enforced; the call returns 0 if the
/// path resolves, -1 otherwise.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chmod(path: *const i8, mode: u32) -> i32 {
    if path.is_null() {
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminator.
    let s = unsafe { crate::posix::cstr_to_str(path as *const _) };
    narf_user_runtime::chmod(s, mode)
}

/// `umask(mask)` — set the file-creation mask, returning the
/// previous value. NARF tracks the mask kernel-side per task; the
/// mask isn't consulted at file creation today.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn umask(mask: u32) -> u32 {
    narf_user_runtime::umask(mask)
}

// ── mount / umount / statvfs (POSIX-2017) ───────────────────────

/// POSIX `<sys/statvfs.h>` `struct statvfs`. Layout matches the
/// kernel's StatfsBuf so a libc client can read the bytes the
/// kernel returns directly.
#[repr(C)]
#[derive(Default, Debug)]
pub struct statvfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namemax: u64,
}

/// `mount(source, target, fstype, flags, data)` — Linux-style
/// `mount(2)`. Forwards to the kernel SYS_MOUNT with the
/// MS_* flag word in `flags`. `data` is accepted for ABI
/// compatibility but not forwarded (per-FS options aren't wired
/// at the kernel side yet).
///
/// # Safety
/// All three string arguments must be NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mount(
    source: *const i8,
    target: *const i8,
    fstype: *const i8,
    flags: u64,
    _data: *const u8,
) -> i32 {
    if source.is_null() || target.is_null() || fstype.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminators.
    let src = unsafe { crate::posix::cstr_to_str(source as *const _) };
    let tgt = unsafe { crate::posix::cstr_to_str(target as *const _) };
    let typ = unsafe { crate::posix::cstr_to_str(fstype as *const _) };
    // SAFETY: forwarded with live &str.
    match unsafe { narf_user_runtime::mount_with_flags(src, tgt, typ, flags) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

/// `chroot(path)` — POSIX-2001 / Linux `chroot(2)`. Rebinds the
/// calling task's `/`. Returns 0 on success, -1 on error.
///
/// # Safety
/// `path` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chroot(path: *const i8) -> i32 {
    if path.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminator.
    let p = unsafe { crate::posix::cstr_to_str(path as *const _) };
    // SAFETY: forwarded.
    match unsafe { narf_user_runtime::chroot(p) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

/// `pivot_root(new_root, put_old)` — Linux `pivot_root(2)`. Used
/// by container-init to swap the root before dropping the
/// bootstrap image. Returns 0 on success, -1 on error.
///
/// # Safety
/// Both arguments must be NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pivot_root(new_root: *const i8, put_old: *const i8) -> i32 {
    if new_root.is_null() || put_old.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminators.
    let nr = unsafe { crate::posix::cstr_to_str(new_root as *const _) };
    let po = unsafe { crate::posix::cstr_to_str(put_old as *const _) };
    // SAFETY: forwarded.
    match unsafe { narf_user_runtime::pivot_root(nr, po) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

/// `umount(target)` — POSIX-2017 single-arg unmount. Forwards
/// to `umount2(target, 0)`.
///
/// # Safety
/// `target` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn umount(target: *const i8) -> i32 {
    // SAFETY: forwarded.
    unsafe { umount2(target, 0) }
}

/// `umount2(target, flags)` — Linux-shaped umount with options.
/// Today flags are accepted but not interpreted.
///
/// # Safety
/// `target` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn umount2(target: *const i8, flags: u32) -> i32 {
    if target.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminator.
    let tgt = unsafe { crate::posix::cstr_to_str(target as *const _) };
    // SAFETY: forwarded.
    match unsafe { narf_user_runtime::umount2(tgt, flags) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

/// `statvfs(path, &buf)` — POSIX-2017 statvfs. Fills `buf` with
/// stats about the FS that covers `path`.
///
/// # Safety
/// `path` must be a NUL-terminated C string; `buf` must be a
/// writable `statvfs` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs(path: *const i8, buf: *mut statvfs) -> i32 {
    if path.is_null() || buf.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminator.
    let p = unsafe { crate::posix::cstr_to_str(path as *const _) };
    // SAFETY: forwarded; buf is writable per caller contract.
    match unsafe { narf_user_runtime::statfs(p, buf as *mut u8) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(2 /* ENOENT */);
            -1
        }
    }
}

/// `fstatvfs(fd, &buf)` — POSIX-2017 fstatvfs.
///
/// # Safety
/// `buf` must be a writable `statvfs` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatvfs(fd: i32, buf: *mut statvfs) -> i32 {
    if buf.is_null() || fd < 0 {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: forwarded.
    match unsafe { narf_user_runtime::fstatfs(fd as u32, buf as *mut u8) } {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(9 /* EBADF */);
            -1
        }
    }
}
