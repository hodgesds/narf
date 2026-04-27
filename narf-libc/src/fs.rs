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

pub const S_IFMT:   u32 = 0o170000;
pub const S_IFREG:  u32 = 0o100000;
pub const S_IFDIR:  u32 = 0o040000;
pub const S_IFCHR:  u32 = 0o020000;
pub const S_IFIFO:  u32 = 0o010000;
pub const S_IFLNK:  u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFBLK:  u32 = 0o060000;

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

/// `chmod(path, mode)` — accepted and ignored. Returns 0 if the path
/// is reachable (so a consumer that error-checks chmod still sees
/// a failure for a missing file), -1 otherwise.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chmod(path: *const i8, _mode: u32) -> i32 {
    // SAFETY: forwarded; `access` walks the C string.
    unsafe { crate::posix::access(path, 0) }
}

/// `umask(mask)` — set the file-creation mask, returning the
/// previous value. NARF tracks the mask kernel-side per task; the
/// mask isn't consulted at file creation today.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn umask(mask: u32) -> u32 {
    narf_user_runtime::umask(mask)
}
