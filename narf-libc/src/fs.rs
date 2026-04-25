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
