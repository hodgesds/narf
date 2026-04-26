//! Environment-variable surface: the POSIX-shaped global `environ`
//! pointer plus the `getenv` / `setenv` / `unsetenv` triad.
//!
//! Stage-4 limitation: the kernel hands a read-only-friendly envp
//! table on the user stack. We don't yet have growable env storage
//! in the user process (no per-task heap-backed env table), so
//! `setenv` / `unsetenv` are stubs that surface ENOSYS-style failure
//! via `errno`. `getenv` walks the live table directly — it's the
//! only operation Rust no_std consumers reach for during validation.
//!
//! Thread-safety: NARF user mode is single-threaded for Stage-4, so
//! the `static mut ENVIRON` access pattern is sound. Each access is
//! wrapped in `unsafe` to localise the assumption.

use crate::set_errno;
use crate::string::strlen;

/// POSIX `errno` value surfaced by the unsupported mutation paths.
/// Linux `ENOSYS` (function not implemented) — picked because Rust
/// libstd's `io::Error::raw_os_error()` round-trips cleanly through
/// it.
const ENOSYS: i32 = 38;

/// POSIX-shaped global environment pointer.
///
/// `__libc_start_main` writes the kernel-supplied envp table here
/// before the user `main` runs. Consumers that read `extern "C"
/// char **environ` from C, or `&ENVIRON` from Rust, observe the
/// same pointer. NULL means "no envp staged" (e.g. on aarch64
/// where the Stage-4 pipeline doesn't lay an argv frame).
///
/// SAFETY note: this is `static mut` rather than `AtomicPtr` because
/// the canonical C ABI is a plain `char **`. Single-threaded user
/// mode + the write-once-during-startup discipline keeps it sound.
#[unsafe(no_mangle)]
pub static mut ENVIRON: *const *const u8 = core::ptr::null();

/// Look up an environment variable. Walks `ENVIRON` for an entry
/// whose `NAME=value` prefix matches the supplied name (length
/// `name_len`, NUL-not-required), and returns a pointer to the
/// first byte of `value`. Returns NULL if no entry matches or if
/// `ENVIRON` is NULL.
///
/// Why a length argument instead of NUL-terminated `name`: callers
/// constructing the name from a Rust `&str` don't have a NUL byte
/// handy, and we already have to scan each envp entry's `=` to find
/// the boundary anyway. The traditional `getenv(const char *)` C
/// shape is provided by the wrapper that takes `strlen(name)`.
///
/// # Safety
/// `name` must point to at least `name_len` valid bytes. `ENVIRON`
/// (if non-null) must point to a NULL-terminated array of NUL-
/// terminated C strings — the kernel-supplied layout satisfies this.
pub unsafe fn getenv(name: *const u8, name_len: usize) -> *const u8 {
    // SAFETY: write-once during single-threaded startup; the
    // pointer-sized read is atomic on x86_64.
    let mut envp = unsafe { ENVIRON };
    if envp.is_null() {
        return core::ptr::null();
    }
    // SAFETY: per the function-level contract — walk the envp array
    // until the terminating NULL.
    unsafe {
        loop {
            let entry = *envp;
            if entry.is_null() {
                return core::ptr::null();
            }
            // Compare `entry[0..name_len]` against `name[0..name_len]`,
            // then require `entry[name_len] == '='`.
            let mut matches = true;
            for i in 0..name_len {
                if *entry.add(i) != *name.add(i) {
                    matches = false;
                    break;
                }
            }
            if matches && *entry.add(name_len) == b'=' {
                return entry.add(name_len + 1);
            }
            envp = envp.add(1);
        }
    }
}

/// C-shaped wrapper: `getenv` with a NUL-terminated name.
///
/// # Safety
/// `name` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getenv_cstr(name: *const u8) -> *const u8 {
    // SAFETY: per the function-level contract.
    let len = unsafe { strlen(name) };
    // SAFETY: `name` is valid for `len` bytes by `strlen`'s walk.
    unsafe { getenv(name, len) }
}

/// Stage-4 stub: setenv requires a growable, heap-backed env table
/// the user process doesn't yet maintain. Sets `errno = ENOSYS` and
/// returns -1. Documented limitation; see module docstring.
///
/// # Safety
/// Arguments are validated only by the no-op shape.
pub unsafe fn setenv(
    _name: *const u8,
    _name_len: usize,
    _value: *const u8,
    _value_len: usize,
    _overwrite: i32,
) -> i32 {
    set_errno(ENOSYS);
    -1
}

/// Stage-4 stub: same shape as `setenv`. The kernel-supplied envp
/// is read-only-friendly; mutation requires a heap-backed copy we
/// don't yet build.
///
/// # Safety
/// Arguments are validated only by the no-op shape.
pub unsafe fn unsetenv(_name: *const u8, _name_len: usize) -> i32 {
    set_errno(ENOSYS);
    -1
}

/// Initialise [`ENVIRON`] from the parsed startup envp pointer.
/// Called by `__libc_start_main` before user `main` runs.
///
/// # Safety
/// Must run exactly once during single-threaded startup. The caller
/// owns the discipline; no internal lock is taken.
pub unsafe fn init_environ(envp: *const *const u8) {
    // SAFETY: write-once during single-threaded startup.
    unsafe {
        ENVIRON = envp;
    }
}

/// `putenv(*const c_char)` — POSIX env modifier shaped as a single
/// `NAME=VALUE` C string. We forward to [`setenv`] after splitting
/// on `=`. Today `setenv` is a stub returning -1, so `putenv`
/// inherits that behaviour and surfaces `errno = ENOSYS`.
///
/// # Safety
/// `s` must be a valid NUL-terminated C string of the form
/// `NAME=VALUE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putenv(s: *const u8) -> i32 {
    if s.is_null() {
        set_errno(ENOSYS);
        return -1;
    }
    // SAFETY: caller contract; walk bounded by `=` or NUL.
    let len = unsafe { strlen(s) };
    let mut eq = 0usize;
    // SAFETY: `len` is the strlen, so reads are in-bounds.
    while eq < len && unsafe { *s.add(eq) } != b'=' {
        eq += 1;
    }
    if eq == len {
        // No `=` — POSIX returns -1.
        set_errno(ENOSYS);
        return -1;
    }
    // SAFETY: `eq < len`, so name + value slices are in-bounds.
    unsafe {
        setenv(s, eq, s.add(eq + 1), len - eq - 1, 1)
    }
}
