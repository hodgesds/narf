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

/// POSIX `errno` value surfaced on alloc failure. Kept as a named
/// constant so the call sites stay self-documenting.
const ENOMEM: i32 = 12;

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

// ── Heap-backed env table ────────────────────────────────────────
//
// Backing store for setenv/unsetenv mutations. We copy the kernel-
// supplied envp on the first mutation and keep a NULL-terminated
// pointer array plus per-entry "NAME=VALUE\0" allocations. After
// the copy, `ENVIRON` points at the heap-resident array so all
// subsequent reads (getenv, walk-the-table consumers) see the
// mutated view.
//
// Reference: musl `src/env/setenv.c` + `src/env/__env_init.c`. The
// musl model uses `__env` as the canonical backing array; we mirror
// it as `OWNED_ENV`. Single-threaded user mode means no internal
// lock.

const OWNED_ENV_CAP: usize = 256;
static mut OWNED_ENV: [*const u8; OWNED_ENV_CAP] = [core::ptr::null(); OWNED_ENV_CAP];
static mut OWNED_ENV_LEN: usize = 0;
static mut OWNED_ENV_ACTIVE: bool = false;

/// Convert the kernel-supplied envp table into the heap-resident
/// OWNED_ENV form. Idempotent — subsequent calls are no-ops once
/// `OWNED_ENV_ACTIVE` is true. Each entry is malloc'd as a single
/// "NAME=VALUE\0" buffer so a future unsetenv can free it cleanly.
///
/// # Safety
/// Single-threaded startup invariant. Walks until a NULL pointer.
unsafe fn ensure_owned() {
    // SAFETY: single-threaded; the flag is set after the copy
    // completes so re-entrance is harmless.
    if unsafe { OWNED_ENV_ACTIVE } {
        return;
    }
    let mut src = unsafe { ENVIRON };
    let mut n = 0usize;
    if !src.is_null() {
        // SAFETY: caller asserts the kernel-supplied envp is
        // NULL-terminated.
        unsafe {
            while n < OWNED_ENV_CAP - 1 {
                let entry = *src;
                if entry.is_null() {
                    break;
                }
                // Walk to NUL to get the length.
                let mut len = 0usize;
                while *entry.add(len) != 0 {
                    len += 1;
                }
                // Allocate + copy.
                let owned = crate::heap::malloc(len + 1);
                if owned.is_null() {
                    break;
                }
                core::ptr::copy_nonoverlapping(entry, owned, len);
                *owned.add(len) = 0;
                OWNED_ENV[n] = owned as *const u8;
                src = src.add(1);
                n += 1;
            }
            OWNED_ENV[n] = core::ptr::null();
        }
    }
    // SAFETY: single-threaded; publish. Use `&raw const` rather than
    // `.as_ptr()` on a `static mut` to avoid the 2024-edition warning
    // about shared refs into mutable statics.
    unsafe {
        OWNED_ENV_LEN = n;
        OWNED_ENV_ACTIVE = true;
        let p = &raw const OWNED_ENV;
        ENVIRON = p as *const *const u8;
    }
}

/// Walk OWNED_ENV looking for a matching `NAME=` prefix. Returns
/// `Some(index)` of the matching entry or `None`.
unsafe fn find_owned(name: *const u8, name_len: usize) -> Option<usize> {
    // SAFETY: caller asserts `name` is valid for `name_len` bytes.
    unsafe {
        for i in 0..OWNED_ENV_LEN {
            let entry = OWNED_ENV[i];
            if entry.is_null() {
                return None;
            }
            let mut matches = true;
            for j in 0..name_len {
                if *entry.add(j) != *name.add(j) {
                    matches = false;
                    break;
                }
            }
            if matches && *entry.add(name_len) == b'=' {
                return Some(i);
            }
        }
    }
    None
}

/// Rust-internal explicit-length form. The C-ABI [`setenv`] entry
/// below walks `strlen` and delegates here.
///
/// Reference: musl `src/env/setenv.c`.
///
/// # Safety
/// `name` / `value` must point at valid byte ranges of the given
/// lengths.
pub unsafe fn setenv_raw(
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
    overwrite: i32,
) -> i32 {
    if name.is_null() || name_len == 0 {
        set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: forwarded; ensure_owned is single-threaded-safe.
    unsafe { ensure_owned() };
    // Same-name lookup.
    let found = unsafe { find_owned(name, name_len) };
    if found.is_some() && overwrite == 0 {
        return 0;
    }
    // Build "NAME=VALUE\0" in a fresh allocation.
    let total = name_len + 1 + value_len + 1;
    // SAFETY: heap allocation.
    let buf = unsafe { crate::heap::malloc(total) };
    if buf.is_null() {
        set_errno(ENOMEM);
        return -1;
    }
    // SAFETY: caller-asserted readable; writes bounded by `total`.
    unsafe {
        core::ptr::copy_nonoverlapping(name, buf, name_len);
        *buf.add(name_len) = b'=';
        if value_len > 0 {
            core::ptr::copy_nonoverlapping(value, buf.add(name_len + 1), value_len);
        }
        *buf.add(name_len + 1 + value_len) = 0;
    }
    // SAFETY: OWNED_ENV writes under the single-threaded invariant.
    unsafe {
        match found {
            Some(idx) => {
                let old = OWNED_ENV[idx];
                if !old.is_null() {
                    crate::heap::free(old as *mut u8);
                }
                OWNED_ENV[idx] = buf as *const u8;
            }
            None => {
                if OWNED_ENV_LEN >= OWNED_ENV_CAP - 1 {
                    crate::heap::free(buf);
                    set_errno(ENOMEM);
                    return -1;
                }
                OWNED_ENV[OWNED_ENV_LEN] = buf as *const u8;
                OWNED_ENV_LEN += 1;
                OWNED_ENV[OWNED_ENV_LEN] = core::ptr::null();
            }
        }
    }
    0
}

/// Rust-internal explicit-length unsetenv. The C-ABI [`unsetenv`]
/// entry below walks `strlen` and delegates here.
///
/// Reference: musl `src/env/unsetenv.c`.
///
/// # Safety
/// `name` must point at `name_len` valid bytes.
pub unsafe fn unsetenv_raw(name: *const u8, name_len: usize) -> i32 {
    if name.is_null() || name_len == 0 {
        set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: name has no `=`.
    for i in 0..name_len {
        if unsafe { *name.add(i) } == b'=' {
            set_errno(crate::errno::EINVAL);
            return -1;
        }
    }
    // SAFETY: forwarded.
    unsafe { ensure_owned() };
    let found = unsafe { find_owned(name, name_len) };
    if let Some(idx) = found {
        // SAFETY: shift-down under the single-threaded invariant.
        unsafe {
            let old = OWNED_ENV[idx];
            if !old.is_null() {
                crate::heap::free(old as *mut u8);
            }
            // Compact the array.
            for j in idx..OWNED_ENV_LEN {
                OWNED_ENV[j] = OWNED_ENV[j + 1];
            }
            OWNED_ENV_LEN -= 1;
            OWNED_ENV[OWNED_ENV_LEN] = core::ptr::null();
        }
    }
    0
}

/// `setenv(name, value, overwrite)` — POSIX-2017 C-ABI shape.
///
/// Reference: musl `src/env/setenv.c`.
///
/// # Safety
/// `name` / `value` must be NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setenv(name: *const u8, value: *const u8, overwrite: i32) -> i32 {
    if name.is_null() {
        set_errno(crate::errno::EINVAL);
        return -1;
    }
    let nlen = unsafe { strlen(name) };
    let vlen = if value.is_null() {
        0
    } else {
        unsafe { strlen(value) }
    };
    let vp = if value.is_null() { b"".as_ptr() } else { value };
    // SAFETY: forwarded; caller-asserted NUL-terminated inputs.
    unsafe { setenv_raw(name, nlen, vp, vlen, overwrite) }
}

/// `unsetenv(name)` — POSIX-2017 C-ABI shape.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unsetenv(name: *const u8) -> i32 {
    if name.is_null() {
        set_errno(crate::errno::EINVAL);
        return -1;
    }
    let nlen = unsafe { strlen(name) };
    // SAFETY: forwarded.
    unsafe { unsetenv_raw(name, nlen) }
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
/// `NAME=VALUE` C string. We split on `=` and forward to
/// [`setenv_raw`].
///
/// # Safety
/// `s` must be a valid NUL-terminated C string of the form
/// `NAME=VALUE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putenv(s: *const u8) -> i32 {
    if s.is_null() {
        set_errno(crate::errno::EINVAL);
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
        set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: `eq < len`, so name + value slices are in-bounds.
    unsafe { setenv_raw(s, eq, s.add(eq + 1), len - eq - 1, 1) }
}
