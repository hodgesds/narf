//! C-ABI veneer over the existing `stdio` Rust-shaped surface.
//!
//! The pre-existing `stdio.rs` exposes `fopen`/`fread`/`fwrite`/etc.
//! with Rust-native signatures (`*const u8 + len`, `&str` mode, etc.)
//! — fine for in-tree call sites but not linkable by a C consumer.
//! This module wraps each Rust helper in an `extern "C"` shape
//! matching POSIX/glibc declarations from `<stdio.h>` so a hand-
//! written C source can `#include <stdio.h>`, link against
//! `narf-libc`, and resolve every `FILE*` entry without a thunk.
//!
//! No new I/O policy lives here — the C wrappers just adapt
//! argument shapes and forward to the Rust helpers. POSIX field
//! semantics (`fopen` mode parsing, `fprintf` literal pass-through
//! since `core::ffi::VaList` is still unstable, `fileno` slot
//! extraction) are documented per-entry.
//!
//! Reference: musl `src/stdio/` for argument validation and
//! glibc `libio/` for the FILE* opacity contract.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int, c_void};
use crate::stdio::File;

/// `fopen(path, mode)` — POSIX shape. Walks `path` and `mode` as
/// NUL-terminated C strings and forwards to the Rust `stdio::fopen`.
///
/// # Safety
/// Both pointers must be valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut File {
    if path.is_null() || mode.is_null() { return core::ptr::null_mut(); }
    // SAFETY: caller asserts NUL-terminated; walk to compute length.
    let mut plen = 0usize;
    while unsafe { *path.add(plen) } != 0 { plen += 1; }
    let mut mlen = 0usize;
    while unsafe { *mode.add(mlen) } != 0 { mlen += 1; }
    // SAFETY: caller asserts the bytes are valid for `plen`/`mlen`.
    let mbytes = unsafe { core::slice::from_raw_parts(mode as *const u8, mlen) };
    let mode_str = match core::str::from_utf8(mbytes) {
        Ok(s) => s,
        Err(_) => return core::ptr::null_mut(),
    };
    // SAFETY: forwarded; the Rust fopen handles path UTF-8 internally.
    unsafe { crate::stdio::fopen(path as *const u8, plen, mode_str) }
}

/// `fdopen(fd, mode)` — POSIX shape. Wrap an existing fd in a
/// `*mut File`. `mode` is parsed for read/write hint only — the
/// underlying fd's actual rights govern.
///
/// # Safety
/// `mode` must be NUL-terminated; `fd` must be a valid open fd.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut File {
    if fd < 0 || mode.is_null() { return core::ptr::null_mut(); }
    // Allocate a File on the heap and wrap the fd.
    // SAFETY: malloc with the right size.
    let f = unsafe { crate::heap::malloc(core::mem::size_of::<File>()) } as *mut File;
    if f.is_null() { return core::ptr::null_mut(); }
    // SAFETY: f is malloc-aligned for File; we own the slot.
    unsafe {
        core::ptr::write(f, File::for_owned_fd(fd as u32));
    }
    f
}

/// `fclose(*mut File)` — C-ABI shape forwarding to stdio::fclose.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fclose(f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fclose(f) }
}

/// `fread(buf, size, count, *mut File)` — C-ABI shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fread(
    buf:   *mut c_void,
    size:  usize,
    count: usize,
    f:     *mut File,
) -> usize {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fread(buf as *mut u8, size, count, f) }
}

/// `fwrite(buf, size, count, *mut File)` — C-ABI shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fwrite(
    buf:   *const c_void,
    size:  usize,
    count: usize,
    f:     *mut File,
) -> usize {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fwrite(buf as *const u8, size, count, f) }
}

/// `fputs(s, *mut File)` — POSIX shape. Walks `s` for length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut File) -> c_int {
    if s.is_null() { return -1; }
    let mut len = 0usize;
    while unsafe { *s.add(len) } != 0 { len += 1; }
    // SAFETY: forwarded.
    unsafe { crate::stdio::fputs(s as *const u8, len, f) }
}

/// `fgets(buf, max_len, *mut File)` — POSIX shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgets(buf: *mut c_char, max_len: c_int, f: *mut File) -> *mut c_char {
    if buf.is_null() || max_len <= 0 { return core::ptr::null_mut(); }
    // SAFETY: forwarded.
    let r = unsafe { crate::stdio::fgets(buf as *mut u8, max_len as usize, f) };
    r as *mut c_char
}

/// `fputc(c, *mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fputc(c, f) }
}

/// `fgetc(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgetc(f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fgetc(f) }
}

/// `getc(*mut File)` — alias for [`fgetc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getc(f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::getc(f) }
}

/// `putc(c, *mut File)` — alias for [`fputc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putc(c: c_int, f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::putc(c, f) }
}

/// `getchar()` — read one byte from stdin.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getchar() -> c_int {
    crate::stdio::getchar()
}

/// `putchar(c)` — write one byte to stdout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putchar(c: c_int) -> c_int {
    crate::stdio::putchar(c)
}

/// `puts(s)` — write NUL-terminated `s` plus newline to stdout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::puts(s as *const u8) }
}

/// `fflush(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fflush(f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fflush(f) }
}

/// `feof(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn feof(f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::feof(f) }
}

/// `ferror(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ferror(f: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::ferror(f) }
}

/// `clearerr(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clearerr(f: *mut File) {
    // SAFETY: forwarded.
    unsafe { crate::stdio::clearerr(f) }
}

/// `setbuf(stream, buf)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setbuf(stream: *mut File, buf: *mut c_char) {
    // SAFETY: forwarded.
    unsafe { crate::stdio::setbuf(stream, buf as *mut u8) }
}

/// `setvbuf(stream, buf, mode, size)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setvbuf(
    stream: *mut File,
    buf:    *mut c_char,
    mode:   c_int,
    size:   usize,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::setvbuf(stream, buf as *mut u8, mode, size) }
}

/// `ungetc(c, stream)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ungetc(c: c_int, stream: *mut File) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::ungetc(c, stream) }
}

/// `fseek(*mut File, offset, whence)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fseek(f: *mut File, offset: i64, whence: c_int) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::stdio::fseek(f, offset, whence) }
}

/// `ftell(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftell(f: *mut File) -> i64 {
    // SAFETY: forwarded.
    unsafe { crate::stdio::ftell(f) }
}

/// `rewind(*mut File)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rewind(f: *mut File) {
    // SAFETY: forwarded.
    unsafe { crate::stdio::rewind(f) }
}

/// `perror(s)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn perror(s: *const c_char) {
    // SAFETY: forwarded.
    unsafe { crate::stdio::perror(s as *const u8) }
}

/// `fileno(*mut File)` — return the underlying fd, or -1 on null.
///
/// # Safety
/// `f` must be a valid `*mut File` or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fileno(f: *mut File) -> c_int {
    if f.is_null() { return -1; }
    // SAFETY: caller asserts validity of `f`.
    unsafe { (*f).fd as c_int }
}

/// `printf(fmt, ...)` — POSIX C-ABI shape. Variadics aren't
/// available without `core::ffi::VaList` (still unstable as of
/// 1.85), so this entry treats `fmt` as a literal byte stream and
/// writes it verbatim to stdout. Real format expansion lives in
/// `printf_str`, which Rust callers should prefer.
///
/// # Safety
/// `fmt` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn printf(fmt: *const c_char) -> c_int {
    if fmt.is_null() { return -1; }
    let mut len = 0usize;
    while unsafe { *fmt.add(len) } != 0 { len += 1; }
    let n = narf_user_runtime::write(1, unsafe {
        core::slice::from_raw_parts(fmt as *const u8, len)
    });
    n as c_int
}

/// `fprintf(stream, fmt, ...)` — same literal-pass behaviour as
/// [`printf`] but on an arbitrary FILE*.
///
/// # Safety
/// `fmt` must be NUL-terminated; `stream` must be a valid FILE*.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fprintf(stream: *mut File, fmt: *const c_char) -> c_int {
    if stream.is_null() || fmt.is_null() { return -1; }
    let mut len = 0usize;
    while unsafe { *fmt.add(len) } != 0 { len += 1; }
    // SAFETY: forwarded.
    unsafe {
        let n = crate::stdio::fwrite(fmt as *const u8, 1, len, stream);
        n as c_int
    }
}

/// `sprintf(buf, fmt, ...)` — literal-pass into `buf`; matches the
/// behaviour of `printf` above.
///
/// # Safety
/// `buf` must be writable for at least `strlen(fmt) + 1` bytes;
/// `fmt` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sprintf(buf: *mut c_char, fmt: *const c_char) -> c_int {
    if buf.is_null() || fmt.is_null() { return -1; }
    let mut len = 0usize;
    while unsafe { *fmt.add(len) } != 0 { len += 1; }
    // SAFETY: caller-asserted writable region with room for len+1.
    unsafe {
        core::ptr::copy_nonoverlapping(fmt as *const u8, buf as *mut u8, len);
        *buf.add(len) = 0;
    }
    len as c_int
}

/// `snprintf(buf, n, fmt, ...)` — literal-pass with truncation.
///
/// # Safety
/// `buf` must be writable for `n` bytes; `fmt` must be NUL-
/// terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn snprintf(
    buf: *mut c_char,
    n:   usize,
    fmt: *const c_char,
) -> c_int {
    if buf.is_null() || n == 0 || fmt.is_null() { return -1; }
    let mut len = 0usize;
    while unsafe { *fmt.add(len) } != 0 { len += 1; }
    let copy = if len + 1 > n { n - 1 } else { len };
    // SAFETY: caller-asserted writable region of `n` bytes; copy
    // bounded by `copy < n`.
    unsafe {
        core::ptr::copy_nonoverlapping(fmt as *const u8, buf as *mut u8, copy);
        *buf.add(copy) = 0;
    }
    len as c_int
}

// ── stdin / stdout / stderr global symbols ──────────────────────
//
// C consumers declare `extern FILE *stdin, *stdout, *stderr;` —
// the symbols are pointer-valued globals. The Rust accessors in
// `stdio.rs` already return `*mut File` from a stable static slot;
// here we surface the C-shaped pointers under the canonical names
// by exporting a `static` of `*mut File` initialised from those
// accessors via a constructor in `__libc_start_main`.

// The actual initialisation runs in `startup::__libc_start_main`
// once the TLS slot is staged. Until then these are NULL.
#[unsafe(no_mangle)]
pub static mut __libc_stdin:  *mut File = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut __libc_stdout: *mut File = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut __libc_stderr: *mut File = core::ptr::null_mut();

/// Initialise the stdin/stdout/stderr C globals. Called once at
/// `__libc_start_main` time.
///
/// # Safety
/// Must run on the single-threaded startup path; the static-mut
/// writes are race-free under that invariant.
pub unsafe fn init_std_streams() {
    // SAFETY: single-threaded startup; the static_muts are written
    // exactly once.
    unsafe {
        __libc_stdin = crate::stdio::stdin();
        __libc_stdout = crate::stdio::stdout();
        __libc_stderr = crate::stdio::stderr();
    }
}
