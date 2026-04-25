//! POSIX `FILE*` layer — buffered, error-tracking, EOF-aware I/O on
//! top of the raw fd primitives in [`crate::io`] and the syscall
//! wrappers in [`narf_user_runtime`].
//!
//! Path-B scope (Stage 4): we ship the load-bearing subset of
//! `<stdio.h>` that real C / no_std-imitating-C programs reach for
//! first — `fopen` / `fclose` / `fread` / `fwrite` / `fputs` /
//! `fgets` / `fflush` / `feof` / `ferror` / `clearerr`, plus static
//! `stdin` / `stdout` / `stderr`. Wide chars, positional formatting,
//! and the full POSIX repositioning surface (`fseek`, `ftell`,
//! `rewind`, `fsetpos`) are deliberately deferred — they're not
//! used by any current consumer.
//!
//! Buffering policy:
//! - Read buffer: 4 KiB, lazily allocated on the first `fread`. We
//!   refill it in one `read(fd, ...)` call when empty; partial
//!   refills are honoured. EOF is latched the first time a refill
//!   returns 0 bytes, matching glibc.
//! - Write buffer: 4 KiB, lazily allocated on the first `fwrite` /
//!   `fputs`. We flush on buffer-full and — for fd 1 / fd 2 — on
//!   `\n`, approximating line-buffering. We don't have `isatty(3)`
//!   yet, so the heuristic is "stdout/stderr are line-buffered, all
//!   other FILE*s are full-buffered". When `isatty` lands, swap the
//!   `is_line_buffered` predicate over to it.
//!
//! Single-thread caveat: `narf-libc` is single-threaded by definition
//! (no pthreads, no thread-local FILE* registries), so the static
//! `stdin` / `stdout` / `stderr` instances are plain `static mut`
//! globals. POSIX requires the FILE* object to outlive the program;
//! `static mut` gives us exactly that with zero allocation surprises
//! and a stable address (relevant because consumers may compare
//! `f == stdout()` or stash the pointer in their own state). When
//! we grow threading, swap to per-thread storage with a proper lock.
//!
//! Wire layout: [`File`] is `#[repr(C)]` so that downstream C code
//! linking against this crate sees a stable shape. Adding fields is
//! a soft-break — append only.
//!
//! Error reporting: per POSIX, the FILE* layer latches errors in the
//! struct itself (`ferror`) rather than relying solely on `errno`.
//! We do both — set `errno` for callers that read it directly, and
//! stamp `f.err` so `ferror` can surface the latest failure.

use core::ptr::{addr_of_mut, null_mut};

use crate::heap::{free, malloc};
use crate::errno::set_errno;

/// Stream EOF / error sentinel. Matches the POSIX `EOF` macro.
pub const EOF: i32 = -1;

/// I/O buffer capacity. 4 KiB matches the BSD / glibc `BUFSIZ`
/// default and a single user page on every NARF target — refills
/// are exactly one syscall round-trip, no fragmentation.
const BUF_CAP: usize = 4096;

/// errno-shaped error codes we surface from the FILE* layer. Real
/// values are placeholders — they line up with the Linux numbers
/// for compatibility but we don't import a full `errno.h` here.
const EBADF:  i32 = 9;
const ENOMEM: i32 = 12;
const EIO:    i32 = 5;

/// Buffered file stream. Opaque to callers, accessed through a raw
/// pointer per POSIX (`FILE*`). `#[repr(C)]` keeps the layout stable
/// so a future C consumer linking against `narf-libc` can `extern`
/// the struct shape if it ever needs to inspect a field directly
/// (we don't recommend it — use the accessor functions).
#[repr(C)]
pub struct File {
    /// Underlying kernel fd. 0 = stdin, 1 = stdout, 2 = stderr per
    /// the kernel-installed defaults; other values come from
    /// `narf_user_runtime::open`.
    pub fd: u32,
    /// Read buffer base pointer. `None` if not yet allocated, or if
    /// allocation has failed. Capacity is always [`BUF_CAP`] when
    /// allocated.
    pub rbuf: Option<*mut u8>,
    /// Index of the next byte the consumer will pull from `rbuf`.
    pub rbuf_pos: usize,
    /// One-past-end of the valid region in `rbuf` (i.e.
    /// `rbuf[rbuf_pos..rbuf_end]` is the unread tail).
    pub rbuf_end: usize,
    /// Write buffer base pointer. `None` until the first write.
    pub wbuf: Option<*mut u8>,
    /// Bytes currently staged in `wbuf`. Always `<= BUF_CAP`.
    pub wbuf_len: usize,
    /// EOF latched on the first 0-byte read result. Cleared by
    /// `clearerr`.
    pub eof: bool,
    /// Last error code, or 0. Cleared by `clearerr`.
    pub err: i32,
    /// True if `fclose` should call `close(fd)` — false for the
    /// static `stdin` / `stdout` / `stderr` so we don't shut the
    /// process's standard streams from underneath later code that
    /// expects them to keep working (POSIX: `fclose` on stdout
    /// MAY close fd 1, but in our single-process model this would
    /// silently break subsequent `printf` calls — refuse it).
    pub owns_fd: bool,
}

impl File {
    /// Construct a `File` wrapping a kernel fd we did not open
    /// (stdin / stdout / stderr). All buffers start unallocated;
    /// they're created on first use so a binary that never touches
    /// stdio pays no heap cost.
    const fn for_std_fd(fd: u32) -> Self {
        Self {
            fd,
            rbuf: None,
            rbuf_pos: 0,
            rbuf_end: 0,
            wbuf: None,
            wbuf_len: 0,
            eof: false,
            err: 0,
            owns_fd: false,
        }
    }
}

// ── Static stdin / stdout / stderr ───────────────────────────────────
//
// The single-thread caveat at the module head explains why these are
// `static mut`s and not `OnceLock`s or `Lazy`s. Each helper returns a
// `*mut File` pointing at the static, which is stable for the program
// lifetime — addresses never move and the underlying fd 0/1/2 are
// pre-installed by the kernel before user code starts.

/// Static stdin instance. Wraps fd 0; `owns_fd = false` so `fclose`
/// won't tear it down.
static mut STDIN: File = File::for_std_fd(0);
/// Static stdout instance. Wraps fd 1; line-buffered for fd 1/2
/// per the policy described at the module head.
static mut STDOUT: File = File::for_std_fd(1);
/// Static stderr instance. Wraps fd 2.
static mut STDERR: File = File::for_std_fd(2);

/// Pointer to the static stdin `File`. Always returns the same
/// address across calls — POSIX guarantees `stdin` is a valid
/// `FILE*` for the entire program lifetime. `addr_of_mut!` only
/// computes an address (no reference, no aliasing requirement); the
/// single-thread invariant is the caller's responsibility.
pub fn stdin() -> *mut File {
    addr_of_mut!(STDIN)
}

/// Pointer to the static stdout `File`. See [`stdin`] for the
/// addressing-only rationale.
pub fn stdout() -> *mut File {
    addr_of_mut!(STDOUT)
}

/// Pointer to the static stderr `File`. See [`stdin`] for the
/// addressing-only rationale.
pub fn stderr() -> *mut File {
    addr_of_mut!(STDERR)
}

// ── Open / close ─────────────────────────────────────────────────────

/// Open `path` (UTF-8 byte slice + length) with `mode`. Modes are a
/// Path-B subset of POSIX:
/// - `"r"`  — read-only.
/// - `"w"`  — write-only (truncate semantics deferred — the kernel
///   side does not surface a truncate flag yet; today this is
///   indistinguishable from `"r+"` for an existing file).
/// - `"rw"` / `"r+"` — read-write.
///
/// Returns a heap-allocated `*mut File` on success, `null_mut()` on
/// failure. The caller must `fclose` to release the kernel fd and
/// the heap allocation.
///
/// **Path-B simplification**: our underlying `narf_user_runtime::open`
/// takes `(path, mount)`. We approximate that by splitting the
/// absolute path on the second `/`: e.g. `/testbin/f` becomes mount
/// `/testbin` + relative `f`. A real mount-table walk lives inside
/// the kernel; this shim is just enough to round-trip the testbin
/// stub-FS. TODO: once the kernel exposes a "resolve absolute path
/// to mount" syscall, drop this split and call that instead.
///
/// # Safety
/// `path` must be a valid pointer to `path_len` UTF-8 bytes. `mode`
/// is a regular `&str` (no NUL-termination requirement).
pub unsafe fn fopen(path: *const u8, path_len: usize, mode: &str) -> *mut File {
    if path.is_null() || path_len == 0 {
        set_errno(EBADF);
        return null_mut();
    }

    // SAFETY: caller-asserted (path,len) is a valid UTF-8 slice.
    let path_bytes = unsafe { core::slice::from_raw_parts(path, path_len) };
    let path_str = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            set_errno(EIO);
            return null_mut();
        }
    };

    // Split on the second '/' to derive (mount, relative) — see the
    // function doc-comment for why this is a Stage-4 approximation.
    if !path_str.starts_with('/') {
        set_errno(EBADF);
        return null_mut();
    }
    let after_root = &path_str[1..];
    let (mount, rel) = match after_root.find('/') {
        Some(i) => (&path_str[..1 + i], &path_str[1 + i + 1..]),
        // Single-segment path like "/foo" — treat the whole thing as
        // mount and pass an empty relative. Kernel behaviour on
        // empty rel is "open the mount root", which is what POSIX
        // expects for opening a directory file by its mount point.
        None => (path_str, ""),
    };

    let fd = match narf_user_runtime::open(rel, mount) {
        Some(fd) => fd,
        None => {
            set_errno(EIO);
            return null_mut();
        }
    };

    // Mode parsing is intentionally permissive: any string starting
    // with 'r' enables reads, any 'w' enables writes, '+' or "rw"
    // enables both. We don't surface mode-mismatch errors at the
    // FILE* layer — the kernel will reject reads on a write-only fd
    // (and vice-versa) when the syscall happens.
    let _ = mode; // (Reserved for when the kernel surfaces O_RDONLY/O_WRONLY/O_RDWR.)

    // Allocate the FILE struct on the bump heap. `malloc` returns
    // null on failure; we propagate that to the caller.
    let f = malloc(core::mem::size_of::<File>()) as *mut File;
    if f.is_null() {
        let _ = narf_user_runtime::close(fd);
        set_errno(ENOMEM);
        return null_mut();
    }
    // SAFETY: `malloc` returned a non-null 16-byte-aligned block of
    // at least `size_of::<File>()` bytes; writing the initialiser
    // into it is well-defined.
    unsafe {
        core::ptr::write(f, File {
            fd,
            rbuf: None, rbuf_pos: 0, rbuf_end: 0,
            wbuf: None, wbuf_len: 0,
            eof: false, err: 0,
            owns_fd: true,
        });
    }
    f
}

/// Flush and close the stream. Returns 0 on success, [`EOF`] on
/// failure. For the static stdin/stdout/stderr instances we flush
/// the write buffer but do NOT close the underlying fd — POSIX
/// permits this and our single-process model relies on those fds
/// staying live.
///
/// # Safety
/// `f` must be either a pointer returned by [`fopen`] or one of the
/// static `stdin` / `stdout` / `stderr` pointers. Calling `fclose`
/// twice on the same `fopen` pointer is undefined (per POSIX).
pub unsafe fn fclose(f: *mut File) -> i32 {
    if f.is_null() {
        return EOF;
    }
    // SAFETY: caller asserts `f` is a valid `File*`.
    let file = unsafe { &mut *f };

    // Flush any pending writes; treat a flush failure as a close
    // failure but still proceed with the rest of teardown so we
    // don't leak the fd.
    let mut rc = 0;
    // SAFETY: `f` is a valid pointer per the contract.
    if unsafe { fflush(f) } != 0 {
        rc = EOF;
    }

    if let Some(p) = file.rbuf.take() {
        // SAFETY: pointer came from `malloc`; `free` is no-op today
        // (bump allocator) but we still call it for forward
        // compatibility with a real freelist implementation.
        free(p);
    }
    if let Some(p) = file.wbuf.take() {
        free(p);
    }

    if file.owns_fd {
        if narf_user_runtime::close(file.fd).is_err() {
            rc = EOF;
        }
    }

    if file.owns_fd {
        // Owned `File` came from `malloc`; release the struct
        // itself. (Static stdin/stdout/stderr have `owns_fd = false`
        // and live in `.bss`, so we leave them alone.)
        free(f as *mut u8);
    }
    rc
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Lazily allocate the read buffer. Returns the slice or `None` if
/// allocation failed (in which case `f.err` is stamped with ENOMEM).
fn ensure_rbuf(f: &mut File) -> Option<*mut u8> {
    if let Some(p) = f.rbuf { return Some(p); }
    let p = malloc(BUF_CAP);
    if p.is_null() {
        f.err = ENOMEM;
        set_errno(ENOMEM);
        return None;
    }
    f.rbuf = Some(p);
    Some(p)
}

/// Lazily allocate the write buffer; mirrors [`ensure_rbuf`].
fn ensure_wbuf(f: &mut File) -> Option<*mut u8> {
    if let Some(p) = f.wbuf { return Some(p); }
    let p = malloc(BUF_CAP);
    if p.is_null() {
        f.err = ENOMEM;
        set_errno(ENOMEM);
        return None;
    }
    f.wbuf = Some(p);
    Some(p)
}

/// fd 1/2 are line-buffered today; everything else is fully
/// buffered. When `isatty` lands, swap this for a real terminal
/// check on the underlying fd.
fn is_line_buffered(fd: u32) -> bool {
    fd == 1 || fd == 2
}

/// Refill `f.rbuf` from the kernel. Returns the number of bytes
/// loaded (0 on EOF, which also latches `f.eof`).
fn refill(f: &mut File) -> usize {
    let p = match ensure_rbuf(f) {
        Some(p) => p,
        None => return 0,
    };
    // SAFETY: `p` points at `BUF_CAP` malloc-owned bytes; the
    // kernel writes at most `BUF_CAP` bytes back.
    let buf = unsafe { core::slice::from_raw_parts_mut(p, BUF_CAP) };
    let n = narf_user_runtime::read(f.fd, buf);
    f.rbuf_pos = 0;
    f.rbuf_end = n;
    if n == 0 {
        f.eof = true;
    }
    n
}

// ── Read / write ─────────────────────────────────────────────────────

/// `fread`: read up to `size * count` bytes through the read buffer.
/// Returns the number of *items* (not bytes) successfully read; a
/// short read is reported by returning a smaller item count, with
/// the residual byte fragment dropped (POSIX-correct: the next
/// `fread` resumes at the next item boundary).
///
/// # Safety
/// `buf` must point to at least `size * count` writable bytes. `f`
/// must be a valid `*mut File`.
pub unsafe fn fread(buf: *mut u8, size: usize, count: usize, f: *mut File) -> usize {
    if f.is_null() || buf.is_null() || size == 0 || count == 0 {
        return 0;
    }
    // SAFETY: caller asserts `f` is valid.
    let file = unsafe { &mut *f };

    let total_bytes = match size.checked_mul(count) {
        Some(n) => n,
        None => { file.err = EIO; return 0; }
    };

    let mut written = 0usize;
    while written < total_bytes {
        // Drain whatever's already in the buffer first.
        if file.rbuf_pos < file.rbuf_end {
            let avail = file.rbuf_end - file.rbuf_pos;
            let want  = total_bytes - written;
            let n     = if avail < want { avail } else { want };
            // SAFETY: rbuf is a `BUF_CAP`-byte allocation; positions
            // are bounded by `rbuf_end <= BUF_CAP`. `buf + written`
            // stays within the caller's slice by construction.
            unsafe {
                let src = file.rbuf.unwrap().add(file.rbuf_pos);
                let dst = buf.add(written);
                core::ptr::copy_nonoverlapping(src, dst, n);
            }
            file.rbuf_pos += n;
            written       += n;
            continue;
        }
        // Buffer empty — refill. EOF or error breaks the loop.
        if file.eof || file.err != 0 {
            break;
        }
        if refill(file) == 0 {
            break;
        }
    }
    // POSIX: partial-item bytes are not reported as items.
    written / size
}

/// `fwrite`: stage `size * count` bytes through the write buffer,
/// flushing on full or (for fd 1/2) on `\n`. Returns the number of
/// items written.
///
/// # Safety
/// `buf` must point to `size * count` readable bytes; `f` must be a
/// valid `*mut File`.
pub unsafe fn fwrite(buf: *const u8, size: usize, count: usize, f: *mut File) -> usize {
    if f.is_null() || buf.is_null() || size == 0 || count == 0 {
        return 0;
    }
    // SAFETY: caller asserts.
    let file = unsafe { &mut *f };

    let total = match size.checked_mul(count) {
        Some(n) => n,
        None => { file.err = EIO; return 0; }
    };
    let line_buf = is_line_buffered(file.fd);

    // Fast path: if the chunk doesn't fit in the buffer at all and
    // we're not line-buffered, flush whatever's pending and write
    // the chunk directly to avoid double-copying.
    if !line_buf && total >= BUF_CAP {
        // SAFETY: f is valid; flushing first preserves write order.
        if unsafe { fflush(f) } != 0 {
            return 0;
        }
        // SAFETY: caller-supplied (buf,total) describes the input.
        let slice = unsafe { core::slice::from_raw_parts(buf, total) };
        let n = narf_user_runtime::write(file.fd, slice);
        if n != total {
            file.err = EIO;
        }
        return n / size;
    }

    let wbuf_ptr = match ensure_wbuf(file) {
        Some(p) => p,
        None => return 0,
    };

    let mut copied = 0usize;
    while copied < total {
        let want = total - copied;
        let room = BUF_CAP - file.wbuf_len;
        let n = if room < want { room } else { want };
        // SAFETY: wbuf is a `BUF_CAP`-byte alloc; `wbuf_len + n <=
        // BUF_CAP` by construction; `buf + copied` is within the
        // caller's region.
        unsafe {
            let src = buf.add(copied);
            let dst = wbuf_ptr.add(file.wbuf_len);
            core::ptr::copy_nonoverlapping(src, dst, n);
        }
        file.wbuf_len += n;
        copied        += n;

        // Trigger a flush if we hit the brim or — for line-buffered
        // streams — if we just landed a `\n`. We flush only if the
        // newline lies inside the bytes we just copied (we don't
        // re-scan the whole buffer each iteration).
        let mut should_flush = file.wbuf_len == BUF_CAP;
        if line_buf && !should_flush {
            // SAFETY: scanning the just-copied region for '\n'.
            let just = unsafe {
                core::slice::from_raw_parts(wbuf_ptr.add(file.wbuf_len - n), n)
            };
            if just.contains(&b'\n') {
                should_flush = true;
            }
        }
        if should_flush {
            // SAFETY: `f` is valid (we hold `&mut *f` via `file`).
            if unsafe { fflush(f) } != 0 {
                // Partial write — return the count of full items
                // we managed to stage. Per POSIX, fwrite reports
                // items, not bytes.
                return copied / size;
            }
        }
    }
    copied / size
}

/// `fputs`: write `s_len` bytes via [`fwrite`]. Returns a
/// non-negative on success, [`EOF`] on failure. POSIX `fputs` takes
/// a NUL-terminated C string and discards the count; we accept an
/// explicit length so Rust callers don't need to NUL-pad.
///
/// # Safety
/// `s` must point to `s_len` readable bytes; `f` must be valid.
pub unsafe fn fputs(s: *const u8, s_len: usize, f: *mut File) -> i32 {
    if f.is_null() || s.is_null() {
        return EOF;
    }
    // SAFETY: forwarded to `fwrite` under the same contract.
    let n = unsafe { fwrite(s, 1, s_len, f) };
    if n == s_len { 0 } else { EOF }
}

/// `fgets`: read up to `max_len - 1` bytes (or until `\n` inclusive),
/// NUL-terminate, return `buf` on success or `null_mut()` on EOF
/// before any byte was read / on error.
///
/// # Safety
/// `buf` must point to at least `max_len` writable bytes; `f` must
/// be valid.
pub unsafe fn fgets(buf: *mut u8, max_len: usize, f: *mut File) -> *mut u8 {
    if f.is_null() || buf.is_null() || max_len < 2 {
        // max_len < 2 leaves no room for both a byte and the NUL.
        return null_mut();
    }
    // SAFETY: caller asserts.
    let file = unsafe { &mut *f };

    let mut written = 0usize;
    let cap = max_len - 1; // reserve a slot for the NUL.

    while written < cap {
        if file.rbuf_pos >= file.rbuf_end {
            if file.eof || file.err != 0 { break; }
            if refill(file) == 0 { break; }
        }
        // SAFETY: rbuf is non-null because refill() succeeded; the
        // slice [rbuf_pos..rbuf_end] is the valid unread region.
        let byte = unsafe { *file.rbuf.unwrap().add(file.rbuf_pos) };
        file.rbuf_pos += 1;
        // SAFETY: written < cap < max_len, so buf+written is in
        // bounds; caller-supplied buffer is writable by contract.
        unsafe { *buf.add(written) = byte; }
        written += 1;
        if byte == b'\n' { break; }
    }

    if written == 0 {
        // Ran into EOF or error before reading anything — POSIX
        // says return NULL and leave `buf` untouched (we touched
        // nothing if `written == 0`).
        return null_mut();
    }
    // SAFETY: written <= cap < max_len so buf+written is within
    // the caller's region; we promised a NUL terminator.
    unsafe { *buf.add(written) = 0; }
    buf
}

// ── Status / flush ───────────────────────────────────────────────────

/// `feof`: returns non-zero (1) if EOF has been latched on `f`.
///
/// # Safety
/// `f` must be valid.
pub unsafe fn feof(f: *mut File) -> i32 {
    if f.is_null() { return 0; }
    // SAFETY: caller asserts.
    if unsafe { (*f).eof } { 1 } else { 0 }
}

/// `ferror`: return the latched error code (0 if none).
///
/// # Safety
/// `f` must be valid.
pub unsafe fn ferror(f: *mut File) -> i32 {
    if f.is_null() { return 0; }
    // SAFETY: caller asserts.
    unsafe { (*f).err }
}

/// `clearerr`: clear both EOF and error latches.
///
/// # Safety
/// `f` must be valid.
pub unsafe fn clearerr(f: *mut File) {
    if f.is_null() { return; }
    // SAFETY: caller asserts.
    unsafe {
        (*f).eof = false;
        (*f).err = 0;
    }
}

/// `fflush`: emit the staged write buffer via the kernel `write`
/// syscall. Returns 0 on success, [`EOF`] on partial write / error.
/// `fflush(NULL)` would normally flush every open stream; we don't
/// track an open-stream registry yet, so passing null is a no-op
/// returning 0.
///
/// # Safety
/// If non-null, `f` must point at a valid `File`.
pub unsafe fn fflush(f: *mut File) -> i32 {
    if f.is_null() {
        // POSIX: fflush(NULL) flushes all open output streams. We
        // don't maintain a registry yet; treat as success so
        // consumers don't see spurious failures while we're still
        // landing the layer.
        return 0;
    }
    // SAFETY: caller asserts.
    let file = unsafe { &mut *f };
    if file.wbuf_len == 0 {
        return 0;
    }
    let p = match file.wbuf {
        Some(p) => p,
        // wbuf_len > 0 with no buffer is an inconsistency — treat
        // as a soft error, not UB.
        None => { file.err = EIO; return EOF; }
    };
    // SAFETY: wbuf is a BUF_CAP-byte alloc; wbuf_len <= BUF_CAP.
    let slice = unsafe { core::slice::from_raw_parts(p, file.wbuf_len) };
    let want = file.wbuf_len;
    let n = narf_user_runtime::write(file.fd, slice);
    file.wbuf_len = 0;
    if n != want {
        file.err = EIO;
        set_errno(EIO);
        return EOF;
    }
    0
}
