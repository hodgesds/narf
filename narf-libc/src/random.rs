//! `<sys/random.h>` + `<sys/uio.h>` — random byte source and
//! scatter/gather I/O.
//!
//! `getrandom` — NARF has no kernel CSRNG surface today. We seed a
//! deterministic xorshift64 PRNG from a compile-time constant and
//! mix in any entropy the caller's flags suggest. This is NOT
//! cryptographically sound; the entry exists so libraries that probe
//! `getrandom` during init (Python's `random.SystemRandom`, OpenSSL's
//! seed mixer) can proceed. Callers that need real entropy will get
//! deterministic output and that's a documented gap until the
//! kernel grows a CSRNG.
//!
//! `readv` / `writev` — stitch a vector of buffers over the existing
//! read / write surface, one element at a time. Short reads/writes
//! at element boundaries are reported as the cumulative count. This
//! matches the Linux semantics on a non-atomic file descriptor.

#![allow(non_camel_case_types)]

use crate::posix::{c_int, c_void, ssize_t};

// ── getrandom ───────────────────────────────────────────────────────

pub const GRND_NONBLOCK: c_int = 1 << 0;
pub const GRND_RANDOM:   c_int = 1 << 1;
pub const GRND_INSECURE: c_int = 1 << 2;

// SAFETY: see callers — every PRNG_STATE access is documented at
// the use site as single-threaded user mode (no aliasing in
// practice). The `&raw mut` form below is the Rust 2024 way to
// take a raw pointer to a mutable static without going through a
// `&mut` reference (which would risk UB if the static were ever
// touched by a parallel signal handler).
//
// xorshift64 — fast, deterministic, sufficient for "give me bytes
// that look random" use cases. Seeded with a non-zero constant so
// the first call returns a valid stream.
static mut PRNG_STATE: u64 = 0x9E37_79B9_7F4A_7C15;

#[inline]
/// xorshift64 step. Takes a raw pointer (rather than `&mut u64`)
/// so callers can hand it `&raw mut PRNG_STATE` without violating
/// the rust_2024_compatibility lint about aliasing risk on
/// mutable statics. Caller is responsible for ensuring no other
/// reference to `state` exists for the duration of the call;
/// every caller in this crate runs single-threaded user mode.
unsafe fn xorshift64(state: *mut u64) -> u64 {
    // SAFETY: caller-asserted exclusive access to `*state`.
    let mut x = unsafe { *state };
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    // SAFETY: same.
    unsafe {
        *state = x;
    }
    x
}

/// `getrandom(buf, buflen, flags)` — write up to `buflen` bytes of
/// pseudo-random data into `buf`. Returns the number of bytes
/// produced (always `buflen` here — we never block, never short-
/// return), or -1 on a NULL buffer.
///
/// NOTE: the underlying source is xorshift64, not a CSRNG. Real
/// cryptographic uses must wait for a kernel CSRNG.
///
/// # Safety
/// `buf` must point to at least `buflen` writable bytes when
/// `buflen > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrandom(
    buf:    *mut c_void,
    buflen: usize,
    _flags: c_int,
) -> ssize_t {
    if buf.is_null() && buflen != 0 {
        return -1;
    }
    if buflen == 0 {
        return 0;
    }
    // SAFETY: caller-supplied writable buffer of `buflen` bytes.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, buflen) };
    let mut i = 0usize;
    while i < buflen {
        // SAFETY: single-threaded user mode; PRNG_STATE access
        // is race-free. xorshift64 takes a `*mut u64` so we
        // can hand it a raw pointer derived from `&raw mut`
        // without going through a `&mut` (which would trip the
        // rust_2024_compatibility static_mut_refs lint).
        let v = unsafe { xorshift64(&raw mut PRNG_STATE) };
        let chunk = v.to_le_bytes();
        let n = core::cmp::min(8, buflen - i);
        slice[i..i + n].copy_from_slice(&chunk[..n]);
        i += n;
    }
    buflen as ssize_t
}

/// `getentropy(buf, buflen)` — OpenBSD-flavour wrapper around
/// `getrandom`. Returns 0 on success, -1 if `buflen > 256` (the
/// OpenBSD cap). Most callers use this in place of `/dev/urandom`.
///
/// # Safety
/// Same as [`getrandom`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getentropy(buf: *mut c_void, buflen: usize) -> c_int {
    if buflen > 256 {
        crate::errno::set_errno(22 /* EINVAL */);
        return -1;
    }
    // SAFETY: forwarded.
    let n = unsafe { getrandom(buf, buflen, 0) };
    if n < 0 { -1 } else { 0 }
}

// ── readv / writev ──────────────────────────────────────────────────

/// `<sys/uio.h>` `struct iovec` — glibc layout. `iov_base` is a
/// `void *`; `iov_len` is a `size_t`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len:  usize,
}

/// `readv(fd, iov, iovcnt)` — gather-read. Walks the iovec array
/// and issues one `read` per element, accumulating the total bytes
/// read. On a short read at any element we stop and return the
/// running total — same semantics as Linux on a non-atomic fd.
///
/// # Safety
/// `iov` must point to `iovcnt` valid `iovec` entries; each
/// `iov_base` must be writable for `iov_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readv(
    fd:     c_int,
    iov:    *const iovec,
    iovcnt: c_int,
) -> ssize_t {
    if iov.is_null() || iovcnt < 0 {
        return -1;
    }
    let mut total: ssize_t = 0;
    for i in 0..iovcnt as usize {
        // SAFETY: caller-supplied `iov` of length `iovcnt`.
        let entry = unsafe { *iov.add(i) };
        if entry.iov_len == 0 {
            continue;
        }
        // SAFETY: forwarded contract.
        let n = unsafe { crate::posix::read(fd, entry.iov_base, entry.iov_len) };
        if n < 0 {
            return if total == 0 { -1 } else { total };
        }
        total += n;
        if (n as usize) < entry.iov_len {
            // Short read — stop.
            break;
        }
    }
    total
}

/// `writev(fd, iov, iovcnt)` — scatter-write. Mirror of [`readv`].
///
/// # Safety
/// `iov` must point to `iovcnt` valid `iovec` entries; each
/// `iov_base` must be readable for `iov_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn writev(
    fd:     c_int,
    iov:    *const iovec,
    iovcnt: c_int,
) -> ssize_t {
    if iov.is_null() || iovcnt < 0 {
        return -1;
    }
    let mut total: ssize_t = 0;
    for i in 0..iovcnt as usize {
        // SAFETY: caller-supplied `iov` of length `iovcnt`.
        let entry = unsafe { *iov.add(i) };
        if entry.iov_len == 0 {
            continue;
        }
        // SAFETY: forwarded contract.
        let n = unsafe { crate::posix::write(fd, entry.iov_base, entry.iov_len) };
        if n < 0 {
            return if total == 0 { -1 } else { total };
        }
        total += n;
        if (n as usize) < entry.iov_len {
            break;
        }
    }
    total
}
