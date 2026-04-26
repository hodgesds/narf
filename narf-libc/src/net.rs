//! `<arpa/inet.h>` byte-order + IPv4 address parsing surface.
//!
//! Path-B scope (Stage 4 Tier 3m): the load-bearing subset a user
//! program writing a TCP client needs, with no kernel dependency.
//! IPv6 (`AF_INET6`) is deferred — the parser is a separate state
//! machine and not yet exercised by anything on this branch.
//!
//! All four byte-order helpers are unconditional swaps because NARF
//! targets are little-endian (x86_64, aarch64 default config). On a
//! big-endian target they'd compile away; we keep the code simple by
//! always swapping rather than `#[cfg]`-ing the host endian.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

pub type in_addr_t = u32;

pub const AF_INET: c_int = 2;
pub const INADDR_NONE: in_addr_t = 0xFFFF_FFFF;
pub const INET_ADDRSTRLEN: usize = 16;

/// `htonl(x)` — host (little-endian) → network (big-endian) for u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn htonl(x: u32) -> u32 {
    x.swap_bytes()
}

/// `htons(x)` — host → network for u16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn htons(x: u16) -> u16 {
    x.swap_bytes()
}

/// `ntohl(x)` — network → host for u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntohl(x: u32) -> u32 {
    x.swap_bytes()
}

/// `ntohs(x)` — network → host for u16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntohs(x: u16) -> u16 {
    x.swap_bytes()
}

/// Walk a NUL-terminated string and try to parse a single decimal
/// octet (0..=255). Returns `Some((value, bytes_consumed))` on
/// success. Strict: rejects empty input, leading `+`, and 4+ digit
/// runs.
fn parse_octet(s: &[u8]) -> Option<(u32, usize)> {
    let mut acc: u32 = 0;
    let mut n = 0usize;
    while n < s.len() && s[n].is_ascii_digit() {
        if n >= 3 { return None; }
        acc = acc * 10 + (s[n] - b'0') as u32;
        n += 1;
    }
    if n == 0 || acc > 255 { return None; }
    Some((acc, n))
}

/// `inet_aton(cp, *out)` — parse a dotted-quad IPv4 string and write
/// the packed 32-bit address (network-byte-order) through `out`.
/// Returns 1 on success, 0 on parse failure (matching POSIX, which
/// is the *opposite* of every other libc function — be careful).
///
/// We accept only the canonical `a.b.c.d` form. The historical
/// `a.b`, `a.b.c`, and single-integer forms are deliberately
/// rejected — they're rarely intended and trip up validators.
///
/// # Safety
/// `cp` must be a valid NUL-terminated C string; `inp` must be a
/// writable `*mut in_addr_t` (or NULL — we then just return the
/// parse-success indicator).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inet_aton(cp: *const c_char, inp: *mut in_addr_t) -> c_int {
    if cp.is_null() { return 0; }
    // SAFETY: caller-supplied NUL-terminated C string.
    let mut len = 0usize;
    unsafe {
        while *cp.add(len) != 0 { len += 1; }
    }
    // SAFETY: NUL-bounded length + caller's pointer.
    let bytes = unsafe { core::slice::from_raw_parts(cp as *const u8, len) };

    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let (v, consumed) = match parse_octet(&bytes[i..]) {
            Some(p) => p,
            None    => return 0,
        };
        if idx >= 4 { return 0; }
        octets[idx] = v as u8;
        idx += 1;
        i += consumed;
        if i == bytes.len() {
            break;
        }
        if bytes[i] != b'.' || idx == 4 { return 0; }
        i += 1; // consume the dot
    }
    if idx != 4 { return 0; }
    // Big-endian packed (a.b.c.d → 0x abcd in network order).
    let packed: u32 = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        |  (octets[3] as u32);
    if !inp.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *inp = packed.swap_bytes(); } // store as network-order bytes
    }
    1
}

/// `inet_addr(cp)` — convenience wrapper. Returns the packed
/// network-byte-order address on success, `INADDR_NONE` on failure
/// (so a successful "255.255.255.255" parse is indistinguishable
/// from an error — that's the POSIX legacy and we honour it).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inet_addr(cp: *const c_char) -> in_addr_t {
    let mut out: in_addr_t = 0;
    // SAFETY: forwarded under the same caller contract.
    let rc = unsafe { inet_aton(cp, &mut out) };
    if rc == 1 { out } else { INADDR_NONE }
}

/// `inet_pton(af, src, dst)` — strict address-family-aware parse.
/// Returns 1 on success, 0 on invalid input, -1 on unsupported
/// `af`. Currently only `AF_INET` is wired; passing any other
/// family (e.g. `AF_INET6 = 10`) returns -1 with errno
/// `EAFNOSUPPORT`-equivalent.
///
/// # Safety
/// `src` must be a valid NUL-terminated C string; `dst` must be a
/// writable region large enough for the requested family (`u32` for
/// `AF_INET`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inet_pton(
    af: c_int,
    src: *const c_char,
    dst: *mut core::ffi::c_void,
) -> c_int {
    if af != AF_INET { return -1; }
    if src.is_null() || dst.is_null() { return 0; }
    let mut packed: in_addr_t = 0;
    // SAFETY: forwarded under the same caller contract; we own the
    // local slot we hand to inet_aton.
    let rc = unsafe { inet_aton(src, &mut packed) };
    if rc != 1 { return 0; }
    // `inet_pton` writes the network-order bytes verbatim — same
    // shape inet_aton already produced.
    // SAFETY: caller asserts `dst` is at least sizeof(u32) writable.
    unsafe {
        core::ptr::write_unaligned(dst as *mut u32, packed);
    }
    1
}

/// `inet_ntop(af, src, dst, size)` — render a packed address into a
/// dotted-quad string. Returns `dst` on success or NULL on failure
/// (unsupported family, undersized buffer).
///
/// # Safety
/// `src` must point to a packed address of the family's size
/// (4 bytes for AF_INET); `dst` must be `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inet_ntop(
    af: c_int,
    src: *const core::ffi::c_void,
    dst: *mut c_char,
    size: usize,
) -> *const c_char {
    if af != AF_INET { return core::ptr::null(); }
    if src.is_null() || dst.is_null() { return core::ptr::null(); }
    if size < INET_ADDRSTRLEN { return core::ptr::null(); }
    // SAFETY: caller asserts `src` is at least 4 bytes readable.
    let packed: u32 = unsafe { core::ptr::read_unaligned(src as *const u32) };
    let a = (packed & 0xFF) as u8;
    let b = ((packed >> 8) & 0xFF) as u8;
    let c = ((packed >> 16) & 0xFF) as u8;
    let d = ((packed >> 24) & 0xFF) as u8;
    // Render byte-by-byte into the caller's buffer. We bound writes
    // by `size`; INET_ADDRSTRLEN is 16 which always fits "255.255.
    // 255.255\0" (15 chars + NUL).
    // SAFETY: caller-supplied writable region.
    let out = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, size) };
    let mut pos = 0usize;
    for (i, oct) in [a, b, c, d].iter().enumerate() {
        if i > 0 { out[pos] = b'.'; pos += 1; }
        if *oct >= 100 { out[pos] = b'0' + (*oct / 100); pos += 1; }
        if *oct >= 10  { out[pos] = b'0' + ((*oct / 10) % 10); pos += 1; }
        out[pos] = b'0' + (*oct % 10);
        pos += 1;
    }
    out[pos] = 0;
    dst as *const c_char
}
