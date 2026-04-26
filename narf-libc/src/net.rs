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

// ── BSD socket API stubs ────────────────────────────────────────────
//
// NARF has no kernel socket layer. Real network I/O lives in a
// future userspace stack daemon (per `net/specification/spec.md`).
// Until that lands, all socket calls fail with `errno = ENOSYS`,
// allowing consumers to fall back (e.g. tools that fork off
// network-fetching code paths only when reachable). Surfaces below
// are link-only.

pub const ENOSYS: c_int = 38;

pub type socklen_t = u32;
pub type sa_family_t = u16;
pub type in_port_t = u16;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM:  c_int = 2;
pub const SOCK_RAW:    c_int = 3;

pub const AF_UNSPEC: c_int = 0;
pub const AF_UNIX:   c_int = 1;
pub const AF_INET6:  c_int = 10;

pub const IPPROTO_IP:   c_int = 0;
pub const IPPROTO_TCP:  c_int = 6;
pub const IPPROTO_UDP:  c_int = 17;

pub const SOL_SOCKET:   c_int = 1;
pub const SO_REUSEADDR: c_int = 2;
pub const SO_KEEPALIVE: c_int = 9;
pub const SO_LINGER:    c_int = 13;
pub const SO_RCVBUF:    c_int = 8;
pub const SO_SNDBUF:    c_int = 7;

pub const SHUT_RD:   c_int = 0;
pub const SHUT_WR:   c_int = 1;
pub const SHUT_RDWR: c_int = 2;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data:   [c_char; 14],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port:   in_port_t,
    pub sin_addr:   in_addr,
    pub sin_zero:   [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct sockaddr_in6 {
    pub sin6_family:   sa_family_t,
    pub sin6_port:     in_port_t,
    pub sin6_flowinfo: u32,
    pub sin6_addr:     [u8; 16],
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct addrinfo {
    pub ai_flags:    c_int,
    pub ai_family:   c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen:  socklen_t,
    pub ai_addr:     *mut sockaddr,
    pub ai_canonname:*mut c_char,
    pub ai_next:     *mut addrinfo,
}

pub const EAI_NONAME: c_int = -2;
pub const EAI_FAIL:   c_int = -4;

#[inline]
unsafe fn enosys_minus_one() -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `socket(domain, type, protocol)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn socket(_domain: c_int, _type: c_int, _protocol: c_int) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `bind(fd, *addr, len)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bind(
    _fd:   c_int,
    _addr: *const sockaddr,
    _len:  socklen_t,
) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `connect(fd, *addr, len)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect(
    _fd:   c_int,
    _addr: *const sockaddr,
    _len:  socklen_t,
) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `listen(fd, backlog)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn listen(_fd: c_int, _backlog: c_int) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `accept(fd, *addr, *len)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn accept(
    _fd:   c_int,
    _addr: *mut sockaddr,
    _len:  *mut socklen_t,
) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `shutdown(fd, how)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shutdown(_fd: c_int, _how: c_int) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `send(fd, *buf, len, flags)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn send(
    _fd:    c_int,
    _buf:   *const core::ffi::c_void,
    _len:   usize,
    _flags: c_int,
) -> isize {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() as isize }
}

/// `recv(fd, *buf, len, flags)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn recv(
    _fd:    c_int,
    _buf:   *mut core::ffi::c_void,
    _len:   usize,
    _flags: c_int,
) -> isize {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() as isize }
}

/// `sendto(fd, *buf, len, flags, *addr, alen)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendto(
    _fd:    c_int,
    _buf:   *const core::ffi::c_void,
    _len:   usize,
    _flags: c_int,
    _addr:  *const sockaddr,
    _alen:  socklen_t,
) -> isize {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() as isize }
}

/// `recvfrom(fd, *buf, len, flags, *addr, *alen)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvfrom(
    _fd:    c_int,
    _buf:   *mut core::ffi::c_void,
    _len:   usize,
    _flags: c_int,
    _addr:  *mut sockaddr,
    _alen:  *mut socklen_t,
) -> isize {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() as isize }
}

/// `getsockopt(fd, level, name, *val, *vlen)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockopt(
    _fd:    c_int,
    _level: c_int,
    _name:  c_int,
    _val:   *mut core::ffi::c_void,
    _vlen:  *mut socklen_t,
) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `setsockopt(fd, level, name, *val, vlen)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsockopt(
    _fd:    c_int,
    _level: c_int,
    _name:  c_int,
    _val:   *const core::ffi::c_void,
    _vlen:  socklen_t,
) -> c_int {
    // SAFETY: pure forwarding.
    unsafe { enosys_minus_one() }
}

/// `getaddrinfo(host, service, hints, *result)` — no resolver in
/// tree, so we always report `EAI_NONAME` (host not found) and
/// leave `*result` untouched. Real DNS lives in a userspace daemon
/// per `net/specification/spec.md`.
///
/// # Safety
/// `result` must be a writable `*mut *mut addrinfo`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getaddrinfo(
    _host:    *const c_char,
    _service: *const c_char,
    _hints:   *const addrinfo,
    result:   *mut *mut addrinfo,
) -> c_int {
    if !result.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *result = core::ptr::null_mut(); }
    }
    EAI_NONAME
}

/// `freeaddrinfo(p)` — no-op (we never returned a non-null result).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeaddrinfo(_p: *mut addrinfo) {}

/// `gai_strerror(err)` — return a human-readable string for the
/// `EAI_*` error code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gai_strerror(err: c_int) -> *const c_char {
    static NONAME: [u8; 33]  = *b"Name or service not known\0\0\0\0\0\0\0\0";
    static FAILURE:[u8; 33]  = *b"Non-recoverable failure in name r";
    static OK:     [u8; 8]   = *b"Success\0";
    let p: *const u8 = match err {
        0          => OK.as_ptr(),
        EAI_NONAME => NONAME.as_ptr(),
        EAI_FAIL   => FAILURE.as_ptr(),
        _          => OK.as_ptr(),
    };
    p as *const c_char
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
