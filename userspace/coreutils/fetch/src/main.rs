//! NARF coreutil: fetch
//!
//! Downloads a file over HTTP/1.1: `fetch [-o output] <url>` writes
//! the response body to `output` (or stdout with no `-o`). Follows
//! redirects (up to 5 hops). Understands `Content-Length` and
//! chunked (`Transfer-Encoding: chunked`) bodies.
//!
//! Deliberate limits of this binary (not of the fetch client as a
//! whole — the kernel-side `net::fetch` engine covers them):
//! - HTTP only. `https://` is refused: there is no TLS in
//!   userspace (the TLS 1.3 client lives in `net::tls_client` and
//!   the production root store is the open remainder #1802).
//! - Literal IPv4 hosts only. `getaddrinfo` has no resolver in
//!   tree, so a hostname cannot be resolved from this binary; use
//!   a literal address (the kernel `net::fetch` resolves hostnames
//!   via the in-tree DNS resolver).
//! - No close-delimited bodies: a response with neither
//!   `Content-Length` nor chunked framing is refused. `narf-libc`'s
//!   `recvfrom` loops on a kernel 0 return, so a userspace reader
//!   can never observe EOF (the kernel's `do_recv` returns Ok(0)
//!   for a peer FIN, but libc never surfaces it); waiting for EOF
//!   would hang. The kernel `net::fetch` client handles
//!   close-delimited bodies.
//!
//! Reference: RFC 9112 — HTTP/1.1 (message format §3, status line
//! §5, field lines §6, chunked §7.1); RFC 9110 §10.2.2 (redirects);
//! RFC 3986 §5.2 (relative resolution).

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

/// Socket read buffer / transfer chunk.
const BUF_SIZE: usize = 4096;
/// Longest URL argument accepted.
const MAX_URL: usize = 2048;
/// Longest single response-head line accepted.
const MAX_LINE: usize = 2048;
/// Longest `Location` value accepted.
const MAX_LOCATION: usize = 1024;
/// Longest request-target accepted.
const MAX_PATH: usize = 1024;
/// Longest host accepted.
const MAX_HOST: usize = 255;
/// Body cap (matches the kernel client's default): 16 MiB.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Redirect hop cap (matches the kernel client's default).
const MAX_REDIRECTS: u8 = 5;

// ── Small output helpers (mirroring coreutils/cat) ───────────────────

/// Write `bytes` to fd 2 (stderr), looping on short writes.
unsafe fn write_stderr(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: bytes is a valid slice.
        let n = unsafe {
            libc::posix_write(
                2,
                bytes.as_ptr().add(written) as *const _,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
}

/// Write a decimal `u64` to stderr.
unsafe fn write_stderr_u64(mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    if n == 0 {
        i -= 1;
        digits[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    // SAFETY: digits[i..] is a valid slice.
    unsafe { write_stderr(&digits[i..]) };
}

/// Walk a NUL-terminated C string and return its byte length.
unsafe fn cstr_len(p: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller guarantees p is NUL-terminated.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

// ── Byte-slice helpers ────────────────────────────────────────────────

/// Case-insensitive ASCII equality.
fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Trim leading/trailing spaces and tabs.
fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if b == b' ' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = s.split_last() {
        if b == b' ' || b == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Parse a decimal `usize` (no sign, no whitespace). `None` on any
/// bad byte or on overflow.
fn parse_decimal(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(n)
}

/// Parse a hexadecimal `usize` (chunk-size line, no `0x` prefix).
fn parse_hex(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => return None,
        };
        n = n.checked_mul(16)?.checked_add(d)?;
    }
    Some(n)
}

// ── URL ───────────────────────────────────────────────────────────────

/// Why a URL argument was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlError {
    /// Malformed (no scheme, empty host, bad port, bad path).
    BadUrl,
    /// `https://` — no TLS in this binary.
    Https,
    /// The host is not a literal IPv4 address (no DNS resolver in
    /// this binary).
    Hostname,
    /// A redirect `Location` was empty or unusable.
    BadLocation,
}

/// A parsed `http://host[:port][/path][?query]` URL. The host is a
/// literal IPv4 address; `host_cstr` is its NUL-terminated copy for
/// `inet_pton`.
struct Url {
    host: [u8; MAX_HOST],
    host_len: usize,
    host_cstr: [u8; MAX_HOST + 1],
    port: u16,
    path: [u8; MAX_PATH],
    path_len: usize,
}

impl Url {
    fn host(&self) -> &[u8] {
        &self.host[..self.host_len]
    }

    fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// The `Host` header value: bare host for port 80, `host:port`
    /// otherwise. Written into `out`; returns the length, or `None`
    /// when it does not fit.
    fn host_header(&self, out: &mut [u8]) -> Option<usize> {
        let mut n = 0usize;
        for &b in self.host() {
            if n >= out.len() {
                return None;
            }
            out[n] = b;
            n += 1;
        }
        if self.port != 80 {
            if n + 1 >= out.len() {
                return None;
            }
            out[n] = b':';
            n += 1;
            let mut digits = [0u8; 5];
            let mut d = 0usize;
            let mut p = self.port;
            if p == 0 {
                digits[d] = b'0';
                d += 1;
            } else {
                let mut rev = [0u8; 5];
                let mut r = 0usize;
                while p > 0 {
                    rev[r] = b'0' + (p % 10) as u8;
                    r += 1;
                    p /= 10;
                }
                while r > 0 {
                    r -= 1;
                    digits[d] = rev[r];
                    d += 1;
                }
            }
            for &b in &digits[..d] {
                if n >= out.len() {
                    return None;
                }
                out[n] = b;
                n += 1;
            }
        }
        Some(n)
    }
}

/// Parse an `http://` URL argument. The fragment (`#...`) is
/// stripped — fragments are never sent (RFC 9110 §4.2.1).
fn parse_url(input: &[u8]) -> Result<Url, UrlError> {
    let (scheme, rest) = match find_subslice(input, b"://") {
        Some(i) => (&input[..i], &input[i + 3..]),
        None => return Err(UrlError::BadUrl),
    };
    if eq_ignore_case(scheme, b"https") {
        return Err(UrlError::Https);
    }
    if !eq_ignore_case(scheme, b"http") {
        return Err(UrlError::BadUrl);
    }
    let rest = match find_subslice(rest, b"#") {
        Some(i) => &rest[..i],
        None => rest,
    };
    let (authority, path) = match find_subslice(rest, b"/") {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, b"/".as_slice()),
    };
    if authority.is_empty() || find_subslice(authority, b"@").is_some() {
        return Err(UrlError::BadUrl);
    }
    if authority.starts_with(b"[") {
        // IPv6 literal: not supported by this binary.
        return Err(UrlError::BadUrl);
    }
    let (host, port) = match authority.iter().rposition(|&b| b == b':') {
        Some(i) => {
            let p = parse_decimal(&authority[i + 1..]).ok_or(UrlError::BadUrl)?;
            if p == 0 || p > 65535 {
                return Err(UrlError::BadUrl);
            }
            (&authority[..i], p as u16)
        }
        None => (authority, 80u16),
    };
    if host.is_empty()
        || host.len() > MAX_HOST
        || path.len() > MAX_PATH
        || host.iter().any(|&b| b <= b' ' || b == 0x7f || b == b':')
        || path.iter().any(|&b| b <= b' ' || b == 0x7f)
    {
        return Err(UrlError::BadUrl);
    }
    let mut url = Url {
        host: [0u8; MAX_HOST],
        host_len: host.len(),
        host_cstr: [0u8; MAX_HOST + 1],
        port,
        path: [0u8; MAX_PATH],
        path_len: path.len(),
    };
    url.host[..host.len()].copy_from_slice(host);
    url.host_cstr[..host.len()].copy_from_slice(host);
    url.host_cstr[host.len()] = 0;
    url.path[..path.len()].copy_from_slice(path);
    // The host must be a literal IPv4 address: there is no DNS
    // resolver behind `getaddrinfo` in this binary.
    let mut packed: u32 = 0;
    // SAFETY: host_cstr is NUL-terminated; packed is a writable u32.
    let rc = unsafe {
        libc::inet_pton(
            libc::AF_INET,
            url.host_cstr.as_ptr() as *const i8,
            &mut packed as *mut u32 as *mut _,
        )
    };
    if rc != 1 {
        return Err(UrlError::Hostname);
    }
    Ok(url)
}

/// Dot-segment removal (RFC 3986 §5.2.4) over a path. Writes into
/// `out`; returns the length, or `None` when it does not fit.
fn normalize_path(path: &[u8], out: &mut [u8]) -> Option<usize> {
    // Segment stack as (start, len) pairs into a scratch copy.
    let mut segs: [(&[u8], usize); 64] = [(&[], 0); 64];
    let mut nseg = 0usize;
    for seg in path.split(|&b| b == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                nseg = nseg.saturating_sub(1);
            }
            s => {
                if nseg >= segs.len() {
                    return None;
                }
                segs[nseg] = (s, s.len());
                nseg += 1;
            }
        }
    }
    let mut n = 0usize;
    if n >= out.len() {
        return None;
    }
    out[n] = b'/';
    n += 1;
    for i in 0..nseg {
        let (s, len) = segs[i];
        if i > 0 {
            if n >= out.len() {
                return None;
            }
            out[n] = b'/';
            n += 1;
        }
        if n + len > out.len() {
            return None;
        }
        out[n..n + len].copy_from_slice(s);
        n += len;
    }
    Some(n)
}

/// Resolve a redirect `Location` against `base` (RFC 3986 §5.2).
fn resolve_relative(base: &Url, location: &[u8]) -> Result<Url, UrlError> {
    let loc = match find_subslice(location, b"#") {
        Some(i) => &location[..i],
        None => location,
    };
    if loc.is_empty() {
        return Err(UrlError::BadLocation);
    }
    if find_subslice(loc, b"://").is_some() {
        return parse_url(loc);
    }
    if let Some(rest) = loc.strip_prefix(b"//") {
        let mut full = [0u8; MAX_URL];
        let prefix = b"http://";
        if prefix.len() + rest.len() > full.len() {
            return Err(UrlError::BadUrl);
        }
        full[..prefix.len()].copy_from_slice(prefix);
        full[prefix.len()..prefix.len() + rest.len()].copy_from_slice(rest);
        return parse_url(&full[..prefix.len() + rest.len()]);
    }
    let mut url = Url {
        host: base.host,
        host_len: base.host_len,
        host_cstr: base.host_cstr,
        port: base.port,
        path: [0u8; MAX_PATH],
        path_len: 0,
    };
    if let Some(path) = loc.strip_prefix(b"/") {
        let mut full = [0u8; MAX_PATH];
        full[0] = b'/';
        if path.len() + 1 > full.len() {
            return Err(UrlError::BadUrl);
        }
        full[1..1 + path.len()].copy_from_slice(path);
        let n = normalize_path(&full[..1 + path.len()], &mut url.path).ok_or(UrlError::BadUrl)?;
        url.path_len = n;
        return Ok(url);
    }
    // Relative: merge with the base directory, then normalize.
    let (rel_path, query) = match find_subslice(loc, b"?") {
        Some(i) => (&loc[..i], Some(&loc[i..])),
        None => (loc, None),
    };
    let base_path = base.path();
    let dir_end = base_path
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let mut merged = [0u8; MAX_PATH];
    let mut m = 0usize;
    if dir_end > merged.len() || dir_end + rel_path.len() > merged.len() {
        return Err(UrlError::BadUrl);
    }
    merged[..dir_end].copy_from_slice(&base_path[..dir_end]);
    m += dir_end;
    merged[m..m + rel_path.len()].copy_from_slice(rel_path);
    m += rel_path.len();
    let n = normalize_path(&merged[..m], &mut url.path).ok_or(UrlError::BadUrl)?;
    url.path_len = n;
    if let Some(q) = query {
        if url.path_len + q.len() > url.path.len() {
            return Err(UrlError::BadUrl);
        }
        url.path[url.path_len..url.path_len + q.len()].copy_from_slice(q);
        url.path_len += q.len();
    }
    Ok(url)
}

// ── Buffered socket reader ────────────────────────────────────────────

/// A small buffered reader over a connected socket fd. Bytes the
/// head parser reads ahead stay buffered for the body reader, so
/// the head/body boundary is never lost.
struct Reader {
    fd: i32,
    buf: [u8; BUF_SIZE],
    pos: usize,
    len: usize,
}

impl Reader {
    fn new(fd: i32) -> Self {
        Self {
            fd,
            buf: [0u8; BUF_SIZE],
            pos: 0,
            len: 0,
        }
    }

    /// Fill the buffer. `Ok(true)` = data available, `Ok(false)` =
    /// EOF (unreachable through `narf-libc`'s `recv`, which loops on
    /// a kernel 0 — see the module docs — so EOF surfaces here only
    /// if that ever changes), `Err(())` = recv error.
    fn fill(&mut self) -> Result<bool, ()> {
        if self.pos < self.len {
            return Ok(true);
        }
        // SAFETY: buf is a writable BUF_SIZE region; flags 0.
        let n = unsafe { libc::recv(self.fd, self.buf.as_mut_ptr() as *mut _, BUF_SIZE, 0) };
        if n < 0 {
            return Err(());
        }
        if n == 0 {
            return Ok(false);
        }
        self.pos = 0;
        self.len = n as usize;
        Ok(true)
    }

    /// One byte, or `None` on EOF.
    fn read_byte(&mut self) -> Result<Option<u8>, ()> {
        if !self.fill()? {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    /// One CRLF-terminated line (without the CRLF), or `None` on
    /// EOF before any byte. `Err(())` when the line overflows `out`
    /// or the socket errors. A trailing CR is stripped by the
    /// caller via `trim_ows`-style handling; lines here keep the CR
    /// so the caller can see it.
    fn read_line(&mut self, out: &mut [u8]) -> Result<Option<usize>, ()> {
        let mut n = 0usize;
        loop {
            match self.read_byte()? {
                None => {
                    if n == 0 {
                        return Ok(None);
                    }
                    return Ok(Some(n));
                }
                Some(b'\n') => return Ok(Some(n)),
                Some(b) => {
                    if n >= out.len() {
                        return Err(());
                    }
                    out[n] = b;
                    n += 1;
                }
            }
        }
    }

    /// Fill `out` exactly, or fail on EOF / socket error.
    fn read_exact(&mut self, mut out: &mut [u8]) -> Result<(), ()> {
        while !out.is_empty() {
            if !self.fill()? {
                return Err(());
            }
            let avail = self.len - self.pos;
            let n = avail.min(out.len());
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            out = &mut out[n..];
        }
        Ok(())
    }

    /// Up to `out.len()` bytes (at least 1 unless EOF). Used for
    /// streaming a body to the output fd.
    fn read_some(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        if !self.fill()? {
            return Ok(0);
        }
        let n = (self.len - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

// ── HTTP exchange ─────────────────────────────────────────────────────

/// What the response head declared.
struct Head {
    status: u16,
    /// `Content-Length`, if present.
    content_length: Option<usize>,
    /// `Transfer-Encoding` included a `chunked` token.
    chunked: bool,
    /// `Location` value, if present.
    location: [u8; MAX_LOCATION],
    location_len: usize,
}

impl Head {
    fn location(&self) -> Option<&[u8]> {
        if self.location_len == 0 {
            None
        } else {
            Some(&self.location[..self.location_len])
        }
    }
}

/// Connect a TCP socket to `url` (literal IPv4 host).
fn tcp_connect(url: &Url) -> Result<i32, ()> {
    // SAFETY: AF_INET/SOCK_STREAM socket open.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(());
    }
    let mut packed: u32 = 0;
    // SAFETY: host_cstr is NUL-terminated; packed is a writable u32.
    let rc = unsafe {
        libc::inet_pton(
            libc::AF_INET,
            url.host_cstr.as_ptr() as *const i8,
            &mut packed as *mut u32 as *mut _,
        )
    };
    if rc != 1 {
        // SAFETY: fd was returned by socket.
        unsafe { libc::posix_close(fd) };
        return Err(());
    }
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        // SAFETY: htons is pure byte order conversion.
        sin_port: unsafe { libc::htons(url.port) },
        sin_addr: libc::in_addr { s_addr: packed },
        sin_zero: [0u8; 8],
    };
    // SAFETY: addr is a valid sockaddr_in; length is its size.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if rc != 0 {
        // SAFETY: fd was returned by socket.
        unsafe { libc::posix_close(fd) };
        return Err(());
    }
    Ok(fd)
}

/// Write all of `buf` to `fd`, looping on short writes.
fn write_all(fd: i32, buf: &[u8]) -> Result<(), ()> {
    let mut sent = 0usize;
    while sent < buf.len() {
        // SAFETY: buf is a valid slice.
        let n =
            unsafe { libc::posix_write(fd, buf.as_ptr().add(sent) as *const _, buf.len() - sent) };
        if n <= 0 {
            return Err(());
        }
        sent += n as usize;
    }
    Ok(())
}

/// Send the GET request for `url` over `fd`.
fn send_request(fd: i32, url: &Url) -> Result<(), ()> {
    let mut req = [0u8; MAX_URL];
    let mut n = 0usize;
    let put = |req: &mut [u8; MAX_URL], n: &mut usize, s: &[u8]| -> Result<(), ()> {
        if *n + s.len() > req.len() {
            return Err(());
        }
        req[*n..*n + s.len()].copy_from_slice(s);
        *n += s.len();
        Ok(())
    };
    put(&mut req, &mut n, b"GET ")?;
    put(&mut req, &mut n, url.path())?;
    put(&mut req, &mut n, b" HTTP/1.1\r\nHost: ")?;
    let mut host_hdr = [0u8; MAX_HOST + 6];
    let hlen = url.host_header(&mut host_hdr).ok_or(())?;
    put(&mut req, &mut n, &host_hdr[..hlen])?;
    put(
        &mut req,
        &mut n,
        b"\r\nUser-Agent: narf-fetch/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
    )?;
    // SAFETY: send loops on short writes inside write_all's caller;
    // use the raw send here (sendto with no address).
    let mut sent = 0usize;
    while sent < n {
        // SAFETY: req[..n] is a valid slice.
        let r = unsafe { libc::send(fd, req.as_ptr().add(sent) as *const _, n - sent, 0) };
        if r <= 0 {
            return Err(());
        }
        sent += r as usize;
    }
    Ok(())
}

/// Read the response head: status line + fields up to the empty
/// line. Returns the parsed head.
fn read_head(r: &mut Reader) -> Result<Head, ()> {
    let mut line = [0u8; MAX_LINE];
    // Status line: `HTTP/1.1 SP status-code SP reason-phrase`.
    let n = r.read_line(&mut line)?.ok_or(())?;
    let status_line = if line[..n].ends_with(b"\r") {
        &line[..n - 1]
    } else {
        &line[..n]
    };
    let sp = find_subslice(status_line, b" ").ok_or(())?;
    let rest = &status_line[sp + 1..];
    if rest.len() < 3 || !rest[..3].iter().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let status =
        (rest[0] - b'0') as u16 * 100 + (rest[1] - b'0') as u16 * 10 + (rest[2] - b'0') as u16;
    let mut head = Head {
        status,
        content_length: None,
        chunked: false,
        location: [0u8; MAX_LOCATION],
        location_len: 0,
    };
    loop {
        let n = r.read_line(&mut line)?.ok_or(())?;
        let field_line = if line[..n].ends_with(b"\r") {
            &line[..n - 1]
        } else {
            &line[..n]
        };
        if field_line.is_empty() {
            break;
        }
        let colon = find_subslice(field_line, b":").ok_or(())?;
        let name = trim_ows(&field_line[..colon]);
        let value = trim_ows(&field_line[colon + 1..]);
        if eq_ignore_case(name, b"content-length") {
            let v = parse_decimal(value).ok_or(())?;
            match head.content_length {
                Some(prev) if prev != v => return Err(()),
                Some(_) => {}
                None => head.content_length = Some(v),
            }
        } else if eq_ignore_case(name, b"transfer-encoding") {
            for token in value.split(|&b| b == b',') {
                if eq_ignore_case(trim_ows(token), b"chunked") {
                    head.chunked = true;
                }
            }
        } else if eq_ignore_case(name, b"location") {
            if value.len() > MAX_LOCATION {
                return Err(());
            }
            head.location[..value.len()].copy_from_slice(value);
            head.location_len = value.len();
        }
    }
    Ok(head)
}

/// Stream a `Content-Length` body to `out_fd`. Returns bytes written.
fn copy_length(r: &mut Reader, out_fd: i32, mut remaining: usize) -> Result<u64, ()> {
    let mut scratch = [0u8; BUF_SIZE];
    let mut total: u64 = 0;
    while remaining > 0 {
        let want = remaining.min(BUF_SIZE);
        let n = r.read_some(&mut scratch[..want])?;
        if n == 0 {
            // EOF before Content-Length satisfied: truncated body.
            return Err(());
        }
        write_all(out_fd, &scratch[..n])?;
        remaining -= n;
        total += n as u64;
        if total > MAX_BODY_BYTES as u64 {
            return Err(());
        }
    }
    Ok(total)
}

/// Stream a chunked body to `out_fd`. Returns bytes written.
fn copy_chunked(r: &mut Reader, out_fd: i32) -> Result<u64, ()> {
    let mut scratch = [0u8; BUF_SIZE];
    let mut total: u64 = 0;
    let mut line = [0u8; MAX_LINE];
    loop {
        let n = r.read_line(&mut line)?.ok_or(())?;
        let size_line = if line[..n].ends_with(b"\r") {
            &line[..n - 1]
        } else {
            &line[..n]
        };
        // Strip chunk-ext (`;...`) before parsing the hex size.
        let size_field = match find_subslice(size_line, b";") {
            Some(i) => &size_line[..i],
            None => size_line,
        };
        let size = parse_hex(trim_ows(size_field)).ok_or(())?;
        if size == 0 {
            // Terminal chunk: consume trailer lines up to the empty
            // line, then the body is done.
            loop {
                let n = r.read_line(&mut line)?.ok_or(())?;
                let trailer_line = if line[..n].ends_with(b"\r") {
                    &line[..n - 1]
                } else {
                    &line[..n]
                };
                if trailer_line.is_empty() {
                    break;
                }
            }
            return Ok(total);
        }
        let mut remaining = size;
        while remaining > 0 {
            let want = remaining.min(BUF_SIZE);
            let n = r.read_some(&mut scratch[..want])?;
            if n == 0 {
                return Err(());
            }
            write_all(out_fd, &scratch[..n])?;
            remaining -= n;
            total += n as u64;
            if total > MAX_BODY_BYTES as u64 {
                return Err(());
            }
        }
        // Each chunk is followed by CRLF.
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(());
        }
    }
}

/// One fetch exchange: connect, GET, read the head, and stream the
/// body to `out_fd`. Returns `(status, Location, bytes_written)`.
/// A redirect body is not read (the connection is single-use).
fn exchange(url: &Url, out_fd: i32) -> Result<(u16, Option<[u8; MAX_LOCATION]>, usize, u64), ()> {
    let fd = tcp_connect(url)?;
    let result = (|| {
        send_request(fd, url)?;
        let mut r = Reader::new(fd);
        let head = read_head(&mut r)?;
        let location = match head.location() {
            Some(loc) => {
                let mut buf = [0u8; MAX_LOCATION];
                buf[..loc.len()].copy_from_slice(loc);
                Some(buf)
            }
            None => None,
        };
        let location_len = head.location_len;
        let written = if head.status >= 300 && head.status < 400 {
            // Redirect: do not consume the body.
            0
        } else if head.chunked {
            copy_chunked(&mut r, out_fd)?
        } else if let Some(n) = head.content_length {
            copy_length(&mut r, out_fd, n)?
        } else {
            // Close-delimited: unsupported in this binary (see the
            // module docs — libc recv never surfaces EOF).
            return Err(());
        };
        Ok((head.status, location, location_len, written))
    })();
    // SAFETY: fd was returned by tcp_connect.
    unsafe { libc::posix_close(fd) };
    result
}

/// Print a fetch failure to stderr.
unsafe fn fail(msg: &[u8]) {
    // SAFETY: msg is a valid slice.
    unsafe {
        write_stderr(b"fetch: ");
        write_stderr(msg);
        write_stderr(b"\n");
    }
}

fn usage() -> i32 {
    // SAFETY: literals are valid slices.
    unsafe {
        write_stderr(b"usage: fetch [-o output] <http://literal-ip[:port]/path>\n");
        write_stderr(b"  -o output  write the body to a file instead of stdout\n");
        write_stderr(b"  HTTP only; hostnames need the kernel fetch client (net::fetch)\n");
    }
    2
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // argv is kernel-provided; entry signature is fixed
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut output: *const u8 = core::ptr::null();
    let mut url_arg: *const u8 = core::ptr::null();
    let mut url_len = 0usize;
    let mut i = 1i32;
    while i < argc {
        // SAFETY: i < argc, so argv[i] is valid.
        let arg_ptr = unsafe { *argv.offset(i as isize) };
        if arg_ptr.is_null() {
            i += 1;
            continue;
        }
        // SAFETY: Valid memory or trusted environment
        let len = unsafe { cstr_len(arg_ptr) };
        // SAFETY: Valid memory or trusted environment
        let arg = unsafe { core::slice::from_raw_parts(arg_ptr, len) };
        if arg == b"-h" || arg == b"--help" {
            return usage();
        } else if arg == b"-o" {
            i += 1;
            if i >= argc {
                // SAFETY: literal is a valid slice.
                unsafe { write_stderr(b"fetch: -o needs an output path\n") };
                return 2;
            }
            // SAFETY: i < argc, so argv[i] is valid.
            output = unsafe { *argv.offset(i as isize) };
            // SAFETY: output is a valid NUL-terminated argv string
            // (or null, short-circuited by the is_null check).
            if output.is_null() || unsafe { cstr_len(output) } == 0 {
                return 2;
            }
        } else if arg.starts_with(b"-") {
            // SAFETY: literal is a valid slice.
            unsafe {
                write_stderr(b"fetch: unknown option: ");
                write_stderr(arg);
                write_stderr(b"\n");
            }
            return 2;
        } else if url_arg.is_null() {
            url_arg = arg_ptr;
            url_len = len;
        } else {
            // SAFETY: literal is a valid slice.
            unsafe { write_stderr(b"fetch: expected exactly one URL\n") };
            return 2;
        }
        i += 1;
    }
    if url_arg.is_null() {
        return usage();
    }
    // SAFETY: url_arg points at a NUL-terminated argv string.
    let url_bytes = unsafe { core::slice::from_raw_parts(url_arg, url_len) };
    if url_bytes.len() > MAX_URL {
        // SAFETY: literal is a valid slice.
        unsafe { fail(b"URL too long") };
        return 1;
    }
    let mut url = match parse_url(url_bytes) {
        Ok(u) => u,
        Err(UrlError::Https) => {
            // SAFETY: literal is a valid slice.
            unsafe {
                fail(b"https:// needs TLS, which is not available in this binary; use the kernel fetch client (net::fetch), see #1802")
            };
            return 1;
        }
        Err(UrlError::Hostname) => {
            // SAFETY: literal is a valid slice.
            unsafe {
                fail(b"hostname cannot be resolved here (no DNS resolver in this binary); use a literal IPv4 address, or the kernel fetch client (net::fetch)")
            };
            return 1;
        }
        Err(_) => {
            // SAFETY: literal is a valid slice.
            unsafe { fail(b"malformed URL (want http://literal-ip[:port]/path)") };
            return 1;
        }
    };

    // Open the output (stdout by default).
    let mut out_fd = 1i32;
    let mut out_is_file = false;
    if !output.is_null() {
        // SAFETY: output is a NUL-terminated argv string.
        let fd = unsafe {
            libc::posix_open(
                output as *const i8,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
        };
        if fd < 0 {
            // SAFETY: literal is a valid slice.
            unsafe { fail(b"cannot open output file") };
            return 1;
        }
        out_fd = fd;
        out_is_file = true;
    }

    let mut hops = 0u8;
    let mut total: u64 = 0;
    let code = loop {
        match exchange(&url, out_fd) {
            Ok((status, location, location_len, written)) => {
                total += written;
                match status {
                    200..=299 => break 0,
                    301 | 302 | 303 | 307 | 308 => {
                        let Some(loc) = location else {
                            // SAFETY: literal is a valid slice.
                            unsafe { fail(b"redirect without Location") };
                            break 1;
                        };
                        if hops >= MAX_REDIRECTS {
                            // SAFETY: literal is a valid slice.
                            unsafe { fail(b"too many redirects") };
                            break 1;
                        }
                        hops += 1;
                        match resolve_relative(&url, &loc[..location_len]) {
                            Ok(next) => url = next,
                            Err(UrlError::Https) => {
                                // SAFETY: literal is a valid slice.
                                unsafe {
                                    fail(b"redirect to https:// needs TLS, which is not available in this binary; use the kernel fetch client (net::fetch), see #1802")
                                };
                                break 1;
                            }
                            Err(UrlError::Hostname) => {
                                // SAFETY: literal is a valid slice.
                                unsafe {
                                    fail(b"redirect to a hostname cannot be resolved here; use the kernel fetch client (net::fetch)")
                                };
                                break 1;
                            }
                            Err(_) => {
                                // SAFETY: literal is a valid slice.
                                unsafe { fail(b"unusable redirect Location") };
                                break 1;
                            }
                        }
                    }
                    _ => {
                        // SAFETY: literal is a valid slice.
                        unsafe {
                            write_stderr(b"fetch: HTTP status ");
                            let mut digits = [0u8; 3];
                            digits[0] = b'0' + ((status / 100) % 10) as u8;
                            digits[1] = b'0' + ((status / 10) % 10) as u8;
                            digits[2] = b'0' + (status % 10) as u8;
                            write_stderr(&digits);
                            write_stderr(b"\n");
                        }
                        break 1;
                    }
                }
            }
            Err(()) => {
                // SAFETY: literal is a valid slice.
                unsafe { fail(b"fetch failed (connect, request, or response error)") };
                break 1;
            }
        }
    };
    if out_is_file {
        // SAFETY: out_fd was returned by posix_open.
        unsafe { libc::posix_close(out_fd) };
        if code == 0 {
            // SAFETY: literals are valid slices.
            unsafe {
                write_stderr(b"fetch: saved ");
                write_stderr_u64(total);
                write_stderr(b" bytes\n");
            }
        } else {
            // A failed download must not leave a partial file behind.
            // SAFETY: output is a NUL-terminated argv string.
            unsafe { libc::posix_unlink(output as *const i8) };
        }
    }
    code
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
