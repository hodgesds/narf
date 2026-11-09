//! HTTP(S) fetch client — download a file over the wired/wifi net stack.
//!
//! The desktop package story needs a way to download a file; this is
//! the client side of it. Plain HTTP runs over [`TcpStream`]
//! (`net::tcp::core`); HTTPS runs the same HTTP/1.1 exchange over the
//! merged TLS 1.3 client ([`TlsStream`] over [`TlsClient`]).
//!
//! The engine ([`fetch`]) is transport-generic: it drives any
//! [`FetchStream`] (a byte stream with short reads), so fixtures can
//! drive it with [`MemStream`] and the HTTPS path with a scripted
//! TLS server flight ([`crate::tls_client::SliceTransport`]). The
//! production entry point is [`fetch_url`], which resolves the host
//! with the in-tree DNS resolver ([`crate::dns::resolve_a`], literal
//! IPv4 first), connects TCP, and — for `https://` — runs the TLS
//! handshake against a caller-provisioned [`RootStore`].
//!
//! Roots are deliberately NOT baked in here: the store starts empty
//! by design (see [`crate::tls_client`]) and production provisioning
//! is the open remainder tracked in #1802. A fetch against a host
//! whose chain is not in the provisioned store fails closed
//! ([`FetchError::Tls`]); there is no skip-verification mode.
//!
//! References (public-only):
//! - RFC 9112 — HTTP/1.1 (R. Fielding et al, June 2022). §3 Message
//!   Format. §5 Status Line. §6 Field Lines. §7.1 Chunked Transfer
//!   Coding. §6.3 (a recipient ignores `Content-Length` when
//!   `Transfer-Encoding` is present).
//!   <https://datatracker.ietf.org/doc/html/rfc9112>
//! - RFC 9110 — HTTP Semantics (R. Fielding et al, June 2022). §15
//!   Status Codes; §10.2.2 (3xx `Location`).
//!   <https://datatracker.ietf.org/doc/html/rfc9110>
//! - RFC 3986 — URI Generic Syntax (T. Berners-Lee et al, Jan 2005).
//!   §3.2.2 (host), §3.3 (path), §5.2 (relative resolution),
//!   §5.2.4 (dot-segment removal).
//!   <https://datatracker.ietf.org/doc/html/rfc3986>
//! - RFC 8446 — TLS 1.3 (E. Rescorla, Aug 2018), via
//!   [`crate::tls_client`].
//!
//! No GPL Linux source consulted.
//!
//! ## Out of scope (remainders)
//!
//! - IPv6 literals and AAAA resolution: the resolver surface used
//!   here is IPv4 (`resolve_a`); an IPv6 URL is rejected with
//!   [`FetchError::BadUrl`].
//! - HTTP/2 and HTTP/3: HTTP/1.1 only (see `http2.rs` / `quic.rs`
//!   for the codecs; no fetch binding yet).
//! - `HEAD`, `POST`, request bodies, cookies, authentication:
//!   GET only, no request body.
//! - Chunked trailers are not surfaced (the terminating zero chunk
//!   ends the body; trailing fields are skipped with the connection).
//! - A close-delimited body cut short by a reset is indistinguishable
//!   from a clean EOF (inherent to HTTP/1.1 close-delimited framing);
//!   `Content-Length` and chunked bodies fail closed on truncation.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::dns::ResolveError;
use crate::http::{
    append_end_of_headers, append_field, iter_chunks, parse_headers, HttpError, RequestLine,
    StatusLine,
};
use crate::tls_client::{ClientConfig, TcpTransport, TlsClient, TlsError, Transport};
use crate::tls_x509::RootStore;

/// Default cap on redirect hops (RFC 9110 §10.2.2 leaves the limit
/// to the client; curl's default is 50, wget's 20 — 5 is enough for
/// package mirrors and bounds a redirect loop).
pub const DEFAULT_MAX_REDIRECTS: u8 = 5;
/// Default cap on a downloaded body: 16 MiB (a package-sized fetch
/// with a bound against an unbounded server).
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Default cap on the response head (status line + fields).
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
/// The `User-Agent` this client sends.
pub const USER_AGENT: &str = "narf-fetch/1.0";

/// Errors from the fetch client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The URL did not parse (no scheme, empty host, bad port, bad
    /// path, IPv6 literal — see the module docs).
    BadUrl,
    /// The URL scheme is not `http` or `https`.
    UnsupportedScheme,
    /// DNS resolution failed (the resolver's own error is carried).
    Dns(ResolveError),
    /// DNS resolved, but to no address.
    NoAddress,
    /// TCP connect failed (refused, unreachable, or the connect
    /// wait timed out).
    Connect,
    /// The byte stream failed (TCP send/recv error, or a read
    /// deadline while waiting for more of a response).
    Transport,
    /// A TLS failure (handshake, alert, bad record MAC, certificate
    /// chain — see [`TlsError`]).
    Tls(TlsError),
    /// The HTTP framing was malformed (see [`HttpError`]), or a
    /// header value was unusable (bad `Content-Length`, conflicting
    /// duplicate `Content-Length`).
    Http(HttpError),
    /// A malformed header value that is not an [`HttpError`]
    /// (bad or conflicting `Content-Length`).
    BadHeader,
    /// The server answered with a non-2xx, non-redirect status; the
    /// value is the status code.
    HttpStatus(u16),
    /// A redirect response carried no usable `Location`.
    BadLocation,
    /// The redirect hop cap was reached.
    TooManyRedirects,
    /// The response head or body exceeded its cap.
    TooLarge,
}

impl From<HttpError> for FetchError {
    fn from(e: HttpError) -> Self {
        FetchError::Http(e)
    }
}

impl From<TlsError> for FetchError {
    fn from(e: TlsError) -> Self {
        FetchError::Tls(e)
    }
}

/// URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP (TCP port 80 by default).
    Http,
    /// HTTPS (TLS 1.3 over TCP port 443 by default).
    Https,
}

impl Scheme {
    /// `"http"` / `"https"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// The default TCP port for the scheme (RFC 9110 §4.2.3).
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// A parsed fetch URL: scheme, host, port, and path (including any
/// `?query`; the `#fragment` is stripped — fragments are never sent,
/// RFC 9110 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// `http` or `https`.
    pub scheme: Scheme,
    /// Hostname or literal IPv4 address (no brackets, no port).
    pub host: String,
    /// TCP port (defaulted from the scheme when absent).
    pub port: u16,
    /// Request target: absolute path, always starting with `/`,
    /// with any `?query` attached.
    pub path: String,
}

impl Url {
    /// Parse `http(s)://host[:port][/path][?query][#fragment]`.
    /// Userinfo (`user@host`) is rejected; IPv6 literals are rejected
    /// (see the module docs).
    pub fn parse(input: &str) -> Result<Url, FetchError> {
        let (scheme_str, rest) = input.split_once("://").ok_or(FetchError::BadUrl)?;
        let scheme = match scheme_str {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(FetchError::UnsupportedScheme),
        };
        // The fragment is never sent to the server.
        let rest = rest.split('#').next().unwrap_or("");
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, alloc::format!("/{p}")),
            None => (rest, String::from("/")),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(FetchError::BadUrl);
        }
        // IPv6 literals (`[::1]`) are not supported yet.
        if authority.starts_with('[') {
            return Err(FetchError::BadUrl);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                if p.is_empty() {
                    return Err(FetchError::BadUrl);
                }
                let port: u16 = p.parse().map_err(|_| FetchError::BadUrl)?;
                (h, port)
            }
            None => (authority, scheme.default_port()),
        };
        if host.is_empty() || host.contains(':') || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(FetchError::BadUrl);
        }
        if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(FetchError::BadUrl);
        }
        Ok(Url {
            scheme,
            host: host.to_string(),
            port,
            path,
        })
    }

    /// The `Host` header value: the bare host for a default port,
    /// `host:port` otherwise (RFC 9112 §3.2).
    pub fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            alloc::format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolve a `Location` value against this URL (RFC 3986 §5.2):
    /// absolute URI, scheme-relative (`//host/path`), absolute path,
    /// or a path relative to this URL's directory, with dot-segment
    /// removal (§5.2.4). The query (if any) rides along on the path.
    pub fn resolve_relative(&self, location: &str) -> Result<Url, FetchError> {
        let loc = location.split('#').next().unwrap_or("");
        if loc.is_empty() {
            return Err(FetchError::BadLocation);
        }
        if loc.contains("://") {
            return Url::parse(loc);
        }
        if let Some(rest) = loc.strip_prefix("//") {
            return Url::parse(&alloc::format!("{}://{rest}", self.scheme.as_str()));
        }
        if let Some(path) = loc.strip_prefix('/') {
            return Ok(Url {
                scheme: self.scheme,
                host: self.host.clone(),
                port: self.port,
                path: normalize_path(&alloc::format!("/{path}")),
            });
        }
        let (rel_path, query) = match loc.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (loc, None),
        };
        let base_dir = match self.path.rfind('/') {
            Some(i) => &self.path[..=i],
            None => "/",
        };
        let mut merged = normalize_path(&alloc::format!("{base_dir}{rel_path}"));
        if let Some(q) = query {
            merged.push('?');
            merged.push_str(q);
        }
        Ok(Url {
            scheme: self.scheme,
            host: self.host.clone(),
            port: self.port,
            path: merged,
        })
    }
}

/// Dot-segment removal (RFC 3986 §5.2.4) over the path part of a
/// URL (no query attached). `//` collapses; `.` drops; `..` pops.
fn normalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    out
}

/// A byte stream the fetch engine runs over. `read` may return short
/// reads; `Ok(0)` is a clean EOF (the peer closed). `write_all` must
/// loop internally until the whole buffer is sent.
pub trait FetchStream {
    /// Read up to `buf.len()` bytes. `Ok(0)` means EOF.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FetchError>;
    /// Write all of `buf`, or fail.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), FetchError>;
}

impl<S: FetchStream> FetchStream for &mut S {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FetchError> {
        (**self).read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), FetchError> {
        (**self).write_all(buf)
    }
}

/// An in-memory stream for fixtures: reads from a fixed input slice,
/// appends writes to an output buffer the test inspects.
#[derive(Debug)]
pub struct MemStream<'a> {
    input: &'a [u8],
    pos: usize,
    /// Everything written to the stream, in order.
    pub output: Vec<u8>,
}

impl<'a> MemStream<'a> {
    /// A stream over the given input bytes.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            output: Vec::new(),
        }
    }

    /// Bytes written so far.
    pub fn written(&self) -> &[u8] {
        &self.output
    }

    /// Bytes of input not yet consumed.
    pub fn remaining_input(&self) -> &[u8] {
        &self.input[self.pos..]
    }
}

impl FetchStream for MemStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FetchError> {
        let n = core::cmp::min(buf.len(), self.input.len() - self.pos);
        buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), FetchError> {
        self.output.extend_from_slice(buf);
        Ok(())
    }
}

/// A plain-TCP stream over a `net::tcp::core` socket id. Connects
/// with the `connect_wait` pattern and pumps the interface while
/// waiting for data (the same rule as [`TcpTransport`]: call from
/// sync context, not from inside an executor poll).
#[derive(Debug)]
pub struct TcpStream {
    id: u32,
}

impl TcpStream {
    /// Open a TCP connection to `ip:port` and wait for establishment.
    pub fn connect(ip: [u8; 4], port: u16) -> Result<Self, FetchError> {
        let id = crate::tcp::core::connect(ip, port).map_err(|_| FetchError::Connect)?;
        crate::tcp::core::connect_wait(id, crate::tcp::core::ConnectOptions::default())
            .map_err(|_| FetchError::Connect)?;
        Ok(Self { id })
    }

    /// The underlying socket id.
    pub fn socket_id(&self) -> u32 {
        self.id
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = crate::tcp::core::close(self.id);
    }
}

impl FetchStream for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FetchError> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match crate::tcp::core::recv(self.id, buf) {
                Ok(n) if n > 0 => return Ok(n),
                Ok(_) => {
                    // Nothing buffered. A readable socket with an
                    // empty buffer means the peer closed (or the
                    // connection died): that is EOF, not "try again".
                    // A pending socket error is a transport failure.
                    let (err, _) = crate::tcp::core::poll_err_hup(self.id);
                    if err {
                        return Err(FetchError::Transport);
                    }
                    if crate::tcp::core::readable(self.id) {
                        return Ok(0);
                    }
                    // Otherwise pump until data arrives, the peer
                    // closes, or the 30-second deadline passes.
                    let deadline = narf_scheduler::narf_time::Deadline::after_ns(30_000_000_000);
                    let mut got = 0usize;
                    let mut closed = false;
                    let mut failed = false;
                    let arrived = narf_scheduler::responsive_spin_until(
                        || {
                            while crate::iface::drain_pump() {}
                            crate::tcp_stack::neigh_tick();
                            match crate::tcp::core::recv(self.id, buf) {
                                Ok(n) if n > 0 => {
                                    got = n;
                                    true
                                }
                                Ok(_) => {
                                    let (err, _) = crate::tcp::core::poll_err_hup(self.id);
                                    if err {
                                        failed = true;
                                        true
                                    } else if crate::tcp::core::readable(self.id) {
                                        closed = true;
                                        true
                                    } else {
                                        false
                                    }
                                }
                                Err(()) => {
                                    failed = true;
                                    true
                                }
                            }
                        },
                        deadline,
                    );
                    if got > 0 {
                        return Ok(got);
                    }
                    if failed {
                        return Err(FetchError::Transport);
                    }
                    if closed {
                        return Ok(0);
                    }
                    if !arrived {
                        return Err(FetchError::Transport);
                    }
                    // The pump woke for another reason; re-check.
                }
                Err(()) => return Err(FetchError::Transport),
            }
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), FetchError> {
        let mut sent = 0;
        while sent < buf.len() {
            match crate::tcp::core::send(self.id, &buf[sent..]) {
                Ok(n) if n > 0 => sent += n,
                Ok(_) => {
                    // Send window full: pump once and retry; a
                    // persistently-zero send is a dead peer.
                    while crate::iface::drain_pump() {}
                    match crate::tcp::core::send(self.id, &buf[sent..]) {
                        Ok(n) if n > 0 => sent += n,
                        _ => return Err(FetchError::Transport),
                    }
                }
                Err(()) => return Err(FetchError::Transport),
            }
        }
        Ok(())
    }
}

/// An HTTPS stream: a [`TlsClient`] over any [`Transport`], with a
/// spill buffer for `recv_app_data` records larger than one `read`.
#[derive(Debug)]
pub struct TlsStream<'a, T: Transport> {
    client: TlsClient<'a, T>,
    spill: Vec<u8>,
    spill_pos: usize,
}

impl<'a, T: Transport> TlsStream<'a, T> {
    /// Run the TLS handshake over `transport` and return the
    /// established stream.
    pub fn connect(transport: T, config: ClientConfig<'a>) -> Result<Self, FetchError> {
        let client = TlsClient::connect(transport, config)?;
        Ok(Self::from_client(client))
    }

    /// Wrap an already-established client (handshake already run).
    pub fn from_client(client: TlsClient<'a, T>) -> Self {
        Self {
            client,
            spill: Vec::new(),
            spill_pos: 0,
        }
    }

    /// The underlying TLS client.
    pub fn client(&mut self) -> &mut TlsClient<'a, T> {
        &mut self.client
    }
}

impl<'a, T: Transport> FetchStream for TlsStream<'a, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FetchError> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.spill_pos < self.spill.len() {
                let n = core::cmp::min(buf.len(), self.spill.len() - self.spill_pos);
                buf[..n].copy_from_slice(&self.spill[self.spill_pos..self.spill_pos + n]);
                self.spill_pos += n;
                return Ok(n);
            }
            match self.client.recv_app_data() {
                Ok(data) => {
                    // A zero-length record carries no bytes; loop
                    // and read the next record rather than reporting
                    // a spurious EOF.
                    self.spill = data;
                    self.spill_pos = 0;
                    if self.spill.is_empty() {
                        continue;
                    }
                }
                Err(TlsError::Closed) => return Ok(0),
                Err(e) => return Err(FetchError::Tls(e)),
            }
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), FetchError> {
        self.client.send_app_data(buf).map_err(FetchError::Tls)
    }
}

/// Either leg of a production fetch: plain TCP or TLS over TCP.
#[derive(Debug)]
pub enum FetchConn<'a> {
    /// Plain HTTP over TCP.
    Plain(TcpStream),
    /// HTTPS: TLS over TCP. Boxed: the TLS stream (~776 bytes)
    /// dwarfs the plain leg (4 bytes), and the connection is
    /// opened once per fetch, so one heap allocation per TLS
    /// fetch keeps the enum small without a hot-path cost.
    Tls(Box<TlsStream<'a, TcpTransport>>),
}

impl FetchStream for FetchConn<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FetchError> {
        match self {
            FetchConn::Plain(s) => s.read(buf),
            FetchConn::Tls(s) => s.read(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), FetchError> {
        match self {
            FetchConn::Plain(s) => s.write_all(buf),
            FetchConn::Tls(s) => s.write_all(buf),
        }
    }
}

/// Fetch tuning. See the `DEFAULT_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchOptions {
    /// Maximum redirect hops followed (default [`DEFAULT_MAX_REDIRECTS`]).
    pub max_redirects: u8,
    /// Maximum response body bytes accepted (default
    /// [`DEFAULT_MAX_BODY_BYTES`]).
    pub max_body_bytes: usize,
    /// Maximum response head bytes accepted (default
    /// [`DEFAULT_MAX_HEADER_BYTES`]).
    pub max_header_bytes: usize,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
        }
    }
}

/// A completed fetch: final status, final URL (after redirects),
/// and the decoded response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    /// The final response status code (2xx).
    pub status: u16,
    /// The URL the body was fetched from (after redirects).
    pub final_url: Url,
    /// The decoded body (`Content-Length`, chunked, or
    /// close-delimited, as the server framed it).
    pub body: Vec<u8>,
}

/// How the response body is framed, from the response fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    /// `Content-Length: n` — exactly `n` bytes follow the head.
    Length(usize),
    /// `Transfer-Encoding: chunked` (RFC 9112 §7.1).
    Chunked,
    /// Neither: the body runs to EOF (connection close).
    Close,
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Case-insensitive field lookup (field names are case-insensitive,
/// RFC 9110 §5.1).
fn header<'a>(fields: &[crate::http::HeaderField<'a>], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case(name))
        .map(|f| f.value)
}

/// The body framing the response fields declare. `Transfer-Encoding:
/// chunked` wins over `Content-Length` (RFC 9112 §6.3). Conflicting
/// duplicate `Content-Length` values are a hard error.
fn body_framing(fields: &[crate::http::HeaderField<'_>]) -> Result<BodyFraming, FetchError> {
    let chunked = fields
        .iter()
        .filter(|f| f.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|f| f.value.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("chunked"));
    if chunked {
        return Ok(BodyFraming::Chunked);
    }
    let mut length: Option<usize> = None;
    for f in fields
        .iter()
        .filter(|f| f.name.eq_ignore_ascii_case("content-length"))
    {
        let v: usize = f.value.trim().parse().map_err(|_| FetchError::BadHeader)?;
        match length {
            Some(prev) if prev != v => return Err(FetchError::BadHeader),
            Some(_) => {}
            None => length = Some(v),
        }
    }
    Ok(match length {
        Some(n) => BodyFraming::Length(n),
        None => BodyFraming::Close,
    })
}

/// Whether the buffered body bytes (after the head) already hold a
/// complete body under `framing`. A malformed chunked body errors
/// here rather than waiting for more bytes that cannot fix it.
fn body_complete(body: &[u8], framing: BodyFraming) -> Result<bool, FetchError> {
    match framing {
        BodyFraming::Length(n) => Ok(body.len() >= n),
        BodyFraming::Close => Ok(false),
        BodyFraming::Chunked => {
            for chunk in iter_chunks(body) {
                match chunk {
                    Ok(c) if c.data.is_empty() => return Ok(true),
                    Ok(_) => {}
                    Err(HttpError::Short) => return Ok(false),
                    Err(e) => return Err(FetchError::Http(e)),
                }
            }
            Ok(false)
        }
    }
}

/// Decode a complete buffered body under `framing`.
fn decode_body(body: &[u8], framing: BodyFraming) -> Result<Vec<u8>, FetchError> {
    match framing {
        BodyFraming::Length(n) => Ok(body[..n].to_vec()),
        BodyFraming::Close => Ok(body.to_vec()),
        BodyFraming::Chunked => {
            let mut out = Vec::new();
            for chunk in iter_chunks(body) {
                let c = chunk?;
                if c.data.is_empty() {
                    break;
                }
                out.extend_from_slice(c.data);
            }
            Ok(out)
        }
    }
}

/// A response reader: the stream plus the bytes read so far.
struct ResponseReader<S: FetchStream> {
    stream: S,
    buf: Vec<u8>,
    eof: bool,
}

impl<S: FetchStream> ResponseReader<S> {
    /// Read one more chunk into the buffer. Returns `false` on EOF.
    fn fill(&mut self) -> Result<bool, FetchError> {
        if self.eof {
            return Ok(false);
        }
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk)? {
            0 => {
                self.eof = true;
                Ok(false)
            }
            n => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
        }
    }
}

/// One request/response exchange over `stream`: send a GET for
/// `url`, return `(status, Location value if any, decoded body)`.
/// Redirects are the caller's job ([`fetch`]). `pub(crate)` so
/// fixtures can assert the exact request bytes for one exchange.
pub(crate) fn fetch_once<S: FetchStream>(
    mut stream: S,
    url: &Url,
    opts: &FetchOptions,
) -> Result<(u16, Option<String>, Vec<u8>), FetchError> {
    // Request (RFC 9112 §3): `GET path HTTP/1.1` + Host +
    // `Connection: close` so a close-delimited body has a definite
    // end and the connection is single-use.
    let mut req = Vec::new();
    RequestLine {
        method: String::from("GET"),
        target: url.path.clone(),
        version: String::from("HTTP/1.1"),
    }
    .encode(&mut req);
    append_field(&mut req, "Host", &url.host_header());
    append_field(&mut req, "User-Agent", USER_AGENT);
    append_field(&mut req, "Accept", "*/*");
    append_field(&mut req, "Connection", "close");
    append_end_of_headers(&mut req);
    stream.write_all(&req)?;

    let mut r = ResponseReader {
        stream,
        buf: Vec::new(),
        eof: false,
    };
    // Head: read until CRLFCRLF, bounded.
    let head_end = loop {
        if let Some(i) = find_subslice(&r.buf, b"\r\n\r\n") {
            break i + 4;
        }
        if r.buf.len() > opts.max_header_bytes {
            return Err(FetchError::TooLarge);
        }
        if !r.fill()? {
            return Err(FetchError::Transport);
        }
    };
    let (status_line, used) = StatusLine::decode(&r.buf[..head_end])?;
    let (fields, _) = parse_headers(&r.buf[used..head_end])?;
    let framing = body_framing(&fields)?;
    let location = header(&fields, "location").map(ToString::to_string);

    // Body: read until the framing says complete, bounded.
    loop {
        if body_complete(&r.buf[head_end..], framing)? {
            break;
        }
        if r.buf.len() > opts.max_header_bytes + opts.max_body_bytes {
            return Err(FetchError::TooLarge);
        }
        if !r.fill()? {
            // EOF: only a close-delimited body may end here; a
            // truncated Content-Length / chunked body fails closed.
            if framing != BodyFraming::Close {
                return Err(FetchError::Transport);
            }
            break;
        }
    }
    let body = decode_body(&r.buf[head_end..], framing)?;
    Ok((status_line.status_code, location, body))
}

/// Fetch `url`, following redirects, over streams minted by
/// `connect` (one fresh stream per hop — a redirect may change host
/// or scheme). Returns the final 2xx response; any other final
/// status is [`FetchError::HttpStatus`].
pub fn fetch<S, F>(
    mut url: Url,
    opts: &FetchOptions,
    mut connect: F,
) -> Result<FetchResponse, FetchError>
where
    S: FetchStream,
    F: FnMut(&Url) -> Result<S, FetchError>,
{
    let mut hops = 0u8;
    loop {
        let stream = connect(&url)?;
        let (status, location, body) = fetch_once(stream, &url, opts)?;
        match status {
            200..=299 => {
                return Ok(FetchResponse {
                    status,
                    final_url: url,
                    body,
                });
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = location.ok_or(FetchError::BadLocation)?;
                if hops >= opts.max_redirects {
                    return Err(FetchError::TooManyRedirects);
                }
                hops += 1;
                url = url.resolve_relative(&loc)?;
            }
            other => return Err(FetchError::HttpStatus(other)),
        }
    }
}

/// Resolve `host` to an IPv4 address: a literal first, else the
/// in-tree DNS resolver on the primary interface.
fn resolve_host(host: &str) -> Result<[u8; 4], FetchError> {
    if let Some(ip) = crate::dns::parse_ipv4_str(host) {
        return Ok(ip);
    }
    let addrs = crate::dns::resolve_a("", host).map_err(FetchError::Dns)?;
    addrs.into_iter().next().ok_or(FetchError::NoAddress)
}

/// Open one leg of a production fetch: TCP for `http://`, TLS over
/// TCP for `https://` (SNI + hostname verification on, chain
/// verified against `roots`, validity at `now_unix`). The hostname
/// is borrowed into the TLS config, so the URL must outlive the
/// returned connection — the production loop in [`fetch_url_at`]
/// keeps it alive for exactly one hop.
fn connect_url<'a>(
    url: &'a Url,
    roots: &'a RootStore<'a>,
    now_unix: u64,
) -> Result<FetchConn<'a>, FetchError> {
    let ip = resolve_host(&url.host)?;
    match url.scheme {
        Scheme::Http => Ok(FetchConn::Plain(TcpStream::connect(ip, url.port)?)),
        Scheme::Https => {
            let transport = TcpTransport::connect(ip, url.port).map_err(|_| FetchError::Connect)?;
            let mut config = ClientConfig::new(roots, now_unix);
            config.server_name = Some(url.host.as_str());
            Ok(FetchConn::Tls(Box::new(TlsStream::connect(
                transport, config,
            )?)))
        }
    }
}

/// Download `url` over the live net stack: DNS → TCP → (TLS for
/// `https://`) → HTTP/1.1 GET, following redirects. `roots` is the
/// caller-provisioned trust store (empty by design — see #1802);
/// certificate validity is checked against the wall clock. There is
/// no skip-verification mode: an unverifiable chain fails closed.
///
/// Must be called from sync context, not from inside an executor
/// poll (the same rule as [`TcpTransport::connect`]).
pub fn fetch_url(url: &str, roots: &RootStore) -> Result<FetchResponse, FetchError> {
    let now = narf_scheduler::narf_time::now_wall().secs.max(0) as u64;
    fetch_url_at(url, roots, now)
}

/// [`fetch_url`] with an injected clock (fixtures / callers that own
/// clock accuracy — there is no SNTP/NTP client in tree yet, #1764).
pub fn fetch_url_at<'a>(
    url: &str,
    roots: &'a RootStore<'a>,
    now_unix: u64,
) -> Result<FetchResponse, FetchError> {
    // This loop mirrors `fetch` instead of calling it: the generic
    // engine's connector cannot return a stream borrowing the URL
    // (the TLS config borrows the hostname), so the production loop
    // lives here, where the URL outlives each hop's connection.
    let mut url = Url::parse(url)?;
    let opts = FetchOptions::default();
    let mut hops = 0u8;
    loop {
        let stream = connect_url(&url, roots, now_unix)?;
        let (status, location, body) = fetch_once(stream, &url, &opts)?;
        match status {
            200..=299 => {
                return Ok(FetchResponse {
                    status,
                    final_url: url,
                    body,
                });
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = location.ok_or(FetchError::BadLocation)?;
                if hops >= opts.max_redirects {
                    return Err(FetchError::TooManyRedirects);
                }
                hops += 1;
                url = url.resolve_relative(&loc)?;
            }
            other => return Err(FetchError::HttpStatus(other)),
        }
    }
}
