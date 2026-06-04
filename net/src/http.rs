//! HTTP/1.1 message framing — clean-room.
//!
//! References (public-only):
//! - RFC 9112 — HTTP/1.1 (R. Fielding et al, June 2022). §3 Message
//!   Format. §4 Request Line. §5 Status Line. §6 Field Lines.
//!   §7 Transfer Codings (chunked, §7.1).
//!   <https://datatracker.ietf.org/doc/html/rfc9112>
//! - RFC 9110 — HTTP Semantics — referenced for method + status
//!   class enumeration; we keep the codec syntactic.
//!   <https://datatracker.ietf.org/doc/html/rfc9110>
//!
//! No GPL Linux source consulted.
//!
//! ## Wire shape
//!
//! ```text
//!   start-line CRLF
//!   *( field-line CRLF )
//!   CRLF
//!   [ message-body ]
//! ```
//!
//! For requests the start line is `METHOD SP request-target SP HTTP/1.1 CRLF`.
//! For responses it's `HTTP/1.1 SP status-code SP reason-phrase CRLF`.
//! Field lines are `field-name ":" OWS field-value OWS CRLF`.
//!
//! ## Chunked transfer (§7.1)
//!
//! Each chunk is `chunk-size [;chunk-ext] CRLF chunk-data CRLF`.
//! `chunk-size` is hexadecimal. A zero-length chunk + optional
//! trailer fields + CRLF terminates the body.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttpError {
    Short,
    /// Start line wasn't terminated by CRLF or was malformed.
    BadStartLine,
    /// Field line wasn't terminated by CRLF or didn't contain a colon.
    BadFieldLine,
    /// Header section wasn't terminated by CRLFCRLF.
    NoEndOfHeaders,
    /// Chunked decoder couldn't parse the chunk-size hex line.
    BadChunkSize,
    /// Chunk data wasn't followed by a trailing CRLF.
    BadChunkTerminator,
}

// ── Request / response start lines ────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLine {
    pub method: String,
    pub target: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusLine {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
}

/// Consume one CRLF-terminated line from `buf`. Returns the line
/// (without the CRLF) and the byte count consumed (including CRLF).
fn read_line(buf: &[u8]) -> Result<(&str, usize), HttpError> {
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            let line = core::str::from_utf8(&buf[..i]).map_err(|_| HttpError::BadStartLine)?;
            return Ok((line, i + 2));
        }
    }
    Err(HttpError::Short)
}

impl RequestLine {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), HttpError> {
        let (line, used) = read_line(buf)?;
        let mut parts = line.splitn(3, ' ');
        let method = parts.next().ok_or(HttpError::BadStartLine)?;
        let target = parts.next().ok_or(HttpError::BadStartLine)?;
        let version = parts.next().ok_or(HttpError::BadStartLine)?;
        if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
            return Err(HttpError::BadStartLine);
        }
        Ok((
            Self {
                method: method.into(),
                target: target.into(),
                version: version.into(),
            },
            used,
        ))
    }
}

impl StatusLine {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.version.as_bytes());
        out.push(b' ');
        let mut digits = [0u8; 3];
        digits[0] = b'0' + ((self.status_code / 100) % 10) as u8;
        digits[1] = b'0' + ((self.status_code / 10) % 10) as u8;
        digits[2] = b'0' + (self.status_code % 10) as u8;
        out.extend_from_slice(&digits);
        out.push(b' ');
        out.extend_from_slice(self.reason.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), HttpError> {
        let (line, used) = read_line(buf)?;
        let mut parts = line.splitn(3, ' ');
        let version = parts.next().ok_or(HttpError::BadStartLine)?;
        let code_str = parts.next().ok_or(HttpError::BadStartLine)?;
        let reason = parts.next().unwrap_or("");
        if !version.starts_with("HTTP/") || code_str.len() != 3 {
            return Err(HttpError::BadStartLine);
        }
        let mut code = 0u16;
        for b in code_str.bytes() {
            if !b.is_ascii_digit() {
                return Err(HttpError::BadStartLine);
            }
            code = code * 10 + (b - b'0') as u16;
        }
        Ok((
            Self {
                version: version.into(),
                status_code: code,
                reason: reason.into(),
            },
            used,
        ))
    }
}

// ── Header field iterator ──────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderField<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Iterate field-lines in an HTTP message starting at `buf`. The
/// iterator stops on the empty line that terminates the header
/// section (CRLFCRLF in source bytes). Returns `(field iterator, bytes
/// consumed including the trailing CRLF)`.
pub fn parse_headers(buf: &[u8]) -> Result<(Vec<HeaderField<'_>>, usize), HttpError> {
    let mut fields = Vec::new();
    let mut pos = 0;
    loop {
        if pos + 1 >= buf.len() {
            return Err(HttpError::NoEndOfHeaders);
        }
        if buf[pos] == b'\r' && buf[pos + 1] == b'\n' {
            return Ok((fields, pos + 2));
        }
        let line_start = pos;
        let mut line_end = None;
        let mut i = pos;
        while i + 1 < buf.len() {
            if buf[i] == b'\r' && buf[i + 1] == b'\n' {
                line_end = Some(i);
                break;
            }
            i += 1;
        }
        let end = line_end.ok_or(HttpError::Short)?;
        let line =
            core::str::from_utf8(&buf[line_start..end]).map_err(|_| HttpError::BadFieldLine)?;
        let colon = line.find(':').ok_or(HttpError::BadFieldLine)?;
        let name = &line[..colon];
        let value = line[colon + 1..].trim_start_matches(|c| c == ' ' || c == '\t');
        let value = value.trim_end_matches(|c| c == ' ' || c == '\t');
        fields.push(HeaderField { name, value });
        pos = end + 2;
    }
}

/// Append a field-line to `out`.
pub fn append_field(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Append the empty line that terminates the header section.
pub fn append_end_of_headers(out: &mut Vec<u8>) {
    out.extend_from_slice(b"\r\n");
}

// ── Chunked transfer-coding (§7.1) ─────────────────────────────────

/// One chunk emitted by `iter_chunks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// Decoded chunk-data. Empty (`length 0`) terminates the body.
    pub data: &'a [u8],
}

/// Walk the chunked body. Stops after consuming a zero-sized chunk,
/// per §7.1. Trailer fields after the final chunk are *not* consumed
/// here — the caller resumes header parsing at the returned offset.
pub fn iter_chunks<'a>(buf: &'a [u8]) -> impl Iterator<Item = Result<Chunk<'a>, HttpError>> + 'a {
    let mut pos = 0;
    let mut done = false;
    core::iter::from_fn(move || {
        if done {
            return None;
        }
        // Read chunk-size line.
        let line_start = pos;
        let mut i = pos;
        while i + 1 < buf.len() {
            if buf[i] == b'\r' && buf[i + 1] == b'\n' {
                break;
            }
            i += 1;
        }
        if i + 1 >= buf.len() {
            return Some(Err(HttpError::Short));
        }
        let size_str = match core::str::from_utf8(&buf[line_start..i]) {
            Ok(s) => s,
            Err(_) => return Some(Err(HttpError::BadChunkSize)),
        };
        // Strip chunk-ext beyond the first ';'.
        let size_field = size_str.split(';').next().unwrap_or("").trim();
        let size = match u64::from_str_radix(size_field, 16) {
            Ok(n) => n as usize,
            Err(_) => return Some(Err(HttpError::BadChunkSize)),
        };
        pos = i + 2;
        if size == 0 {
            // last-chunk per RFC 9112 §7.1 is `0CRLF` only — no
            // CRLF on (empty) chunk-data. Trailers (if any) and
            // the final body-terminator CRLF are the caller's
            // problem.
            done = true;
            return Some(Ok(Chunk {
                data: &buf[pos..pos],
            }));
        }
        if pos + size + 2 > buf.len() {
            return Some(Err(HttpError::Short));
        }
        let data = &buf[pos..pos + size];
        if buf[pos + size] != b'\r' || buf[pos + size + 1] != b'\n' {
            return Some(Err(HttpError::BadChunkTerminator));
        }
        pos += size + 2;
        Some(Ok(Chunk { data }))
    })
}

/// Encode one chunk (size in hex, CRLF, data, CRLF). The terminating
/// zero-length chunk is `encode_chunk(out, &[])`.
pub fn encode_chunk(out: &mut Vec<u8>, data: &[u8]) {
    let mut hex = [0u8; 16];
    let mut len = data.len();
    let mut i = hex.len();
    if len == 0 {
        i -= 1;
        hex[i] = b'0';
    } else {
        while len > 0 {
            i -= 1;
            let nibble = (len & 0x0F) as u8;
            hex[i] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            len >>= 4;
        }
    }
    out.extend_from_slice(&hex[i..]);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}
