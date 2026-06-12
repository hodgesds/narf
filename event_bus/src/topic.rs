//! Topic names — fixed 96-byte buffer, hierarchical dot-separated
//! tokens, max 5 segments. Names hash via FxHash for fast lookup;
//! the registry stores `(name_hash, name)` so the producer side is
//! one hash + one slot inspection.
//!
//! Reserved roots — kernel-only mint:
//! - `kernel`, `system`, `net`, `block`, `input`, `acpi`, `power`
//!
//! Userspace prefix: `user.<daemon>.…`. Anything else is rejected.

use core::fmt;

/// Maximum total bytes in a topic name (excluding any nul). 96 bytes
/// is the spec's chosen size; covers the longest realistic name
/// (`system.security.audit` etc.) plus headroom for daemon prefixes.
pub const MAX_NAME_BYTES: usize = 96;

/// Maximum dot-separated segments. 5 is conservative; matches the
/// `<root>.<component>.<instance>.<event>.<extra>` shape with one
/// segment of headroom.
pub const MAX_SEGMENTS: usize = 5;

/// Reserved root prefixes that only the kernel can mint topics
/// under.
pub const RESERVED_ROOTS: &[&str] = &["kernel", "system", "net", "block", "input", "acpi", "power"];

/// User-mint prefix.
pub const USER_ROOT: &str = "user";

/// Errors from `TopicName::parse`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    /// Empty input.
    Empty,
    /// Total length exceeds `MAX_NAME_BYTES`.
    TooLong,
    /// More than `MAX_SEGMENTS` segments.
    TooManySegments,
    /// One of the segments is empty (e.g. trailing `.`, double `..`).
    EmptySegment,
    /// One of the segments contains a disallowed byte.
    InvalidChar,
    /// Non-ASCII byte.
    NonAscii,
}

/// Compact fixed-buffer topic name. `Copy` so it's cheap to pass by
/// value; the buffer is 96 bytes + a length, well under a cache line.
#[derive(Copy, Clone)]
pub struct TopicName {
    buf: [u8; MAX_NAME_BYTES],
    len: u8,
}

impl TopicName {
    /// Parse and validate. ASCII-only, dot-separated, each segment
    /// matches `[a-zA-Z0-9_-]+`, max 5 segments, max 96 bytes total.
    pub fn parse(s: &str) -> Result<Self, NameError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Err(NameError::Empty);
        }
        if bytes.len() > MAX_NAME_BYTES {
            return Err(NameError::TooLong);
        }
        let mut segments = 0usize;
        let mut seg_len = 0usize;
        for &b in bytes {
            if !b.is_ascii() {
                return Err(NameError::NonAscii);
            }
            if b == b'.' {
                if seg_len == 0 {
                    return Err(NameError::EmptySegment);
                }
                segments += 1;
                if segments >= MAX_SEGMENTS {
                    // Need one more segment after the last '.'.
                    return Err(NameError::TooManySegments);
                }
                seg_len = 0;
                continue;
            }
            if !is_segment_byte(b) {
                return Err(NameError::InvalidChar);
            }
            seg_len += 1;
        }
        if seg_len == 0 {
            // Trailing dot.
            return Err(NameError::EmptySegment);
        }
        // We counted segments at each separator; total segments =
        // separators + 1.
        let total_segments = segments + 1;
        if total_segments > MAX_SEGMENTS {
            return Err(NameError::TooManySegments);
        }
        let mut buf = [0u8; MAX_NAME_BYTES];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            buf,
            len: bytes.len() as u8,
        })
    }

    /// Borrow as `&str`. Always valid UTF-8 because we accept ASCII
    /// only in `parse`.
    pub fn as_str(&self) -> &str {
        // SAFETY: `parse` rejects non-ASCII. The buffer is initialised
        // to 0 outside `[0..len]` and we slice to `len`.
        // SAFETY: Valid memory or trusted environment
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }

    /// 64-bit hash for registry lookup. FxHash-style mixing — fast,
    /// non-cryptographic; the registry isn't trust-sensitive (every
    /// caller is already cap-gated).
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a basis.
        for &b in &self.buf[..self.len as usize] {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3); // FNV-1a prime.
        }
        h
    }

    /// First segment (the "root"). Used to decide if a topic
    /// requires kernel-only mint authority.
    pub fn root(&self) -> &str {
        let s = self.as_str();
        match s.find('.') {
            Some(idx) => &s[..idx],
            None => s,
        }
    }

    /// `true` if this name's root is one of `RESERVED_ROOTS`.
    pub fn is_reserved(&self) -> bool {
        let r = self.root();
        RESERVED_ROOTS.contains(&r)
    }

    /// `true` if this name's root is `user`.
    pub fn is_user(&self) -> bool {
        self.root() == USER_ROOT
    }
}

impl PartialEq for TopicName {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for TopicName {}

impl fmt::Debug for TopicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TopicName({:?})", self.as_str())
    }
}

impl fmt::Display for TopicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[inline]
fn is_segment_byte(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-')
}
