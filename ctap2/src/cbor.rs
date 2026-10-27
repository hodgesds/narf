//! Minimal CBOR (RFC 8949) codec in the CTAP2 canonical form.
//!
//! ## Spec sources
//!
//! - RFC 8949 §3 (data item encoding), §4.2 (deterministically
//!   encoded CBOR): shortest-form integers, and map keys sorted
//!   first by the length of their encoded form, then bytewise.
//! - FIDO2 CTAP2 specification, "CTAP2" message encoding: all CTAP2
//!   command and response payloads are CBOR maps; encodings MUST be
//!   canonical per the rule above. This codec therefore *always*
//!   emits canonical form and the fixtures pin the emitted bytes.
//!
//! The decoder is deliberately strict where the protocol requires
//! it: indefinite-length items, non-shortest-form integers, floats,
//! duplicate map keys, trailing garbage, and nesting past
//! [`MAX_DEPTH`] are all hard errors — a malformed authenticator
//! response must never panic or be silently misread.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum nesting depth accepted by the decoder (CTAP2 structures
/// nest at most ~4 deep; 16 is generous headroom, and a hard cap
/// keeps a hostile byte string from exhausting the stack).
pub const MAX_DEPTH: usize = 16;
/// Maximum total input accepted for one CBOR item (authenticator
/// `maxMsgSize` is at most 7609 in CTAP2.1's HID profile; 16 KiB is
/// the client-side ceiling for a single decoded payload).
pub const MAX_INPUT: usize = 16 * 1024;

/// A CBOR data item, restricted to the types CTAP2 uses.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Major type 0.
    UInt(u64),
    /// Major type 1, stored as the mathematical value (so the wire
    /// argument is `-1 - value`).
    NInt(i64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5. Insertion order is irrelevant; the encoder
    /// canonicalises.
    Map(Vec<(Value, Value)>),
    /// Major type 7, simple values 20/21.
    Bool(bool),
    /// Major type 7, simple value 22.
    Null,
}

impl Value {
    pub fn uint(v: u64) -> Self {
        Value::UInt(v)
    }

    /// Build a signed value, choosing the major type by sign.
    pub fn int(v: i64) -> Self {
        if v >= 0 {
            Value::UInt(v as u64)
        } else {
            Value::NInt(v)
        }
    }

    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(b.into())
    }

    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::UInt(v) if *v <= i64::MAX as u64 => Some(*v as i64),
            Value::NInt(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::UInt(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Look up an integer key in a map value.
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_int() == Some(key))
            .map(|(_, v)| v)
    }

    /// Look up a text key in a map value.
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    /// Look up an integer key whose value must be a byte string.
    pub fn get_int_key_bytes(&self, key: i64) -> Option<&[u8]> {
        self.get_int(key)?.as_bytes()
    }

    /// Look up a text key whose value must be a byte string.
    pub fn get_text_key_bytes(&self, key: &str) -> Option<&[u8]> {
        self.get_text(key)?.as_bytes()
    }
}

/// CBOR encode/decode failures. Every variant is a clean error —
/// the decoder never panics on untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    /// Input ended before the item was complete.
    UnexpectedEnd,
    /// Non-shortest-form integer/length, or an indefinite-length
    /// item — neither is valid CTAP2 canonical CBOR.
    NonCanonical,
    /// A major type this codec does not model (tags, floats,
    /// unassigned simple values).
    UnsupportedType,
    /// Map keys are not unique.
    DuplicateKey,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Input longer than [`MAX_INPUT`], or trailing bytes after a
    /// complete item where a single item was required.
    TooLarge,
    /// Text string was not valid UTF-8.
    InvalidUtf8,
}

// ── Encoder (always canonical) ──────────────────────────────────────

fn encode_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= 0xFF {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Encode one value in CTAP2 canonical form.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::UInt(v) => encode_head(out, 0, *v),
        Value::NInt(v) => {
            // RFC 8949 §3: argument is -1 - value.
            let arg = (-1i128 - *v as i128) as u64;
            encode_head(out, 1, arg);
        }
        Value::Bytes(b) => {
            encode_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            encode_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            encode_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            // Canonical ordering (RFC 8949 §4.2.1): sort by the
            // encoded key, shorter encodings first, then bytewise.
            let mut encoded: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, v)| (encode(k), v)).collect();
            encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            encode_head(out, 5, encoded.len() as u64);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                encode_into(v, out);
            }
        }
        Value::Bool(b) => out.push(if *b { 0xF5 } else { 0xF4 }),
        Value::Null => out.push(0xF6),
    }
}

// ── Decoder (strict) ────────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if self.buf.len() - self.pos < n {
            return Err(CborError::UnexpectedEnd);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a head argument, enforcing shortest form (canonical).
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(CborError::NonCanonical);
                }
                Ok(v)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= 0xFF {
                    return Err(CborError::NonCanonical);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xFFFF {
                    return Err(CborError::NonCanonical);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= 0xFFFF_FFFF {
                    return Err(CborError::NonCanonical);
                }
                Ok(v)
            }
            // 28..=30 reserved, 31 = indefinite length.
            _ => Err(CborError::NonCanonical),
        }
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1F;
        match major {
            0 => Ok(Value::UInt(self.argument(info)?)),
            1 => {
                let arg = self.argument(info)?;
                if arg > i64::MAX as u64 {
                    return Err(CborError::UnsupportedType);
                }
                Ok(Value::NInt(-1 - arg as i64))
            }
            2 => {
                let n = self.argument(info)? as usize;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(info)? as usize;
                let raw = self.take(n)?;
                let s = core::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(s.into()))
            }
            4 => {
                let n = self.argument(info)? as usize;
                // Each element costs ≥1 byte; reject absurd counts
                // before allocating.
                if n > self.buf.len() - self.pos {
                    return Err(CborError::UnexpectedEnd);
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.argument(info)? as usize;
                if n > (self.buf.len() - self.pos) / 2 {
                    return Err(CborError::UnexpectedEnd);
                }
                let mut entries: Vec<(Value, Value)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    let v = self.item(depth + 1)?;
                    if entries.iter().any(|(ek, _)| *ek == k) {
                        return Err(CborError::DuplicateKey);
                    }
                    entries.push((k, v));
                }
                Ok(Value::Map(entries))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(CborError::UnsupportedType),
            },
            _ => Err(CborError::UnsupportedType),
        }
    }
}

/// Decode exactly one CBOR item; trailing bytes are an error.
pub fn decode(input: &[u8]) -> Result<Value, CborError> {
    if input.len() > MAX_INPUT {
        return Err(CborError::TooLarge);
    }
    let mut r = Reader { buf: input, pos: 0 };
    let v = r.item(0)?;
    if r.pos != input.len() {
        return Err(CborError::TooLarge);
    }
    Ok(v)
}

/// Decode one item from the front of `input`, returning the value
/// and the number of bytes consumed (authData embeds a CBOR public
/// key mid-buffer, so the caller needs the consumed length).
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), CborError> {
    if input.len() > MAX_INPUT {
        return Err(CborError::TooLarge);
    }
    let mut r = Reader { buf: input, pos: 0 };
    let v = r.item(0)?;
    Ok((v, r.pos))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    macro_rules! check_eq {
        ($a:expr, $b:expr, $msg:expr) => {
            if $a != $b {
                return TestResult::Fail($msg);
            }
        };
    }

    fn smoke_canonical_map_ordering_length_then_bytes() -> TestResult {
        // RFC 8949 §4.2.1: keys sort by encoded length first, then
        // bytewise — 1, 2, -1 sort before the two-byte heads of
        // 24 and 100.
        let m = Value::Map(vec![
            (Value::int(24), Value::Null),
            (Value::int(2), Value::Null),
            (Value::int(-1), Value::Null),
            (Value::int(1), Value::Null),
            (Value::int(100), Value::Null),
        ]);
        let enc = encode(&m);
        check_eq!(
            enc,
            alloc::vec![
                0xA5, 0x01, 0xF6, 0x02, 0xF6, 0x20, 0xF6, 0x18, 0x18, 0xF6, 0x18, 0x64, 0xF6
            ],
            "canonical key order: 01, 02, 20(-1), 1818(24), 1864(100)"
        );
        TestResult::Pass
    }
    kernel_test_in!("ctap2/cbor", smoke_canonical_map_ordering_length_then_bytes);

    fn smoke_negative_int_encoding() -> TestResult {
        // RFC 8949 Appendix A: -7 encodes as 0x26, -1000 as 0x39 0x03 0xE7.
        check_eq!(encode(&Value::int(-7)), alloc::vec![0x26], "-7 encoding");
        check_eq!(
            encode(&Value::int(-1000)),
            alloc::vec![0x39, 0x03, 0xE7],
            "-1000 encoding"
        );
        check_eq!(decode(&[0x26]), Ok(Value::NInt(-7)), "-7 decoding");
        TestResult::Pass
    }
    kernel_test_in!("ctap2/cbor", smoke_negative_int_encoding);

    fn smoke_decoder_rejects_noncanonical_and_indefinite() -> TestResult {
        // 0x18 0x17 = 23 in two-byte form — non-shortest.
        check_eq!(
            decode(&[0x18, 0x17]),
            Err(CborError::NonCanonical),
            "non-shortest rejected"
        );
        // 0x5F = indefinite byte string.
        check_eq!(
            decode(&[0x5F, 0xFF]),
            Err(CborError::NonCanonical),
            "indefinite rejected"
        );
        // Trailing garbage.
        check_eq!(
            decode(&[0x01, 0x01]),
            Err(CborError::TooLarge),
            "trailing rejected"
        );
        // Truncated byte string.
        check_eq!(
            decode(&[0x42, 0x01]),
            Err(CborError::UnexpectedEnd),
            "truncated rejected"
        );
        // Float (major 7, info 27) — unsupported.
        check_eq!(
            decode(&[0xFB, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(CborError::UnsupportedType),
            "float rejected"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "ctap2/cbor",
        smoke_decoder_rejects_noncanonical_and_indefinite
    );

    fn smoke_round_trip_nested() -> TestResult {
        let v = Value::Map(vec![(
            Value::int(1),
            Value::Array(vec![
                Value::text("versions"),
                Value::Bytes(vec![1, 2, 3]),
                Value::Map(vec![(Value::int(-2), Value::Bool(true))]),
            ]),
        )]);
        let enc = encode(&v);
        check_eq!(decode(&enc), Ok(v), "nested round trip");
        TestResult::Pass
    }
    kernel_test_in!("ctap2/cbor", smoke_round_trip_nested);
}
