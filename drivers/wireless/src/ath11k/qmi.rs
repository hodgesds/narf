//! QMI (Qualcomm MSM Interface) TLV wire codec.
//!
//! Every ath11k firmware-control message after MHI mission mode is
//! a QMI message carried in a QRTR DATA packet (see [`super::qrtr`]):
//!
//! ```text
//! qmi_header (7 bytes, packed, LE)   then  TLV*   (payload, msg_len bytes)
//! u8 type | u16 txn_id | u16 msg_id | u16 msg_len
//! TLV = u8 type | u16 length (LE) | value[length]
//! ```
//!
//! Linux drives the encoding with a `struct qmi_elem_info` table per
//! message, interpreted by `drivers/soc/qcom/qmi_encdec.c`. This
//! module is the idiomatic equivalent: a [`TlvWriter`] / [`TlvReader`]
//! pair plus a nested-struct writer/reader, used by the explicit
//! per-message codecs in [`super::qmi_wlfw`]. The rules below are the
//! `qmi_encode` / `qmi_decode` semantics, restated:
//!
//! **Encode** (`qmi_encode`, `enc_level == 1` for the message,
//! `> 1` inside a `QMI_STRUCT`):
//! - each top-level element gets its own TLV, in ei-table order;
//!   a `QMI_OPT_FLAG` of 0 omits the TLV entirely;
//! - `QMI_DATA_LEN` + `VAR_LEN_ARRAY` share one TLV: the count
//!   (`u8` or `u16` per the DATA_LEN `elem_size`) then the elements;
//!   a count of 0 still emits the TLV holding just the count;
//! - `QMI_STRUCT` members are concatenated with no TLV framing;
//! - a top-level `QMI_STRING` is the raw `strlen` bytes (no count,
//!   no NUL); a nested one is prefixed with a `u8` count when the ei
//!   `elem_len <= U8_MAX`, else a `u16` count;
//! - integers and enums are little-endian, `elem_size` bytes wide;
//! - the payload may not exceed the message's `*_MAX_LEN`
//!   (`-ETOOSMALL`).
//!
//! **Decode** (`qmi_decode`):
//! - TLVs may arrive in any order; the last copy of a TLV wins;
//! - an unknown TLV with type `< 0x10` (`OPTIONAL_TLV_TYPE_START`)
//!   fails the message (`-EINVAL`, "Inval element info"); an unknown
//!   optional TLV (`>= 0x10`) is skipped by its length;
//! - a var-len count above the ei `elem_len` fails (`-ETOOSMALL`);
//! - a `QMI_STRUCT` TLV must be consumed exactly (`-EFAULT`), but a
//!   struct whose bytes run out on a member boundary leaves the rest
//!   of its members zero (Linux decodes into a zeroed buffer and
//!   stops when `decoded_bytes == in_buf_len`). [`StructReader`]
//!   reproduces that; an array of top-level structs likewise stops
//!   early with the remaining entries zeroed, while an array nested
//!   inside a struct must be complete;
//! - a top-level string's length is the TLV length and must be
//!   `< elem_len`; a nested string's count must be `< elem_len` and
//!   fit the remaining bytes.
//!
//! **Where this codec is deliberately stricter than Linux** — each a
//! case where `qmi_decode` reads past the TLV (or the buffer) or
//! silently decodes nothing; all are malformed messages a working
//! firmware never sends:
//! - a TLV header or a known TLV's value that runs past the end of
//!   the payload is [`QmiError::Truncated`] (Linux over-reads);
//! - a known TLV of basic elements whose length is not exactly the
//!   element bytes is [`QmiError::LengthMismatch`] (Linux advances by
//!   the element size, not the TLV length, and desynchronises);
//! - a missing mandatory TLV (`< 0x10`) leaves the field at its
//!   default, exactly as Linux leaves the zeroed field — so a response
//!   without TLV 0x02 reads as SUCCESS. Firmware is developed against
//!   Linux, so accepting what Linux accepts is the compatible choice.
//!
//! Like Linux `qmi_decode_message`, decoding uses every byte after
//! the header; `qmi_header.msg_len` is not consulted.
//!
//! Linux references (GPL-2.0, citation + adaptation permitted):
//! - `drivers/soc/qcom/qmi_encdec.c` — `qmi_encode`, `qmi_decode`,
//!   `qmi_encode_message`, `qmi_decode_message`,
//!   `qmi_response_type_v01_ei`.
//! - `include/linux/soc/qcom/qmi.h` — `struct qmi_header`,
//!   `QMI_REQUEST/RESPONSE/INDICATION`, `QMI_RESULT_*`, `QMI_ERR_*`.
//! - `drivers/soc/qcom/qmi_interface.c::qmi_handle_message` — the
//!   short-packet check.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Header ─────────────────────────────────────────────────────────

/// `QMI_REQUEST` (`include/linux/soc/qcom/qmi.h`).
pub const QMI_REQUEST: u8 = 0;
/// `QMI_RESPONSE`.
pub const QMI_RESPONSE: u8 = 2;
/// `QMI_INDICATION`.
pub const QMI_INDICATION: u8 = 4;

/// `QMI_COMMON_TLV_TYPE` — the `tlv_type` of nested-struct members.
pub const QMI_COMMON_TLV_TYPE: u8 = 0;
/// `OPTIONAL_TLV_TYPE_START` (`qmi_encdec.c`): TLV types at or above
/// this are optional; unknown ones are skipped on decode.
pub const OPTIONAL_TLV_TYPE_START: u8 = 0x10;
/// `TLV_TYPE_SIZE + TLV_LEN_SIZE`.
pub const TLV_HDR_SIZE: usize = 3;
/// `sizeof(struct qmi_header)` — packed `u8 + 3 * __le16`.
pub const QMI_HEADER_SIZE: usize = 7;

/// `QMI_RESULT_SUCCESS_V01`.
pub const QMI_RESULT_SUCCESS_V01: u16 = 0;
/// `QMI_RESULT_FAILURE_V01`.
pub const QMI_RESULT_FAILURE_V01: u16 = 1;

pub const QMI_ERR_NONE_V01: u16 = 0;
pub const QMI_ERR_MALFORMED_MSG_V01: u16 = 1;
pub const QMI_ERR_NO_MEMORY_V01: u16 = 2;
pub const QMI_ERR_INTERNAL_V01: u16 = 3;
pub const QMI_ERR_CLIENT_IDS_EXHAUSTED_V01: u16 = 5;
pub const QMI_ERR_INVALID_ID_V01: u16 = 41;
pub const QMI_ERR_ENCODING_V01: u16 = 58;
pub const QMI_ERR_DISABLED_V01: u16 = 69;
pub const QMI_ERR_INCOMPATIBLE_STATE_V01: u16 = 90;
pub const QMI_ERR_NOT_SUPPORTED_V01: u16 = 94;

/// Codec failure. Each variant names the Linux return it stands in
/// for, or (where marked) a case this codec is stricter about.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QmiError {
    /// Encoded payload longer than the message's `*_MAX_LEN`
    /// (`qmi_encode` `-ETOOSMALL`).
    BufferTooSmall { needed: usize, max: usize },
    /// Var-len array count above the ei `elem_len` (`qmi_encode`
    /// `-EINVAL` "Invalid data length"; `qmi_decode` `-ETOOSMALL`
    /// "Data len %d > max spec %d").
    ArrayTooLong { tlv: u8, len: usize, max: usize },
    /// String longer than the ei allows (`qmi_encode_string_elem`
    /// `-EINVAL`; `qmi_decode_string_elem` `-ETOOSMALL` for
    /// `len >= elem_len`, `-EFAULT` for `len >` the bytes present).
    StringTooLong { tlv: u8, len: usize, max: usize },
    /// Fewer than [`QMI_HEADER_SIZE`] bytes
    /// (`qmi_handle_message` "ignoring short QMI packet").
    ShortHeader,
    /// TLV header, value, or struct member runs past the bytes
    /// present. Stricter than Linux, which over-reads.
    Truncated { tlv: u8 },
    /// Unknown TLV with type `< 0x10` (`qmi_decode` `-EINVAL`
    /// "Inval element info").
    UnknownMandatoryTlv(u8),
    /// Known basic-element TLV whose length is not the element
    /// bytes. Stricter than Linux, which desynchronises.
    LengthMismatch {
        tlv: u8,
        expected: usize,
        got: usize,
    },
    /// Struct TLV not consumed exactly, or a nested struct array
    /// short of its count (`qmi_decode_struct_elem` `-EFAULT`).
    StructLengthMismatch { tlv: u8 },
    /// Header `type` / `msg_id` not the message being decoded.
    /// (Linux matches responses by `txn_id` alone and indications by
    /// `(type, msg_id)` in `qmi_invoke_handler`.)
    UnexpectedMessage { msg_type: u8, msg_id: u16 },
}

/// `struct qmi_header` (`include/linux/soc/qcom/qmi.h`), decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QmiHeader {
    pub msg_type: u8,
    pub txn_id: u16,
    pub msg_id: u16,
    pub msg_len: u16,
}

impl QmiHeader {
    /// Wire bytes, as `qmi_encode_message` fills `hdr`.
    pub fn to_bytes(&self) -> [u8; QMI_HEADER_SIZE] {
        let t = self.txn_id.to_le_bytes();
        let m = self.msg_id.to_le_bytes();
        let l = self.msg_len.to_le_bytes();
        [self.msg_type, t[0], t[1], m[0], m[1], l[0], l[1]]
    }

    /// Parse the first [`QMI_HEADER_SIZE`] bytes of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, QmiError> {
        if buf.len() < QMI_HEADER_SIZE {
            return Err(QmiError::ShortHeader);
        }
        Ok(Self {
            msg_type: buf[0],
            txn_id: u16::from_le_bytes([buf[1], buf[2]]),
            msg_id: u16::from_le_bytes([buf[3], buf[4]]),
            msg_len: u16::from_le_bytes([buf[5], buf[6]]),
        })
    }
}

/// Prefix `payload` with a QMI header — `qmi_encode_message`.
/// `payload` comes from [`TlvWriter::finish`], which has already
/// enforced the message's max length (always `< 65536`).
pub fn encode_message(msg_type: u8, msg_id: u16, txn_id: u16, payload: &[u8]) -> Vec<u8> {
    let hdr = QmiHeader {
        msg_type,
        txn_id,
        msg_id,
        msg_len: payload.len() as u16,
    };
    let mut out = Vec::with_capacity(QMI_HEADER_SIZE + payload.len());
    out.extend_from_slice(&hdr.to_bytes());
    out.extend_from_slice(payload);
    out
}

/// Split a received QMI message into header + TLV payload. Like
/// `qmi_decode_message`, the payload is every byte after the header;
/// `msg_len` is reported but not used.
pub fn split_message(buf: &[u8]) -> Result<(QmiHeader, &[u8]), QmiError> {
    let hdr = QmiHeader::parse(buf)?;
    Ok((hdr, &buf[QMI_HEADER_SIZE..]))
}

// ── Encode ─────────────────────────────────────────────────────────

/// Width of a `QMI_DATA_LEN` count: the ei entry's `elem_size`
/// (`sizeof(u8)` → 1 byte, anything else → 2 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LenSize {
    U8,
    U16,
}

impl LenSize {
    pub const fn bytes(self) -> usize {
        match self {
            LenSize::U8 => 1,
            LenSize::U16 => 2,
        }
    }
}

fn push_len(buf: &mut Vec<u8>, size: LenSize, n: usize) {
    match size {
        LenSize::U8 => buf.push(n as u8),
        LenSize::U16 => buf.extend_from_slice(&(n as u16).to_le_bytes()),
    }
}

/// `strlen` of a C-string-ish byte slice: bytes up to the first NUL.
fn c_strlen(s: &[u8]) -> usize {
    s.iter().position(|&b| b == 0).unwrap_or(s.len())
}

/// Builder for a message's top-level TLV stream (`enc_level == 1`).
#[derive(Debug)]
pub struct TlvWriter {
    buf: Vec<u8>,
    max_len: usize,
}

impl TlvWriter {
    /// `max_len` is the message's `*_MAX_LEN` — the `*len` Linux
    /// passes to `qmi_encode_message`.
    pub fn new(max_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_len,
        }
    }

    fn tlv(&mut self, ty: u8, value: &[u8]) -> &mut Self {
        self.buf.push(ty);
        self.buf
            .extend_from_slice(&(value.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    /// `QMI_UNSIGNED_1_BYTE`, `NO_ARRAY`.
    pub fn u8(&mut self, ty: u8, v: u8) -> &mut Self {
        self.tlv(ty, &[v])
    }

    /// `QMI_UNSIGNED_2_BYTE` / `QMI_SIGNED_2_BYTE_ENUM`.
    pub fn u16(&mut self, ty: u8, v: u16) -> &mut Self {
        self.tlv(ty, &v.to_le_bytes())
    }

    /// `QMI_UNSIGNED_4_BYTE`.
    pub fn u32(&mut self, ty: u8, v: u32) -> &mut Self {
        self.tlv(ty, &v.to_le_bytes())
    }

    /// `QMI_SIGNED_4_BYTE_ENUM` — the C enum's 4 bytes, LE.
    pub fn i32(&mut self, ty: u8, v: i32) -> &mut Self {
        self.tlv(ty, &v.to_le_bytes())
    }

    /// `QMI_UNSIGNED_8_BYTE`.
    pub fn u64(&mut self, ty: u8, v: u64) -> &mut Self {
        self.tlv(ty, &v.to_le_bytes())
    }

    /// Optional (`QMI_OPT_FLAG`-guarded) `u8`: `None` emits nothing.
    pub fn opt_u8(&mut self, ty: u8, v: Option<u8>) -> &mut Self {
        if let Some(v) = v {
            self.u8(ty, v);
        }
        self
    }

    /// Optional `u32`.
    pub fn opt_u32(&mut self, ty: u8, v: Option<u32>) -> &mut Self {
        if let Some(v) = v {
            self.u32(ty, v);
        }
        self
    }

    /// Optional 4-byte enum.
    pub fn opt_i32(&mut self, ty: u8, v: Option<i32>) -> &mut Self {
        if let Some(v) = v {
            self.i32(ty, v);
        }
        self
    }

    /// Optional `u64`.
    pub fn opt_u64(&mut self, ty: u8, v: Option<u64>) -> &mut Self {
        if let Some(v) = v {
            self.u64(ty, v);
        }
        self
    }

    /// Top-level `QMI_STRING`: the `strlen(s)` bytes, no count, no
    /// NUL. `elem_len` is the ei `elem_len` (buffer size, i.e. max
    /// characters + 1); Linux rejects `strlen > elem_len`.
    pub fn string(&mut self, ty: u8, s: &[u8], elem_len: usize) -> Result<&mut Self, QmiError> {
        let n = c_strlen(s);
        if n > elem_len {
            return Err(QmiError::StringTooLong {
                tlv: ty,
                len: n,
                max: elem_len,
            });
        }
        Ok(self.tlv(ty, &s[..n]))
    }

    /// `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of `QMI_UNSIGNED_1_BYTE`.
    pub fn var_u8_array(
        &mut self,
        ty: u8,
        len_size: LenSize,
        data: &[u8],
        max_elems: usize,
    ) -> Result<&mut Self, QmiError> {
        if data.len() > max_elems {
            return Err(QmiError::ArrayTooLong {
                tlv: ty,
                len: data.len(),
                max: max_elems,
            });
        }
        let mut v = Vec::with_capacity(len_size.bytes() + data.len());
        push_len(&mut v, len_size, data.len());
        v.extend_from_slice(data);
        Ok(self.tlv(ty, &v))
    }

    /// `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of `QMI_UNSIGNED_4_BYTE`.
    pub fn var_u32_array(
        &mut self,
        ty: u8,
        len_size: LenSize,
        data: &[u32],
        max_elems: usize,
    ) -> Result<&mut Self, QmiError> {
        if data.len() > max_elems {
            return Err(QmiError::ArrayTooLong {
                tlv: ty,
                len: data.len(),
                max: max_elems,
            });
        }
        let mut v = Vec::with_capacity(len_size.bytes() + 4 * data.len());
        push_len(&mut v, len_size, data.len());
        for d in data {
            v.extend_from_slice(&d.to_le_bytes());
        }
        Ok(self.tlv(ty, &v))
    }

    /// `QMI_STRUCT`, `NO_ARRAY`: one TLV holding the members `f`
    /// writes, unframed.
    pub fn struct_tlv(
        &mut self,
        ty: u8,
        f: impl FnOnce(&mut StructWriter) -> Result<(), QmiError>,
    ) -> Result<&mut Self, QmiError> {
        let mut sw = StructWriter { buf: Vec::new() };
        f(&mut sw)?;
        Ok(self.tlv(ty, &sw.buf))
    }

    /// `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of `QMI_STRUCT`: the count,
    /// then `count` structs written by `f(writer, index)`.
    pub fn var_struct_array(
        &mut self,
        ty: u8,
        len_size: LenSize,
        count: usize,
        max_elems: usize,
        mut f: impl FnMut(&mut StructWriter, usize) -> Result<(), QmiError>,
    ) -> Result<&mut Self, QmiError> {
        if count > max_elems {
            return Err(QmiError::ArrayTooLong {
                tlv: ty,
                len: count,
                max: max_elems,
            });
        }
        let mut sw = StructWriter { buf: Vec::new() };
        push_len(&mut sw.buf, len_size, count);
        for i in 0..count {
            f(&mut sw, i)?;
        }
        Ok(self.tlv(ty, &sw.buf))
    }

    /// The finished TLV payload, or `BufferTooSmall` if it exceeds
    /// the message's max length (`qmi_encode` `-ETOOSMALL`).
    pub fn finish(self) -> Result<Vec<u8>, QmiError> {
        if self.buf.len() > self.max_len || self.buf.len() > u16::MAX as usize {
            return Err(QmiError::BufferTooSmall {
                needed: self.buf.len(),
                max: self.max_len,
            });
        }
        Ok(self.buf)
    }
}

/// Writer for the members of a `QMI_STRUCT` (`enc_level > 1`): no
/// TLV framing, members concatenated in ei order.
#[derive(Debug)]
pub struct StructWriter {
    buf: Vec<u8>,
}

impl StructWriter {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// `QMI_SIGNED_4_BYTE_ENUM`.
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Nested `QMI_STRING`: count (`u8` if `elem_len <= 255`, else
    /// `u16`) then the `strlen` bytes.
    pub fn string(&mut self, s: &[u8], elem_len: usize) -> Result<&mut Self, QmiError> {
        let n = c_strlen(s);
        if n > elem_len {
            return Err(QmiError::StringTooLong {
                tlv: QMI_COMMON_TLV_TYPE,
                len: n,
                max: elem_len,
            });
        }
        let size = if elem_len <= u8::MAX as usize {
            LenSize::U8
        } else {
            LenSize::U16
        };
        push_len(&mut self.buf, size, n);
        self.buf.extend_from_slice(&s[..n]);
        Ok(self)
    }

    /// Nested `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of `QMI_STRUCT`.
    pub fn var_struct_array(
        &mut self,
        len_size: LenSize,
        count: usize,
        max_elems: usize,
        mut f: impl FnMut(&mut StructWriter, usize) -> Result<(), QmiError>,
    ) -> Result<&mut Self, QmiError> {
        if count > max_elems {
            return Err(QmiError::ArrayTooLong {
                tlv: QMI_COMMON_TLV_TYPE,
                len: count,
                max: max_elems,
            });
        }
        push_len(&mut self.buf, len_size, count);
        for i in 0..count {
            f(self, i)?;
        }
        Ok(self)
    }
}

// ── Decode ─────────────────────────────────────────────────────────

/// One top-level TLV.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub ty: u8,
    pub value: &'a [u8],
}

/// Iterator over a message's top-level TLVs. Yields `Err(Truncated)`
/// (then stops) if a header or value runs past the payload.
#[derive(Debug)]
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> TlvReader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            buf: payload,
            pos: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for TlvReader<'a> {
    type Item = Result<Tlv<'a>, QmiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.buf.len() {
            return None;
        }
        let rest = &self.buf[self.pos..];
        if rest.len() < TLV_HDR_SIZE {
            self.failed = true;
            return Some(Err(QmiError::Truncated { tlv: rest[0] }));
        }
        let ty = rest[0];
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        let start = TLV_HDR_SIZE;
        if rest.len() - start < len {
            self.failed = true;
            return Some(Err(QmiError::Truncated { tlv: ty }));
        }
        self.pos += start + len;
        Some(Ok(Tlv {
            ty,
            value: &rest[start..start + len],
        }))
    }
}

/// Walk a message payload the way `qmi_decode` does at level 1:
/// `f(ty, value)` for every TLV whose type is in `known`; unknown
/// optional TLVs (`>= 0x10`) are skipped — including one whose length
/// runs past the end, which Linux steps over and accepts; unknown
/// mandatory TLVs fail. Returns the set of known TLV types seen, as
/// a bitmap indexed by type, for mandatory-presence checks.
pub fn decode_tlvs<'a>(
    payload: &'a [u8],
    known: &[u8],
    mut f: impl FnMut(u8, &'a [u8]) -> Result<(), QmiError>,
) -> Result<TlvSeen, QmiError> {
    let mut seen = TlvSeen::default();
    let mut pos = 0usize;
    while pos < payload.len() {
        let rest = &payload[pos..];
        if rest.len() < TLV_HDR_SIZE {
            return Err(QmiError::Truncated { tlv: rest[0] });
        }
        let ty = rest[0];
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        pos += TLV_HDR_SIZE;
        if !known.contains(&ty) {
            if ty < OPTIONAL_TLV_TYPE_START {
                return Err(QmiError::UnknownMandatoryTlv(ty));
            }
            pos += len;
            continue;
        }
        let value = payload
            .get(pos..pos + len)
            .ok_or(QmiError::Truncated { tlv: ty })?;
        f(ty, value)?;
        seen.set(ty);
        pos += len;
    }
    Ok(seen)
}

/// Bitmap of TLV types seen by [`decode_tlvs`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TlvSeen([u64; 4]);

impl TlvSeen {
    fn set(&mut self, ty: u8) {
        self.0[(ty >> 6) as usize] |= 1u64 << (ty & 63);
    }

    pub fn contains(&self, ty: u8) -> bool {
        self.0[(ty >> 6) as usize] & (1u64 << (ty & 63)) != 0
    }
}

fn exact<const N: usize>(ty: u8, value: &[u8]) -> Result<[u8; N], QmiError> {
    if value.len() != N {
        return Err(QmiError::LengthMismatch {
            tlv: ty,
            expected: N,
            got: value.len(),
        });
    }
    let mut a = [0u8; N];
    a.copy_from_slice(value);
    Ok(a)
}

/// Top-level `QMI_UNSIGNED_1_BYTE` value.
pub fn tlv_u8(ty: u8, value: &[u8]) -> Result<u8, QmiError> {
    Ok(exact::<1>(ty, value)?[0])
}

/// Top-level `QMI_UNSIGNED_2_BYTE` / `QMI_SIGNED_2_BYTE_ENUM` value.
pub fn tlv_u16(ty: u8, value: &[u8]) -> Result<u16, QmiError> {
    Ok(u16::from_le_bytes(exact::<2>(ty, value)?))
}

/// Top-level `QMI_UNSIGNED_4_BYTE` value.
pub fn tlv_u32(ty: u8, value: &[u8]) -> Result<u32, QmiError> {
    Ok(u32::from_le_bytes(exact::<4>(ty, value)?))
}

/// Top-level `QMI_SIGNED_4_BYTE_ENUM` value.
pub fn tlv_i32(ty: u8, value: &[u8]) -> Result<i32, QmiError> {
    Ok(i32::from_le_bytes(exact::<4>(ty, value)?))
}

/// Top-level `QMI_UNSIGNED_8_BYTE` value.
pub fn tlv_u64(ty: u8, value: &[u8]) -> Result<u64, QmiError> {
    Ok(u64::from_le_bytes(exact::<8>(ty, value)?))
}

/// Top-level `QMI_STRING` value: the whole TLV, which must be
/// shorter than `elem_len` (`qmi_decode_string_elem` `-ETOOSMALL`).
/// Returned up to the first NUL — what a C consumer of the
/// NUL-terminated decode buffer sees.
pub fn tlv_string(ty: u8, value: &[u8], elem_len: usize) -> Result<Vec<u8>, QmiError> {
    if value.len() >= elem_len {
        return Err(QmiError::StringTooLong {
            tlv: ty,
            len: value.len(),
            max: elem_len,
        });
    }
    Ok(value[..c_strlen(value)].to_vec())
}

/// Top-level `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of bytes: count, then
/// exactly `count` bytes.
pub fn tlv_var_u8_array(
    ty: u8,
    value: &[u8],
    len_size: LenSize,
    max_elems: usize,
) -> Result<Vec<u8>, QmiError> {
    if value.len() < len_size.bytes() {
        return Err(QmiError::Truncated { tlv: ty });
    }
    let mut r = StructReader::new(ty, value);
    let n = r.data_len(len_size)?;
    if n > max_elems {
        return Err(QmiError::ArrayTooLong {
            tlv: ty,
            len: n,
            max: max_elems,
        });
    }
    let data = r.rest();
    if data.len() != n {
        return Err(QmiError::LengthMismatch {
            tlv: ty,
            expected: len_size.bytes() + n,
            got: value.len(),
        });
    }
    Ok(data.to_vec())
}

/// Reader for `QMI_STRUCT` members (`dec_level > 1`) with
/// `qmi_decode`'s semantics: once the bytes are exhausted on a member
/// boundary every further member reads as zero (Linux stops at
/// `decoded_bytes == in_buf_len` and leaves the kzalloc'd field);
/// a member cut in half is `Truncated`.
#[derive(Debug)]
pub struct StructReader<'a> {
    tlv: u8,
    buf: &'a [u8],
    pos: usize,
}

impl<'a> StructReader<'a> {
    /// `tlv` labels errors with the enclosing top-level TLV type.
    pub fn new(tlv: u8, buf: &'a [u8]) -> Self {
        Self { tlv, buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_exhausted(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], QmiError> {
        let mut a = [0u8; N];
        if self.is_exhausted() {
            return Ok(a);
        }
        if self.remaining() < N {
            return Err(QmiError::Truncated { tlv: self.tlv });
        }
        a.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, QmiError> {
        Ok(self.take::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, QmiError> {
        Ok(u16::from_le_bytes(self.take::<2>()?))
    }

    pub fn u32(&mut self) -> Result<u32, QmiError> {
        Ok(u32::from_le_bytes(self.take::<4>()?))
    }

    pub fn i32(&mut self) -> Result<i32, QmiError> {
        Ok(i32::from_le_bytes(self.take::<4>()?))
    }

    pub fn u64(&mut self) -> Result<u64, QmiError> {
        Ok(u64::from_le_bytes(self.take::<8>()?))
    }

    /// A `QMI_DATA_LEN` count.
    pub fn data_len(&mut self, size: LenSize) -> Result<usize, QmiError> {
        Ok(match size {
            LenSize::U8 => self.u8()? as usize,
            LenSize::U16 => self.u16()? as usize,
        })
    }

    /// Nested `QMI_STRING` (count-prefixed). Count `>= elem_len` is
    /// `StringTooLong` (`-ETOOSMALL`), count beyond the bytes present
    /// is `StringTooLong` too (`-EFAULT`). Returned up to the first
    /// NUL.
    pub fn string(&mut self, elem_len: usize) -> Result<Vec<u8>, QmiError> {
        if self.is_exhausted() {
            return Ok(Vec::new());
        }
        let size = if elem_len <= u8::MAX as usize {
            LenSize::U8
        } else {
            LenSize::U16
        };
        let n = self.data_len(size)?;
        if n >= elem_len || n > self.remaining() {
            return Err(QmiError::StringTooLong {
                tlv: self.tlv,
                len: n,
                max: elem_len,
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s[..c_strlen(s)].to_vec())
    }

    /// Everything not yet consumed (consumes it).
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// The bytes not yet consumed, as a sub-reader for a nested
    /// struct; advance with [`Self::advance`].
    pub fn sub(&self) -> StructReader<'a> {
        StructReader::new(self.tlv, &self.buf[self.pos..])
    }

    pub fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }

    pub fn consumed(&self) -> usize {
        self.pos
    }

    /// The struct TLV must be fully consumed (`qmi_decode_struct_elem`
    /// `decoded_bytes != tlv_len` → `-EFAULT`).
    pub fn finish(&self) -> Result<(), QmiError> {
        if !self.is_exhausted() {
            return Err(QmiError::StructLengthMismatch { tlv: self.tlv });
        }
        Ok(())
    }
}

/// Decode a top-level `QMI_STRUCT`, `NO_ARRAY` TLV with `f`, which
/// must consume it exactly.
pub fn tlv_struct<'a, T>(
    ty: u8,
    value: &'a [u8],
    f: impl FnOnce(&mut StructReader<'a>) -> Result<T, QmiError>,
) -> Result<T, QmiError> {
    let mut r = StructReader::new(ty, value);
    let v = f(&mut r)?;
    r.finish()?;
    Ok(v)
}

/// Decode a top-level `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of
/// `QMI_STRUCT` (`qmi_decode_struct_elem` at `dec_level == 2`): the
/// count, then up to `count` structs — decoding stops early when the
/// bytes run out, and (as in Linux, whose decode buffer is zeroed)
/// the missing entries are `T::default()`. The TLV must be consumed
/// exactly.
pub fn tlv_var_struct_array<'a, T: Default>(
    ty: u8,
    value: &'a [u8],
    len_size: LenSize,
    max_elems: usize,
    mut f: impl FnMut(&mut StructReader<'a>) -> Result<T, QmiError>,
) -> Result<Vec<T>, QmiError> {
    // At level 1 the count is read unconditionally.
    if value.len() < len_size.bytes() {
        return Err(QmiError::Truncated { tlv: ty });
    }
    let mut r = StructReader::new(ty, value);
    let n = r.data_len(len_size)?;
    if n > max_elems {
        return Err(QmiError::ArrayTooLong {
            tlv: ty,
            len: n,
            max: max_elems,
        });
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if r.is_exhausted() {
            out.push(T::default());
            continue;
        }
        out.push(f(&mut r)?);
    }
    r.finish()?;
    Ok(out)
}

/// Decode a `QMI_DATA_LEN` + `VAR_LEN_ARRAY` of `QMI_STRUCT` nested
/// inside a struct (`dec_level > 2`): unlike the top-level case, all
/// `count` entries must start before the bytes run out
/// (`i < elem_len` → `-EFAULT`).
pub fn nested_var_struct_array<'a, T>(
    r: &mut StructReader<'a>,
    len_size: LenSize,
    max_elems: usize,
    mut f: impl FnMut(&mut StructReader<'a>) -> Result<T, QmiError>,
) -> Result<Vec<T>, QmiError> {
    let n = r.data_len(len_size)?;
    if n > max_elems {
        return Err(QmiError::ArrayTooLong {
            tlv: r.tlv,
            len: n,
            max: max_elems,
        });
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if r.is_exhausted() {
            return Err(QmiError::StructLengthMismatch { tlv: r.tlv });
        }
        out.push(f(r)?);
    }
    Ok(out)
}

// ── Common response ────────────────────────────────────────────────

/// `struct qmi_response_type_v01` — TLV `0x02` of every response.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QmiResponse {
    pub result: u16,
    pub error: u16,
}

/// TLV type carrying [`QmiResponse`] in every WLFW response ei table.
pub const QMI_RESPONSE_TLV: u8 = 0x02;

impl QmiResponse {
    /// Decode the members per `qmi_response_type_v01_ei`: two
    /// `QMI_SIGNED_2_BYTE_ENUM`s.
    pub fn read(r: &mut StructReader<'_>) -> Result<Self, QmiError> {
        Ok(Self {
            result: r.u16()?,
            error: r.u16()?,
        })
    }

    /// Decode a TLV `0x02` value.
    pub fn from_tlv(value: &[u8]) -> Result<Self, QmiError> {
        tlv_struct(QMI_RESPONSE_TLV, value, Self::read)
    }

    pub fn is_success(&self) -> bool {
        self.result == QMI_RESULT_SUCCESS_V01
    }
}
