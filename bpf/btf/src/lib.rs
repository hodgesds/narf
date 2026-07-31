//! # `narf-bpf-btf` — a BTF blob parser
//!
//! `BPF_BTF_LOAD` hands the kernel a byte blob that a userspace loader built.
//! Every real loader — libbpf, bpftool, systemd's BPF bits — ships one
//! alongside its programs, so accepting it is a hard compatibility
//! requirement. This crate is the part that reads it.
//!
//! ## What this is not
//!
//! It is **not** NARF's type system. Linux carries kfunc argument semantics in
//! BTF parameter-name suffixes (`__k`, `__sz`, `__uninit`, …) plus a hardcoded
//! `special_kfunc_list[]` of BTF ids; NARF derives them from Rust types through
//! the `kfunc!` macro and a link-section registry
//! (`bpf/specification/spec.md` §1.3). So BTF here is a compatibility surface
//! that a loader can hand us and get an fd back for, and nothing in the
//! verifier consumes it. That is the entire reason this is ~1.5k lines against
//! Linux's 9.7k `btf.c`.
//!
//! Deliberately absent, and staying absent (the plan says so):
//!
//! * `btf_show_*` pretty-printing — 900 lines of `%s`-formatting a value
//!   against a type, for `bpf_snprintf_btf()`. Nothing in NARF calls it.
//! * In-kernel CO-RE candidate finding. libbpf does CO-RE relocation in
//!   userspace; the in-kernel path exists for `bpf_core_apply_relo` on
//!   light-skeleton loads, which NARF does not have.
//! * Split BTF and module BTF — the `base_btf` machinery. A blob whose header
//!   `flags` are nonzero is rejected rather than half-understood.
//!
//! ## Threat model
//!
//! The blob arrives from userspace and every field in it is attacker-chosen.
//! A panic here is a kernel panic driven by a syscall argument, so:
//!
//! * The crate is `#![forbid(unsafe_code)]` and has no dependencies.
//! * Every offset and length is combined with `checked_add`/`checked_mul` in
//!   `u64` or `usize` before it is used, never with `+` in `u32`. The
//!   codebase has been bitten twice by an unchecked `addr + len` wrapping to
//!   something that then passed a bounds test.
//! * Every slice access goes through `get()`. There is no `[i]` indexing of
//!   blob-derived data, and no `unwrap()`.
//! * The whole-graph walk is an explicit-stack DFS, not recursion, because
//!   the depth is a function of the blob.
//! * Cycles that would make a type walk non-terminating are rejected before
//!   any consumer can walk the graph.
//!
//! ## Divergences from Linux
//!
//! Pinned with `// LINUX-GAP` at the site. The visible ones are the errno for
//! the three "unsupported" rejections (see [`Reason::errno`]) and the absence
//! of the three subsystems listed above.
//!
//! ## Layout of a blob
//!
//! ```text
//! ┌──────────────┬───────────────────────┬─────────────────────┐
//! │ btf_header   │ type section          │ string section      │
//! │ (hdr_len)    │ (type_off, type_len)  │ (str_off, str_len)  │
//! └──────────────┴───────────────────────┴─────────────────────┘
//!                 ^ section offsets are relative to the end of the header
//! ```
//!
//! The two sections must tile the space after the header exactly: no gap, no
//! overlap, nothing left over, and the string section last. That is Linux's
//! rule (`btf_check_sec_info`) and it is worth keeping — it removes a whole
//! class of "which bytes did the producer mean" ambiguity.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

extern crate alloc;

mod error;
mod resolve;
pub mod types;

#[cfg(test)]
mod builder;
#[cfg(test)]
mod tests;

pub use error::{BtfError, Errno, Reason};
pub use types::{
    BtfType, Enum64Value, EnumValue, FuncLinkage, IntEncoding, Kind, Member, Param, SecInfo,
    VarLinkage,
};

use alloc::vec::Vec;

/// `BTF_MAGIC`. Little-endian on the wire; a big-endian blob reads as `0x9feb`
/// here and is rejected, exactly as Linux rejects it.
pub const BTF_MAGIC: u16 = 0xeb9f;

/// `BTF_VERSION`.
pub const BTF_VERSION: u8 = 1;

/// The fixed size of `struct btf_header`.
const HEADER_LEN: usize = 24;

/// `BTF_MAX_SIZE` — the largest blob accepted, matching Linux. A `vmlinux`
/// BTF is a few MiB; 16 MiB leaves room and is also `MAX_USER_COPY` in NARF's
/// user-copy helpers, so the two limits agree by construction.
pub const MAX_BTF_SIZE: usize = 16 * 1024 * 1024;

/// `BTF_MAX_TYPE` — the largest `type_id`.
pub const MAX_TYPE_ID: u32 = 0x000f_ffff;

/// `BTF_MAX_NAME_OFFSET`.
const MAX_NAME_OFFSET: u32 = 0x00ff_ffff;

/// `KSYM_NAME_LEN` — the longest identifier accepted in the string section.
const MAX_NAME_LEN: usize = 512;

/// `BTF_INFO_MASK` — the bits of `btf_type::info` that are defined. Anything
/// else set means the producer used a field we do not understand.
const INFO_MASK: u32 = 0x9f00_ffff;

/// `BTF_INT_MASK` — the defined bits of an `INT`'s trailing word.
const INT_MASK: u32 = 0x0fff_ffff;

/// Pointer width. Both NARF targets are 64-bit; a 32-bit port would need this
/// to come from the loading task's ABI, which is why it is named rather than
/// spelled `8` at the one site that uses it.
const PTR_SIZE: u32 = 8;

/// `struct btf_header`, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Declared header length. May exceed [`HEADER_LEN`] if the trailing bytes
    /// are all zero.
    pub hdr_len: u32,
    /// Type-section offset, relative to the end of the header.
    pub type_off: u32,
    /// Type-section length in bytes.
    pub type_len: u32,
    /// String-section offset, relative to the end of the header.
    pub str_off: u32,
    /// String-section length in bytes.
    pub str_len: u32,
}

/// A parsed, validated BTF blob.
///
/// Holding the raw bytes as well as the decoded graph is deliberate and
/// mirrors Linux's `btf->data`: `BPF_OBJ_GET_INFO_BY_FD` on a BTF fd returns
/// the blob verbatim, and re-encoding the graph to serve that would be a
/// second serializer to keep in sync with the parser. The parsed graph is an
/// index over the bytes, not a replacement for them.
#[derive(Debug)]
pub struct Btf {
    data: Vec<u8>,
    header: Header,
    /// Byte range of the string section within `data`.
    str_start: usize,
    str_end: usize,
    /// Index `i` is `type_id` `i + 1`. Type id 0 is void and has no entry.
    types: Vec<BtfType>,
    /// Byte size of each type, or `None` for the sizeless kinds. Same
    /// indexing as `types`.
    sizes: Vec<Option<u32>>,
    /// Each type with modifiers stripped. Same indexing as `types`.
    resolved: Vec<u32>,
}

impl Btf {
    /// Parse and validate a blob.
    ///
    /// Takes ownership because the blob is retained; the caller has already
    /// copied it out of userspace and has no further use for it.
    ///
    /// # Errors
    ///
    /// [`BtfError`] naming the check that failed and the `type_id` it failed
    /// in. Never panics, for any input.
    pub fn parse(data: Vec<u8>) -> Result<Self, BtfError> {
        if data.is_empty() {
            return Err(BtfError::global(Reason::BlobEmpty));
        }
        if data.len() > MAX_BTF_SIZE {
            return Err(BtfError::global(Reason::BlobTooLarge));
        }

        let header = parse_header(&data)?;
        let (str_start, str_end) = check_str_sec(&data, &header)?;

        // `check_sec_info` already proved these stay inside the blob, but the
        // arithmetic is still checked: "an earlier call proved it" is exactly
        // the kind of invariant that rots when the earlier call is edited.
        let oob = || BtfError::global(Reason::SectionOffsetOutOfRange);
        let type_start = (header.hdr_len as usize)
            .checked_add(header.type_off as usize)
            .ok_or_else(oob)?;
        let type_end = type_start
            .checked_add(header.type_len as usize)
            .ok_or_else(oob)?;

        if header.type_len == 0 {
            return Err(BtfError::global(Reason::NoTypes));
        }

        let strings = data.get(str_start..str_end).ok_or_else(|| {
            // Unreachable given `check_str_sec`, but expressed as a rejection
            // rather than an `expect` so that a future edit to the section
            // arithmetic degrades into EINVAL and not a kernel panic.
            BtfError::global(Reason::StringSectionInvalid)
        })?;
        let type_sec = data.get(type_start..type_end).ok_or_else(oob)?;

        let types = parse_types(type_sec, strings)?;

        let mut btf = Self {
            data,
            header,
            str_start,
            str_end,
            types,
            sizes: Vec::new(),
            resolved: Vec::new(),
        };
        resolve::resolve(&mut btf)?;
        Ok(btf)
    }

    /// The raw blob, exactly as userspace supplied it.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// The decoded header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The string section.
    #[must_use]
    pub fn strings(&self) -> &[u8] {
        // Both bounds were validated in `parse`; `get` rather than a slice
        // expression so a future edit cannot turn this into a panic.
        self.data.get(self.str_start..self.str_end).unwrap_or(&[])
    }

    /// How many types the blob declares. Type ids run `1..=nr_types()`.
    #[must_use]
    pub fn nr_types(&self) -> u32 {
        // Bounded by `MAX_TYPE_ID` at parse time.
        self.types.len() as u32
    }

    /// The type with this id, or `None` for void (0) and out-of-range ids.
    #[must_use]
    pub fn type_by_id(&self, id: u32) -> Option<&BtfType> {
        self.types.get(id.checked_sub(1)? as usize)
    }

    /// The byte size of a type, following modifiers.
    ///
    /// `None` for void and for the sizeless kinds — `FWD`, `FUNC`,
    /// `FUNC_PROTO`, `VAR`, `DATASEC`, `DECL_TAG` — which is what makes
    /// "a struct member must have a size" expressible.
    #[must_use]
    pub fn size_of(&self, id: u32) -> Option<u32> {
        *self.sizes.get(id.checked_sub(1)? as usize)?
    }

    /// The id this one denotes with `typedef`/`const`/`volatile`/`restrict`/
    /// `type_tag` stripped. Terminates because cycles were rejected at parse.
    #[must_use]
    pub fn skip_modifiers(&self, id: u32) -> u32 {
        self.resolved
            .get(id.wrapping_sub(1) as usize)
            .copied()
            .unwrap_or(0)
    }

    /// The NUL-terminated name at `off`, or `None` if the offset is outside
    /// the string section or the bytes are not UTF-8.
    ///
    /// Non-UTF-8 is `None` rather than an error because Linux only constrains
    /// the character set of names that must be *identifiers*; an `INT`'s name,
    /// for instance, is never charset-checked. Rejecting the whole blob for a
    /// name nothing reads would break real producers.
    #[must_use]
    pub fn name(&self, off: u32) -> Option<&str> {
        core::str::from_utf8(name_bytes(self.strings(), off)?).ok()
    }

    /// Iterate `(type_id, type)` in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &BtfType)> + '_ {
        self.types
            .iter()
            .enumerate()
            .map(|(i, t)| ((i as u32) + 1, t))
    }

    /// The decoded types, indexed from 0 for `type_id` 1.
    pub(crate) fn types(&self) -> &[BtfType] {
        &self.types
    }

    pub(crate) fn set_resolution(&mut self, sizes: Vec<Option<u32>>, resolved: Vec<u32>) {
        self.sizes = sizes;
        self.resolved = resolved;
    }
}

// ── header and section layout ───────────────────────────────────────

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

fn parse_header(data: &[u8]) -> Result<Header, BtfError> {
    // Linux reads `hdr_len` first and only then trusts the rest, because the
    // producer is allowed to declare a header longer than the kernel knows.
    // `offsetofend(struct btf_header, hdr_len)` is 8.
    let hdr_len = u32_at(data, 4).ok_or(BtfError::global(Reason::HeaderTruncated))?;
    let hdr_len_us = hdr_len as usize;
    if data.len() < hdr_len_us {
        return Err(BtfError::global(Reason::HeaderTruncated));
    }

    // A header longer than the fields we know is fine only if the extra bytes
    // are zero — otherwise the producer meant something by them and we would
    // be silently ignoring it.
    if hdr_len_us > HEADER_LEN {
        let tail = data
            .get(HEADER_LEN..hdr_len_us)
            .ok_or(BtfError::global(Reason::HeaderTruncated))?;
        if tail.iter().any(|b| *b != 0) {
            return Err(BtfError::global(Reason::UnsupportedHeader));
        }
    }

    // Fields past `hdr_len` read as zero, mirroring Linux's
    // `memcpy(&btf->hdr, data, min(hdr_len, sizeof(hdr)))` into a zeroed
    // struct. A short header therefore declares zero-length sections and is
    // caught below by the tiling check, not by a special case here.
    let field = |off: usize| -> u32 {
        if off + 4 <= hdr_len_us {
            u32_at(data, off).unwrap_or(0)
        } else {
            0
        }
    };

    let magic = u16_at(data, 0).ok_or(BtfError::global(Reason::HeaderTruncated))?;
    if magic != BTF_MAGIC {
        return Err(BtfError::global(Reason::BadMagic));
    }
    let version = *data
        .get(2)
        .ok_or(BtfError::global(Reason::HeaderTruncated))?;
    if version != BTF_VERSION {
        return Err(BtfError::global(Reason::UnsupportedVersion));
    }
    let flags = *data
        .get(3)
        .ok_or(BtfError::global(Reason::HeaderTruncated))?;
    if flags != 0 {
        // The only defined flag is split BTF's base-BTF marker, which is out
        // of scope by design. Refusing beats half-understanding.
        return Err(BtfError::global(Reason::UnsupportedFlags));
    }

    if data.len() == hdr_len_us {
        return Err(BtfError::global(Reason::NoData));
    }

    let header = Header {
        hdr_len,
        type_off: field(8),
        type_len: field(12),
        str_off: field(16),
        str_len: field(20),
    };

    // Before the tiling check, not after: the tiling rule happens to force
    // `type_off == 0` for any blob it accepts (the type section is first, and
    // a nonzero offset is a gap), so an alignment check placed after it would
    // be unreachable — a rule that reads as enforced and is not. Here it is a
    // live check with a live test.
    if header.type_off % 4 != 0 {
        return Err(BtfError::global(Reason::UnalignedTypeSection));
    }

    check_sec_info(data.len(), &header)?;
    Ok(header)
}

/// The two sections must tile `[hdr_len, data.len())` exactly.
///
/// All arithmetic in `u64`: `off` and `len` are attacker-chosen `u32`s and
/// `off + len` overflows `u32` for perfectly ordinary hostile values.
fn check_sec_info(data_len: usize, hdr: &Header) -> Result<(), BtfError> {
    let expected_total = (data_len as u64) - u64::from(hdr.hdr_len);

    // Sorted by offset, as Linux sorts them: the tiling check is order-free
    // only if the sections are visited in address order.
    let mut secs = [
        (u64::from(hdr.type_off), u64::from(hdr.type_len)),
        (u64::from(hdr.str_off), u64::from(hdr.str_len)),
    ];
    if secs[1].0 < secs[0].0 {
        secs.swap(0, 1);
    }

    let mut total: u64 = 0;
    for (off, len) in secs {
        if expected_total < off {
            return Err(BtfError::global(Reason::SectionOffsetOutOfRange));
        }
        if total < off {
            return Err(BtfError::global(Reason::SectionGap));
        }
        if total > off {
            return Err(BtfError::global(Reason::SectionOverlap));
        }
        if expected_total - total < len {
            return Err(BtfError::global(Reason::SectionTooLong));
        }
        total += len;
    }
    if expected_total != total {
        return Err(BtfError::global(Reason::TrailingData));
    }
    Ok(())
}

/// Validate the string section and return its byte range in the blob.
///
/// The leading NUL is what makes `name_off == 0` mean "anonymous"; the
/// trailing NUL is what makes every name NUL-terminated, so `name_bytes` needs
/// no end-of-section special case.
fn check_str_sec(data: &[u8], hdr: &Header) -> Result<(usize, usize), BtfError> {
    let start = u64::from(hdr.hdr_len) + u64::from(hdr.str_off);
    let end = start + u64::from(hdr.str_len);
    if end != data.len() as u64 {
        return Err(BtfError::global(Reason::StringSectionNotAtEnd));
    }
    if hdr.str_len == 0 || hdr.str_len - 1 > MAX_NAME_OFFSET {
        return Err(BtfError::global(Reason::StringSectionInvalid));
    }
    let (start, end) = (start as usize, end as usize);
    let sec = data
        .get(start..end)
        .ok_or(BtfError::global(Reason::StringSectionInvalid))?;
    if sec.first() != Some(&0) || sec.last() != Some(&0) {
        return Err(BtfError::global(Reason::StringSectionInvalid));
    }
    Ok((start, end))
}

// ── names ───────────────────────────────────────────────────────────

/// The NUL-terminated bytes at `off`, or `None` if `off` is out of range.
///
/// The section's trailing NUL guarantees a terminator exists, so the `position`
/// below cannot run off the end — but it is still written as a bounded search
/// over a sub-slice rather than a pointer walk.
fn name_bytes(strings: &[u8], off: u32) -> Option<&[u8]> {
    let rest = strings.get(off as usize..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    rest.get(..end)
}

/// `__btf_name_char_ok`: alphanumeric, `_`, or `.`; a leading digit is out.
const fn name_char_ok(c: u8, first: bool) -> bool {
    if c == b'_' || c == b'.' {
        return true;
    }
    if first {
        c.is_ascii_alphabetic()
    } else {
        c.is_ascii_alphanumeric()
    }
}

/// `btf_name_valid_identifier` — also `btf_name_valid_section`, which Linux
/// long ago collapsed into the same predicate once `.` became legal in both.
fn name_is_valid_identifier(strings: &[u8], off: u32) -> bool {
    let Some(bytes) = name_bytes(strings, off) else {
        return false;
    };
    if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
        return false;
    }
    bytes
        .iter()
        .enumerate()
        .all(|(i, c)| name_char_ok(*c, i == 0))
}

// ── the type section ────────────────────────────────────────────────

/// A bounded cursor over the type section.
///
/// Every read is `Option`-returning and every position advance is checked, so
/// a truncated record is a `TypeTruncated` rejection rather than a slice
/// panic. `type_id` is carried only so the rejection can name the record.
struct TypeReader<'a> {
    sec: &'a [u8],
    pos: usize,
    type_id: u32,
}

impl<'a> TypeReader<'a> {
    fn err(&self, reason: Reason) -> BtfError {
        BtfError::at(self.type_id, reason)
    }

    fn u32(&mut self) -> Result<u32, BtfError> {
        let v = u32_at(self.sec, self.pos).ok_or(self.err(Reason::TypeTruncated))?;
        // `pos + 4` cannot overflow: `u32_at` already proved `pos + 4` is a
        // valid index range in `sec`, whose length is bounded by the blob.
        self.pos += 4;
        Ok(v)
    }

    fn i32(&mut self) -> Result<i32, BtfError> {
        Ok(self.u32()? as i32)
    }

    fn done(&self) -> bool {
        self.pos >= self.sec.len()
    }
}

#[allow(clippy::too_many_lines)]
fn parse_types(sec: &[u8], strings: &[u8]) -> Result<Vec<BtfType>, BtfError> {
    let mut out: Vec<BtfType> = Vec::new();
    let mut r = TypeReader {
        sec,
        pos: 0,
        type_id: 0,
    };

    let str_len = strings.len() as u32;
    let name_off_valid = |off: u32| off < str_len;

    while !r.done() {
        // Type ids are 1-based, so the id of the record about to be read is
        // one more than the count already decoded.
        r.type_id = (out.len() as u32)
            .checked_add(1)
            .ok_or(BtfError::global(Reason::TooManyTypes))?;
        if r.type_id > MAX_TYPE_ID {
            return Err(BtfError::global(Reason::TooManyTypes));
        }

        let name_off = r.u32()?;
        let info = r.u32()?;
        let size_or_type = r.u32()?;

        if info & !INFO_MASK != 0 {
            return Err(r.err(Reason::InvalidInfo));
        }
        let vlen = (info & 0xffff) as u16;
        let kind_flag = info >> 31 != 0;
        let kind = Kind::from_raw(((info >> 24) & 0x1f) as u8)
            .ok_or_else(|| r.err(Reason::InvalidKind))?;

        if !name_off_valid(name_off) {
            return Err(r.err(Reason::InvalidNameOffset));
        }

        // Shorthands used by nearly every arm. `named` is "must be a
        // non-empty identifier"; `anonymous` is "must have no name at all".
        let named = |r: &TypeReader| -> Result<(), BtfError> {
            if name_off == 0 || !name_is_valid_identifier(strings, name_off) {
                Err(r.err(Reason::InvalidName))
            } else {
                Ok(())
            }
        };
        let anonymous = |r: &TypeReader| -> Result<(), BtfError> {
            if name_off != 0 {
                Err(r.err(Reason::InvalidName))
            } else {
                Ok(())
            }
        };
        let optionally_named = |r: &TypeReader| -> Result<(), BtfError> {
            if name_off != 0 && !name_is_valid_identifier(strings, name_off) {
                Err(r.err(Reason::InvalidName))
            } else {
                Ok(())
            }
        };
        let no_vlen = |r: &TypeReader| -> Result<(), BtfError> {
            if vlen != 0 {
                Err(r.err(Reason::VlenNotZero))
            } else {
                Ok(())
            }
        };
        let no_kflag = |r: &TypeReader| -> Result<(), BtfError> {
            if kind_flag {
                Err(r.err(Reason::KindFlagNotZero))
            } else {
                Ok(())
            }
        };
        // A `type_id` reference. Only the syntactic bound is checkable here —
        // forward references are legal, so the count is not known yet. The
        // real bound against `nr_types` is a post-pass in `resolve`.
        let type_ref = |r: &TypeReader, id: u32, may_be_void: bool| -> Result<u32, BtfError> {
            if (!may_be_void && id == 0) || id > MAX_TYPE_ID {
                Err(r.err(Reason::InvalidTypeId))
            } else {
                Ok(id)
            }
        };

        let decoded = match kind {
            Kind::Int => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                let int_data = r.u32()?;
                if int_data & !INT_MASK != 0 {
                    return Err(r.err(Reason::IntDataInvalid));
                }
                let nr_bits = (int_data & 0xff) as u8;
                let bit_offset = ((int_data >> 16) & 0xff) as u8;
                // u32 arithmetic on two u8s: cannot overflow, and the bound
                // is 128 anyway.
                let total_bits = u32::from(nr_bits) + u32::from(bit_offset);
                if total_bits > 128 {
                    return Err(r.err(Reason::IntBitsExceedU128));
                }
                if total_bits.div_ceil(8) > size_or_type {
                    return Err(r.err(Reason::IntBitsExceedSize));
                }
                let encoding = match (int_data >> 24) & 0x0f {
                    0 => IntEncoding::None,
                    1 => IntEncoding::Signed,
                    2 => IntEncoding::Char,
                    4 => IntEncoding::Bool,
                    // Two attributes at once, or an undefined bit. Linux says
                    // one is enough for decoding and refuses the rest.
                    _ => return Err(r.err(Reason::IntEncodingUnsupported)),
                };
                BtfType::Int {
                    name_off,
                    size: size_or_type,
                    encoding,
                    bit_offset,
                    nr_bits,
                }
            }

            Kind::Ptr => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                anonymous(&r)?;
                BtfType::Ptr {
                    type_id: type_ref(&r, size_or_type, true)?,
                }
            }

            Kind::Typedef => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                named(&r)?;
                BtfType::Typedef {
                    name_off,
                    type_id: type_ref(&r, size_or_type, true)?,
                }
            }

            Kind::Const | Kind::Volatile | Kind::Restrict => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                anonymous(&r)?;
                BtfType::Qualifier {
                    kind,
                    type_id: type_ref(&r, size_or_type, true)?,
                }
            }

            Kind::TypeTag => {
                no_vlen(&r)?;
                // `kind_flag` is accepted here (and only here among the ref
                // kinds): Linux uses it to mark an attribute tag as opposed
                // to a name tag. NARF records neither, but rejecting the flag
                // would reject blobs clang emits today.
                //
                // The tag text must be non-empty but is *not* charset-checked
                // — Linux only tests `value[0]`, and a tag is free-form.
                if name_bytes(strings, name_off).is_none_or(<[u8]>::is_empty) {
                    return Err(r.err(Reason::InvalidName));
                }
                BtfType::TypeTag {
                    name_off,
                    type_id: type_ref(&r, size_or_type, true)?,
                }
            }

            Kind::Array => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                anonymous(&r)?;
                if size_or_type != 0 {
                    return Err(r.err(Reason::SizeNotZero));
                }
                let elem_type = r.u32()?;
                let index_type = r.u32()?;
                let nelems = r.u32()?;
                BtfType::Array {
                    elem_type: type_ref(&r, elem_type, false)
                        .map_err(|_| BtfError::at(r.type_id, Reason::InvalidElem))?,
                    index_type: type_ref(&r, index_type, false)
                        .map_err(|_| BtfError::at(r.type_id, Reason::InvalidIndex))?,
                    nelems,
                }
            }

            Kind::Struct | Kind::Union => {
                let is_union = kind == Kind::Union;
                optionally_named(&r)?;
                let struct_size = size_or_type;
                let mut members = Vec::new();
                let mut last_bit_offset: u32 = 0;
                for _ in 0..vlen {
                    let m_name = r.u32()?;
                    let m_type = r.u32()?;
                    let m_off = r.u32()?;
                    if !name_off_valid(m_name) {
                        return Err(r.err(Reason::InvalidNameOffset));
                    }
                    // A member may be anonymous (an unnamed union), but a
                    // named one must be a real identifier.
                    if m_name != 0 && !name_is_valid_identifier(strings, m_name) {
                        return Err(r.err(Reason::InvalidName));
                    }
                    let m_type = type_ref(&r, m_type, false)?;
                    let (bit_offset, bitfield_size) = if kind_flag {
                        ((m_off & 0x00ff_ffff), (m_off >> 24) as u8)
                    } else {
                        (m_off, 0)
                    };
                    if is_union && bit_offset != 0 {
                        return Err(r.err(Reason::UnionMemberBitOffsetNotZero));
                    }
                    if last_bit_offset > bit_offset {
                        return Err(r.err(Reason::MemberBitOffsetNotMonotonic));
                    }
                    // `>` and not `>=`: a trailing `char a[0]` legitimately
                    // starts exactly at the end of the struct. u64 because
                    // `bit_offset + 7` overflows u32 near the top of the
                    // range and would round down into a passing value.
                    if u64::from(bit_offset).div_ceil(8) > u64::from(struct_size) {
                        return Err(r.err(Reason::MemberOffsetExceedsStructSize));
                    }
                    last_bit_offset = bit_offset;
                    members.push(Member {
                        name_off: m_name,
                        type_id: m_type,
                        bit_offset,
                        bitfield_size,
                    });
                }
                BtfType::Composite {
                    name_off,
                    is_union,
                    size: struct_size,
                    kind_flag,
                    members,
                }
            }

            Kind::Enum | Kind::Enum64 => {
                optionally_named(&r)?;
                let size = size_or_type;
                if size > 8 || !size.is_power_of_two() {
                    return Err(r.err(Reason::EnumUnexpectedSize));
                }
                if kind == Kind::Enum {
                    let mut values = Vec::new();
                    for _ in 0..vlen {
                        let v_name = r.u32()?;
                        let val = r.i32()?;
                        if !name_off_valid(v_name) {
                            return Err(r.err(Reason::InvalidNameOffset));
                        }
                        if !name_is_valid_identifier(strings, v_name) {
                            return Err(r.err(Reason::InvalidName));
                        }
                        values.push(EnumValue {
                            name_off: v_name,
                            val,
                        });
                    }
                    BtfType::Enum {
                        name_off,
                        size,
                        signed: kind_flag,
                        values,
                    }
                } else {
                    let mut values = Vec::new();
                    for _ in 0..vlen {
                        let v_name = r.u32()?;
                        let lo = r.u32()?;
                        let hi = r.u32()?;
                        if !name_off_valid(v_name) {
                            return Err(r.err(Reason::InvalidNameOffset));
                        }
                        if !name_is_valid_identifier(strings, v_name) {
                            return Err(r.err(Reason::InvalidName));
                        }
                        values.push(Enum64Value {
                            name_off: v_name,
                            val: (u64::from(hi) << 32) | u64::from(lo),
                        });
                    }
                    BtfType::Enum64 {
                        name_off,
                        size,
                        signed: kind_flag,
                        values,
                    }
                }
            }

            Kind::Fwd => {
                no_vlen(&r)?;
                if size_or_type != 0 {
                    return Err(r.err(Reason::TypeNotZero));
                }
                named(&r)?;
                BtfType::Fwd {
                    name_off,
                    is_union: kind_flag,
                }
            }

            Kind::Func => {
                no_kflag(&r)?;
                named(&r)?;
                let linkage = match vlen {
                    0 => FuncLinkage::Static,
                    1 => FuncLinkage::Global,
                    // `BTF_FUNC_EXTERN` (2) exists in the uapi header but
                    // Linux rejects it here: an extern function has no body
                    // to attach to, and libbpf rewrites it before load.
                    _ => return Err(r.err(Reason::FuncLinkageInvalid)),
                };
                BtfType::Func {
                    name_off,
                    linkage,
                    proto: type_ref(&r, size_or_type, false)?,
                }
            }

            Kind::FuncProto => {
                no_kflag(&r)?;
                anonymous(&r)?;
                let ret_type = type_ref(&r, size_or_type, true)?;
                let mut params = Vec::new();
                for _ in 0..vlen {
                    let p_name = r.u32()?;
                    let p_type = r.u32()?;
                    if !name_off_valid(p_name) {
                        return Err(r.err(Reason::InvalidNameOffset));
                    }
                    if p_name != 0 && !name_is_valid_identifier(strings, p_name) {
                        return Err(r.err(Reason::InvalidName));
                    }
                    if p_type > MAX_TYPE_ID {
                        return Err(r.err(Reason::InvalidTypeId));
                    }
                    params.push(Param {
                        name_off: p_name,
                        type_id: p_type,
                    });
                }
                BtfType::FuncProto { ret_type, params }
            }

            Kind::Var => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                named(&r)?;
                let type_id = type_ref(&r, size_or_type, false)?;
                let linkage = match r.u32()? {
                    0 => VarLinkage::Static,
                    1 => VarLinkage::GlobalAllocated,
                    // `BTF_VAR_GLOBAL_EXTERN` (2) and anything above it.
                    _ => return Err(r.err(Reason::VarLinkageUnsupported)),
                };
                BtfType::Var {
                    name_off,
                    type_id,
                    linkage,
                }
            }

            Kind::DataSec => {
                no_kflag(&r)?;
                let size = size_or_type;
                if size == 0 {
                    return Err(r.err(Reason::DatasecSizeZero));
                }
                if vlen == 0 {
                    return Err(r.err(Reason::DatasecVlenZero));
                }
                named(&r)?;
                let mut vars = Vec::new();
                // Members must tile the section in ascending order without
                // overlapping. `last_end` is u64 so `offset + size` cannot
                // wrap into a passing value.
                let mut last_end: u64 = 0;
                let mut sum: u64 = 0;
                for _ in 0..vlen {
                    let v_type = r.u32()?;
                    let v_off = r.u32()?;
                    let v_size = r.u32()?;
                    let v_type = type_ref(&r, v_type, false)?;
                    if u64::from(v_off) < last_end || v_off >= size {
                        return Err(r.err(Reason::DatasecOffsetInvalid));
                    }
                    if v_size == 0 || v_size > size {
                        return Err(r.err(Reason::DatasecSizeInvalid));
                    }
                    last_end = u64::from(v_off) + u64::from(v_size);
                    if last_end > u64::from(size) {
                        return Err(r.err(Reason::DatasecOffsetSizeInvalid));
                    }
                    sum += u64::from(v_size);
                    vars.push(SecInfo {
                        type_id: v_type,
                        offset: v_off,
                        size: v_size,
                    });
                }
                if u64::from(size) < sum {
                    return Err(r.err(Reason::DatasecSumExceedsSize));
                }
                BtfType::DataSec {
                    name_off,
                    size,
                    vars,
                }
            }

            Kind::Float => {
                no_vlen(&r)?;
                no_kflag(&r)?;
                // No charset check on the name, deliberately, and the same
                // goes for `INT` above: `long double` and
                // `long long unsigned int` are the names clang emits, and
                // neither is an identifier. Linux does not check them either.
                if !name_off_valid(name_off) {
                    return Err(r.err(Reason::InvalidNameOffset));
                }
                if !matches!(size_or_type, 2 | 4 | 8 | 12 | 16) {
                    return Err(r.err(Reason::FloatSizeInvalid));
                }
                BtfType::Float {
                    name_off,
                    size: size_or_type,
                }
            }

            Kind::DeclTag => {
                no_vlen(&r)?;
                // The tag's *value* is its name, so it must be present, but
                // it is free-form text and not an identifier.
                if name_bytes(strings, name_off).is_none_or(<[u8]>::is_empty) {
                    return Err(r.err(Reason::InvalidName));
                }
                let type_id = type_ref(&r, size_or_type, false)?;
                let component_idx = r.i32()?;
                if component_idx < -1 {
                    return Err(r.err(Reason::DeclTagComponentIdxInvalid));
                }
                BtfType::DeclTag {
                    name_off,
                    type_id,
                    component_idx,
                }
            }
        };

        out.push(decoded);
    }

    if out.is_empty() {
        return Err(BtfError::global(Reason::NoTypes));
    }
    Ok(out)
}
