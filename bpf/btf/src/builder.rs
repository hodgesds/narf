//! A BTF blob builder, for tests only.
//!
//! Exists so that a negative test can say "a valid blob, but with the array's
//! element `type_id` set to 9999" instead of hand-editing a byte array and
//! hoping the offset is still right after the next edit. Every malformed case
//! in `tests.rs` is built by taking a well-formed blob and breaking exactly
//! one field.
//!
//! It is a *builder*, not a validator: it will happily emit garbage, which is
//! the point. It deliberately does **not** share code with the parser, so a
//! bug in the parser's offset arithmetic cannot be cancelled out by the same
//! bug in the fixture.

use alloc::vec::Vec;

/// Kind constants, spelled as raw numbers so the fixtures do not depend on the
/// parser's `Kind` enum being right.
pub(crate) const K_INT: u32 = 1;
pub(crate) const K_PTR: u32 = 2;
pub(crate) const K_ARRAY: u32 = 3;
pub(crate) const K_STRUCT: u32 = 4;
pub(crate) const K_UNION: u32 = 5;
pub(crate) const K_ENUM: u32 = 6;
pub(crate) const K_FWD: u32 = 7;
pub(crate) const K_TYPEDEF: u32 = 8;
pub(crate) const K_VOLATILE: u32 = 9;
pub(crate) const K_CONST: u32 = 10;
pub(crate) const K_RESTRICT: u32 = 11;
pub(crate) const K_FUNC: u32 = 12;
pub(crate) const K_FUNC_PROTO: u32 = 13;
pub(crate) const K_VAR: u32 = 14;
pub(crate) const K_DATASEC: u32 = 15;
pub(crate) const K_FLOAT: u32 = 16;
pub(crate) const K_DECL_TAG: u32 = 17;
pub(crate) const K_TYPE_TAG: u32 = 18;
pub(crate) const K_ENUM64: u32 = 19;

/// `btf_type::info` from its three fields.
pub(crate) const fn info(kind: u32, vlen: u32, kflag: bool) -> u32 {
    (kind << 24) | (vlen & 0xffff) | ((kflag as u32) << 31)
}

/// `BTF_KIND_INT`'s trailing word.
pub(crate) const fn int_data(encoding: u32, offset: u32, bits: u32) -> u32 {
    (encoding << 24) | (offset << 16) | bits
}

/// Assembles a type section and a string section into a blob.
#[derive(Default)]
pub(crate) struct Builder {
    types: Vec<u8>,
    strings: Vec<u8>,
    /// Byte offset within the type section of each record appended so far.
    /// Index `i` is `type_id` `i + 1`. Kept explicitly rather than derived
    /// from the section length, because trailing payloads make records
    /// variable-width.
    offsets: Vec<usize>,
    /// Overrides for the header fields, so a test can corrupt one.
    pub(crate) magic: Option<u16>,
    pub(crate) version: Option<u8>,
    pub(crate) flags: Option<u8>,
    pub(crate) hdr_len: Option<u32>,
    pub(crate) type_off: Option<u32>,
    pub(crate) type_len: Option<u32>,
    pub(crate) str_off: Option<u32>,
    pub(crate) str_len: Option<u32>,
    /// Extra bytes appended after the string section.
    pub(crate) trailer: Vec<u8>,
}

impl Builder {
    pub(crate) fn new() -> Self {
        // The string section must start with a NUL so that offset 0 is the
        // empty name.
        Self {
            strings: alloc::vec![0u8],
            ..Self::default()
        }
    }

    /// Intern a name and return its offset.
    pub(crate) fn name(&mut self, s: &str) -> u32 {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0);
        off
    }

    /// Append a raw `struct btf_type` and return the new type's id.
    pub(crate) fn ty(&mut self, name_off: u32, info: u32, size_or_type: u32) -> u32 {
        self.offsets.push(self.types.len());
        self.types.extend_from_slice(&name_off.to_le_bytes());
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size_or_type.to_le_bytes());
        self.offsets.len() as u32
    }

    /// Append a trailing `u32` to the type most recently appended.
    pub(crate) fn word(&mut self, v: u32) -> &mut Self {
        self.types.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A named `INT` of `bytes` bytes, unsigned, no bit offset.
    pub(crate) fn int(&mut self, name: &str, bytes: u32) -> u32 {
        let n = self.name(name);
        let id = self.ty(n, info(K_INT, 0, false), bytes);
        self.word(int_data(0, 0, bytes * 8));
        id
    }

    /// Serialise. `type_len`/`str_len`/offsets come from the actual sections
    /// unless a test overrode them.
    pub(crate) fn build(&self) -> Vec<u8> {
        let hdr_len = self.hdr_len.unwrap_or(24);
        let type_off = self.type_off.unwrap_or(0);
        let type_len = self.type_len.unwrap_or(self.types.len() as u32);
        let str_off = self.str_off.unwrap_or(self.types.len() as u32);
        let str_len = self.str_len.unwrap_or(self.strings.len() as u32);

        let mut out = Vec::new();
        out.extend_from_slice(&self.magic.unwrap_or(0xeb9f).to_le_bytes());
        out.push(self.version.unwrap_or(1));
        out.push(self.flags.unwrap_or(0));
        out.extend_from_slice(&hdr_len.to_le_bytes());
        out.extend_from_slice(&type_off.to_le_bytes());
        out.extend_from_slice(&type_len.to_le_bytes());
        out.extend_from_slice(&str_off.to_le_bytes());
        out.extend_from_slice(&str_len.to_le_bytes());
        // Pad or truncate to the declared header length.
        out.resize(hdr_len as usize, 0);
        out.extend_from_slice(&self.types);
        out.extend_from_slice(&self.strings);
        out.extend_from_slice(&self.trailer);
        out
    }

    /// Byte offset within the built blob of `type_id`'s `name_off` field —
    /// the start of its record. `+4` is `info`, `+8` is `size`/`type`, `+12`
    /// is the first trailing word.
    pub(crate) fn record_off(&self, type_id: u32) -> usize {
        let hdr_len = self.hdr_len.unwrap_or(24) as usize;
        let type_off = self.type_off.unwrap_or(0) as usize;
        hdr_len + type_off + self.offsets[type_id as usize - 1]
    }
}

/// Overwrite the `u32` at `off` in a blob.
pub(crate) fn poke(blob: &mut [u8], off: usize, v: u32) {
    blob[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
