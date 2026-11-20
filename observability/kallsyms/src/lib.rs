//! Compact kernel symbol table — the bytes `xtask` writes into the image's
//! `.kallsyms` reservation after linking, and the allocation-free decoder the
//! kernel reads them back with for `/proc/kallsyms`.
//!
//! Linux reference: `scripts/kallsyms.c` (generator) and `kernel/kallsyms.c`
//! (decoder). The shape is the same — addresses stored as 32-bit offsets from
//! `_text`, names compressed with a 256-entry best-pair token table, markers
//! for random access — with two changes driven by Rust's symbol names:
//!
//! * **Names are deduplicated.** Monomorphisation gives many symbols the same
//!   demangled name (the x86_64 test image has ~384k symbols and ~89k
//!   distinct names), so each symbol carries a 24-bit index into a table of unique
//!   names instead of its own copy, as Linux's `kallsyms_seqs_of_names` does
//!   for the reverse lookup.
//! * **Unique names are front-coded.** They are stored sorted, and each name
//!   in a block of [`BLOCK`] records only how many leading bytes it shares
//!   with its predecessor. Rust paths (`narf_drivers_wireless_rtw::rtw88::…`)
//!   share long prefixes, which a 256-token table alone cannot capture.
//!
//! Addresses are relative to the link-time `_text`, so the table holds no
//! absolute address and needs no KASLR relocation: the runtime address of a
//! symbol is the runtime `_text` plus its offset, exactly as Linux's
//! `kallsyms_sym_address` adds `kallsyms_relative_base`.
//!
//! # Layout (little-endian, no alignment requirement)
//!
//! ```text
//! header        HEADER_LEN bytes (field offsets below)
//! offsets       u32 × num_syms        symbol address − _text, ascending
//! types         u8  × num_syms        nm(1) type letter
//! name_index    u24 × num_syms        index into the unique-name table
//! markers       u32 × ⌈num_names/BLOCK⌉  byte offset of each block in `names`
//! names         per unique name: uleb(prefix) uleb(ntok) token-code × ntok
//! token_index   u32 × 257             token c = token_bytes[idx[c]..idx[c+1]]
//! token_bytes   expanded token strings
//! ```
//!
//! The decoder never trusts the bytes: every read is bounds-checked and a
//! malformed table yields [`Error::Malformed`], never a panic, so a corrupt
//! or stale reservation cannot take the kernel down through a `/proc` read.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

// The encoder is host-only (`alloc` feature); unit tests always build it so
// `cargo test -p narf-kallsyms` covers the round trip without extra flags.
#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

#[cfg(any(test, feature = "alloc"))]
pub mod encode;

/// Header magic, `"KSYM"`. An unfilled reservation is all zeroes, so a table
/// that was never patched in is told apart from one that was.
pub const MAGIC: u32 = u32::from_le_bytes(*b"KSYM");

/// Format version. Bumped on any layout change; the decoder refuses others.
pub const VERSION: u16 = 1;

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 64;

/// Linux `KSYM_NAME_LEN` (`include/linux/kallsyms.h`): names are at most
/// `KSYM_NAME_LEN - 1` bytes. perf's `kallsyms__parse` reads into a
/// `KSYM_NAME_LEN + 1` buffer, so a longer line would be split mid-name.
pub const KSYM_NAME_LEN: usize = 512;

/// Longest name the table stores, in bytes.
pub const MAX_NAME: usize = KSYM_NAME_LEN - 1;

/// Unique names per front-coding block. Decoding a name decodes at most this
/// many names from its block's marker; 16 keeps a full `/proc/kallsyms` pass
/// cheap while leaving most of the prefix sharing in place.
pub const BLOCK: usize = 16;

/// Token codes. Every byte value is a code; the ones no name uses as a
/// literal are free to stand for a token.
pub const TOKENS: usize = 256;

/// Largest unique-name count a 24-bit name index can address.
pub const MAX_NAMES: usize = 1 << 24;

// Header field offsets.
const H_MAGIC: usize = 0;
const H_VERSION: usize = 4;
const H_HEADER_LEN: usize = 6;
const H_NUM_SYMS: usize = 8;
const H_NUM_NAMES: usize = 12;
const H_TEXT_LINK: usize = 16;
const H_OFFSETS: usize = 24;
const H_TYPES: usize = 28;
const H_NAME_INDEX: usize = 32;
const H_MARKERS: usize = 36;
const H_NAMES: usize = 40;
const H_NAMES_LEN: usize = 44;
const H_TOKEN_INDEX: usize = 48;
const H_TOKEN_BYTES: usize = 52;
const H_TOKEN_BYTES_LEN: usize = 56;
const H_TOTAL_LEN: usize = 60;

/// Why a table could not be read.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The blob is shorter than its header or than a region it declares.
    Truncated,
    /// No table: the reservation was never filled in (all zero), or holds
    /// something else.
    BadMagic,
    /// A table in a format version this decoder does not read.
    BadVersion,
    /// The bytes violate the format: unsorted offsets, an out-of-range index,
    /// a token that expands past [`MAX_NAME`], and so on.
    Malformed,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u24_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(3)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], 0]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut v = [0u8; 8];
    v.copy_from_slice(s);
    Some(u64::from_le_bytes(v))
}

/// Unsigned LEB128, at most two bytes (every value the format stores is
/// below [`KSYM_NAME_LEN`]).
fn uleb_at(b: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *b.get(*pos)?;
    *pos += 1;
    if first & 0x80 == 0 {
        return Some(first as usize);
    }
    let second = *b.get(*pos)?;
    *pos += 1;
    if second & 0x80 != 0 {
        return None;
    }
    Some((first & 0x7F) as usize | ((second as usize) << 7))
}

/// A region `[start, start + len)` of the blob.
#[derive(Copy, Clone, Debug)]
struct Region {
    start: usize,
    len: usize,
}

impl Region {
    fn read(blob: &[u8], at: usize, len: usize) -> Result<Self, Error> {
        let start = u32_at(blob, at).ok_or(Error::Truncated)? as usize;
        let end = start.checked_add(len).ok_or(Error::Malformed)?;
        if start < HEADER_LEN || end > blob.len() {
            return Err(Error::Truncated);
        }
        Ok(Region { start, len })
    }

    fn slice<'a>(&self, blob: &'a [u8]) -> &'a [u8] {
        // In bounds: checked when the region was read.
        &blob[self.start..self.start + self.len]
    }
}

/// A parsed, bounds-validated symbol table borrowing its bytes.
#[derive(Copy, Clone)]
pub struct Table<'a> {
    offsets: &'a [u8],
    types: &'a [u8],
    name_index: &'a [u8],
    markers: &'a [u8],
    names: &'a [u8],
    token_index: &'a [u8],
    token_bytes: &'a [u8],
    num_syms: usize,
    num_names: usize,
    text_link: u64,
}

impl core::fmt::Debug for Table<'_> {
    // Counts, not the megabytes of table bytes a derived impl would print.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Table")
            .field("num_syms", &self.num_syms)
            .field("num_names", &self.num_names)
            .field("text_link", &format_args!("{:#x}", self.text_link))
            .finish_non_exhaustive()
    }
}

/// One symbol in address order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Position in address order.
    pub index: usize,
    /// Address minus `_text`.
    pub offset: u32,
    /// nm(1) type letter (`T`, `t`, `D`, `r`, …).
    pub kind: u8,
    /// Index into the unique-name table; decode with [`Table::name`].
    pub name_index: u32,
}

/// Caller-owned buffer a name is decoded into. No name is longer than
/// [`MAX_NAME`] bytes, so decoding never allocates.
#[derive(Clone)]
pub struct NameBuf {
    buf: [u8; KSYM_NAME_LEN],
    len: usize,
}

impl Default for NameBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("NameBuf")
            .field(&core::str::from_utf8(self.as_bytes()).unwrap_or("<non-utf8>"))
            .finish()
    }
}

impl NameBuf {
    pub const fn new() -> Self {
        NameBuf {
            buf: [0; KSYM_NAME_LEN],
            len: 0,
        }
    }

    /// The decoded name.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The decoded name as UTF-8, if it is (every name the encoder accepts).
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

impl<'a> Table<'a> {
    /// Parse and validate a table. Every region must lie inside `blob`, the
    /// offsets must be ascending, every name index in range and every token
    /// well formed; only the name stream is checked lazily, as it is read.
    pub fn parse(blob: &'a [u8]) -> Result<Self, Error> {
        if blob.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let magic = u32_at(blob, H_MAGIC).ok_or(Error::Truncated)?;
        if magic != MAGIC {
            return Err(Error::BadMagic);
        }
        if u16_at(blob, H_VERSION) != Some(VERSION) {
            return Err(Error::BadVersion);
        }
        if u16_at(blob, H_HEADER_LEN).ok_or(Error::Truncated)? as usize != HEADER_LEN {
            return Err(Error::Malformed);
        }
        let total = u32_at(blob, H_TOTAL_LEN).ok_or(Error::Truncated)? as usize;
        if total < HEADER_LEN || total > blob.len() {
            return Err(Error::Truncated);
        }
        let blob = &blob[..total];

        let num_syms = u32_at(blob, H_NUM_SYMS).ok_or(Error::Truncated)? as usize;
        let num_names = u32_at(blob, H_NUM_NAMES).ok_or(Error::Truncated)? as usize;
        if num_names > MAX_NAMES || (num_names == 0 && num_syms != 0) {
            return Err(Error::Malformed);
        }
        let text_link = u64_at(blob, H_TEXT_LINK).ok_or(Error::Truncated)?;
        let blocks = num_names.div_ceil(BLOCK);
        let mul = |n: usize, w: usize| n.checked_mul(w).ok_or(Error::Malformed);

        let offsets = Region::read(blob, H_OFFSETS, mul(num_syms, 4)?)?.slice(blob);
        let types = Region::read(blob, H_TYPES, num_syms)?.slice(blob);
        let name_index = Region::read(blob, H_NAME_INDEX, mul(num_syms, 3)?)?.slice(blob);
        let markers = Region::read(blob, H_MARKERS, mul(blocks, 4)?)?.slice(blob);
        let names_len = u32_at(blob, H_NAMES_LEN).ok_or(Error::Truncated)? as usize;
        let names = Region::read(blob, H_NAMES, names_len)?.slice(blob);
        let token_index = Region::read(blob, H_TOKEN_INDEX, (TOKENS + 1) * 4)?.slice(blob);
        let token_bytes_len = u32_at(blob, H_TOKEN_BYTES_LEN).ok_or(Error::Truncated)? as usize;
        let token_bytes = Region::read(blob, H_TOKEN_BYTES, token_bytes_len)?.slice(blob);

        let table = Table {
            offsets,
            types,
            name_index,
            markers,
            names,
            token_index,
            token_bytes,
            num_syms,
            num_names,
            text_link,
        };

        // Token index: monotonic, inside the token bytes, no token longer
        // than a name can be.
        let mut prev = 0u32;
        for c in 0..=TOKENS {
            let at = u32_at(token_index, c * 4).ok_or(Error::Truncated)?;
            if at < prev || at as usize > token_bytes.len() {
                return Err(Error::Malformed);
            }
            if c > 0 && (at - prev) as usize > MAX_NAME {
                return Err(Error::Malformed);
            }
            prev = at;
        }
        // Markers inside the name stream, ascending.
        let mut prev = 0u32;
        for b in 0..blocks {
            let at = u32_at(markers, b * 4).ok_or(Error::Truncated)?;
            if at < prev || at as usize > names.len() {
                return Err(Error::Malformed);
            }
            prev = at;
        }
        // Symbols: ascending offsets (address order is the `/proc/kallsyms`
        // order and what `lookup` bisects), valid type letters, name indices
        // in range.
        let mut prev = 0u32;
        for (i, kind) in types.iter().enumerate() {
            let off = u32_at(offsets, i * 4).ok_or(Error::Truncated)?;
            if off < prev || !kind.is_ascii_alphabetic() {
                return Err(Error::Malformed);
            }
            if u24_at(name_index, i * 3).ok_or(Error::Truncated)? as usize >= num_names {
                return Err(Error::Malformed);
            }
            prev = off;
        }
        Ok(table)
    }

    /// Number of symbols.
    pub fn len(&self) -> usize {
        self.num_syms
    }

    /// `true` when the table holds no symbols.
    pub fn is_empty(&self) -> bool {
        self.num_syms == 0
    }

    /// Number of distinct names.
    pub fn num_names(&self) -> usize {
        self.num_names
    }

    /// Link-time address of `_text`, the base every offset is relative to.
    /// The runtime base is this plus the KASLR slide.
    pub fn text_link(&self) -> u64 {
        self.text_link
    }

    /// Symbol `index` in address order, or `None` past the end.
    pub fn entry(&self, index: usize) -> Option<Entry> {
        if index >= self.num_syms {
            return None;
        }
        Some(Entry {
            index,
            offset: u32_at(self.offsets, index * 4)?,
            kind: *self.types.get(index)?,
            name_index: u24_at(self.name_index, index * 3)?,
        })
    }

    /// Every symbol, in address order.
    pub fn iter(&self) -> impl Iterator<Item = Entry> + '_ {
        (0..self.num_syms).filter_map(move |i| self.entry(i))
    }

    fn token(&self, code: u8) -> Option<&'a [u8]> {
        let c = code as usize;
        let start = u32_at(self.token_index, c * 4)? as usize;
        let end = u32_at(self.token_index, (c + 1) * 4)? as usize;
        let tok = self.token_bytes.get(start..end)?;
        // An empty token is a code no name uses: referencing it is corrupt.
        if tok.is_empty() {
            None
        } else {
            Some(tok)
        }
    }

    /// Decode unique name `name_index` into `out`.
    pub fn name(&self, name_index: u32, out: &mut NameBuf) -> Result<(), Error> {
        let n = name_index as usize;
        if n >= self.num_names {
            return Err(Error::Malformed);
        }
        let block = n / BLOCK;
        let mut pos = u32_at(self.markers, block * 4).ok_or(Error::Malformed)? as usize;
        out.len = 0;
        for k in block * BLOCK..=n {
            let prefix = uleb_at(self.names, &mut pos).ok_or(Error::Malformed)?;
            let ntok = uleb_at(self.names, &mut pos).ok_or(Error::Malformed)?;
            // A block's first name stands alone; the rest extend a prefix of
            // their predecessor and so can never claim more than it had.
            if prefix > out.len || (k == block * BLOCK && prefix != 0) {
                return Err(Error::Malformed);
            }
            out.len = prefix;
            let codes = self
                .names
                .get(pos..pos.checked_add(ntok).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            pos += ntok;
            for &code in codes {
                let tok = self.token(code).ok_or(Error::Malformed)?;
                let end = out.len + tok.len();
                if end > MAX_NAME {
                    return Err(Error::Malformed);
                }
                out.buf[out.len..end].copy_from_slice(tok);
                out.len = end;
            }
        }
        if out.len == 0 {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The symbol covering `offset` (an address minus `_text`): the last one
    /// at or below it, moved back to the first alias at that address, as
    /// Linux's `get_symbol_pos` does. Returns the symbol and its size — the
    /// distance to the next higher address, or `None` for the last symbol.
    pub fn lookup(&self, offset: u64) -> Option<(Entry, Option<u32>)> {
        if self.num_syms == 0 || offset > u32::MAX as u64 {
            return None;
        }
        let target = offset as u32;
        let first = self.entry(0)?;
        if target < first.offset {
            return None;
        }
        // Largest i with offsets[i] <= target.
        let (mut lo, mut hi) = (0usize, self.num_syms);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.entry(mid)?.offset <= target {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let at = self.entry(lo)?.offset;
        let mut i = lo;
        while i > 0 && self.entry(i - 1)?.offset == at {
            i -= 1;
        }
        // `lo` is the last symbol at or below the target, so the next one
        // (if any) is strictly above it.
        let size = self.entry(lo + 1).map(|e| e.offset - at);
        Some((self.entry(i)?, size))
    }
}

#[cfg(test)]
mod tests;
