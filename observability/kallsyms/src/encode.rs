//! Build-time encoder (host only, `alloc` feature).
//!
//! Linux reference: `scripts/kallsyms.c` — `sort_symbols`/`compare_symbols`
//! for the address order and its tie-breaks, and `optimize_token_table` for
//! the best-pair token compression. See the crate docs for what differs.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::{BLOCK, HEADER_LEN, MAGIC, MAX_NAME, MAX_NAMES, TOKENS, VERSION};

/// One symbol to encode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// Link-time address.
    pub addr: u64,
    /// nm(1) type letter.
    pub kind: u8,
    /// Display name, at most [`MAX_NAME`] bytes.
    pub name: String,
}

/// Why a symbol set cannot be encoded. Each is a build error: writing a
/// table that silently dropped or misplaced a symbol would make every
/// address after it resolve to the wrong function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A symbol below `_text`: offsets are unsigned.
    BelowText { name: String, addr: u64 },
    /// A symbol more than 4 GiB above `_text`.
    OffsetTooLarge { name: String, addr: u64 },
    /// An empty name.
    EmptyName { addr: u64 },
    /// A name longer than [`MAX_NAME`] bytes; the caller truncates first.
    NameTooLong { name: String },
    /// A type letter that is not ASCII alphabetic.
    BadKind { name: String, kind: u8 },
    /// More distinct names than a 24-bit index can address.
    TooManyNames(usize),
    /// A region past what a 32-bit offset can address.
    TooLarge,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::BelowText { name, addr } => {
                write!(f, "symbol {name} at {addr:#x} is below _text")
            }
            EncodeError::OffsetTooLarge { name, addr } => {
                write!(
                    f,
                    "symbol {name} at {addr:#x} is more than 4 GiB above _text"
                )
            }
            EncodeError::EmptyName { addr } => write!(f, "symbol at {addr:#x} has no name"),
            EncodeError::NameTooLong { name } => {
                write!(
                    f,
                    "symbol name is {} bytes (max {MAX_NAME}): {name}",
                    name.len()
                )
            }
            EncodeError::BadKind { name, kind } => {
                write!(f, "symbol {name} has type {kind:#x}, not an nm letter")
            }
            EncodeError::TooManyNames(n) => {
                write!(f, "{n} distinct names exceed the 24-bit name index")
            }
            EncodeError::TooLarge => write!(f, "table exceeds 4 GiB"),
        }
    }
}

/// Size accounting for the build log.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub symbols: usize,
    pub names: usize,
    /// Bytes of all symbol names, uncompressed and undeduplicated — what a
    /// plain `nm` listing of the same names would hold.
    pub raw_name_bytes: usize,
    /// Bytes of the compressed name stream.
    pub name_stream_bytes: usize,
    /// Token codes assigned to multi-byte tokens.
    pub tokens: usize,
    /// Encoded table size.
    pub total: usize,
}

/// `may_be_linker_script_provide_symbol` from `scripts/kallsyms.c`: names
/// that look like section bounds (`__start_*`, `__stop_*`, `__end_*`,
/// `__*_start`, `__*_end`) sort after a real symbol at the same address.
fn may_be_linker_script_provide_symbol(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() < 8 || !name.starts_with("__") {
        return false;
    }
    let rest = &name[2..];
    rest.starts_with("start_")
        || rest.starts_with("stop_")
        || rest.starts_with("end_")
        || name.ends_with("_start")
        || name.ends_with("_end")
}

/// The tie-break order of `compare_symbols`: address, then non-weak before
/// weak, then real symbols before linker-script bounds, then fewer leading
/// underscores first, then input order (the sort is stable).
fn sort_key(s: &Symbol) -> (u64, bool, bool, usize) {
    (
        s.addr,
        matches!(s.kind, b'w' | b'W'),
        may_be_linker_script_provide_symbol(&s.name),
        s.name.bytes().take_while(|&c| c == b'_').count(),
    )
}

fn push_uleb(out: &mut Vec<u8>, v: usize) {
    debug_assert!(v < 1 << 14);
    if v < 0x80 {
        out.push(v as u8);
    } else {
        out.push((v & 0x7F) as u8 | 0x80);
        out.push((v >> 7) as u8);
    }
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Best-pair token compression, `scripts/kallsyms.c::optimize_token_table`.
///
/// Every byte value a suffix uses stands for itself. The rest are handed out,
/// highest code first, to whichever adjacent code pair occurs most often,
/// and that pair is replaced everywhere; a pair may contain earlier tokens,
/// so a token can expand to a long string. Returns each code's expansion
/// (empty for an unused code) and rewrites `strs` in place.
///
/// Linux rescans every symbol for each new token. Here each pair keeps the
/// list of strings it occurs in, so a round only revisits the strings that
/// actually contain the chosen pair; the result is identical (same pair
/// choice, same left-to-right replacement), just without the full rescans
/// that make a 200k-symbol Rust image take minutes.
fn compress(strs: &mut [Vec<u8>]) -> (Vec<Vec<u8>>, usize) {
    let mut table: Vec<Vec<u8>> = vec![Vec::new(); TOKENS];
    for s in strs.iter() {
        for &c in s {
            table[c as usize] = vec![c];
        }
    }

    let pair = |a: u8, b: u8| a as usize | (b as usize) << 8;
    let mut profit = vec![0i64; 1 << 16];
    let mut occurs: Vec<Vec<u32>> = vec![Vec::new(); 1 << 16];
    for (i, s) in strs.iter().enumerate() {
        for w in s.windows(2) {
            let p = pair(w[0], w[1]);
            profit[p] += 1;
            if occurs[p].last() != Some(&(i as u32)) {
                occurs[p].push(i as u32);
            }
        }
    }

    // Visit stamp per string, so a string listed twice for one pair (stale
    // entries are never removed) is rewritten once per round.
    let mut seen = vec![u32::MAX; strs.len()];
    let mut assigned = 0;
    for code in (0..TOKENS).rev() {
        if !table[code].is_empty() {
            continue;
        }
        // First maximum in pair order, as `find_best_token` picks it.
        let mut best = 0usize;
        let mut best_profit = i64::MIN;
        for (p, &v) in profit.iter().enumerate() {
            if v > best_profit {
                best = p;
                best_profit = v;
            }
        }
        if best_profit <= 0 {
            break;
        }
        let (a, b) = ((best & 0xFF) as u8, (best >> 8) as u8);
        let mut expansion = table[a as usize].clone();
        expansion.extend_from_slice(&table[b as usize]);
        table[code] = expansion;
        assigned += 1;

        let list = core::mem::take(&mut occurs[best]);
        for &i in &list {
            let i = i as usize;
            if seen[i] == code as u32 {
                continue;
            }
            seen[i] = code as u32;
            let s = &mut strs[i];
            if !s.windows(2).any(|w| w[0] == a && w[1] == b) {
                continue;
            }
            // forget_symbol
            for w in s.windows(2) {
                profit[pair(w[0], w[1])] -= 1;
            }
            // Greedy left-to-right replacement, as `compress_symbols` does.
            let mut out = Vec::with_capacity(s.len());
            let mut k = 0;
            while k < s.len() {
                if k + 1 < s.len() && s[k] == a && s[k + 1] == b {
                    out.push(code as u8);
                    k += 2;
                } else {
                    out.push(s[k]);
                    k += 1;
                }
            }
            *s = out;
            // learn_symbol, and list the string under every pair that now
            // involves the new code (the others were listed already).
            for w in s.windows(2) {
                let p = pair(w[0], w[1]);
                profit[p] += 1;
                if (w[0] == code as u8 || w[1] == code as u8)
                    && occurs[p].last() != Some(&(i as u32))
                {
                    occurs[p].push(i as u32);
                }
            }
        }
    }
    (table, assigned)
}

#[cfg(test)]
pub(crate) fn compress_for_test(strs: &mut [Vec<u8>]) -> (Vec<Vec<u8>>, usize) {
    compress(strs)
}

/// Encode `symbols` relative to the link-time `_text` at `text_link`.
pub fn encode(text_link: u64, symbols: Vec<Symbol>) -> Result<(Vec<u8>, Stats), EncodeError> {
    let mut syms = symbols;
    for s in &syms {
        if s.name.is_empty() {
            return Err(EncodeError::EmptyName { addr: s.addr });
        }
        if s.name.len() > MAX_NAME {
            return Err(EncodeError::NameTooLong {
                name: s.name.clone(),
            });
        }
        if !s.kind.is_ascii_alphabetic() {
            return Err(EncodeError::BadKind {
                name: s.name.clone(),
                kind: s.kind,
            });
        }
        if s.addr < text_link {
            return Err(EncodeError::BelowText {
                name: s.name.clone(),
                addr: s.addr,
            });
        }
        if s.addr - text_link > u32::MAX as u64 {
            return Err(EncodeError::OffsetTooLarge {
                name: s.name.clone(),
                addr: s.addr,
            });
        }
    }
    syms.sort_by_key(sort_key);

    // Unique names, bytewise sorted.
    let mut names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    if names.len() > MAX_NAMES {
        return Err(EncodeError::TooManyNames(names.len()));
    }

    // Front coding: each name past a block's first records how much of its
    // predecessor it keeps; only the rest is token-compressed.
    let mut prefixes = Vec::with_capacity(names.len());
    let mut suffixes: Vec<Vec<u8>> = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let prefix = if i % BLOCK == 0 {
            0
        } else {
            common_prefix(names[i - 1].as_bytes(), name.as_bytes())
        };
        prefixes.push(prefix);
        suffixes.push(name.as_bytes()[prefix..].to_vec());
    }
    let (tokens, assigned) = compress(&mut suffixes);

    let mut stream = Vec::new();
    let mut markers = Vec::with_capacity(names.len().div_ceil(BLOCK));
    for (i, (prefix, suffix)) in prefixes.iter().zip(&suffixes).enumerate() {
        if i % BLOCK == 0 {
            markers.push(u32::try_from(stream.len()).map_err(|_| EncodeError::TooLarge)?);
        }
        push_uleb(&mut stream, *prefix);
        push_uleb(&mut stream, suffix.len());
        stream.extend_from_slice(suffix);
    }

    let mut token_index = Vec::with_capacity(TOKENS + 1);
    let mut token_bytes = Vec::new();
    for t in &tokens {
        token_index.push(token_bytes.len() as u32);
        token_bytes.extend_from_slice(t);
    }
    token_index.push(token_bytes.len() as u32);

    // Assemble.
    let n = syms.len();
    let offsets_at = HEADER_LEN;
    let types_at = offsets_at + n * 4;
    let name_index_at = types_at + n;
    let markers_at = name_index_at + n * 3;
    let names_at = markers_at + markers.len() * 4;
    let token_index_at = names_at + stream.len();
    let token_bytes_at = token_index_at + (TOKENS + 1) * 4;
    let total = token_bytes_at + token_bytes.len();
    let to32 = |v: usize| u32::try_from(v).map_err(|_| EncodeError::TooLarge);

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    out.extend_from_slice(&to32(n)?.to_le_bytes());
    out.extend_from_slice(&to32(names.len())?.to_le_bytes());
    out.extend_from_slice(&text_link.to_le_bytes());
    for v in [
        offsets_at,
        types_at,
        name_index_at,
        markers_at,
        names_at,
        stream.len(),
        token_index_at,
        token_bytes_at,
        token_bytes.len(),
        total,
    ] {
        out.extend_from_slice(&to32(v)?.to_le_bytes());
    }
    debug_assert_eq!(out.len(), HEADER_LEN);

    for s in &syms {
        out.extend_from_slice(&((s.addr - text_link) as u32).to_le_bytes());
    }
    for s in &syms {
        out.push(s.kind);
    }
    for s in &syms {
        // Present: `names` was built from these very strings.
        let idx = names.binary_search(&s.name.as_str()).unwrap_or(0) as u32;
        out.extend_from_slice(&idx.to_le_bytes()[..3]);
    }
    for m in &markers {
        out.extend_from_slice(&m.to_le_bytes());
    }
    out.extend_from_slice(&stream);
    for t in &token_index {
        out.extend_from_slice(&t.to_le_bytes());
    }
    out.extend_from_slice(&token_bytes);
    debug_assert_eq!(out.len(), total);

    let stats = Stats {
        symbols: n,
        names: names.len(),
        raw_name_bytes: syms.iter().map(|s| s.name.len()).sum(),
        name_stream_bytes: stream.len(),
        tokens: assigned,
        total,
    };
    Ok((out, stats))
}

/// Cut `name` to at most [`MAX_NAME`] bytes on a UTF-8 boundary.
///
/// Linux refuses such a symbol at build time (`read_symbol`'s
/// "too long for kallsyms"), which drops it from the table — and then every
/// address inside it resolves to whatever symbol precedes it. Truncating
/// keeps the address attributed to the right function under a recognisable
/// prefix of its name. Rust generic instantiations routinely exceed 511 bytes.
pub fn truncate_name(name: &str) -> &str {
    if name.len() <= MAX_NAME {
        return name;
    }
    let mut end = MAX_NAME;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}
