//! Host tests: `cargo test -p narf-kallsyms --features alloc`.

extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::encode::{encode, truncate_name, EncodeError, Symbol};
use crate::{Error, NameBuf, Table, BLOCK, MAX_NAME};

const TEXT: u64 = 0xFFFF_FFFF_9001_7000;

fn sym(off: u64, kind: u8, name: &str) -> Symbol {
    Symbol {
        addr: TEXT + off,
        kind,
        name: name.to_string(),
    }
}

/// Every symbol of a table, decoded, in table order.
fn decode_all(t: &Table<'_>) -> Vec<(u32, u8, String)> {
    let mut buf = NameBuf::new();
    t.iter()
        .map(|e| {
            t.name(e.name_index, &mut buf).expect("name decodes");
            (e.offset, e.kind, buf.as_str().unwrap().to_string())
        })
        .collect()
}

/// Deterministic xorshift, so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A Rust-looking symbol set: long shared module paths, generics,
/// duplicates (monomorphisations), data symbols.
fn rusty(n: usize, seed: u64) -> Vec<Symbol> {
    let crates = [
        "narf_filesystem",
        "narf_drivers_wireless_rtw",
        "narf_userspace",
        "core",
        "alloc",
    ];
    let mods = [
        "procfs",
        "rtw88::firmware_transport",
        "handlers",
        "ptr",
        "fmt",
    ];
    let items = [
        "read",
        "write",
        "drop_in_place<narf::X>",
        "fmt",
        "poll",
        "new",
    ];
    let kinds = [b't', b'T', b'r', b'R', b'd', b'D', b'b', b'B'];
    let mut rng = Rng(seed);
    let mut out = Vec::new();
    let mut addr = 0u64;
    for i in 0..n {
        let name = format!(
            "{}::{}::{}{}",
            crates[rng.below(crates.len() as u64) as usize],
            mods[rng.below(mods.len() as u64) as usize],
            items[rng.below(items.len() as u64) as usize],
            if rng.below(3) == 0 {
                String::new()
            } else {
                format!("_{}", i % 97)
            }
        );
        out.push(Symbol {
            addr: TEXT + addr,
            kind: kinds[rng.below(kinds.len() as u64) as usize],
            name,
        });
        // Some aliases (same address).
        if rng.below(5) != 0 {
            addr += 1 + rng.below(0x400);
        }
    }
    out
}

#[test]
fn round_trip_preserves_every_symbol_in_address_order() {
    let input = rusty(5000, 1);
    let (blob, stats) = encode(TEXT, input.clone()).unwrap();
    let t = Table::parse(&blob).unwrap();
    assert_eq!(t.len(), input.len());
    assert_eq!(t.text_link(), TEXT);
    assert_eq!(stats.total, blob.len());

    let got = decode_all(&t);
    // Same multiset of (address, type, name).
    let mut want: Vec<(u32, u8, String)> = input
        .iter()
        .map(|s| ((s.addr - TEXT) as u32, s.kind, s.name.clone()))
        .collect();
    let mut sorted_got = got.clone();
    want.sort();
    sorted_got.sort();
    assert_eq!(want, sorted_got);
    // And in ascending address order.
    assert!(got.windows(2).all(|w| w[0].0 <= w[1].0));
}

#[test]
fn duplicate_names_share_one_entry() {
    let input = vec![
        sym(0x10, b't', "core::ptr::drop_in_place"),
        sym(0x20, b't', "core::ptr::drop_in_place"),
        sym(0x30, b't', "core::ptr::drop_in_place"),
        sym(0x40, b'T', "_text_other"),
    ];
    let (blob, stats) = encode(TEXT, input).unwrap();
    let t = Table::parse(&blob).unwrap();
    assert_eq!(t.len(), 4);
    assert_eq!(t.num_names(), 2);
    assert_eq!(stats.names, 2);
    let e: Vec<u32> = t.iter().map(|e| e.name_index).collect();
    assert_eq!(e[0], e[1]);
    assert_eq!(e[1], e[2]);
    assert_ne!(e[2], e[3]);
}

#[test]
fn aliases_sort_like_linux_compare_symbols() {
    // Same address: non-weak before weak, real before linker-script bounds,
    // fewer leading underscores first, then input order.
    let input = vec![
        sym(0, b'T', "__text_start"),
        sym(0, b'W', "weak_alias"),
        sym(0, b'T', "_text"),
        sym(0, b'T', "_stext"),
        sym(0, b'T', "startup"),
    ];
    let (blob, _) = encode(TEXT, input).unwrap();
    let t = Table::parse(&blob).unwrap();
    let names: Vec<String> = decode_all(&t).into_iter().map(|(_, _, n)| n).collect();
    assert_eq!(
        names,
        ["startup", "_text", "_stext", "__text_start", "weak_alias"]
    );
}

#[test]
fn names_across_block_boundaries_and_at_max_length() {
    let mut input = Vec::new();
    let long = "x".repeat(MAX_NAME);
    input.push(sym(0, b't', &long));
    let mut almost = "x".repeat(MAX_NAME - 1);
    almost.push('y');
    input.push(sym(1, b't', &almost));
    // Many names sharing long prefixes, spanning several blocks.
    for i in 0..(BLOCK * 5 + 3) {
        input.push(sym(
            2 + i as u64,
            b't',
            &format!("narf_drivers_wireless_rtw::rtw88::firmware_transport::f{i:04}"),
        ));
    }
    input.push(sym(1000, b't', "a"));
    let (blob, _) = encode(TEXT, input.clone()).unwrap();
    let t = Table::parse(&blob).unwrap();
    let got = decode_all(&t);
    for s in &input {
        assert!(
            got.iter()
                .any(|(o, _, n)| *o as u64 == s.addr - TEXT && n == &s.name),
            "missing {}",
            s.name
        );
    }
}

#[test]
fn front_coding_and_tokens_compress_rust_paths() {
    let input = rusty(20_000, 7);
    let (_, stats) = encode(TEXT, input).unwrap();
    assert!(stats.tokens > 0);
    // The stream must be far smaller than the raw names it replaces.
    assert!(
        stats.name_stream_bytes * 4 < stats.raw_name_bytes,
        "stream {} vs raw {}",
        stats.name_stream_bytes,
        stats.raw_name_bytes
    );
}

#[test]
fn encoding_is_deterministic() {
    let a = encode(TEXT, rusty(3000, 3)).unwrap().0;
    let b = encode(TEXT, rusty(3000, 3)).unwrap().0;
    assert_eq!(a, b);
}

#[test]
fn rejects_what_it_cannot_represent() {
    assert!(matches!(
        encode(
            TEXT,
            vec![Symbol {
                addr: TEXT - 1,
                kind: b't',
                name: "low".into()
            }]
        ),
        Err(EncodeError::BelowText { .. })
    ));
    // (A low base: `TEXT + 4 GiB` would not fit a u64.)
    assert!(matches!(
        encode(
            0x1000,
            vec![Symbol {
                addr: 0x1000 + (1 << 32),
                kind: b't',
                name: "far".into()
            }]
        ),
        Err(EncodeError::OffsetTooLarge { .. })
    ));
    assert!(matches!(
        encode(TEXT, vec![sym(0, b't', "")]),
        Err(EncodeError::EmptyName { .. })
    ));
    assert!(matches!(
        encode(TEXT, vec![sym(0, b't', &"y".repeat(MAX_NAME + 1))]),
        Err(EncodeError::NameTooLong { .. })
    ));
    assert!(matches!(
        encode(TEXT, vec![sym(0, b'?', "q")]),
        Err(EncodeError::BadKind { .. })
    ));
}

#[test]
fn truncate_name_cuts_on_a_char_boundary() {
    assert_eq!(truncate_name("short"), "short");
    let ascii = "a".repeat(MAX_NAME + 40);
    assert_eq!(truncate_name(&ascii).len(), MAX_NAME);
    // A two-byte char straddling the limit is dropped whole.
    let mut s = "a".repeat(MAX_NAME - 1);
    s.push('é');
    s.push_str("tail");
    let t = truncate_name(&s);
    assert_eq!(t.len(), MAX_NAME - 1);
    assert!(t.is_char_boundary(t.len()));
}

#[test]
fn lookup_resolves_to_the_first_alias_and_reports_size() {
    let input = vec![
        sym(0x100, b'T', "alpha"),
        sym(0x100, b't', "alpha_alias"),
        sym(0x180, b'T', "beta"),
        sym(0x400, b'D', "gamma"),
    ];
    let (blob, _) = encode(TEXT, input).unwrap();
    let t = Table::parse(&blob).unwrap();
    let mut buf = NameBuf::new();

    assert!(t.lookup(0xFF).is_none());
    let (e, size) = t.lookup(0x17F).unwrap();
    t.name(e.name_index, &mut buf).unwrap();
    assert_eq!(buf.as_str(), Some("alpha"));
    assert_eq!(e.offset, 0x100);
    assert_eq!(size, Some(0x80));

    let (e, size) = t.lookup(0x180).unwrap();
    t.name(e.name_index, &mut buf).unwrap();
    assert_eq!(buf.as_str(), Some("beta"));
    assert_eq!(size, Some(0x280));

    let (e, size) = t.lookup(0x1000).unwrap();
    t.name(e.name_index, &mut buf).unwrap();
    assert_eq!(buf.as_str(), Some("gamma"));
    assert_eq!(size, None);
    assert!(t.lookup(1 << 33).is_none());
}

#[test]
fn empty_and_unfilled_tables() {
    let (blob, _) = encode(TEXT, Vec::new()).unwrap();
    let t = Table::parse(&blob).unwrap();
    assert!(t.is_empty());
    assert!(t.lookup(0).is_none());
    // An unpatched reservation is zero-filled.
    assert_eq!(Table::parse(&[0u8; 4096]).unwrap_err(), Error::BadMagic);
    assert_eq!(Table::parse(&blob[..10]).unwrap_err(), Error::Truncated);
    // A reservation larger than the table parses: the header bounds it.
    let mut padded = blob.clone();
    padded.resize(blob.len() + 4096, 0);
    assert!(Table::parse(&padded).is_ok());
}

#[test]
fn corruption_never_panics() {
    let (blob, _) = encode(TEXT, rusty(600, 11)).unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut buf = NameBuf::new();
    for _ in 0..3000 {
        let mut b = blob.clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(b.len() as u64) as usize;
            b[at] = rng.next() as u8;
        }
        if rng.below(8) == 0 {
            let cut = rng.below(b.len() as u64) as usize;
            b.truncate(cut);
        }
        if let Ok(t) = Table::parse(&b) {
            for e in t.iter() {
                let _ = t.name(e.name_index, &mut buf);
            }
            for name in 0..t.num_names() as u32 + 2 {
                let _ = t.name(name, &mut buf);
            }
            let _ = t.lookup(rng.below(0x10_0000));
        }
    }
}

/// `scripts/kallsyms.c`'s algorithm verbatim — a full rescan per token — as
/// the reference the indexed implementation must match byte for byte.
fn linux_reference_compress(strs: &mut [Vec<u8>]) -> Vec<Vec<u8>> {
    let mut table: Vec<Vec<u8>> = vec![Vec::new(); 256];
    for s in strs.iter() {
        for &c in s {
            table[c as usize] = vec![c];
        }
    }
    for code in (0..256).rev() {
        if !table[code].is_empty() {
            continue;
        }
        let mut profit = vec![0i64; 1 << 16];
        for s in strs.iter() {
            for w in s.windows(2) {
                profit[w[0] as usize | (w[1] as usize) << 8] += 1;
            }
        }
        let (mut best, mut bp) = (0, i64::MIN);
        for (p, &v) in profit.iter().enumerate() {
            if v > bp {
                best = p;
                bp = v;
            }
        }
        if bp <= 0 {
            break;
        }
        let (a, b) = ((best & 0xFF) as u8, (best >> 8) as u8);
        let mut e = table[a as usize].clone();
        e.extend_from_slice(&table[b as usize]);
        table[code] = e;
        for s in strs.iter_mut() {
            let mut out = Vec::new();
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
        }
    }
    table
}

#[test]
fn indexed_compression_matches_the_linux_algorithm() {
    let input = rusty(2500, 5);
    let mut strs: Vec<Vec<u8>> = input.iter().map(|s| s.name.as_bytes().to_vec()).collect();
    let mut reference = strs.clone();
    let (tokens, _) = crate::encode::compress_for_test(&mut strs);
    let ref_tokens = linux_reference_compress(&mut reference);
    assert_eq!(tokens, ref_tokens);
    assert_eq!(strs, reference);
}
