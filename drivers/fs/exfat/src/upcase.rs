//! exFAT Up-case Table.
//!
//! Clean-room. The up-case table is an array of u16 entries indexed
//! by input UTF-16 code unit; the value at each index is the
//! upper-cased form of that code unit. exFAT requires a per-volume
//! table because the Unicode case folding rules vary by volume
//! creation tool, so on-disk hashes (§7.6.8 NameHash) are only
//! reproducible by reading the volume's own table.
//!
//! References:
//! - exFAT file system specification (Microsoft, 2019),
//!   §7.2 Up-case Table Directory Entry.
//!   §7.2.5.1 RecommendedUpcaseTable — sample uncompressed table
//!     showing the value at each input code unit.
//!   §7.2.5.2 Compression — runs of N "identity" entries can be
//!     replaced by the magic value `0xFFFF` followed by a u16 run
//!     count (the omitted entries map each input → input).
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>

use alloc::vec;
use alloc::vec::Vec;

/// In-memory up-case table — `table[c as usize]` is the upper-case
/// form of code unit `c`. Constructed by decompressing the on-disk
/// stream (§7.2.5.2).
#[derive(Debug, Clone)]
pub struct UpcaseTable {
    table: Vec<u16>,
}

impl UpcaseTable {
    /// An ASCII-only fallback table used when no on-disk table has
    /// been loaded yet (e.g. early-mount, or the reduced table on a
    /// freshly formatted volume).
    pub fn ascii_fallback() -> Self {
        let mut table = vec![0u16; 0x10000];
        for i in 0..0x10000u32 {
            table[i as usize] = if (b'a'..=b'z').contains(&(i as u8)) && i < 0x80 {
                (i as u8 - b'a' + b'A') as u16
            } else {
                i as u16
            };
        }
        Self { table }
    }

    /// Decompress the on-disk up-case table per §7.2.5.2. The
    /// stream is a flat run of u16 values; whenever the value
    /// `0xFFFF` appears, the *next* u16 is a run count, and that
    /// many output positions are the identity (input == output).
    /// Returns an in-memory table sized to `0x10000` (one slot per
    /// possible u16 input).
    ///
    /// Spec NOTE on §7.2.5.2: only the *compressed* on-disk
    /// representation uses the `0xFFFF` escape. We don't validate
    /// the table's checksum against §7.2.3 — that's TODO for write
    /// (a read-only mount can't damage the table, and a malformed
    /// table just means wrong case folding).
    pub fn decompress(stream: &[u8]) -> Self {
        let mut table = vec![0u16; 0x10000];
        let mut i: usize = 0;
        let mut input_index: usize = 0;
        while i + 2 <= stream.len() && input_index < 0x10000 {
            let v = u16::from_le_bytes([stream[i], stream[i + 1]]);
            i += 2;
            if v == 0xFFFF && i + 2 <= stream.len() {
                let run = u16::from_le_bytes([stream[i], stream[i + 1]]) as usize;
                i += 2;
                let end = (input_index + run).min(0x10000);
                for j in input_index..end {
                    table[j] = j as u16;
                }
                input_index = end;
            } else {
                table[input_index] = v;
                input_index += 1;
            }
        }
        // Identity-fill any tail not described by the stream — a
        // truncated table just means "no folding for those code
        // units", which matches the spec's compression semantics.
        for j in input_index..0x10000 {
            table[j] = j as u16;
        }
        Self { table }
    }

    /// Upper-case a single UTF-16 code unit via lookup.
    pub fn upcase_char(&self, c: u16) -> u16 {
        self.table[c as usize]
    }

    /// Upper-case a UTF-16 string into a freshly allocated `Vec`.
    pub fn upcase(&self, s: &[u16]) -> Vec<u16> {
        s.iter().map(|&c| self.upcase_char(c)).collect()
    }

    /// Case-insensitive equality on two UTF-16 strings, both
    /// up-cased through this table per §7.4 lookup semantics.
    pub fn equal_ignoring_case(&self, a: &[u16], b: &[u16]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        for (x, y) in a.iter().zip(b.iter()) {
            if self.upcase_char(*x) != self.upcase_char(*y) {
                return false;
            }
        }
        true
    }
}

/// Up-case-table checksum per §7.2.3. Treats the on-disk stream as
/// a byte sequence and rotates-right then sums each byte:
///
///   checksum = ((checksum & 1) << 31) | (checksum >> 1);
///   checksum += byte;
///
/// The same algorithm appears in §7.1.4 for the volume-flags
/// checksum and is the canonical Microsoft 32-bit rotate-add. Used
/// both for verification on mount and for re-computation on write.
pub fn upcase_checksum(bytes: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &b in bytes {
        sum = ((sum & 1) << 31).wrapping_add(sum >> 1).wrapping_add(b as u32);
    }
    sum
}
