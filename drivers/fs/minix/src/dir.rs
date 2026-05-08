//! MINIX directory entry decoding.
//!
//! Clean-room. Tanenbaum *Operating Systems: Design and
//! Implementation* (1st ed., Ch. 5) defines the directory entry as
//! a packed `(u16 d_ino, char d_name[N])` record where N is 14 or
//! 30 depending on the magic; MINIX 3 raises N to 60.
//!
//! Names are NUL-terminated within the fixed name field. A zero
//! `d_ino` marks an unused slot — the directory must be scanned
//! to its `i_size` regardless (do not stop at the first zero).

use alloc::string::String;

use super::NameLen;

/// Decoded directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub ino: u16,
    pub name: String,
}

impl DirEntry {
    /// Decode one entry from `buf[offset..]`. Returns `None` if the
    /// slot has no inode assigned (`d_ino == 0`).
    pub fn decode(name_len: NameLen, buf: &[u8], offset: usize) -> Option<Self> {
        let n = name_len.bytes();
        let total = name_len.entry_size();
        if offset + total > buf.len() {
            return None;
        }
        let ino = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        if ino == 0 {
            return None;
        }
        let name_bytes = &buf[offset + 2..offset + 2 + n];
        // Trim at first NUL.
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(n);
        // Lossy decode — MINIX names are bytes; we render printable
        // ASCII directly and replace non-UTF-8 bytes. This matches
        // the FAT driver's pragma for SFN bytes.
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        Some(Self { ino, name })
    }

    /// Decode every populated entry in `buf` (length must be a
    /// multiple of `name_len.entry_size()`).
    pub fn decode_all(name_len: NameLen, buf: &[u8]) -> alloc::vec::Vec<Self> {
        let entry_sz = name_len.entry_size();
        let mut out = alloc::vec::Vec::new();
        let mut off = 0;
        while off + entry_sz <= buf.len() {
            if let Some(e) = Self::decode(name_len, buf, off) {
                out.push(e);
            }
            off += entry_sz;
        }
        out
    }
}
