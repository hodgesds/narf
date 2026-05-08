//! ext2 directory entry layout + walker helpers.
//!
//! Sources:
//! - Card, Ts'o, Tweedie, §"Directories".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Directories".
//! - OSDev Wiki, "Ext2 — Directory Entry":
//!   <https://wiki.osdev.org/Ext2#Directory_Entry>
//!
//! No GPL/LGPL source was consulted.

/// Variable-length on-disk directory entry. Each record begins on a
/// 4-byte boundary; `rec_len` is what advances the cursor.
#[derive(Debug, Clone)]
pub struct DirEntry<'a> {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name: &'a [u8],
}

/// File-type byte values per OSDev Wiki "Ext2 — Directory Entry,
/// File Type Indicator". The 0 value means "unknown" and is what
/// rev-0 volumes report (since `file_type` overlaps the high byte of
/// the rev-0 `name_len`).
pub mod ftype {
    pub const UNKNOWN: u8 = 0;
    pub const REGULAR: u8 = 1;
    pub const DIR: u8 = 2;
    pub const SYMLINK: u8 = 7;
}

/// Parse the directory entry starting at `buf[off..]`. Returns
/// `None` if `off` falls outside the buffer or the record extends
/// past the end of the buffer.
pub fn parse_entry(buf: &[u8], off: usize) -> Option<DirEntry<'_>> {
    if off + 8 > buf.len() {
        return None;
    }
    let inode = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    let rec_len = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
    let name_len = buf[off + 6];
    let file_type = buf[off + 7];

    if rec_len < 8 {
        return None;
    }
    let name_end = off + 8 + name_len as usize;
    let rec_end = off + rec_len as usize;
    if name_end > buf.len() || rec_end > buf.len() {
        return None;
    }
    if name_end > rec_end {
        return None;
    }
    Some(DirEntry {
        inode,
        rec_len,
        name_len,
        file_type,
        name: &buf[off + 8..name_end],
    })
}

/// Walk every entry in a directory's data buffer, calling `f` for
/// each. Stops when `f` returns `false` or the buffer is exhausted.
/// Skips entries whose `inode` field is 0 (a "deleted" slot).
pub fn for_each_entry<F: FnMut(&DirEntry<'_>) -> bool>(buf: &[u8], mut f: F) {
    let mut off = 0usize;
    while off + 8 <= buf.len() {
        let entry = match parse_entry(buf, off) {
            Some(e) => e,
            None => return,
        };
        if entry.rec_len < 8 {
            return;
        }
        let advance = entry.rec_len as usize;
        if entry.inode != 0 && entry.name_len > 0 && !f(&entry) {
            return;
        }
        off += advance;
    }
}
