//! ext2 directory entry layout + walker helpers.
//!
//! Sources:
//! - Card, Ts'o, Tweedie, §"Directories".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Directories".
//! - OSDev Wiki, "Ext2 — Directory Entry":
//!   <https://wiki.osdev.org/Ext2#Directory_Entry>
//! - Linux `fs/ext2/dir.c` — `ext2_add_link` / `ext2_delete_entry` /
//!   `ext2_make_empty` consulted post-relicense (NARF is GPL-2.0+
//!   as of 2026-05-20) for the splice + coalesce algorithms.

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
    pub const CHRDEV: u8 = 3;
    pub const BLKDEV: u8 = 4;
    pub const FIFO: u8 = 5;
    pub const SOCK: u8 = 6;
    pub const SYMLINK: u8 = 7;
}

/// Minimum record length that fits a name of `name_len` bytes:
/// 8-byte header + name padded up to a 4-byte boundary.
///
/// Mirrors Linux `EXT2_DIR_REC_LEN(name_len)` in `ext2.h`:
/// `((name_len) + 8 + 3) & ~3`.
pub const fn rec_len_for(name_len: u8) -> u16 {
    let raw = (name_len as u16) + 8;
    (raw + 3) & !3
}

/// In-place mutators for a directory data block.
pub mod splice {
    use super::{ftype, rec_len_for};

    /// Result of a directory insert attempt against a single block.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum InsertResult {
        /// Splice succeeded; the dirent now lives at `offset`.
        Ok { offset: usize },
        /// No room in this block — caller must extend the directory
        /// (allocate a new logical block) and try again.
        NoRoom,
        /// Name already present — caller surfaces `FsError::AlreadyExists`.
        Exists,
        /// The block bytes are malformed (e.g. rec_len = 0). Caller
        /// surfaces I/O error.
        Corrupt,
    }

    /// Insert a new directory entry `(inode, name, file_type)` into
    /// `block`. Walks the block looking for either an entry whose
    /// inode is 0 (a zombie slot) with rec_len >= reclen OR a live
    /// entry with enough slack at its tail to be split.
    ///
    /// Mirrors Linux `fs/ext2/dir.c::ext2_add_link`, post-relicense.
    pub fn insert_entry(block: &mut [u8], inode: u32, name: &[u8], file_type: u8) -> InsertResult {
        if name.is_empty() || name.len() > 255 {
            return InsertResult::Corrupt;
        }
        let reclen = rec_len_for(name.len() as u8);
        let blocksize = block.len();
        if blocksize < reclen as usize {
            return InsertResult::NoRoom;
        }

        let mut off = 0usize;
        while off + 8 <= blocksize {
            let cur_inode =
                u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
            let cur_rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]);
            let cur_name_len = block[off + 6];
            let cur_file_type = block[off + 7];

            if cur_rec_len < 8 || (cur_rec_len & 3) != 0 {
                return InsertResult::Corrupt;
            }
            if off + cur_rec_len as usize > blocksize {
                return InsertResult::Corrupt;
            }

            // ext4 metadata_csum reserves the final 12-byte fake dirent as a
            // checksum carrier. It looks like a reusable inode-zero slot to
            // an ext2 splicer, so recognize its sentinel file type and leave
            // it intact.
            let checksum_tail = cur_inode == 0
                && cur_rec_len == 12
                && cur_name_len == 0
                && cur_file_type == 0xde
                && off + 12 == blocksize;
            if checksum_tail {
                off += 12;
                continue;
            }

            // Duplicate-name check — only against live (inode != 0) entries.
            if cur_inode != 0 && cur_name_len as usize == name.len() {
                let n_off = off + 8;
                if &block[n_off..n_off + name.len()] == name {
                    return InsertResult::Exists;
                }
            }

            // Compute slack: how many bytes can this record give up?
            // - Zombie (inode == 0): the whole rec_len is reclaimable.
            // - Live: rec_len - rec_len_for(name_len) is the tail slack.
            let minimal = if cur_inode == 0 {
                0
            } else {
                rec_len_for(cur_name_len) as usize
            };
            let avail = cur_rec_len as usize - minimal;
            if avail >= reclen as usize {
                // Splice here. Shrink the existing record to its
                // minimal size; the new record gets the leftover.
                let new_off = off + minimal;
                let new_rec_len = (cur_rec_len as usize - minimal) as u16;
                if minimal != 0 {
                    // Shrink existing rec_len in place.
                    block[off + 4..off + 6].copy_from_slice(&(minimal as u16).to_le_bytes());
                }
                // Write the new entry.
                block[new_off..new_off + 4].copy_from_slice(&inode.to_le_bytes());
                block[new_off + 4..new_off + 6].copy_from_slice(&new_rec_len.to_le_bytes());
                block[new_off + 6] = name.len() as u8;
                block[new_off + 7] = file_type;
                block[new_off + 8..new_off + 8 + name.len()].copy_from_slice(name);
                // Zero-pad to the record boundary so stale bytes don't leak.
                let tail = new_off + 8 + name.len();
                let pad_end = new_off + new_rec_len as usize;
                if pad_end > tail {
                    for b in &mut block[tail..pad_end] {
                        *b = 0;
                    }
                }
                return InsertResult::Ok { offset: new_off };
            }
            off += cur_rec_len as usize;
        }
        InsertResult::NoRoom
    }

    /// Delete the entry at offset `target_off`, coalescing it with
    /// the preceding entry's rec_len so iteration skips the now-empty
    /// slot. Mirrors Linux `fs/ext2/dir.c::ext2_delete_entry`.
    pub fn delete_entry(block: &mut [u8], target_off: usize) -> Result<(), ()> {
        let blocksize = block.len();
        if target_off + 8 > blocksize {
            return Err(());
        }
        let target_rec_len = u16::from_le_bytes([block[target_off + 4], block[target_off + 5]]);
        if target_rec_len < 8 {
            return Err(());
        }
        // Walk to find the preceding entry whose tail abuts `target_off`.
        let mut prev: Option<usize> = None;
        let mut off = 0usize;
        while off < target_off {
            let rl = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
            if rl < 8 {
                return Err(());
            }
            if off + rl == target_off {
                prev = Some(off);
                break;
            }
            if off + rl > target_off {
                return Err(());
            }
            off += rl;
        }
        match prev {
            Some(p) => {
                // Coalesce by extending the previous entry's rec_len.
                let prev_rec = u16::from_le_bytes([block[p + 4], block[p + 5]]);
                let merged = prev_rec + target_rec_len;
                block[p + 4..p + 6].copy_from_slice(&merged.to_le_bytes());
                // Zero the deleted record's inode/name area for hygiene.
                for b in &mut block[target_off..target_off + 8] {
                    *b = 0;
                }
            }
            None => {
                // First entry deleted — set inode to 0; rec_len stays
                // so iteration jumps past the empty slot.
                block[target_off..target_off + 4].copy_from_slice(&0u32.to_le_bytes());
                block[target_off + 6] = 0; // name_len = 0
                block[target_off + 7] = 0; // file_type = 0
            }
        }
        Ok(())
    }

    /// Write a fresh "." + ".." pair into the first block of an empty
    /// directory, filling the whole block. Mirrors
    /// `fs/ext2/dir.c::ext2_make_empty`.
    pub fn make_empty_dir(block: &mut [u8], self_ino: u32, parent_ino: u32) {
        for b in block.iter_mut() {
            *b = 0;
        }
        let dot_rec_len = rec_len_for(1);
        let dotdot_rec_len = block.len() as u16 - dot_rec_len;
        // "." entry.
        block[0..4].copy_from_slice(&self_ino.to_le_bytes());
        block[4..6].copy_from_slice(&dot_rec_len.to_le_bytes());
        block[6] = 1;
        block[7] = ftype::DIR;
        block[8] = b'.';
        // ".." entry.
        let off = dot_rec_len as usize;
        block[off..off + 4].copy_from_slice(&parent_ino.to_le_bytes());
        block[off + 4..off + 6].copy_from_slice(&dotdot_rec_len.to_le_bytes());
        block[off + 6] = 2;
        block[off + 7] = ftype::DIR;
        block[off + 8] = b'.';
        block[off + 9] = b'.';
    }

    /// Returns true iff the directory body contains only "." and ".." —
    /// the precondition for rmdir. Mirrors
    /// `fs/ext2/dir.c::ext2_empty_dir`.
    pub fn is_dir_empty(buf: &[u8]) -> bool {
        let mut off = 0usize;
        while off + 8 <= buf.len() {
            let inode = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            let rec_len = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
            let name_len = buf[off + 6];
            if rec_len < 8 {
                return false;
            }
            if inode != 0 && name_len > 0 {
                if buf[off + 8] != b'.' {
                    return false;
                }
                if name_len > 2 {
                    return false;
                }
                if name_len == 2 && buf[off + 9] != b'.' {
                    return false;
                }
                // name_len == 1 => ".", name_len == 2 => "..". Both allowed.
            }
            off += rec_len as usize;
        }
        true
    }
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
