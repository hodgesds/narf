//! ext2 on-disk inode.
//!
//! Sources:
//! - Card, Ts'o, Tweedie, §"Inodes".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Inode".
//! - OSDev Wiki, "Ext2 — Inode Table":
//!   <https://wiki.osdev.org/Ext2#Inode_Data_Structure>
//!
//! No GPL/LGPL source was consulted.

/// 12 direct block pointers + 1 single + 1 double + 1 triple
/// indirect = 15 entries total in `i_block[]`.
pub const N_DIRECT: usize = 12;
pub const I_BLOCK_LEN: usize = 15;
pub const SINGLE_IND_IDX: usize = 12;
pub const DOUBLE_IND_IDX: usize = 13;
pub const TRIPLE_IND_IDX: usize = 14;

// File-mode `i_mode` field — type bits in the high nibble of the
// upper byte. The bit pattern is the same as POSIX `mode_t`. We
// only decode the type discriminator.
pub const S_IFMT: u16 = 0xF000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFLNK: u16 = 0xA000;

/// Decoded subset of an on-disk inode.
#[derive(Debug, Copy, Clone)]
pub struct Inode {
    /// `i_mode` — file type + permission bits.
    pub mode: u16,
    /// `i_size` — file size, low 32 bits. Directories report their
    /// directory-block byte length here.
    pub size: u32,
    /// `i_blocks` — count of 512-byte sectors held by the file.
    pub blocks: u32,
    /// `i_block[15]` — block pointers (12 direct + 3 indirect tiers).
    pub block: [u32; I_BLOCK_LEN],
}

impl Inode {
    /// Decode an inode from `buf`, which must hold at least the
    /// 128-byte rev-0 layout. Larger `s_inode_size` values from
    /// rev-1 volumes are tolerated — we only read the first 128
    /// bytes.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 128 {
            return None;
        }
        let mode = u16::from_le_bytes([buf[0], buf[1]]);
        let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let blocks = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let mut block = [0u32; I_BLOCK_LEN];
        for i in 0..I_BLOCK_LEN {
            let off = 40 + i * 4;
            block[i] = u32::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]);
        }
        Some(Self {
            mode,
            size,
            blocks,
            block,
        })
    }

    pub fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    pub fn is_regular(&self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }

    /// Encode this inode into a 128-byte buffer. Only fields we
    /// surface (mode/size/blocks/block) are written; everything else
    /// is preserved by reading the on-disk bytes first and only
    /// overwriting our fields. Caller should pass `buf` initialised
    /// from `read_byte_range` and call `encode` to update.
    pub fn encode_into(&self, buf: &mut [u8]) {
        if buf.len() < 128 {
            return;
        }
        buf[0..2].copy_from_slice(&self.mode.to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf[28..32].copy_from_slice(&self.blocks.to_le_bytes());
        for i in 0..I_BLOCK_LEN {
            let off = 40 + i * 4;
            buf[off..off + 4].copy_from_slice(&self.block[i].to_le_bytes());
        }
    }

    /// Build a fresh regular-file inode.
    pub fn new_regular(perms: u16) -> Self {
        Self {
            mode: S_IFREG | (perms & 0o777),
            size: 0,
            blocks: 0,
            block: [0; I_BLOCK_LEN],
        }
    }

    /// Build a fresh directory inode.
    pub fn new_directory(perms: u16) -> Self {
        Self {
            mode: S_IFDIR | (perms & 0o777),
            size: 0,
            blocks: 0,
            block: [0; I_BLOCK_LEN],
        }
    }
}
