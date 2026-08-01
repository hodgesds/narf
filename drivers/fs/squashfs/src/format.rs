//! SquashFS 4.0 on-disk constants and bounded little-endian decoders.
//!
//! Primary reference: Linux `fs/squashfs/squashfs_fs.h`.  The codec is
//! deliberately field-by-field: on-disk records are packed and untrusted, so
//! Rust `repr(C)` casts would add alignment and padding hazards.

use narf_filesystem::FsError;

pub const MAGIC: u32 = 0x7371_7368;
pub const MAJOR: u16 = 4;
pub const MINOR: u16 = 0;
pub const SUPERBLOCK_SIZE: usize = 96;
pub const METADATA_SIZE: usize = 8192;
pub const INVALID_U32: u32 = u32::MAX;
pub const INVALID_U64: u64 = u64::MAX;
pub const NAME_LEN: usize = 256;
pub const MAX_BLOCK_SIZE: u32 = 1 << 20;
pub const DATA_UNCOMPRESSED: u32 = 1 << 24;
pub const METADATA_UNCOMPRESSED: u16 = 1 << 15;

pub const FLAG_COMP_OPTIONS: u16 = 1 << 10;

pub const DIR_TYPE: u16 = 1;
pub const REG_TYPE: u16 = 2;
pub const SYMLINK_TYPE: u16 = 3;
pub const BLKDEV_TYPE: u16 = 4;
pub const CHRDEV_TYPE: u16 = 5;
pub const FIFO_TYPE: u16 = 6;
pub const SOCKET_TYPE: u16 = 7;
pub const LDIR_TYPE: u16 = 8;
pub const LREG_TYPE: u16 = 9;
pub const LSYMLINK_TYPE: u16 = 10;
pub const LBLKDEV_TYPE: u16 = 11;
pub const LCHRDEV_TYPE: u16 = 12;
pub const LFIFO_TYPE: u16 = 13;
pub const LSOCKET_TYPE: u16 = 14;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Compression {
    Zlib,
    Lz4,
}

impl Compression {
    pub fn decode(raw: u16) -> Result<Self, FsError> {
        match raw {
            1 => Ok(Self::Zlib),
            5 => Ok(Self::Lz4),
            // LZMA (2), LZO (3), XZ (4), and Zstandard (6) are valid
            // SquashFS compressors, but this no_std build has no matching
            // bounded decoder.  Reject at mount instead of misreading data.
            _ => Err(FsError::Unsupported),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub inodes: u32,
    pub mkfs_time: u32,
    pub block_size: u32,
    pub fragments: u32,
    pub compression: Compression,
    pub block_log: u16,
    pub flags: u16,
    pub no_ids: u16,
    pub root_inode: u64,
    pub bytes_used: u64,
    pub id_table_start: u64,
    pub xattr_id_table_start: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    pub lookup_table_start: u64,
}

impl Superblock {
    pub fn decode(buf: &[u8]) -> Result<Self, FsError> {
        if buf.len() < SUPERBLOCK_SIZE || le32(buf, 0)? != MAGIC {
            return Err(FsError::InvalidData);
        }
        if le16(buf, 28)? != MAJOR || le16(buf, 30)? > MINOR {
            return Err(FsError::Unsupported);
        }
        Ok(Self {
            inodes: le32(buf, 4)?,
            mkfs_time: le32(buf, 8)?,
            block_size: le32(buf, 12)?,
            fragments: le32(buf, 16)?,
            compression: Compression::decode(le16(buf, 20)?)?,
            block_log: le16(buf, 22)?,
            flags: le16(buf, 24)?,
            no_ids: le16(buf, 26)?,
            root_inode: le64(buf, 32)?,
            bytes_used: le64(buf, 40)?,
            id_table_start: le64(buf, 48)?,
            xattr_id_table_start: le64(buf, 56)?,
            inode_table_start: le64(buf, 64)?,
            directory_table_start: le64(buf, 72)?,
            fragment_table_start: le64(buf, 80)?,
            lookup_table_start: le64(buf, 88)?,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InodeRef {
    pub block: u32,
    pub offset: u16,
}

impl InodeRef {
    pub const fn decode(raw: u64) -> Self {
        Self {
            block: (raw >> 16) as u32,
            offset: raw as u16,
        }
    }

    pub const fn encode(self) -> u64 {
        ((self.block as u64) << 16) | self.offset as u64
    }
}

pub fn le16(buf: &[u8], off: usize) -> Result<u16, FsError> {
    let b = buf.get(off..off + 2).ok_or(FsError::InvalidData)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub fn le32(buf: &[u8], off: usize) -> Result<u32, FsError> {
    let b = buf.get(off..off + 4).ok_or(FsError::InvalidData)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn le64(buf: &[u8], off: usize) -> Result<u64, FsError> {
    let b = buf.get(off..off + 8).ok_or(FsError::InvalidData)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}
