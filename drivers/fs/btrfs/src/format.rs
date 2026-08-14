//! btrfs on-disk format: constants, little-endian decoders, keys, superblock.
//!
//! Field layouts and offsets follow the authoritative kernel definitions in
//! `/usr/src/linux/include/uapi/linux/btrfs_tree.h` (`struct btrfs_super_block`,
//! `struct btrfs_header`, `struct btrfs_disk_key`, …). This is an independent
//! Rust reimplementation decoding by fixed byte offset; no C is copied. All
//! multi-byte integers are little-endian on disk.

use narf_filesystem::FsError;

// ── Magic / geometry ───────────────────────────────────────────────

/// `_BHRfS_M` as a little-endian u64 (`BTRFS_MAGIC`).
pub const BTRFS_MAGIC: u64 = 0x4D5F_5366_5248_425F;

/// Primary superblock lives 64 KiB into the device (`BTRFS_SUPER_INFO_OFFSET`).
pub const SUPERBLOCK_OFFSET: u64 = 65536;

/// On-disk superblock size, padded to 4096 bytes.
pub const SUPERBLOCK_SIZE: usize = 4096;

/// Bytes of csum at the front of the superblock and every tree node.
pub const CSUM_SIZE: usize = 32;

/// FS UUID length (`BTRFS_FSID_SIZE`).
pub const FSID_SIZE: usize = 16;

/// Maximum size of the embedded system chunk array (`BTRFS_SYSTEM_CHUNK_ARRAY_SIZE`).
pub const SYS_CHUNK_ARRAY_SIZE: usize = 2048;

/// Fixed on-disk offset of `sys_chunk_array` within the superblock. Stable
/// across kernel versions: fields added ahead of it consume `reserved[]` so the
/// array stays at `0x32b`.
pub const SYS_CHUNK_ARRAY_OFFSET: usize = 811;

/// `csum_type` value for CRC32C (`BTRFS_CSUM_TYPE_CRC32`); the only algorithm
/// this driver supports.
pub const CSUM_TYPE_CRC32: u16 = 0;

// ── Well-known object ids ──────────────────────────────────────────

pub const ROOT_TREE_OBJECTID: u64 = 1;
pub const EXTENT_TREE_OBJECTID: u64 = 2;
pub const CHUNK_TREE_OBJECTID: u64 = 3;
pub const FS_TREE_OBJECTID: u64 = 5;
/// Directory objectid inside the root tree that holds the "default" subvolume
/// `DIR_ITEM` (`BTRFS_ROOT_TREE_DIR_OBJECTID`).
pub const ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const CSUM_TREE_OBJECTID: u64 = 7;
/// Device tree (holds `DEV_ITEM` + `DEV_EXTENT`).
pub const DEV_TREE_OBJECTID: u64 = 4;
/// Objectid every `DEV_ITEM`/`DEV_EXTENT` shares (`BTRFS_DEV_ITEMS_OBJECTID`).
pub const DEV_ITEMS_OBJECTID: u64 = 1;
/// Objectid every chunk lives under (`BTRFS_FIRST_CHUNK_TREE_OBJECTID`).
pub const FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
/// Free-space tree (`space_cache=v2`).
pub const FREE_SPACE_TREE_OBJECTID: u64 = 10;
/// Objectid all data-checksum items share (`BTRFS_EXTENT_CSUM_OBJECTID`, -10).
pub const EXTENT_CSUM_OBJECTID: u64 = (-10i64) as u64;
/// First object id available to files/dirs; also the fs-tree root directory.
pub const FIRST_FREE_OBJECTID: u64 = 256;
/// Highest object id available to files/dirs (`BTRFS_LAST_FREE_OBJECTID`, -256);
/// object ids above this are reserved. Bounds the inode-number search.
pub const LAST_FREE_OBJECTID: u64 = (-256i64) as u64;

// ── Item (key) types ───────────────────────────────────────────────

pub const INODE_ITEM_KEY: u8 = 1;
pub const INODE_REF_KEY: u8 = 12;
pub const XATTR_ITEM_KEY: u8 = 24;
pub const DIR_ITEM_KEY: u8 = 84;
pub const DIR_INDEX_KEY: u8 = 96;
pub const EXTENT_DATA_KEY: u8 = 108;
pub const EXTENT_CSUM_KEY: u8 = 128;
pub const ROOT_ITEM_KEY: u8 = 132;
pub const EXTENT_ITEM_KEY: u8 = 168;
/// Skinny-metadata tree-block extent record; length is `nodesize`.
pub const METADATA_ITEM_KEY: u8 = 169;
pub const BLOCK_GROUP_ITEM_KEY: u8 = 192;
pub const DEV_EXTENT_KEY: u8 = 204;
pub const DEV_ITEM_KEY: u8 = 216;
pub const FREE_SPACE_INFO_KEY: u8 = 198;
pub const FREE_SPACE_EXTENT_KEY: u8 = 199;
pub const FREE_SPACE_BITMAP_KEY: u8 = 200;
pub const CHUNK_ITEM_KEY: u8 = 228;

// ── File-extent item types (`btrfs_file_extent_item.type`) ─────────

pub const FILE_EXTENT_INLINE: u8 = 0;
pub const FILE_EXTENT_REG: u8 = 1;
pub const FILE_EXTENT_PREALLOC: u8 = 2;

// ── Compression algorithms (`btrfs_file_extent_item.compression`) ──

pub const COMPRESS_NONE: u8 = 0;
pub const COMPRESS_ZLIB: u8 = 1;
pub const COMPRESS_LZO: u8 = 2;
pub const COMPRESS_ZSTD: u8 = 3;

// ── Directory entry `type` byte (`BTRFS_FT_*`) ─────────────────────

pub const FT_REG_FILE: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_CHRDEV: u8 = 3;
pub const FT_BLKDEV: u8 = 4;
pub const FT_FIFO: u8 = 5;
pub const FT_SOCK: u8 = 6;
pub const FT_SYMLINK: u8 = 7;
/// `BTRFS_FT_XATTR` — the `type` byte an `XATTR_ITEM`'s `btrfs_dir_item` carries.
pub const FT_XATTR: u8 = 8;

// ── Block-group / chunk `type` flags (`BTRFS_BLOCK_GROUP_*`) ────────

pub const BLOCK_GROUP_DATA: u64 = 1 << 0;
pub const BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
pub const BLOCK_GROUP_METADATA: u64 = 1 << 2;
/// Profile bits we support: SINGLE (no profile bit) and DUP.
pub const BLOCK_GROUP_DUP: u64 = 1 << 5;
/// All RAID/DUP profile bits (`BTRFS_BLOCK_GROUP_PROFILE_MASK`): RAID0(3),
/// RAID1(4), DUP(5), RAID10(6), RAID5(7), RAID6(8), RAID1C3(9), RAID1C4(10).
/// A chunk whose masked profile is neither 0 (SINGLE) nor exactly DUP is
/// rejected.
pub const BLOCK_GROUP_PROFILE_MASK: u64 = 0x7F8;

// ── Little-endian decoders ─────────────────────────────────────────

/// Read a little-endian u16 at `off`, bounds-checked.
pub fn le16(buf: &[u8], off: usize) -> Result<u16, FsError> {
    let end = off.checked_add(2).ok_or(FsError::InvalidData)?;
    let bytes = buf.get(off..end).ok_or(FsError::InvalidData)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a little-endian u32 at `off`, bounds-checked.
pub fn le32(buf: &[u8], off: usize) -> Result<u32, FsError> {
    let end = off.checked_add(4).ok_or(FsError::InvalidData)?;
    let bytes = buf.get(off..end).ok_or(FsError::InvalidData)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian u64 at `off`, bounds-checked.
pub fn le64(buf: &[u8], off: usize) -> Result<u64, FsError> {
    let end = off.checked_add(8).ok_or(FsError::InvalidData)?;
    let bytes = buf.get(off..end).ok_or(FsError::InvalidData)?;
    let mut v = [0u8; 8];
    v.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(v))
}

// ── Keys ───────────────────────────────────────────────────────────

/// A btrfs b-tree key in CPU order (`struct btrfs_key`). The tuple
/// `(objectid, type, offset)` defines the total order used for every search;
/// the derived `Ord` compares fields in declaration order, which is exactly
/// `btrfs_comp_keys`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub item_type: u8,
    pub offset: u64,
}

impl BtrfsKey {
    pub const fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        BtrfsKey {
            objectid,
            item_type,
            offset,
        }
    }

    /// Decode a 17-byte on-disk `struct btrfs_disk_key` at `off`.
    pub fn decode(buf: &[u8], off: usize) -> Result<Self, FsError> {
        Ok(BtrfsKey {
            objectid: le64(buf, off)?,
            item_type: *buf.get(off + 8).ok_or(FsError::InvalidData)?,
            offset: le64(buf, off + 9)?,
        })
    }
}

/// On-disk size of `struct btrfs_disk_key`.
pub const DISK_KEY_SIZE: usize = 17;

// ── Superblock ─────────────────────────────────────────────────────

// Fixed byte offsets within `struct btrfs_super_block`. Stable ABI.
const OFF_CSUM: usize = 0;
const OFF_MAGIC: usize = 64;
const OFF_GENERATION: usize = 72;
const OFF_ROOT: usize = 80;
const OFF_CHUNK_ROOT: usize = 88;
const OFF_TOTAL_BYTES: usize = 112;
const OFF_BYTES_USED: usize = 120;
const OFF_NUM_DEVICES: usize = 136;
const OFF_SECTORSIZE: usize = 144;
const OFF_NODESIZE: usize = 148;
const OFF_SYS_CHUNK_ARRAY_SIZE: usize = 160;
const OFF_INCOMPAT_FLAGS: usize = 188;
const OFF_CSUM_TYPE: usize = 196;
const OFF_ROOT_LEVEL: usize = 198;
const OFF_CHUNK_ROOT_LEVEL: usize = 199;

/// Decoded btrfs superblock — only the fields the driver consumes.
#[derive(Clone, Debug)]
pub struct Superblock {
    /// Stored block checksum (low 4 bytes are the CRC32C).
    pub csum: [u8; CSUM_SIZE],
    pub magic: u64,
    pub generation: u64,
    /// Logical address of the root-tree root node.
    pub root: u64,
    /// Logical address of the chunk-tree root node.
    pub chunk_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    /// Copy of the embedded system chunk array (`sys_chunk_array_size` bytes).
    pub sys_chunk_array: alloc::vec::Vec<u8>,
}

impl Superblock {
    /// Decode a superblock from a ≥4096-byte buffer read at
    /// [`SUPERBLOCK_OFFSET`]. Validates magic and the driver's hard limits.
    pub fn decode(buf: &[u8]) -> Result<Self, FsError> {
        if buf.len() < SUPERBLOCK_SIZE {
            return Err(FsError::InvalidData);
        }
        let magic = le64(buf, OFF_MAGIC)?;
        if magic != BTRFS_MAGIC {
            return Err(FsError::InvalidData);
        }
        let csum_type = le16(buf, OFF_CSUM_TYPE)?;
        if csum_type != CSUM_TYPE_CRC32 {
            // xxhash/sha256/blake2 volumes are not supported.
            return Err(FsError::Unsupported);
        }
        let num_devices = le64(buf, OFF_NUM_DEVICES)?;
        if num_devices != 1 {
            return Err(FsError::Unsupported);
        }
        let sectorsize = le32(buf, OFF_SECTORSIZE)?;
        let nodesize = le32(buf, OFF_NODESIZE)?;
        if sectorsize != 4096 || !nodesize.is_power_of_two() || nodesize < sectorsize {
            return Err(FsError::Unsupported);
        }
        let sys_len = le32(buf, OFF_SYS_CHUNK_ARRAY_SIZE)? as usize;
        if sys_len > SYS_CHUNK_ARRAY_SIZE {
            return Err(FsError::InvalidData);
        }
        let sys_start = SYS_CHUNK_ARRAY_OFFSET;
        let sys_end = sys_start.checked_add(sys_len).ok_or(FsError::InvalidData)?;
        let sys_chunk_array = buf
            .get(sys_start..sys_end)
            .ok_or(FsError::InvalidData)?
            .to_vec();

        let mut csum = [0u8; CSUM_SIZE];
        csum.copy_from_slice(&buf[OFF_CSUM..OFF_CSUM + CSUM_SIZE]);

        // incompat_flags is decoded for future gating; unknown bits are
        // tolerated because the driver rejects the specific on-disk shapes it
        // cannot handle (RAID chunks, compressed extents) at point of use.
        let _incompat = le64(buf, OFF_INCOMPAT_FLAGS)?;

        Ok(Superblock {
            csum,
            magic,
            generation: le64(buf, OFF_GENERATION)?,
            root: le64(buf, OFF_ROOT)?,
            chunk_root: le64(buf, OFF_CHUNK_ROOT)?,
            total_bytes: le64(buf, OFF_TOTAL_BYTES)?,
            bytes_used: le64(buf, OFF_BYTES_USED)?,
            num_devices,
            sectorsize,
            nodesize,
            csum_type,
            root_level: *buf.get(OFF_ROOT_LEVEL).ok_or(FsError::InvalidData)?,
            chunk_root_level: *buf.get(OFF_CHUNK_ROOT_LEVEL).ok_or(FsError::InvalidData)?,
            sys_chunk_array,
        })
    }
}
