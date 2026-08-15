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

/// Physical device offsets of every superblock copy, in mirror order
/// (`btrfs_sb_offset`): the primary at 64 KiB, then mirrors at 64 MiB and
/// 256 GiB. A copy is written only when it fits within the device; each copy
/// records its own offset in `bytenr@48` and carries its own checksum.
pub const SUPERBLOCK_MIRROR_OFFSETS: [u64; 3] = [65536, 64 << 20, 256 << 30];

/// Offset of the `bytenr` field (this copy's own physical address) within the
/// superblock. Differs per mirror, so each copy's checksum differs too.
pub const SUPERBLOCK_BYTENR_OFFSET: usize = 48;

/// On-disk superblock size, padded to 4096 bytes.
pub const SUPERBLOCK_SIZE: usize = 4096;

/// Linux Btrfs accepts power-of-two data sectors from 4 KiB through 64 KiB.
pub const MIN_SECTORSIZE: u32 = 4096;
pub const MAX_SECTORSIZE: u32 = 65536;
/// Maximum metadata node size accepted by Linux Btrfs.
pub const MAX_NODESIZE: u32 = 65536;

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

/// `csum_type` values from `enum btrfs_csum_type`.
pub const CSUM_TYPE_CRC32: u16 = 0;
pub(crate) const CSUM_TYPE_XXHASH: u16 = 1;
pub(crate) const CSUM_TYPE_SHA256: u16 = 2;
pub(crate) const CSUM_TYPE_BLAKE2: u16 = 3;

// ── Well-known object ids ──────────────────────────────────────────

pub const ROOT_TREE_OBJECTID: u64 = 1;
pub const EXTENT_TREE_OBJECTID: u64 = 2;
pub const CHUNK_TREE_OBJECTID: u64 = 3;
pub const FS_TREE_OBJECTID: u64 = 5;
/// `btrfs_root_item.flags`: the subvolume must not be mutated.
pub const ROOT_SUBVOL_RDONLY: u64 = 1;
/// Directory objectid inside the root tree that holds the "default" subvolume
/// `DIR_ITEM` (`BTRFS_ROOT_TREE_DIR_OBJECTID`).
pub const ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const CSUM_TREE_OBJECTID: u64 = 7;
/// Quota-group status, accounting, limits, and hierarchy.
pub const QUOTA_TREE_OBJECTID: u64 = 8;
/// UUID index tree (subvolume UUID → root objectid).
pub const UUID_TREE_OBJECTID: u64 = 9;
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
/// The tree-log tree (`BTRFS_TREE_LOG_OBJECTID`, -7): the fsync log root, and the
/// objectid of the log-root tree that maps each subvolume to its log.
pub const TREE_LOG_OBJECTID: u64 = (-7i64) as u64;
/// First object id available to files/dirs; also the fs-tree root directory.
pub const FIRST_FREE_OBJECTID: u64 = 256;
/// Highest object id available to files/dirs (`BTRFS_LAST_FREE_OBJECTID`, -256);
/// object ids above this are reserved. Bounds the inode-number search.
pub const LAST_FREE_OBJECTID: u64 = (-256i64) as u64;

// ── Item (key) types ───────────────────────────────────────────────

pub const INODE_ITEM_KEY: u8 = 1;
pub const INODE_REF_KEY: u8 = 12;
pub const XATTR_ITEM_KEY: u8 = 24;
/// Legacy directory-log range key (defined by the format, no longer emitted by
/// current Linux kernels). Kept so replay never copies it into the FS tree.
pub const DIR_LOG_ITEM_KEY: u8 = 60;
/// Modern directory-log authoritative range. The key offset is the inclusive
/// start and its `btrfs_dir_log_item.end` body is the inclusive end.
pub const DIR_LOG_INDEX_KEY: u8 = 72;
pub const DIR_ITEM_KEY: u8 = 84;
pub const DIR_INDEX_KEY: u8 = 96;
pub const EXTENT_DATA_KEY: u8 = 108;
pub const EXTENT_CSUM_KEY: u8 = 128;
pub const ROOT_ITEM_KEY: u8 = 132;
pub const ROOT_BACKREF_KEY: u8 = 144;
pub const ROOT_REF_KEY: u8 = 156;
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
pub const QGROUP_STATUS_KEY: u8 = 240;
pub const QGROUP_INFO_KEY: u8 = 242;
pub const QGROUP_LIMIT_KEY: u8 = 244;
pub const QGROUP_RELATION_KEY: u8 = 246;
pub const UUID_KEY_SUBVOL: u8 = 251;

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
pub const BLOCK_GROUP_RAID0: u64 = 1 << 3;
pub const BLOCK_GROUP_RAID1: u64 = 1 << 4;
pub const BLOCK_GROUP_DUP: u64 = 1 << 5;
pub const BLOCK_GROUP_RAID10: u64 = 1 << 6;
pub const BLOCK_GROUP_RAID5: u64 = 1 << 7;
pub const BLOCK_GROUP_RAID6: u64 = 1 << 8;
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
pub const OFF_LOG_ROOT: usize = 96;
pub const OFF_LOG_ROOT_TRANSID: usize = 104;
pub const OFF_LOG_ROOT_LEVEL: usize = 200;
const OFF_TOTAL_BYTES: usize = 112;
const OFF_BYTES_USED: usize = 120;
const OFF_NUM_DEVICES: usize = 136;
const OFF_SECTORSIZE: usize = 144;
const OFF_NODESIZE: usize = 148;
const OFF_SYS_CHUNK_ARRAY_SIZE: usize = 160;
const OFF_COMPAT_RO_FLAGS: usize = 180;
pub(crate) const OFF_INCOMPAT_FLAGS: usize = 188;
const OFF_CSUM_TYPE: usize = 196;
const OFF_ROOT_LEVEL: usize = 198;
const OFF_CHUNK_ROOT_LEVEL: usize = 199;
const OFF_FSID: usize = 32;
/// Embedded member-specific `struct btrfs_dev_item` in each superblock.
pub const SUPERBLOCK_DEV_ITEM_OFFSET: usize = 201;
pub const SUPERBLOCK_DEV_ITEM_SIZE: usize = 98;
const OFF_DEV_ITEM: usize = SUPERBLOCK_DEV_ITEM_OFFSET;
const DEV_ITEM_UUID: usize = 66;
const DEV_ITEM_FSID: usize = 82;

// Features whose on-disk shapes are understood by this driver. Read-only
// compatibility bits are not safe to ignore here because this implementation
// can mount writable and does not yet have a read-only fallback mount mode.
pub const COMPAT_RO_FREE_SPACE_TREE: u64 = 1 << 0;
pub const COMPAT_RO_FREE_SPACE_TREE_VALID: u64 = 1 << 1;
pub const SUPPORTED_COMPAT_RO_FLAGS: u64 =
    COMPAT_RO_FREE_SPACE_TREE | COMPAT_RO_FREE_SPACE_TREE_VALID;

pub const INCOMPAT_MIXED_BACKREF: u64 = 1 << 0;
pub const INCOMPAT_DEFAULT_SUBVOL: u64 = 1 << 1;
pub const INCOMPAT_MIXED_GROUPS: u64 = 1 << 2;
pub const INCOMPAT_COMPRESS_LZO: u64 = 1 << 3;
pub const INCOMPAT_COMPRESS_ZSTD: u64 = 1 << 4;
pub const INCOMPAT_BIG_METADATA: u64 = 1 << 5;
pub const INCOMPAT_EXTENDED_IREF: u64 = 1 << 6;
/// Required when any RAID5/RAID6 block group exists.
pub const INCOMPAT_RAID56: u64 = 1 << 7;
pub const INCOMPAT_SKINNY_METADATA: u64 = 1 << 8;
pub const INCOMPAT_NO_HOLES: u64 = 1 << 9;
pub const INCOMPAT_METADATA_UUID: u64 = 1 << 10;
/// Extents allocated while simple quotas are active carry a permanent owner
/// reference. Linux deliberately leaves this bit set after quotas are disabled.
pub const INCOMPAT_SIMPLE_QUOTA: u64 = 1 << 16;
pub const SUPPORTED_INCOMPAT_FLAGS: u64 = INCOMPAT_MIXED_BACKREF
    | INCOMPAT_DEFAULT_SUBVOL
    | INCOMPAT_MIXED_GROUPS
    | INCOMPAT_COMPRESS_LZO
    | INCOMPAT_COMPRESS_ZSTD
    | INCOMPAT_BIG_METADATA
    | INCOMPAT_EXTENDED_IREF
    | INCOMPAT_RAID56
    | INCOMPAT_SKINNY_METADATA
    | INCOMPAT_NO_HOLES
    | INCOMPAT_METADATA_UUID
    | INCOMPAT_SIMPLE_QUOTA;

/// Decoded btrfs superblock — only the fields the driver consumes.
#[derive(Clone, Debug)]
pub struct Superblock {
    /// Stored block checksum (the algorithm determines how many bytes are used).
    pub csum: [u8; CSUM_SIZE],
    pub fsid: [u8; 16],
    pub devid: u64,
    pub device_total_bytes: u64,
    pub dev_uuid: [u8; 16],
    pub magic: u64,
    pub generation: u64,
    /// Logical address of the root-tree root node.
    pub root: u64,
    /// Logical address of the chunk-tree root node.
    pub chunk_root: u64,
    /// Logical address of the log-root tree, or 0 when no fsync log is pending.
    /// A non-zero value means the volume was left with an unreplayed tree-log.
    pub log_root: u64,
    /// Level of the log-root tree node at [`log_root`](Self::log_root).
    pub log_root_level: u8,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    /// Copy of the embedded system chunk array (`sys_chunk_array_size` bytes).
    pub sys_chunk_array: alloc::vec::Vec<u8>,
}

impl Superblock {
    /// Read the checksum selector before decoding the rest of a raw superblock.
    /// Mount needs this field in order to verify the block that contains it.
    pub(crate) fn checksum_type(buf: &[u8]) -> Result<u16, FsError> {
        le16(buf, OFF_CSUM_TYPE)
    }

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
        let csum_type = Self::checksum_type(buf)?;
        if !crate::checksum::is_supported(csum_type) {
            return Err(FsError::Unsupported);
        }
        let num_devices = le64(buf, OFF_NUM_DEVICES)?;
        if num_devices == 0 {
            return Err(FsError::InvalidData);
        }
        let sectorsize = le32(buf, OFF_SECTORSIZE)?;
        let nodesize = le32(buf, OFF_NODESIZE)?;
        if !sectorsize.is_power_of_two()
            || !(MIN_SECTORSIZE..=MAX_SECTORSIZE).contains(&sectorsize)
            || !nodesize.is_power_of_two()
            || nodesize < sectorsize
            || nodesize > MAX_NODESIZE
        {
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
        let mut fsid = [0u8; 16];
        fsid.copy_from_slice(
            buf.get(OFF_FSID..OFF_FSID + 16)
                .ok_or(FsError::InvalidData)?,
        );
        let devid = le64(buf, OFF_DEV_ITEM)?;
        if devid == 0 {
            return Err(FsError::InvalidData);
        }
        let mut dev_uuid = [0u8; 16];
        dev_uuid.copy_from_slice(
            buf.get(OFF_DEV_ITEM + DEV_ITEM_UUID..OFF_DEV_ITEM + DEV_ITEM_UUID + 16)
                .ok_or(FsError::InvalidData)?,
        );
        if buf.get(OFF_DEV_ITEM + DEV_ITEM_FSID..OFF_DEV_ITEM + DEV_ITEM_FSID + 16)
            != Some(fsid.as_slice())
        {
            return Err(FsError::InvalidData);
        }

        let compat_ro_flags = le64(buf, OFF_COMPAT_RO_FLAGS)?;
        let incompat_flags = le64(buf, OFF_INCOMPAT_FLAGS)?;
        if compat_ro_flags & !SUPPORTED_COMPAT_RO_FLAGS != 0
            || incompat_flags & !SUPPORTED_INCOMPAT_FLAGS != 0
        {
            return Err(FsError::Unsupported);
        }

        Ok(Superblock {
            csum,
            fsid,
            devid,
            device_total_bytes: le64(buf, OFF_DEV_ITEM + 8)?,
            dev_uuid,
            magic,
            generation: le64(buf, OFF_GENERATION)?,
            root: le64(buf, OFF_ROOT)?,
            chunk_root: le64(buf, OFF_CHUNK_ROOT)?,
            log_root: le64(buf, OFF_LOG_ROOT)?,
            log_root_level: *buf.get(OFF_LOG_ROOT_LEVEL).ok_or(FsError::InvalidData)?,
            total_bytes: le64(buf, OFF_TOTAL_BYTES)?,
            bytes_used: le64(buf, OFF_BYTES_USED)?,
            num_devices,
            compat_ro_flags,
            incompat_flags,
            sectorsize,
            nodesize,
            csum_type,
            root_level: *buf.get(OFF_ROOT_LEVEL).ok_or(FsError::InvalidData)?,
            chunk_root_level: *buf.get(OFF_CHUNK_ROOT_LEVEL).ok_or(FsError::InvalidData)?,
            sys_chunk_array,
        })
    }
}
