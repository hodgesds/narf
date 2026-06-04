//! ext4 on-disk inode — wraps the shared decoder from
//! `drivers/fs/ext2/` and adds ext4-specific fields the sibling
//! crate doesn't surface today: `i_flags` (to read `EXT4_EXTENTS_FL`),
//! the 32-bit-extent half of `i_blocks` (`i_blocks_lo` + `i_blocks_hi`
//! when HUGE_FILE is on), and the upper 32 bits of `i_size`.
//!
//! Sources:
//! - Linux `fs/ext4/ext4.h::struct ext4_inode` — the 156-byte
//!   on-disk inode layout (256 bytes including the extra-isize
//!   tail).
//! - Linux `fs/ext4/inode.c::ext4_iget` — flag handling
//!   (`EXT4_EXTENTS_FL` makes `i_block[]` an extent-tree root).
//! - Linux `include/uapi/linux/ext4_fs.h::EXT4_*_FL` — the inode
//!   flag bits.

pub use narf_drivers_fs_ext2::inode::{
    Inode, DOUBLE_IND_IDX, I_BLOCK_LEN, N_DIRECT, SINGLE_IND_IDX, S_IFDIR, S_IFLNK, S_IFMT,
    S_IFREG, TRIPLE_IND_IDX,
};

/// `EXT4_EXTENTS_FL` — when set in `i_flags` (offset 32 of the
/// on-disk inode), `i_block[]` holds an extent tree rather than the
/// classic 12 direct + 3 indirect pointer table. Set by mkfs.ext4
/// on every new file on an EXTENTS volume.
/// Linux `include/uapi/linux/ext4_fs.h::EXT4_EXTENTS_FL`.
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// `EXT4_INDEX_FL` — directory uses an HTREE rather than a flat
/// list of dirents. Linux `include/uapi/linux/ext4_fs.h::EXT4_INDEX_FL`.
pub const EXT4_INDEX_FL: u32 = 0x0000_1000;

/// `EXT4_INLINE_DATA_FL` — file content is stored in `i_block[]`
/// and the EA region instead of in data blocks.
/// Linux `include/uapi/linux/ext4_fs.h::EXT4_INLINE_DATA_FL`.
pub const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;

/// ext4-specific extended inode view. Wraps the shared `Inode`
/// (mode/size/links/blocks/block[]) and adds the ext4-only fields.
#[derive(Debug, Copy, Clone)]
pub struct Ext4Inode {
    pub core: Inode,
    /// `i_flags` — offset 32 of the on-disk inode. Per-file feature
    /// flags including `EXT4_EXTENTS_FL`.
    pub flags: u32,
    /// Upper 32 bits of `i_size`. Combined with `core.size` they
    /// form a 64-bit file length (HUGE_FILE / LARGE_FILE).
    /// Offset 108 on the on-disk inode (`i_size_high`).
    pub size_hi: u32,
}

impl Ext4Inode {
    /// Decode an ext4 inode from `buf`. Reads the shared 128-byte
    /// core plus the ext4-only fields at offsets 32 (`i_flags`) and
    /// 108 (`i_size_high`).
    ///
    /// Returns `None` if the core decode fails (bad core layout) or
    /// `buf` is too short to contain the extended fields.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let core = Inode::parse(buf)?;
        // i_flags at offset 32 (4 bytes).
        if buf.len() < 36 {
            return None;
        }
        let flags = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        // i_size_high at offset 108 (4 bytes). Falls back to zero
        // on 128-byte rev-0 inodes — those are pre-LARGE_FILE.
        let size_hi = if buf.len() >= 112 {
            u32::from_le_bytes([buf[108], buf[109], buf[110], buf[111]])
        } else {
            0
        };
        Some(Self {
            core,
            flags,
            size_hi,
        })
    }

    /// 64-bit file size — `i_size_high << 32 | i_size`. Files larger
    /// than 4 GiB depend on this; smaller files have `size_hi == 0`.
    pub fn size64(&self) -> u64 {
        ((self.size_hi as u64) << 32) | self.core.size as u64
    }

    /// True iff `EXT4_EXTENTS_FL` is set — the inode's `i_block[]`
    /// region holds an extent-tree root (12-byte header + up to 4
    /// extent / index entries) instead of legacy direct/indirect
    /// pointers.
    pub fn uses_extents(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL != 0
    }

    /// True iff `EXT4_INDEX_FL` is set — the directory uses an
    /// HTREE for name lookup. Only meaningful when `core.mode`
    /// classifies the inode as a directory.
    pub fn has_htree(&self) -> bool {
        self.flags & EXT4_INDEX_FL != 0
    }

    /// True iff `EXT4_INLINE_DATA_FL` is set — file content fits in
    /// `i_block[]` and is read directly from the inode bytes.
    pub fn is_inline(&self) -> bool {
        self.flags & EXT4_INLINE_DATA_FL != 0
    }

    /// Borrow the 60-byte `i_block[]` region as the canonical input
    /// for an extent-tree decode. The on-disk slice is the same
    /// bytes the shared `Inode::block: [u32; 15]` field carries, just
    /// addressed as a flat byte buffer (which is what the extent
    /// decoder wants).
    pub fn i_block_bytes(&self) -> [u8; 60] {
        let mut out = [0u8; 60];
        for i in 0..I_BLOCK_LEN {
            let off = i * 4;
            out[off..off + 4].copy_from_slice(&self.core.block[i].to_le_bytes());
        }
        out
    }

    /// Convenience constructor for tests + write-path callers: a
    /// fresh regular file inode with the EXTENTS flag set so the
    /// extent-tree machinery treats `i_block[]` as an extent header
    /// from the first write. Caller still needs to initialise the
    /// extent header in `core.block[]` (12 bytes of header at offset
    /// 0 of i_block, magic 0xF30A, depth 0, max 4, entries 0).
    pub fn new_regular_with_extents(perms: u16) -> Self {
        let mut core = Inode::new_regular(perms);
        // Initialise an empty extent header in i_block[0..3]. The
        // 12 bytes are: magic(2)+entries(2)+max(2)+depth(2)+gen(4).
        // Empty header: 0xF30A, 0, 4, 0, 0.
        let header: u32 = 0x0000_F30A; // magic in low half; entries=0 in high half
        let max_depth: u32 = 0x0000_0004; // max=4, depth=0
        core.block[0] = header;
        core.block[1] = max_depth;
        core.block[2] = 0;
        Self {
            core,
            flags: EXT4_EXTENTS_FL,
            size_hi: 0,
        }
    }

    /// Encode the ext4-only fields into `buf`. Caller should call
    /// `Inode::encode_into` first to write the shared fields, then
    /// this to overwrite `i_flags` and `i_size_high`.
    pub fn encode_into(&self, buf: &mut [u8]) {
        if buf.len() < 36 {
            return;
        }
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        if buf.len() >= 112 {
            buf[108..112].copy_from_slice(&self.size_hi.to_le_bytes());
        }
    }
}
