//! ext2 on-disk inode.
//!
//! Sources (post-relicense — NARF is GPL-2.0+ as of 2026-05-20):
//! - Card, Ts'o, Tweedie, §"Inodes".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Inode".
//! - OSDev Wiki, "Ext2 — Inode Table":
//!   <https://wiki.osdev.org/Ext2#Inode_Data_Structure>
//! - Linux `include/uapi/linux/ext4_fs.h` — `EXT4_INDEX_FL`,
//!   `EXT4_EXTENTS_FL`.
//!
//! No non-GPL source was consulted for the original 128-byte layout;
//! the flag constants are from the public kernel UAPI header.

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

/// `i_flags` bit: directory uses HTREE indexing. Matches
/// `EXT4_INDEX_FL` from `include/uapi/linux/ext4_fs.h`.
pub const I_FLAGS_INDEX: u32 = 0x0000_1000;

/// `i_flags` bit: inode uses extent tree for data blocks. Matches
/// `EXT4_EXTENTS_FL`.
pub const I_FLAGS_EXTENTS: u32 = 0x0008_0000;

/// `i_flags` bit: the inode's data lives inline in `i_block` / the in-inode
/// xattr area. Matches `EXT4_INLINE_DATA_FL`.
pub const I_FLAGS_INLINE_DATA: u32 = 0x1000_0000;

/// Decoded subset of an on-disk inode.
///
/// On-disk layout (rev-0, 128 bytes):
///
/// ```text
/// offset  size  field
///      0     2  i_mode
///      2     2  i_uid
///      4     4  i_size
///      8     4  i_atime   ← seconds since epoch
///     12     4  i_ctime
///     16     4  i_mtime
///     20     4  i_dtime
///     24     2  i_gid
///     26     2  i_links_count
///     28     4  i_blocks  (512-byte sectors)
///     32     4  i_flags
///     36     4  i_osd1 / reserved
///     40    60  i_block[15]
///    120     2  l_i_uid_high (Linux i_osd2)
///    122     2  l_i_gid_high (Linux i_osd2)
/// ```
#[derive(Debug, Copy, Clone)]
pub struct Inode {
    /// `i_mode` — file type + permission bits.
    pub mode: u16,
    /// POSIX owner id (`i_uid` plus Linux `l_i_uid_high`).
    pub uid: u32,
    /// `i_size` — file size, low 32 bits.
    pub size: u32,
    /// `i_atime` — last access time (seconds since UNIX epoch).
    pub atime: u32,
    /// `i_ctime` — inode-change time (any metadata mutation).
    pub ctime: u32,
    /// `i_mtime` — last data-content modification time.
    pub mtime: u32,
    /// `i_dtime` — deletion time. A non-zero value marks an unlinked inode
    /// slot as deleted until the allocator reuses it.
    pub dtime: u32,
    /// POSIX group owner id (`i_gid` plus Linux `l_i_gid_high`).
    pub gid: u32,
    /// `i_blocks` — count of 512-byte sectors held by the file.
    pub blocks: u32,
    /// `i_links_count` (offset 26). Hard-link refcount.
    pub links_count: u16,
    /// `i_flags` (offset 32). Carries `I_FLAGS_INDEX` for HTREE dirs
    /// and `I_FLAGS_EXTENTS` for ext4 extent-tree inodes.
    pub flags: u32,
    /// `i_generation` (offset 100). ext4 includes this value in inode,
    /// directory-block, and external extent-node checksums.
    pub generation: u32,
    /// `i_block[15]` — block pointers (12 direct + 3 indirect tiers).
    pub block: [u32; I_BLOCK_LEN],
    /// `i_file_acl` (offset 104) plus `l_i_file_acl_high` (offset 118): the
    /// external xattr block, whose sectors `i_blocks` includes. Decoded,
    /// never encoded.
    pub file_acl: u64,
    /// Whether the slot carries any extended attribute: an `i_file_acl`
    /// block, or the in-inode `EXT4_XATTR_MAGIC`. Decoded, never encoded —
    /// a hint that lets a lookup skip the xattr read for the (common)
    /// inode with none, e.g. `DirOps::access_acl_present`.
    pub has_xattrs: bool,
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
        let uid = u16::from_le_bytes([buf[2], buf[3]]) as u32
            | ((u16::from_le_bytes([buf[120], buf[121]]) as u32) << 16);
        let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let atime = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let ctime = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let mtime = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let dtime = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let gid = u16::from_le_bytes([buf[24], buf[25]]) as u32
            | ((u16::from_le_bytes([buf[122], buf[123]]) as u32) << 16);
        let links_count = u16::from_le_bytes([buf[26], buf[27]]);
        let blocks = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let flags = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let generation = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);
        let file_acl = u64::from(u32::from_le_bytes([buf[104], buf[105], buf[106], buf[107]]))
            | (u64::from(u16::from_le_bytes([buf[118], buf[119]])) << 32);
        let ibody = buf.len() > 130 && {
            let magic_at = 128 + u16::from_le_bytes([buf[128], buf[129]]) as usize;
            magic_at + 4 <= buf.len()
                && u32::from_le_bytes([
                    buf[magic_at],
                    buf[magic_at + 1],
                    buf[magic_at + 2],
                    buf[magic_at + 3],
                ]) == 0xEA02_0000
        };
        let mut block = [0u32; I_BLOCK_LEN];
        for (i, b) in block.iter_mut().enumerate() {
            let off = 40 + i * 4;
            *b = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        }
        Some(Self {
            mode,
            uid,
            size,
            atime,
            ctime,
            mtime,
            dtime,
            gid,
            blocks,
            links_count,
            flags,
            generation,
            block,
            file_acl,
            has_xattrs: file_acl != 0 || ibody,
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

    /// `true` when the directory uses HTREE indexing (`EXT4_INDEX_FL`).
    pub fn is_htree(&self) -> bool {
        self.flags & I_FLAGS_INDEX != 0
    }

    /// `true` when `i_block` holds the symlink target text rather than block
    /// pointers or an extent root. Mirrors `fs/ext4/inode.c::
    /// ext4_inode_is_fast_symlink` (non-`ea_inode` arm): an inline-data
    /// inode is never fast, and the external xattr block is excluded from
    /// `i_blocks` before the zero test. `block_size` is the volume block
    /// size, which is the cluster size without bigalloc.
    pub fn is_fast_symlink(&self, block_size: u32) -> bool {
        if !self.is_symlink() || self.flags & I_FLAGS_INLINE_DATA != 0 {
            return false;
        }
        let ea_sectors = if self.file_acl != 0 {
            block_size >> 9
        } else {
            0
        };
        self.blocks.wrapping_sub(ea_sectors) == 0
    }

    /// `true` when this inode's `i_block` stores an ext4 extent root.
    pub fn uses_extents(&self) -> bool {
        self.flags & I_FLAGS_EXTENTS != 0
    }

    /// Encode this inode into a 128-byte buffer. Only fields we
    /// surface (mode/size/atime/ctime/mtime/links/blocks/flags/block)
    /// are written; everything else is preserved by reading the
    /// on-disk bytes first and only overwriting our fields. Caller
    /// should pass `buf` initialised from `read_byte_range` and call
    /// `encode_into` to update.
    pub fn encode_into(&self, buf: &mut [u8]) {
        if buf.len() < 128 {
            return;
        }
        buf[0..2].copy_from_slice(&self.mode.to_le_bytes());
        buf[2..4].copy_from_slice(&(self.uid as u16).to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf[8..12].copy_from_slice(&self.atime.to_le_bytes());
        buf[12..16].copy_from_slice(&self.ctime.to_le_bytes());
        buf[16..20].copy_from_slice(&self.mtime.to_le_bytes());
        buf[20..24].copy_from_slice(&self.dtime.to_le_bytes());
        buf[24..26].copy_from_slice(&(self.gid as u16).to_le_bytes());
        buf[26..28].copy_from_slice(&self.links_count.to_le_bytes());
        buf[28..32].copy_from_slice(&self.blocks.to_le_bytes());
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        buf[100..104].copy_from_slice(&self.generation.to_le_bytes());
        for i in 0..I_BLOCK_LEN {
            let off = 40 + i * 4;
            buf[off..off + 4].copy_from_slice(&self.block[i].to_le_bytes());
        }
        buf[120..122].copy_from_slice(&((self.uid >> 16) as u16).to_le_bytes());
        buf[122..124].copy_from_slice(&((self.gid >> 16) as u16).to_le_bytes());
    }

    /// Build a fresh regular-file inode.
    pub fn new_regular(perms: u16) -> Self {
        Self {
            mode: S_IFREG | (perms & 0o7777),
            uid: 0,
            size: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            gid: 0,
            blocks: 0,
            links_count: 1,
            flags: 0,
            generation: 0,
            block: [0; I_BLOCK_LEN],
            file_acl: 0,
            has_xattrs: false,
        }
    }

    /// Build a fresh directory inode.
    pub fn new_directory(perms: u16) -> Self {
        Self {
            mode: S_IFDIR | (perms & 0o777),
            uid: 0,
            size: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            gid: 0,
            blocks: 0,
            // Fresh dir has links_count = 2 ("." back-link + parent's
            // dirent). The parent gets bumped separately for "..".
            links_count: 2,
            flags: 0,
            generation: 0,
            block: [0; I_BLOCK_LEN],
            file_acl: 0,
            has_xattrs: false,
        }
    }

    /// Build a fresh symlink inode. Caller fills size + block[] for
    /// fast-symlinks (target stored inline in block[]) or allocates
    /// a data block for slow symlinks.
    pub fn new_symlink(perms: u16) -> Self {
        Self {
            mode: S_IFLNK | (perms & 0o777),
            uid: 0,
            size: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            gid: 0,
            blocks: 0,
            links_count: 1,
            flags: 0,
            generation: 0,
            block: [0; I_BLOCK_LEN],
            file_acl: 0,
            has_xattrs: false,
        }
    }

    /// Build a cleared inode-table slot for an inode that has been unlinked.
    /// `i_dtime` remains non-zero after the allocation bit is released so
    /// ext4 tooling never mistakes stale metadata for a live orphan.
    pub fn deleted(now: u32) -> Self {
        Self {
            mode: 0,
            uid: 0,
            size: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: now.max(1),
            gid: 0,
            blocks: 0,
            links_count: 0,
            flags: 0,
            generation: 0,
            block: [0; I_BLOCK_LEN],
            file_acl: 0,
            has_xattrs: false,
        }
    }

    /// Update both `ctime` and `mtime` to `now_secs`. Call on any
    /// mutation that changes directory or file data content.
    pub fn touch_ctime_mtime(&mut self, now_secs: u32) {
        self.ctime = now_secs;
        self.mtime = now_secs;
    }

    /// Update only `ctime` to `now_secs`. Call on link-count or
    /// mode changes that don't alter data content (hardlink, unlink,
    /// rename, chmod).
    pub fn touch_ctime(&mut self, now_secs: u32) {
        self.ctime = now_secs;
    }
}
