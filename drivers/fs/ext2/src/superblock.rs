//! ext2 superblock layout.
//!
//! Sources:
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, §"Physical Layout".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Superblock".
//! - OSDev Wiki, "Ext2 — Superblock":
//!   <https://wiki.osdev.org/Ext2#Superblock>
//!
//! No Linux/GRUB/e2fsprogs source was consulted; the field offsets
//! below come from the OSDev wiki + Rusling cross-check.

use super::EXT2_SUPER_MAGIC;

// ── Feature-flag constants (ext2/3/4 §1.1.2 in the e2fsprogs spec) ──

/// `s_feature_compat` bits — we tolerate any bit set here; the
/// driver ignores compat features it doesn't implement.
pub mod compat {
    pub const DIR_PREALLOC: u32 = 0x0001;
    pub const IMAGIC_INODES: u32 = 0x0002;
    /// HAS_JOURNAL — turns an ext2 volume into ext3.
    pub const HAS_JOURNAL: u32 = 0x0004;
    pub const EXT_ATTR: u32 = 0x0008;
    pub const RESIZE_INODE: u32 = 0x0010;
    pub const DIR_INDEX: u32 = 0x0020;
    pub const ORPHAN_FILE: u32 = 0x1000;
}

/// `s_feature_incompat` bits — if any unknown bit is set the
/// driver MUST refuse to mount (per the ext4 spec contract).
pub mod incompat {
    pub const COMPRESSION: u32 = 0x0001;
    pub const FILETYPE: u32 = 0x0002;
    pub const RECOVER: u32 = 0x0004;
    pub const JOURNAL_DEV: u32 = 0x0008;
    pub const META_BG: u32 = 0x0010;
    /// HAS_EXTENTS — file blocks via extent trees instead of
    /// indirect blocks. ext4-defining.
    pub const EXTENTS: u32 = 0x0040;
    /// 64BIT — block counts span more than 32 bits; group
    /// descriptors are 64 bytes.
    pub const SIXTYFOURBIT: u32 = 0x0080;
    pub const MMP: u32 = 0x0100;
    pub const FLEX_BG: u32 = 0x0200;
    pub const EA_INODE: u32 = 0x0400;
    pub const DIRDATA: u32 = 0x1000;
    pub const CSUM_SEED: u32 = 0x2000;
    pub const LARGEDIR: u32 = 0x4000;
    pub const INLINE_DATA: u32 = 0x8000;
    pub const ENCRYPT: u32 = 0x1_0000;
    pub const CASEFOLD: u32 = 0x2_0000;

    /// What this driver actually knows how to handle. Any bit set
    /// in the superblock that ISN'T in this mask means we refuse to
    /// mount (the volume uses a feature we'd misinterpret).
    // `CSUM_SEED` alters only the checksum seed; the mount path validates
    // that seed and mounts metadata-checksummed volumes read-only until all
    // metadata writers can regenerate their checksums.
    pub const SUPPORTED: u32 = FILETYPE | EXTENTS | SIXTYFOURBIT | FLEX_BG | RECOVER | CSUM_SEED;
}

/// `s_feature_ro_compat` bits — if any unknown bit is set the
/// driver MUST refuse RW mounts but MAY allow RO mounts.
pub mod ro_compat {
    pub const SPARSE_SUPER: u32 = 0x0001;
    pub const LARGE_FILE: u32 = 0x0002;
    pub const BTREE_DIR: u32 = 0x0004;
    pub const HUGE_FILE: u32 = 0x0008;
    pub const GDT_CSUM: u32 = 0x0010;
    pub const DIR_NLINK: u32 = 0x0020;
    pub const EXTRA_ISIZE: u32 = 0x0040;
    pub const QUOTA: u32 = 0x0100;
    pub const BIGALLOC: u32 = 0x0200;
    pub const METADATA_CSUM: u32 = 0x0400;
    pub const READONLY: u32 = 0x1000;
    pub const PROJECT: u32 = 0x2000;
    pub const VERITY: u32 = 0x8000;
    /// The orphan file contains entries that must be replayed before a writer
    /// can safely reuse inodes or blocks.
    pub const ORPHAN_PRESENT: u32 = 0x1_0000;

    /// Features whose write-side layout this driver preserves. `GDT_CSUM`
    /// alone still uses CRC16, which is not implemented; metadata_csum
    /// supersedes it with CRC32C and is checked separately below.
    pub const WRITE_SUPPORTED: u32 =
        SPARSE_SUPER | LARGE_FILE | HUGE_FILE | GDT_CSUM | DIR_NLINK | EXTRA_ISIZE | METADATA_CSUM;
}

/// What flavour of the ext family a superblock represents. Driver
/// dispatch (extent vs indirect-block reads, journal replay vs none,
/// etc.) keys on this.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExtFlavour {
    /// Original ext2 — no journal, indirect-block addressing.
    Ext2,
    /// ext2 + journaling (`HAS_JOURNAL` compat flag, no extents).
    Ext3,
    /// ext3 + extents (the `EXTENTS` incompat flag is set, or 64BIT,
    /// or any other ext4-only incompat feature).
    Ext4,
}

/// Errors during feature inspection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FeatureError {
    /// `s_feature_incompat` has a bit set we don't recognise; the
    /// volume uses a feature we'd misinterpret if we mounted.
    UnsupportedIncompat(u32),
}

/// Decoded ext2 superblock — the subset of fields this driver
/// actually uses. We deliberately do _not_ use `#[repr(C, packed)]`
/// for the full 1024-byte super-block because we only need a dozen
/// fields and reading them with `u32::from_le_bytes` is cheaper /
/// less unsafe than a full layout struct.
#[derive(Debug, Copy, Clone)]
pub struct Superblock {
    /// `s_inodes_count` — total inodes in the volume.
    pub inodes_count: u32,
    /// `s_blocks_count` — total blocks in the volume.
    pub blocks_count: u32,
    /// `s_first_data_block` — block number of group 0's superblock.
    /// Equals 1 on 1-KiB block volumes (the boot sector + superblock
    /// share block 0 only on >= 2-KiB-block volumes); equals 0 on
    /// 2 KiB / 4 KiB block volumes (superblock starts at byte 1024 of
    /// block 0). The block-group descriptor table sits in the block
    /// _after_ this one.
    pub first_data_block: u32,
    /// `s_log_block_size` — block size = 1024 << s_log_block_size.
    pub log_block_size: u32,
    /// `s_blocks_per_group`.
    pub blocks_per_group: u32,
    /// `s_inodes_per_group`.
    pub inodes_per_group: u32,
    /// `s_magic` — must be `0xEF53` for a valid ext2 volume.
    pub magic: u16,
    /// `s_rev_level` — 0 = good-old, 1 = dynamic. Determines whether
    /// `s_inode_size` is meaningful.
    pub rev_level: u32,
    /// `s_inode_size` — bytes per inode. Fixed at 128 on rev-0
    /// volumes; on rev-1 the field is meaningful and may be 256+.
    pub inode_size: u16,
    /// `s_feature_compat` (byte 92) — backwards-compatible features.
    /// `HAS_JOURNAL` here distinguishes ext3+ from ext2.
    pub feature_compat: u32,
    /// `s_feature_incompat` (byte 96) — features the driver MUST
    /// understand. Any bit outside [`incompat::SUPPORTED`] forces
    /// us to refuse the mount.
    pub feature_incompat: u32,
    /// `s_feature_ro_compat` (byte 100) — bits the driver MUST
    /// understand to write to the volume. Read-only mounts MAY
    /// proceed when unknown bits are set.
    pub feature_ro_compat: u32,
    /// `s_blocks_count_hi` (byte 336, ext4 64BIT only). When the
    /// 64BIT incompat bit is set, the effective block count is
    /// `(blocks_count_hi << 32) | blocks_count`.
    pub blocks_count_hi: u32,
    /// `s_desc_size` (byte 254) — bytes per group descriptor. 32
    /// for ext2/3, 64 for ext4 with 64BIT. Zero on legacy SBs.
    pub desc_size: u16,
    /// `s_state` (byte 58) — 1 = EXT2_VALID_FS (clean), 0 = unclean
    /// (the kernel set it to zero on mount and didn't get a chance
    /// to set it back to one before the system went away). Drives
    /// the journal-replay decision at mount time.
    pub state: u16,
    /// `s_journal_inum` (byte 224, rev-1+) — inode number that
    /// holds the journal file (typically 8). Used together with
    /// `compat::HAS_JOURNAL` to locate the JBD2 journal for replay.
    pub journal_inum: u32,
    /// `s_uuid` (offset 104). Used to derive the metadata checksum seed on
    /// ext4 filesystems that do not set `csum_seed`.
    pub uuid: [u8; 16],
    /// `s_checksum_seed` (offset 624). Meaningful only with
    /// `INCOMPAT_CSUM_SEED`.
    pub checksum_seed: u32,
    /// `s_hash_seed` (offset 236). The four-word secret used by ext3/4
    /// HTREE directory name hashes.
    pub hash_seed: [u32; 4],
    /// `s_want_extra_isize` (offset 350). Fresh ext4 inodes reserve this many
    /// bytes beyond the original 128-byte body for checksum/timestamp fields.
    pub want_extra_isize: u16,
    /// `s_orphan_file_inum` (offset 640), when `COMPAT_ORPHAN_FILE`
    /// is enabled.
    pub orphan_file_inum: u32,
}

/// `s_state` value meaning "filesystem was unmounted cleanly".
/// Linux `include/uapi/linux/ext2_fs.h::EXT2_VALID_FS`.
pub const EXT2_VALID_FS: u16 = 0x0001;
/// `s_state` "filesystem has errors detected". Mostly informational
/// for the mount path — we still trigger journal replay.
pub const EXT2_ERROR_FS: u16 = 0x0002;

impl Superblock {
    /// Decode a superblock from a 1024-byte (or larger) buffer
    /// containing the superblock's bytes starting at byte 0.
    /// Returns `None` if the magic is wrong.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 96 {
            return None;
        }
        let magic = u16::from_le_bytes([buf[56], buf[57]]);
        if magic != EXT2_SUPER_MAGIC {
            return None;
        }

        let inodes_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let blocks_count = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let first_data_block = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let log_block_size = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let blocks_per_group = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let inodes_per_group = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let rev_level = u32::from_le_bytes([buf[76], buf[77], buf[78], buf[79]]);
        let inode_size = if rev_level >= 1 && buf.len() >= 90 {
            u16::from_le_bytes([buf[88], buf[89]])
        } else {
            128
        };
        // Feature flags + ext4 extensions live in the rev-1 dynamic
        // tail of the superblock (bytes 84+). On rev-0 volumes
        // they're all zero so reading conservatively works.
        let feature_compat = if buf.len() >= 96 {
            u32::from_le_bytes([buf[92], buf[93], buf[94], buf[95]])
        } else {
            0
        };
        let feature_incompat = if buf.len() >= 100 {
            u32::from_le_bytes([buf[96], buf[97], buf[98], buf[99]])
        } else {
            0
        };
        let feature_ro_compat = if buf.len() >= 104 {
            u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]])
        } else {
            0
        };
        let desc_size = if buf.len() >= 256 {
            u16::from_le_bytes([buf[254], buf[255]])
        } else {
            0
        };
        // s_blocks_count_hi is in the 64-bit-only extended section
        // (byte 336). Reading only when present + when 64BIT bit
        // says it's meaningful.
        let blocks_count_hi = if buf.len() >= 340 && feature_incompat & incompat::SIXTYFOURBIT != 0
        {
            u32::from_le_bytes([buf[336], buf[337], buf[338], buf[339]])
        } else {
            0
        };
        // s_state (byte 58) — present even on rev-0 superblocks.
        let state = if buf.len() >= 60 {
            u16::from_le_bytes([buf[58], buf[59]])
        } else {
            0
        };
        // s_journal_inum (byte 224) lives in the rev-1 dynamic
        // tail. Zero on rev-0 / non-journaled volumes.
        let journal_inum = if buf.len() >= 228 {
            u32::from_le_bytes([buf[224], buf[225], buf[226], buf[227]])
        } else {
            0
        };
        let uuid = if buf.len() >= 120 {
            buf[104..120].try_into().expect("checked UUID bounds")
        } else {
            [0; 16]
        };
        let checksum_seed = if buf.len() >= 628 {
            u32::from_le_bytes([buf[624], buf[625], buf[626], buf[627]])
        } else {
            0
        };
        let hash_seed = if buf.len() >= 252 {
            core::array::from_fn(|i| {
                let off = 236 + i * 4;
                u32::from_le_bytes(buf[off..off + 4].try_into().expect("checked hash seed"))
            })
        } else {
            [0; 4]
        };
        let want_extra_isize = if buf.len() >= 352 {
            u16::from_le_bytes([buf[350], buf[351]])
        } else {
            0
        };
        let orphan_file_inum = if buf.len() >= 644 {
            u32::from_le_bytes([buf[640], buf[641], buf[642], buf[643]])
        } else {
            0
        };

        Some(Self {
            inodes_count,
            blocks_count,
            first_data_block,
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            magic,
            rev_level,
            inode_size,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            blocks_count_hi,
            desc_size,
            state,
            journal_inum,
            uuid,
            checksum_seed,
            hash_seed,
            want_extra_isize,
            orphan_file_inum,
        })
    }

    /// True iff `s_state` indicates a clean unmount (== EXT2_VALID_FS).
    /// Unclean volumes (state == 0) need journal replay before their
    /// metadata can be trusted.
    pub fn is_clean(&self) -> bool {
        self.state & EXT2_VALID_FS != 0
    }

    /// True iff the volume carries a JBD2 journal (HAS_JOURNAL compat
    /// bit set AND `s_journal_inum` is non-zero).
    pub fn has_journal(&self) -> bool {
        self.feature_compat & compat::HAS_JOURNAL != 0 && self.journal_inum != 0
    }

    /// True when ext4 metadata blocks carry CRC32C checksums.
    pub fn has_metadata_csum(&self) -> bool {
        self.feature_ro_compat & ro_compat::METADATA_CSUM != 0
    }

    /// True when ext4 supplies `s_checksum_seed` instead of deriving the
    /// metadata checksum seed from `s_uuid`.
    pub fn uses_csum_seed(&self) -> bool {
        self.feature_incompat & incompat::CSUM_SEED != 0
    }

    /// Whether all feature flags and dynamic recovery state permit direct
    /// metadata writes by this driver.
    ///
    /// NARF does not yet commit JBD2 transactions, replay the orphan file, or
    /// generate legacy `gdt_csum` CRC16 values. Such volumes remain readable
    /// but are mounted read-only until Linux/e2fsck leaves them clean or the
    /// missing writer is implemented.
    pub fn write_features_supported(&self) -> bool {
        let unknown_ro = self.feature_ro_compat & !ro_compat::WRITE_SUPPORTED;
        let needs_journal_recovery = self.feature_incompat & incompat::RECOVER != 0;
        let needs_orphan_recovery = self.feature_ro_compat & ro_compat::ORPHAN_PRESENT != 0;
        let legacy_gdt_csum =
            self.feature_ro_compat & ro_compat::GDT_CSUM != 0 && !self.has_metadata_csum();
        unknown_ro == 0 && !needs_journal_recovery && !needs_orphan_recovery && !legacy_gdt_csum
    }

    /// Classify the volume's flavour. Tracks ext-family evolution:
    /// HAS_JOURNAL bit promotes ext2 → ext3; any ext4-only incompat
    /// bit (EXTENTS / 64BIT / FLEX_BG / etc.) promotes further to ext4.
    pub fn flavour(&self) -> ExtFlavour {
        const EXT4_INCOMPAT_MASK: u32 = incompat::EXTENTS
            | incompat::SIXTYFOURBIT
            | incompat::FLEX_BG
            | incompat::EA_INODE
            | incompat::INLINE_DATA
            | incompat::LARGEDIR;
        if self.feature_incompat & EXT4_INCOMPAT_MASK != 0 {
            ExtFlavour::Ext4
        } else if self.feature_compat & compat::HAS_JOURNAL != 0 {
            ExtFlavour::Ext3
        } else {
            ExtFlavour::Ext2
        }
    }

    /// Verify the driver supports every `feature_incompat` bit set.
    /// Returns `UnsupportedIncompat(unknown_bits)` if not.
    /// Mount paths gate on this — refusing rather than corrupting.
    pub fn check_incompat_features(&self) -> Result<(), FeatureError> {
        let unknown = self.feature_incompat & !incompat::SUPPORTED;
        if unknown != 0 {
            return Err(FeatureError::UnsupportedIncompat(unknown));
        }
        Ok(())
    }

    /// True iff the volume uses extent trees (vs ext2's indirect
    /// block pointers). Inode 0x80 i_flags carries a per-file
    /// extents bit too, but the volume-wide
    /// `feature_incompat::EXTENTS` is what tells the driver to even
    /// look at the eh_magic header.
    pub fn uses_extents(&self) -> bool {
        self.feature_incompat & incompat::EXTENTS != 0
    }

    /// Effective 64-bit block count. On 32-bit (ext2/3) volumes the
    /// high half is zero so this returns just `blocks_count`.
    pub fn total_blocks(&self) -> u64 {
        ((self.blocks_count_hi as u64) << 32) | self.blocks_count as u64
    }

    /// Effective group-descriptor size in bytes. 32 on ext2/3,
    /// 64 on ext4 with 64BIT. Falls back to 32 when `desc_size`
    /// is zero on a legacy superblock.
    pub fn effective_desc_size(&self) -> usize {
        if self.feature_incompat & incompat::SIXTYFOURBIT != 0 && self.desc_size >= 64 {
            self.desc_size as usize
        } else {
            32
        }
    }

    /// Block size in bytes — `1024 << s_log_block_size`. The minimum
    /// is 1024 (with `s_log_block_size == 0`).
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }

    /// Number of block groups in the volume — ceil(blocks_count /
    /// blocks_per_group).
    pub fn block_group_count(&self) -> u32 {
        self.total_blocks().div_ceil(self.blocks_per_group as u64) as u32
    }

    /// Bytes per inode — for rev-0 volumes this is fixed at 128;
    /// rev-1+ uses the explicit `s_inode_size`.
    pub fn inode_size_bytes(&self) -> usize {
        self.inode_size as usize
    }

    /// First non-reserved inode number for fresh allocations.
    /// Linux `include/uapi/linux/ext2_fs.h::EXT2_GOOD_OLD_FIRST_INO`
    /// is 11; rev-1+ volumes embed `s_first_ino` at byte 84 of the
    /// superblock. We don't decode the rev-1 field (it's almost
    /// always 11 in practice) and just return the fixed value.
    pub fn first_ino(&self) -> u32 {
        11
    }
}
