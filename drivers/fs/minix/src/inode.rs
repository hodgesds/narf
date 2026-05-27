//! MINIX inode decoding.
//!
//! Clean-room. Layout from:
//! - Tanenbaum, *Operating Systems: Design and Implementation*
//!   (1st ed., Ch. 5) — defines `d1_inode` fields including
//!   `i_zone[9]` (7 direct + 1 indirect + 1 double-indirect).
//! - Tanenbaum & Bos, *Modern Operating Systems* (4th ed.), §4.6 —
//!   defines `d2_inode` fields including `i_zone[10]` (V2/V3 add
//!   a 7th triple-indirect slot).
//! - MINIX 3 reference manual on-disk format documentation.
//!
//! Type bits in `i_mode` are POSIX (`S_IF*`) just like every other
//! Unix inode — directory = 0o040000, regular = 0o100000, symlink
//! = 0o120000.

use super::MinixVersion;

/// Number of direct zone slots in `i_zone[]`. Same on every version.
pub const DIRECT_ZONES: usize = 7;
/// Single-indirect slot index in `i_zone[]`.
pub const IND_SLOT: usize = 7;
/// Double-indirect slot index in `i_zone[]`.
pub const DBL_SLOT: usize = 8;
/// Triple-indirect slot index (V2/V3 only).
pub const TRI_SLOT: usize = 9;

/// File-type bits in `i_mode` (high bits). Tanenbaum §5.5 / POSIX.
pub mod mode {
    pub const IFMT:   u16 = 0o170000;
    pub const IFREG:  u16 = 0o100000;
    pub const IFDIR:  u16 = 0o040000;
    pub const IFLNK:  u16 = 0o120000;
    pub const IFCHR:  u16 = 0o020000;
    pub const IFBLK:  u16 = 0o060000;
    pub const IFIFO:  u16 = 0o010000;
}

/// Decoded inode (version-agnostic). Times collapse onto a single
/// `mtime` field on V1 (V1 only stores one timestamp); V2/V3 carry
/// atime/mtime/ctime separately and we surface mtime here.
#[derive(Debug, Copy, Clone)]
pub struct Inode {
    pub mode: u16,
    pub nlinks: u16,
    pub uid: u16,
    pub gid: u16,
    pub size: u32,
    pub mtime: u32,
    /// Up to 10 zone slots — V1 only fills the first 9, V2/V3 fill
    /// all 10. Unused slots are 0.
    pub zones: [u32; 10],
}

impl Inode {
    /// Decode an inode from a buffer that holds at least one inode's
    /// worth of bytes starting at `offset`.
    pub fn decode(version: MinixVersion, buf: &[u8], offset: usize) -> Option<Self> {
        match version {
            MinixVersion::V1 => Self::decode_v1(buf, offset),
            MinixVersion::V2 | MinixVersion::V3 => Self::decode_v2(buf, offset),
        }
    }

    fn decode_v1(buf: &[u8], offset: usize) -> Option<Self> {
        if offset + 32 > buf.len() {
            return None;
        }
        let s = &buf[offset..offset + 32];
        let u16le = |o: usize| u16::from_le_bytes([s[o], s[o + 1]]);
        let u32le = |o: usize| {
            u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]])
        };
        let mode = u16le(0);
        let uid = u16le(2);
        let size = u32le(4);
        let mtime = u32le(8);
        let gid = s[12] as u16;
        let nlinks = s[13] as u16;
        let mut zones = [0u32; 10];
        for i in 0..9 {
            zones[i] = u16le(14 + i * 2) as u32;
        }
        Some(Self {
            mode,
            nlinks,
            uid,
            gid,
            size,
            mtime,
            zones,
        })
    }

    fn decode_v2(buf: &[u8], offset: usize) -> Option<Self> {
        if offset + 64 > buf.len() {
            return None;
        }
        let s = &buf[offset..offset + 64];
        let u16le = |o: usize| u16::from_le_bytes([s[o], s[o + 1]]);
        let u32le = |o: usize| {
            u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]])
        };
        let mode = u16le(0);
        let nlinks = u16le(2);
        let uid = u16le(4);
        let gid = u16le(6);
        let size = u32le(8);
        let _atime = u32le(12);
        let mtime = u32le(16);
        let _ctime = u32le(20);
        let mut zones = [0u32; 10];
        for i in 0..10 {
            zones[i] = u32le(24 + i * 4);
        }
        Some(Self {
            mode,
            nlinks,
            uid,
            gid,
            size,
            mtime,
            zones,
        })
    }

    pub fn is_dir(&self) -> bool {
        self.mode & mode::IFMT == mode::IFDIR
    }

    pub fn is_reg(&self) -> bool {
        self.mode & mode::IFMT == mode::IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & mode::IFMT == mode::IFLNK
    }

    /// Encode this inode into the on-disk format at `buf[offset..]`.
    /// Inverse of `decode`. Caller must reserve at least the inode-
    /// size bytes (V1 = 32, V2/V3 = 64).
    pub fn encode(&self, version: MinixVersion, buf: &mut [u8], offset: usize) {
        match version {
            MinixVersion::V1 => self.encode_v1(buf, offset),
            MinixVersion::V2 | MinixVersion::V3 => self.encode_v2(buf, offset),
        }
    }

    fn encode_v1(&self, buf: &mut [u8], offset: usize) {
        let s = &mut buf[offset..offset + 32];
        s[0..2].copy_from_slice(&self.mode.to_le_bytes());
        s[2..4].copy_from_slice(&self.uid.to_le_bytes());
        s[4..8].copy_from_slice(&self.size.to_le_bytes());
        s[8..12].copy_from_slice(&self.mtime.to_le_bytes());
        s[12] = self.gid as u8;
        s[13] = self.nlinks as u8;
        // V1 only persists 9 zone slots (7 direct + 1 IND + 1 DBL).
        for i in 0..9 {
            let z16 = self.zones[i] as u16;
            s[14 + i * 2..14 + i * 2 + 2].copy_from_slice(&z16.to_le_bytes());
        }
    }

    fn encode_v2(&self, buf: &mut [u8], offset: usize) {
        let s = &mut buf[offset..offset + 64];
        // Zero the V2 layout first so reserved slots are stable.
        for b in s.iter_mut() {
            *b = 0;
        }
        s[0..2].copy_from_slice(&self.mode.to_le_bytes());
        s[2..4].copy_from_slice(&self.nlinks.to_le_bytes());
        s[4..6].copy_from_slice(&self.uid.to_le_bytes());
        s[6..8].copy_from_slice(&self.gid.to_le_bytes());
        s[8..12].copy_from_slice(&self.size.to_le_bytes());
        // _atime (12..16) left zero — we don't track atime.
        s[16..20].copy_from_slice(&self.mtime.to_le_bytes());
        // _ctime (20..24) — Linux mirrors mtime when ctime is not
        // independently tracked. Matches mkfs.minix output on quiet
        // mounts.
        s[20..24].copy_from_slice(&self.mtime.to_le_bytes());
        for i in 0..10 {
            s[24 + i * 4..24 + i * 4 + 4]
                .copy_from_slice(&self.zones[i].to_le_bytes());
        }
    }

    /// Build a fresh regular-file inode. `mode_bits` are the low 9
    /// POSIX bits; `IFREG` is OR'd in here.
    pub fn new_regular(mode_bits: u16, mtime: u32) -> Self {
        Self {
            mode: mode::IFREG | (mode_bits & 0o777),
            nlinks: 1,
            uid: 0,
            gid: 0,
            size: 0,
            mtime,
            zones: [0; 10],
        }
    }

    /// Build a fresh directory inode. `nlinks` starts at 2 (self +
    /// `.` reference back to itself) per Tanenbaum §5.
    pub fn new_directory(mode_bits: u16, mtime: u32) -> Self {
        Self {
            mode: mode::IFDIR | (mode_bits & 0o777),
            nlinks: 2,
            uid: 0,
            gid: 0,
            size: 0,
            mtime,
            zones: [0; 10],
        }
    }

    /// Build a fresh symlink inode. Body is the textual target,
    /// written via `write_file` (MINIX inlines short symlinks in
    /// `zones[0]` but treating them as regular files works too).
    pub fn new_symlink(mtime: u32) -> Self {
        Self {
            mode: mode::IFLNK | 0o777,
            nlinks: 1,
            uid: 0,
            gid: 0,
            size: 0,
            mtime,
            zones: [0; 10],
        }
    }
}
