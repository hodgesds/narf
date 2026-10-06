//! Inode items (`struct btrfs_inode_item`) and file-type mapping.

use narf_filesystem::{FileType, FsError};

use crate::format::{le32, le64};

// Field offsets within `struct btrfs_inode_item` (160 bytes total).
const OFF_SIZE: usize = 16;
const OFF_NLINK: usize = 40;
const OFF_UID: usize = 44;
const OFF_GID: usize = 48;
const OFF_MODE: usize = 52;
const OFF_RDEV: usize = 56;
// `struct btrfs_timespec {__le64 sec; __le32 nsec}` (12 bytes, packed):
// atime@112, ctime@124, mtime@136, otime@148.
const OFF_ATIME: usize = 112;
const OFF_CTIME: usize = 124;
const OFF_MTIME: usize = 136;
const OFF_OTIME: usize = 148;
/// Minimum decodable inode-item length (the full 160-byte item, through the
/// otime timespec).
const INODE_ITEM_MIN: usize = OFF_OTIME + 12;

// Linux `S_IFMT` file-type bits within the mode word.
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;
const S_IFBLK: u32 = 0o060000;
const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;
const S_IFIFO: u32 = 0o010000;

/// Decoded `btrfs_inode_item` — the fields the driver surfaces via stat.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InodeItem {
    pub size: u64,
    /// Full Linux mode word (`S_IF*` type bits | permission bits).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    /// Device number for a char/block special file (`0` otherwise).
    pub rdev: u64,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    /// Creation time (`otime`), reported as statx `btime`.
    pub otime_sec: i64,
    pub otime_nsec: u32,
}

/// Wall-clock nanoseconds for one `btrfs_timespec`. Linux hands the on-disk
/// `sec`/`nsec` pair to `inode_set_*time` verbatim (`btrfs_read_locked_inode`),
/// so the value is exact to the nanosecond. A time before the epoch clamps to
/// 0: [`narf_filesystem::InodeAttrs`] is unsigned.
pub fn timespec_ns(sec: i64, nsec: u32) -> u64 {
    if sec < 0 {
        return 0;
    }
    (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(nsec))
}

fn timespec(body: &[u8], off: usize) -> Result<(i64, u32), FsError> {
    Ok((le64(body, off)? as i64, le32(body, off + 8)?))
}

impl InodeItem {
    /// Decode an inode item from a leaf item body.
    pub fn decode(body: &[u8]) -> Result<Self, FsError> {
        if body.len() < INODE_ITEM_MIN {
            return Err(FsError::InvalidData);
        }
        let (atime_sec, atime_nsec) = timespec(body, OFF_ATIME)?;
        let (ctime_sec, ctime_nsec) = timespec(body, OFF_CTIME)?;
        let (mtime_sec, mtime_nsec) = timespec(body, OFF_MTIME)?;
        let (otime_sec, otime_nsec) = timespec(body, OFF_OTIME)?;
        Ok(InodeItem {
            size: le64(body, OFF_SIZE)?,
            mode: le32(body, OFF_MODE)?,
            uid: le32(body, OFF_UID)?,
            gid: le32(body, OFF_GID)?,
            nlink: le32(body, OFF_NLINK)?,
            rdev: le64(body, OFF_RDEV)?,
            atime_sec,
            atime_nsec,
            ctime_sec,
            ctime_nsec,
            mtime_sec,
            mtime_nsec,
            otime_sec,
            otime_nsec,
        })
    }

    /// `st_atim` in wall-clock nanoseconds.
    pub fn atime_ns(&self) -> u64 {
        timespec_ns(self.atime_sec, self.atime_nsec)
    }

    /// `st_ctim` in wall-clock nanoseconds.
    pub fn ctime_ns(&self) -> u64 {
        timespec_ns(self.ctime_sec, self.ctime_nsec)
    }

    /// `st_mtim` in wall-clock nanoseconds. fontconfig validates its caches
    /// against a font directory's exact `st_mtim`, so this must not lose the
    /// on-disk nanoseconds.
    pub fn mtime_ns(&self) -> u64 {
        timespec_ns(self.mtime_sec, self.mtime_nsec)
    }

    /// Decompose `rdev` into `(major, minor)`. btrfs stores the **raw kernel
    /// `dev_t`** (`MKDEV(major, minor) == (major << 20) | minor`, `MINORBITS ==
    /// 20`) — `btrfs_set_inode_rdev(item, inode->i_rdev)` with no re-encoding —
    /// not the packed userspace `dev_t`.
    pub fn rdev_major_minor(&self) -> (u32, u32) {
        let d = self.rdev;
        ((d >> 20) as u32, (d & 0xf_ffff) as u32)
    }

    /// Low 12 permission/special mode bits.
    pub fn perms(&self) -> u16 {
        (self.mode & 0o7777) as u16
    }

    /// VFS file type derived from the mode's `S_IFMT` bits.
    pub fn file_type(&self) -> FileType {
        file_type_from_mode(self.mode)
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// Map a Linux mode word to the VFS [`FileType`].
pub fn file_type_from_mode(mode: u32) -> FileType {
    match mode & S_IFMT {
        S_IFDIR => FileType::Dir,
        S_IFLNK => FileType::Symlink,
        S_IFCHR => FileType::Special,
        S_IFBLK => FileType::Block,
        S_IFIFO => FileType::Fifo,
        S_IFSOCK => FileType::Socket,
        // S_IFREG and anything unrecognised present as a regular file.
        _ => FileType::File,
    }
}
