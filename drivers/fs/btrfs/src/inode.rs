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
const OFF_MTIME_SEC: usize = 136;
const OFF_MTIME_NSEC: usize = 144;
/// Minimum decodable inode-item length (through the mtime timespec).
const INODE_ITEM_MIN: usize = OFF_MTIME_NSEC + 4;

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
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

impl InodeItem {
    /// Decode an inode item from a leaf item body.
    pub fn decode(body: &[u8]) -> Result<Self, FsError> {
        if body.len() < INODE_ITEM_MIN {
            return Err(FsError::InvalidData);
        }
        Ok(InodeItem {
            size: le64(body, OFF_SIZE)?,
            mode: le32(body, OFF_MODE)?,
            uid: le32(body, OFF_UID)?,
            gid: le32(body, OFF_GID)?,
            nlink: le32(body, OFF_NLINK)?,
            rdev: le64(body, OFF_RDEV)?,
            mtime_sec: le64(body, OFF_MTIME_SEC)? as i64,
            mtime_nsec: le32(body, OFF_MTIME_NSEC)?,
        })
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
