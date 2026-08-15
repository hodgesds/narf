//! Directory items (`struct btrfs_dir_item`): name → inode resolution.
//!
//! A directory has two parallel item streams keyed on its inode objectid:
//! `DIR_ITEM` (keyed by the CRC32C name hash, used for name lookup) and
//! `DIR_INDEX` (keyed by a monotonic sequence, used for stable readdir order).
//! Both carry a `btrfs_dir_item` whose `location` key names the child.
//!
//! A single `DIR_ITEM` body may hold several concatenated entries when name
//! hashes collide, so decoding walks the body until it is consumed.

use alloc::string::String;
use alloc::vec::Vec;

use narf_filesystem::{FileType, FsError};

use crate::format::{self, le16, BtrfsKey};

/// Fixed header size of `struct btrfs_dir_item` (location key + transid +
/// data_len + name_len + type), before the inline name bytes.
const DIR_ITEM_HEADER: usize = format::DISK_KEY_SIZE + 8 + 2 + 2 + 1;

/// One decoded directory entry. The same `btrfs_dir_item` layout backs
/// `DIR_ITEM`/`DIR_INDEX` and `XATTR_ITEM`; for an xattr, `name` is the
/// attribute name and `value` is its data (empty for ordinary dir entries).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    /// Key of the child object (`INODE_ITEM` for files/dirs, `ROOT_ITEM` for a
    /// subvolume mount point). Unused for xattrs.
    pub location: BtrfsKey,
    /// `BTRFS_FT_*` directory entry type.
    pub ftype: u8,
    /// Trailing item data — the attribute value for an `XATTR_ITEM`.
    pub value: Vec<u8>,
}

impl DirEntry {
    /// The child object id (inode number for a regular child).
    pub fn child_objectid(&self) -> u64 {
        self.location.objectid
    }

    /// Whether the child location refers to an inode in this same tree (as
    /// opposed to a subvolume `ROOT_ITEM`, which this driver does not descend).
    pub fn is_inode(&self) -> bool {
        self.location.item_type == format::INODE_ITEM_KEY
    }

    /// VFS file type from the `BTRFS_FT_*` byte.
    pub fn file_type(&self) -> FileType {
        match self.ftype {
            format::FT_DIR => FileType::Dir,
            format::FT_SYMLINK => FileType::Symlink,
            format::FT_CHRDEV => FileType::Special,
            format::FT_BLKDEV => FileType::Block,
            format::FT_FIFO => FileType::Fifo,
            format::FT_SOCK => FileType::Socket,
            _ => FileType::File,
        }
    }
}

/// Decode every `btrfs_dir_item` packed into one item `body`.
pub fn decode_dir_items(body: &[u8]) -> Result<Vec<DirEntry>, FsError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < DIR_ITEM_HEADER {
            return Err(FsError::InvalidData);
        }
        let location = BtrfsKey::decode(body, pos)?;
        let data_len = le16(body, pos + format::DISK_KEY_SIZE + 8)? as usize;
        let name_len = le16(body, pos + format::DISK_KEY_SIZE + 10)? as usize;
        let ftype = body[pos + format::DISK_KEY_SIZE + 12];
        let name_start = pos + DIR_ITEM_HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(FsError::InvalidData)?;
        let name_bytes = body.get(name_start..name_end).ok_or(FsError::InvalidData)?;
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| FsError::InvalidData)?
            .into();
        // The value (xattr data) follows the name; ordinary dir items have
        // data_len == 0.
        let value_end = name_end.checked_add(data_len).ok_or(FsError::InvalidData)?;
        let value = body
            .get(name_end..value_end)
            .ok_or(FsError::InvalidData)?
            .to_vec();
        entries.push(DirEntry {
            name,
            location,
            ftype,
            value,
        });
        pos = value_end;
    }
    Ok(entries)
}

/// Return the entry named `name` from a possibly hash-colliding item body.
pub fn find_dir_item(body: &[u8], name: &str) -> Result<DirEntry, FsError> {
    decode_dir_items(body)?
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or(FsError::NotFound)
}

/// Remove exactly the record named `name` from a packed item body while
/// preserving every other record byte-for-byte. The returned body is empty when
/// the removed record was the bucket's only entry.
pub fn remove_dir_item(body: &[u8], name: &str) -> Result<Vec<u8>, FsError> {
    let mut remaining = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    let mut found = false;
    while pos < body.len() {
        if body.len() - pos < DIR_ITEM_HEADER {
            return Err(FsError::InvalidData);
        }
        let data_len = le16(body, pos + format::DISK_KEY_SIZE + 8)? as usize;
        let name_len = le16(body, pos + format::DISK_KEY_SIZE + 10)? as usize;
        let name_start = pos + DIR_ITEM_HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(FsError::InvalidData)?;
        let record_end = name_end.checked_add(data_len).ok_or(FsError::InvalidData)?;
        let name_bytes = body.get(name_start..name_end).ok_or(FsError::InvalidData)?;
        body.get(pos..record_end).ok_or(FsError::InvalidData)?;
        if name_bytes == name.as_bytes() {
            if found {
                return Err(FsError::InvalidData); // duplicate name in one bucket
            }
            found = true;
        } else {
            remaining.extend_from_slice(&body[pos..record_end]);
        }
        pos = record_end;
    }
    if found {
        Ok(remaining)
    } else {
        Err(FsError::NotFound)
    }
}

/// Append `record` to an existing collision bucket. An exact duplicate name is
/// rejected; a different name with the same hash is the normal append case.
pub fn append_dir_item(body: Option<&[u8]>, name: &str, record: &[u8]) -> Result<Vec<u8>, FsError> {
    let mut out = body.unwrap_or_default().to_vec();
    if decode_dir_items(&out)?
        .iter()
        .any(|entry| entry.name == name)
    {
        return Err(FsError::InvalidData);
    }
    out.extend_from_slice(record);
    Ok(out)
}
