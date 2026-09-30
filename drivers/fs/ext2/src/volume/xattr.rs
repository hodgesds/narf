//! ext2/3/4 extended attributes, including POSIX ACLs — `fs/ext4/xattr.c`
//! and `fs/ext4/acl.c`.
//!
//! The driver had no xattr store at all: `set_xattr` fell through to the
//! trait's `Unsupported`, which the syscall layer answers with -EOPNOTSUPP
//! for the two ACL names. systemd-tmpfiles treats that as "ACLs not
//! supported by this filesystem" and skips its `a+` lines, so
//! /var/log/journal and its files never got `group:adm:r-x` /
//! `group:wheel:r-x` and those users could not read the journal. The ACL
//! enforcement (`acl_permission_check`) and inheritance
//! (`posix_acl_create`) already live in the VFS; they need the filesystem
//! to store and return the bytes.
//!
//! On-disk layout (`fs/ext4/xattr.h`):
//! - in-inode ("ibody"): after `128 + i_extra_isize`, a 4-byte
//!   `EXT4_XATTR_MAGIC`, then entries; value offsets are relative to the
//!   first entry (`IFIRST`) and values sit at the end of the inode slot.
//! - one external block at `i_file_acl`: a 32-byte header (magic,
//!   refcount, blocks = 1, hash, checksum), entries from offset 32 sorted by
//!   (index, name length, name), values at the end, offsets relative to the
//!   block. Counted in `i_blocks`; shared blocks carry `h_refcount > 1`.
//! - entry: name_len, name_index, value_offs, value_inum, value_size, hash,
//!   name; `EXT4_XATTR_LEN` = `(name_len + 16 + 3) & !3`.
//! - ACL values use ext4's own format (`ext4_acl_to_disk`): version 1, and
//!   the four "object" tags as 4-byte short entries, `ACL_USER` /
//!   `ACL_GROUP` as 8-byte entries.
//!
//! New attributes go into the inode body while they fit and spill into the
//! block otherwise (`ext4_xattr_set_handle`: ibody first, then block).
//!
//! LINUX-GAP: values stored in an EA inode (`e_value_inum != 0`,
//! `ea_inode` feature) are not read (such entries are skipped) and never
//! written — a value too large for the inode body or one block is -ENOSPC,
//! which is Linux's answer without `ea_inode`. Shared blocks are
//! copied-on-write when changed but new blocks are never deduplicated
//! (no mbcache).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{AclEntry, FsError, PosixAcl};

use super::{metadata_csum, Ext2Volume};

const XATTR_MAGIC: u32 = 0xEA02_0000;
const BLOCK_HEADER_LEN: usize = 32;
const ENTRY_HEAD: usize = 16;

const INDEX_USER: u8 = 1;
const INDEX_POSIX_ACL_ACCESS: u8 = 2;
const INDEX_POSIX_ACL_DEFAULT: u8 = 3;
const INDEX_TRUSTED: u8 = 4;
const INDEX_SECURITY: u8 = 6;
const INDEX_SYSTEM: u8 = 7;

/// `EXT4_FEATURE_COMPAT_EXT_ATTR`, set by `ext4_xattr_update_super_block`
/// when the first attribute is written.
const COMPAT_EXT_ATTR: u32 = 0x0008;
/// `EXT4_ACL_VERSION`.
const EXT4_ACL_VERSION: u32 = 0x0001;

fn corrupt() -> FsError {
    FsError::InvalidData
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

/// One stored attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XEntry {
    pub(crate) index: u8,
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

impl XEntry {
    fn entry_len(&self) -> usize {
        (self.name.len() + ENTRY_HEAD + 3) & !3
    }
    fn value_len(&self) -> usize {
        (self.value.len() + 3) & !3
    }
}

/// `ext4_xattr_handler_map` + the handlers' prefixes: a user-visible name to
/// `(name_index, suffix)`.
pub(crate) fn split_name(name: &str) -> Option<(u8, &[u8])> {
    if name == narf_filesystem::XATTR_NAME_POSIX_ACL_ACCESS {
        return Some((INDEX_POSIX_ACL_ACCESS, b""));
    }
    if name == narf_filesystem::XATTR_NAME_POSIX_ACL_DEFAULT {
        return Some((INDEX_POSIX_ACL_DEFAULT, b""));
    }
    for (prefix, index) in [
        ("user.", INDEX_USER),
        ("trusted.", INDEX_TRUSTED),
        ("security.", INDEX_SECURITY),
        ("system.", INDEX_SYSTEM),
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            // "system.data" is inline data; other system.* names have no
            // ext4 handler (-EOPNOTSUPP at the VFS already).
            return (!rest.is_empty()).then_some((index, rest.as_bytes()));
        }
    }
    None
}

fn full_name(e: &XEntry) -> Option<String> {
    let suffix = core::str::from_utf8(&e.name).ok()?;
    Some(match e.index {
        INDEX_USER => alloc::format!("user.{suffix}"),
        INDEX_POSIX_ACL_ACCESS => String::from(narf_filesystem::XATTR_NAME_POSIX_ACL_ACCESS),
        INDEX_POSIX_ACL_DEFAULT => String::from(narf_filesystem::XATTR_NAME_POSIX_ACL_DEFAULT),
        INDEX_TRUSTED => alloc::format!("trusted.{suffix}"),
        INDEX_SECURITY => alloc::format!("security.{suffix}"),
        // `system.data` (inline data) is not listed by ext4.
        _ => return None,
    })
}

/// `ext4_xattr_hash_entry`.
fn entry_hash(name: &[u8], value: &[u8]) -> u32 {
    const NAME_HASH_SHIFT: u32 = 5;
    const VALUE_HASH_SHIFT: u32 = 16;
    let mut hash: u32 = 0;
    for &c in name {
        hash = (hash << NAME_HASH_SHIFT) ^ (hash >> (32 - NAME_HASH_SHIFT)) ^ u32::from(c);
    }
    let mut padded = value.to_vec();
    padded.resize((value.len() + 3) & !3, 0);
    for w in padded.chunks_exact(4) {
        hash = (hash << VALUE_HASH_SHIFT)
            ^ (hash >> (32 - VALUE_HASH_SHIFT))
            ^ u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    hash
}

/// Parse entries starting at `start` in `buf`; value offsets are relative
/// to `base`.
fn parse_entries(buf: &[u8], start: usize, base: usize) -> Result<Vec<XEntry>, FsError> {
    let mut out = Vec::new();
    let mut off = start;
    loop {
        if off + 4 > buf.len() {
            return Err(corrupt());
        }
        if le32(buf, off) == 0 {
            return Ok(out);
        }
        if off + ENTRY_HEAD > buf.len() {
            return Err(corrupt());
        }
        let name_len = buf[off] as usize;
        let index = buf[off + 1];
        let voffs = le16(buf, off + 2) as usize;
        let vinum = le32(buf, off + 4);
        let vsize = le32(buf, off + 8) as usize;
        let name_end = off + ENTRY_HEAD + name_len;
        if name_end > buf.len() {
            return Err(corrupt());
        }
        let name = buf[off + ENTRY_HEAD..name_end].to_vec();
        if vinum == 0 {
            let vstart = base + voffs;
            if vstart + vsize > buf.len() {
                return Err(corrupt());
            }
            out.push(XEntry {
                index,
                name,
                value: buf[vstart..vstart + vsize].to_vec(),
            });
        }
        off += (name_len + ENTRY_HEAD + 3) & !3;
    }
}

/// Lay `entries` out in `buf[start..]` (value offsets relative to `base`).
/// `false` when they do not fit — the buffer is then unspecified.
fn layout(buf: &mut [u8], start: usize, base: usize, entries: &[XEntry]) -> bool {
    let need_entries: usize = entries.iter().map(XEntry::entry_len).sum::<usize>() + 4;
    let need_values: usize = entries.iter().map(XEntry::value_len).sum();
    if start + need_entries + need_values > buf.len() {
        return false;
    }
    for b in &mut buf[start..] {
        *b = 0;
    }
    let mut off = start;
    let mut vend = buf.len();
    for e in entries {
        vend -= e.value_len();
        buf[vend..vend + e.value.len()].copy_from_slice(&e.value);
        buf[off] = e.name.len() as u8;
        buf[off + 1] = e.index;
        buf[off + 2..off + 4].copy_from_slice(&((vend - base) as u16).to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&(e.value.len() as u32).to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&entry_hash(&e.name, &e.value).to_le_bytes());
        buf[off + ENTRY_HEAD..off + ENTRY_HEAD + e.name.len()].copy_from_slice(&e.name);
        off += e.entry_len();
    }
    true
}

/// `ext4_xattr_rehash` over a laid-out block.
fn block_hash(block: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    let mut off = BLOCK_HEADER_LEN;
    while off + 4 <= block.len() && le32(block, off) != 0 {
        let e_hash = le32(block, off + 12);
        if e_hash == 0 {
            return 0;
        }
        hash = (hash << 16) ^ (hash >> 16) ^ e_hash;
        off += (block[off] as usize + ENTRY_HEAD + 3) & !3;
    }
    hash
}

/// `ext4_acl_to_disk`: uapi `system.posix_acl_*` bytes -> ext4's format.
pub(crate) fn acl_to_disk(acl: &PosixAcl) -> Result<Vec<u8>, FsError> {
    use narf_filesystem::{ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER, ACL_USER_OBJ};
    let mut out = Vec::with_capacity(4 + acl.entries.len() * 8);
    out.extend_from_slice(&EXT4_ACL_VERSION.to_le_bytes());
    for e in &acl.entries {
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        match e.tag {
            ACL_USER | ACL_GROUP => out.extend_from_slice(&e.id.to_le_bytes()),
            ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER => {}
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok(out)
}

/// `ext4_acl_from_disk`: -EINVAL for a bad header or tag.
pub(crate) fn acl_from_disk(value: &[u8]) -> Result<PosixAcl, FsError> {
    use narf_filesystem::{
        posix_acl::ACL_UNDEFINED_ID, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER,
        ACL_USER_OBJ,
    };
    if value.len() < 4 || le32(value, 0) != EXT4_ACL_VERSION {
        return Err(FsError::InvalidData);
    }
    let mut entries = Vec::new();
    let mut off = 4;
    while off < value.len() {
        if off + 4 > value.len() {
            return Err(FsError::InvalidData);
        }
        let tag = le16(value, off);
        let perm = le16(value, off + 2);
        match tag {
            ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER => {
                entries.push(AclEntry::with_id(tag, ACL_UNDEFINED_ID, perm));
                off += 4;
            }
            ACL_USER | ACL_GROUP => {
                if off + 8 > value.len() {
                    return Err(FsError::InvalidData);
                }
                entries.push(AclEntry::with_id(tag, le32(value, off + 4), perm));
                off += 8;
            }
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok(PosixAcl::from_entries(entries))
}

/// Where an inode's attributes live right now.
pub(crate) struct XattrState {
    /// The raw inode slot, with its byte offset on disk.
    raw: Vec<u8>,
    raw_off: u64,
    ibody: Vec<XEntry>,
    block_no: u64,
    block: Vec<XEntry>,
    block_refcount: u32,
}

impl XattrState {
    pub(crate) fn all(&self) -> impl Iterator<Item = &XEntry> {
        self.ibody.iter().chain(self.block.iter())
    }
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    fn inode_slot_offset(&self, inode_no: u32) -> Result<u64, FsError> {
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let gd = &self.group_descs[group as usize];
        let bs = self.block_size() as u64;
        Ok(gd.inode_table * bs + index as u64 * self.superblock.inode_size_bytes() as u64)
    }

    /// `(start of entries, end)` of the in-inode xattr region, or `None`
    /// when the slot has no room for one (128-byte inodes).
    fn ibody_region(&self, raw: &[u8]) -> Option<usize> {
        if raw.len() <= 128 + 2 {
            return None;
        }
        let extra = le16(raw, 128) as usize;
        let magic_at = 128 + extra;
        (magic_at + 4 + 4 <= raw.len()).then_some(magic_at)
    }

    /// Read an inode's attributes (`ext4_xattr_ibody_get` +
    /// `ext4_xattr_block_get`).
    pub(crate) async fn xattr_load(&self, inode_no: u32) -> Result<XattrState, FsError> {
        let raw_off = self.inode_slot_offset(inode_no)?;
        let mut raw = vec![0u8; self.superblock.inode_size_bytes()];
        self.read_byte_range(raw_off, &mut raw).await?;
        if !metadata_csum::verify_inode_checksum(&self.superblock, inode_no, &raw) {
            return Err(FsError::InvalidData);
        }
        let ibody = match self.ibody_region(&raw) {
            Some(magic_at) if le32(&raw, magic_at) == XATTR_MAGIC => {
                parse_entries(&raw, magic_at + 4, magic_at + 4)?
            }
            _ => Vec::new(),
        };
        let block_no = u64::from(le32(&raw, 104)) | (u64::from(le16(&raw, 118)) << 32);
        let (block, block_refcount) = if block_no != 0 {
            let mut buf = vec![0u8; self.block_size()];
            self.read_block(block_no, &mut buf).await?;
            if le32(&buf, 0) != XATTR_MAGIC || le32(&buf, 8) != 1 {
                return Err(corrupt());
            }
            if self.superblock.has_metadata_csum()
                && le32(&buf, 16) != self.xattr_block_csum(block_no, &buf)
            {
                return Err(corrupt());
            }
            (parse_entries(&buf, BLOCK_HEADER_LEN, 0)?, le32(&buf, 4))
        } else {
            (Vec::new(), 0)
        };
        Ok(XattrState {
            raw,
            raw_off,
            ibody,
            block_no,
            block,
            block_refcount,
        })
    }

    /// `ext4_xattr_block_csum`: crc32c(seed, le64 block number, block with
    /// `h_checksum` zeroed).
    fn xattr_block_csum(&self, block_no: u64, block: &[u8]) -> u32 {
        let mut copy = block.to_vec();
        copy[16..20].fill(0);
        let state = metadata_csum::crc32c(
            metadata_csum::seed(&self.superblock),
            &block_no.to_le_bytes(),
        );
        metadata_csum::crc32c(state, &copy)
    }

    async fn write_xattr_block(
        &self,
        block_no: u64,
        entries: &[XEntry],
        refcount: u32,
    ) -> Result<(), FsError> {
        let mut buf = vec![0u8; self.block_size()];
        if !layout(&mut buf, BLOCK_HEADER_LEN, 0, entries) {
            return Err(FsError::NoSpace);
        }
        buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&refcount.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        let hash = block_hash(&buf);
        buf[12..16].copy_from_slice(&hash.to_le_bytes());
        if self.superblock.has_metadata_csum() {
            let csum = self.xattr_block_csum(block_no, &buf);
            buf[16..20].copy_from_slice(&csum.to_le_bytes());
        }
        self.write_block(block_no, &buf).await
    }

    /// Drop this inode's reference to its xattr block: free it, or just
    /// decrement a shared block's refcount (`ext4_xattr_release_block`).
    async fn release_xattr_block(&self, block_no: u64) -> Result<(), FsError> {
        let mut buf = vec![0u8; self.block_size()];
        self.read_block(block_no, &mut buf).await?;
        let refcount = le32(&buf, 4);
        if le32(&buf, 0) == XATTR_MAGIC && refcount > 1 {
            let entries = parse_entries(&buf, BLOCK_HEADER_LEN, 0)?;
            self.write_xattr_block(block_no, &entries, refcount - 1)
                .await
        } else {
            self.free_block(block_no).await
        }
    }

    async fn ensure_ext_attr_feature(&self) -> Result<(), FsError> {
        if self.superblock.feature_compat & COMPAT_EXT_ATTR != 0 {
            return Ok(());
        }
        let mut bytes = vec![0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        let compat = le32(&bytes, 92);
        if compat & COMPAT_EXT_ATTR != 0 {
            return Ok(());
        }
        bytes[92..96].copy_from_slice(&(compat | COMPAT_EXT_ATTR).to_le_bytes());
        if metadata_csum::write_superblock_checksum(&self.superblock, &mut bytes).is_none() {
            return Err(FsError::InvalidData);
        }
        self.write_byte_range(1024, &bytes).await
    }

    /// Store `entries` as the inode's complete attribute set — ibody first,
    /// the rest in the block (sorted like `ext4_xattr_find_entry`'s
    /// `sorted` search expects). `mode` replaces the permission bits of
    /// `i_mode` when given (ACL <-> mode coherence). The caller holds
    /// `inode_update_lock`.
    pub(crate) async fn xattr_store(
        &self,
        inode_no: u32,
        mut st: XattrState,
        entries: Vec<XEntry>,
        mode: Option<u16>,
    ) -> Result<(), FsError> {
        if !entries.is_empty() {
            self.ensure_ext_attr_feature().await?;
        }
        let spb = (self.block_size() / 512) as u32;
        // Fill the inode body in order; what does not fit goes to the block.
        let mut in_body: Vec<XEntry> = Vec::new();
        let mut in_block: Vec<XEntry> = Vec::new();
        let region = self.ibody_region(&st.raw);
        for e in entries {
            let mut trial = in_body.clone();
            trial.push(e.clone());
            let fits = match region {
                Some(magic_at) => {
                    let mut scratch = st.raw.clone();
                    layout(&mut scratch, magic_at + 4, magic_at + 4, &trial)
                }
                None => false,
            };
            if fits && in_block.is_empty() {
                in_body = trial;
            } else {
                in_block.push(e);
            }
        }
        in_block.sort_by(|a, b| {
            (a.index, a.name.len(), &a.name).cmp(&(b.index, b.name.len(), &b.name))
        });
        if let Some(magic_at) = region {
            if in_body.is_empty() {
                // Linux leaves an empty body without its magic.
                st.raw[magic_at..].fill(0);
            } else {
                st.raw[magic_at..magic_at + 4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
                if !layout(&mut st.raw, magic_at + 4, magic_at + 4, &in_body) {
                    return Err(FsError::NoSpace);
                }
            }
        }
        let mut blocks = le32(&st.raw, 28);
        let mut block_no = st.block_no;
        if in_block.is_empty() {
            if block_no != 0 {
                self.release_xattr_block(block_no).await?;
                blocks = blocks.saturating_sub(spb);
                block_no = 0;
            }
        } else if block_no != 0 && st.block_refcount <= 1 {
            self.write_xattr_block(block_no, &in_block, 1).await?;
        } else {
            // A new block, or copy-on-write of a shared one.
            let fresh = self.alloc_block().await?;
            if let Err(e) = self.write_xattr_block(fresh, &in_block, 1).await {
                let _ = self.free_block(fresh).await;
                return Err(e);
            }
            if block_no != 0 {
                self.release_xattr_block(block_no).await?;
            } else {
                blocks = blocks.saturating_add(spb);
            }
            block_no = fresh;
        }
        st.raw[28..32].copy_from_slice(&blocks.to_le_bytes());
        st.raw[104..108].copy_from_slice(&(block_no as u32).to_le_bytes());
        st.raw[118..120].copy_from_slice(&((block_no >> 32) as u16).to_le_bytes());
        if let Some(perms) = mode {
            let m = le16(&st.raw, 0);
            let m = (m & 0xF000) | (perms & 0o7777);
            st.raw[0..2].copy_from_slice(&m.to_le_bytes());
        }
        let now = Self::now_secs();
        st.raw[12..16].copy_from_slice(&now.to_le_bytes()); // i_ctime
        let _ = metadata_csum::write_inode_checksum(&self.superblock, inode_no, &mut st.raw);
        self.write_byte_range(st.raw_off, &st.raw).await
    }

    /// On inode deletion: release the xattr block (`ext4_xattr_delete_inode`).
    pub(crate) async fn xattr_release_on_free(&self, inode_no: u32) -> Result<(), FsError> {
        let raw_off = self.inode_slot_offset(inode_no)?;
        let mut raw = vec![0u8; self.superblock.inode_size_bytes()];
        self.read_byte_range(raw_off, &mut raw).await?;
        let block_no = u64::from(le32(&raw, 104)) | (u64::from(le16(&raw, 118)) << 32);
        if block_no == 0 {
            return Ok(());
        }
        self.release_xattr_block(block_no).await?;
        raw[104..108].fill(0);
        raw[118..120].fill(0);
        let _ = metadata_csum::write_inode_checksum(&self.superblock, inode_no, &mut raw);
        self.write_byte_range(raw_off, &raw).await
    }

    /// `listxattr`: NUL-separated names, `system.posix_acl_*` included.
    pub(crate) fn xattr_list_names(st: &XattrState) -> Vec<u8> {
        let mut out = Vec::new();
        for e in st.all() {
            if let Some(name) = full_name(e) {
                out.extend_from_slice(name.as_bytes());
                out.push(0);
            }
        }
        out
    }
}

/// Look up `(index, suffix)` in a loaded set.
pub(crate) fn find<'a>(st: &'a XattrState, index: u8, name: &[u8]) -> Option<&'a XEntry> {
    st.all().find(|e| e.index == index && e.name == name)
}

/// The set with `(index, name)` replaced by `value` (`None` removes it).
pub(crate) fn with_value(
    st: &XattrState,
    index: u8,
    name: &[u8],
    value: Option<Vec<u8>>,
) -> Vec<XEntry> {
    let mut out: Vec<XEntry> = st
        .all()
        .filter(|e| !(e.index == index && e.name == name))
        .cloned()
        .collect();
    if let Some(value) = value {
        out.push(XEntry {
            index,
            name: name.to_vec(),
            value,
        });
    }
    out
}

pub(crate) const INDEX_ACL_ACCESS: u8 = INDEX_POSIX_ACL_ACCESS;
pub(crate) const INDEX_ACL_DEFAULT: u8 = INDEX_POSIX_ACL_DEFAULT;
