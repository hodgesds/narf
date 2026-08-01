//! SquashFS volume I/O, metadata streams, inode decoding and data reads.
//!
//! Linux reference call chains:
//! `squashfs_fill_super` -> table-index readers,
//! `squashfs_read_inode` -> `squashfs_read_metadata`, and
//! `squashfs_readpage_block`/`squashfs_frag_lookup` -> decompressor.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockError, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_filesystem::{FileType, FsError};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use crate::format::{
    self, le16, le32, le64, Compression, InodeRef, Superblock, BLKDEV_TYPE, CHRDEV_TYPE,
    DATA_UNCOMPRESSED, DIR_TYPE, FIFO_TYPE, INVALID_U32, INVALID_U64, LBLKDEV_TYPE, LCHRDEV_TYPE,
    LDIR_TYPE, LFIFO_TYPE, LREG_TYPE, LSOCKET_TYPE, LSYMLINK_TYPE, METADATA_SIZE,
    METADATA_UNCOMPRESSED, NAME_LEN, REG_TYPE, SOCKET_TYPE, SYMLINK_TYPE,
};

const MAX_XATTR_VALUE: usize = 64 * 1024;
const XATTR_VALUE_OOL: u16 = 1 << 8;
const XATTR_PREFIX_MASK: u16 = 0xff;

#[derive(Debug)]
struct VolumeIo {
    cap: Cap<DmaBuffer, Write>,
    block_size: usize,
}

impl VolumeIo {
    fn buffer(&self) -> Option<Arc<DmaBuffer>> {
        resolve_cap(&self.cap)
    }
}

impl Drop for VolumeIo {
    fn drop(&mut self) {
        unregister(self.cap);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MetadataCursor {
    pub block: u64,
    pub offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRecord {
    pub name: String,
    pub inode_ref: InodeRef,
    pub inode_number: u32,
    pub file_type: FileType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiskKind {
    File {
        start_block: u64,
        file_size: u64,
        sparse: u64,
        fragment: u32,
        fragment_offset: u32,
        block_sizes: Vec<u32>,
    },
    Directory {
        start_block: u32,
        offset: u16,
        file_size: u32,
        parent_inode: u32,
    },
    Symlink(String),
    Special {
        file_type: FileType,
        rdev: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskInode {
    pub inode_ref: InodeRef,
    pub inode_number: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u32,
    pub xattr: Option<u32>,
    pub kind: DiskKind,
}

impl DiskInode {
    pub fn file_type(&self) -> FileType {
        match &self.kind {
            DiskKind::File { .. } => FileType::File,
            DiskKind::Directory { .. } => FileType::Dir,
            DiskKind::Symlink(_) => FileType::Symlink,
            DiskKind::Special { file_type, .. } => *file_type,
        }
    }

    pub fn size(&self) -> u64 {
        match &self.kind {
            DiskKind::File { file_size, .. } => *file_size,
            DiskKind::Directory { file_size, .. } => u64::from(*file_size),
            DiskKind::Symlink(target) => target.len() as u64,
            DiskKind::Special { .. } => 0,
        }
    }

    pub fn blocks_512(&self) -> u64 {
        let allocated = match &self.kind {
            DiskKind::File {
                file_size, sparse, ..
            } => file_size.saturating_sub(*sparse),
            _ => self.size(),
        };
        allocated.div_ceil(512)
    }
}

#[derive(Clone, Debug)]
struct XattrTable {
    data_start: u64,
    ids: u32,
    indexes: Vec<u64>,
}

/// Mounted SquashFS 4.0 volume.
#[derive(Debug)]
pub struct SquashfsVolume<B: BlockDevice> {
    pub device: Arc<B>,
    pub superblock: Superblock,
    pub self_weak: Weak<SquashfsVolume<B>>,
    io: Mutex<VolumeIo>,
    id_indexes: Vec<u64>,
    fragment_indexes: Vec<u64>,
    xattrs: Option<XattrTable>,
    root_inode: IrqSafeSpinLock<Option<DiskInode>>,
}

impl<B: BlockDevice + 'static> SquashfsVolume<B> {
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let logical = device.logical_block_size() as usize;
        if !(512..=4096).contains(&logical) || !logical.is_power_of_two() {
            return Err(FsError::Unsupported);
        }
        let capacity = device
            .capacity_blocks()
            .checked_mul(logical as u64)
            .ok_or(FsError::InvalidData)?;
        if capacity < format::SUPERBLOCK_SIZE as u64 {
            return Err(FsError::InvalidData);
        }

        let dma = alloc_coherent(logical, domain).map_err(|_| FsError::Io(BlockError::IOError))?;
        let io = Mutex::new(VolumeIo {
            cap: register_with_cap(dma),
            block_size: logical,
        });

        let mut raw = [0u8; format::SUPERBLOCK_SIZE];
        read_exact_from(&*device, &io, capacity, 0, &mut raw).await?;
        let sb = Superblock::decode(&raw)?;
        validate_superblock(&sb, capacity)?;

        // LZ4 images must carry the Linux legacy-format options record.
        if sb.flags & format::FLAG_COMP_OPTIONS != 0 {
            let (opts, _) = read_metadata_block_from(
                &*device,
                &io,
                sb.bytes_used,
                sb.compression,
                format::SUPERBLOCK_SIZE as u64,
            )
            .await?;
            if sb.compression == Compression::Lz4 && (opts.len() < 8 || le32(&opts, 0)? != 1) {
                return Err(FsError::Unsupported);
            }
        } else if sb.compression == Compression::Lz4 {
            return Err(FsError::InvalidData);
        }

        let id_index_count = index_count(u64::from(sb.no_ids), 4)?;
        let id_indexes = read_index_table(
            &*device,
            &io,
            sb.bytes_used,
            sb.id_table_start,
            id_index_count,
        )
        .await?;
        validate_metadata_indexes(&id_indexes, sb.id_table_start)?;

        let fragment_index_count = index_count(u64::from(sb.fragments), 16)?;
        let fragment_indexes = if fragment_index_count == 0 {
            Vec::new()
        } else {
            let indexes = read_index_table(
                &*device,
                &io,
                sb.bytes_used,
                sb.fragment_table_start,
                fragment_index_count,
            )
            .await?;
            validate_metadata_indexes(&indexes, sb.fragment_table_start)?;
            indexes
        };

        let xattrs = if sb.xattr_id_table_start == INVALID_U64 {
            None
        } else {
            let mut header = [0u8; 16];
            read_exact_from(
                &*device,
                &io,
                sb.bytes_used,
                sb.xattr_id_table_start,
                &mut header,
            )
            .await?;
            let data_start = le64(&header, 0)?;
            let ids = le32(&header, 8)?;
            if ids == 0 || data_start >= sb.xattr_id_table_start {
                return Err(FsError::InvalidData);
            }
            let count = index_count(u64::from(ids), 16)?;
            let indexes = read_index_table(
                &*device,
                &io,
                sb.bytes_used,
                sb.xattr_id_table_start + 16,
                count,
            )
            .await?;
            validate_metadata_indexes(&indexes, sb.xattr_id_table_start)?;
            if indexes.first().copied().is_none_or(|p| data_start >= p) {
                return Err(FsError::InvalidData);
            }
            Some(XattrTable {
                data_start,
                ids,
                indexes,
            })
        };

        let volume = Arc::new_cyclic(|weak| Self {
            device,
            superblock: sb,
            self_weak: weak.clone(),
            io,
            id_indexes,
            fragment_indexes,
            xattrs,
            root_inode: IrqSafeSpinLock::new(None),
        });

        // Linux mounts only after the root inode decodes as a directory.
        let root = volume.read_inode(InodeRef::decode(sb.root_inode)).await?;
        if !matches!(root.kind, DiskKind::Directory { .. }) {
            return Err(FsError::InvalidData);
        }
        *volume.root_inode.lock() = Some(root);
        Ok(volume)
    }

    pub fn root_ref(&self) -> InodeRef {
        InodeRef::decode(self.superblock.root_inode)
    }

    pub(crate) fn cached_root_inode(&self) -> Option<DiskInode> {
        self.root_inode.lock().clone()
    }

    pub async fn read_inode(&self, inode_ref: InodeRef) -> Result<DiskInode, FsError> {
        if inode_ref.offset as usize >= METADATA_SIZE {
            return Err(FsError::InvalidData);
        }
        let block = self
            .superblock
            .inode_table_start
            .checked_add(u64::from(inode_ref.block))
            .ok_or(FsError::InvalidData)?;
        if block >= self.superblock.directory_table_start {
            return Err(FsError::InvalidData);
        }
        let mut cursor = MetadataCursor {
            block,
            offset: inode_ref.offset as usize,
        };
        let base = self.read_metadata(&mut cursor, 16).await?;
        let inode_type = le16(&base, 0)?;
        let mode = le16(&base, 2)?;
        if mode & 0o170000 != 0 {
            return Err(FsError::InvalidData);
        }
        let uid = self.read_id(le16(&base, 4)?).await?;
        let gid = self.read_id(le16(&base, 6)?).await?;
        let mtime = le32(&base, 8)?;
        let inode_number = le32(&base, 12)?;
        if inode_number == 0 || inode_number > self.superblock.inodes {
            return Err(FsError::InvalidData);
        }

        let (nlink, xattr, kind) = match inode_type {
            REG_TYPE => {
                let rest = self.read_metadata(&mut cursor, 16).await?;
                let start_block = u64::from(le32(&rest, 0)?);
                let fragment = le32(&rest, 4)?;
                let fragment_offset = le32(&rest, 8)?;
                let file_size = u64::from(le32(&rest, 12)?);
                let block_sizes = self
                    .read_block_list(&mut cursor, file_size, fragment)
                    .await?;
                (
                    1,
                    None,
                    DiskKind::File {
                        start_block,
                        file_size,
                        sparse: 0,
                        fragment,
                        fragment_offset,
                        block_sizes,
                    },
                )
            }
            LREG_TYPE => {
                let rest = self.read_metadata(&mut cursor, 40).await?;
                let start_block = le64(&rest, 0)?;
                let file_size = le64(&rest, 8)?;
                let sparse = le64(&rest, 16)?;
                let nlink = le32(&rest, 24)?;
                let fragment = le32(&rest, 28)?;
                let fragment_offset = le32(&rest, 32)?;
                let xattr = decode_xattr(le32(&rest, 36)?);
                if sparse > file_size || nlink == 0 {
                    return Err(FsError::InvalidData);
                }
                let block_sizes = self
                    .read_block_list(&mut cursor, file_size, fragment)
                    .await?;
                (
                    nlink,
                    xattr,
                    DiskKind::File {
                        start_block,
                        file_size,
                        sparse,
                        fragment,
                        fragment_offset,
                        block_sizes,
                    },
                )
            }
            DIR_TYPE => {
                let rest = self.read_metadata(&mut cursor, 16).await?;
                let nlink = le32(&rest, 4)?;
                let file_size = u32::from(le16(&rest, 8)?);
                let offset = le16(&rest, 10)?;
                let parent_inode = le32(&rest, 12)?;
                if nlink == 0 || offset as usize >= METADATA_SIZE {
                    return Err(FsError::InvalidData);
                }
                (
                    nlink,
                    None,
                    DiskKind::Directory {
                        start_block: le32(&rest, 0)?,
                        offset,
                        file_size,
                        parent_inode,
                    },
                )
            }
            LDIR_TYPE => {
                let rest = self.read_metadata(&mut cursor, 24).await?;
                let nlink = le32(&rest, 0)?;
                let file_size = le32(&rest, 4)?;
                let start_block = le32(&rest, 8)?;
                let parent_inode = le32(&rest, 12)?;
                let index_count = le16(&rest, 16)?;
                let offset = le16(&rest, 18)?;
                let xattr = decode_xattr(le32(&rest, 20)?);
                if nlink == 0 || offset as usize >= METADATA_SIZE {
                    return Err(FsError::InvalidData);
                }
                // Directory indexes are optional accelerators.  Validate and
                // skip them so malformed index records cannot make the inode
                // cursor escape metadata, while lookup still scans linearly.
                for _ in 0..index_count {
                    let idx = self.read_metadata(&mut cursor, 12).await?;
                    let name_len = le32(&idx, 8)? as usize + 1;
                    if name_len > NAME_LEN {
                        return Err(FsError::InvalidData);
                    }
                    let _ = self.read_metadata(&mut cursor, name_len).await?;
                }
                (
                    nlink,
                    xattr,
                    DiskKind::Directory {
                        start_block,
                        offset,
                        file_size,
                        parent_inode,
                    },
                )
            }
            SYMLINK_TYPE | LSYMLINK_TYPE => {
                let rest = self.read_metadata(&mut cursor, 8).await?;
                let nlink = le32(&rest, 0)?;
                let len = le32(&rest, 4)? as usize;
                if nlink == 0 || len > 4096 {
                    return Err(FsError::InvalidData);
                }
                let target_bytes = self.read_metadata(&mut cursor, len).await?;
                let target = core::str::from_utf8(&target_bytes)
                    .map_err(|_| FsError::InvalidData)?
                    .to_string();
                let xattr = if inode_type == LSYMLINK_TYPE {
                    let raw = self.read_metadata(&mut cursor, 4).await?;
                    decode_xattr(le32(&raw, 0)?)
                } else {
                    None
                };
                (nlink, xattr, DiskKind::Symlink(target))
            }
            BLKDEV_TYPE | CHRDEV_TYPE | LBLKDEV_TYPE | LCHRDEV_TYPE => {
                let extended = inode_type == LBLKDEV_TYPE || inode_type == LCHRDEV_TYPE;
                let rest = self
                    .read_metadata(&mut cursor, if extended { 12 } else { 8 })
                    .await?;
                let nlink = le32(&rest, 0)?;
                let rdev = le32(&rest, 4)?;
                let xattr = if extended {
                    decode_xattr(le32(&rest, 8)?)
                } else {
                    None
                };
                let file_type = if inode_type == BLKDEV_TYPE || inode_type == LBLKDEV_TYPE {
                    FileType::Block
                } else {
                    FileType::Special
                };
                (nlink, xattr, DiskKind::Special { file_type, rdev })
            }
            FIFO_TYPE | SOCKET_TYPE | LFIFO_TYPE | LSOCKET_TYPE => {
                let extended = inode_type == LFIFO_TYPE || inode_type == LSOCKET_TYPE;
                let rest = self
                    .read_metadata(&mut cursor, if extended { 8 } else { 4 })
                    .await?;
                let nlink = le32(&rest, 0)?;
                let xattr = if extended {
                    decode_xattr(le32(&rest, 4)?)
                } else {
                    None
                };
                let file_type = if inode_type == FIFO_TYPE || inode_type == LFIFO_TYPE {
                    FileType::Fifo
                } else {
                    FileType::Socket
                };
                (nlink, xattr, DiskKind::Special { file_type, rdev: 0 })
            }
            _ => return Err(FsError::InvalidData),
        };

        if nlink == 0 {
            return Err(FsError::InvalidData);
        }
        if let Some(id) = xattr {
            if self.xattrs.as_ref().is_none_or(|table| id >= table.ids) {
                return Err(FsError::InvalidData);
            }
        }
        Ok(DiskInode {
            inode_ref,
            inode_number,
            mode,
            uid,
            gid,
            mtime,
            nlink,
            xattr,
            kind,
        })
    }

    async fn read_block_list(
        &self,
        cursor: &mut MetadataCursor,
        file_size: u64,
        fragment: u32,
    ) -> Result<Vec<u32>, FsError> {
        let block_size = u64::from(self.superblock.block_size);
        let blocks = if fragment == INVALID_U32 {
            file_size.div_ceil(block_size)
        } else {
            if file_size != 0 && file_size % block_size == 0 {
                return Err(FsError::InvalidData);
            }
            file_size / block_size
        };
        if blocks > self.superblock.bytes_used / 4 || blocks > usize::MAX as u64 {
            return Err(FsError::InvalidData);
        }
        let raw = self.read_metadata(cursor, blocks as usize * 4).await?;
        let mut out = Vec::with_capacity(blocks as usize);
        for off in (0..raw.len()).step_by(4) {
            let encoded = le32(&raw, off)?;
            if encoded >> 25 != 0 {
                return Err(FsError::InvalidData);
            }
            out.push(encoded);
        }
        Ok(out)
    }

    async fn read_id(&self, index: u16) -> Result<u32, FsError> {
        if index >= self.superblock.no_ids {
            return Err(FsError::InvalidData);
        }
        let byte = usize::from(index) * 4;
        let pointer = *self
            .id_indexes
            .get(byte / METADATA_SIZE)
            .ok_or(FsError::InvalidData)?;
        let mut cursor = MetadataCursor {
            block: pointer,
            offset: byte % METADATA_SIZE,
        };
        let raw = self.read_metadata(&mut cursor, 4).await?;
        le32(&raw, 0)
    }

    pub async fn read_metadata(
        &self,
        cursor: &mut MetadataCursor,
        len: usize,
    ) -> Result<Vec<u8>, FsError> {
        read_metadata_from(
            &*self.device,
            &self.io,
            self.superblock.bytes_used,
            self.superblock.compression,
            cursor,
            len,
        )
        .await
    }

    pub async fn scan_directory(&self, inode: &DiskInode) -> Result<Vec<DirectoryRecord>, FsError> {
        let DiskKind::Directory {
            start_block,
            offset,
            file_size,
            ..
        } = inode.kind
        else {
            return Err(FsError::InvalidData);
        };
        // Linux invents `.` and `..` and offsets external directory
        // positions by three.  SquashFS stores that bias in `i_size`, so the
        // actual directory metadata stream is exactly `file_size - 3` bytes
        // (`squashfs_readdir`: ctx->pos starts at 3, then record lengths are
        // added until they equal i_size).
        let stream_size = file_size.checked_sub(3).ok_or(FsError::InvalidData)? as usize;
        if stream_size as u64 > self.superblock.bytes_used {
            return Err(FsError::InvalidData);
        }
        let mut cursor = MetadataCursor {
            block: self
                .superblock
                .directory_table_start
                .checked_add(u64::from(start_block))
                .ok_or(FsError::InvalidData)?,
            offset: offset as usize,
        };
        let mut consumed = 0usize;
        let mut records = Vec::new();
        while consumed < stream_size {
            if stream_size - consumed < 12 {
                return Err(FsError::InvalidData);
            }
            let header = self.read_metadata(&mut cursor, 12).await?;
            consumed += 12;
            let count = le32(&header, 0)?
                .checked_add(1)
                .ok_or(FsError::InvalidData)?;
            if count > 256 {
                return Err(FsError::InvalidData);
            }
            let inode_block = le32(&header, 4)?;
            let inode_base = le32(&header, 8)?;
            for _ in 0..count {
                if stream_size - consumed < 8 {
                    return Err(FsError::InvalidData);
                }
                let entry = self.read_metadata(&mut cursor, 8).await?;
                consumed += 8;
                let name_len = usize::from(le16(&entry, 6)?) + 1;
                if name_len > NAME_LEN || name_len > stream_size - consumed {
                    return Err(FsError::InvalidData);
                }
                let name_raw = self.read_metadata(&mut cursor, name_len).await?;
                consumed += name_len;
                if name_raw.contains(&0) || name_raw.contains(&b'/') {
                    return Err(FsError::InvalidData);
                }
                let name = core::str::from_utf8(&name_raw)
                    .map_err(|_| FsError::InvalidData)?
                    .to_string();
                let inode_delta = le16(&entry, 2)? as i16 as i64;
                let inode_number = i64::from(inode_base)
                    .checked_add(inode_delta)
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| *v != 0 && *v <= self.superblock.inodes)
                    .ok_or(FsError::InvalidData)?;
                let inode_type = le16(&entry, 4)?;
                let file_type = directory_file_type(inode_type)?;
                records.push(DirectoryRecord {
                    name,
                    inode_ref: InodeRef {
                        block: inode_block,
                        offset: le16(&entry, 0)?,
                    },
                    inode_number,
                    file_type,
                });
            }
        }
        if consumed != stream_size {
            return Err(FsError::InvalidData);
        }
        Ok(records)
    }

    pub async fn read_inode_data(
        &self,
        inode: &DiskInode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, FsError> {
        match &inode.kind {
            DiskKind::Symlink(target) => {
                let bytes = target.as_bytes();
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                if start >= bytes.len() {
                    return Ok(0);
                }
                let n = dst.len().min(bytes.len() - start);
                dst[..n].copy_from_slice(&bytes[start..start + n]);
                Ok(n)
            }
            DiskKind::File {
                start_block,
                file_size,
                fragment,
                fragment_offset,
                block_sizes,
                ..
            } => {
                if offset >= *file_size || dst.is_empty() {
                    return Ok(0);
                }
                let want = dst.len().min((file_size - offset) as usize);
                let block_size = self.superblock.block_size as u64;
                let mut done = 0usize;
                let mut cursor = offset;
                while done < want {
                    let logical = cursor / block_size;
                    let in_block = (cursor % block_size) as usize;
                    let remaining_file = (*file_size - cursor) as usize;
                    let chunk = (want - done)
                        .min(self.superblock.block_size as usize - in_block)
                        .min(remaining_file);
                    let full_blocks = block_sizes.len() as u64;
                    if logical < full_blocks {
                        let mut physical = *start_block;
                        for encoded in &block_sizes[..logical as usize] {
                            physical = physical
                                .checked_add(u64::from(encoded & !DATA_UNCOMPRESSED))
                                .ok_or(FsError::InvalidData)?;
                        }
                        let encoded = block_sizes[logical as usize];
                        if encoded & !DATA_UNCOMPRESSED == 0 {
                            dst[done..done + chunk].fill(0);
                        } else {
                            let block = self
                                .read_data_block(
                                    physical,
                                    encoded,
                                    self.superblock.block_size as usize,
                                )
                                .await?;
                            if in_block + chunk > block.len() {
                                return Err(FsError::InvalidData);
                            }
                            dst[done..done + chunk]
                                .copy_from_slice(&block[in_block..in_block + chunk]);
                        }
                    } else {
                        if *fragment == INVALID_U32 || logical != full_blocks {
                            return Err(FsError::InvalidData);
                        }
                        let tail = self.read_fragment(*fragment).await?;
                        let begin = *fragment_offset as usize + in_block;
                        if begin + chunk > tail.len() {
                            return Err(FsError::InvalidData);
                        }
                        dst[done..done + chunk].copy_from_slice(&tail[begin..begin + chunk]);
                    }
                    done += chunk;
                    cursor += chunk as u64;
                }
                Ok(done)
            }
            _ => Err(FsError::Unsupported),
        }
    }

    async fn read_data_block(
        &self,
        absolute: u64,
        encoded: u32,
        output_limit: usize,
    ) -> Result<Vec<u8>, FsError> {
        if encoded >> 25 != 0 {
            return Err(FsError::InvalidData);
        }
        let size = (encoded & !DATA_UNCOMPRESSED) as usize;
        if size == 0 || size > output_limit {
            return Err(FsError::InvalidData);
        }
        let mut raw = vec![0u8; size];
        read_exact_from(
            &*self.device,
            &self.io,
            self.superblock.bytes_used,
            absolute,
            &mut raw,
        )
        .await?;
        if encoded & DATA_UNCOMPRESSED != 0 {
            Ok(raw)
        } else {
            decompress(self.superblock.compression, &raw, output_limit)
        }
    }

    async fn read_fragment(&self, fragment: u32) -> Result<Vec<u8>, FsError> {
        if fragment >= self.superblock.fragments {
            return Err(FsError::InvalidData);
        }
        let byte = fragment as usize * 16;
        let pointer = *self
            .fragment_indexes
            .get(byte / METADATA_SIZE)
            .ok_or(FsError::InvalidData)?;
        let mut cursor = MetadataCursor {
            block: pointer,
            offset: byte % METADATA_SIZE,
        };
        let raw = self.read_metadata(&mut cursor, 16).await?;
        let absolute = le64(&raw, 0)?;
        let encoded = le32(&raw, 8)?;
        self.read_data_block(absolute, encoded, self.superblock.block_size as usize)
            .await
    }

    pub async fn read_xattrs(&self, inode: &DiskInode) -> Result<Vec<(String, Vec<u8>)>, FsError> {
        let Some(xattr_id) = inode.xattr else {
            return Ok(Vec::new());
        };
        let table = self.xattrs.as_ref().ok_or(FsError::InvalidData)?;
        if xattr_id >= table.ids {
            return Err(FsError::InvalidData);
        }
        let byte = xattr_id as usize * 16;
        let pointer = *table
            .indexes
            .get(byte / METADATA_SIZE)
            .ok_or(FsError::InvalidData)?;
        let mut id_cursor = MetadataCursor {
            block: pointer,
            offset: byte % METADATA_SIZE,
        };
        let id = self.read_metadata(&mut id_cursor, 16).await?;
        let xref = le64(&id, 0)?;
        let count = le32(&id, 8)?;
        let total_size = le32(&id, 12)? as usize;
        if count > 4096 || total_size > self.superblock.bytes_used as usize {
            return Err(FsError::InvalidData);
        }
        let mut cursor = MetadataCursor {
            block: table
                .data_start
                .checked_add(xref >> 16)
                .ok_or(FsError::InvalidData)?,
            offset: (xref & 0xffff) as usize,
        };
        let mut out = Vec::new();
        for _ in 0..count {
            let entry = self.read_metadata(&mut cursor, 4).await?;
            let entry_type = le16(&entry, 0)?;
            let name_len = le16(&entry, 2)? as usize;
            if name_len > NAME_LEN {
                return Err(FsError::InvalidData);
            }
            let raw_name = self.read_metadata(&mut cursor, name_len).await?;
            let suffix = core::str::from_utf8(&raw_name).map_err(|_| FsError::InvalidData)?;
            let prefix = match entry_type & XATTR_PREFIX_MASK {
                0 => "user.",
                1 => "trusted.",
                2 => "security.",
                _ => return Err(FsError::InvalidData),
            };
            let value_header = self.read_metadata(&mut cursor, 4).await?;
            let stored_len = le32(&value_header, 0)? as usize;
            let value = if entry_type & XATTR_VALUE_OOL != 0 {
                if stored_len != 8 {
                    return Err(FsError::InvalidData);
                }
                let raw_ref = self.read_metadata(&mut cursor, 8).await?;
                let value_ref = le64(&raw_ref, 0)?;
                let mut value_cursor = MetadataCursor {
                    block: table
                        .data_start
                        .checked_add(value_ref >> 16)
                        .ok_or(FsError::InvalidData)?,
                    offset: (value_ref & 0xffff) as usize,
                };
                let header = self.read_metadata(&mut value_cursor, 4).await?;
                let len = le32(&header, 0)? as usize;
                if len > MAX_XATTR_VALUE {
                    return Err(FsError::InvalidData);
                }
                self.read_metadata(&mut value_cursor, len).await?
            } else {
                if stored_len > MAX_XATTR_VALUE {
                    return Err(FsError::InvalidData);
                }
                self.read_metadata(&mut cursor, stored_len).await?
            };
            out.push((alloc::format!("{prefix}{suffix}"), value));
        }
        Ok(out)
    }
}

fn validate_superblock(sb: &Superblock, capacity: u64) -> Result<(), FsError> {
    if sb.inodes == 0
        || sb.no_ids == 0
        || sb.bytes_used < format::SUPERBLOCK_SIZE as u64
        || sb.bytes_used > capacity
        || !sb.block_size.is_power_of_two()
        || !(4096..=format::MAX_BLOCK_SIZE).contains(&sb.block_size)
        || sb.block_log > 20
        || sb.block_size != 1u32.checked_shl(u32::from(sb.block_log)).unwrap_or(0)
        || InodeRef::decode(sb.root_inode).offset as usize >= METADATA_SIZE
        || sb.inode_table_start < format::SUPERBLOCK_SIZE as u64
        || sb.inode_table_start >= sb.directory_table_start
        || sb.directory_table_start >= sb.bytes_used
        || sb.id_table_start >= sb.bytes_used
        || (sb.fragments != 0 && sb.fragment_table_start >= sb.bytes_used)
    {
        return Err(FsError::InvalidData);
    }
    Ok(())
}

fn index_count(entries: u64, entry_size: u64) -> Result<usize, FsError> {
    let bytes = entries
        .checked_mul(entry_size)
        .ok_or(FsError::InvalidData)?;
    usize::try_from(bytes.div_ceil(METADATA_SIZE as u64)).map_err(|_| FsError::InvalidData)
}

async fn read_index_table<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    bytes_used: u64,
    start: u64,
    count: usize,
) -> Result<Vec<u64>, FsError> {
    if count == 0 || start == INVALID_U64 {
        return Err(FsError::InvalidData);
    }
    let byte_len = count.checked_mul(8).ok_or(FsError::InvalidData)?;
    let mut raw = vec![0u8; byte_len];
    read_exact_from(device, io, bytes_used, start, &mut raw).await?;
    let mut out = Vec::with_capacity(count);
    for off in (0..byte_len).step_by(8) {
        out.push(le64(&raw, off)?);
    }
    Ok(out)
}

fn validate_metadata_indexes(indexes: &[u64], table_start: u64) -> Result<(), FsError> {
    if indexes.is_empty() {
        return Err(FsError::InvalidData);
    }
    let mut previous = None;
    for &pointer in indexes {
        if pointer >= table_start {
            return Err(FsError::InvalidData);
        }
        if let Some(prev) = previous {
            if pointer <= prev || pointer - prev > METADATA_SIZE as u64 + 2 {
                return Err(FsError::InvalidData);
            }
        }
        previous = Some(pointer);
    }
    Ok(())
}

async fn read_exact_from<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    limit: u64,
    offset: u64,
    dst: &mut [u8],
) -> Result<(), FsError> {
    let end = offset
        .checked_add(dst.len() as u64)
        .ok_or(FsError::InvalidData)?;
    if end > limit {
        return Err(FsError::InvalidData);
    }
    let mut done = 0usize;
    while done < dst.len() {
        let absolute = offset + done as u64;
        let guard = io.lock().await;
        let block_size = guard.block_size;
        let lba = absolute / block_size as u64;
        let in_block = (absolute % block_size as u64) as usize;
        let request = BlockRequest {
            op: BlockOp::Read,
            lba,
            blocks: 1,
            buffer: guard
                .cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        device.submit(request).await.result.map_err(FsError::Io)?;
        let buffer = guard
            .buffer()
            .ok_or(FsError::Io(BlockError::PermissionDenied))?;
        let copy = (dst.len() - done).min(block_size - in_block);
        // SAFETY: `guard` serializes all submissions using this registered
        // coherent buffer.  The allocation is `block_size` bytes and remains
        // registered until the volume is dropped.
        let source = unsafe { core::slice::from_raw_parts(buffer.as_ptr(), block_size) };
        dst[done..done + copy].copy_from_slice(&source[in_block..in_block + copy]);
        done += copy;
        // Make the guard's lifetime explicit before the next loop/await.
        drop(guard);
    }
    Ok(())
}

async fn read_metadata_block_from<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    bytes_used: u64,
    compression: Compression,
    block: u64,
) -> Result<(Vec<u8>, u64), FsError> {
    let mut header = [0u8; 2];
    read_exact_from(device, io, bytes_used, block, &mut header).await?;
    let encoded = u16::from_le_bytes(header);
    let stored = usize::from(encoded & !METADATA_UNCOMPRESSED);
    if stored == 0 || stored > METADATA_SIZE {
        return Err(FsError::InvalidData);
    }
    let mut raw = vec![0u8; stored];
    read_exact_from(device, io, bytes_used, block + 2, &mut raw).await?;
    let decoded = if encoded & METADATA_UNCOMPRESSED != 0 {
        raw
    } else {
        decompress(compression, &raw, METADATA_SIZE)?
    };
    if decoded.is_empty() || decoded.len() > METADATA_SIZE {
        return Err(FsError::InvalidData);
    }
    let next = block
        .checked_add(2 + stored as u64)
        .ok_or(FsError::InvalidData)?;
    Ok((decoded, next))
}

async fn read_metadata_from<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    bytes_used: u64,
    compression: Compression,
    cursor: &mut MetadataCursor,
    len: usize,
) -> Result<Vec<u8>, FsError> {
    if cursor.offset >= METADATA_SIZE || len as u64 > bytes_used {
        return Err(FsError::InvalidData);
    }
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let (block, next) =
            read_metadata_block_from(device, io, bytes_used, compression, cursor.block).await?;
        if cursor.offset > block.len() {
            return Err(FsError::InvalidData);
        }
        let copy = (len - out.len()).min(block.len() - cursor.offset);
        if copy == 0 {
            return Err(FsError::InvalidData);
        }
        out.extend_from_slice(&block[cursor.offset..cursor.offset + copy]);
        cursor.offset += copy;
        if cursor.offset == block.len() {
            cursor.block = next;
            cursor.offset = 0;
        }
    }
    Ok(out)
}

fn decompress(compression: Compression, input: &[u8], limit: usize) -> Result<Vec<u8>, FsError> {
    match compression {
        Compression::Zlib => miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(input, limit)
            .map_err(|_| FsError::InvalidData),
        Compression::Lz4 => {
            let mut output = vec![0u8; limit];
            let len = narf_memory::compress::lz4_decode(input, &mut output)
                .map_err(|_| FsError::InvalidData)?;
            output.truncate(len);
            Ok(output)
        }
    }
}

fn directory_file_type(raw: u16) -> Result<FileType, FsError> {
    match raw {
        DIR_TYPE => Ok(FileType::Dir),
        REG_TYPE => Ok(FileType::File),
        SYMLINK_TYPE => Ok(FileType::Symlink),
        BLKDEV_TYPE => Ok(FileType::Block),
        CHRDEV_TYPE => Ok(FileType::Special),
        FIFO_TYPE => Ok(FileType::Fifo),
        SOCKET_TYPE => Ok(FileType::Socket),
        _ => Err(FsError::InvalidData),
    }
}

fn decode_xattr(raw: u32) -> Option<u32> {
    (raw != INVALID_U32).then_some(raw)
}
