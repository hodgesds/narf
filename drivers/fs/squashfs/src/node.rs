//! VFS node surface for immutable SquashFS inodes.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, FsStat, FsStatx,
    FsStatxTimestamp, Mode, Stat,
};

use crate::volume::{DiskInode, DiskKind, SquashfsVolume};

const STATX_BASIC_STATS: u32 = 0x07ff;

#[derive(Debug)]
pub struct SquashfsNode<B: BlockDevice> {
    volume: Arc<SquashfsVolume<B>>,
    inode: DiskInode,
}

impl<B: BlockDevice + 'static> SquashfsNode<B> {
    pub fn new(volume: Arc<SquashfsVolume<B>>, inode: DiskInode) -> Self {
        Self { volume, inode }
    }

    fn stat_value(&self) -> Stat {
        Stat {
            size: self.inode.size(),
            blocks: self.inode.blocks_512(),
            mode: Mode {
                file_type: self.inode.file_type(),
                perms: self.inode.mode & 0o7777,
            },
            // `Stat` currently stores scheduler cycles, not wall-clock
            // seconds.  Preserve SquashFS's wall time through native statx.
            mtime_cycles: 0,
        }
    }

    async fn find_child(&self, name: &str) -> Result<DiskInode, FsError> {
        let records = self.volume.scan_directory(&self.inode).await?;
        let record = records
            .into_iter()
            .find(|record| record.name == name)
            .ok_or(FsError::NotFound)?;
        let inode = self.volume.read_inode(record.inode_ref).await?;
        if inode.inode_number != record.inode_number || inode.file_type() != record.file_type {
            return Err(FsError::InvalidData);
        }
        Ok(inode)
    }

    fn mode_word(&self) -> u16 {
        let type_bits = match self.inode.file_type() {
            FileType::File => 0o100000,
            FileType::Dir => 0o040000,
            FileType::Symlink => 0o120000,
            FileType::Special => 0o020000,
            FileType::Block => 0o060000,
            FileType::Socket => 0o140000,
            FileType::Fifo => 0o010000,
        };
        type_bits | (self.inode.mode & 0o7777)
    }
}

impl<B: BlockDevice + 'static> FileOps for SquashfsNode<B> {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { self.volume.read_inode_data(&self.inode, offset, buf).await })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        self.stat_value()
    }

    fn ino(&self) -> u64 {
        u64::from(self.inode.inode_number)
    }

    fn owners(&self) -> (u32, u32) {
        (self.inode.uid, self.inode.gid)
    }

    fn statx_async<'a>(&'a self, _flags: u32, _mask: u32) -> FsFuture<'a, FsStatx> {
        Box::pin(async move {
            let (rdev_major, rdev_minor) = match self.inode.kind {
                DiskKind::Special { rdev, .. } => decode_device(rdev),
                _ => (0, 0),
            };
            Ok(FsStatx {
                mask: STATX_BASIC_STATS,
                block_size: self.volume.superblock.block_size,
                nlink: self.inode.nlink,
                uid: self.inode.uid,
                gid: self.inode.gid,
                mode: self.mode_word(),
                ino: u64::from(self.inode.inode_number),
                size: self.inode.size(),
                blocks: self.inode.blocks_512(),
                atime: FsStatxTimestamp {
                    seconds: i64::from(self.inode.mtime),
                    nanoseconds: 0,
                },
                ctime: FsStatxTimestamp {
                    seconds: i64::from(self.inode.mtime),
                    nanoseconds: 0,
                },
                mtime: FsStatxTimestamp {
                    seconds: i64::from(self.inode.mtime),
                    nanoseconds: 0,
                },
                rdev_major,
                rdev_minor,
                ..FsStatx::default()
            })
        })
    }

    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }

    fn set_times(&self, _atime_ns: Option<u64>, _mtime_ns: Option<u64>) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn set_owners<'a>(&'a self, _uid: u32, _gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }

    fn set_perms<'a>(&'a self, _perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.volume
                .read_xattrs(&self.inode)
                .await?
                .into_iter()
                .find_map(|(candidate, value)| (candidate == name).then_some(value))
                .ok_or(FsError::NotFound)
        })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let attrs = self.volume.read_xattrs(&self.inode).await?;
            let mut out = Vec::new();
            for (name, _) in attrs {
                out.extend_from_slice(name.as_bytes());
                out.push(0);
            }
            Ok(out)
        })
    }

    fn set_xattr<'a>(&'a self, _name: &'a str, _value: &'a [u8], _flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }

    fn remove_xattr<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
}

impl<B: BlockDevice + 'static> DirOps for SquashfsNode<B> {
    fn ino(&self) -> u64 {
        u64::from(self.inode.inode_number)
    }

    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            Ok(
                Arc::new(Self::new(self.volume.clone(), self.find_child(name).await?))
                    as Arc<dyn FileOps>,
            )
        })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let inode = self.find_child(name).await?;
            if !matches!(inode.kind, DiskKind::Directory { .. }) {
                return Err(FsError::NotFound);
            }
            Ok(Arc::new(Self::new(self.volume.clone(), inode)) as Arc<dyn DirOps>)
        })
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            Ok(self
                .volume
                .scan_directory(&self.inode)
                .await?
                .into_iter()
                .skip(cursor)
                .take(max)
                .map(|entry| (entry.name, entry.file_type))
                .collect())
        })
    }

    fn dir_mode(&self) -> u16 {
        self.inode.mode & 0o7777
    }

    fn dir_owners(&self) -> (u32, u32) {
        (self.inode.uid, self.inode.gid)
    }

    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        readonly()
    }
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        readonly()
    }
    fn create_socket<'a>(&'a self, _name: &'a str, _perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        readonly()
    }
    fn mknod<'a>(
        &'a self,
        _name: &'a str,
        _file_type: FileType,
        _rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        readonly()
    }
    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        readonly()
    }
    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        readonly()
    }
    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        readonly()
    }
    fn rename<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        readonly()
    }
    fn rename_to<'a>(
        &'a self,
        _old_name: &'a str,
        _new_dir: &'a dyn DirOps,
        _new_name: &'a str,
        _flags: u32,
    ) -> FsFuture<'a, ()> {
        readonly()
    }
    fn link<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        readonly()
    }
    fn link_to<'a>(
        &'a self,
        _old_name: &'a str,
        _new_dir: &'a dyn DirOps,
        _new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        readonly()
    }
    fn link_node<'a>(&'a self, _name: &'a str, _node: Arc<dyn FileOps>) -> FsFuture<'a, ()> {
        readonly()
    }
    fn tmpfile<'a>(&'a self, _mode: u32) -> FsFuture<'a, Arc<dyn FileOps>> {
        readonly()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

impl<B: BlockDevice + 'static> FsInstance for SquashfsVolume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let volume = self
            .self_weak
            .upgrade()
            .expect("SquashfsVolume::root called after drop");
        let inode = self
            .cached_root_inode()
            .expect("SquashfsVolume root inode was not validated");
        Arc::new(SquashfsNode::new(volume, inode))
    }

    fn name(&self) -> &str {
        "squashfs"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move {
            Ok(FsStat {
                blocks: self
                    .superblock
                    .bytes_used
                    .div_ceil(u64::from(self.superblock.block_size)),
                blocks_free: 0,
                blocks_available: 0,
                files: u64::from(self.superblock.inodes),
                files_free: 0,
                block_size: self.superblock.block_size,
                name_len: crate::format::NAME_LEN as u32,
                fragment_size: self.superblock.block_size,
            })
        })
    }

    fn reconfigure(&self, options: &str) -> Result<(), FsError> {
        for option in options.split(',').filter(|s| !s.is_empty()) {
            if option != "ro" && option != "errors=continue" && option != "threads=single" {
                return Err(FsError::Unsupported);
            }
        }
        Ok(())
    }
}

fn readonly<'a, T>() -> FsFuture<'a, T> {
    Box::pin(async { Err(FsError::ReadOnly) })
}

fn decode_device(encoded: u32) -> (u32, u32) {
    let major = (encoded & 0x000f_ff00) >> 8;
    let minor = (encoded & 0x0000_00ff) | ((encoded >> 12) & 0x000f_ff00);
    (major, minor)
}
