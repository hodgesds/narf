//! MINIX VFS node — `DirOps` / `FileOps` impls.
//!
//! Clean-room. Directory walk and file read trace back to:
//! - Tanenbaum, *Operating Systems: Design and Implementation*
//!   (1st ed., Ch. 5) — fixed-size dir entries; zone indexing.
//! - Tanenbaum & Bos, *Modern Operating Systems* (4th ed.), §4.6 —
//!   V2/V3 inode + triple-indirect.
//!
//! Per-node we hold the inode number and a copy of the decoded
//! inode (cached at lookup time so `stat` is synchronous). Read-
//! only first cut: no `truncate` / `write` / `unlink` / `mkdir`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::inode::{mode, Inode};
use super::volume::MinixVolume;

#[derive(Debug)]
pub struct MinixNode<B: BlockDevice> {
    pub volume: Arc<MinixVolume<B>>,
    pub ino: u32,
    /// Cached inode. `None` initially when the node was constructed
    /// without a fresh decode (e.g. the volume root); the first
    /// async op fills it. After that it's never invalidated — this
    /// is a read-only driver.
    inode: IrqSafeSpinLock<Option<Inode>>,
}

impl<B: BlockDevice + 'static> MinixNode<B> {
    pub fn new(volume: Arc<MinixVolume<B>>, ino: u32) -> Self {
        Self {
            volume,
            ino,
            inode: IrqSafeSpinLock::new(None),
        }
    }

    pub fn new_with_inode(volume: Arc<MinixVolume<B>>, ino: u32, inode: Inode) -> Self {
        Self {
            volume,
            ino,
            inode: IrqSafeSpinLock::new(Some(inode)),
        }
    }

    /// Get a copy of the inode, lazily reading it if needed.
    async fn ensure_inode(&self) -> Result<Inode, FsError> {
        if let Some(i) = *self.inode.lock() {
            return Ok(i);
        }
        let i = self.volume.read_inode(self.ino).await?;
        *self.inode.lock() = Some(i);
        Ok(i)
    }

    fn stat_for(&self, inode: &Inode) -> Stat {
        let block_size = self.volume.sb.block_size as u64;
        Stat {
            size: inode.size as u64,
            blocks: (inode.size as u64).div_ceil(block_size),
            mode: Mode {
                file_type: if inode.is_dir() {
                    FileType::Dir
                } else if inode.is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::File
                },
                perms: inode.mode & 0o777,
            },
            mtime_cycles: inode.mtime as u64,
        }
    }

    /// Read every populated `(name, ino)` entry of this directory.
    async fn read_entries(&self) -> Result<Vec<(String, u32)>, FsError> {
        let inode = self.ensure_inode().await?;
        if !inode.is_dir() {
            return Err(FsError::InvalidPath);
        }
        let bytes = self.volume.read_dir_bytes(&inode).await?;
        let entries = super::dir::DirEntry::decode_all(self.volume.sb.name_len, &bytes);
        Ok(entries.into_iter().map(|e| (e.name, e.ino as u32)).collect())
    }
}

impl<B: BlockDevice + 'static> FileOps for MinixNode<B> {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let inode = self.ensure_inode().await?;
            if inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            self.volume.read_file(&inode, offset, buf).await
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // TODO: write paths require the bitmap allocator.
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        // If we don't have a cached inode, return a placeholder.
        // The async stat returns the real value.
        match *self.inode.lock() {
            Some(i) => self.stat_for(&i),
            None => Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RO,
                mtime_cycles: 0,
            },
        }
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            let inode = self.ensure_inode().await?;
            Ok(self.stat_for(&inode))
        })
    }

    // truncate intentionally left as the trait default (Unsupported).
}

impl<B: BlockDevice + 'static> DirOps for MinixNode<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // MINIX lookups are inherently async (block reads). VFS
        // prefers `lookup_async` automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let entries = self.read_entries().await?;
            for (n, ino) in entries {
                if n == name {
                    let child = self.volume.read_inode(ino).await?;
                    return Ok(Arc::new(MinixNode::new_with_inode(
                        self.volume.clone(),
                        ino,
                        child,
                    )) as Arc<dyn FileOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let entries = self.read_entries().await?;
            for (n, ino) in entries {
                if n == name {
                    let child = self.volume.read_inode(ino).await?;
                    if !(child.mode & mode::IFMT == mode::IFDIR) {
                        return Err(FsError::InvalidPath);
                    }
                    return Ok(Arc::new(MinixNode::new_with_inode(
                        self.volume.clone(),
                        ino,
                        child,
                    )) as Arc<dyn DirOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Disk-backed FS — sync iteration is unsupported. Use
        // `enumerate_async`.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let entries = self.read_entries().await?;
            let mut out = Vec::new();
            for (i, (name, ino)) in entries.into_iter().enumerate() {
                if i < cursor {
                    continue;
                }
                if out.len() >= max {
                    break;
                }
                // We need the file type for the entry; read the
                // inode to learn it. (MINIX does NOT store the type
                // in the directory entry, unlike ext4.)
                let child = self.volume.read_inode(ino).await?;
                let ft = if child.is_dir() {
                    FileType::Dir
                } else if child.is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::File
                };
                out.push((name, ft));
            }
            Ok(out)
        })
    }

    // create / mkdir / unlink / rmdir / symlink / rename: defaulted
    // to `Err(FsError::Unsupported)` from the trait. TODO: write
    // paths + bitmap allocator.
}
