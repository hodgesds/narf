//! ext2 node — `FileOps` + `DirOps` implementation.
//!
//! Clean-room implementation. Directory walking, inode-to-stat
//! translation, and the read-side block-pointer walk all derived
//! strictly from the public references below — no GPL Linux
//! `fs/ext2/*`, GRUB, e2fsprogs, or BSD ext2 sources were consulted
//! while writing this file.
//!
//! References:
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, §"Inodes", §"Directories".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_.
//! - OSDev Wiki, "Ext2 — Inode Data Structure", "Ext2 — Directory
//!   Entry": <https://wiki.osdev.org/Ext2>
//!
//! NOTE: write-side operations (create/unlink/mkdir/rmdir/rename),
//! symlink resolution, and HTREE directory indexes are **TODO** —
//! the read-only first cut deliberately defers them, see the crate
//! README.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{
    DirEntry as VfsDirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::dir::{ftype, for_each_entry};
use super::inode::Inode;
use super::volume::Ext2Volume;

#[derive(Debug, Copy, Clone)]
pub struct Ext2NodeState {
    pub inode_no: u32,
    pub stat: Stat,
    /// Cached inode bytes, lazily populated on first I/O. We do not
    /// persist mutations through this cache — all writes would
    /// re-read on each operation. (Read-only cut: never written.)
    pub inode: Option<Inode>,
}

#[derive(Debug)]
pub struct Ext2Node<B: BlockDevice> {
    pub volume: Arc<Ext2Volume<B>>,
    pub state: IrqSafeSpinLock<Ext2NodeState>,
}

impl<B: BlockDevice + 'static> Ext2Node<B> {
    pub fn new(volume: Arc<Ext2Volume<B>>, inode_no: u32, stat: Stat) -> Self {
        Self {
            volume,
            state: IrqSafeSpinLock::new(Ext2NodeState {
                inode_no,
                stat,
                inode: None,
            }),
        }
    }

    /// Translate an on-disk inode into a VFS `Stat`. Block count is
    /// reported in 512-byte sectors (matching `i_blocks`).
    fn stat_from_inode(volume: &Ext2Volume<B>, inode: &Inode) -> Stat {
        let _ = volume;
        let file_type = if inode.is_dir() {
            FileType::Dir
        } else if inode.is_symlink() {
            FileType::Symlink
        } else {
            FileType::File
        };
        Stat {
            size: inode.size as u64,
            blocks: inode.blocks as u64,
            mode: Mode {
                file_type,
                perms: inode.mode & 0o777,
            },
            mtime_cycles: 0,
        }
    }

    /// Lazily fetch + cache the inode from disk.
    async fn load_inode(&self) -> Result<Inode, FsError> {
        let cached = self.state.lock().inode;
        if let Some(i) = cached {
            return Ok(i);
        }
        let ino_no = self.state.lock().inode_no;
        let inode = self.volume.read_inode(ino_no).await?;
        {
            let mut g = self.state.lock();
            g.inode = Some(inode);
            g.stat = Self::stat_from_inode(&self.volume, &inode);
        }
        Ok(inode)
    }

    /// Read the entire byte content of the inode into a heap
    /// `Vec<u8>`. Used by directory enumeration; the caller is
    /// responsible for never calling this on a regular file's full
    /// size (file reads use the streaming `read` API instead).
    async fn read_all_inode_bytes(&self, inode: &Inode) -> Result<Vec<u8>, FsError> {
        let size = inode.size as usize;
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut out = vec![0u8; size];
        self.read_inode_at(inode, 0, &mut out).await?;
        Ok(out)
    }

    /// Read `dst.len()` bytes from `inode` starting at logical
    /// offset `offset`. Stops short of `dst.len()` only if EOF is
    /// reached. Holes (zero block-pointers) yield zero-bytes.
    async fn read_inode_at(
        &self,
        inode: &Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, FsError> {
        let size = inode.size as u64;
        if offset >= size {
            return Ok(0);
        }
        let bs = self.volume.block_size() as u64;
        let mut to_read = core::cmp::min(dst.len() as u64, size - offset);
        let mut total: usize = 0;
        let mut cursor = offset;

        while to_read > 0 {
            let logical = cursor / bs;
            let in_block = (cursor % bs) as usize;
            let chunk = core::cmp::min(to_read as usize, bs as usize - in_block);

            let physical = self.volume.map_block(inode, logical).await?;
            if physical == 0 {
                // Hole — zero-fill the destination range.
                for b in dst[total..total + chunk].iter_mut() {
                    *b = 0;
                }
            } else {
                let mut blockbuf = vec![0u8; bs as usize];
                self.volume.read_block(physical as u64, &mut blockbuf).await?;
                dst[total..total + chunk]
                    .copy_from_slice(&blockbuf[in_block..in_block + chunk]);
            }
            total += chunk;
            cursor += chunk as u64;
            to_read -= chunk as u64;
        }
        Ok(total)
    }

    /// Walk `inode`'s directory bytes calling `f` for each entry.
    /// Stops when `f` returns `false`.
    async fn walk_dir<F: FnMut(&str, u32, u8) -> bool>(
        &self,
        inode: &Inode,
        mut f: F,
    ) -> Result<(), FsError> {
        let bytes = self.read_all_inode_bytes(inode).await?;
        let mut continue_walk = true;
        for_each_entry(&bytes, |entry| {
            if !continue_walk {
                return false;
            }
            let name = match core::str::from_utf8(entry.name) {
                Ok(s) => s,
                Err(_) => return true, // skip non-UTF8 entries
            };
            let keep = f(name, entry.inode, entry.file_type);
            continue_walk = keep;
            keep
        });
        Ok(())
    }
}

impl<B: BlockDevice + 'static> FileOps for Ext2Node<B> {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let inode = self.load_inode().await?;
            self.read_inode_at(&inode, offset, buf).await
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // TODO: write paths land alongside the bitmap allocator.
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        self.state.lock().stat
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            let _ = self.load_inode().await?;
            Ok(self.state.lock().stat)
        })
    }

    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
}

impl<B: BlockDevice + 'static> DirOps for Ext2Node<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Ext2 lookups are async (block reads). Sync API is
        // unsupported — VFS prefers `lookup_async`.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let inode = self.load_inode().await?;
            let bytes = self.read_all_inode_bytes(&inode).await?;
            let mut found_ino: u32 = 0;
            for_each_entry(&bytes, |entry| {
                let candidate = match core::str::from_utf8(entry.name) {
                    Ok(s) => s,
                    Err(_) => return true,
                };
                if candidate == name {
                    found_ino = entry.inode;
                    return false;
                }
                true
            });
            if found_ino == 0 {
                return Err(FsError::NotFound);
            }
            let target = self.volume.read_inode(found_ino).await?;
            let stat = Self::stat_from_inode(&self.volume, &target);
            Ok(Arc::new(Ext2Node::new(
                self.volume.clone(),
                found_ino,
                stat,
            )) as Arc<dyn FileOps>)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let inode = self.load_inode().await?;
            let bytes = self.read_all_inode_bytes(&inode).await?;
            let mut found_ino: u32 = 0;
            let mut found_type: u8 = ftype::UNKNOWN;
            for_each_entry(&bytes, |entry| {
                let candidate = match core::str::from_utf8(entry.name) {
                    Ok(s) => s,
                    Err(_) => return true,
                };
                if candidate == name {
                    found_ino = entry.inode;
                    found_type = entry.file_type;
                    return false;
                }
                true
            });
            if found_ino == 0 {
                return Err(FsError::NotFound);
            }
            let target = self.volume.read_inode(found_ino).await?;
            // Honour the on-disk inode mode rather than the rev-0
            // dirent type byte, which is unreliable on rev-0 volumes
            // (overlap with the high byte of `name_len`).
            if !target.is_dir() && found_type != ftype::DIR {
                return Err(FsError::NotFound);
            }
            let stat = Self::stat_from_inode(&self.volume, &target);
            Ok(Arc::new(Ext2Node::new(
                self.volume.clone(),
                found_ino,
                stat,
            )) as Arc<dyn DirOps>)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = VfsDirEntry> + 'a> {
        // Disk-backed FS — sync iteration is unsupported.
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
            let inode = self.load_inode().await?;
            let mut out: Vec<(String, FileType)> = Vec::new();
            let mut idx = 0usize;
            self.walk_dir(&inode, |name, ino, ft| {
                if ino == 0 {
                    return true;
                }
                if idx >= cursor {
                    let typ = match ft {
                        ftype::DIR => FileType::Dir,
                        ftype::SYMLINK => FileType::Symlink,
                        ftype::REGULAR => FileType::File,
                        // rev-0 volumes — the on-disk inode mode is
                        // the authority; we'd need to fetch it to
                        // know for sure. For enumerate, default to
                        // File for unknown.
                        _ => FileType::File,
                    };
                    out.push((String::from(name), typ));
                    if out.len() >= max {
                        return false;
                    }
                }
                idx += 1;
                true
            })
            .await?;
            Ok(out)
        })
    }

    // Mutation surface — TODO. Read-only first cut.
    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn rename<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
}
