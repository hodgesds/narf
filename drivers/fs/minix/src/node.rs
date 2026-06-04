//! MINIX VFS node — `DirOps` / `FileOps` impls.
//!
//! Clean-room. Directory walk and file read trace back to:
//! - Tanenbaum, *Operating Systems: Design and Implementation*
//!   (1st ed., Ch. 5) — fixed-size dir entries; zone indexing.
//! - Tanenbaum & Bos, *Modern Operating Systems* (4th ed.), §4.6 —
//!   V2/V3 inode + triple-indirect.
//!
//! Write paths (`create`, `mkdir`, `unlink`, `rmdir`, `write`,
//! `truncate`, `symlink`, `rename`) trace to Linux
//! `fs/minix/{namei.c,bitmap.c,inode.c}`. The on-disk format is
//! identical to mkfs.minix's V3 output (see `tests::build_minix3_image`).
//!
//! Per-node we hold the inode number and a copy of the decoded
//! inode (cached at lookup time so `stat` is synchronous).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use super::dir::{clear_entry, find_entry, DirEntry as MxDirEntry};
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
        Ok(entries
            .into_iter()
            .map(|e| (e.name, e.ino as u32))
            .collect())
    }

    /// Append (or fill the first empty slot of) a directory entry
    /// in `dir_inode`'s body. Caller passes the current body bytes
    /// in `bytes`; the body is rewritten in place.
    async fn append_dir_entry(
        &self,
        dir_inode: &mut Inode,
        bytes: &mut Vec<u8>,
        ino: u16,
        name: &str,
    ) -> Result<(), FsError> {
        let nl = self.volume.sb.name_len;
        let entry_sz = nl.entry_size();
        if name.as_bytes().len() > nl.bytes() {
            return Err(FsError::InvalidPath);
        }
        // Find a hole (ino == 0 slot) or extend.
        let mut placed_off: Option<usize> = None;
        let mut off = 0usize;
        while off + entry_sz <= bytes.len() {
            let ino_val = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
            if ino_val == 0 {
                placed_off = Some(off);
                break;
            }
            off += entry_sz;
        }
        let entry = MxDirEntry {
            ino,
            name: alloc::string::String::from(name),
        };
        match placed_off {
            Some(off) => {
                entry.encode(nl, bytes, off);
                self.volume.write_file(dir_inode, 0, bytes).await?;
            }
            None => {
                // Append a fresh entry.
                let mut new_entry = alloc::vec![0u8; entry_sz];
                entry.encode(nl, &mut new_entry, 0);
                let write_off = bytes.len() as u64;
                self.volume
                    .write_file(dir_inode, write_off, &new_entry)
                    .await?;
                bytes.extend_from_slice(&new_entry);
            }
        }
        Ok(())
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

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let mut inode = self.ensure_inode().await?;
            if inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            let n = self.volume.write_file(&mut inode, offset, buf).await?;
            self.volume.write_inode(self.ino, &inode).await?;
            *self.inode.lock() = Some(inode);
            Ok(n)
        })
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

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut inode = self.ensure_inode().await?;
            if inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            if len == 0 {
                self.volume.truncate_inode(&mut inode).await?;
            } else if (len as u32) <= inode.size {
                // Shrink — free zones past the new end.
                let zs = self.volume.sb.zone_size() as u64;
                let _last_zone = (len.div_ceil(zs)) as u32;
                // For simplicity, just shrink size without freeing
                // intermediate zones (matches Linux's behaviour for
                // non-aligned truncates which leaves the partial
                // tail zone allocated).
                inode.size = len as u32;
            } else {
                // Grow — write zero-fill is implicit via map_block
                // (uninitialised zones read as zero). Just update
                // size; no allocation needed for sparse growth.
                inode.size = len as u32;
            }
            self.volume.write_inode(self.ino, &inode).await?;
            *self.inode.lock() = Some(inode);
            Ok(())
        })
    }
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
                    return Ok(
                        Arc::new(MinixNode::new_with_inode(self.volume.clone(), ino, child))
                            as Arc<dyn FileOps>,
                    );
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
                    return Ok(
                        Arc::new(MinixNode::new_with_inode(self.volume.clone(), ino, child))
                            as Arc<dyn DirOps>,
                    );
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

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                return Err(FsError::InvalidPath);
            }
            let mut dir_inode = self.ensure_inode().await?;
            if !dir_inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            // Refuse duplicate.
            let mut bytes = self.volume.read_dir_bytes(&dir_inode).await?;
            if find_entry(self.volume.sb.name_len, &bytes, name).is_some() {
                return Err(FsError::Busy);
            }
            // Allocate inode + initialise as a regular file.
            let new_ino = self.volume.alloc_inode().await?;
            let file_inode = Inode::new_regular(0o644, dir_inode.mtime);
            self.volume.write_inode(new_ino, &file_inode).await?;
            // Append entry to the directory body.
            self.append_dir_entry(&mut dir_inode, &mut bytes, new_ino as u16, name)
                .await?;
            self.volume.write_inode(self.ino, &dir_inode).await?;
            *self.inode.lock() = Some(dir_inode);
            Ok(Arc::new(MinixNode::new_with_inode(
                self.volume.clone(),
                new_ino,
                file_inode,
            )) as Arc<dyn FileOps>)
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                return Err(FsError::InvalidPath);
            }
            let mut dir_inode = self.ensure_inode().await?;
            if !dir_inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            let mut bytes = self.volume.read_dir_bytes(&dir_inode).await?;
            if find_entry(self.volume.sb.name_len, &bytes, name).is_some() {
                return Err(FsError::Busy);
            }
            let new_ino = self.volume.alloc_inode().await?;
            let mut child_inode = Inode::new_directory(0o755, dir_inode.mtime);
            // Build the "." and ".." entries into a fresh zone.
            let nl = self.volume.sb.name_len;
            let entry_sz = nl.entry_size();
            let zs = self.volume.sb.zone_size() as usize;
            let mut child_bytes = alloc::vec![0u8; zs];
            MxDirEntry {
                ino: new_ino as u16,
                name: alloc::string::String::from("."),
            }
            .encode(nl, &mut child_bytes, 0);
            MxDirEntry {
                ino: self.ino as u16,
                name: alloc::string::String::from(".."),
            }
            .encode(nl, &mut child_bytes, entry_sz);
            let body_size = 2 * entry_sz;
            // Write into the child directory.
            self.volume
                .write_file(&mut child_inode, 0, &child_bytes[..body_size])
                .await?;
            self.volume.write_inode(new_ino, &child_inode).await?;
            // Append entry in the parent. Bumps parent nlinks by 1
            // (the child's ".." references parent).
            self.append_dir_entry(&mut dir_inode, &mut bytes, new_ino as u16, name)
                .await?;
            dir_inode.nlinks = dir_inode.nlinks.saturating_add(1);
            self.volume.write_inode(self.ino, &dir_inode).await?;
            *self.inode.lock() = Some(dir_inode);
            Ok(Arc::new(MinixNode::new_with_inode(
                self.volume.clone(),
                new_ino,
                child_inode,
            )) as Arc<dyn DirOps>)
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if name == "." || name == ".." || name.is_empty() {
                return Err(FsError::InvalidPath);
            }
            let mut dir_inode = self.ensure_inode().await?;
            let mut bytes = self.volume.read_dir_bytes(&dir_inode).await?;
            let off = find_entry(self.volume.sb.name_len, &bytes, name).ok_or(FsError::NotFound)?;
            let entry = MxDirEntry::decode(self.volume.sb.name_len, &bytes, off)
                .ok_or(FsError::NotFound)?;
            let mut victim = self.volume.read_inode(entry.ino as u32).await?;
            if victim.is_dir() {
                return Err(FsError::InvalidPath);
            }
            victim.nlinks = victim.nlinks.saturating_sub(1);
            if victim.nlinks == 0 {
                self.volume.truncate_inode(&mut victim).await?;
                self.volume.free_inode(entry.ino as u32).await?;
            } else {
                self.volume.write_inode(entry.ino as u32, &victim).await?;
            }
            // Clear directory slot in place. We don't compact — Linux
            // doesn't either; future inserts reuse the hole.
            clear_entry(self.volume.sb.name_len, &mut bytes, off);
            // Rewrite the directory body up to its original size.
            self.volume.write_file(&mut dir_inode, 0, &bytes).await?;
            self.volume.write_inode(self.ino, &dir_inode).await?;
            *self.inode.lock() = Some(dir_inode);
            Ok(())
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if name == "." || name == ".." || name.is_empty() {
                return Err(FsError::InvalidPath);
            }
            let mut dir_inode = self.ensure_inode().await?;
            let mut bytes = self.volume.read_dir_bytes(&dir_inode).await?;
            let off = find_entry(self.volume.sb.name_len, &bytes, name).ok_or(FsError::NotFound)?;
            let entry = MxDirEntry::decode(self.volume.sb.name_len, &bytes, off)
                .ok_or(FsError::NotFound)?;
            let mut victim = self.volume.read_inode(entry.ino as u32).await?;
            if !victim.is_dir() {
                return Err(FsError::InvalidPath);
            }
            // Refuse non-empty (more than just "." and "..").
            let child_bytes = self.volume.read_dir_bytes(&victim).await?;
            let entries = super::dir::DirEntry::decode_all(self.volume.sb.name_len, &child_bytes);
            let user_count = entries
                .iter()
                .filter(|e| e.name != "." && e.name != "..")
                .count();
            if user_count != 0 {
                return Err(FsError::Busy);
            }
            self.volume.truncate_inode(&mut victim).await?;
            self.volume.free_inode(entry.ino as u32).await?;
            clear_entry(self.volume.sb.name_len, &mut bytes, off);
            self.volume.write_file(&mut dir_inode, 0, &bytes).await?;
            dir_inode.nlinks = dir_inode.nlinks.saturating_sub(1);
            self.volume.write_inode(self.ino, &dir_inode).await?;
            *self.inode.lock() = Some(dir_inode);
            Ok(())
        })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                return Err(FsError::InvalidPath);
            }
            let mut dir_inode = self.ensure_inode().await?;
            if !dir_inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            let mut bytes = self.volume.read_dir_bytes(&dir_inode).await?;
            if find_entry(self.volume.sb.name_len, &bytes, name).is_some() {
                return Err(FsError::Busy);
            }
            let new_ino = self.volume.alloc_inode().await?;
            let mut link_inode = Inode::new_symlink(dir_inode.mtime);
            // Persist the target text as the symlink body.
            self.volume
                .write_file(&mut link_inode, 0, target.as_bytes())
                .await?;
            self.volume.write_inode(new_ino, &link_inode).await?;
            self.append_dir_entry(&mut dir_inode, &mut bytes, new_ino as u16, name)
                .await?;
            self.volume.write_inode(self.ino, &dir_inode).await?;
            *self.inode.lock() = Some(dir_inode);
            Ok(Arc::new(MinixNode::new_with_inode(
                self.volume.clone(),
                new_ino,
                link_inode,
            )) as Arc<dyn FileOps>)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if old_name.is_empty()
                || new_name.is_empty()
                || old_name == "."
                || old_name == ".."
                || new_name == "."
                || new_name == ".."
            {
                return Err(FsError::InvalidPath);
            }
            let mut dir_inode = self.ensure_inode().await?;
            let mut bytes = self.volume.read_dir_bytes(&dir_inode).await?;
            let old_off =
                find_entry(self.volume.sb.name_len, &bytes, old_name).ok_or(FsError::NotFound)?;
            let old_entry = MxDirEntry::decode(self.volume.sb.name_len, &bytes, old_off)
                .ok_or(FsError::NotFound)?;
            // Refuse if new_name already exists. Linux replaces, but
            // we keep semantics simple.
            if find_entry(self.volume.sb.name_len, &bytes, new_name).is_some() {
                return Err(FsError::Busy);
            }
            // Length check on the new name.
            if new_name.as_bytes().len() > self.volume.sb.name_len.bytes() {
                return Err(FsError::InvalidPath);
            }
            // Overwrite old slot's name in place — same inode number.
            let new_entry = MxDirEntry {
                ino: old_entry.ino,
                name: alloc::string::String::from(new_name),
            };
            new_entry.encode(self.volume.sb.name_len, &mut bytes, old_off);
            self.volume.write_file(&mut dir_inode, 0, &bytes).await?;
            self.volume.write_inode(self.ino, &dir_inode).await?;
            *self.inode.lock() = Some(dir_inode);
            Ok(())
        })
    }
}
