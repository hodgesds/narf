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
//! Write support: `write` + `truncate` are landed on the FileOps
//! side, backed by `volume::write_inode_data` /
//! `volume::truncate_inode` (which sit on the §"Block Allocation"
//! bitmap allocator — see `volume.rs::alloc_block` /
//! `alloc_inode`). The legacy 12-direct + indirect block pointer
//! path is implemented, and ext4 extent trees grow, convert unwritten
//! extents and free through `volume::extent_write`.
//!
//! Directory-mutation surface (create / mkdir / unlink / rmdir /
//! rename / symlink) is implemented in `dir_mut.rs` and dispatched
//! through here. HTREE read decoding lives in `htree.rs`; HTREE
//! write (leaf split + rebalance on insert) is deferred — new
//! dirents land at the tail via the linear walker.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{
    DirEntry as VfsDirEntry, DirOps, FileFolio, FileMapping, FileOps, FileType, FsError, FsFuture,
    Mode, Stat, PAGE_SIZE,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::dir::{for_each_entry, ftype};
use super::inode::{Inode, S_IFMT};
use super::volume::Ext2Volume;

#[derive(Debug, Copy, Clone)]
pub struct Ext2NodeState {
    pub inode_no: u32,
    pub stat: Stat,
    /// Cached inode bytes, populated by lookup or lazily on first I/O and
    /// refreshed after every data or metadata mutation.
    pub inode: Option<Inode>,
}

/// The in-memory inode of one ext2 inode. Only ever constructed by the
/// volume's inode cache (`Ext2Volume::iget`), so there is at most one live
/// node per on-disk inode and every path to the file shares it.
#[derive(Debug)]
pub struct Ext2Node<B: BlockDevice + 'static> {
    pub volume: Arc<Ext2Volume<B>>,
    inode_no: u32,
    /// This node's own `Arc`, for handing out `Arc<dyn …>` views of it
    /// (`as_dir`) without minting a second node.
    self_weak: Weak<Ext2Node<B>>,
    pub state: IrqSafeSpinLock<Ext2NodeState>,
    /// This inode's page cache (Linux `inode->i_mapping`). Regular-file
    /// `read`, `write` and `truncate` all go through it, so every holder of
    /// the inode sees one copy of each file page. Keyed by this node's
    /// incarnation as well as the inode number, so a freed-and-reused inode
    /// number can never alias a still-live node's pages.
    mapping: FileMapping,
    /// Its last link went while this node was live (Linux: `i_nlink == 0`
    /// with references outstanding). The inode and its blocks are released
    /// when the node drops, not at unlink.
    orphaned: core::sync::atomic::AtomicBool,
}

impl<B: BlockDevice + 'static> Drop for Ext2Node<B> {
    fn drop(&mut self) {
        self.volume.icache_evict(self.inode_no, self as *const Self);
        // `iput_final` -> `ext2_evict_inode`: an unlinked inode is released
        // with its last reference. Dropping cannot do I/O, so hand it to the
        // volume, which releases it under the next inode update.
        if self.orphaned.load(core::sync::atomic::Ordering::Acquire) {
            self.volume.queue_orphan(self.inode_no);
        }
        // `evict` -> `truncate_inode_pages_final`: the in-memory inode's
        // pages go with it.
        self.mapping.remove_from(0);
    }
}

impl<B: BlockDevice + 'static> Ext2Node<B> {
    /// Build the cache's node for `inode_no`. Called by `Ext2Volume` under
    /// its icache lock; nothing else may construct a node.
    pub(crate) fn new_cached(volume: Arc<Ext2Volume<B>>, inode_no: u32, inode: Inode) -> Arc<Self> {
        let mapping = volume.new_file_mapping(inode_no);
        Arc::new_cyclic(|self_weak| Self {
            inode_no,
            self_weak: self_weak.clone(),
            mapping,
            orphaned: core::sync::atomic::AtomicBool::new(false),
            state: IrqSafeSpinLock::new(Ext2NodeState {
                inode_no,
                stat: Self::stat_from_inode(&volume, &inode),
                inode: Some(inode),
            }),
            volume,
        })
    }

    /// Defer this inode's release to the drop of the node (see `orphaned`).
    pub(crate) fn mark_orphaned(&self) {
        self.orphaned
            .store(true, core::sync::atomic::Ordering::Release);
    }

    /// Replace the cached inode with what was just written to disk. Called
    /// by the volume's inode write funnel for every inode write.
    pub(crate) fn set_cached_inode(&self, inode: Inode) {
        let stat = Self::stat_from_inode(&self.volume, &inode);
        let mut state = self.state.lock();
        state.inode = Some(inode);
        state.stat = stat;
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
                perms: inode.mode & 0o7777,
            },
            // Report the on-disk `i_mtime` (wall-clock seconds since the epoch),
            // not a hardcoded 0 (which made every ext2 file claim mtime 1970 and
            // broke `ls -l`, `make`, `git`, `tar`, and any autoload/cache that
            // keys on mtime). The ns→cycles→ns round trip is NOT exact, so the
            // precise value (with ext4's nanoseconds) travels in
            // `InodeAttrs::mtime_ns`, which `stat`/`statx` prefer.
            mtime_cycles: narf_time::ns_to_cycles(inode.mtime_ns()),
        }
    }

    /// Give the inode named `old_name` in directory `old_parent` a second
    /// name `new_name` in directory `new_parent` (same volume).
    async fn hardlink_into(
        &self,
        old_parent: u32,
        old_name: &str,
        new_parent: u32,
        new_name: &str,
    ) -> Result<(), FsError> {
        let parent_inode = self.volume.read_inode(old_parent).await?;
        let (target, _) = self
            .volume
            .dir_lookup(&parent_inode, old_name.as_bytes())
            .await?;
        if target == 0 {
            return Err(FsError::NotFound);
        }
        self.volume
            .dir_hardlink(new_parent, new_name.as_bytes(), target)
            .await
    }

    /// `InodeAttrs` for this node from the cached on-disk inode: device plus
    /// exact atime/ctime/mtime, nanoseconds included. Nodes come out of
    /// `iget` with their inode cached; an uncached one reports device only
    /// and the stat path falls back to `Stat`.
    fn attrs_from_cache(&self) -> narf_filesystem::InodeAttrs {
        let inode = self.state.lock().inode;
        narf_filesystem::InodeAttrs {
            dev: self.volume.dev,
            atime_ns: inode.map_or(0, |i| i.atime_ns()),
            ctime_ns: inode.map_or(0, |i| i.ctime_ns()),
            mtime_ns: inode.map_or(0, |i| i.mtime_ns()),
            ..Default::default()
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

    /// Read `dst.len()` bytes of a DIRECTORY's blocks starting at `offset`,
    /// through the block-device mapping where directory blocks live (they
    /// are rewritten by `dir_mut` with block writes, which invalidate
    /// exactly that mapping). Regular-file data goes through the inode's
    /// page cache instead (`read_file`). Stops short of `dst.len()` only at
    /// EOF; holes read as zero.
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
            } else if in_block == 0 && chunk == bs as usize {
                // mmap materialization normally asks for one aligned 4 KiB
                // filesystem block. Fill the caller's page directly instead
                // of allocating and copying a same-sized temporary buffer.
                self.volume
                    .read_block(physical, &mut dst[total..total + chunk])
                    .await?;
            } else {
                let mut blockbuf = vec![0u8; bs as usize];
                self.volume.read_block(physical, &mut blockbuf).await?;
                dst[total..total + chunk].copy_from_slice(&blockbuf[in_block..in_block + chunk]);
            }
            total += chunk;
            cursor += chunk as u64;
            to_read -= chunk as u64;
        }
        Ok(total)
    }

    /// File page `page`, from the inode's page cache or read in by
    /// `->read_folio` (`Ext2Volume::read_file_page`). The fill reads the
    /// cached inode only after it owns the page's fill ticket, so it sees
    /// every block a completed write allocated.
    async fn file_page(&self, page: u64) -> Result<FileFolio, FsError> {
        self.mapping
            .get_or_fill(page, |mut folio| async move {
                let inode = self.load_inode().await?;
                self.volume
                    .read_file_page(&inode, page, &mut folio[..PAGE_SIZE])
                    .await?;
                Ok(folio)
            })
            .await
    }

    /// `filemap_read`: copy `[offset, offset + dst.len())` out of the page
    /// cache, clamped at EOF. Under memory pressure (no folio frame) a page
    /// is read uncached instead — it cannot be resident, so it holds no
    /// newer bytes than the disk.
    async fn read_file(&self, offset: u64, dst: &mut [u8]) -> Result<usize, FsError> {
        let size = u64::from(self.load_inode().await?.size);
        if offset >= size {
            return Ok(0);
        }
        let len = (dst.len() as u64).min(size - offset) as usize;
        let mut done = 0usize;
        while done < len {
            let pos = offset + done as u64;
            let page = pos / PAGE_SIZE as u64;
            let in_page = (pos % PAGE_SIZE as u64) as usize;
            let n = (PAGE_SIZE - in_page).min(len - done);
            match self.file_page(page).await {
                Ok(folio) => folio.read(in_page, &mut dst[done..done + n]),
                Err(FsError::OutOfMemory) => {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(PAGE_SIZE)
                        .map_err(|_| FsError::OutOfMemory)?;
                    bytes.resize(PAGE_SIZE, 0);
                    let inode = self.load_inode().await?;
                    self.volume.read_file_page(&inode, page, &mut bytes).await?;
                    dst[done..done + n].copy_from_slice(&bytes[in_page..in_page + n]);
                }
                Err(error) => return Err(error),
            }
            done += n;
        }
        Ok(len)
    }

    /// `generic_perform_write`, write-through: copy each chunk into the
    /// cached page (reading the page first when it is not resident, like
    /// `write_begin`), then write the filesystem blocks it touched straight
    /// from that page. Readers and mappings see the new bytes as soon as
    /// they are in the page; the disk has them before this returns, so a
    /// write needs no later writeback and fsync only has mapped stores to
    /// flush. The caller holds `inode_update_lock` and persists `inode`.
    ///
    /// Returns the bytes written; a failure after some progress reports the
    /// progress (Linux returns a short write). A page whose block write
    /// failed keeps the new bytes and is marked dirty, so the cache never
    /// silently reverts and writeback retries it.
    async fn write_file(
        &self,
        inode: &mut Inode,
        offset: u64,
        src: &[u8],
    ) -> Result<usize, FsError> {
        let inode_no = self.inode_no;
        let mut done = 0usize;
        while done < src.len() {
            let pos = offset + done as u64;
            let page = pos / PAGE_SIZE as u64;
            let in_page = (pos % PAGE_SIZE as u64) as usize;
            let n = (PAGE_SIZE - in_page).min(src.len() - done);
            // Only a fill that raced a removal of this very page can come
            // back unpublished; truncation and eviction are excluded by the
            // caller's lock and our own reference, so retrying converges.
            let folio = loop {
                match self.file_page(page).await {
                    Ok(folio) if folio.published() => break folio,
                    Ok(_) => continue,
                    Err(error) if done == 0 => return Err(error),
                    Err(_) => return Ok(done),
                }
            };
            folio.write(in_page, &src[done..done + n]);
            let written = self
                .volume
                .write_file_page(inode_no, inode, page, &folio, in_page, in_page + n, true)
                .await;
            if let Err(error) = written {
                self.mapping.mark_dirty(page);
                if done == 0 {
                    return Err(error);
                }
                return Ok(done);
            }
            done += n;
            let end = pos + n as u64;
            if end > u64::from(inode.size) {
                inode.size = end as u32;
            }
            // Publish the new block map and size to concurrent page fills
            // before this page's reference is dropped (after which reclaim
            // could evict it and a fill would reread the blocks).
            self.set_cached_inode(*inode);
        }
        Ok(done)
    }

    /// `block_truncate_page` + `truncate_inode_partial_folio`: zero the
    /// bytes from `new_size` to the end of its page in the cache and write
    /// the block(s) of that page from `new_size` on to the disk.
    async fn zero_tail_after(&self, inode: &mut Inode, new_size: u64) -> Result<(), FsError> {
        let in_page = (new_size % PAGE_SIZE as u64) as usize;
        if in_page == 0 {
            return Ok(());
        }
        let page = new_size / PAGE_SIZE as u64;
        let folio = loop {
            let folio = self.file_page(page).await?;
            if folio.published() {
                break folio;
            }
        };
        folio.zero(in_page, PAGE_SIZE - in_page);
        let inode_no = self.inode_no;
        self.volume
            .write_file_page(inode_no, inode, page, &folio, in_page, PAGE_SIZE, false)
            .await
    }

    /// `ext4_punch_hole`: deallocate `offset..offset + len`, which then reads
    /// as zeros; `i_size` never changes. Block-mapped and extent-mapped
    /// inodes both punch. A hole at or past EOF is a no-op, and one running
    /// past EOF stops at the end of the block holding it. The partial blocks
    /// at either edge are zeroed in place (only where mapped: zeroing must
    /// not allocate) and every whole block inside is released.
    async fn punch_hole(&self, offset: u64, len: u64) -> Result<(), FsError> {
        let bs = self.volume.block_size() as u64;
        let page = PAGE_SIZE as u64;
        let clip = |size: u64| -> Option<u64> {
            if offset >= size {
                return None;
            }
            let end = offset.saturating_add(len);
            Some(if end >= size {
                size.div_ceil(bs) * bs
            } else {
                end
            })
        };
        let Some(end) = clip(self.stat().size) else {
            return Ok(());
        };
        let (first_page, end_page) = (offset / page, end.div_ceil(page));
        // `ext4_truncate_page_cache_block_range`: dirty data in the range
        // reaches disk first, and no mapping may keep a page of it — the
        // blocks underneath are about to change.
        self.write_back_dirty(first_page, end_page).await?;
        narf_filesystem::unmap_mapping_range(self, first_page * page)?;
        let _update = self.volume.lock_inode_updates().await;
        let inode_no = self.state.lock().inode_no;
        let mut inode = self.volume.read_inode(inode_no).await?;
        let Some(end) = clip(u64::from(inode.size)) else {
            return Ok(());
        };
        self.mapping.remove_range(first_page, end_page);
        let result = self.punch_blocks(inode_no, &mut inode, offset, end).await;
        // `file_modified`, whether or not the punch got all the way.
        inode.touch_ctime_mtime(Ext2Volume::<B>::now_secs());
        let persisted = self.volume.write_inode(inode_no, &inode).await;
        // A fault between the removal above and the block changes may have
        // cached the old contents again.
        self.mapping.remove_range(first_page, end_page);
        result.and(persisted)
    }

    /// The on-disk half of [`Self::punch_hole`] over `offset..end`
    /// (`ext4_zero_partial_blocks` + `ext4_ext_remove_space` /
    /// `ext4_ind_remove_space`).
    async fn punch_blocks(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        offset: u64,
        end: u64,
    ) -> Result<(), FsError> {
        let bs = self.volume.block_size() as u64;
        let first_whole = offset.div_ceil(bs);
        let end_whole = end / bs;
        // The partial head, which also covers a hole inside one block.
        if offset % bs != 0 {
            let to = end.min((offset / bs + 1) * bs);
            self.zero_mapped(inode, offset, to).await?;
        }
        // The partial tail, unless the head already covered its block.
        if end % bs != 0 && end_whole >= first_whole {
            self.zero_mapped(inode, end_whole * bs, end).await?;
        }
        self.volume
            .free_block_range(inode_no, inode, first_whole, end_whole)
            .await
    }

    /// Zero `from..to` (inside one block) on disk if that block is mapped; a
    /// hole already reads as zeros, and zeroing must not allocate one.
    async fn zero_mapped(&self, inode: &Inode, from: u64, to: u64) -> Result<(), FsError> {
        let bs = self.volume.block_size() as u64;
        let phys = self.volume.map_block(inode, from / bs).await?;
        if phys == 0 {
            return Ok(());
        }
        let zeros = alloc::vec![0u8; (to - from) as usize];
        self.volume
            .write_byte_range(phys * bs + from % bs, &zeros)
            .await
    }

    /// Write the dirty pages in `[first_page, end_page)` to disk (Linux
    /// `filemap_write_and_wait_range` over `->writepages`): every block of
    /// each page inside EOF, allocating holes, then persist the inode if
    /// that allocated anything. A page whose write fails is re-marked dirty
    /// and the error is returned.
    pub(crate) async fn write_back_dirty(
        &self,
        first_page: u64,
        end_page: u64,
    ) -> Result<(), FsError> {
        let _update = self.volume.lock_inode_updates().await;
        let dirty = self.mapping.take_dirty(first_page, end_page);
        if dirty.is_empty() {
            return Ok(());
        }
        let inode_no = self.inode_no;
        let mut inode = self.volume.read_inode(inode_no).await?;
        let before = (inode.blocks, inode.block);
        let size = u64::from(inode.size);
        let mut result = Ok(());
        for folio in &dirty {
            let page_start = folio.page() * PAGE_SIZE as u64;
            if page_start >= size {
                continue; // wholly past EOF: nothing of it is file data
            }
            let hi = (size - page_start).min(PAGE_SIZE as u64) as usize;
            if let Err(error) = self
                .volume
                .write_file_page(inode_no, &mut inode, folio.page(), folio, 0, hi, true)
                .await
            {
                self.mapping.mark_dirty(folio.page());
                result = Err(error);
            }
        }
        if (inode.blocks, inode.block) != before {
            self.volume.write_inode(inode_no, &inode).await?;
        }
        result
    }

    /// Walk `inode`'s directory bytes calling `f` for each entry.
    /// Stops when `f` returns `false`.
    async fn walk_dir<F: FnMut(&str, u32, u8) -> bool>(
        &self,
        inode: &Inode,
        mut f: F,
    ) -> Result<(), FsError> {
        let size = inode.size as usize;
        if size == 0 {
            return Ok(());
        }
        let block_size = self.volume.block_size();
        let mut continue_walk = true;
        let mut offset = 0usize;
        while offset < size && continue_walk {
            let logical = (offset / block_size) as u64;
            let valid = core::cmp::min(block_size, size - offset);
            let physical = self.volume.map_block(inode, logical).await?;
            if physical != 0 {
                let block = self.volume.read_block_view(physical).await?;
                for_each_entry(&block[..valid], |entry| {
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
            }
            offset += valid;
        }
        Ok(())
    }
}

impl<B: BlockDevice + 'static> FileOps for Ext2Node<B> {
    /// Stored file data: no `.poll`, so `epoll_ctl` refuses it. Decided per
    /// inode — a FIFO or device node living in this filesystem dispatches
    /// elsewhere on open and stays pollable. See `fs_inode_can_poll`.
    fn can_poll(&self) -> bool {
        narf_filesystem::fs_inode_can_poll(self.stat().mode.file_type)
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let inode = self.load_inode().await?;
            // The VFS path walker (`resolve_async`) reads a symlink's target
            // via `FileOps::read`. A *fast* symlink (target ≤ 60 bytes, e.g.
            // Alpine's `/bin/cat` → `/bin/busybox`) stores the target inline in
            // the inode's `i_block[]` with no data blocks, so the generic
            // block-pointer walk below returns nothing — making every symlink
            // unresolvable (and every busybox applet "not found" in a mounted
            // distro rootfs). Serve the link target from the symlink-aware path.
            if inode.is_symlink() {
                let target = self.volume.read_symlink_target(&inode).await?;
                let start = offset as usize;
                if start >= target.len() {
                    return Ok(0);
                }
                let n = (target.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&target[start..start + n]);
                return Ok(n);
            }
            if inode.is_dir() {
                return self.read_inode_at(&inode, offset, buf).await;
            }
            self.read_file(offset, buf).await
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let _update = self.volume.lock_inode_updates().await;
            // Mutations start from the current on-disk inode.
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            if inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            let result = self.write_file(&mut inode, offset, buf).await;
            let persisted = match &result {
                // Nothing reached the file: leave the inode as it was.
                Err(_) => Ok(()),
                Ok(_) => self.volume.write_inode(inode_no, &inode).await,
            };
            if persisted.is_err() || result.is_err() {
                // The cached inode ran ahead of the disk while the write was
                // in progress; put it back to what the disk holds.
                if let Ok(on_disk) = self.volume.read_inode(inode_no).await {
                    self.set_cached_inode(on_disk);
                }
            }
            persisted?;
            result
        })
    }

    fn fsync<'a>(&'a self, _data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // `ext4_sync_file`: write back this inode's dirty pages, then
            // flush the device's volatile cache so the data is durable.
            self.write_back_dirty(0, u64::MAX).await?;
            self.volume.device.flush().await;
            Ok(())
        })
    }

    fn stat(&self) -> Stat {
        self.state.lock().stat
    }

    fn mmap_is_ram(&self) -> bool {
        true
    }

    fn supports_mmap_fault(&self) -> bool {
        true
    }

    /// `filemap_fault`: expose the same canonical folio used by read/write.
    /// The mapping is conservatively dirty from its first fault because NARF
    /// does not yet collect hardware PTE dirty bits for filesystem writeback.
    fn mmap_fault(&self, offset: u64) -> Result<u64, FsError> {
        if offset % PAGE_SIZE as u64 != 0 || offset >= self.stat().size {
            return Err(FsError::InvalidData);
        }
        let page = offset / PAGE_SIZE as u64;
        loop {
            let folio = narf_scheduler::block_on_spin(self.file_page(page))?;
            // A concurrent shrink publishes its new i_size before removing
            // folios. Never install a newly-obsolete page after that point.
            if offset >= self.stat().size {
                return Err(FsError::InvalidData);
            }
            if !folio.published() {
                continue;
            }
            assert!(self.mapping.mark_dirty(page));
            return Ok(folio.mmap_frame());
        }
    }

    fn ino(&self) -> u64 {
        // Real on-disk inode number — distinct per file, so musl's
        // DSO dedup by (st_dev, st_ino) never collapses two libraries.
        self.state.lock().inode_no as u64
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.attrs_from_cache()
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            let _ = self.load_inode().await?;
            Ok(self.state.lock().stat)
        })
    }

    /// `ext4_fallocate`. The VFS checks (`vfs_fallocate`: argument ranges,
    /// mode combinations, fd mode, file type, immutable/append-only) are the
    /// syscall layer's; what reaches here is a valid request.
    fn fallocate<'a>(&'a self, mode: u32, offset: u64, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            const KEEP_SIZE: u32 = 0x01;
            const PUNCH_HOLE: u32 = 0x02;
            if mode == PUNCH_HOLE | KEEP_SIZE {
                return self.punch_hole(offset, len).await;
            }
            // Modes this filesystem implements; anything else is
            // `ext4_fallocate`'s -EOPNOTSUPP.
            if mode & !KEEP_SIZE != 0 {
                return Err(FsError::Unsupported);
            }
            let end = offset.checked_add(len).ok_or(FsError::InvalidData)?;
            let _update = self.volume.lock_inode_updates().await;
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            if inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            // LINUX-GAP: `i_size` is 32 bits here (no `i_size_high`), so a
            // range ending past 4 GiB is refused as `truncate` refuses it
            // (EINVAL) where Linux would allocate it.
            let new_size = if mode & KEEP_SIZE == 0 && end > u64::from(inode.size) {
                Some(u32::try_from(end).map_err(|_| FsError::InvalidData)?)
            } else {
                None
            };
            let bs = self.volume.block_size() as u64;
            let allocated = self
                .volume
                .preallocate(inode_no, &mut inode, offset / bs, end.div_ceil(bs))
                .await;
            if let Err(FsError::Unsupported) = allocated {
                // Block-mapped: nothing was touched.
                return Err(FsError::Unsupported);
            }
            // `ext4_do_fallocate` -> `ext4_alloc_file_blocks`: the size moves
            // only once the whole range is allocated; a partial allocation
            // (ENOSPC) keeps its blocks but not a size covering them.
            if allocated.is_ok() {
                if let Some(size) = new_size {
                    inode.size = size;
                }
            }
            // `file_modified`.
            inode.touch_ctime_mtime(Ext2Volume::<B>::now_secs());
            self.volume.write_inode(inode_no, &inode).await?;
            allocated
        })
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let new_size = u32::try_from(len).map_err(|_| FsError::InvalidData)?;
            let _update = self.volume.lock_inode_updates().await;
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            if inode.is_dir() {
                return Err(FsError::InvalidPath);
            }
            let old_size = u64::from(inode.size);
            if len < old_size {
                // Publish i_size first so a racing fault at/after the new EOF
                // fails. Then revoke every existing borrowed PTE before cache
                // folios are removed or block ownership changes.
                let mut visible = inode;
                visible.size = new_size;
                self.set_cached_inode(visible);
                if let Err(error) = narf_filesystem::unmap_mapping_range(self, len) {
                    self.set_cached_inode(inode);
                    return Err(error);
                }
            }
            if len == 0 {
                if let Err(error) = self.volume.truncate_inode(&mut inode).await {
                    self.set_cached_inode(self.volume.read_inode(inode_no).await.unwrap_or(inode));
                    return Err(error);
                }
            } else {
                // Growing is size only: the new range reads as a hole.
                inode.size = new_size;
            }
            if len < old_size {
                // `ext2_setsize` -> `block_truncate_page`: zero the rest of
                // the block holding the new EOF, in the cache and on disk,
                // so a later extension reads zeros there rather than the old
                // bytes. Done before the size shrinks in the cached inode so
                // the page still fills with the pre-truncate contents.
                if let Err(error) = self.zero_tail_after(&mut inode, len).await {
                    self.set_cached_inode(self.volume.read_inode(inode_no).await.unwrap_or(inode));
                    return Err(error);
                }
                // `truncate_pagecache`: drop every page wholly past the new
                // EOF — BEFORE its blocks are freed, so no cached page can
                // be written back into a block another file now owns.
                self.mapping.remove_from(len.div_ceil(PAGE_SIZE as u64));
                // `ext4_truncate`: release every block wholly past the new
                // EOF. Keeping them mapped let the next extension read the
                // pre-truncate bytes back (fsx: truncate down, then write
                // past a hole or fallocate, then read).
                if len != 0 {
                    let first = len.div_ceil(self.volume.block_size() as u64);
                    if let Err(error) = self
                        .volume
                        .truncate_inode_from(inode_no, &mut inode, first)
                        .await
                    {
                        self.set_cached_inode(
                            self.volume.read_inode(inode_no).await.unwrap_or(inode),
                        );
                        return Err(error);
                    }
                }
            }
            if let Err(error) = self.volume.write_inode(inode_no, &inode).await {
                self.set_cached_inode(self.volume.read_inode(inode_no).await.unwrap_or(inode));
                return Err(error);
            }
            Ok(())
        })
    }

    fn owners(&self) -> (u32, u32) {
        self.state
            .lock()
            .inode
            .map_or((0, 0), |inode| (inode.uid, inode.gid))
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _update = self.volume.lock_inode_updates().await;
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            inode.uid = uid;
            inode.gid = gid;
            if !inode.is_dir() {
                // Linux chown kills privilege-bearing mode bits on
                // non-directories (ATTR_KILL_SUID/ATTR_KILL_SGID).
                inode.mode &= !0o6000;
            }
            inode.touch_ctime(Ext2Volume::<B>::now_secs());
            self.volume.write_inode(inode_no, &inode).await?;
            let stat = Self::stat_from_inode(&self.volume, &inode);
            let mut state = self.state.lock();
            state.inode = Some(inode);
            state.stat = stat;
            Ok(())
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _update = self.volume.lock_inode_updates().await;
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            inode.mode = (inode.mode & S_IFMT) | (perms & 0o7777);
            inode.touch_ctime(Ext2Volume::<B>::now_secs());
            self.volume.write_inode(inode_no, &inode).await?;
            self.acl_chmod_locked(inode_no, perms).await?;
            self.refresh_cached_inode(inode_no).await
        })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(self.xattr_set(name, Some(value), flags))
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(self.xattr_get(name))
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(self.xattr_list())
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(self.xattr_set(name, None, 0))
    }

    /// Bridge an opened-directory fd to its `DirOps`. `resolve_async`
    /// returns a directory as an `Ext2Node` *FileOps* (see
    /// `lookup_async`), so `open(dir, O_DIRECTORY)` installs that
    /// FileOps in the fd table; `sys_getdents64` then needs `as_dir()`
    /// to recover the `DirOps` view. Returns `None` for non-directories
    /// so `getdents64` on a regular-file fd is ENOTDIR. The view is this
    /// same node: one in-memory inode per on-disk inode.
    fn as_dir(&self) -> Option<Arc<dyn DirOps>> {
        if self.state.lock().stat.mode.file_type != FileType::Dir {
            return None;
        }
        self.self_weak.upgrade().map(|node| node as Arc<dyn DirOps>)
    }
}

impl<B: BlockDevice + 'static> DirOps for Ext2Node<B> {
    fn ino(&self) -> u64 {
        self.state.lock().inode_no as u64
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.attrs_from_cache()
    }

    /// The directory's on-disk `i_mtime` with ext4 nanoseconds. Without it
    /// every ext2/ext4 directory stat'd as the epoch, so fontconfig judged
    /// every system font cache stale (it compares the font directory's exact
    /// `st_mtim`) and rescanned all fonts on each application start.
    fn dir_mtime_ns(&self) -> u64 {
        self.state.lock().inode.map_or(0, |i| i.mtime_ns())
    }

    fn dcache_identity(&self) -> (usize, u64, u64) {
        (
            Arc::as_ptr(&self.volume) as *const () as usize,
            0,
            u64::from(self.inode_no),
        )
    }

    fn rcu_walkable(&self) -> bool {
        true
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Ext2 lookups are fundamentally async (inode + directory-block reads),
        // but the sync VFS API must still work for callers that can't await —
        // notably bind-mount source resolution (`build_bind_fs` walking a DEEP
        // StateDirectory= path such as /var/lib/systemd/linger) and mount-subtree
        // cloning. Drive the async lookup to completion via the SPIN bridge: it
        // is re-entrancy-safe inside a syscall's executor poll and never halts,
        // so the block-device IRQ (IRQs are enabled on this path, and no mount
        // lock is held) completes the reads. Returning None made every deep bind
        // fail NotFound → ENOENT → 226/EXIT_NAMESPACE (logind et al.).
        narf_scheduler::block_on_spin(self.lookup_async(name)).ok()
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let inode = self.load_inode().await?;
            let (found_ino, _) = self.volume.dir_lookup(&inode, name.as_bytes()).await?;
            Ok(self.volume.iget(found_ino).await? as Arc<dyn FileOps>)
        })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        // See `lookup`: drive the async directory lookup to completion so the
        // synchronous VFS API resolves real entries on this block-backed FS.
        narf_scheduler::block_on_spin(self.lookup_dir_async(name)).ok()
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let inode = self.load_inode().await?;
            let (found_ino, found_type) = self.volume.dir_lookup(&inode, name.as_bytes()).await?;
            let node = self.volume.iget(found_ino).await?;
            // Honour the on-disk inode mode rather than the rev-0
            // dirent type byte, which is unreliable on rev-0 volumes
            // (overlap with the high byte of `name_len`).
            if !node.load_inode().await?.is_dir() && found_type != ftype::DIR {
                return Err(FsError::NotFound);
            }
            Ok(node as Arc<dyn DirOps>)
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

    fn dir_mode(&self) -> u16 {
        self.state.lock().stat.mode.perms
    }

    fn set_dir_mode_async<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _update = self.volume.lock_inode_updates().await;
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            inode.mode = (inode.mode & S_IFMT) | (perms & 0o7777);
            inode.touch_ctime(Ext2Volume::<B>::now_secs());
            self.volume.write_inode(inode_no, &inode).await?;
            self.acl_chmod_locked(inode_no, perms).await?;
            self.refresh_cached_inode(inode_no).await
        })
    }

    fn dir_owners(&self) -> (u32, u32) {
        self.state
            .lock()
            .inode
            .map_or((0, 0), |inode| (inode.uid, inode.gid))
    }

    fn set_dir_owners_async<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _update = self.volume.lock_inode_updates().await;
            let inode_no = self.state.lock().inode_no;
            let mut inode = self.volume.read_inode(inode_no).await?;
            inode.uid = uid;
            inode.gid = gid;
            inode.touch_ctime(Ext2Volume::<B>::now_secs());
            self.volume.write_inode(inode_no, &inode).await?;
            let stat = Self::stat_from_inode(&self.volume, &inode);
            let mut state = self.state.lock();
            state.inode = Some(inode);
            state.stat = stat;
            Ok(())
        })
    }

    // Directory-mutation surface — wired through to the
    // `dir_mut::dir_*` helpers on `Ext2Volume`. Each method:
    //   * resolves this node's parent-inode number,
    //   * dispatches to the volume operation,
    //   * returns a fresh handle for create/mkdir/symlink.
    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let parent_ino = self.state.lock().inode_no;
            let new_ino = self
                .volume
                .dir_create_regular(parent_ino, name.as_bytes(), 0o644)
                .await?;
            Ok(self.volume.iget(new_ino).await? as Arc<dyn FileOps>)
        })
    }

    fn create_with_attrs<'a>(
        &'a self,
        name: &'a str,
        perms: u16,
        uid: u32,
        gid: u32,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let parent_ino = self.state.lock().inode_no;
            let new_ino = self
                .volume
                .dir_create_regular_with_attrs(parent_ino, name.as_bytes(), perms, uid, gid)
                .await?;
            Ok(self.volume.iget(new_ino).await? as Arc<dyn FileOps>)
        })
    }
    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let parent_ino = self.state.lock().inode_no;
            let new_ino = self
                .volume
                .dir_create_directory(parent_ino, name.as_bytes(), 0o755)
                .await?;
            Ok(self.volume.iget(new_ino).await? as Arc<dyn DirOps>)
        })
    }
    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let parent_ino = self.state.lock().inode_no;
            self.volume.dir_unlink(parent_ino, name.as_bytes()).await
        })
    }
    /// `link(2)` within this directory: ext2/ext4 `ext4_link` adds a dirent
    /// for the existing inode and bumps `i_links_count`.
    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[new_name]);
            let parent_ino = self.state.lock().inode_no;
            self.hardlink_into(parent_ino, old_name, parent_ino, new_name)
                .await
        })
    }

    /// `link(2)` into another directory of the SAME volume. A directory of a
    /// different filesystem is EXDEV territory, which the syscall resolves
    /// before it gets here; refuse it rather than write a foreign inode
    /// number into this volume.
    fn link_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let (volume_id, _, new_parent) = new_dir.dcache_identity();
            if volume_id != Arc::as_ptr(&self.volume) as *const () as usize {
                return Err(FsError::Unsupported);
            }
            let new_parent = u32::try_from(new_parent).map_err(|_| FsError::InvalidData)?;
            let _path_mutation = narf_filesystem::begin_path_mutation(new_dir, &[new_name]);
            let old_parent = self.state.lock().inode_no;
            self.hardlink_into(old_parent, old_name, new_parent, new_name)
                .await
        })
    }

    /// `ext4_rename` across directories of this volume. The VFS has already
    /// done `do_renameat2`'s checks (same mount, types, permissions,
    /// ancestry); `dir_rename` moves the dirent, replaces a victim (an empty
    /// directory only), and rebalances link counts and a moved directory's
    /// `..`. Without this every cross-directory move on ext2/ext4 fell back to
    /// EXDEV (directories) or a link+unlink emulation (files).
    fn rename_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
        flags: u32,
    ) -> FsFuture<'a, ()> {
        const RENAME_NOREPLACE: u32 = 1;
        Box::pin(async move {
            // RENAME_EXCHANGE / RENAME_WHITEOUT are not implemented here; the
            // VFS answers EINVAL for them, as Linux does for an unsupported
            // flag.
            if flags & !RENAME_NOREPLACE != 0 {
                return Err(FsError::Unsupported);
            }
            let (volume_id, _, new_parent) = new_dir.dcache_identity();
            if volume_id != Arc::as_ptr(&self.volume) as *const () as usize {
                return Err(FsError::Unsupported);
            }
            let new_parent = u32::try_from(new_parent).map_err(|_| FsError::InvalidData)?;
            let _old_mutation = narf_filesystem::begin_path_mutation(self, &[old_name]);
            let _new_mutation = narf_filesystem::begin_path_mutation(new_dir, &[new_name]);
            let old_parent = self.state.lock().inode_no;
            if flags & RENAME_NOREPLACE != 0 {
                let new_parent_inode = self.volume.read_inode(new_parent).await?;
                if self
                    .volume
                    .dir_lookup(&new_parent_inode, new_name.as_bytes())
                    .await
                    .is_ok()
                {
                    return Err(FsError::AlreadyExists);
                }
            }
            self.volume
                .dir_rename(
                    old_parent,
                    old_name.as_bytes(),
                    new_parent,
                    new_name.as_bytes(),
                )
                .await
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let parent_ino = self.state.lock().inode_no;
            self.volume.dir_rmdir(parent_ino, name.as_bytes()).await
        })
    }
    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[old_name, new_name]);
            let parent_ino = self.state.lock().inode_no;
            self.volume
                .dir_rename(
                    parent_ino,
                    old_name.as_bytes(),
                    parent_ino,
                    new_name.as_bytes(),
                )
                .await
        })
    }
    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let _path_mutation = narf_filesystem::begin_path_mutation(self, &[name]);
            let parent_ino = self.state.lock().inode_no;
            let new_ino = self
                .volume
                .dir_create_symlink(parent_ino, name.as_bytes(), target.as_bytes())
                .await?;
            Ok(self.volume.iget(new_ino).await? as Arc<dyn FileOps>)
        })
    }

    /// `Some(false)` for a directory whose inode carries no xattr at all —
    /// the path-walk permission check then skips the ACL read — else "ask
    /// properly".
    fn access_acl_present(&self) -> Option<bool> {
        match self.state.lock().inode {
            Some(inode) if !inode.has_xattrs => Some(false),
            _ => None,
        }
    }

    /// The directory's `system.posix_acl_default` in uapi form, for the
    /// VFS's `posix_acl_create` at create time.
    fn default_acl(&self) -> Option<Vec<u8>> {
        narf_scheduler::block_on_spin(self.xattr_get(narf_filesystem::XATTR_NAME_POSIX_ACL_DEFAULT))
            .ok()
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(self.xattr_set(name, Some(value), flags))
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(self.xattr_get(name))
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(self.xattr_list())
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(self.xattr_set(name, None, 0))
    }
}

// ── extended attributes and POSIX ACLs ──────────────────────────────
//
// Storage is `volume::xattr`. The ACL rules are `fs/ext4/acl.c`:
// `ext4_set_acl` runs `posix_acl_update_mode` for an ACCESS ACL (the mode's
// permission bits become the ACL's, and an ACL that is exactly the mode is
// not stored), `__ext4_set_acl` refuses a DEFAULT ACL on a non-directory
// (`acl ? -EACCES : 0`), and `ext4_setattr` -> `posix_acl_chmod` keeps the
// stored ACL's mask/group entry in step with a chmod. `inode_owner_or_capable`
// is the syscall layer's (see `xattr_permission_check`).

/// `setxattr(2)` flags.
const XATTR_CREATE: u32 = 1;
const XATTR_REPLACE: u32 = 2;

impl<B: BlockDevice + 'static> Ext2Node<B> {
    async fn xattr_get(&self, name: &str) -> Result<Vec<u8>, FsError> {
        use super::volume::xattr;
        let (index, suffix) = xattr::split_name(name).ok_or(FsError::Unsupported)?;
        let inode_no = self.state.lock().inode_no;
        let st = self.volume.xattr_load(inode_no).await?;
        let entry = xattr::find(&st, index, suffix).ok_or(FsError::NotFound)?;
        if index == xattr::INDEX_ACL_ACCESS || index == xattr::INDEX_ACL_DEFAULT {
            // `ext4_get_acl` -> `ext4_acl_from_disk`, then the VFS's
            // `posix_acl_to_xattr`.
            return Ok(xattr::acl_from_disk(&entry.value)?.to_xattr());
        }
        Ok(entry.value.clone())
    }

    async fn xattr_list(&self) -> Result<Vec<u8>, FsError> {
        let inode_no = self.state.lock().inode_no;
        let st = self.volume.xattr_load(inode_no).await?;
        Ok(Ext2Volume::<B>::xattr_list_names(&st))
    }

    /// Set (`Some`) or remove (`None`) one attribute.
    async fn xattr_set(&self, name: &str, value: Option<&[u8]>, flags: u32) -> Result<(), FsError> {
        use super::volume::xattr;
        use narf_filesystem::PosixAcl;
        let (index, suffix) = xattr::split_name(name).ok_or(FsError::Unsupported)?;
        let _update = self.volume.lock_inode_updates().await;
        let inode_no = self.state.lock().inode_no;
        let inode = self.volume.read_inode(inode_no).await?;
        let st = self.volume.xattr_load(inode_no).await?;
        let is_acl = index == xattr::INDEX_ACL_ACCESS || index == xattr::INDEX_ACL_DEFAULT;
        let (entries, mode) = if is_acl {
            // `do_set_acl` decodes only a non-empty value; a zero-entry
            // header also decodes to "no ACL". `setxattr`'s CREATE/REPLACE
            // flags do not apply on this path.
            let acl = match value {
                Some(v) if !v.is_empty() => PosixAcl::from_xattr(v)?,
                _ => None,
            };
            if index == xattr::INDEX_ACL_DEFAULT {
                if !inode.is_dir() {
                    return match acl {
                        Some(_) => Err(FsError::PermissionDenied),
                        None => Ok(()),
                    };
                }
                let disk = match acl {
                    Some(acl) => {
                        acl.valid()?;
                        Some(xattr::acl_to_disk(&acl)?)
                    }
                    None => None,
                };
                (xattr::with_value(&st, index, suffix, disk), None)
            } else {
                match acl {
                    Some(acl) => {
                        acl.valid()?;
                        let (mode, stored) = narf_filesystem::posix_acl_update_mode(
                            inode.mode & 0o7777,
                            acl,
                            narf_filesystem::caller_in_group_or_capable(inode.uid, inode.gid),
                        )?;
                        let disk = match stored {
                            Some(acl) => Some(xattr::acl_to_disk(&acl)?),
                            None => None,
                        };
                        (xattr::with_value(&st, index, suffix, disk), Some(mode))
                    }
                    None => (xattr::with_value(&st, index, suffix, None), None),
                }
            }
        } else {
            let exists = xattr::find(&st, index, suffix).is_some();
            match value {
                Some(v) => {
                    // `ext4_xattr_set_handle`: XATTR_CREATE on an existing
                    // name is -EEXIST, XATTR_REPLACE on a missing one
                    // -ENODATA.
                    if flags & XATTR_CREATE != 0 && exists {
                        return Err(FsError::Busy);
                    }
                    if flags & XATTR_REPLACE != 0 && !exists {
                        return Err(FsError::NotFound);
                    }
                    (
                        xattr::with_value(&st, index, suffix, Some(v.to_vec())),
                        None,
                    )
                }
                None => {
                    if !exists {
                        return Err(FsError::NotFound);
                    }
                    (xattr::with_value(&st, index, suffix, None), None)
                }
            }
        };
        self.volume.xattr_store(inode_no, st, entries, mode).await?;
        self.refresh_cached_inode(inode_no).await
    }

    async fn refresh_cached_inode(&self, inode_no: u32) -> Result<(), FsError> {
        let inode = self.volume.read_inode(inode_no).await?;
        let stat = Self::stat_from_inode(&self.volume, &inode);
        let mut state = self.state.lock();
        state.inode = Some(inode);
        state.stat = stat;
        Ok(())
    }

    /// `posix_acl_chmod`: after a chmod, re-mask the stored access ACL so
    /// its mask (or group) entry matches the new group bits. Called with
    /// `inode_update_lock` held.
    async fn acl_chmod_locked(&self, inode_no: u32, perms: u16) -> Result<(), FsError> {
        use super::volume::xattr;
        let st = self.volume.xattr_load(inode_no).await?;
        let Some(entry) = xattr::find(&st, xattr::INDEX_ACL_ACCESS, b"") else {
            return Ok(());
        };
        let mut acl = xattr::acl_from_disk(&entry.value)?;
        acl.chmod_masq(perms)?;
        let disk = xattr::acl_to_disk(&acl)?;
        let entries = xattr::with_value(&st, xattr::INDEX_ACL_ACCESS, b"", Some(disk));
        self.volume.xattr_store(inode_no, st, entries, None).await
    }
}
