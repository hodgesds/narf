//! ext2 directory mutation surface — create / mkdir / unlink / rmdir
//! / rename / hardlink / symlink, built on top of the splice helpers in
//! `dir::splice` and the block / inode allocators in `volume`.
//!
//! Splits cleanly from `volume.rs` to keep the read-side / mount-side
//! surface there from ballooning. All methods take `&Ext2Volume<B>`
//! and drive the disk through the existing `read_inode` / `write_inode`
//! / `write_inode_data` / `truncate_inode` helpers.
//!
//! Sources (post-relicense — NARF is GPL-2.0+ as of 2026-05-20):
//! - Linux `fs/ext2/dir.c`  — `ext2_add_link`, `ext2_delete_entry`,
//!   `ext2_make_empty`, `ext2_empty_dir`.
//! - Linux `fs/ext2/namei.c` — `ext2_create`, `ext2_mkdir`,
//!   `ext2_unlink`, `ext2_rmdir`, `ext2_link`, `ext2_symlink`,
//!   `ext2_rename`.
//! - OSDev Wiki, "Ext2 — Directory Entry" — wire format reference.

use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::dir::{ftype, splice};
use super::htree::{self, DxRoot};
use super::inode::{Inode, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use super::metadata_csum;
use super::superblock::compat;
use super::volume::Ext2Volume;

/// What kind of dirent type byte to write for a given inode mode.
fn ftype_for_mode(mode: u16) -> u8 {
    match mode & S_IFMT {
        S_IFDIR => ftype::DIR,
        S_IFREG => ftype::REGULAR,
        S_IFLNK => ftype::SYMLINK,
        _ => ftype::UNKNOWN,
    }
}

/// `EXT4_LINK_MAX`.
const EXT4_LINK_MAX: u16 = 65000;

/// `ext4_inc_count`: a directory past `EXT4_LINK_MAX` links (possible only
/// with `dir_nlink` on an indexed directory) counts 1, meaning "many", and
/// stays 1.
fn inc_count(inode: &mut Inode) {
    inode.links_count = inode.links_count.saturating_add(1);
    if inode.is_htree() && (inode.links_count > EXT4_LINK_MAX || inode.links_count == 2) {
        inode.links_count = 1;
    }
}

/// `ext4_dec_count`: a directory at 1 ("many") or 2 keeps its count.
fn dec_count(inode: &mut Inode) {
    if !inode.is_dir() || inode.links_count > 2 {
        inode.links_count = inode.links_count.saturating_sub(1);
    }
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    fn add_directory_checksum_tail(&self, block: &mut [u8]) -> Result<(), FsError> {
        if !self.superblock.has_metadata_csum() {
            return Ok(());
        }
        let tail = block.len().checked_sub(12).ok_or(FsError::InvalidData)?;
        block[tail..tail + 4].fill(0);
        block[tail + 4..tail + 6].copy_from_slice(&12u16.to_le_bytes());
        block[tail + 6] = 0;
        block[tail + 7] = 0xde;
        block[tail + 8..tail + 12].fill(0);
        Ok(())
    }

    fn verify_directory_block_for_write(
        &self,
        inode_no: u32,
        inode: &Inode,
        block: &[u8],
    ) -> Result<(), FsError> {
        if metadata_csum::verify_directory_block_checksum(
            &self.superblock,
            inode_no,
            inode.generation,
            block,
        ) {
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }

    async fn write_directory_block(
        &self,
        inode_no: u32,
        inode: &Inode,
        physical: u64,
        block: &mut [u8],
    ) -> Result<(), FsError> {
        if metadata_csum::write_directory_block_checksum(
            &self.superblock,
            inode_no,
            inode.generation,
            block,
        )
        .is_none()
            && self.superblock.has_metadata_csum()
        {
            return Err(FsError::InvalidData);
        }
        self.write_block(physical, block).await
    }

    fn verify_htree_block_for_write(
        &self,
        inode_no: u32,
        inode: &Inode,
        block: &[u8],
    ) -> Result<(), FsError> {
        if metadata_csum::verify_htree_block_checksum(
            &self.superblock,
            inode_no,
            inode.generation,
            block,
        ) {
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }

    /// Check the `rmdir` emptiness invariant one retained folio-backed block
    /// at a time. Directory entries never cross filesystem-block boundaries,
    /// so flattening the entire inode is both unnecessary and harmful for
    /// large desktop directories.
    async fn dir_is_empty(&self, inode: &Inode) -> Result<bool, FsError> {
        let size = inode.size as usize;
        let block_size = self.block_size();
        let mut base = 0usize;
        while base < size {
            let logical = (base / block_size) as u64;
            let valid = core::cmp::min(block_size, size - base);
            let physical = self.map_block(inode, logical).await?;
            if physical == 0 {
                return Ok(false);
            }
            let block = self.read_block_view(physical).await?;
            if !splice::is_dir_empty(&block[..valid]) {
                return Ok(false);
            }
            base += valid;
        }
        Ok(true)
    }

    /// Look up `name` in `parent_inode`, returning `(inode_no,
    /// file_type)`. Returns `NotFound` if the name is absent.
    pub(crate) async fn dir_lookup(
        &self,
        parent_inode: &Inode,
        name: &[u8],
    ) -> Result<(u32, u8), FsError> {
        let size = parent_inode.size as usize;
        let block_size = self.block_size();
        let mut base = 0usize;
        while base < size {
            let logical = (base / block_size) as u64;
            let valid = core::cmp::min(block_size, size - base);
            let physical = self.map_block(parent_inode, logical).await?;
            if physical == 0 {
                base += valid;
                continue;
            }
            let block = self.read_block_view(physical).await?;

            let mut off = 0usize;
            while off + 8 <= valid {
                let inode = u32::from_le_bytes([
                    block[off],
                    block[off + 1],
                    block[off + 2],
                    block[off + 3],
                ]);
                let rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
                let name_len = block[off + 6] as usize;
                let file_type = block[off + 7];
                if rec_len < 8 || off + rec_len > valid || name_len > rec_len.saturating_sub(8) {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
                if inode != 0
                    && name_len == name.len()
                    && &block[off + 8..off + 8 + name_len] == name
                {
                    return Ok((inode, file_type));
                }
                off += rec_len;
            }
            base += valid;
        }
        Err(FsError::NotFound)
    }

    /// `dx_root_limit`: index entries that fit in the root block after
    /// `.`, `..`, `dx_root_info` and (with metadata_csum) the `dx_tail`.
    fn dx_root_limit(&self) -> u16 {
        let tail = if self.superblock.has_metadata_csum() {
            8
        } else {
            0
        };
        ((self.block_size() - 32 - tail) / 8) as u16
    }

    /// `dx_node_limit`: index entries in an interior node after its fake
    /// dirent and (with metadata_csum) the `dx_tail`.
    fn dx_node_limit(&self) -> u16 {
        let tail = if self.superblock.has_metadata_csum() {
            8
        } else {
            0
        };
        ((self.block_size() - 8 - tail) / 8) as u16
    }

    /// Write an index block (root or node) with its `dx_tail` checksum.
    async fn write_dx_block(
        &self,
        inode_no: u32,
        inode: &Inode,
        physical: u64,
        block: &mut [u8],
    ) -> Result<(), FsError> {
        if self.superblock.has_metadata_csum()
            && metadata_csum::write_htree_block_checksum(
                &self.superblock,
                inode_no,
                inode.generation,
                block,
            )
            .is_none()
        {
            return Err(FsError::Corrupted);
        }
        self.write_block(physical, block).await
    }

    /// `dx_probe`: walk the index from the root to the leaf that holds
    /// `hash`, validating each level as Linux does (hash version, depth,
    /// `limit` against the computed limit, `count`, block numbers inside the
    /// directory, the `dx_tail` checksum). Structural damage is
    /// `Corrupted` (EFSCORRUPTED), a checksum failure `BadChecksum`.
    async fn dx_probe(
        &self,
        dir_no: u32,
        dir: &Inode,
        name: &[u8],
    ) -> Result<(alloc::vec::Vec<DxFrame>, u32, u8), FsError> {
        let bs = self.block_size();
        let dir_blocks = (dir.size as usize).div_ceil(bs) as u64;
        let root_phys = self.map_block(dir, 0).await?;
        if root_phys == 0 {
            return Err(FsError::Corrupted);
        }
        let mut root = vec![0u8; bs];
        self.read_block(root_phys, &mut root).await?;
        if self
            .verify_htree_block_for_write(dir_no, dir, &root)
            .is_err()
        {
            return Err(FsError::BadChecksum);
        }
        let info = DxRoot::parse(&root).ok_or(FsError::Corrupted)?;
        if info.limit != self.dx_root_limit() {
            return Err(FsError::Corrupted);
        }
        let version =
            htree::lookup_hash_version(info.hash_version, self.superblock.hash_unsigned());
        let hash = htree::ext4fs_dirhash(name, version, &self.superblock.hash_seed)
            .ok_or(FsError::Corrupted)?
            .hash;
        let mut frames = alloc::vec::Vec::with_capacity(2);
        let at = dx::find(&root, htree::DX_ROOT_ENTRIES_OFF, hash).ok_or(FsError::Corrupted)?;
        frames.push(DxFrame {
            physical: root_phys,
            block: root,
            entries: htree::DX_ROOT_ENTRIES_OFF,
            at,
        });
        for _ in 0..info.indirect_levels {
            let parent = frames.last().expect("root frame");
            let child = u64::from(dx::block_of(&parent.block, parent.entries, parent.at));
            if child == 0 || child >= dir_blocks {
                return Err(FsError::Corrupted);
            }
            let phys = self.map_block(dir, child).await?;
            if phys == 0 {
                return Err(FsError::Corrupted);
            }
            let mut node = vec![0u8; bs];
            self.read_block(phys, &mut node).await?;
            // A dx_node opens with a fake dirent spanning the block.
            if node[0..4] != [0; 4] || usize::from(u16::from_le_bytes([node[4], node[5]])) != bs {
                return Err(FsError::Corrupted);
            }
            if self
                .verify_htree_block_for_write(dir_no, dir, &node)
                .is_err()
            {
                return Err(FsError::BadChecksum);
            }
            if dx::limit(&node, htree::DX_NODE_ENTRIES_OFF) != self.dx_node_limit() {
                return Err(FsError::Corrupted);
            }
            let at = dx::find(&node, htree::DX_NODE_ENTRIES_OFF, hash).ok_or(FsError::Corrupted)?;
            frames.push(DxFrame {
                physical: phys,
                block: node,
                entries: htree::DX_NODE_ENTRIES_OFF,
                at,
            });
        }
        let leaf = frames.last().expect("frame");
        let leaf_block = u64::from(dx::block_of(&leaf.block, leaf.entries, leaf.at));
        if leaf_block == 0 || leaf_block >= dir_blocks {
            return Err(FsError::Corrupted);
        }
        Ok((frames, hash, version))
    }

    /// Append one block to directory `dir` (`ext4_append`): map it, grow
    /// `i_size`, and return its logical and physical numbers. The inode is
    /// not written; the caller does that once the block's contents are on
    /// the device.
    async fn dir_append_block(&self, dir_no: u32, dir: &mut Inode) -> Result<(u64, u64), FsError> {
        let bs = self.block_size() as u64;
        let logical = dir.size.div_ceil(bs);
        let physical = self.map_block_alloc(dir_no, dir, logical).await?;
        dir.size = (logical + 1) * bs;
        Ok((logical, physical))
    }

    /// `ext4_dx_add_entry`: insert into an indexed directory, splitting the
    /// target leaf (`do_split`), a full index node, or adding the second
    /// index level, as Linux does.
    ///
    /// Without a journal every split keeps this order: write the new block,
    /// write the inode that maps it, write the one index block that makes it
    /// reachable (the commit), then shorten the old block. A crash before
    /// the commit leaves a block nothing indexes; a crash after it leaves
    /// entries present twice. Either is what e2fsck repairs; no entry is
    /// ever unreachable. An error after a block was allocated is recorded
    /// with `fs_error`.
    ///
    /// LINUX-GAP: a full one-block linear directory grows linearly; it is
    /// not converted to an index (`make_indexed_dir`).
    async fn dir_insert_htree(
        &self,
        parent_inode_no: u32,
        parent_inode: &mut Inode,
        name: &[u8],
        target_inode_no: u32,
        file_type: u8,
    ) -> Result<(), FsError> {
        let bs = self.block_size();
        // At most two index splits (node, then root) precede the leaf split.
        for _ in 0..3 {
            let (mut frames, hash, version) =
                self.dx_probe(parent_inode_no, parent_inode, name).await?;
            let last = frames.len() - 1;
            let leaf_logical = u64::from(dx::block_of(
                &frames[last].block,
                frames[last].entries,
                frames[last].at,
            ));
            let leaf_phys = self.map_block(parent_inode, leaf_logical).await?;
            if leaf_phys == 0 {
                return Err(FsError::Corrupted);
            }
            let mut leaf = vec![0u8; bs];
            self.read_block(leaf_phys, &mut leaf).await?;
            if self
                .verify_directory_block_for_write(parent_inode_no, parent_inode, &leaf)
                .is_err()
            {
                return Err(FsError::BadChecksum);
            }
            match splice::insert_entry(&mut leaf, target_inode_no, name, file_type) {
                splice::InsertResult::Ok { .. } => {
                    return self
                        .write_directory_block(parent_inode_no, parent_inode, leaf_phys, &mut leaf)
                        .await;
                }
                splice::InsertResult::Exists => return Err(FsError::InvalidPath),
                splice::InsertResult::Corrupt => return Err(FsError::Corrupted),
                splice::InsertResult::NoRoom => {}
            }
            let full = {
                let f = &frames[last];
                dx::count(&f.block, f.entries) == dx::limit(&f.block, f.entries)
            };
            if !full {
                return self
                    .dx_split_leaf(
                        parent_inode_no,
                        parent_inode,
                        &mut frames[last],
                        (leaf_phys, leaf),
                        (hash, version),
                        (name, target_inode_no, file_type),
                    )
                    .await;
            }
            self.dx_split_index(parent_inode_no, parent_inode, &mut frames)
                .await?;
        }
        Err(FsError::Corrupted)
    }

    /// `do_split`: move the upper half (by hash) of a full leaf into a new
    /// block, index it from `frame`, then insert the new name into the half
    /// its hash belongs to.
    async fn dx_split_leaf(
        &self,
        dir_no: u32,
        dir: &mut Inode,
        frame: &mut DxFrame,
        (leaf_phys, leaf): (u64, alloc::vec::Vec<u8>),
        (hash, version): (u32, u8),
        (name, target, file_type): (&[u8], u32, u8),
    ) -> Result<(), FsError> {
        let bs = self.block_size();
        let csum_tail = if self.superblock.has_metadata_csum() {
            12
        } else {
            0
        };
        let map = dx::make_map(&leaf, bs - csum_tail, version, &self.superblock.hash_seed)
            .ok_or(FsError::Corrupted)?;
        let split = dx::split_point(&map, bs);
        if split == 0 || split >= map.len() {
            return Err(FsError::Corrupted);
        }
        let hash2 = map[split].hash;
        let continued = u32::from(hash2 == map[split - 1].hash);

        let saved = *dir;
        let (new_logical, new_phys) = self.dir_append_block(dir_no, dir).await?;
        let mut upper = dx::pack(&leaf, &map[split..], bs, csum_tail);
        let mut lower = dx::pack(&leaf, &map[..split], bs, csum_tail);
        if csum_tail != 0 {
            self.add_directory_checksum_tail(&mut upper)?;
            self.add_directory_checksum_tail(&mut lower)?;
        }
        // New block, then the inode that maps it: before the commit, a
        // failure can still be undone.
        let staged = async {
            self.write_directory_block(dir_no, dir, new_phys, &mut upper)
                .await?;
            self.write_inode(dir_no, dir).await
        }
        .await;
        if let Err(error) = staged {
            let _ = self.free_block(new_phys).await;
            *dir = saved;
            let _ = self.write_inode(dir_no, dir).await;
            return Err(error);
        }
        // The commit: index the new block.
        dx::insert_after(
            &mut frame.block,
            frame.entries,
            frame.at,
            hash2 + continued,
            new_logical as u32,
        );
        let committed = async {
            self.write_dx_block(dir_no, dir, frame.physical, &mut frame.block)
                .await?;
            self.write_directory_block(dir_no, dir, leaf_phys, &mut lower)
                .await?;
            let (dest_phys, dest) = if hash >= hash2 {
                (new_phys, &mut upper)
            } else {
                (leaf_phys, &mut lower)
            };
            match splice::insert_entry(dest, target, name, file_type) {
                splice::InsertResult::Ok { .. } => {}
                splice::InsertResult::Exists => return Err(FsError::InvalidPath),
                _ => return Err(FsError::Corrupted),
            }
            self.write_directory_block(dir_no, dir, dest_phys, dest)
                .await
        }
        .await;
        if let Err(error) = &committed {
            if !matches!(error, FsError::InvalidPath) {
                self.fs_error(super::volume::sb_state::ErrorSite {
                    func: "dx_split_leaf",
                    ino: dir_no,
                    block: leaf_phys,
                    errno: narf_lib::errno::EIO,
                })
                .await;
            }
        }
        committed
    }

    /// The index level `frames.last()` is full: split it into two nodes
    /// (when its parent has room), or move the root's entries into a new
    /// node and make the root point at it (`indirect_levels` 0 → 1). A
    /// tree at its maximum depth whose root is full is ENOSPC, before any
    /// write, as in Linux.
    async fn dx_split_index(
        &self,
        dir_no: u32,
        dir: &mut Inode,
        frames: &mut [DxFrame],
    ) -> Result<(), FsError> {
        let levels = frames.len();
        let parent_has_room = levels == 2 && {
            let root = &frames[0];
            dx::count(&root.block, root.entries) < dx::limit(&root.block, root.entries)
        };
        if levels == 1 + usize::from(htree::MAX_INDIRECT_LEVELS) && !parent_has_room {
            return Err(FsError::NoSpace);
        }
        let bs = self.block_size();
        let node_limit = self.dx_node_limit();
        let saved = *dir;
        let (new_logical, new_phys) = self.dir_append_block(dir_no, dir).await?;
        let full = frames.last().expect("frame");
        let icount = dx::count(&full.block, full.entries);
        let moved_from = if parent_has_room { icount / 2 } else { 0 };
        let mut node = dx::new_node(bs, node_limit);
        dx::copy_entries(&full.block, full.entries, moved_from, icount, &mut node);
        let staged = async {
            self.write_dx_block(dir_no, dir, new_phys, &mut node)
                .await?;
            self.write_inode(dir_no, dir).await
        }
        .await;
        if let Err(error) = staged {
            let _ = self.free_block(new_phys).await;
            *dir = saved;
            let _ = self.write_inode(dir_no, dir).await;
            return Err(error);
        }
        let committed = if parent_has_room {
            // Split a full node: the root gains an entry for the new one,
            // then the old node keeps its lower half.
            let hash2 = dx::hash_of(&frames[1].block, frames[1].entries, moved_from);
            let (root, rest) = frames.split_at_mut(1);
            let root = &mut root[0];
            dx::insert_after(
                &mut root.block,
                root.entries,
                root.at,
                hash2,
                new_logical as u32,
            );
            let old = &mut rest[0];
            async {
                self.write_dx_block(dir_no, dir, root.physical, &mut root.block)
                    .await?;
                dx::set_count(&mut old.block, old.entries, moved_from);
                self.write_dx_block(dir_no, dir, old.physical, &mut old.block)
                    .await
            }
            .await
        } else {
            // Add a level: the root's entries move to the new node and the
            // root indexes only it.
            let root = &mut frames[0];
            dx::set_count(&mut root.block, root.entries, 1);
            dx::set_block(&mut root.block, root.entries, 0, new_logical as u32);
            root.block[htree::DX_ROOT_INFO_OFF + 6] += 1;
            self.write_dx_block(dir_no, dir, root.physical, &mut root.block)
                .await
        };
        if committed.is_err() {
            self.fs_error(super::volume::sb_state::ErrorSite {
                func: "dx_split_index",
                ino: dir_no,
                block: new_phys,
                errno: narf_lib::errno::EIO,
            })
            .await;
        }
        committed
    }

    pub(crate) async fn dir_insert(
        &self,
        parent_inode_no: u32,
        parent_inode: &mut Inode,
        name: &[u8],
        target_inode_no: u32,
        target_mode: u16,
    ) -> Result<(), FsError> {
        if name.is_empty() || name.len() > 255 {
            return Err(FsError::InvalidPath);
        }
        // A directory removed while open (`IS_DEADDIR`: `S_DEAD`, which
        // `vfs_rmdir` sets in memory; its node is marked orphaned): ENOENT.
        if self
            .icache_get(parent_inode_no)
            .is_some_and(|node| node.is_orphaned())
        {
            return Err(FsError::NotFound);
        }
        let bs = self.block_size();
        let blocks = (parent_inode.size as usize).div_ceil(bs);
        let file_type = ftype_for_mode(target_mode);

        // Determine whether HTREE is active on this directory.
        // Two conditions must both hold:
        //   (a) The superblock has compat::DIR_INDEX set.
        //   (b) The inode has I_FLAGS_INDEX set.
        let htree_active =
            self.superblock.feature_compat & compat::DIR_INDEX != 0 && parent_inode.is_htree();
        if htree_active {
            return self
                .dir_insert_htree(
                    parent_inode_no,
                    parent_inode,
                    name,
                    target_inode_no,
                    file_type,
                )
                .await;
        }

        // Try each existing block.
        for i in 0..blocks {
            let phys = self.map_block(parent_inode, i as u64).await?;
            if phys == 0 {
                continue;
            }
            let mut blockbuf = vec![0u8; bs];
            self.read_block(phys, &mut blockbuf).await?;
            self.verify_directory_block_for_write(parent_inode_no, parent_inode, &blockbuf)?;
            match splice::insert_entry(&mut blockbuf, target_inode_no, name, file_type) {
                splice::InsertResult::Ok { .. } => {
                    self.write_directory_block(parent_inode_no, parent_inode, phys, &mut blockbuf)
                        .await?;
                    return Ok(());
                }
                splice::InsertResult::Exists => {
                    return Err(FsError::InvalidPath);
                }
                splice::InsertResult::Corrupt => {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
                splice::InsertResult::NoRoom => {
                    // Try next block.
                }
            }
        }

        // No existing block had room — extend the directory by one
        // block. Allocate, seed with a single record, write, then
        // bump the parent's i_size. `map_block_alloc` already counted the
        // new block (and any index block) in i_blocks.
        let new_logical = blocks as u64;
        let phys = self
            .map_block_alloc(parent_inode_no, parent_inode, new_logical)
            .await?;
        let mut blockbuf = vec![0u8; bs];
        // Single record filling the whole block.
        let rec_len = if self.superblock.has_metadata_csum() {
            self.add_directory_checksum_tail(&mut blockbuf)?;
            (bs - 12) as u16
        } else {
            bs as u16
        };
        blockbuf[0..4].copy_from_slice(&target_inode_no.to_le_bytes());
        blockbuf[4..6].copy_from_slice(&rec_len.to_le_bytes());
        blockbuf[6] = name.len() as u8;
        blockbuf[7] = file_type;
        blockbuf[8..8 + name.len()].copy_from_slice(name);
        self.write_directory_block(parent_inode_no, parent_inode, phys, &mut blockbuf)
            .await?;
        // Update parent inode bookkeeping.
        parent_inode.size += bs as u64;
        self.write_inode(parent_inode_no, parent_inode).await
    }

    /// Find and delete an entry by name from `parent_inode`. Walks
    /// each directory block until the name is located, then calls
    /// `splice::delete_entry` to merge it with its predecessor.
    /// Returns the deleted entry's (inode, file_type) so the caller
    /// can drop the link count.
    pub(crate) async fn dir_delete(
        &self,
        parent_inode_no: u32,
        parent_inode: &mut Inode,
        name: &[u8],
    ) -> Result<(u32, u8), FsError> {
        let (phys, mut blockbuf, off, inode, file_type) =
            self.dir_locate(parent_inode_no, parent_inode, name).await?;
        splice::delete_entry(&mut blockbuf, off).map_err(|_| FsError::Corrupted)?;
        self.write_directory_block(parent_inode_no, parent_inode, phys, &mut blockbuf)
            .await?;
        Ok((inode, file_type))
    }

    /// `ext4_setent`: point `name`'s existing dirent at `inode_no`, in
    /// place. The name never stops existing, so a crash during a rename
    /// that replaces it leaves it naming the old inode or the new one.
    async fn dir_setent(
        &self,
        dir_no: u32,
        dir: &Inode,
        name: &[u8],
        inode_no: u32,
        mode: u16,
    ) -> Result<(), FsError> {
        let (phys, mut blockbuf, off, _, _) = self.dir_locate(dir_no, dir, name).await?;
        blockbuf[off..off + 4].copy_from_slice(&inode_no.to_le_bytes());
        if self.superblock.feature_incompat & super::superblock::incompat::FILETYPE != 0 {
            blockbuf[off + 7] = ftype_for_mode(mode);
        }
        self.write_directory_block(dir_no, dir, phys, &mut blockbuf)
            .await
    }

    /// Find `name`'s dirent for a change: its block (physical number and
    /// bytes, checked for writing), the dirent's offset, inode and type.
    /// Leaves are scanned in order. The index blocks of an HTREE hold no
    /// names: the root's index hides inside `..`, and an interior node opens
    /// with a fake dirent spanning the block, so both are skipped at any
    /// depth.
    ///
    /// LINUX-GAP: an indexed directory is scanned leaf by leaf rather than
    /// probed by hash (`ext4_dx_find_entry`); the result is the same.
    async fn dir_locate(
        &self,
        dir_no: u32,
        dir: &Inode,
        name: &[u8],
    ) -> Result<(u64, alloc::vec::Vec<u8>, usize, u32, u8), FsError> {
        let bs = self.block_size();
        let blocks = (dir.size as usize).div_ceil(bs);
        let indexed = dir.is_htree();
        let first_leaf = if indexed {
            let root_phys = self.map_block(dir, 0).await?;
            if root_phys == 0 {
                return Err(FsError::Corrupted);
            }
            let mut root = vec![0u8; bs];
            self.read_block(root_phys, &mut root).await?;
            if self
                .verify_htree_block_for_write(dir_no, dir, &root)
                .is_err()
            {
                return Err(FsError::BadChecksum);
            }
            DxRoot::parse(&root).ok_or(FsError::Corrupted)?;
            1
        } else {
            0
        };
        for i in first_leaf..blocks {
            let phys = self.map_block(dir, i as u64).await?;
            if phys == 0 {
                continue;
            }
            let mut blockbuf = vec![0u8; bs];
            self.read_block(phys, &mut blockbuf).await?;
            if indexed
                && blockbuf[0..4] == [0; 4]
                && usize::from(u16::from_le_bytes([blockbuf[4], blockbuf[5]])) == bs
            {
                continue;
            }
            self.verify_directory_block_for_write(dir_no, dir, &blockbuf)?;
            let mut off = 0usize;
            while off + 8 <= blockbuf.len() {
                let inode = u32::from_le_bytes([
                    blockbuf[off],
                    blockbuf[off + 1],
                    blockbuf[off + 2],
                    blockbuf[off + 3],
                ]);
                let rec_len = u16::from_le_bytes([blockbuf[off + 4], blockbuf[off + 5]]) as usize;
                let name_len = blockbuf[off + 6] as usize;
                let file_type = blockbuf[off + 7];
                if rec_len < 8 || off + rec_len > blockbuf.len() || 8 + name_len > rec_len {
                    return Err(FsError::Corrupted);
                }
                if inode != 0
                    && name_len == name.len()
                    && &blockbuf[off + 8..off + 8 + name_len] == name
                {
                    return Ok((phys, blockbuf, off, inode, file_type));
                }
                off += rec_len;
            }
        }
        Err(FsError::NotFound)
    }

    /// Roll back an inode written but never linked (`discard_new_inode`):
    /// the slot is cleared first, so nothing maps the data block when it is
    /// freed.
    async fn discard_new_inode(&self, ino: u32, data_block: Option<u64>) {
        let _ = self.free_inode(ino).await;
        if let Some(block) = data_block {
            let _ = self.free_block(block).await;
        }
    }

    /// `EXT4_DIR_LINK_MAX`: `dir` cannot take another subdirectory. At
    /// `EXT4_LINK_MAX` links it is full, unless `dir_nlink` lets an indexed
    /// directory go on with a link count of 1.
    fn dir_link_max(&self, dir: &Inode) -> bool {
        dir.links_count >= EXT4_LINK_MAX
            && !(self.superblock.feature_ro_compat & super::superblock::ro_compat::DIR_NLINK != 0
                && dir.is_htree())
    }

    /// Create a regular file inode + directory entry.
    pub async fn dir_create_regular(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        mode: u16,
    ) -> Result<u32, FsError> {
        self.dir_create_regular_with_attrs(parent_inode_no, name, mode, 0, 0)
            .await
    }

    /// Create a regular file with its final mode and owner before publishing
    /// the name in its parent directory.  Files opened through `O_CREAT` must
    /// never be observable as a root-owned `0644` placeholder while a later
    /// chmod/chown catches up.
    pub(crate) async fn dir_create_regular_with_attrs(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<u32, FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        // Allocate inode + initialise with timestamps.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_regular(mode);
        self.init_extent_root(&mut new_inode);
        new_inode.uid = uid;
        new_inode.gid = gid;
        new_inode.atime = now;
        new_inode.touch_ctime_mtime(now);
        if let Err(error) = self.write_new_inode(new_ino, &new_inode).await {
            let _ = self.abort_inode_allocation(new_ino).await;
            return Err(error);
        }
        // Splice the dirent into the parent.
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            // Roll back the inode allocation.
            let _ = self.free_inode(new_ino).await;
            return Err(FsError::InvalidPath);
        }
        if let Err(e) = self
            .dir_insert(
                parent_inode_no,
                &mut parent_inode,
                name,
                new_ino,
                new_inode.mode,
            )
            .await
        {
            let _ = self.free_inode(new_ino).await;
            return Err(e);
        }
        // Parent directory mtime + ctime change because its dirent list
        // was modified.
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        Ok(new_ino)
    }

    /// Create a fresh subdirectory inode, seed it with `.` and `..`,
    /// add the parent dirent, and bump parent's link count for the
    /// `..` back-link.
    pub async fn dir_create_directory(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        mode: u16,
    ) -> Result<u32, FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        let bs = self.block_size();
        let parent = self.read_inode(parent_inode_no).await?;
        if !parent.is_dir() {
            return Err(FsError::InvalidPath);
        }
        // `ext4_mkdir`: a parent at its link limit takes no subdirectory.
        if self.dir_link_max(&parent) {
            return Err(FsError::TooManyLinks);
        }
        // Allocate the inode + a data block.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_directory(mode);
        new_inode.atime = now;
        new_inode.touch_ctime_mtime(now);
        // Allocate the first data block to hold "." and "..": through an
        // extent tree on an ext4 volume (`ext4_new_inode` gives directories
        // one), otherwise as the block map's first direct pointer.
        let first_block = if self.init_extent_root(&mut new_inode) {
            self.map_block_alloc(new_ino, &mut new_inode, 0).await
        } else {
            self.alloc_block().await.inspect(|&b| {
                new_inode.block[0] = b as u32;
                new_inode.blocks = bs as u32 / 512;
            })
        };
        let data_block = match first_block {
            Ok(b) => b,
            Err(e) => {
                let _ = self.abort_inode_allocation(new_ino).await;
                return Err(e);
            }
        };
        new_inode.size = bs as u64;
        // Write "." + ".." into the data block.
        let mut blockbuf = vec![0u8; bs];
        splice::make_empty_dir(&mut blockbuf, new_ino, parent_inode_no);
        if self.superblock.has_metadata_csum() {
            let dotdot = super::dir::rec_len_for(1) as usize;
            let rec_len = (bs - dotdot - 12) as u16;
            blockbuf[dotdot + 4..dotdot + 6].copy_from_slice(&rec_len.to_le_bytes());
            self.add_directory_checksum_tail(&mut blockbuf)?;
        }
        if let Err(e) = self
            .write_directory_block(new_ino, &new_inode, data_block, &mut blockbuf)
            .await
        {
            let _ = self.free_block(data_block).await;
            let _ = self.abort_inode_allocation(new_ino).await;
            return Err(e);
        }
        // Persist the new dir inode.
        if let Err(error) = self.write_new_inode(new_ino, &new_inode).await {
            let _ = self.free_block(data_block).await;
            let _ = self.abort_inode_allocation(new_ino).await;
            return Err(error);
        }
        // Splice into the parent: the dirent is the commit. Before it, the
        // inode is cleared first, so nothing maps the block it frees.
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if let Err(e) = self
            .dir_insert(
                parent_inode_no,
                &mut parent_inode,
                name,
                new_ino,
                new_inode.mode,
            )
            .await
        {
            let _ = self.free_inode(new_ino).await;
            let _ = self.free_block(data_block).await;
            return Err(e);
        }
        // `ext4_inc_count`: the new ".." links the parent.
        inc_count(&mut parent_inode);
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        self.note_dir_count_delta(new_ino, 1).await?;
        Ok(new_ino)
    }

    /// Remove a file dirent. Decrements the target's link count; if
    /// it drops to zero, frees its blocks + inode slot.
    pub async fn dir_unlink(&self, parent_inode_no: u32, name: &[u8]) -> Result<(), FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            return Err(FsError::InvalidPath);
        }
        let (target_ino, _ft) = self
            .dir_delete(parent_inode_no, &mut parent_inode, name)
            .await?;
        // Drop the target's link count; if it reaches zero, free.
        let mut target = self.read_inode(target_ino).await?;
        if target.is_dir() {
            // Caller should have used dir_rmdir for directories.
            // Restore the dirent to avoid corrupting the FS.
            self.dir_insert(
                parent_inode_no,
                &mut parent_inode,
                name,
                target_ino,
                target.mode,
            )
            .await?;
            return Err(FsError::InvalidPath);
        }
        target.links_count = target.links_count.saturating_sub(1);
        // ctime changes on link-count decrease (POSIX); mtime/ctime of
        // the parent changes because its dirent list was modified.
        target.touch_ctime(now);
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        if target.links_count == 0 {
            self.release_unlinked(target_ino, &mut target).await?;
        } else {
            self.write_inode(target_ino, &target).await?;
        }
        Ok(())
    }

    /// Remove an empty subdirectory. Refuses if non-empty. Frees both
    /// the data blocks and the inode regardless of the link count
    /// (rmdir invalidates the slot — `.` and `..` are removed
    /// implicitly when the block is freed).
    pub async fn dir_rmdir(&self, parent_inode_no: u32, name: &[u8]) -> Result<(), FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            return Err(FsError::InvalidPath);
        }
        // Look up the target without deleting yet.
        let (target_ino, _ft) = self.dir_lookup(&parent_inode, name).await?;
        if target_ino == 0 || name == b"." || name == b".." {
            return Err(FsError::InvalidPath);
        }
        let mut target = self.read_inode(target_ino).await?;
        if !target.is_dir() {
            return Err(FsError::InvalidPath);
        }
        // Empty check.
        if !self.dir_is_empty(&target).await? {
            return Err(FsError::Busy);
        }
        // Delete the dirent, free data blocks + inode, drop parent's
        // links_count for the ".." back-link.
        let _ = self
            .dir_delete(parent_inode_no, &mut parent_inode, name)
            .await?;
        // `ext4_rmdir`: `clear_nlink`, `i_size = 0`, and the inode on the
        // orphan record while it is open (a process's cwd); its blocks and
        // the inode go with the last reference. Unlinked before its blocks
        // go, so the inode written with them gone is never a live directory
        // with no blocks.
        target.links_count = 0;
        target.size = 0;
        self.release_unlinked(target_ino, &mut target).await?;
        dec_count(&mut parent_inode);
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        Ok(())
    }

    /// Hardlink an existing inode under a new name. Increments link
    /// count. Forbidden for directories (Linux rejects hardlinks to
    /// dirs to prevent cycles).
    pub async fn dir_hardlink(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        target_ino: u32,
    ) -> Result<(), FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            return Err(FsError::InvalidPath);
        }
        let mut target = self.read_inode(target_ino).await?;
        if target.is_dir() {
            return Err(FsError::InvalidPath);
        }
        // `link(2)` onto an existing name is EEXIST (`filename_create`);
        // `dir_insert` itself would add a duplicate dirent.
        match self.dir_lookup(&parent_inode, name).await {
            Ok(_) => return Err(FsError::Busy),
            Err(FsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        // `ext4_link`.
        if target.links_count >= EXT4_LINK_MAX {
            return Err(FsError::TooManyLinks);
        }
        // The count goes up on disk before the name exists: a crash in
        // between leaves a count one too high (e2fsck lowers it), never a
        // name the count does not cover, which a later unlink would free
        // from under.
        let before = target;
        target.links_count += 1;
        // ctime changes on the target (link count changed); parent
        // dir's mtime + ctime change because its dirent list grew.
        target.touch_ctime(now);
        self.write_inode(target_ino, &target).await?;
        if let Err(error) = self
            .dir_insert(
                parent_inode_no,
                &mut parent_inode,
                name,
                target_ino,
                target.mode,
            )
            .await
        {
            let _ = self.write_inode(target_ino, &before).await;
            return Err(error);
        }
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        Ok(())
    }

    /// Rename `old_name` in `old_parent_inode_no` to `new_name` in
    /// `new_parent_inode_no`. Implements `RENAME_NOREPLACE` semantics:
    /// fails with `FsError::InvalidPath` when the destination already
    /// exists (Linux `fs/ext4/namei.c::ext4_rename` with
    /// `RENAME_NOREPLACE`).
    ///
    /// Cross-directory moves of directories adjust link counts on both
    /// parents and rewrite the target's `..` entry.
    pub async fn dir_rename(
        &self,
        old_parent_inode_no: u32,
        old_name: &[u8],
        new_parent_inode_no: u32,
        new_name: &[u8],
    ) -> Result<(), FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        // Look up the source so we know what to splice into the dest.
        let old_parent = self.read_inode(old_parent_inode_no).await?;
        if !old_parent.is_dir() {
            return Err(FsError::InvalidPath);
        }
        let (target_ino, _ft) = self.dir_lookup(&old_parent, old_name).await?;
        let mut target = self.read_inode(target_ino).await?;
        let is_dir = target.is_dir();

        // RENAME_NOREPLACE: fail if the destination already exists.
        let new_parent_probe = if old_parent_inode_no == new_parent_inode_no {
            old_parent
        } else {
            self.read_inode(new_parent_inode_no).await?
        };
        if !new_parent_probe.is_dir() {
            return Err(FsError::InvalidPath);
        }
        // An existing destination is REPLACED, not rejected. POSIX and
        // Linux both require plain rename(2) to swap the name atomically;
        // only renameat2(RENAME_NOREPLACE) refuses, and the syscall layer
        // already enforces that itself (returning the correct EEXIST).
        //
        // This is Qt QSaveFile's every-write path: write a temp beside the
        // target, then rename it ONTO the existing target. Refusing broke
        // every KConfig/KSycoca write on the ext2 rootfs.
        let victim = match self.dir_lookup(&new_parent_probe, new_name).await {
            Ok((victim_ino, _)) => {
                // Renaming a name onto ITSELF is a documented no-op that
                // must leave the file intact.
                if victim_ino == target_ino {
                    return Ok(());
                }
                let victim_inode = self.read_inode(victim_ino).await?;
                // `ext4_rename`: a directory may only be replaced when it is
                // empty (`ext4_empty_dir` → -ENOTEMPTY, which `rename_errno`
                // maps from `Busy`). Checked before any dirent changes so a
                // refused rename leaves both directories untouched.
                if victim_inode.is_dir() && !self.dir_is_empty(&victim_inode).await? {
                    return Err(FsError::Busy);
                }
                Some((victim_ino, victim_inode))
            }
            Err(FsError::NotFound) => {
                // A directory moving to a new parent adds a link there.
                if is_dir
                    && old_parent_inode_no != new_parent_inode_no
                    && self.dir_link_max(&new_parent_probe)
                {
                    return Err(FsError::TooManyLinks);
                }
                None
            }
            Err(error) => return Err(error),
        };

        // The new name: the victim's dirent repointed in place
        // (`ext4_setent`), so the name exists throughout and a crash leaves
        // it naming the old inode or the new one; or a new dirent.
        let mut new_parent = self.read_inode(new_parent_inode_no).await?;
        if victim.is_some() {
            self.dir_setent(
                new_parent_inode_no,
                &new_parent,
                new_name,
                target_ino,
                target.mode,
            )
            .await?;
        } else {
            self.dir_insert(
                new_parent_inode_no,
                &mut new_parent,
                new_name,
                target_ino,
                target.mode,
            )
            .await?;
        }
        target.touch_ctime(now);
        self.write_inode(target_ino, &target).await?;
        // Then the old name goes. Re-read: the insert may have changed the
        // directory (old == new).
        let mut old_parent = self.read_inode(old_parent_inode_no).await?;
        self.dir_delete(old_parent_inode_no, &mut old_parent, old_name)
            .await?;
        old_parent.touch_ctime_mtime(now);
        self.write_inode(old_parent_inode_no, &old_parent).await?;

        // The replaced inode loses its name.
        let replaced = victim.is_some();
        if let Some((victim_ino, mut victim_inode)) = victim {
            if victim_inode.is_dir() {
                // Released as `dir_rmdir` releases (`clear_nlink`, then
                // `ext4_orphan_add` while it is open).
                victim_inode.links_count = 0;
                victim_inode.touch_ctime(now);
                self.release_unlinked(victim_ino, &mut victim_inode).await?;
            } else {
                // As dir_unlink does: drop a link, and free the blocks +
                // inode when the last one goes. Skipping this would leak
                // the overwritten file's blocks on every config save.
                victim_inode.links_count = victim_inode.links_count.saturating_sub(1);
                victim_inode.touch_ctime(now);
                if victim_inode.links_count == 0 {
                    self.release_unlinked(victim_ino, &mut victim_inode).await?;
                } else {
                    self.write_inode(victim_ino, &victim_inode).await?;
                }
            }
        }

        if is_dir {
            // `ext4_rename_dir_finish`: the moved directory's ".." names its
            // new parent.
            if old_parent_inode_no != new_parent_inode_no {
                self.set_dotdot(target_ino, new_parent_inode_no).await?;
            }
            // `ext4_dec_count(old.dir)`, and `ext4_inc_count(new.dir)` unless
            // the directory replaced one (whose ".." link it takes over).
            let mut op = self.read_inode(old_parent_inode_no).await?;
            dec_count(&mut op);
            op.touch_ctime(now);
            self.write_inode(old_parent_inode_no, &op).await?;
            if !replaced {
                let mut np = self.read_inode(new_parent_inode_no).await?;
                inc_count(&mut np);
                self.write_inode(new_parent_inode_no, &np).await?;
            }
        }
        if old_parent_inode_no != new_parent_inode_no {
            let mut np = self.read_inode(new_parent_inode_no).await?;
            np.touch_ctime_mtime(now);
            self.write_inode(new_parent_inode_no, &np).await?;
        }
        Ok(())
    }

    /// Point directory `dir_no`'s ".." at `parent`. It is the second entry
    /// of the first block, which for an indexed directory is the dx root:
    /// that block carries a `dx_tail` checksum, not a dirent tail.
    async fn set_dotdot(&self, dir_no: u32, parent: u32) -> Result<(), FsError> {
        let dir = self.read_inode(dir_no).await?;
        let phys = self.map_block(&dir, 0).await?;
        if phys == 0 {
            return Err(FsError::Corrupted);
        }
        let mut blockbuf = vec![0u8; self.block_size()];
        self.read_block(phys, &mut blockbuf).await?;
        let indexed = dir.is_htree();
        let checked = if indexed {
            self.verify_htree_block_for_write(dir_no, &dir, &blockbuf)
        } else {
            self.verify_directory_block_for_write(dir_no, &dir, &blockbuf)
        };
        if checked.is_err() {
            return Err(FsError::BadChecksum);
        }
        let dot = usize::from(u16::from_le_bytes([blockbuf[4], blockbuf[5]]));
        if dot + 10 > blockbuf.len()
            || blockbuf[6] != 1
            || blockbuf[8] != b'.'
            || blockbuf[dot + 6] != 2
            || &blockbuf[dot + 8..dot + 10] != b".."
        {
            return Err(FsError::Corrupted);
        }
        blockbuf[dot..dot + 4].copy_from_slice(&parent.to_le_bytes());
        if indexed {
            self.write_dx_block(dir_no, &dir, phys, &mut blockbuf).await
        } else {
            self.write_directory_block(dir_no, &dir, phys, &mut blockbuf)
                .await
        }
    }

    /// Create a symlink. A target that fits in the inode's 60-byte
    /// `i_block` area together with its NUL — at most 59 bytes — is stored
    /// there ("fast symlink"); a longer one gets a data block. That is
    /// `ext4_symlink`'s `disk_link.len > EXT4_N_BLOCKS * 4` test, where
    /// `disk_link.len` counts the NUL: e2fsck rejects a fast symlink of
    /// 60 bytes.
    pub async fn dir_create_symlink(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        target: &[u8],
    ) -> Result<u32, FsError> {
        let _update = self.lock_inode_updates().await;
        let now = Ext2Volume::<B>::now_secs();
        if target.is_empty() {
            return Err(FsError::InvalidPath);
        }
        // `fscrypt_prepare_symlink`, before any inode exists: the target and
        // its NUL must fit in one block (-ENAMETOOLONG).
        if target.len() + 1 > self.block_size() {
            return Err(FsError::NameTooLong);
        }
        // Allocate the inode.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_symlink(0o777);
        new_inode.atime = now;
        new_inode.touch_ctime_mtime(now);
        new_inode.size = target.len() as u64;
        // The data block of a slow symlink, for rollback.
        let mut slow_block: Option<u64> = None;

        if target.len() < 60 {
            // Fast symlink — pack target bytes into block[].
            let mut bytes = [0u8; 60];
            bytes[..target.len()].copy_from_slice(target);
            for i in 0..super::inode::I_BLOCK_LEN {
                let off = i * 4;
                new_inode.block[i] = u32::from_le_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ]);
            }
            new_inode.blocks = 0;
        } else {
            // Slow symlink — store target in a data block.
            let bs = self.block_size();
            // `ext4_symlink`: a slow symlink is extent-mapped on an ext4
            // volume, block-mapped otherwise.
            let first_block = if self.init_extent_root(&mut new_inode) {
                self.map_block_alloc(new_ino, &mut new_inode, 0).await
            } else {
                self.alloc_block().await.inspect(|&b| {
                    new_inode.block[0] = b as u32;
                    new_inode.blocks = bs as u32 / 512;
                })
            };
            let data_block = match first_block {
                Ok(b) => b,
                Err(e) => {
                    let _ = self.abort_inode_allocation(new_ino).await;
                    return Err(e);
                }
            };
            let mut buf = vec![0u8; bs];
            buf[..target.len()].copy_from_slice(target);
            if let Err(error) = self.write_block(data_block, &buf).await {
                let _ = self.free_block(data_block).await;
                let _ = self.abort_inode_allocation(new_ino).await;
                return Err(error);
            }
            slow_block = Some(data_block);
        }
        if let Err(error) = self.write_new_inode(new_ino, &new_inode).await {
            if let Some(block) = slow_block {
                let _ = self.free_block(block).await;
            }
            let _ = self.abort_inode_allocation(new_ino).await;
            return Err(error);
        }
        // The dirent is the commit; before it, the inode is cleared, then
        // a slow symlink's block is freed (it leaked before).
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            self.discard_new_inode(new_ino, slow_block).await;
            return Err(FsError::InvalidPath);
        }
        if let Err(e) = self
            .dir_insert(
                parent_inode_no,
                &mut parent_inode,
                name,
                new_ino,
                new_inode.mode,
            )
            .await
        {
            self.discard_new_inode(new_ino, slow_block).await;
            return Err(e);
        }
        // Parent directory mtime + ctime change because its dirent list
        // was modified.
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        Ok(new_ino)
    }

    /// Read the textual target of a symlink. For fast symlinks the
    /// bytes come from `i_block`; for slow symlinks the first data
    /// block is read.
    pub async fn read_symlink_target(&self, inode: &Inode) -> Result<Vec<u8>, FsError> {
        if !inode.is_symlink() {
            return Err(FsError::InvalidPath);
        }
        let len = inode.size as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        if len <= 60 && inode.is_fast_symlink(self.block_size() as u32) {
            // Fast — pull from block[] serialised as 60 bytes.
            let mut bytes = [0u8; 60];
            for i in 0..super::inode::I_BLOCK_LEN {
                let off = i * 4;
                bytes[off..off + 4].copy_from_slice(&inode.block[i].to_le_bytes());
            }
            return Ok(bytes[..len].to_vec());
        }
        // Slow — single data block, found through the inode's mapping: an
        // ext4 slow symlink is extent-mapped, so `i_block[0]` holds the
        // extent header, not a block number (`ext4_get_link` reads logical
        // block 0 through `ext4_bread`). Reading it as a pointer returned
        // garbage for every link target longer than 60 bytes on a
        // Linux-made ext4 volume.
        let bs = self.block_size();
        let phys = self.map_block(inode, 0).await?;
        if phys == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; bs];
        self.read_block(phys, &mut buf).await?;
        Ok(buf[..len.min(bs)].to_vec())
    }
}

/// One level of a `dx_probe` walk: an index block (root or node), where its
/// entries start, and the entry the hash chose (`frame->at`).
struct DxFrame {
    physical: u64,
    block: alloc::vec::Vec<u8>,
    entries: usize,
    at: u16,
}

/// The dx index block layout (`fs/ext4/namei.c`). Entry `i` sits at
/// `entries + 8 * i` as `{ u32 hash, u32 block }`; entry 0's hash word is
/// the `(limit, count)` header. Linux keeps the top four bits of a block
/// number reserved (`dx_get_block`).
mod dx {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::super::dir::rec_len_for;
    use super::super::htree;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    pub fn limit(b: &[u8], entries: usize) -> u16 {
        u16_at(b, entries)
    }

    pub fn count(b: &[u8], entries: usize) -> u16 {
        u16_at(b, entries + 2)
    }

    pub fn set_count(b: &mut [u8], entries: usize, count: u16) {
        b[entries + 2..entries + 4].copy_from_slice(&count.to_le_bytes());
    }

    pub fn hash_of(b: &[u8], entries: usize, i: u16) -> u32 {
        u32_at(b, entries + 8 * usize::from(i))
    }

    pub fn block_of(b: &[u8], entries: usize, i: u16) -> u32 {
        u32_at(b, entries + 8 * usize::from(i) + 4) & 0x0fff_ffff
    }

    pub fn set_block(b: &mut [u8], entries: usize, i: u16, block: u32) {
        let at = entries + 8 * usize::from(i) + 4;
        b[at..at + 4].copy_from_slice(&block.to_le_bytes());
    }

    /// `dx_probe`'s binary search: the last entry whose hash is at most
    /// `hash` (entry 0 covers everything below entry 1). `None` for a
    /// count that is zero or past the limit.
    pub fn find(b: &[u8], entries: usize, hash: u32) -> Option<u16> {
        let count = count(b, entries);
        if count == 0 || count > limit(b, entries) || entries + 8 * usize::from(count) > b.len() {
            return None;
        }
        let (mut p, mut q) = (1i32, i32::from(count) - 1);
        while p <= q {
            let m = p + (q - p) / 2;
            if hash_of(b, entries, m as u16) > hash {
                q = m - 1;
            } else {
                p = m + 1;
            }
        }
        Some((p - 1) as u16)
    }

    /// `dx_insert_block`: a new entry `(hash, block)` right after `at`.
    pub fn insert_after(b: &mut [u8], entries: usize, at: u16, hash: u32, block: u32) {
        let count = usize::from(count(b, entries));
        let from = entries + 8 * (usize::from(at) + 1);
        let end = entries + 8 * count;
        b.copy_within(from..end, from + 8);
        b[from..from + 4].copy_from_slice(&hash.to_le_bytes());
        b[from + 4..from + 8].copy_from_slice(&block.to_le_bytes());
        set_count(b, entries, (count + 1) as u16);
    }

    /// An empty `dx_node`: a fake dirent spanning the block, then the
    /// `(limit, count)` header.
    pub fn new_node(bs: usize, limit: u16) -> Vec<u8> {
        let mut b = vec![0u8; bs];
        b[4..6].copy_from_slice(&(bs as u16).to_le_bytes());
        b[htree::DX_NODE_ENTRIES_OFF..htree::DX_NODE_ENTRIES_OFF + 2]
            .copy_from_slice(&limit.to_le_bytes());
        b
    }

    /// Entries `from..to` of `src` become entries `0..` of the node `dst`
    /// (whose own entry-0 hash word stays its header).
    pub fn copy_entries(src: &[u8], src_entries: usize, from: u16, to: u16, dst: &mut [u8]) {
        let off = htree::DX_NODE_ENTRIES_OFF;
        for (k, i) in (from..to).enumerate() {
            let k = k as u16;
            if k != 0 {
                let at = off + 8 * usize::from(k);
                dst[at..at + 4].copy_from_slice(&hash_of(src, src_entries, i).to_le_bytes());
            }
            set_block(dst, off, k, block_of(src, src_entries, i));
        }
        set_count(dst, off, to - from);
    }

    /// One live dirent of a leaf (`struct dx_map_entry`).
    #[derive(Copy, Clone)]
    pub struct MapEntry {
        pub hash: u32,
        pub offset: usize,
        /// The record's `rec_len`, slack included.
        pub size: usize,
    }

    /// `dx_make_map`: every live entry of `leaf[..usable]` with its hash,
    /// sorted by hash. `None` for a malformed record.
    pub fn make_map(
        leaf: &[u8],
        usable: usize,
        version: u8,
        seed: &[u32; 4],
    ) -> Option<Vec<MapEntry>> {
        let mut map = Vec::new();
        let mut off = 0usize;
        while off + 8 <= usable {
            let inode = u32_at(leaf, off);
            let rec_len = usize::from(u16_at(leaf, off + 4));
            let name_len = usize::from(leaf[off + 6]);
            if rec_len < 8 || rec_len % 4 != 0 || off + rec_len > usable || 8 + name_len > rec_len {
                return None;
            }
            if inode != 0 && name_len != 0 {
                let name = &leaf[off + 8..off + 8 + name_len];
                let hash = htree::ext4fs_dirhash(name, version, seed)?.hash;
                map.push(MapEntry {
                    hash,
                    offset: off,
                    size: rec_len,
                });
            }
            off += rec_len;
        }
        map.sort_by_key(|e| e.hash);
        Some(map)
    }

    /// `do_split`'s split point: from the highest hash down, the entries
    /// whose sizes fit in half a block move; if they all would, split by
    /// count instead.
    pub fn split_point(map: &[MapEntry], bs: usize) -> usize {
        let mut size = 0usize;
        for (moved, e) in map.iter().rev().enumerate() {
            if size + e.size / 2 > bs / 2 {
                return map.len() - moved;
            }
            size += e.size;
        }
        map.len() / 2
    }

    /// `dx_move_dirents` / `dx_pack_dirents`: the given entries of `leaf`,
    /// packed at their minimal record length, the last one spanning to the
    /// checksum tail.
    pub fn pack(leaf: &[u8], entries: &[MapEntry], bs: usize, csum_tail: usize) -> Vec<u8> {
        let mut out = vec![0u8; bs];
        let mut pos = 0usize;
        for (i, e) in entries.iter().enumerate() {
            let name_len = leaf[e.offset + 6];
            let len = usize::from(rec_len_for(name_len));
            out[pos..pos + 8 + usize::from(name_len)]
                .copy_from_slice(&leaf[e.offset..e.offset + 8 + usize::from(name_len)]);
            let rec_len = if i + 1 == entries.len() {
                bs - csum_tail - pos
            } else {
                len
            };
            out[pos + 4..pos + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
            pos += len;
        }
        out
    }
}
