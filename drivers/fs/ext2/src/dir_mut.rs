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
use super::inode::{Inode, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
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

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Read every directory data block of `parent_inode` into a
    /// flat `Vec<u8>`. Length equals `parent_inode.size`.
    pub(crate) async fn read_dir_bytes(
        &self,
        parent_inode: &Inode,
    ) -> Result<Vec<u8>, FsError> {
        let size = parent_inode.size as usize;
        if size == 0 {
            return Ok(Vec::new());
        }
        let bs = self.block_size();
        let mut out = vec![0u8; size];
        let mut off = 0usize;
        while off < size {
            let logical = (off / bs) as u64;
            let in_block = off % bs;
            let want = core::cmp::min(size - off, bs - in_block);
            let phys = self.map_block(parent_inode, logical).await?;
            if phys == 0 {
                for b in &mut out[off..off + want] {
                    *b = 0;
                }
            } else {
                let mut blockbuf = vec![0u8; bs];
                self.read_block(phys, &mut blockbuf).await?;
                out[off..off + want]
                    .copy_from_slice(&blockbuf[in_block..in_block + want]);
            }
            off += want;
        }
        Ok(out)
    }

    /// Write one directory data block back to disk. Walks the parent's
    /// block pointer chain; allocates a fresh data block if `logical`
    /// is currently a hole. Caller must persist any inode mutations.
    async fn write_dir_block(
        &self,
        parent_inode: &mut Inode,
        logical: u64,
        block: &[u8],
    ) -> Result<(), FsError> {
        let bs = self.block_size();
        if block.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let phys = self.map_block_alloc(parent_inode, logical).await?;
        self.write_block(phys, block).await
    }

    /// Look up `name` in `parent_inode`, returning `(inode_no,
    /// file_type)`. Returns `NotFound` if the name is absent.
    pub(crate) async fn dir_lookup(
        &self,
        parent_inode: &Inode,
        name: &[u8],
    ) -> Result<(u32, u8), FsError> {
        let bytes = self.read_dir_bytes(parent_inode).await?;
        let mut off = 0usize;
        while off + 8 <= bytes.len() {
            let inode = u32::from_le_bytes([
                bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3],
            ]);
            let rec_len = u16::from_le_bytes([bytes[off + 4], bytes[off + 5]]) as usize;
            let name_len = bytes[off + 6] as usize;
            let file_type = bytes[off + 7];
            if rec_len < 8 || off + rec_len > bytes.len() {
                return Err(FsError::Io(narf_block::BlockError::IOError));
            }
            if inode != 0 && name_len == name.len() && &bytes[off + 8..off + 8 + name_len] == name {
                return Ok((inode, file_type));
            }
            off += rec_len;
        }
        Err(FsError::NotFound)
    }

    /// Splice a `(name, inode, file_type)` entry into `parent_inode`'s
    /// directory body. Walks logical blocks in order, attempting a
    /// per-block splice; when every existing block reports `NoRoom`,
    /// allocates a fresh logical block and seeds it with a single
    /// entry whose `rec_len` extends to end-of-block.
    ///
    /// On `Exists`, returns `FsError::InvalidPath` (the FS layer uses
    /// that for name conflicts — `FsError` has no dedicated AlreadyExists
    /// variant yet).
    ///
    /// Caller persists the parent inode (size may grow on extension).
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
        let bs = self.block_size();
        let blocks = (parent_inode.size as usize + bs - 1) / bs;
        let file_type = ftype_for_mode(target_mode);

        // Try each existing block.
        for i in 0..blocks {
            let phys = self.map_block(parent_inode, i as u64).await?;
            if phys == 0 {
                continue;
            }
            let mut blockbuf = vec![0u8; bs];
            self.read_block(phys, &mut blockbuf).await?;
            match splice::insert_entry(&mut blockbuf, target_inode_no, name, file_type) {
                splice::InsertResult::Ok { .. } => {
                    self.write_block(phys, &blockbuf).await?;
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
        // bump the parent's i_size + i_blocks.
        let new_logical = blocks as u64;
        let phys = self.map_block_alloc(parent_inode, new_logical).await?;
        let mut blockbuf = vec![0u8; bs];
        // Single record filling the whole block.
        let rec_len = bs as u16;
        blockbuf[0..4].copy_from_slice(&target_inode_no.to_le_bytes());
        blockbuf[4..6].copy_from_slice(&rec_len.to_le_bytes());
        blockbuf[6] = name.len() as u8;
        blockbuf[7] = file_type;
        blockbuf[8..8 + name.len()].copy_from_slice(name);
        self.write_block(phys, &blockbuf).await?;
        // Update parent inode bookkeeping.
        parent_inode.size += bs as u32;
        // i_blocks is in 512-byte sectors.
        parent_inode.blocks = parent_inode.blocks.saturating_add(bs as u32 / 512);
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
        let bs = self.block_size();
        let blocks = (parent_inode.size as usize + bs - 1) / bs;
        for i in 0..blocks {
            let phys = self.map_block(parent_inode, i as u64).await?;
            if phys == 0 {
                continue;
            }
            let mut blockbuf = vec![0u8; bs];
            self.read_block(phys, &mut blockbuf).await?;
            // Scan for the entry.
            let mut off = 0usize;
            while off + 8 <= blockbuf.len() {
                let inode = u32::from_le_bytes([
                    blockbuf[off],
                    blockbuf[off + 1],
                    blockbuf[off + 2],
                    blockbuf[off + 3],
                ]);
                let rec_len = u16::from_le_bytes([
                    blockbuf[off + 4],
                    blockbuf[off + 5],
                ]) as usize;
                let name_len = blockbuf[off + 6] as usize;
                let file_type = blockbuf[off + 7];
                if rec_len < 8 || off + rec_len > blockbuf.len() {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
                if inode != 0
                    && name_len == name.len()
                    && &blockbuf[off + 8..off + 8 + name_len] == name
                {
                    splice::delete_entry(&mut blockbuf, off)
                        .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
                    self.write_block(phys, &blockbuf).await?;
                    // Touch parent inode mtime by re-persisting so the
                    // dirent change is observable on later mounts.
                    let _ = self.write_inode(parent_inode_no, parent_inode).await;
                    return Ok((inode, file_type));
                }
                off += rec_len;
            }
        }
        Err(FsError::NotFound)
    }

    /// Create a regular file inode + directory entry.
    pub async fn dir_create_regular(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        mode: u16,
    ) -> Result<u32, FsError> {
        // Allocate inode + initialise.
        let new_ino = self.alloc_inode().await?;
        let new_inode = Inode::new_regular(mode);
        self.write_inode(new_ino, &new_inode).await?;
        // Splice the dirent into the parent.
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            // Roll back the inode allocation.
            let _ = self.free_inode(new_ino).await;
            return Err(FsError::InvalidPath);
        }
        if let Err(e) = self
            .dir_insert(parent_inode_no, &mut parent_inode, name, new_ino, new_inode.mode)
            .await
        {
            let _ = self.free_inode(new_ino).await;
            return Err(e);
        }
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
        let bs = self.block_size();
        // Allocate the inode + a data block.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_directory(mode);
        // Allocate the first data block to hold "." and "..".
        let data_block = match self.alloc_block().await {
            Ok(b) => b,
            Err(e) => {
                let _ = self.free_inode(new_ino).await;
                return Err(e);
            }
        };
        new_inode.block[0] = data_block as u32;
        new_inode.size = bs as u32;
        new_inode.blocks = bs as u32 / 512;
        // Write "." + ".." into the data block.
        let mut blockbuf = vec![0u8; bs];
        splice::make_empty_dir(&mut blockbuf, new_ino, parent_inode_no);
        if let Err(e) = self.write_block(data_block, &blockbuf).await {
            let _ = self.free_block(data_block).await;
            let _ = self.free_inode(new_ino).await;
            return Err(e);
        }
        // Persist the new dir inode.
        self.write_inode(new_ino, &new_inode).await?;
        // Splice into the parent.
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            let _ = self.free_block(data_block).await;
            let _ = self.free_inode(new_ino).await;
            return Err(FsError::InvalidPath);
        }
        if let Err(e) = self
            .dir_insert(parent_inode_no, &mut parent_inode, name, new_ino, new_inode.mode)
            .await
        {
            let _ = self.free_block(data_block).await;
            let _ = self.free_inode(new_ino).await;
            return Err(e);
        }
        // Bump parent's links_count for the new child's ".." entry.
        parent_inode.links_count = parent_inode.links_count.saturating_add(1);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        Ok(new_ino)
    }

    /// Remove a file dirent. Decrements the target's link count; if
    /// it drops to zero, frees its blocks + inode slot.
    pub async fn dir_unlink(
        &self,
        parent_inode_no: u32,
        name: &[u8],
    ) -> Result<(), FsError> {
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
        if target.links_count == 0 {
            self.truncate_inode(&mut target).await?;
            self.write_inode(target_ino, &target).await?;
            self.free_inode(target_ino).await?;
        } else {
            self.write_inode(target_ino, &target).await?;
        }
        Ok(())
    }

    /// Remove an empty subdirectory. Refuses if non-empty. Frees both
    /// the data blocks and the inode regardless of the link count
    /// (rmdir invalidates the slot — `.` and `..` are removed
    /// implicitly when the block is freed).
    pub async fn dir_rmdir(
        &self,
        parent_inode_no: u32,
        name: &[u8],
    ) -> Result<(), FsError> {
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
        let body = self.read_dir_bytes(&target).await?;
        if !splice::is_dir_empty(&body) {
            return Err(FsError::Busy);
        }
        // Delete the dirent, free data blocks + inode, drop parent's
        // links_count for the ".." back-link.
        let _ = self
            .dir_delete(parent_inode_no, &mut parent_inode, name)
            .await?;
        self.truncate_inode(&mut target).await?;
        target.links_count = 0;
        self.write_inode(target_ino, &target).await?;
        self.free_inode(target_ino).await?;
        parent_inode.links_count = parent_inode.links_count.saturating_sub(1);
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
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
            return Err(FsError::InvalidPath);
        }
        let mut target = self.read_inode(target_ino).await?;
        if target.is_dir() {
            return Err(FsError::InvalidPath);
        }
        self.dir_insert(
            parent_inode_no,
            &mut parent_inode,
            name,
            target_ino,
            target.mode,
        )
        .await?;
        target.links_count = target.links_count.saturating_add(1);
        self.write_inode(target_ino, &target).await?;
        Ok(())
    }

    /// Rename `old_name` in `old_parent_inode_no` to `new_name` in
    /// `new_parent_inode_no`. Implements the cross-directory case
    /// (old != new) by bumping the new parent's link count when a
    /// directory moves and dropping the old parent's count
    /// symmetrically.
    ///
    /// For same-directory renames this is equivalent to insert + delete.
    pub async fn dir_rename(
        &self,
        old_parent_inode_no: u32,
        old_name: &[u8],
        new_parent_inode_no: u32,
        new_name: &[u8],
    ) -> Result<(), FsError> {
        // Look up the source so we know what to splice into the dest.
        let old_parent = self.read_inode(old_parent_inode_no).await?;
        if !old_parent.is_dir() {
            return Err(FsError::InvalidPath);
        }
        let (target_ino, _ft) = self.dir_lookup(&old_parent, old_name).await?;
        let target = self.read_inode(target_ino).await?;
        let is_dir = target.is_dir();

        // If the destination already exists, fail (matches POSIX
        // RENAME_NOREPLACE — we do not implement atomic replace yet).
        let new_parent_probe = if old_parent_inode_no == new_parent_inode_no {
            old_parent
        } else {
            self.read_inode(new_parent_inode_no).await?
        };
        if !new_parent_probe.is_dir() {
            return Err(FsError::InvalidPath);
        }
        if let Ok(_) = self.dir_lookup(&new_parent_probe, new_name).await {
            return Err(FsError::InvalidPath);
        }

        // Insert into the new parent.
        let mut new_parent = self.read_inode(new_parent_inode_no).await?;
        self.dir_insert(
            new_parent_inode_no,
            &mut new_parent,
            new_name,
            target_ino,
            target.mode,
        )
        .await?;
        // Delete from the old parent. Re-read in case insert
        // mutated it (when old == new).
        let mut old_parent = self.read_inode(old_parent_inode_no).await?;
        self.dir_delete(old_parent_inode_no, &mut old_parent, old_name)
            .await?;

        // Cross-directory move of a directory needs link-count balance:
        // - old parent loses the ".." back-link → drop links_count
        // - new parent gains it → bump links_count
        // - target's ".." entry is updated to the new parent
        if is_dir && old_parent_inode_no != new_parent_inode_no {
            let mut old_parent = self.read_inode(old_parent_inode_no).await?;
            old_parent.links_count = old_parent.links_count.saturating_sub(1);
            self.write_inode(old_parent_inode_no, &old_parent).await?;
            let mut new_parent = self.read_inode(new_parent_inode_no).await?;
            new_parent.links_count = new_parent.links_count.saturating_add(1);
            self.write_inode(new_parent_inode_no, &new_parent).await?;
            // Rewrite target's ".." to point at the new parent.
            let mut target = self.read_inode(target_ino).await?;
            let bs = self.block_size();
            // ".." is the second entry in the first block.
            let phys = self.map_block(&target, 0).await?;
            if phys != 0 {
                let mut blockbuf = vec![0u8; bs];
                self.read_block(phys, &mut blockbuf).await?;
                // Skip "." entry then patch the ".." inode pointer.
                let dot_rec_len = u16::from_le_bytes([blockbuf[4], blockbuf[5]]) as usize;
                if dot_rec_len + 4 <= blockbuf.len() {
                    blockbuf[dot_rec_len..dot_rec_len + 4]
                        .copy_from_slice(&new_parent_inode_no.to_le_bytes());
                    self.write_block(phys, &blockbuf).await?;
                }
            }
            self.write_inode(target_ino, &target).await?;
        }
        Ok(())
    }

    /// Create a symlink. For targets ≤ 60 bytes, the link path is
    /// stored inline in the inode's `i_block` area ("fast symlink");
    /// longer targets get an allocated data block.
    pub async fn dir_create_symlink(
        &self,
        parent_inode_no: u32,
        name: &[u8],
        target: &[u8],
    ) -> Result<u32, FsError> {
        if target.is_empty() {
            return Err(FsError::InvalidPath);
        }
        // Allocate the inode.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_symlink(0o777);
        new_inode.size = target.len() as u32;

        if target.len() <= 60 {
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
            if target.len() > bs {
                let _ = self.free_inode(new_ino).await;
                return Err(FsError::InvalidPath);
            }
            let data_block = match self.alloc_block().await {
                Ok(b) => b,
                Err(e) => {
                    let _ = self.free_inode(new_ino).await;
                    return Err(e);
                }
            };
            let mut buf = vec![0u8; bs];
            buf[..target.len()].copy_from_slice(target);
            self.write_block(data_block, &buf).await?;
            new_inode.block[0] = data_block as u32;
            new_inode.blocks = bs as u32 / 512;
        }
        self.write_inode(new_ino, &new_inode).await?;
        let mut parent_inode = self.read_inode(parent_inode_no).await?;
        if !parent_inode.is_dir() {
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
        Ok(new_ino)
    }

    /// Read the textual target of a symlink. For fast symlinks the
    /// bytes come from `i_block`; for slow symlinks the first data
    /// block is read.
    pub async fn read_symlink_target(
        &self,
        inode: &Inode,
    ) -> Result<Vec<u8>, FsError> {
        if !inode.is_symlink() {
            return Err(FsError::InvalidPath);
        }
        let len = inode.size as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        if len <= 60 && inode.blocks == 0 {
            // Fast — pull from block[] serialised as 60 bytes.
            let mut bytes = [0u8; 60];
            for i in 0..super::inode::I_BLOCK_LEN {
                let off = i * 4;
                bytes[off..off + 4].copy_from_slice(&inode.block[i].to_le_bytes());
            }
            return Ok(bytes[..len].to_vec());
        }
        // Slow — single data block.
        let bs = self.block_size();
        let phys = inode.block[0] as u64;
        if phys == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; bs];
        self.read_block(phys, &mut buf).await?;
        Ok(buf[..len.min(bs)].to_vec())
    }
}
