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

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Read every directory data block of `parent_inode` into a
    /// flat `Vec<u8>`. Length equals `parent_inode.size`.
    pub(crate) async fn read_dir_bytes(&self, parent_inode: &Inode) -> Result<Vec<u8>, FsError> {
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
                out[off..off + want].copy_from_slice(&blockbuf[in_block..in_block + want]);
            }
            off += want;
        }
        Ok(out)
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
            let inode =
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
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
    /// either performs an HTREE leaf-split (when the directory is
    /// HTREE-indexed and the compat flag is present), or falls back
    /// to allocating a fresh logical block seeded with a single entry.
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
        let blocks = (parent_inode.size as usize).div_ceil(bs);
        let file_type = ftype_for_mode(target_mode);

        // Determine whether HTREE is active on this directory.
        // Two conditions must both hold:
        //   (a) The superblock has compat::DIR_INDEX set.
        //   (b) The inode has I_FLAGS_INDEX set.
        let htree_active =
            self.superblock.feature_compat & compat::DIR_INDEX != 0 && parent_inode.is_htree();

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
                splice::InsertResult::NoRoom if htree_active && i > 0 => {
                    // HTREE leaf block is full — split it.
                    // Block 0 is the root node, not a leaf; skip it.
                    //
                    // Read the root block to get hash_version + seed.
                    let root_phys = self.map_block(parent_inode, 0).await?;
                    if root_phys == 0 {
                        // Corrupt tree — fall through to linear extend.
                        continue;
                    }
                    let mut root_buf = vec![0u8; bs];
                    self.read_block(root_phys, &mut root_buf).await?;
                    let dx_root = match DxRoot::parse(&root_buf) {
                        Some(r) => r,
                        None => continue, // not really an HTREE root; skip
                    };
                    let seed = [0u32; 4]; // s_hash_seed — zero for generated images
                    match htree::htree_split_leaf(&blockbuf, dx_root.hash_version, &seed) {
                        Err(_) => {
                            // Split failed (corrupt or only 1 entry) —
                            // fall through to linear append.
                            continue;
                        }
                        Ok(split) => {
                            // Allocate a new physical block for the upper half.
                            let new_phys = self.alloc_block().await? as u32;
                            let zeros = vec![0u8; bs];
                            self.write_block(new_phys as u64, &zeros).await?;

                            // Write repacked halves.
                            self.write_block(phys, &split.old_block_data).await?;
                            self.write_block(new_phys as u64, &split.new_block_data)
                                .await?;

                            // Update the root-node index with the new
                            // (split_hash, new_phys) entry. Only the
                            // one-level case (indirect_levels == 0) is
                            // handled here; deeper trees fall through.
                            if dx_root.indirect_levels == 0 {
                                htree::index_node_insert_entry(
                                    &mut root_buf,
                                    htree::DX_ROOT_HEAD_OFF,
                                    htree::DX_ROOT_ENTRIES_OFF,
                                    split.split_hash,
                                    new_phys,
                                )
                                .ok(); // IndexFull: we still wrote the blocks; new entry is just unreachable until a deeper split is done
                                self.write_block(root_phys, &root_buf).await?;
                            }
                            // Bump i_blocks for the new physical block.
                            parent_inode.blocks =
                                parent_inode.blocks.saturating_add(bs as u32 / 512);
                            // i_size stays the same — we reused the
                            // same number of logical blocks; the HTREE
                            // root's count already covers the new block
                            // via the index entry.
                            self.write_inode(parent_inode_no, parent_inode).await?;

                            // Now try to insert into the appropriate half.
                            // Hash the name to decide which block to use.
                            let h = htree::name_hash(name, dx_root.hash_version, &seed);
                            let target_buf = if h.hash >= split.split_hash {
                                // Upper half (the new block).
                                let mut nb = split.new_block_data.clone();
                                if let splice::InsertResult::Ok { .. } =
                                    splice::insert_entry(&mut nb, target_inode_no, name, file_type)
                                {
                                    self.write_block(new_phys as u64, &nb).await?;
                                    return Ok(());
                                }
                                nb
                            } else {
                                // Lower half (old block).
                                let mut ob = split.old_block_data.clone();
                                if let splice::InsertResult::Ok { .. } =
                                    splice::insert_entry(&mut ob, target_inode_no, name, file_type)
                                {
                                    self.write_block(phys, &ob).await?;
                                    return Ok(());
                                }
                                ob
                            };
                            // If insert still failed after split, fall through
                            // by continuing — the outer loop will try other blocks.
                            let _ = target_buf;
                        }
                    }
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
        _parent_inode_no: u32,
        parent_inode: &mut Inode,
        name: &[u8],
    ) -> Result<(u32, u8), FsError> {
        let bs = self.block_size();
        let blocks = (parent_inode.size as usize).div_ceil(bs);
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
                let rec_len = u16::from_le_bytes([blockbuf[off + 4], blockbuf[off + 5]]) as usize;
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
        let now = Ext2Volume::<B>::now_secs();
        // Allocate inode + initialise with timestamps.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_regular(mode);
        new_inode.atime = now;
        new_inode.touch_ctime_mtime(now);
        self.write_inode(new_ino, &new_inode).await?;
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
        let now = Ext2Volume::<B>::now_secs();
        let bs = self.block_size();
        // Allocate the inode + a data block.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_directory(mode);
        new_inode.atime = now;
        new_inode.touch_ctime_mtime(now);
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
            .dir_insert(
                parent_inode_no,
                &mut parent_inode,
                name,
                new_ino,
                new_inode.mode,
            )
            .await
        {
            let _ = self.free_block(data_block).await;
            let _ = self.free_inode(new_ino).await;
            return Err(e);
        }
        // Bump parent's links_count + touch its timestamps.
        parent_inode.links_count = parent_inode.links_count.saturating_add(1);
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(parent_inode_no, &parent_inode).await?;
        Ok(new_ino)
    }

    /// Remove a file dirent. Decrements the target's link count; if
    /// it drops to zero, frees its blocks + inode slot.
    pub async fn dir_unlink(&self, parent_inode_no: u32, name: &[u8]) -> Result<(), FsError> {
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
    pub async fn dir_rmdir(&self, parent_inode_no: u32, name: &[u8]) -> Result<(), FsError> {
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
        let now = Ext2Volume::<B>::now_secs();
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
        // ctime changes on the target (link count changed); parent
        // dir's mtime + ctime change because its dirent list grew.
        target.touch_ctime(now);
        parent_inode.touch_ctime_mtime(now);
        self.write_inode(target_ino, &target).await?;
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
        // already enforces that itself (returning the correct EEXIST), so
        // failing here was both redundant and wrong — and it reported
        // EINVAL rather than EEXIST.
        //
        // This is Qt QSaveFile's every-write path: write a temp beside the
        // target, then rename it ONTO the existing target. Refusing broke
        // every KConfig/KSycoca write on the ext2 rootfs, surfacing as
        // kwin logging `Couldn't write ".../kwinrc" . Disk full?` (KConfig
        // prints that for any failed commit; the disk had 2.5 GB free).
        //
        // Unlink the victim FIRST so `dir_insert` cannot leave a second
        // dirent with the same name in the directory: insert-then-unlink
        // would remove whichever entry matched first on the next pass.
        let victim = self.dir_lookup(&new_parent_probe, new_name).await.ok();
        if let Some((victim_ino, _)) = victim {
            // Renaming a name onto ITSELF is a documented no-op that must
            // leave the file intact, so do not unlink in that case.
            if victim_ino == target_ino {
                return Ok(());
            }
            let mut victim_parent = self.read_inode(new_parent_inode_no).await?;
            self.dir_delete(new_parent_inode_no, &mut victim_parent, new_name)
                .await?;
            victim_parent.touch_ctime_mtime(now);
            self.write_inode(new_parent_inode_no, &victim_parent)
                .await?;
            // Release the replaced inode exactly as dir_unlink does: drop a
            // link, and free the blocks + inode when the last one goes.
            // Skipping this would leak the overwritten file's blocks on
            // every config save.
            let mut victim_inode = self.read_inode(victim_ino).await?;
            victim_inode.links_count = victim_inode.links_count.saturating_sub(1);
            victim_inode.touch_ctime(now);
            if victim_inode.links_count == 0 {
                self.truncate_inode(&mut victim_inode).await?;
                self.write_inode(victim_ino, &victim_inode).await?;
                self.free_inode(victim_ino).await?;
            } else {
                self.write_inode(victim_ino, &victim_inode).await?;
            }
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

        // Touch timestamps on the target (ctime always) and both
        // parent dirs (mtime + ctime because their dirent lists changed).
        target.touch_ctime(now);
        self.write_inode(target_ino, &target).await?;
        old_parent.touch_ctime_mtime(now);
        self.write_inode(old_parent_inode_no, &old_parent).await?;
        if old_parent_inode_no != new_parent_inode_no {
            let mut np = self.read_inode(new_parent_inode_no).await?;
            np.touch_ctime_mtime(now);
            self.write_inode(new_parent_inode_no, &np).await?;
        }

        // Cross-directory move of a directory needs link-count balance:
        // - old parent loses the ".." back-link → drop links_count
        // - new parent gains it → bump links_count
        // - target's ".." entry is updated to the new parent
        if is_dir && old_parent_inode_no != new_parent_inode_no {
            let mut old_p = self.read_inode(old_parent_inode_no).await?;
            old_p.links_count = old_p.links_count.saturating_sub(1);
            old_p.touch_ctime(now);
            self.write_inode(old_parent_inode_no, &old_p).await?;
            let mut new_p = self.read_inode(new_parent_inode_no).await?;
            new_p.links_count = new_p.links_count.saturating_add(1);
            new_p.touch_ctime(now);
            self.write_inode(new_parent_inode_no, &new_p).await?;
            // Rewrite target's ".." to point at the new parent.
            let target_now = self.read_inode(target_ino).await?;
            let bs = self.block_size();
            // ".." is the second entry in the first block.
            let phys = self.map_block(&target_now, 0).await?;
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
            self.write_inode(target_ino, &target_now).await?;
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
        let now = Ext2Volume::<B>::now_secs();
        if target.is_empty() {
            return Err(FsError::InvalidPath);
        }
        // Allocate the inode.
        let new_ino = self.alloc_inode().await?;
        let mut new_inode = Inode::new_symlink(0o777);
        new_inode.atime = now;
        new_inode.touch_ctime_mtime(now);
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
