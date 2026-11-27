//! The orphan file and the orphan list (`fs/ext4/orphan.c`): an inode whose
//! last link went while it was still open is recorded on disk, in the same
//! journal transaction as the unlink, so a crash before its release is
//! completed at the next mount.
//!
//! - With `orphan_file`, a slot of the orphan file's blocks holds its number
//!   (`ext4_orphan_file_add`). Each block ends with `ob_magic` and a crc32c
//!   over the block number and the entries, seeded with the orphan inode's
//!   checksum seed.
//! - Otherwise, or when the orphan file is full, the inode goes at the head
//!   of the list `s_last_orphan` threads through `i_dtime` (`NEXT_ORPHAN`).
//! - Only with a journal (`ext4_orphan_add` returns early without one):
//!   without a journal nothing makes the unlink and the record atomic.
//!
//! At mount, `ext4_orphan_cleanup` finishes what a crash interrupted: a
//! listed inode with no links is deleted, one with links (an interrupted
//! truncate) is truncated to its `i_size`, and either is taken off the
//! list. It runs on a read-only mount too when the device can be written.
//!
//! The orphan file never grows or shrinks, as on Linux ("For now we don't
//! grow or shrink orphan file").

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::super::inode::Inode;
use super::super::metadata_csum;
use super::super::superblock::{compat, EXT2_ERROR_FS};
use super::Ext2Volume;

/// `EXT4_ORPHAN_BLOCK_MAGIC`.
pub(crate) const ORPHAN_BLOCK_MAGIC: u32 = 0x0b10_ca04;
/// `EXT4_MAX_ORPHAN_FILE_BLOCKS`.
const MAX_ORPHAN_FILE_BLOCKS: u64 = 512;
/// `struct ext4_orphan_block_tail`.
const TAIL_BYTES: usize = 8;
/// `s_last_orphan`'s offset in the superblock.
const LAST_ORPHAN: usize = 0xE8;

/// Where a tracked orphan is recorded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Slot {
    /// `EXT4_STATE_ORPHAN_FILE` with this `i_orphan_idx`.
    File(u32),
    /// On the `s_last_orphan` list.
    List,
}

/// `struct ext4_orphan_info`, plus the in-memory list (`s_orphan`).
#[derive(Debug, Default)]
pub(crate) struct Orphans {
    /// The orphan file's blocks, by physical block number.
    blocks: Vec<u64>,
    /// Free entries per block (`ob_free_entries`).
    free: Vec<u32>,
    /// The orphan inode's checksum seed (`of_csum_seed`).
    csum_seed: u32,
    /// Tracked inodes and where each is recorded.
    slots: BTreeMap<u32, Slot>,
    /// The on-disk list, head first.
    list: Vec<u32>,
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// `ext4_inodes_per_orphan_block`.
    fn inodes_per_orphan_block(&self) -> usize {
        (self.block_size() - TAIL_BYTES) / 4
    }

    /// The tail checksum of orphan file block `physical`
    /// (`ext4_orphan_file_block_trigger`).
    fn orphan_block_csum(&self, seed: u32, physical: u64, block: &[u8]) -> u32 {
        let state = metadata_csum::crc32c(seed, &physical.to_le_bytes());
        metadata_csum::crc32c(state, &block[..self.inodes_per_orphan_block() * 4])
    }

    /// `ext4_init_orphan_info`: read and check every orphan file block.
    /// A block with a bad magic or checksum fails the mount with EIO.
    pub(crate) async fn init_orphan_info(&self) -> Result<(), FsError> {
        if self.superblock.feature_compat & compat::ORPHAN_FILE == 0 {
            return Ok(());
        }
        let ino = self.superblock.orphan_file_inum;
        let inode = self.read_inode(ino).await?;
        let bs = self.block_size() as u64;
        if inode.size > MAX_ORPHAN_FILE_BLOCKS * bs {
            return Err(FsError::Corrupted);
        }
        let count = (inode.size / bs) as usize;
        let seed = if self.superblock.has_metadata_csum() {
            let s =
                metadata_csum::crc32c(metadata_csum::seed(&self.superblock), &ino.to_le_bytes());
            metadata_csum::crc32c(s, &inode.generation.to_le_bytes())
        } else {
            0
        };
        let per = self.inodes_per_orphan_block();
        let mut blocks = Vec::with_capacity(count);
        let mut free = Vec::with_capacity(count);
        let mut buf = vec![0u8; bs as usize];
        for i in 0..count {
            let physical = self.map_block(&inode, i as u64).await?;
            if physical == 0 {
                return Err(FsError::Io(narf_block::BlockError::IOError));
            }
            self.read_block(physical, &mut buf).await?;
            let tail = bs as usize - TAIL_BYTES;
            let magic = u32::from_le_bytes(buf[tail..tail + 4].try_into().expect("4 bytes"));
            let stored = u32::from_le_bytes(buf[tail + 4..].try_into().expect("4 bytes"));
            if magic != ORPHAN_BLOCK_MAGIC
                || (self.superblock.has_metadata_csum()
                    && stored != self.orphan_block_csum(seed, physical, &buf))
            {
                self.orphan_error(i);
                return Err(FsError::Io(narf_block::BlockError::IOError));
            }
            free.push(
                buf[..per * 4]
                    .chunks_exact(4)
                    .filter(|e| e == &[0; 4])
                    .count() as u32,
            );
            blocks.push(physical);
        }
        let mut orphans = self.orphans_state.lock();
        orphans.blocks = blocks;
        orphans.free = free;
        orphans.csum_seed = seed;
        Ok(())
    }

    fn orphan_error(&self, block: usize) {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "EXT4-fs error ({}): ext4_init_orphan_info: orphan file block {block}: bad magic or checksum",
            super::sb_state::uuid_string(&self.superblock)
        );
    }

    /// `s_last_orphan`, through the journal when it runs.
    async fn set_last_orphan(&self, ino: u32) -> Result<(), FsError> {
        let _allocation = self.allocation_lock.lock().await;
        let mut bytes = [0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        bytes[LAST_ORPHAN..LAST_ORPHAN + 4].copy_from_slice(&ino.to_le_bytes());
        metadata_csum::write_superblock_checksum(&self.superblock, &mut bytes)
            .ok_or(FsError::InvalidData)?;
        self.write_byte_range(1024, &bytes).await
    }

    pub(crate) async fn last_orphan(&self) -> Result<u32, FsError> {
        let mut bytes = [0u8; 4];
        self.read_byte_range(1024 + LAST_ORPHAN as u64, &mut bytes)
            .await?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Rewrite orphan file entry `idx` to `value`, with its block's checksum.
    async fn write_orphan_entry(&self, idx: u32, value: u32) -> Result<(), FsError> {
        let per = self.inodes_per_orphan_block();
        let (block_index, entry) = (idx as usize / per, idx as usize % per);
        let (physical, seed) = {
            let orphans = self.orphans_state.lock();
            (orphans.blocks[block_index], orphans.csum_seed)
        };
        let bs = self.block_size();
        let mut buf = vec![0u8; bs];
        self.read_block(physical, &mut buf).await?;
        buf[entry * 4..entry * 4 + 4].copy_from_slice(&value.to_le_bytes());
        if self.superblock.has_metadata_csum() {
            let csum = self.orphan_block_csum(seed, physical, &buf);
            buf[bs - 4..].copy_from_slice(&csum.to_le_bytes());
        }
        self.write_block(physical, &buf).await
    }

    /// `ext4_orphan_add`. The caller holds `inode_update_lock` and writes
    /// `inode` afterwards (a list entry changes its `i_dtime`).
    pub(crate) async fn orphan_add(&self, ino: u32, inode: &mut Inode) -> Result<(), FsError> {
        if !self.journaling() || self.orphans_state.lock().slots.contains_key(&ino) {
            return Ok(());
        }
        let per = self.inodes_per_orphan_block();
        // `ext4_orphan_file_add`: a block with a free entry.
        let target = {
            let orphans = self.orphans_state.lock();
            orphans.free.iter().position(|&f| f > 0)
        };
        if let Some(block_index) = target {
            let physical = self.orphans_state.lock().blocks[block_index];
            let mut buf = vec![0u8; self.block_size()];
            self.read_block(physical, &mut buf).await?;
            if let Some(entry) = buf[..per * 4].chunks_exact(4).position(|e| e == [0; 4]) {
                let idx = (block_index * per + entry) as u32;
                self.write_orphan_entry(idx, ino).await?;
                let mut orphans = self.orphans_state.lock();
                orphans.free[block_index] -= 1;
                orphans.slots.insert(ino, Slot::File(idx));
                return Ok(());
            }
        }
        // The orphan list.
        let inodes_count = self.superblock.inodes_count;
        if inode.dtime == 0 || inode.dtime > inodes_count {
            inode.dtime = self.last_orphan().await?;
            self.set_last_orphan(ino).await?;
        }
        let mut orphans = self.orphans_state.lock();
        orphans.list.insert(0, ino);
        orphans.slots.insert(ino, Slot::List);
        Ok(())
    }

    /// `ext4_orphan_del`. The caller holds `inode_update_lock` and writes
    /// `inode` afterwards (`i_dtime` is cleared for a list entry).
    pub(crate) async fn orphan_del(&self, ino: u32, inode: &mut Inode) -> Result<(), FsError> {
        let slot = self.orphans_state.lock().slots.remove(&ino);
        match slot {
            None => Ok(()),
            Some(Slot::File(idx)) => {
                self.write_orphan_entry(idx, 0).await?;
                let per = self.inodes_per_orphan_block();
                self.orphans_state.lock().free[idx as usize / per] += 1;
                Ok(())
            }
            Some(Slot::List) => {
                let next = inode.dtime;
                let pos = {
                    let mut orphans = self.orphans_state.lock();
                    let pos = orphans.list.iter().position(|&i| i == ino);
                    if let Some(p) = pos {
                        orphans.list.remove(p);
                    }
                    pos
                };
                match pos {
                    Some(0) | None => self.set_last_orphan(next).await?,
                    Some(p) => {
                        let prev = self.orphans_state.lock().list[p - 1];
                        let mut prev_inode = self.read_inode(prev).await?;
                        prev_inode.dtime = next;
                        self.write_inode(prev, &prev_inode).await?;
                    }
                }
                inode.dtime = 0;
                Ok(())
            }
        }
    }

    /// `ext4_orphan_file_empty`: no slot of the orphan file is in use.
    pub(crate) fn orphan_file_empty(&self) -> bool {
        let per = self.inodes_per_orphan_block() as u32;
        self.orphans_state.lock().free.iter().all(|&f| f == per)
    }

    /// Whether anything is recorded as an orphan on disk.
    pub(crate) async fn orphans_recorded(&self) -> Result<bool, FsError> {
        Ok(self.last_orphan().await? != 0 || !self.orphan_file_empty())
    }

    /// At mount, after the journal is loaded and `setup_super`: `ext4_fill_super`'s
    /// `ext4_orphan_cleanup`, then `ext4_mark_recovery_complete` when
    /// `needs_recovery` (an orphan list, `ORPHAN_PRESENT` or `RECOVER` at
    /// mount, with the journal loaded from a writable device).
    /// `journal_clean`: the log has nothing left to replay.
    ///
    /// A read-only mount of a writable device writes while it does this, as
    /// Linux clears `SB_RDONLY` for its cleanup ("orphan cleanup on readonly
    /// fs"). The writes go through the journal, which is flushed before
    /// writing stops; then `RECOVER` and `ORPHAN_PRESENT` are cleared.
    ///
    /// LINUX-GAP: a filesystem NARF cannot write (its write gate refuses it
    /// for a feature Linux writes) gets no cleanup on a read-only mount, and
    /// keeps `RECOVER` / `ORPHAN_PRESENT` while its orphan file is not
    /// empty, for Linux to finish.
    pub(crate) async fn finish_orphans_at_mount(
        &self,
        needs_recovery: bool,
        journal_clean: bool,
    ) -> Result<(), FsError> {
        use core::sync::atomic::Ordering;
        let ro_mount = self.is_read_only();
        let gate = super::sb_state::rw_refusal(&self.superblock, journal_clean, self.profile);
        let narf_writes = !matches!(gate, Some(super::sb_state::Refusal::Gate(_)));
        let recorded = self.orphans_recorded().await?;
        let open = ro_mount
            && !self.device.is_read_only()
            && (needs_recovery || (recorded && narf_writes));
        if open {
            self.read_only.store(false, Ordering::Release);
            if let Err(error) = self.journal_enable(false).await {
                self.read_only.store(true, Ordering::Release);
                return Err(error);
            }
        }
        let result = async {
            use core::fmt::Write as _;
            let uuid = super::sb_state::uuid_string(&self.superblock);
            let _update = self.inode_update_lock.lock().await;
            // `ext4_orphan_cleanup` returns nothing: what it cannot do is
            // reported (and recorded as an error where Linux records one),
            // and the mount goes on.
            if let Err(error) = self.orphan_cleanup(ro_mount, gate, recorded).await {
                let _ = writeln!(
                    narf_console::Writer,
                    "EXT4-fs ({uuid}): orphan cleanup failed: {error:?}"
                );
            }
            if needs_recovery {
                let _ = writeln!(narf_console::Writer, "EXT4-fs ({uuid}): recovery complete");
            }
            // `ext4_mark_recovery_complete`'s `jbd2_journal_flush`; a
            // read-only mount's cleanup is flushed before writing stops.
            if needs_recovery || open {
                self.journal_flush().await?;
            }
            if needs_recovery && ro_mount {
                self.clear_recovery_flags(narf_writes).await?;
            }
            Ok(())
        }
        .await;
        if open {
            self.journal_disable();
            self.read_only.store(true, Ordering::Release);
        }
        result
    }

    /// The read-only half of `ext4_mark_recovery_complete`: `RECOVER` and
    /// `ORPHAN_PRESENT` off, unless the orphan file still lists an inode,
    /// which is EFSCORRUPTED ("Orphan file not empty on read-only fs") and
    /// fails the mount.
    async fn clear_recovery_flags(&self, narf_writes: bool) -> Result<(), FsError> {
        use super::super::superblock::{incompat, ro_compat};
        use core::fmt::Write as _;
        let mut bytes = [0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        let get =
            |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"));
        if get(&bytes, 0x60) & incompat::RECOVER == 0
            && get(&bytes, 0x64) & ro_compat::ORPHAN_PRESENT == 0
        {
            return Ok(());
        }
        if !self.orphan_file_empty() {
            if !narf_writes {
                return Ok(());
            }
            let _ = writeln!(
                narf_console::Writer,
                "EXT4-fs error ({}): ext4_mark_recovery_complete: Orphan file not empty on read-only fs.",
                super::sb_state::uuid_string(&self.superblock)
            );
            return Err(FsError::Corrupted);
        }
        self.sb_update(|b| {
            let incompat_bits = get(b, 0x60) & !incompat::RECOVER;
            let ro_bits = get(b, 0x64) & !ro_compat::ORPHAN_PRESENT;
            b[0x60..0x64].copy_from_slice(&incompat_bits.to_le_bytes());
            b[0x64..0x68].copy_from_slice(&ro_bits.to_le_bytes());
        })
        .await
    }

    /// Whether the filesystem has an error, recorded at mount or since
    /// (`s_mount_state & EXT4_ERROR_FS`).
    fn has_errors(&self) -> bool {
        self.mount_state & EXT2_ERROR_FS != 0
            || self.errors_seen.load(core::sync::atomic::Ordering::Acquire)
    }

    /// `ext4_orphan_cleanup`, in its order. The caller holds
    /// `inode_update_lock` and, on a read-only mount with something to do,
    /// has made the volume writable. `recorded`: anything was recorded at
    /// mount.
    async fn orphan_cleanup(
        &self,
        ro_mount: bool,
        gate: Option<super::sb_state::Refusal>,
        recorded: bool,
    ) -> Result<(), FsError> {
        use super::sb_state::Refusal;
        use core::fmt::Write as _;
        let uuid = super::sb_state::uuid_string(&self.superblock);
        let file_blocks = self.orphans_state.lock().blocks.len();
        if self.last_orphan().await? == 0 && file_blocks == 0 {
            return Ok(());
        }
        if self.device.is_read_only() {
            let _ = writeln!(
                narf_console::Writer,
                "EXT4-fs ({uuid}): write access unavailable, skipping orphan cleanup"
            );
            return Ok(());
        }
        match gate {
            // `ext4_feature_set_ok(sb, 0)`.
            Some(Refusal::ReadOnlyFeature | Refusal::Unsupported(_)) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "EXT4-fs ({uuid}): Skipping orphan cleanup due to unknown ROCOMPAT features"
                );
                return Ok(());
            }
            // LINUX-GAP: see `finish_orphans_at_mount`.
            Some(Refusal::Gate(why)) => {
                if recorded {
                    let _ = writeln!(
                        narf_console::Writer,
                        "EXT4-fs ({uuid}): skipping orphan cleanup: {why}"
                    );
                }
                return Ok(());
            }
            None => {}
        }
        if self.has_errors() {
            // Not on a read-only mount.
            if self.last_orphan().await? != 0 && !ro_mount {
                let _ = writeln!(
                    narf_console::Writer,
                    "EXT4-fs ({uuid}): Errors on filesystem, clearing orphan list."
                );
                self.set_last_orphan(0).await?;
            }
            return Ok(());
        }
        if ro_mount {
            let _ = writeln!(
                narf_console::Writer,
                "EXT4-fs ({uuid}): orphan cleanup on readonly fs"
            );
        }
        let mut counts = (0u32, 0u32);
        // The list, head first: each release moves `s_last_orphan` on.
        loop {
            let ino = self.last_orphan().await?;
            if ino == 0 {
                break;
            }
            // An error during the cleanup skips the rest.
            if self.has_errors() {
                let _ = self.set_last_orphan(0).await;
                break;
            }
            let Some(inode) = self.orphan_get(ino).await else {
                let _ = self.set_last_orphan(0).await;
                break;
            };
            {
                let mut orphans = self.orphans_state.lock();
                orphans.list.insert(0, ino);
                orphans.slots.insert(ino, Slot::List);
            }
            self.process_orphan(ino, inode, &mut counts).await;
        }
        // Then every slot of the orphan file. A bad one stays.
        let per = self.inodes_per_orphan_block();
        for block_index in 0..file_blocks {
            let physical = self.orphans_state.lock().blocks[block_index];
            let mut buf = vec![0u8; self.block_size()];
            self.read_block(physical, &mut buf).await?;
            for entry in 0..per {
                let at = entry * 4;
                let ino = u32::from_le_bytes(buf[at..at + 4].try_into().expect("4 bytes"));
                if ino == 0 {
                    continue;
                }
                let Some(inode) = self.orphan_get(ino).await else {
                    continue;
                };
                let idx = (block_index * per + entry) as u32;
                self.orphans_state.lock().slots.insert(ino, Slot::File(idx));
                self.process_orphan(ino, inode, &mut counts).await;
            }
        }
        let plural = |n: u32| if n == 1 { "" } else { "s" };
        if counts.0 != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "EXT4-fs ({uuid}): {} orphan inode{} deleted",
                counts.0,
                plural(counts.0)
            );
        }
        if counts.1 != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "EXT4-fs ({uuid}): {} truncate{} cleaned up",
                counts.1,
                plural(counts.1)
            );
        }
        Ok(())
    }

    /// `ext4_orphan_get`: the inode `ino` names, when it is a valid orphan:
    /// in range, allocated in its group's inode bitmap, readable, truncatable
    /// when it still has links, and with an in-range `NEXT_ORPHAN`. Anything
    /// else is "bad orphan inode", a filesystem error.
    async fn orphan_get(&self, ino: u32) -> Option<Inode> {
        let max = self.superblock.inodes_count;
        let found = if ino < self.superblock.first_ino() || ino > max {
            None
        } else {
            match self.inode_bit_set(ino).await {
                // `ext4_read_inode_bitmap` reported it.
                Err(_) => return None,
                Ok(false) => None,
                Ok(true) => match self.read_inode(ino).await {
                    Err(error) => {
                        self.fs_error(super::sb_state::ErrorSite {
                            func: "ext4_orphan_get",
                            ino,
                            block: 0,
                            errno: super::extent_write::fs_errno(&error),
                        })
                        .await;
                        return None;
                    }
                    Ok(inode) => {
                        let truncatable = inode.mode & 0xF000 == 0x8000
                            || inode.is_dir()
                            || (inode.is_symlink()
                                && !inode.is_fast_symlink(self.block_size() as u32));
                        if (inode.links_count != 0 && !truncatable) || inode.dtime > max {
                            None
                        } else {
                            Some(inode)
                        }
                    }
                },
            }
        };
        // "bad orphan inode".
        if found.is_none() {
            self.fs_error(super::sb_state::ErrorSite {
                func: "ext4_orphan_get",
                ino,
                block: 0,
                errno: 0,
            })
            .await;
        }
        found
    }

    /// Whether inode `ino` is allocated in its group's inode bitmap
    /// (`ext4_read_inode_bitmap`: an `INODE_UNINIT` group has none).
    async fn inode_bit_set(&self, ino: u32) -> Result<bool, FsError> {
        let per_group = self.superblock.inodes_per_group;
        let group = ((ino - 1) / per_group) as usize;
        let bit = (ino - 1) % per_group;
        if super::uninit::has_group_desc_csum(&self.superblock)
            && self.current_group_desc(group).await?.flags
                & super::super::group_desc::BG_INODE_UNINIT
                != 0
        {
            return Ok(false);
        }
        let bitmap = self
            .group_descs
            .get(group)
            .ok_or(FsError::Corrupted)?
            .inode_bitmap;
        let mut buf = vec![0u8; self.block_size()];
        self.read_block(bitmap, &mut buf).await?;
        self.verify_bitmap(group, super::BitmapKind::Inode, &buf)
            .await?;
        Ok(buf[(bit / 8) as usize] & (1 << (bit % 8)) != 0)
    }

    /// One orphan (`ext4_process_orphan`). No links: delete it (`iput`).
    /// Links: an interrupted truncate, finished to `i_size`
    /// (`ext4_truncate`). Either way it leaves the record. A failure is a
    /// filesystem error, as `ext4_std_error` makes it, which ends the walk
    /// of the list.
    async fn process_orphan(&self, ino: u32, mut inode: Inode, counts: &mut (u32, u32)) {
        let truncate = inode.links_count != 0;
        if truncate {
            counts.1 += 1;
        } else {
            counts.0 += 1;
        }
        let result = async {
            if truncate {
                self.zero_tail_past_eof(&inode).await?;
                let first = inode.size.div_ceil(self.block_size() as u64);
                self.truncate_inode_from(ino, &mut inode, first).await?;
                self.orphan_del(ino, &mut inode).await?;
                self.write_inode(ino, &inode).await
            } else {
                self.evict_inode(ino, &mut inode).await
            }
        }
        .await;
        if let Err(error) = result {
            {
                let mut orphans = self.orphans_state.lock();
                orphans.slots.remove(&ino);
                orphans.list.retain(|&i| i != ino);
            }
            self.fs_error(super::sb_state::ErrorSite {
                func: "ext4_orphan_cleanup",
                ino,
                block: 0,
                errno: super::extent_write::fs_errno(&error),
            })
            .await;
        }
    }

    /// `ext4_block_truncate_page` for a regular file: zero the rest of the
    /// block holding EOF, so the bytes a truncate cut cannot come back.
    async fn zero_tail_past_eof(&self, inode: &Inode) -> Result<(), FsError> {
        let bs = self.block_size() as u64;
        let tail = inode.size % bs;
        if tail == 0
            || inode.mode & 0xF000 != 0x8000
            || inode.flags & super::super::inode::I_FLAGS_INLINE_DATA != 0
        {
            return Ok(());
        }
        let physical = self.map_block(inode, inode.size / bs).await?;
        if physical == 0 {
            return Ok(());
        }
        let zeros = vec![0u8; (bs - tail) as usize];
        self.write_data_range(physical * bs + tail, &zeros).await
    }
}
