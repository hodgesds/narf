//! Mounted btrfs volume: block I/O, chunk-map bootstrap, logical reads.
//!
//! Read call chain mirrors `/usr/src/linux/fs/btrfs`: `open_ctree` reads the
//! superblock, bootstraps the chunk map from `sys_chunk_array`, walks the chunk
//! tree to complete the logical→physical map, then reads the root tree to find
//! the default FS tree. Every read above the superblock is by logical address
//! and goes through [`BtrfsVolume::read_logical`].
//!
//! Mutable metadata (the chunk map, the tree roots, the live superblock) lives
//! behind one `IrqSafeSpinLock`. The lock is **never** held across a block-I/O
//! `await`: readers snapshot the scalars they need (a physical offset, a root
//! address), drop the guard, then do I/O. Holding a spinlock across
//! `poll_blocking` would wedge the volume under an IRQ-driven backend.

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockError, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_filesystem::FsError;
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use alloc::string::String;

use crate::chunk::ChunkMap;
use crate::format::{self, BtrfsKey, Superblock};
use crate::inode::InodeItem;

/// Selects which subvolume a `mount -t btrfs` request roots at.
#[derive(Clone, Debug)]
pub enum Subvol {
    /// `subvolid=N` — a subvolume root objectid.
    Id(u64),
    /// `subvol=PATH` — a path from the top-level FS tree to a subvolume root.
    Name(String),
}

/// Volume-owned scratch DMA buffer, serialised across all block submissions.
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

/// Mutable volume metadata guarded by one lock (never held across I/O).
#[derive(Debug)]
struct VolState {
    /// The live superblock. Its tree roots and `generation` advance on a COW
    /// write; the read path snapshots the roots it needs.
    superblock: Superblock,
    /// Physical offset of the superblock copy selected at mount. Reads use this
    /// until the next commit rewrites every mirror and heals the primary.
    superblock_source: u64,
    /// Completed logical→physical chunk map.
    chunk_map: ChunkMap,
    /// Selected FS-tree objectid and live root node (logical address + level).
    fs_tree_id: u64,
    fs_tree_root: u64,
    fs_tree_level: u8,
    /// On-disk `btrfs_root_item.flags` for the selected tree.
    fs_tree_flags: u64,
    /// Cached root-directory inode (objectid 256), for the sync `root()` path.
    root_inode: Option<InodeItem>,
    /// False when the selected root item carries `BTRFS_ROOT_SUBVOL_RDONLY`.
    writable_fs_tree: bool,
    /// Highest logical address handed out by a write this session. Seeds the
    /// next write's allocator so successive writes don't collide before the
    /// extent tree records the allocations. Reset to 0 at mount.
    alloc_floor: u64,
}

/// A mounted btrfs filesystem.
#[derive(Debug)]
pub struct BtrfsVolume<B: BlockDevice> {
    pub device: Arc<B>,
    pub self_weak: Weak<BtrfsVolume<B>>,
    /// Immutable geometry (copied out of the superblock so hot reads need no
    /// lock).
    magic: u64,
    nodesize: u32,
    sectorsize: u32,
    total_bytes: u64,
    /// On-disk metadata/data checksum algorithm selected by the superblock.
    csum_type: u16,
    /// Enforce per-node/superblock checksum verification.
    verify_checksums: bool,
    io: Mutex<VolumeIo>,
    device_capacity: u64,
    state: IrqSafeSpinLock<VolState>,
}

impl<B: BlockDevice + 'static> BtrfsVolume<B> {
    // ── Geometry accessors (lock-free) ─────────────────────────────

    pub fn magic(&self) -> u64 {
        self.magic
    }

    pub fn nodesize(&self) -> usize {
        self.nodesize as usize
    }

    pub fn sectorsize(&self) -> u32 {
        self.sectorsize
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn verify_checksums(&self) -> bool {
        self.verify_checksums
    }

    pub(crate) fn csum_type(&self) -> u16 {
        self.csum_type
    }

    /// All checksum algorithms accepted at mount are emitted by the COW writer.
    /// A subvolume marked read-only in its root item remains read-only.
    pub(crate) fn supports_writes(&self) -> bool {
        self.state.lock().writable_fs_tree
    }

    /// Objectid of the currently mounted fs tree (`5` for the top-level tree).
    pub(crate) fn fs_tree_id(&self) -> u64 {
        self.state.lock().fs_tree_id
    }

    /// On-disk `btrfs_root_item.flags` for the mounted subvolume.
    pub(crate) fn fs_tree_flags(&self) -> u64 {
        self.state.lock().fs_tree_flags
    }

    // ── State snapshots (brief lock, no I/O) ───────────────────────

    /// Currently mounted fs-tree/subvolume root `(logical, level)`.
    pub fn fs_tree_root(&self) -> (u64, u8) {
        let g = self.state.lock();
        (g.fs_tree_root, g.fs_tree_level)
    }

    /// Root-tree root `(logical, level)` from the live superblock.
    pub fn root_tree_root(&self) -> (u64, u8) {
        let g = self.state.lock();
        (g.superblock.root, g.superblock.root_level)
    }

    /// Number of chunks currently in the map.
    pub fn chunk_map_len(&self) -> usize {
        self.state.lock().chunk_map.len()
    }

    /// Translate a logical address to a physical offset via the chunk map.
    pub fn map_logical(&self, logical: u64) -> Result<u64, FsError> {
        self.state.lock().chunk_map.map_logical(logical)
    }

    /// Translate a logical address to its primary and optional single-device
    /// DUP copy.
    pub(crate) fn map_logical_copies(&self, logical: u64) -> Result<(u64, Option<u64>), FsError> {
        self.state.lock().chunk_map.map_logical_copies(logical)
    }

    /// Snapshot of the live superblock (for statfs / write bookkeeping).
    pub fn superblock(&self) -> Superblock {
        self.state.lock().superblock.clone()
    }

    // ── Physical / logical reads ───────────────────────────────────

    /// Read `dst.len()` bytes at physical device byte offset `offset`.
    async fn read_physical(&self, offset: u64, dst: &mut [u8]) -> Result<(), FsError> {
        read_exact_from(&*self.device, &self.io, self.device_capacity, offset, dst).await
    }

    /// Read `len` bytes at btrfs *logical* address `logical`. The range must lie
    /// within a single chunk (true for any node or single extent read).
    pub async fn read_logical(&self, logical: u64, len: usize) -> Result<Vec<u8>, FsError> {
        // Resolve both physical copies under the lock, then release it before
        // I/O. A plain logical read can retry transport failure; callers with a
        // checksum (notably read_node and the data-csum path) retry corruption.
        let (physical, mirror) = self.map_logical_copies(logical)?;
        let mut buf = vec![0u8; len];
        if let Err(primary_error) = self.read_physical(physical, &mut buf).await {
            let Some(mirror) = mirror else {
                return Err(primary_error);
            };
            self.read_physical(mirror, &mut buf).await?;
        }
        Ok(buf)
    }

    /// Read a logical range from the first physical copy whose bytes match the
    /// supplied on-disk data checksum. Unlike [`Self::read_logical`], checksum
    /// failure is part of copy selection, so a readable-but-corrupt primary DUP
    /// stripe falls back to its mirror.
    pub(crate) async fn read_logical_checked(
        &self,
        logical: u64,
        len: usize,
        stored: &[u8],
    ) -> Result<Vec<u8>, FsError> {
        let (primary, mirror) = self.map_logical_copies(logical)?;
        let mut buf = vec![0u8; len];
        for physical in [Some(primary), mirror].into_iter().flatten() {
            if self.read_physical(physical, &mut buf).await.is_err() {
                continue;
            }
            let digest = crate::checksum::digest(self.csum_type, &buf)?;
            if digest.get(..stored.len()) == Some(stored) {
                return Ok(buf);
            }
        }
        Err(FsError::InvalidData)
    }

    /// Read one b-tree node (a `nodesize` block) at logical address `logical`,
    /// validating its self-recorded `bytenr` and, when
    /// [`verify_checksums`](Self::verify_checksums) is set, its checksum.
    pub async fn read_node(&self, logical: u64) -> Result<Vec<u8>, FsError> {
        let (primary, mirror) = self.map_logical_copies(logical)?;
        let mut buf = vec![0u8; self.nodesize()];
        for physical in [Some(primary), mirror].into_iter().flatten() {
            if self.read_physical(physical, &mut buf).await.is_err() {
                continue;
            }
            if format::le64(&buf, 48)? != logical {
                continue;
            }
            if self.verify_checksums
                && !crate::checksum::verify(
                    self.csum_type,
                    &buf[format::CSUM_SIZE..],
                    &buf[..format::CSUM_SIZE],
                )?
            {
                continue;
            }
            return Ok(buf);
        }
        Err(FsError::InvalidData)
    }

    // ── Mount ──────────────────────────────────────────────────────

    /// Mount with checksum verification enabled.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        Self::mount_opts(device, domain, true).await
    }

    /// Mount and, if a subvolume is selected, root the volume at that subvolume
    /// instead of the default `FS_TREE`.
    pub async fn mount_subvol(
        device: Arc<B>,
        domain: DomainId,
        verify_checksums: bool,
        subvol: Option<Subvol>,
    ) -> Result<Arc<Self>, FsError> {
        let volume = Self::mount_opts(device, domain, verify_checksums).await?;
        if let Some(sel) = subvol {
            volume.switch_to_subvol(&sel).await?;
        }
        Ok(volume)
    }

    /// Re-root the volume at the named/identified subvolume: resolve its tree in
    /// the root tree and cache its root directory inode. Subsequent `root()`
    /// calls start there.
    pub async fn switch_to_subvol(&self, sel: &Subvol) -> Result<(), FsError> {
        let (root_tree, _) = self.root_tree_root();
        let (subvol_id, subvol_root, subvol_level, subvol_flags) = match sel {
            Subvol::Id(n) => {
                let (bytenr, level, flags) =
                    crate::roots::find_root_with_flags(self, root_tree, *n).await?;
                (*n, bytenr, level, flags)
            }
            Subvol::Name(path) => self.resolve_subvol_path(root_tree, path).await?,
        };
        let root_inode = self
            .load_inode_in(subvol_root, format::FIRST_FREE_OBJECTID)
            .await?;
        let mut g = self.state.lock();
        g.fs_tree_id = subvol_id;
        g.fs_tree_root = subvol_root;
        g.fs_tree_level = subvol_level;
        g.fs_tree_flags = subvol_flags;
        g.root_inode = Some(root_inode);
        g.writable_fs_tree = subvol_flags & format::ROOT_SUBVOL_RDONLY == 0;
        Ok(())
    }

    /// Resolve a `subvol=PATH` from the top-level FS_TREE. Ordinary directory
    /// components stay in the current tree; a ROOT_ITEM component enters that
    /// subvolume at inode 256. The final component itself must be a subvolume.
    async fn resolve_subvol_path(
        &self,
        root_tree: u64,
        path: &str,
    ) -> Result<(u64, u64, u8, u64), FsError> {
        let mut components = path.split('/').peekable();
        let mut dir_ino = format::FIRST_FREE_OBJECTID;
        let (mut tree_root, _) = crate::roots::find_fs_tree(self, root_tree).await?;

        while let Some(name) = components.next() {
            if name.is_empty() || name == "." || name == ".." {
                return Err(FsError::Unsupported);
            }
            let key = BtrfsKey::new(
                dir_ino,
                format::DIR_ITEM_KEY,
                u64::from(crate::checksum::name_hash(name.as_bytes())),
            );
            let body = crate::btree::find_item(self, tree_root, &key)
                .await?
                .ok_or(FsError::NotFound)?;
            let entry = crate::dir::decode_dir_items(&body)?
                .into_iter()
                .find(|entry| entry.name == name)
                .ok_or(FsError::NotFound)?;

            match entry.location.item_type {
                format::ROOT_ITEM_KEY => {
                    let subvol_id = entry.location.objectid;
                    let (bytenr, level, flags) =
                        crate::roots::find_root_with_flags(self, root_tree, subvol_id).await?;
                    if components.peek().is_none() {
                        return Ok((subvol_id, bytenr, level, flags));
                    }
                    tree_root = bytenr;
                    dir_ino = format::FIRST_FREE_OBJECTID;
                }
                format::INODE_ITEM_KEY if components.peek().is_some() => {
                    let inode = self
                        .load_inode_in(tree_root, entry.location.objectid)
                        .await?;
                    if !inode.is_dir() {
                        return Err(FsError::NotFound);
                    }
                    dir_ino = entry.location.objectid;
                }
                _ => return Err(FsError::NotFound),
            }
        }
        Err(FsError::NotFound)
    }

    /// Mount, optionally disabling checksum verification (test bring-up only).
    pub async fn mount_opts(
        device: Arc<B>,
        domain: DomainId,
        verify_checksums: bool,
    ) -> Result<Arc<Self>, FsError> {
        let logical = device.logical_block_size() as usize;
        if !(512..=4096).contains(&logical) || !logical.is_power_of_two() {
            return Err(FsError::Unsupported);
        }
        let capacity = device
            .capacity_blocks()
            .checked_mul(logical as u64)
            .ok_or(FsError::InvalidData)?;
        if capacity < format::SUPERBLOCK_OFFSET + format::SUPERBLOCK_SIZE as u64 {
            return Err(FsError::InvalidData);
        }

        let dma = alloc_coherent(logical, domain).map_err(|_| FsError::Io(BlockError::IOError))?;
        let io = Mutex::new(VolumeIo {
            cap: register_with_cap(dma),
            block_size: logical,
        });

        // Validate every superblock copy that fits, then choose the newest
        // generation. On a tie the earlier mirror wins, so a healthy primary
        // remains preferred. Unsupported feature sets are reported distinctly
        // when no usable copy remains.
        let mut selected: Option<(u64, Vec<u8>, Superblock)> = None;
        let mut saw_unsupported = false;
        for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
            if offset + format::SUPERBLOCK_SIZE as u64 > capacity {
                continue;
            }
            let mut candidate = vec![0u8; format::SUPERBLOCK_SIZE];
            if read_exact_from(&*device, &io, capacity, offset, &mut candidate)
                .await
                .is_err()
            {
                continue;
            }
            if format::le64(&candidate, format::SUPERBLOCK_BYTENR_OFFSET) != Ok(offset) {
                continue;
            }
            let candidate_csum = match Superblock::checksum_type(&candidate) {
                Ok(kind) if crate::checksum::is_supported(kind) => kind,
                Ok(_) => {
                    saw_unsupported = true;
                    continue;
                }
                Err(_) => continue,
            };
            if verify_checksums {
                match crate::checksum::verify(
                    candidate_csum,
                    &candidate[format::CSUM_SIZE..format::SUPERBLOCK_SIZE],
                    &candidate[..format::CSUM_SIZE],
                ) {
                    Ok(true) => {}
                    _ => continue,
                }
            }
            let decoded = match Superblock::decode(&candidate) {
                Ok(sb) if sb.total_bytes <= capacity => sb,
                Ok(_) => continue,
                Err(FsError::Unsupported) => {
                    saw_unsupported = true;
                    continue;
                }
                Err(_) => continue,
            };
            let replace = selected
                .as_ref()
                .is_none_or(|(_, _, current)| decoded.generation > current.generation);
            if replace {
                selected = Some((offset, candidate, decoded));
            }
        }
        let (superblock_source, _raw, superblock) = match selected {
            Some(candidate) => candidate,
            None if saw_unsupported => return Err(FsError::Unsupported),
            None => return Err(FsError::InvalidData),
        };
        let csum_type = superblock.csum_type;

        // Seed the chunk map so the chunk tree is reachable by logical address.
        let seed = ChunkMap::seed_from_sys_array(&superblock.sys_chunk_array)?;
        seed.map_logical(superblock.chunk_root)?;

        let volume = Arc::new_cyclic(|self_weak| BtrfsVolume {
            device,
            self_weak: self_weak.clone(),
            magic: superblock.magic,
            nodesize: superblock.nodesize,
            sectorsize: superblock.sectorsize,
            total_bytes: superblock.total_bytes,
            csum_type,
            verify_checksums,
            io,
            device_capacity: capacity,
            state: IrqSafeSpinLock::new(VolState {
                superblock,
                superblock_source,
                chunk_map: seed,
                fs_tree_id: format::FS_TREE_OBJECTID,
                fs_tree_root: 0,
                fs_tree_level: 0,
                fs_tree_flags: 0,
                root_inode: None,
                writable_fs_tree: true,
                alloc_floor: 0,
            }),
        });

        // Complete the chunk map and locate the FS tree now that the volume can
        // read nodes.
        volume.finish_mount().await?;
        Ok(volume)
    }

    /// Walk the chunk tree to complete the logical→physical map, then read the
    /// root tree to find the default FS tree. Requires the b-tree engine.
    async fn finish_mount(self: &Arc<Self>) -> Result<(), FsError> {
        let (chunk_root, root_tree, root_level) = {
            let g = self.state.lock();
            (
                g.superblock.chunk_root,
                g.superblock.root,
                g.superblock.root_level,
            )
        };
        let _ = root_level;

        // 1. Collect every CHUNK_ITEM from the chunk tree and add it to the map.
        //    Chunk items are keyed (FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM, logical).
        let chunks = crate::btree::collect_for(
            self,
            chunk_root,
            format::FIRST_FREE_OBJECTID, // 256 == BTRFS_FIRST_CHUNK_TREE_OBJECTID
            format::CHUNK_ITEM_KEY,
        )
        .await?;
        {
            let mut g = self.state.lock();
            for (key, body) in &chunks {
                g.chunk_map.insert_chunk_item(key.offset, body)?;
            }
        }

        // 2. Find the FS_TREE root item (5, ROOT_ITEM, *) in the root tree and
        //    extract its root node address + level.
        let (fs_root, fs_level, fs_flags) =
            crate::roots::find_root_with_flags(self, root_tree, format::FS_TREE_OBJECTID).await?;
        {
            let mut g = self.state.lock();
            g.fs_tree_root = fs_root;
            g.fs_tree_level = fs_level;
            g.fs_tree_flags = fs_flags;
            g.writable_fs_tree = fs_flags & format::ROOT_SUBVOL_RDONLY == 0;
        }

        // 2b. Replay a pending fsync tree-log (crash recovery) before anything
        //     reads the fs tree. The replay commits into the fs tree and publishes
        //     the recovered roots via `commit_roots`, so later steps see them.
        if self.superblock().log_root != 0 && !self.supports_writes() {
            // Replay mutates the fs tree and superblock, so it is permitted only
            // when the selected tree is writable.
            return Err(FsError::Unsupported);
        }
        crate::write::replay_log(self).await?;

        // 3. Cache the root-directory inode so the synchronous `root()` path has
        //    it without I/O.
        let root_inode = self.load_inode(format::FIRST_FREE_OBJECTID).await?;
        self.state.lock().root_inode = Some(root_inode);

        // 4. Honor the on-disk default subvolume, if one is set to a subvolume
        //    other than FS_TREE (an explicit `subvolid=`/`subvol=` overrides this
        //    afterwards in `mount_subvol`).
        if let Some(id) = self.default_subvol_id(root_tree).await? {
            if id != format::FS_TREE_OBJECTID {
                self.switch_to_subvol(&Subvol::Id(id)).await?;
            }
        }
        Ok(())
    }

    /// The objectid of the on-disk default subvolume, from the root tree's
    /// `ROOT_TREE_DIR` "default" `DIR_ITEM`. `None` if unset.
    async fn default_subvol_id(&self, root_tree: u64) -> Result<Option<u64>, FsError> {
        let key = BtrfsKey::new(
            format::ROOT_TREE_DIR_OBJECTID,
            format::DIR_ITEM_KEY,
            u64::from(crate::checksum::name_hash(b"default")),
        );
        let body = match crate::btree::find_item(self, root_tree, &key).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let entry = crate::dir::decode_dir_items(&body)?
            .into_iter()
            .find(|e| e.name == "default");
        match entry {
            Some(e) if e.location.item_type == format::ROOT_ITEM_KEY => {
                Ok(Some(e.location.objectid))
            }
            _ => Ok(None),
        }
    }

    /// Read and decode the inode item `(ino, INODE_ITEM, 0)` from the default
    /// FS tree.
    pub async fn load_inode(&self, ino: u64) -> Result<InodeItem, FsError> {
        let (fs_root, _) = self.fs_tree_root();
        self.load_inode_in(fs_root, ino).await
    }

    /// Read and decode the inode item `(ino, INODE_ITEM, 0)` from the tree
    /// rooted at logical `tree_root` (a subvolume's fs tree, or the default).
    pub async fn load_inode_in(&self, tree_root: u64, ino: u64) -> Result<InodeItem, FsError> {
        if tree_root == 0 {
            return Err(FsError::NotFound);
        }
        let key = BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0);
        let body = crate::btree::find_item(self, tree_root, &key)
            .await?
            .ok_or(FsError::NotFound)?;
        InodeItem::decode(&body)
    }

    /// Cached root-directory inode (available after mount completes).
    pub fn root_inode(&self) -> Option<InodeItem> {
        self.state.lock().root_inode
    }

    /// The session allocation floor — writes seed their allocator from at least
    /// this to avoid colliding with earlier same-session writes.
    pub fn alloc_floor(&self) -> u64 {
        self.state.lock().alloc_floor
    }

    /// Raise the session allocation floor after a write.
    pub fn set_alloc_floor(&self, v: u64) {
        let mut g = self.state.lock();
        g.alloc_floor = g.alloc_floor.max(v);
    }

    // ── Writes (Phase 7 COW path) ──────────────────────────────────

    /// Write `src` at physical device byte offset `offset` (block-granular,
    /// read-modify-write for partial leading/trailing blocks).
    async fn write_physical(&self, offset: u64, src: &[u8]) -> Result<(), FsError> {
        write_exact_to(&*self.device, &self.io, self.device_capacity, offset, src).await
    }

    /// Write `src` at btrfs *logical* address `logical` (single-chunk range).
    pub async fn write_logical(&self, logical: u64, src: &[u8]) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        self.write_logical_unchecked(logical, src).await
    }

    /// Root-tree transaction write used only to change the mounted subvolume's
    /// own read-only flag. Clearing that flag must be able to commit while the
    /// current live subvolume is still read-only; ordinary mutations continue
    /// to go through [`Self::write_logical`] and its writeability check.
    pub(crate) async fn write_logical_root_admin(
        &self,
        logical: u64,
        src: &[u8],
    ) -> Result<(), FsError> {
        self.write_logical_unchecked(logical, src).await
    }

    async fn write_logical_unchecked(&self, logical: u64, src: &[u8]) -> Result<(), FsError> {
        let physical = self.map_logical(logical)?;
        // The whole range must stay inside one chunk: the last byte must map to
        // a physically-contiguous offset.
        if src.len() > 1 {
            let last = self.map_logical(logical + src.len() as u64 - 1)?;
            if last != physical + src.len() as u64 - 1 {
                return Err(FsError::NoSpace);
            }
        }
        self.write_physical(physical, src).await
    }

    /// Overwrite every superblock copy with `raw` (a full 4096-byte block whose
    /// `bytenr`/checksum are those of the primary at 64 KiB) and flush.
    ///
    /// btrfs keeps up to three copies (`btrfs_sb_offset`): the primary at 64 KiB,
    /// then mirrors at 64 MiB and 256 GiB, each written only when it fits within
    /// the filesystem. Every copy records its own physical offset in `bytenr@48`
    /// (so its checksum differs), and a real kernel picks the copy with the
    /// newest generation — so all copies must advance together on each commit or
    /// `btrfs check` reports a mismatch. The primary is written last, after its
    /// mirrors are durable, so a torn write can never leave the newest primary
    /// pointing at trees an out-of-date mirror would supersede on recovery.
    pub async fn write_superblock(&self, raw: &[u8]) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        self.write_superblock_unchecked(raw).await
    }

    /// Superblock half of [`Self::write_logical_root_admin`].
    pub(crate) async fn write_superblock_root_admin(&self, raw: &[u8]) -> Result<(), FsError> {
        self.write_superblock_unchecked(raw).await
    }

    async fn write_superblock_unchecked(&self, raw: &[u8]) -> Result<(), FsError> {
        if raw.len() != format::SUPERBLOCK_SIZE {
            return Err(FsError::InvalidData);
        }
        let limit = self.total_bytes.min(self.device_capacity);
        // Mirrors first (highest offset to lowest), primary (offset 0) last.
        for &offset in format::SUPERBLOCK_MIRROR_OFFSETS.iter().rev() {
            if offset != format::SUPERBLOCK_OFFSET
                && offset + format::SUPERBLOCK_SIZE as u64 > limit
            {
                continue; // this mirror doesn't fit in the filesystem
            }
            let mut copy;
            let block: &[u8] = if offset == format::SUPERBLOCK_OFFSET {
                raw
            } else {
                copy = raw.to_vec();
                let b = format::SUPERBLOCK_BYTENR_OFFSET;
                copy[b..b + 8].copy_from_slice(&offset.to_le_bytes());
                crate::checksum::stamp_block(self.csum_type, &mut copy)?;
                &copy
            };
            self.write_physical(offset, block).await?;
            self.device.flush().await; // each copy durable before the next
        }
        self.state.lock().superblock_source = format::SUPERBLOCK_OFFSET;
        Ok(())
    }

    /// Flush the backing device.
    pub async fn flush(&self) {
        self.device.flush().await;
    }

    /// Read the selected raw superblock and normalize it to primary-copy form.
    /// Transaction code can therefore heal a damaged primary without knowing
    /// which mirror supplied the mounted generation.
    pub async fn read_raw_superblock(&self) -> Result<Vec<u8>, FsError> {
        let source = self.state.lock().superblock_source;
        let mut raw = vec![0u8; format::SUPERBLOCK_SIZE];
        self.read_physical(source, &mut raw).await?;
        if source != format::SUPERBLOCK_OFFSET {
            let at = format::SUPERBLOCK_BYTENR_OFFSET;
            raw[at..at + 8].copy_from_slice(&format::SUPERBLOCK_OFFSET.to_le_bytes());
            crate::checksum::stamp_block(self.csum_type, &mut raw)?;
        }
        Ok(raw)
    }

    /// Clear the cached superblock's log-root pointer after a tree-log has been
    /// replayed and the on-disk pointer zeroed.
    pub fn clear_log_root(&self) {
        let mut g = self.state.lock();
        g.superblock.log_root = 0;
        g.superblock.log_root_level = 0;
    }

    /// After a COW commit, publish the new roots into the live volume so
    /// subsequent reads through this handle observe the write.
    pub(crate) fn commit_roots(
        &self,
        new_root_tree: u64,
        new_fs_root: u64,
        new_fs_level: u8,
        new_generation: u64,
        new_fs_tree_flags: Option<u64>,
    ) {
        let mut g = self.state.lock();
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
        g.fs_tree_root = new_fs_root;
        g.fs_tree_level = new_fs_level;
        if let Some(flags) = new_fs_tree_flags {
            g.fs_tree_flags = flags;
            g.writable_fs_tree = flags & format::ROOT_SUBVOL_RDONLY == 0;
        }
    }

    /// Register a freshly-allocated chunk's `logical→physical` mapping so writes
    /// and reads can reach it (used by the chunk-growth path).
    pub fn add_chunk_mapping(&self, logical: u64, length: u64, devid: u64, physical: u64) {
        self.state
            .lock()
            .chunk_map
            .add_entry(logical, length, devid, physical);
    }

    /// After a chunk-growth commit, publish the new chunk-tree + root-tree roots
    /// and generation into the live superblock.
    pub fn commit_chunk_root(&self, new_chunk_root: u64, new_root_tree: u64, new_generation: u64) {
        let mut g = self.state.lock();
        g.superblock.chunk_root = new_chunk_root;
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
    }
}

/// Write `src` at physical byte offset `offset`, one logical block at a time,
/// reading-modifying-writing any partial leading/trailing block.
async fn write_exact_to<B: BlockDevice + 'static>(
    device: &B,
    io: &Mutex<VolumeIo>,
    limit: u64,
    offset: u64,
    src: &[u8],
) -> Result<(), FsError> {
    let end = offset
        .checked_add(src.len() as u64)
        .ok_or(FsError::InvalidData)?;
    if end > limit {
        return Err(FsError::InvalidData);
    }
    let mut done = 0usize;
    while done < src.len() {
        let absolute = offset + done as u64;
        let guard = io.lock().await;
        let block_size = guard.block_size;
        let lba = absolute / block_size as u64;
        let in_block = (absolute % block_size as u64) as usize;
        let copy = (src.len() - done).min(block_size - in_block);
        let partial = in_block != 0 || copy < block_size;

        // For a partial block, fetch existing contents first so untouched bytes
        // are preserved.
        if partial {
            let read = BlockRequest {
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
            device.submit(read).await.result.map_err(FsError::Io)?;
        }

        let buffer = guard
            .buffer()
            .ok_or(FsError::Io(BlockError::PermissionDenied))?;
        // SAFETY: `guard` serialises all submissions on this registered coherent
        // buffer of `block_size` bytes; we hold a strong Arc for the copy.
        let dst = unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr(), block_size) };
        dst[in_block..in_block + copy].copy_from_slice(&src[done..done + copy]);

        let write = BlockRequest {
            op: BlockOp::Write { fua: false },
            lba,
            blocks: 1,
            buffer: guard
                .cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        device.submit(write).await.result.map_err(FsError::Io)?;
        done += copy;
        drop(guard);
    }
    Ok(())
}

/// Read `dst.len()` bytes at physical byte offset `offset`, one logical block at
/// a time through the volume's serialised scratch buffer. Copied from the
/// squashfs driver's byte-range reader.
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
        // SAFETY: `guard` serialises all submissions on this registered coherent
        // buffer, which is `block_size` bytes and stays registered until the
        // volume drops.
        let source = unsafe { core::slice::from_raw_parts(buffer.as_ptr(), block_size) };
        dst[done..done + copy].copy_from_slice(&source[in_block..in_block + copy]);
        done += copy;
        drop(guard);
    }
    Ok(())
}
