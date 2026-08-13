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
    /// `subvol=NAME` — a single-component name under the default subvolume root.
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
    /// Completed logical→physical chunk map.
    chunk_map: ChunkMap,
    /// Default FS_TREE root node (logical address + level).
    fs_tree_root: u64,
    fs_tree_level: u8,
    /// Cached root-directory inode (objectid 256), for the sync `root()` path.
    root_inode: Option<InodeItem>,
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
    /// Enforce per-node/superblock CRC32C verification.
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

    // ── State snapshots (brief lock, no I/O) ───────────────────────

    /// Default FS_TREE root `(logical, level)`.
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
        // Resolve the physical offset under the lock, then release it before I/O.
        let physical = self.map_logical(logical)?;
        let mut buf = vec![0u8; len];
        self.read_physical(physical, &mut buf).await?;
        Ok(buf)
    }

    /// Read one b-tree node (a `nodesize` block) at logical address `logical`,
    /// validating its self-recorded `bytenr` and, when
    /// [`verify_checksums`](Self::verify_checksums) is set, its CRC32C.
    pub async fn read_node(&self, logical: u64) -> Result<Vec<u8>, FsError> {
        let buf = self.read_logical(logical, self.nodesize()).await?;
        if format::le64(&buf, 48)? != logical {
            return Err(FsError::InvalidData);
        }
        if self.verify_checksums {
            let stored = format::le32(&buf, 0)?;
            if crate::checksum::block_csum(&buf[format::CSUM_SIZE..]) != stored {
                return Err(FsError::InvalidData);
            }
        }
        Ok(buf)
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
        let subvol_id = match sel {
            Subvol::Id(n) => *n,
            Subvol::Name(name) => {
                // Resolve the name in the default FS_TREE root directory; its
                // location must be a subvolume ROOT_ITEM.
                let (fs_root, _) = self.fs_tree_root();
                let key = BtrfsKey::new(
                    format::FIRST_FREE_OBJECTID,
                    format::DIR_ITEM_KEY,
                    u64::from(crate::checksum::name_hash(name.as_bytes())),
                );
                let body = crate::btree::find_item(self, fs_root, &key)
                    .await?
                    .ok_or(FsError::NotFound)?;
                let entry = crate::dir::decode_dir_items(&body)?
                    .into_iter()
                    .find(|e| &e.name == name)
                    .ok_or(FsError::NotFound)?;
                if entry.location.item_type != format::ROOT_ITEM_KEY {
                    return Err(FsError::NotFound);
                }
                entry.location.objectid
            }
        };
        let (subvol_root, subvol_level) =
            crate::roots::find_root(self, root_tree, subvol_id).await?;
        let root_inode = self
            .load_inode_in(subvol_root, format::FIRST_FREE_OBJECTID)
            .await?;
        let mut g = self.state.lock();
        g.fs_tree_root = subvol_root;
        g.fs_tree_level = subvol_level;
        g.root_inode = Some(root_inode);
        Ok(())
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

        // Read + decode the primary superblock at 64 KiB.
        let mut raw = vec![0u8; format::SUPERBLOCK_SIZE];
        read_exact_from(&*device, &io, capacity, format::SUPERBLOCK_OFFSET, &mut raw).await?;
        // The superblock checksum covers everything after the 32-byte csum
        // field, up to the 4096-byte block.
        if verify_checksums {
            let stored = format::le32(&raw, 0)?;
            if crate::checksum::block_csum(&raw[format::CSUM_SIZE..format::SUPERBLOCK_SIZE])
                != stored
            {
                return Err(FsError::InvalidData);
            }
        }
        let superblock = Superblock::decode(&raw)?;

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
            verify_checksums,
            io,
            device_capacity: capacity,
            state: IrqSafeSpinLock::new(VolState {
                superblock,
                chunk_map: seed,
                fs_tree_root: 0,
                fs_tree_level: 0,
                root_inode: None,
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
        let (fs_root, fs_level) = crate::roots::find_fs_tree(self, root_tree).await?;
        {
            let mut g = self.state.lock();
            g.fs_tree_root = fs_root;
            g.fs_tree_level = fs_level;
        }

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

    /// Overwrite the primary superblock (at 64 KiB) with `raw` (a full 4096-byte
    /// block whose checksum the caller has already recomputed) and flush.
    pub async fn write_superblock(&self, raw: &[u8]) -> Result<(), FsError> {
        if raw.len() != format::SUPERBLOCK_SIZE {
            return Err(FsError::InvalidData);
        }
        self.write_physical(format::SUPERBLOCK_OFFSET, raw).await?;
        self.device.flush().await;
        Ok(())
    }

    /// Flush the backing device.
    pub async fn flush(&self) {
        self.device.flush().await;
    }

    /// Read the raw 4096-byte superblock block from disk.
    pub async fn read_raw_superblock(&self) -> Result<Vec<u8>, FsError> {
        let mut raw = vec![0u8; format::SUPERBLOCK_SIZE];
        self.read_physical(format::SUPERBLOCK_OFFSET, &mut raw)
            .await?;
        Ok(raw)
    }

    /// After a COW commit, publish the new roots into the live volume so
    /// subsequent reads through this handle observe the write.
    pub fn commit_roots(&self, new_root_tree: u64, new_fs_root: u64, new_generation: u64) {
        let mut g = self.state.lock();
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
        g.fs_tree_root = new_fs_root;
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
