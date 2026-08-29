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

use alloc::collections::BTreeMap;
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

use crate::chunk::{ChunkMap, ChunkProfile};
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

/// Profile targets for a balance conversion. `None` leaves that allocation
/// class unchanged. Mixed DATA+METADATA block groups require identical data
/// and metadata targets, as they do in Linux.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BalanceProfiles {
    pub data: Option<ChunkProfile>,
    pub metadata: Option<ChunkProfile>,
    pub system: Option<ChunkProfile>,
}

/// Counts returned by a completed synchronous balance.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BalanceStats {
    pub considered: u64,
    pub converted: u64,
}

/// Volume-owned scratch DMA buffer, serialised across all block submissions.
#[derive(Debug)]
struct VolumeIo {
    cap: Cap<DmaBuffer, Write>,
    block_size: usize,
}

/// One member device, with geometry and scratch I/O state local to that
/// device. Different members may expose different logical block sizes.
#[derive(Debug)]
struct VolumeDevice<B: BlockDevice> {
    device: Arc<B>,
    capacity: u64,
    /// Member-specific embedded dev_item, preserved while common superblock
    /// transaction fields are replicated to every device.
    dev_item: IrqSafeSpinLock<[u8; format::SUPERBLOCK_DEV_ITEM_SIZE]>,
    io: Mutex<VolumeIo>,
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

/// Cached metadata nodes, keyed by logical address.
///
/// `epoch` is what makes filling the cache safe against a concurrent write.
/// A reader that misses must drop the lock to do its I/O, and a writer may
/// invalidate that very address while the read is in flight; inserting the
/// bytes afterwards would publish a node that is already stale. The reader
/// samples `epoch` before its read and only inserts if no invalidation has
/// happened since, so a racing write costs a skipped fill rather than a wrong
/// answer.
#[derive(Debug, Default)]
struct NodeCache {
    entries: BTreeMap<u64, alloc::vec::Vec<u8>>,
    epoch: u64,
}

/// Cached nodes. At a 16 KiB nodesize this bounds the cache at 4 MiB, which
/// comfortably holds the working set a commit's fixed point revisits while
/// staying a fixed, predictable cost.
const NODE_CACHE_MAX: usize = 256;

impl NodeCache {
    /// Drop `logical` and advance the epoch, so any fill already in flight for
    /// it (or for anything else) declines to publish.
    fn invalidate(&mut self, logical: u64) {
        self.entries.remove(&logical);
        self.epoch = self.epoch.wrapping_add(1);
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
    superblock_source: (u64, u64),
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
    /// Source device passed first at mount. Retained for compatibility with
    /// single-device callers and tests; logical I/O routes through `devices`.
    pub device: Arc<B>,
    pub self_weak: Weak<BtrfsVolume<B>>,
    /// Immutable geometry (copied out of the superblock so hot reads need no
    /// lock).
    magic: u64,
    nodesize: u32,
    sectorsize: u32,
    domain: DomainId,
    /// On-disk metadata/data checksum algorithm selected by the superblock.
    csum_type: u16,
    /// Enforce per-node/superblock checksum verification.
    verify_checksums: bool,
    /// Missing members make a redundant array readable but never writable.
    degraded: bool,
    devices: IrqSafeSpinLock<BTreeMap<u64, Arc<VolumeDevice<B>>>>,
    state: IrqSafeSpinLock<VolState>,
    /// Metadata node cache, keyed by logical address.
    ///
    /// A commit path-COWs the extent tree once per fixed-point round, and a
    /// round re-reads the same nodes the previous one did — measured at 724
    /// rounds across 152 commits in the boot write smoke, with that re-reading
    /// the single largest cost in the whole commit. Every miss costs an
    /// (emulated) device read plus a full-node checksum verification, and both
    /// are pure repetition for a block nothing has written since.
    nodes: IrqSafeSpinLock<NodeCache>,
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
        self.state.lock().superblock.total_bytes
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

    /// `(devid, physical capacity)` for every assembled member.
    pub(crate) fn member_capacities(&self) -> Vec<(u64, u64)> {
        self.devices
            .lock()
            .iter()
            .map(|(&devid, member)| (devid, member.capacity))
            .collect()
    }

    pub(crate) fn member_dev_items(&self) -> Vec<(u64, [u8; format::SUPERBLOCK_DEV_ITEM_SIZE])> {
        self.devices
            .lock()
            .iter()
            .map(|(&devid, member)| (devid, *member.dev_item.lock()))
            .collect()
    }

    fn device_uuid(&self, devid: u64, capacity: u64) -> [u8; 16] {
        let sb = self.superblock();
        let mut uuid = sb.fsid;
        let salt = devid ^ capacity.rotate_left(17) ^ sb.generation.rotate_left(31);
        for (index, byte) in uuid.iter_mut().enumerate() {
            *byte ^= salt.rotate_left((index * 7) as u32) as u8;
            *byte = byte.wrapping_add((index as u8).wrapping_mul(0x3d));
        }
        // RFC-4122-shaped bits are conventional for btrfs UUIDs even though
        // the on-disk format treats the field as opaque.
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        uuid
    }

    async fn new_member(
        &self,
        device: Arc<B>,
        dev_item: [u8; format::SUPERBLOCK_DEV_ITEM_SIZE],
    ) -> Result<Arc<VolumeDevice<B>>, FsError> {
        let logical = device.logical_block_size() as usize;
        if !(512..=4096).contains(&logical) || !logical.is_power_of_two() {
            return Err(FsError::Unsupported);
        }
        let capacity = device
            .capacity_blocks()
            .checked_mul(logical as u64)
            .ok_or(FsError::InvalidData)?;
        if capacity <= 1024 * 1024 || capacity % u64::from(self.sectorsize) != 0 {
            return Err(FsError::InvalidData);
        }
        let dma =
            alloc_coherent(logical, self.domain).map_err(|_| FsError::Io(BlockError::IOError))?;
        Ok(Arc::new(VolumeDevice {
            device,
            capacity,
            dev_item: IrqSafeSpinLock::new(dev_item),
            io: Mutex::new(VolumeIo {
                cap: register_with_cap(dma),
                block_size: logical,
            }),
        }))
    }

    /// Add a writable member and commit its `DEV_ITEM` plus superblocks. New
    /// chunks continue to use the current profiles; a later balance can spread
    /// existing allocations onto the member.
    pub async fn add_device(&self, device: Arc<B>) -> Result<u64, FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        if self
            .devices
            .lock()
            .values()
            .any(|member| Arc::ptr_eq(&member.device, &device))
        {
            return Err(FsError::Busy);
        }
        let devid = self
            .devices
            .lock()
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(FsError::InvalidData)?;
        let logical = device.logical_block_size() as u64;
        let capacity = device
            .capacity_blocks()
            .checked_mul(logical)
            .ok_or(FsError::InvalidData)?;
        let total = capacity / u64::from(self.sectorsize) * u64::from(self.sectorsize);
        let mut item = [0u8; format::SUPERBLOCK_DEV_ITEM_SIZE];
        item[0..8].copy_from_slice(&devid.to_le_bytes());
        item[8..16].copy_from_slice(&total.to_le_bytes());
        item[24..28].copy_from_slice(&self.sectorsize.to_le_bytes());
        item[28..32].copy_from_slice(&self.sectorsize.to_le_bytes());
        item[32..36].copy_from_slice(&self.sectorsize.to_le_bytes());
        item[66..82].copy_from_slice(&self.device_uuid(devid, total));
        item[82..98].copy_from_slice(&self.superblock().fsid);
        let member = self.new_member(device, item).await?;
        self.devices.lock().insert(devid, member);
        if let Err(error) = crate::write::grow_add_chunk(self).await {
            self.devices.lock().remove(&devid);
            return Err(error);
        }
        Ok(devid)
    }

    /// Relocate selected block groups onto freshly allocated physical extents
    /// and atomically replace their chunk geometry. Logical addresses do not
    /// change, so file/tree backreferences remain valid while the profile does.
    pub async fn balance_profiles(
        &self,
        profiles: BalanceProfiles,
    ) -> Result<BalanceStats, FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        crate::write::balance_profiles(self, profiles, None).await
    }

    /// Replace one member with another device while retaining its devid, UUID,
    /// and physical stripe offsets. Only allocated device extents are copied.
    pub async fn replace_device(&self, devid: u64, target: Arc<B>) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        let source = self.member(devid)?;
        if self
            .devices
            .lock()
            .values()
            .any(|member| Arc::ptr_eq(&member.device, &target))
        {
            return Err(FsError::Busy);
        }
        let replacement = self.new_member(target, *source.dev_item.lock()).await?;
        if replacement.capacity < source.capacity {
            return Err(FsError::NoSpace);
        }
        for (start, length) in crate::write::device_extent_ranges(self, devid).await? {
            let mut offset = 0u64;
            while offset < length {
                let take = (length - offset).min(128 * 1024) as usize;
                let mut bytes = vec![0u8; take];
                read_exact_from(
                    &*source.device,
                    &source.io,
                    source.capacity,
                    start + offset,
                    &mut bytes,
                )
                .await?;
                write_exact_to(
                    &*replacement.device,
                    &replacement.io,
                    replacement.capacity,
                    start + offset,
                    &bytes,
                )
                .await?;
                offset += take as u64;
            }
        }
        let raw = self.read_raw_superblock().await?;
        self.devices.lock().insert(devid, replacement);
        self.write_superblock(&raw).await?;
        let zero = vec![0u8; format::SUPERBLOCK_SIZE];
        for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
            if offset + format::SUPERBLOCK_SIZE as u64 <= source.capacity {
                write_exact_to(&*source.device, &source.io, source.capacity, offset, &zero).await?;
            }
        }
        source.device.flush().await;
        Ok(())
    }

    /// Remove a member, first relocating every chunk stripe that resides on it
    /// while retaining each block group's current profile.
    pub async fn remove_device(&self, devid: u64) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        if self.devices.lock().len() <= 1 {
            return Err(FsError::Busy);
        }
        if !crate::write::device_extent_ranges(self, devid)
            .await?
            .is_empty()
        {
            crate::write::balance_profiles(self, BalanceProfiles::default(), Some(devid)).await?;
        }
        let removed = self
            .devices
            .lock()
            .remove(&devid)
            .ok_or(FsError::NotFound)?;
        self.select_live_superblock_source()?;
        if let Err(error) = crate::write::grow_add_chunk(self).await {
            self.devices.lock().insert(devid, removed);
            self.select_live_superblock_source()?;
            return Err(error);
        }
        let zero = vec![0u8; format::SUPERBLOCK_SIZE];
        for &offset in &format::SUPERBLOCK_MIRROR_OFFSETS {
            if offset + format::SUPERBLOCK_SIZE as u64 <= removed.capacity {
                write_exact_to(
                    &*removed.device,
                    &removed.io,
                    removed.capacity,
                    offset,
                    &zero,
                )
                .await?;
            }
        }
        removed.device.flush().await;
        Ok(())
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
    #[cfg(feature = "kernel-test")]
    pub(crate) fn map_logical_copies(&self, logical: u64) -> Result<(u64, Option<u64>), FsError> {
        self.state.lock().chunk_map.map_logical_copies(logical)
    }

    /// Logical bytes left in the containing chunk/block group.
    pub(crate) fn logical_chunk_remaining(&self, logical: u64) -> Result<u64, FsError> {
        self.state.lock().chunk_map.chunk_remaining(logical)
    }

    /// Resolve every direct copy of a logical byte, preserving device ids.
    pub fn map_logical_stripes(
        &self,
        logical: u64,
    ) -> Result<Vec<crate::chunk::StripeLocation>, FsError> {
        self.state.lock().chunk_map.map_logical_stripes(logical)
    }

    /// Snapshot of the live superblock (for statfs / write bookkeeping).
    pub fn superblock(&self) -> Superblock {
        self.state.lock().superblock.clone()
    }

    // ── Physical / logical reads ───────────────────────────────────

    fn member(&self, devid: u64) -> Result<Arc<VolumeDevice<B>>, FsError> {
        self.devices
            .lock()
            .get(&devid)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    /// Read `dst.len()` bytes at a member device's physical byte offset.
    pub(crate) async fn read_physical_on(
        &self,
        devid: u64,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let member = self.member(devid)?;
        read_exact_from(&*member.device, &member.io, member.capacity, offset, dst).await
    }

    /// Read one direct-copy choice, splitting at chunk/stripe boundaries.
    async fn read_logical_copy(
        &self,
        logical: u64,
        dst: &mut [u8],
        copy: usize,
    ) -> Result<(), FsError> {
        let mut done = 0usize;
        while done < dst.len() {
            let at = logical
                .checked_add(done as u64)
                .ok_or(FsError::InvalidData)?;
            let (locations, contiguous) = {
                let g = self.state.lock();
                (
                    g.chunk_map.map_logical_stripes(at)?,
                    g.chunk_map.max_contiguous(at)?,
                )
            };
            let take = (dst.len() - done).min(contiguous as usize);
            if let Some(location) = locations.get(copy) {
                self.read_physical_on(
                    location.devid,
                    location.physical,
                    &mut dst[done..done + take],
                )
                .await?;
            } else if copy == locations.len() {
                self.reconstruct_raid56(at, &mut dst[done..done + take])
                    .await?;
            } else {
                return Err(FsError::NotFound);
            }
            done += take;
        }
        Ok(())
    }

    /// Rebuild one RAID5/6 logical data slice. The requested stripe is treated
    /// as absent even when readable, which gives checksum-aware callers an
    /// independent parity-derived retry for silent corruption.
    async fn reconstruct_raid56(&self, logical: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let set = self.state.lock().chunk_map.raid56_set(logical)?;
        let delta = logical
            .checked_sub(set.logical_start)
            .ok_or(FsError::InvalidData)?;
        let target = (delta / set.stripe_len) as usize;
        let within = delta % set.stripe_len;
        if target >= set.data.len() || dst.len() as u64 > set.stripe_len - within {
            return Err(FsError::InvalidData);
        }

        let mut data = Vec::with_capacity(set.data.len());
        let mut unavailable = 1usize; // requested data stripe is intentionally absent
        for (index, location) in set.data.iter().enumerate() {
            if index == target {
                data.push(None);
                continue;
            }
            let mut bytes = vec![0u8; dst.len()];
            if self
                .read_physical_on(location.devid, location.physical + within, &mut bytes)
                .await
                .is_ok()
            {
                data.push(Some(bytes));
            } else {
                unavailable += 1;
                data.push(None);
            }
        }

        let mut parity = Vec::with_capacity(set.parity.len());
        for location in &set.parity {
            let mut bytes = vec![0u8; dst.len()];
            if self
                .read_physical_on(location.devid, location.physical + within, &mut bytes)
                .await
                .is_ok()
            {
                parity.push(Some(bytes));
            } else {
                unavailable += 1;
                parity.push(None);
            }
        }
        if unavailable > set.parity.len() {
            return Err(FsError::NotFound);
        }
        crate::raid56::recover(
            &mut data,
            parity.first().and_then(Option::as_deref),
            parity.get(1).and_then(Option::as_deref),
            dst.len(),
        )?;
        dst.copy_from_slice(data[target].as_deref().ok_or(FsError::InvalidData)?);
        Ok(())
    }

    fn logical_read_copies(&self, logical: u64) -> Result<usize, FsError> {
        let g = self.state.lock();
        let direct = g.chunk_map.map_logical_stripes(logical)?.len();
        match g.chunk_map.raid56_set(logical) {
            Ok(_) => Ok(direct + 1),
            Err(FsError::Unsupported) => Ok(direct),
            Err(error) => Err(error),
        }
    }

    /// Read `len` bytes at btrfs *logical* address `logical`. The range must lie
    /// within a single chunk (true for any node or single extent read).
    pub async fn read_logical(&self, logical: u64, len: usize) -> Result<Vec<u8>, FsError> {
        // Resolve both physical copies under the lock, then release it before
        // I/O. A plain logical read can retry transport failure; callers with a
        // checksum (notably read_node and the data-csum path) retry corruption.
        let mut buf = vec![0u8; len];
        let copies = self.logical_read_copies(logical)?;
        let mut last = FsError::NotFound;
        for copy in 0..copies {
            match self.read_logical_copy(logical, &mut buf, copy).await {
                Ok(()) => return Ok(buf),
                Err(error) => last = error,
            }
        }
        Err(last)
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
        let mut buf = vec![0u8; len];
        let copies = self.logical_read_copies(logical)?;
        for copy in 0..copies {
            if self
                .read_logical_copy(logical, &mut buf, copy)
                .await
                .is_err()
            {
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
        // Serve from the node cache when nothing has written this address
        // since it was filled. A hit skips both the device read and the
        // full-node checksum verification; the clone is a memcpy against an
        // I/O plus a checksum over the whole node.
        let epoch = {
            let cache = self.nodes.lock();
            if let Some(hit) = cache.entries.get(&logical) {
                return Ok(hit.clone());
            }
            cache.epoch
        };

        let mut buf = vec![0u8; self.nodesize()];
        let copies = self.logical_read_copies(logical)?;
        for copy in 0..copies {
            if self
                .read_logical_copy(logical, &mut buf, copy)
                .await
                .is_err()
            {
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
            // Only cache a node that passed BOTH checks above — a copy that
            // failed one is retried from another mirror, and caching it would
            // make a transient bad mirror permanent for this mount.
            let mut cache = self.nodes.lock();
            if cache.epoch == epoch {
                // A write landed while this read was in flight if the epoch
                // moved; the bytes in hand may already be stale, so drop them
                // rather than publish them.
                if cache.entries.len() >= NODE_CACHE_MAX {
                    // Crude but bounded, and the working set a commit revisits
                    // sits far below the cap — an LRU's bookkeeping would cost
                    // more here than the misses it saves.
                    cache.entries.clear();
                }
                cache.entries.insert(logical, buf.clone());
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

    /// Mount a volume from an explicit set of member devices. The first device
    /// is the requested source; additional devices with another FSID are
    /// ignored, matching registry-wide discovery.
    pub async fn mount_devices(
        devices: Vec<Arc<B>>,
        domain: DomainId,
    ) -> Result<Arc<Self>, FsError> {
        Self::mount_devices_opts(devices, domain, true).await
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

    /// Multi-device equivalent of [`Self::mount_subvol`].
    pub async fn mount_subvol_devices(
        devices: Vec<Arc<B>>,
        domain: DomainId,
        verify_checksums: bool,
        subvol: Option<Subvol>,
    ) -> Result<Arc<Self>, FsError> {
        let volume = Self::mount_devices_opts(devices, domain, verify_checksums).await?;
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
        g.writable_fs_tree = !self.degraded && subvol_flags & format::ROOT_SUBVOL_RDONLY == 0;
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
        Self::mount_devices_opts(alloc::vec![device], domain, verify_checksums).await
    }

    /// Mount from an explicit member set, optionally disabling checksum
    /// verification (test bring-up only).
    pub async fn mount_devices_opts(
        input: Vec<Arc<B>>,
        domain: DomainId,
        verify_checksums: bool,
    ) -> Result<Arc<Self>, FsError> {
        let source_device = input.first().cloned().ok_or(FsError::NotFound)?;
        let mut scanned = Vec::new();
        for (index, device) in input.into_iter().enumerate() {
            let logical = device.logical_block_size() as usize;
            if !(512..=4096).contains(&logical) || !logical.is_power_of_two() {
                if index == 0 {
                    return Err(FsError::Unsupported);
                }
                continue;
            }
            let capacity = device
                .capacity_blocks()
                .checked_mul(logical as u64)
                .ok_or(FsError::InvalidData)?;
            if capacity < format::SUPERBLOCK_OFFSET + format::SUPERBLOCK_SIZE as u64 {
                if index == 0 {
                    return Err(FsError::InvalidData);
                }
                continue;
            }
            let dma =
                alloc_coherent(logical, domain).map_err(|_| FsError::Io(BlockError::IOError))?;
            let io = Mutex::new(VolumeIo {
                cap: register_with_cap(dma),
                block_size: logical,
            });
            let mut best: Option<(u64, Superblock, [u8; format::SUPERBLOCK_DEV_ITEM_SIZE])> = None;
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
                if verify_checksums
                    && !matches!(
                        crate::checksum::verify(
                            candidate_csum,
                            &candidate[format::CSUM_SIZE..format::SUPERBLOCK_SIZE],
                            &candidate[..format::CSUM_SIZE],
                        ),
                        Ok(true)
                    )
                {
                    continue;
                }
                let decoded = match Superblock::decode(&candidate) {
                    Ok(sb) if sb.device_total_bytes <= capacity => sb,
                    Ok(_) => continue,
                    Err(FsError::Unsupported) => {
                        saw_unsupported = true;
                        continue;
                    }
                    Err(_) => continue,
                };
                if best
                    .as_ref()
                    .is_none_or(|(_, current, _)| decoded.generation > current.generation)
                {
                    let start = format::SUPERBLOCK_DEV_ITEM_OFFSET;
                    let mut dev_item = [0u8; format::SUPERBLOCK_DEV_ITEM_SIZE];
                    dev_item.copy_from_slice(
                        &candidate[start..start + format::SUPERBLOCK_DEV_ITEM_SIZE],
                    );
                    best = Some((offset, decoded, dev_item));
                }
            }
            match best {
                Some((offset, superblock, dev_item)) => {
                    let member = Arc::new(VolumeDevice {
                        device,
                        capacity,
                        dev_item: IrqSafeSpinLock::new(dev_item),
                        io,
                    });
                    scanned.push((member, offset, superblock));
                }
                None if index == 0 && saw_unsupported => return Err(FsError::Unsupported),
                None if index == 0 => return Err(FsError::InvalidData),
                None => {}
            }
        }

        let source_fsid = scanned
            .first()
            .map(|(_, _, sb)| sb.fsid)
            .ok_or(FsError::InvalidData)?;
        let source_geometry = scanned
            .first()
            .map(|(_, _, sb)| (sb.sectorsize, sb.nodesize, sb.csum_type))
            .ok_or(FsError::InvalidData)?;
        let mut devices = BTreeMap::new();
        let mut selected: Option<(u64, u64, Superblock)> = None;
        let mut min_generation = u64::MAX;
        let mut max_generation = 0u64;
        let mut common_superblock: Option<Superblock> = None;
        let mut inconsistent_members = false;
        for (member, offset, candidate) in scanned {
            if candidate.fsid != source_fsid {
                continue;
            }
            if (
                candidate.sectorsize,
                candidate.nodesize,
                candidate.csum_type,
            ) != source_geometry
            {
                return Err(FsError::InvalidData);
            }
            if devices.insert(candidate.devid, member).is_some() {
                return Err(FsError::InvalidData);
            }
            min_generation = min_generation.min(candidate.generation);
            max_generation = max_generation.max(candidate.generation);
            if let Some(common) = &common_superblock {
                inconsistent_members |= !same_common_superblock(common, &candidate);
            } else {
                common_superblock = Some(candidate.clone());
            }
            if selected
                .as_ref()
                .is_none_or(|(_, _, current)| candidate.generation > current.generation)
            {
                selected = Some((candidate.devid, offset, candidate));
            }
        }
        let (source_devid, source_offset, superblock) = selected.ok_or(FsError::InvalidData)?;
        if devices.len() > superblock.num_devices as usize {
            return Err(FsError::InvalidData);
        }
        // A member left behind by an interrupted prior commit is readable from
        // the newest mirrors, but must not participate in a new transaction.
        let degraded = devices.len() < superblock.num_devices as usize
            || min_generation != max_generation
            || inconsistent_members;
        let csum_type = superblock.csum_type;

        // Seed the chunk map so the chunk tree is reachable by logical address.
        let seed = ChunkMap::seed_from_sys_array(&superblock.sys_chunk_array)?;
        seed.map_logical(superblock.chunk_root)?;

        let volume = Arc::new_cyclic(|self_weak| BtrfsVolume {
            device: source_device,
            self_weak: self_weak.clone(),
            magic: superblock.magic,
            nodesize: superblock.nodesize,
            sectorsize: superblock.sectorsize,
            domain,
            csum_type,
            verify_checksums,
            degraded,
            devices: IrqSafeSpinLock::new(devices),
            nodes: IrqSafeSpinLock::new(NodeCache::default()),
            state: IrqSafeSpinLock::new(VolState {
                superblock,
                superblock_source: (source_devid, source_offset),
                chunk_map: seed,
                fs_tree_id: format::FS_TREE_OBJECTID,
                fs_tree_root: 0,
                fs_tree_level: 0,
                fs_tree_flags: 0,
                root_inode: None,
                writable_fs_tree: !degraded,
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
            g.writable_fs_tree = !self.degraded && fs_flags & format::ROOT_SUBVOL_RDONLY == 0;
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
    pub(crate) async fn write_physical_on(
        &self,
        devid: u64,
        offset: u64,
        src: &[u8],
    ) -> Result<(), FsError> {
        let member = self.member(devid)?;
        write_exact_to(&*member.device, &member.io, member.capacity, offset, src).await
    }

    /// Write `src` at btrfs *logical* address `logical` (single-chunk range).
    pub async fn write_logical(&self, logical: u64, src: &[u8]) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        self.write_logical_unchecked(logical, src).await.map(|_| ())
    }

    /// Root-tree transaction write used only to change the mounted subvolume's
    /// own read-only flag. Clearing that flag must be able to commit while the
    /// current live subvolume is still read-only; ordinary mutations continue
    /// to go through [`Self::write_logical`] and its writeability check.
    async fn write_logical_unchecked(&self, logical: u64, src: &[u8]) -> Result<u64, FsError> {
        // Every node write funnels through here, so this is the one place the
        // node cache has to be invalidated.
        //
        // The epoch moves on BOTH sides of the write, and both are load
        // bearing. Before, so no reader can take a hit on bytes this write is
        // about to replace. After, because a reader that missed and started
        // its device read while the write was still in flight may hold
        // pre-write bytes; without the second bump its epoch check would pass
        // and it would publish them as current.
        let _ = self.invalidate_nodes(logical, src.len());
        let mut done = 0usize;
        while done < src.len() {
            let at = logical
                .checked_add(done as u64)
                .ok_or(FsError::InvalidData)?;
            let (locations, contiguous, raid56) = {
                let g = self.state.lock();
                let raid56 = match g.chunk_map.raid56_set(at) {
                    Ok(set) => Some(set),
                    Err(FsError::Unsupported) => None,
                    Err(error) => return Err(error),
                };
                (
                    g.chunk_map.map_logical_stripes(at)?,
                    g.chunk_map.max_contiguous(at)?,
                    raid56,
                )
            };
            let take = (src.len() - done).min(contiguous as usize);
            if let Some(set) = raid56 {
                self.write_raid56(at, &src[done..done + take], &set).await?;
            } else {
                for location in locations {
                    self.write_physical_on(
                        location.devid,
                        location.physical,
                        &src[done..done + take],
                    )
                    .await?;
                }
            }
            done += take;
        }
        Ok(self.invalidate_nodes(logical, src.len()))
    }

    /// Publish a node this volume has just written, so the read that follows
    /// it does not have to fetch back bytes we are already holding.
    ///
    /// A commit writes its new nodes and then immediately reads part of the
    /// tree back — `total_block_group_used` re-reads the freshly written
    /// extent tree so the superblock's `bytes_used` can never drift from the
    /// block groups. Every one of those reads is a guaranteed MISS, because
    /// the write that produced the node invalidated it moments earlier: the
    /// cache is defeated precisely where it would help most.
    ///
    /// This is safe in a way a speculative fill is not — the bytes are what
    /// was just written, not what was read from somewhere and might be stale.
    /// It must still be called AFTER the write completes, so the write's own
    /// trailing invalidation cannot remove the entry it just published.
    fn cache_written_node(&self, logical: u64, buf: &[u8], epoch: u64) {
        if buf.len() != self.nodesize() {
            return; // not a metadata node
        }
        let mut cache = self.nodes.lock();
        // `epoch` is what this write left behind. If it has moved, another
        // write has touched the cache since — publishing now could put our
        // bytes over newer ones, so decline. Same trade as a racing fill:
        // a missed publish, never a wrong answer.
        if cache.epoch != epoch {
            return;
        }
        if cache.entries.len() >= NODE_CACHE_MAX {
            cache.entries.clear();
        }
        cache.entries.insert(logical, buf.to_vec());
    }

    /// Write one metadata node and keep it cached.
    pub async fn write_node(&self, logical: u64, buf: &[u8]) -> Result<(), FsError> {
        if !self.supports_writes() {
            return Err(FsError::ReadOnly);
        }
        let epoch = self.write_logical_unchecked(logical, buf).await?;
        self.cache_written_node(logical, buf, epoch);
        Ok(())
    }

    /// [`Self::write_node`] for the root-admin path.
    pub(crate) async fn write_node_root_admin(
        &self,
        logical: u64,
        buf: &[u8],
    ) -> Result<(), FsError> {
        if self.degraded {
            return Err(FsError::ReadOnly);
        }
        let epoch = self.write_logical_unchecked(logical, buf).await?;
        self.cache_written_node(logical, buf, epoch);
        Ok(())
    }

    /// Drop every cached node the byte range `[logical, logical + len)`
    /// touches, and advance the epoch.
    ///
    /// A cached entry at `a` covers `[a, a + nodesize)`, so the scan starts a
    /// node below `logical`: an entry beginning just under the range still
    /// overlaps it, and skipping those would leave exactly the partially
    /// overwritten nodes cached.
    ///
    /// Chunk relocation writes by physical address without coming through
    /// here, and deliberately needs no invalidation — it copies each logical
    /// block's bytes unchanged to new backing, so cached contents stay
    /// correct. Superblock writes likewise: they are never read as nodes.
    fn invalidate_nodes(&self, logical: u64, len: usize) -> u64 {
        let node = self.nodesize() as u64;
        let end = logical.saturating_add(len as u64);
        let from = logical.saturating_sub(node.saturating_sub(1));
        let mut cache = self.nodes.lock();
        let stale: alloc::vec::Vec<u64> = cache
            .entries
            .range(from..end)
            .map(|(&addr, _)| addr)
            .collect();
        for addr in stale {
            cache.invalidate(addr);
        }
        cache.epoch = cache.epoch.wrapping_add(1);
        cache.epoch
    }

    /// Read-modify-write one data slice and its P/Q parity. The caller splits
    /// writes at stripe boundaries, and writable mounts require every declared
    /// member, so all peer data is available without degraded reconstruction.
    async fn write_raid56(
        &self,
        logical: u64,
        src: &[u8],
        set: &crate::chunk::Raid56Set,
    ) -> Result<(), FsError> {
        let delta = logical
            .checked_sub(set.logical_start)
            .ok_or(FsError::InvalidData)?;
        let target = (delta / set.stripe_len) as usize;
        let within = delta % set.stripe_len;
        if target >= set.data.len() || src.len() as u64 > set.stripe_len - within {
            return Err(FsError::InvalidData);
        }

        let mut data = Vec::with_capacity(set.data.len());
        for (index, location) in set.data.iter().enumerate() {
            if index == target {
                data.push(src.to_vec());
            } else {
                let mut bytes = vec![0u8; src.len()];
                self.read_physical_on(location.devid, location.physical + within, &mut bytes)
                    .await?;
                data.push(bytes);
            }
        }
        let slices: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let (p, q) = crate::raid56::syndromes(&slices, set.parity.len() == 2)?;

        let location = set.data.get(target).ok_or(FsError::InvalidData)?;
        self.write_physical_on(location.devid, location.physical + within, src)
            .await?;
        for (index, location) in set.parity.iter().enumerate() {
            let parity = if index == 0 {
                p.as_slice()
            } else {
                q.as_slice()
            };
            self.write_physical_on(location.devid, location.physical + within, parity)
                .await?;
        }
        Ok(())
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

    /// Superblock half of [`Self::write_node_root_admin`].
    pub(crate) async fn write_superblock_root_admin(&self, raw: &[u8]) -> Result<(), FsError> {
        if self.degraded {
            return Err(FsError::ReadOnly);
        }
        self.write_superblock_unchecked(raw).await
    }

    async fn write_superblock_unchecked(&self, raw: &[u8]) -> Result<(), FsError> {
        if raw.len() != format::SUPERBLOCK_SIZE {
            return Err(FsError::InvalidData);
        }
        // Mirrors first (highest offset to lowest), primary (offset 0) last,
        // across every member. Common transaction fields are shared, while the
        // embedded dev_item remains unique to each device.
        let members: Vec<(u64, Arc<VolumeDevice<B>>)> = self
            .devices
            .lock()
            .iter()
            .map(|(&devid, member)| (devid, member.clone()))
            .collect();
        for &offset in format::SUPERBLOCK_MIRROR_OFFSETS.iter().rev() {
            for (devid, member) in &members {
                if offset + format::SUPERBLOCK_SIZE as u64 > member.capacity {
                    continue; // this mirror doesn't fit on this member
                }
                let mut copy = raw.to_vec();
                let b = format::SUPERBLOCK_BYTENR_OFFSET;
                copy[b..b + 8].copy_from_slice(&offset.to_le_bytes());
                let d = format::SUPERBLOCK_DEV_ITEM_OFFSET;
                copy[d..d + format::SUPERBLOCK_DEV_ITEM_SIZE]
                    .copy_from_slice(&*member.dev_item.lock());
                crate::checksum::stamp_block(self.csum_type, &mut copy)?;
                self.write_physical_on(*devid, offset, &copy).await?;
                member.device.flush().await; // each copy durable before the next
            }
        }
        let devid = members
            .first()
            .map(|(devid, _)| *devid)
            .ok_or(FsError::NotFound)?;
        self.state.lock().superblock_source = (devid, format::SUPERBLOCK_OFFSET);
        Ok(())
    }

    /// Flush the backing device.
    pub async fn flush(&self) {
        let members: Vec<Arc<VolumeDevice<B>>> = self.devices.lock().values().cloned().collect();
        for member in members {
            member.device.flush().await;
        }
    }

    /// Read the selected raw superblock and normalize it to primary-copy form.
    /// Transaction code can therefore heal a damaged primary without knowing
    /// which mirror supplied the mounted generation.
    pub async fn read_raw_superblock(&self) -> Result<Vec<u8>, FsError> {
        let (devid, source) = self.state.lock().superblock_source;
        let mut raw = vec![0u8; format::SUPERBLOCK_SIZE];
        self.read_physical_on(devid, source, &mut raw).await?;
        if source != format::SUPERBLOCK_OFFSET {
            let at = format::SUPERBLOCK_BYTENR_OFFSET;
            raw[at..at + 8].copy_from_slice(&format::SUPERBLOCK_OFFSET.to_le_bytes());
            crate::checksum::stamp_block(self.csum_type, &mut raw)?;
        }
        Ok(raw)
    }

    /// Point raw-superblock reads at a currently assembled member. Device
    /// removal can otherwise leave the cached source devid referring to the
    /// member that was just detached even though every survivor has the same
    /// committed generation.
    fn select_live_superblock_source(&self) -> Result<(), FsError> {
        let devid = self
            .devices
            .lock()
            .keys()
            .next()
            .copied()
            .ok_or(FsError::NotFound)?;
        self.state.lock().superblock_source = (devid, format::SUPERBLOCK_OFFSET);
        Ok(())
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
        incompat_flags_add: u64,
    ) {
        let mut g = self.state.lock();
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
        g.superblock.incompat_flags |= incompat_flags_add;
        g.fs_tree_root = new_fs_root;
        g.fs_tree_level = new_fs_level;
        if let Some(flags) = new_fs_tree_flags {
            g.fs_tree_flags = flags;
            g.writable_fs_tree = !self.degraded && flags & format::ROOT_SUBVOL_RDONLY == 0;
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

    /// Register a complete freshly allocated chunk item, including all member
    /// stripes and its RAID profile.
    pub(crate) fn add_chunk_item_mapping(&self, logical: u64, chunk: &[u8]) -> Result<(), FsError> {
        self.state.lock().chunk_map.add_chunk_item(logical, chunk)
    }

    /// Publish replacement geometry for an existing logical chunk after its
    /// new physical contents and COWed chunk tree are durable.
    pub(crate) fn replace_chunk_item_mapping(
        &self,
        logical: u64,
        chunk: &[u8],
    ) -> Result<(), FsError> {
        self.state
            .lock()
            .chunk_map
            .replace_chunk_item(logical, chunk)
    }

    /// Publish per-member allocation accounting before the superblock copies
    /// are emitted. Each copy retains its own embedded dev_item.
    pub(crate) fn set_device_bytes_used(&self, used: &BTreeMap<u64, u64>) -> Result<(), FsError> {
        for (&devid, &bytes) in used {
            let member = self.member(devid)?;
            let mut item = member.dev_item.lock();
            item[16..24].copy_from_slice(&bytes.to_le_bytes());
        }
        Ok(())
    }

    /// After a chunk-growth commit, publish the new chunk-tree + root-tree roots
    /// and generation into the live superblock.
    pub fn commit_chunk_root(
        &self,
        new_chunk_root: u64,
        new_root_tree: u64,
        new_generation: u64,
        total_bytes: u64,
        num_devices: u64,
        incompat_flags_add: u64,
    ) {
        let mut g = self.state.lock();
        g.superblock.chunk_root = new_chunk_root;
        g.superblock.root = new_root_tree;
        g.superblock.generation = new_generation;
        g.superblock.total_bytes = total_bytes;
        g.superblock.num_devices = num_devices;
        g.superblock.incompat_flags |= incompat_flags_add;
    }

    /// Replace the complete cached system chunk array after balance rewrites
    /// one or more SYSTEM mappings.
    pub(crate) fn commit_sys_chunk_array(&self, array: Vec<u8>) -> Result<(), FsError> {
        if array.len() > format::SYS_CHUNK_ARRAY_SIZE {
            return Err(FsError::NoSpace);
        }
        self.state.lock().superblock.sys_chunk_array = array;
        Ok(())
    }
}

/// Compare the shared part of two member superblocks. The checksum and embedded
/// dev_item fields are intentionally member-specific; every other decoded field
/// must describe the same transaction before the array is safe to write.
fn same_common_superblock(left: &Superblock, right: &Superblock) -> bool {
    left.fsid == right.fsid
        && left.magic == right.magic
        && left.generation == right.generation
        && left.root == right.root
        && left.chunk_root == right.chunk_root
        && left.log_root == right.log_root
        && left.log_root_level == right.log_root_level
        && left.total_bytes == right.total_bytes
        && left.bytes_used == right.bytes_used
        && left.num_devices == right.num_devices
        && left.compat_ro_flags == right.compat_ro_flags
        && left.incompat_flags == right.incompat_flags
        && left.sectorsize == right.sectorsize
        && left.nodesize == right.nodesize
        && left.csum_type == right.csum_type
        && left.root_level == right.root_level
        && left.chunk_root_level == right.chunk_root_level
        && left.sys_chunk_array == right.sys_chunk_array
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
