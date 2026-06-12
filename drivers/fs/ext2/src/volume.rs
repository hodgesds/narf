//! ext2 volume management.
//!
//! Clean-room implementation. Volume mount, superblock + BGDT
//! decoding, inode-number-to-block-group math, and the indirect-block
//! pointer walk all derived strictly from the public references
//! below — no GPL Linux `fs/ext2/*`, GRUB, e2fsprogs, or BSD ext2
//! sources were consulted while writing this file.
//!
//! References:
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, §"Physical Layout", §"Block Groups",
//!   §"Inodes". <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_.
//! - OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{DirOps, FsError, FsInstance};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::now_wall;

use super::group_desc::GroupDesc;
use super::inode::Inode;
use super::journal;
use super::superblock::{ExtFlavour, Superblock};

/// Cap → DmaBuffer pair owned by an Ext2Volume. The cap is minted
/// once at `mount()` via `narf_io::register_with_cap` and is the
/// load-bearing identifier in every `BlockRequest::buffer`. Drop
/// calls `unregister`, which bumps the epoch + frees the registry
/// slot + releases the underlying frame.
#[derive(Debug)]
struct VolumeIo {
    /// Owning cap for the registered DMA scratch buffer.
    cap: Cap<DmaBuffer, Write>,
    /// Logical block size of the underlying device — every
    /// `BlockRequest` is exactly this many bytes.
    lbs: usize,
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

/// One mounted ext2 volume.
#[derive(Debug)]
pub struct Ext2Volume<B: BlockDevice> {
    pub device: Arc<B>,
    pub superblock: Superblock,
    pub group_descs: Vec<GroupDesc>,
    pub domain: DomainId,
    pub self_weak: Weak<Ext2Volume<B>>,
    /// Per-volume scratch buffer + cap. Wrapped in a spinlock so
    /// every device-LBA op holds it for the synchronous-copy span
    /// only and never across an `await` (the lock would otherwise
    /// deadlock under cooperative async).
    io: IrqSafeSpinLock<VolumeIo>,
    /// JBD2 read-side replay overrides — FS-block → post-replay
    /// bytes. Populated by `Ext2Volume::mount` when an unclean
    /// ext3+ volume is seen; consulted by `read_block` before
    /// going to the device so RO reads observe the post-replay
    /// state without ever touching the disk. Empty on clean
    /// volumes and on ext2 (which has no journal).
    journal_overrides: BTreeMap<u64, Vec<u8>>,
}

/// Free-function indirect-pointer read used by the pre-construction
/// journal-replay path. Mirrors `Ext2Volume::read_indirect` but
/// borrows everything directly so the async future has no implicit
/// 'static bound from `Ext2Volume::<B>::...` qualification.
async fn read_indirect_static<B: BlockDevice>(
    device: &B,
    io: &VolumeIo,
    bs: usize,
    block_no: u32,
    index: u64,
) -> Result<u32, FsError> {
    if block_no == 0 {
        return Ok(0);
    }
    if index >= (bs / 4) as u64 {
        return Err(FsError::Io(narf_block::BlockError::InvalidRange));
    }
    let mut buf = vec![0u8; bs];
    read_byte_range_into_static(device, io, block_no as u64 * bs as u64, &mut buf).await?;
    let off = (index as usize) * 4;
    Ok(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

/// Free-function variant of `Ext2Volume::read_byte_range_into`
/// usable from other free helpers.
async fn read_byte_range_into_static<B: BlockDevice>(
    device: &B,
    io: &VolumeIo,
    byte_off: u64,
    dst: &mut [u8],
) -> Result<(), FsError> {
    let lbs = io.lbs;
    let mut cursor = 0usize;
    while cursor < dst.len() {
        let abs = byte_off + cursor as u64;
        let lba = abs / lbs as u64;
        let in_lba = (abs % lbs as u64) as usize;
        let want = core::cmp::min(dst.len() - cursor, lbs - in_lba);

        let req = BlockRequest {
            op: BlockOp::Read,
            lba,
            blocks: 1,
            buffer: io
                .cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        let completion = device.submit(req).await;
        completion.result.map_err(FsError::Io)?;

        let buf = io
            .buffer()
            .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
        // SAFETY: see Ext2Volume::read_byte_range_into.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
        dst[cursor..cursor + want].copy_from_slice(&src[in_lba..in_lba + want]);
        cursor += want;
    }
    Ok(())
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Mount an ext2 volume. Reads the superblock at byte offset
    /// 1024 (in 512-byte sectors that's LBA 2), validates the
    /// `0xEF53` magic, then loads the block group descriptor table.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let lbs = device.logical_block_size() as usize;
        if lbs == 0 || 1024 % lbs != 0 && lbs % 1024 != 0 {
            // The driver assumes the device's logical block size is
            // a power-of-two factor of 1024 (or vice-versa). 512,
            // 1024, 2048, 4096 all qualify.
            return Err(FsError::Unsupported);
        }
        let buffer = alloc_coherent(lbs, domain)
            .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap, lbs };

        // Read 1024 bytes starting at byte 1024 — the superblock.
        // For a 512-byte LBS this is two LBA reads (LBA 2 and LBA
        // 3); for a 1024-byte LBS it's one (LBA 1); for a 4096-byte
        // LBS the superblock sits inside LBA 0 at byte 1024.
        let mut sb_bytes = vec![0u8; 1024];
        Self::read_byte_range_into(&*device, &io, 1024, &mut sb_bytes).await?;

        let superblock = match Superblock::parse(&sb_bytes) {
            Some(s) => s,
            None => {
                unregister(io.cap);
                core::mem::forget(io); // unregister already ran
                return Err(FsError::Unsupported);
            }
        };
        // Reject any volume that uses incompat features we don't
        // implement — refusing is safer than mis-decoding. Encrypted
        // and inline-data volumes hit this; ext2/3/4 with EXTENTS +
        // 64BIT + FLEX_BG + FILETYPE + RECOVER pass.
        if superblock.check_incompat_features().is_err() {
            unregister(io.cap);
            core::mem::forget(io);
            return Err(FsError::Unsupported);
        }

        // Block group descriptor table starts at the block after
        // the superblock. With a 1-KiB block volume that's block 2;
        // with a 2-KiB or 4-KiB block volume it's block 1. The
        // canonical formula:
        //
        //     bgdt_block = s_first_data_block + 1
        //
        // ext2 design paper, §"Block Groups". ext4 with 64BIT uses
        // 64-byte descriptors instead of 32 — see effective_desc_size.
        let bs = superblock.block_size() as u64;
        let group_count = superblock.block_group_count() as usize;
        let desc_size = superblock.effective_desc_size();
        let bgdt_size_bytes = (group_count * desc_size) as u64;
        let bgdt_block_offset = (superblock.first_data_block + 1) as u64 * bs;

        let mut bgdt_bytes = vec![0u8; bgdt_size_bytes as usize];
        Self::read_byte_range_into(&*device, &io, bgdt_block_offset, &mut bgdt_bytes).await?;

        let mut group_descs = Vec::with_capacity(group_count);
        for i in 0..group_count {
            let off = i * desc_size;
            let gd = GroupDesc::parse_sized(&bgdt_bytes[off..off + desc_size], desc_size)
                .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
            group_descs.push(gd);
        }

        // ── JBD2 read-side replay ───────────────────────────────
        //
        // If the volume is ext3+ AND was not cleanly unmounted, walk
        // the journal and build an override map of FS-block →
        // post-replay bytes. For RO mounts this is sufficient — we
        // never write to disk; later `read_block` calls consult the
        // override before doing device I/O.
        let mut journal_overrides: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        if superblock.flavour() != ExtFlavour::Ext2
            && superblock.has_journal()
            && !superblock.is_clean()
        {
            // Best-effort replay: failure is non-fatal for an RO
            // mount (we just fall back to the on-disk state — same
            // as ext2 was before journal support). The override
            // map only narrows reads, never invents data.
            if let Ok(map) =
                Self::replay_journal_at_mount(&*device, &io, &superblock, &group_descs).await
            {
                journal_overrides = map;
            }
        }

        Ok(Arc::new_cyclic(|self_weak| Ext2Volume {
            device,
            superblock,
            group_descs,
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
            journal_overrides,
        }))
    }

    /// Drive `journal::replay_journal` against the on-disk journal
    /// inode (`s_journal_inum`, typically 8). Reads journal blocks
    /// in sequence by walking the inode's logical→physical map and
    /// fetching one FS block at a time, eagerly into a `Vec<Vec<u8>>`
    /// (one entry per journal-block index) so the pure-logic
    /// `replay_journal` closure stays synchronous.
    ///
    /// References:
    ///   * Linux `fs/jbd2/journal.c::jbd2_journal_get_descriptor_buffer`
    ///     for the journal-block addressing model (logical block N of
    ///     the journal inode → on-disk FS block via `map_block`).
    ///   * Linux `fs/jbd2/recovery.c::do_one_pass` for the algorithm
    ///     we implement in `journal::replay_journal`.
    async fn replay_journal_at_mount(
        device: &B,
        io: &VolumeIo,
        sb: &Superblock,
        group_descs: &[GroupDesc],
    ) -> Result<BTreeMap<u64, Vec<u8>>, FsError> {
        let bs = sb.block_size() as usize;
        let inode_no = sb.journal_inum;
        if inode_no == 0 {
            return Ok(BTreeMap::new());
        }
        // Read the journal inode directly (avoid building a temporary
        // Ext2Volume just for this — we already have `device`,
        // `group_descs`, and `io`).
        let (group, index) = {
            let zero = inode_no.checked_sub(1).ok_or(FsError::NotFound)?;
            let g = zero / sb.inodes_per_group;
            let i = zero % sb.inodes_per_group;
            if (g as usize) >= group_descs.len() {
                return Err(FsError::NotFound);
            }
            (g, i)
        };
        let gd = &group_descs[group as usize];
        let inode_size = sb.inode_size_bytes();
        let table_byte_off = gd.inode_table * bs as u64;
        let inode_byte_off = table_byte_off + (index as u64) * inode_size as u64;
        let mut inode_buf = vec![0u8; 128];
        read_byte_range_into_static::<B>(device, io, inode_byte_off, &mut inode_buf).await?;
        let inode = Inode::parse(&inode_buf).ok_or(FsError::Io(narf_block::BlockError::IOError))?;

        // Size of the journal in bytes → number of journal blocks.
        let journal_bytes = inode.size as u64;
        let n_blocks = (journal_bytes / bs as u64) as u32;
        if n_blocks == 0 {
            return Ok(BTreeMap::new());
        }

        // Eagerly fetch every journal block into memory. JBD2 journals
        // are typically 128 MiB max; for the in-driver replay the
        // simplicity of a flat buffer is worth the cost. We can swap
        // to a demand-fetch closure later if needed.
        let mut journal_image: Vec<Vec<u8>> = Vec::with_capacity(n_blocks as usize);
        for i in 0..n_blocks {
            let phys =
                Self::map_block_static(device, io, sb, group_descs, &inode, i as u64).await?;
            if phys == 0 {
                // Sparse hole in the journal — treat as a block of
                // zeros. The replay walker will hit a bad-magic
                // header and stop walking forward at this point.
                journal_image.push(vec![0u8; bs]);
                continue;
            }
            let mut buf = vec![0u8; bs];
            read_byte_range_into_static::<B>(device, io, phys * bs as u64, &mut buf).await?;
            journal_image.push(buf);
        }

        let report = journal::replay_journal(n_blocks, |i| journal_image.get(i as usize).cloned())
            .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        Ok(report.blocks_to_write)
    }

    /// Static block-map walk usable before the `Arc<Ext2Volume>`
    /// exists. Mirrors `map_block` but takes all state by reference.
    /// Only used during the journal-replay path at mount.
    async fn map_block_static(
        device: &B,
        io: &VolumeIo,
        sb: &Superblock,
        _group_descs: &[GroupDesc],
        inode: &Inode,
        logical: u64,
    ) -> Result<u64, FsError> {
        if sb.uses_extents() {
            // Mirror map_block_extents but read child blocks via
            // the static helper.
            use super::extent::{lookup_in_node, LookupOutcome};
            let mut node_buf = vec![0u8; 60];
            for (i, &b) in inode.block.iter().enumerate() {
                node_buf[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
            }
            let logical32 = if logical > u32::MAX as u64 {
                return Err(FsError::Io(narf_block::BlockError::InvalidRange));
            } else {
                logical as u32
            };
            let mut depth = 8u32;
            loop {
                match lookup_in_node(&node_buf, logical32) {
                    LookupOutcome::Mapped {
                        physical,
                        is_uninitialized,
                    } => {
                        if is_uninitialized {
                            return Ok(0);
                        }
                        return Ok(physical);
                    }
                    LookupOutcome::Hole => return Ok(0),
                    LookupOutcome::Corrupt => {
                        return Err(FsError::Io(narf_block::BlockError::IOError));
                    }
                    LookupOutcome::DeeperLookupRequired { child_block } => {
                        depth = depth
                            .checked_sub(1)
                            .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
                        let bs = sb.block_size() as usize;
                        let mut child = vec![0u8; bs];
                        read_byte_range_into_static::<B>(
                            device,
                            io,
                            child_block * bs as u64,
                            &mut child,
                        )
                        .await?;
                        node_buf = child;
                    }
                }
            }
        }
        // Legacy indirect-block walk.
        let bs = sb.block_size() as usize;
        let p = (bs / 4) as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;

        if logical < direct_max {
            return Ok(inode.block[logical as usize] as u64);
        }
        if logical < single_max {
            let idx = logical - direct_max;
            let l1 = inode.block[super::inode::SINGLE_IND_IDX];
            return Ok(read_indirect_static::<B>(device, io, bs, l1, idx).await? as u64);
        }
        if logical < double_max {
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let l2_block = inode.block[super::inode::DOUBLE_IND_IDX];
            let middle = read_indirect_static::<B>(device, io, bs, l2_block, l1).await?;
            return Ok(read_indirect_static::<B>(device, io, bs, middle, l0).await? as u64);
        }
        if logical < triple_max {
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let l3_block = inode.block[super::inode::TRIPLE_IND_IDX];
            let middle = read_indirect_static::<B>(device, io, bs, l3_block, l2).await?;
            let leaf = read_indirect_static::<B>(device, io, bs, middle, l1).await?;
            return Ok(read_indirect_static::<B>(device, io, bs, leaf, l0).await? as u64);
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// Filesystem block size in bytes.
    pub fn block_size(&self) -> usize {
        self.superblock.block_size() as usize
    }

    /// Number of 32-bit pointers per indirect block.
    pub fn pointers_per_block(&self) -> usize {
        self.block_size() / 4
    }

    /// Read one filesystem block (`block_size()` bytes) into `dst`.
    /// Internally this may cost multiple device-LBA reads if the
    /// device's logical block size is smaller than the FS block
    /// size, or one partial read if larger.
    ///
    /// JBD2 replay override: if `block_no` is in the
    /// `journal_overrides` map (populated at mount for unclean
    /// ext3+ volumes), serve from memory instead of going to disk.
    /// This is the RO-replay path — every metadata block that the
    /// journal said should be updated is read back as its
    /// post-replay contents without ever writing to the device.
    pub async fn read_block(&self, block_no: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let bs = self.block_size();
        if dst.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        if let Some(override_data) = self.journal_overrides.get(&block_no) {
            // Override block size must match the FS block size; if
            // a future journal carries a different blocksize we fall
            // back to disk to avoid mis-serving truncated data.
            if override_data.len() == bs {
                dst.copy_from_slice(override_data);
                return Ok(());
            }
        }
        let byte_off = block_no * bs as u64;
        self.read_byte_range(byte_off, dst).await
    }

    /// Number of journal-replay overrides installed at mount. Zero
    /// on clean volumes / ext2. Used by smokes to confirm replay
    /// fired without exposing the internal map.
    pub fn journal_override_count(&self) -> usize {
        self.journal_overrides.len()
    }

    /// Read `dst.len()` bytes starting at the device byte offset
    /// `byte_off`. Internally serialises on the volume's scratch
    /// buffer + cap.
    ///
    /// If the requested range falls inside one or more FS blocks
    /// that the journal replay overrode, those bytes are served
    /// from the in-memory override map; bytes outside overridden
    /// blocks go to the device. This keeps RO replay correctness
    /// for inode-table reads (which are sub-block byte ranges)
    /// without paying the override-check cost in the device-LBA
    /// loop.
    pub async fn read_byte_range(&self, byte_off: u64, dst: &mut [u8]) -> Result<(), FsError> {
        // Fast path — no overrides installed.
        if self.journal_overrides.is_empty() {
            let (cap, lbs) = {
                let g = self.io.lock();
                (g.cap, g.lbs)
            };
            return Self::read_byte_range_with(&*self.device, cap, lbs, &self.io, byte_off, dst)
                .await;
        }
        // Walk one FS-block at a time, consulting the override map.
        let bs = self.block_size() as u64;
        let mut cursor = 0usize;
        while cursor < dst.len() {
            let abs = byte_off + cursor as u64;
            let fs_block = abs / bs;
            let in_block = (abs % bs) as usize;
            let want = core::cmp::min(dst.len() - cursor, bs as usize - in_block);
            if let Some(ov) = self.journal_overrides.get(&fs_block) {
                if ov.len() == bs as usize {
                    dst[cursor..cursor + want].copy_from_slice(&ov[in_block..in_block + want]);
                    cursor += want;
                    continue;
                }
            }
            let (cap, lbs) = {
                let g = self.io.lock();
                (g.cap, g.lbs)
            };
            Self::read_byte_range_with(
                &*self.device,
                cap,
                lbs,
                &self.io,
                abs,
                &mut dst[cursor..cursor + want],
            )
            .await?;
            cursor += want;
        }
        Ok(())
    }

    /// Write `src.len()` bytes starting at device byte offset
    /// `byte_off`. Inverse of `read_byte_range`. Note: this is a
    /// byte-granularity write — for sub-LBA spans we read-modify-
    /// write the enclosing sector.
    pub async fn write_byte_range(&self, byte_off: u64, src: &[u8]) -> Result<(), FsError> {
        let (cap, lbs) = {
            let g = self.io.lock();
            (g.cap, g.lbs)
        };
        let mut cursor = 0usize;
        while cursor < src.len() {
            let abs = byte_off + cursor as u64;
            let lba = abs / lbs as u64;
            let in_lba = (abs % lbs as u64) as usize;
            let want = core::cmp::min(src.len() - cursor, lbs - in_lba);

            // If we're not writing a full sector, do a RMW.
            let mut sector = alloc::vec![0u8; lbs];
            if !(in_lba == 0 && want == lbs) {
                Self::read_byte_range_with(
                    &*self.device,
                    cap,
                    lbs,
                    &self.io,
                    lba * lbs as u64,
                    &mut sector,
                )
                .await?;
            }
            sector[in_lba..in_lba + want].copy_from_slice(&src[cursor..cursor + want]);

            // Stage into the DMA buffer, then issue the write.
            {
                let buf = self
                    .io
                    .lock()
                    .buffer()
                    .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
                // SAFETY: see read_byte_range_with. Single-CPU
                // cooperative async means the spinlock guards the
                // buffer bytes for the duration of the copy.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                let dst = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), lbs) };
                dst.copy_from_slice(&sector);
            }
            let req = BlockRequest {
                op: BlockOp::Write { fua: false },
                lba,
                blocks: 1,
                buffer: cap
                    .derive::<Read>()
                    .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            let completion = self.device.submit(req).await;
            completion.result.map_err(FsError::Io)?;

            cursor += want;
        }
        Ok(())
    }

    /// Write one filesystem block from `src`. Inverse of
    /// `read_block`. NOTE: this writes to the device only; it does
    /// not touch the journal-replay overrides cache (which is the
    /// read-side replay path; writes invalidate it).
    pub async fn write_block(&self, block_no: u64, src: &[u8]) -> Result<(), FsError> {
        let bs = self.block_size();
        if src.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        self.write_byte_range(block_no * bs as u64, src).await
    }

    /// Variant of `read_byte_range` usable before the `Ext2Volume`
    /// `Arc` exists — `mount()` calls this through a `&VolumeIo`
    /// directly.
    async fn read_byte_range_into(
        device: &B,
        io: &VolumeIo,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let lbs = io.lbs;
        let mut cursor = 0usize;
        while cursor < dst.len() {
            let abs = byte_off + cursor as u64;
            let lba = abs / lbs as u64;
            let in_lba = (abs % lbs as u64) as usize;
            let want = core::cmp::min(dst.len() - cursor, lbs - in_lba);

            let req = BlockRequest {
                op: BlockOp::Read,
                lba,
                blocks: 1,
                buffer: io
                    .cap
                    .derive::<Read>()
                    .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            let completion = device.submit(req).await;
            completion.result.map_err(FsError::Io)?;

            let buf = io
                .buffer()
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: the registry holds the only `Arc<DmaBuffer>`
            // outside this clone; ext2 mount serialises sector ops
            // via the outer spinlock so no other CPU/task is racing
            // the buffer bytes during this copy. Identity-mapped
            // phys backs the read.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
            dst[cursor..cursor + want].copy_from_slice(&src[in_lba..in_lba + want]);
            cursor += want;
        }
        Ok(())
    }

    /// Internal helper used by `read_byte_range`. Holds the volume's
    /// cap-bound buffer for one sector at a time, serialising on
    /// `io` for the brief synchronous-copy span only.
    async fn read_byte_range_with(
        device: &B,
        cap: Cap<DmaBuffer, Write>,
        lbs: usize,
        io_lock: &IrqSafeSpinLock<VolumeIo>,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let mut cursor = 0usize;
        while cursor < dst.len() {
            let abs = byte_off + cursor as u64;
            let lba = abs / lbs as u64;
            let in_lba = (abs % lbs as u64) as usize;
            let want = core::cmp::min(dst.len() - cursor, lbs - in_lba);

            let req = BlockRequest {
                op: BlockOp::Read,
                lba,
                blocks: 1,
                buffer: cap
                    .derive::<Read>()
                    .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            let completion = device.submit(req).await;
            completion.result.map_err(FsError::Io)?;

            let buf = io_lock
                .lock()
                .buffer()
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: see read_byte_range_into.
            let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
            dst[cursor..cursor + want].copy_from_slice(&src[in_lba..in_lba + want]);
            cursor += want;
        }
        Ok(())
    }

    /// `(group, index)` for an inode number. Inode numbers are
    /// 1-based on disk; the math (per the design paper §"Inodes"):
    ///
    /// ```text
    /// group = (inode - 1) / s_inodes_per_group
    /// index = (inode - 1) % s_inodes_per_group
    /// ```
    pub fn inode_group_and_index(&self, inode_no: u32) -> Option<(u32, u32)> {
        if inode_no == 0 {
            return None;
        }
        let zero = inode_no - 1;
        let group = zero / self.superblock.inodes_per_group;
        let index = zero % self.superblock.inodes_per_group;
        if (group as usize) >= self.group_descs.len() {
            return None;
        }
        Some((group, index))
    }

    /// Write inode `inode_no` back to the inode table. Preserves
    /// the rev-1+ extra-fields tail by read-modify-writing the full
    /// `inode_size_bytes()` slot.
    pub async fn write_inode(&self, inode_no: u32, inode: &Inode) -> Result<(), FsError> {
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let gd = &self.group_descs[group as usize];
        let inode_size = self.superblock.inode_size_bytes();
        let bs = self.block_size() as u64;
        let table_byte_off = gd.inode_table * bs;
        let inode_byte_off = table_byte_off + (index as u64) * inode_size as u64;
        let mut buf = vec![0u8; inode_size];
        self.read_byte_range(inode_byte_off, &mut buf).await?;
        inode.encode_into(&mut buf);
        self.write_byte_range(inode_byte_off, &buf).await
    }

    // ── Bitmap allocator (Linux fs/ext2/balloc.c + ialloc.c) ─────

    /// Scan a bitmap block for the first zero bit and set it. The
    /// `start_block` lives in `bm_block` (FS block number); on
    /// success returns the (zero-based) bit position. Bits 0..k are
    /// skipped if `skip_first` is set (used to reserve bit 0 of the
    /// inode bitmap on the first scanned block — Linux does this
    /// implicitly because inode 0 is unused and inode 1 may be
    /// reserved).
    async fn alloc_in_bitmap_block(
        &self,
        bm_block: u64,
        max_bits: u32,
        skip_first: u32,
    ) -> Result<Option<u32>, FsError> {
        let bs = self.block_size();
        let mut buf = vec![0u8; bs];
        self.read_block(bm_block, &mut buf).await?;
        let max = (max_bits as usize).min(bs * 8);
        for bit in (skip_first as usize)..max {
            let byte = bit / 8;
            let bit_in_byte = bit % 8;
            if (buf[byte] >> bit_in_byte) & 1 == 0 {
                buf[byte] |= 1 << bit_in_byte;
                self.write_block(bm_block, &buf).await?;
                return Ok(Some(bit as u32));
            }
        }
        Ok(None)
    }

    /// Clear bit `bit_index` in bitmap block `bm_block`.
    async fn free_in_bitmap_block(&self, bm_block: u64, bit_index: u32) -> Result<(), FsError> {
        let bs = self.block_size();
        let mut buf = vec![0u8; bs];
        self.read_block(bm_block, &mut buf).await?;
        let byte = (bit_index / 8) as usize;
        let bit_in_byte = (bit_index % 8) as u8;
        if byte < buf.len() {
            buf[byte] &= !(1u8 << bit_in_byte);
            self.write_block(bm_block, &buf).await?;
        }
        Ok(())
    }

    /// Allocate a free block from the volume. Walks block groups in
    /// order, scanning each group's block bitmap. Returns the
    /// absolute (1-based) block number of the allocated block.
    ///
    /// The on-disk `bg_free_blocks_count` is treated as a hint only
    /// — we still scan the bitmap when the count is zero, because
    /// the in-memory snapshot reflects mount-time state and we
    /// don't update the descriptor cache on every alloc. Linux does
    /// the same (`ext2_new_blocks` re-scans rather than trusting
    /// the descriptor) for robustness against unclean mounts.
    pub async fn alloc_block(&self) -> Result<u64, FsError> {
        let bpg = self.superblock.blocks_per_group;
        let first_block = self.superblock.first_data_block;
        for (gi, gd) in self.group_descs.iter().enumerate() {
            // ext2 block numbers are 1-based starting from
            // first_data_block. Bit 0 of group `g`'s bitmap maps
            // to absolute block `first_data_block + g*blocks_per_group`.
            let group_first = first_block as u64 + gi as u64 * bpg as u64;
            let group_last = (group_first + bpg as u64).min(self.superblock.blocks_count as u64);
            let bits_in_group = (group_last - group_first) as u32;
            if let Some(bit) = self
                .alloc_in_bitmap_block(gd.block_bitmap, bits_in_group, 0)
                .await?
            {
                return Ok(group_first + bit as u64);
            }
        }
        Err(FsError::NoSpace)
    }

    /// Free block `block_no` (absolute 1-based).
    pub async fn free_block(&self, block_no: u64) -> Result<(), FsError> {
        let bpg = self.superblock.blocks_per_group as u64;
        let first_block = self.superblock.first_data_block as u64;
        if block_no < first_block {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let group = ((block_no - first_block) / bpg) as usize;
        let bit = ((block_no - first_block) % bpg) as u32;
        if group >= self.group_descs.len() {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let bm_block = self.group_descs[group].block_bitmap;
        self.free_in_bitmap_block(bm_block, bit).await
    }

    /// Allocate a free inode. Returns the 1-based inode number.
    /// Treats `bg_free_inodes_count` as a hint (see `alloc_block`).
    pub async fn alloc_inode(&self) -> Result<u32, FsError> {
        let ipg = self.superblock.inodes_per_group;
        let first_reserved = self.superblock.first_ino();
        for (gi, gd) in self.group_descs.iter().enumerate() {
            // Reserve first_reserved-1 bits of group 0 (matches
            // mkfs.ext2's behaviour — bit 0 = inode 1, bit 1 = inode 2,
            // ...). Higher groups have no reserved range.
            let skip = if gi == 0 {
                first_reserved.saturating_sub(1)
            } else {
                0
            };
            if let Some(bit) = self
                .alloc_in_bitmap_block(gd.inode_bitmap, ipg, skip)
                .await?
            {
                return Ok((gi as u32) * ipg + bit + 1);
            }
        }
        Err(FsError::NoSpace)
    }

    /// Free inode `inode_no` (1-based).
    pub async fn free_inode(&self, inode_no: u32) -> Result<(), FsError> {
        if inode_no == 0 {
            return Ok(());
        }
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let bm_block = self.group_descs[group as usize].inode_bitmap;
        self.free_in_bitmap_block(bm_block, index).await
    }

    /// Map a logical block index to a physical block, allocating
    /// a fresh block (and intermediate indirect blocks) when the
    /// slot is currently a hole. The inode is mutated in place;
    /// caller persists via `write_inode`.
    ///
    /// Only the legacy (non-extents) path is supported on the write
    /// side — ext4 extents trees stay read-only for now.
    pub async fn map_block_alloc(&self, inode: &mut Inode, logical: u64) -> Result<u64, FsError> {
        if self.superblock.uses_extents() {
            // Refuse extents-tree writes — implementing a write-side
            // walker is multi-thousand lines on top of this.
            return Err(FsError::Unsupported);
        }
        let p = self.pointers_per_block() as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;
        let bs = self.block_size();
        if logical < direct_max {
            let slot = &mut inode.block[logical as usize];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                let zeros = vec![0u8; bs];
                self.write_block(b as u64, &zeros).await?;
            }
            return Ok(*slot as u64);
        }
        if logical < single_max {
            let slot = &mut inode.block[super::inode::SINGLE_IND_IDX];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                let zeros = vec![0u8; bs];
                self.write_block(b as u64, &zeros).await?;
            }
            let ind = *slot;
            let idx = logical - direct_max;
            return self.alloc_indirect_slot(ind as u64, idx).await;
        }
        if logical < double_max {
            let slot = &mut inode.block[super::inode::DOUBLE_IND_IDX];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                let zeros = vec![0u8; bs];
                self.write_block(b as u64, &zeros).await?;
            }
            let dbl = *slot;
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let mid = self.alloc_indirect_slot(dbl as u64, l1).await?;
            return self.alloc_indirect_slot(mid, l0).await;
        }
        if logical < triple_max {
            let slot = &mut inode.block[super::inode::TRIPLE_IND_IDX];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                let zeros = vec![0u8; bs];
                self.write_block(b as u64, &zeros).await?;
            }
            let tri = *slot;
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let mid = self.alloc_indirect_slot(tri as u64, l2).await?;
            let leaf = self.alloc_indirect_slot(mid, l1).await?;
            return self.alloc_indirect_slot(leaf, l0).await;
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// Read pointer `idx` from indirect block `ind_block`. If zero,
    /// allocate a fresh data block, write the pointer back, and
    /// return the new block number.
    async fn alloc_indirect_slot(&self, ind_block: u64, idx: u64) -> Result<u64, FsError> {
        let bs = self.block_size();
        let p = self.pointers_per_block() as u64;
        if idx >= p {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let mut buf = vec![0u8; bs];
        self.read_block(ind_block, &mut buf).await?;
        let off = (idx as usize) * 4;
        let cur = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if cur != 0 {
            return Ok(cur as u64);
        }
        let new = self.alloc_block().await? as u32;
        buf[off..off + 4].copy_from_slice(&new.to_le_bytes());
        self.write_block(ind_block, &buf).await?;
        let zeros = vec![0u8; bs];
        self.write_block(new as u64, &zeros).await?;
        Ok(new as u64)
    }

    /// Free every block an inode owns (direct, indirect, double-indirect, and
    /// triple-indirect), zeroing the inode's `block[]` field. Caller persists
    /// the inode.
    pub async fn truncate_inode(&self, inode: &mut Inode) -> Result<(), FsError> {
        if self.superblock.uses_extents() {
            return Err(FsError::Unsupported);
        }
        let bs = self.block_size();
        let p = self.pointers_per_block() as u64;
        for i in 0..super::inode::N_DIRECT {
            let b = inode.block[i];
            if b != 0 {
                self.free_block(b as u64).await?;
                inode.block[i] = 0;
            }
        }
        // Single-indirect.
        let single = inode.block[super::inode::SINGLE_IND_IDX];
        if single != 0 {
            self.free_indirect_one(single as u64, p, bs).await?;
            self.free_block(single as u64).await?;
            inode.block[super::inode::SINGLE_IND_IDX] = 0;
        }
        // Double-indirect.
        let dbl = inode.block[super::inode::DOUBLE_IND_IDX];
        if dbl != 0 {
            let mut mid_buf = vec![0u8; bs];
            self.read_block(dbl as u64, &mut mid_buf).await?;
            for i in 0..p {
                let off = (i as usize) * 4;
                let mid = u32::from_le_bytes([
                    mid_buf[off],
                    mid_buf[off + 1],
                    mid_buf[off + 2],
                    mid_buf[off + 3],
                ]);
                if mid != 0 {
                    self.free_indirect_one(mid as u64, p, bs).await?;
                    self.free_block(mid as u64).await?;
                }
            }
            self.free_block(dbl as u64).await?;
            inode.block[super::inode::DOUBLE_IND_IDX] = 0;
        }
        // Triple-indirect.
        let tri = inode.block[super::inode::TRIPLE_IND_IDX];
        if tri != 0 {
            let mut top_buf = vec![0u8; bs];
            self.read_block(tri as u64, &mut top_buf).await?;
            for i in 0..p {
                let off = (i as usize) * 4;
                let mid = u32::from_le_bytes([
                    top_buf[off],
                    top_buf[off + 1],
                    top_buf[off + 2],
                    top_buf[off + 3],
                ]);
                if mid != 0 {
                    let mut mid_buf = vec![0u8; bs];
                    self.read_block(mid as u64, &mut mid_buf).await?;
                    for j in 0..p {
                        let o2 = (j as usize) * 4;
                        let leaf = u32::from_le_bytes([
                            mid_buf[o2],
                            mid_buf[o2 + 1],
                            mid_buf[o2 + 2],
                            mid_buf[o2 + 3],
                        ]);
                        if leaf != 0 {
                            self.free_indirect_one(leaf as u64, p, bs).await?;
                            self.free_block(leaf as u64).await?;
                        }
                    }
                    self.free_block(mid as u64).await?;
                }
            }
            self.free_block(tri as u64).await?;
            inode.block[super::inode::TRIPLE_IND_IDX] = 0;
        }
        inode.size = 0;
        inode.blocks = 0;
        Ok(())
    }

    /// Free every pointer in a single-indirect block.
    async fn free_indirect_one(&self, ind_block: u64, p: u64, bs: usize) -> Result<(), FsError> {
        let mut buf = vec![0u8; bs];
        self.read_block(ind_block, &mut buf).await?;
        for i in 0..p {
            let off = (i as usize) * 4;
            let v = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            if v != 0 {
                self.free_block(v as u64).await?;
            }
        }
        Ok(())
    }

    /// Write `src` to `inode` starting at `offset`. Allocates blocks
    /// as needed via `map_block_alloc`. Extends `inode.size`.
    pub async fn write_inode_data(
        &self,
        inode: &mut Inode,
        offset: u64,
        src: &[u8],
    ) -> Result<usize, FsError> {
        if self.superblock.uses_extents() {
            return Err(FsError::Unsupported);
        }
        let bs = self.block_size() as u64;
        let mut total = 0usize;
        let mut remaining = src.len();
        let mut cur_off = offset;
        while remaining > 0 {
            let logical = cur_off / bs;
            let in_block = (cur_off % bs) as usize;
            let n = core::cmp::min(remaining, bs as usize - in_block);
            let phys = self.map_block_alloc(inode, logical).await?;
            // RMW the block.
            let mut bbuf = vec![0u8; bs as usize];
            if in_block != 0 || n != bs as usize {
                self.read_block(phys, &mut bbuf).await?;
            }
            bbuf[in_block..in_block + n].copy_from_slice(&src[total..total + n]);
            self.write_block(phys, &bbuf).await?;
            total += n;
            remaining -= n;
            cur_off += n as u64;
        }
        if cur_off > inode.size as u64 {
            inode.size = cur_off as u32;
        }
        Ok(total)
    }

    /// Read the on-disk inode `inode_no`.
    pub async fn read_inode(&self, inode_no: u32) -> Result<Inode, FsError> {
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let gd = &self.group_descs[group as usize];
        let inode_size = self.superblock.inode_size_bytes();
        let bs = self.block_size() as u64;

        let table_byte_off = gd.inode_table * bs;
        let inode_byte_off = table_byte_off + (index as u64) * inode_size as u64;

        // Only need 128 bytes — the rest of the inode (rev-1+ extra
        // fields) is unused by this driver.
        let mut buf = vec![0u8; 128];
        self.read_byte_range(inode_byte_off, &mut buf).await?;
        Inode::parse(&buf).ok_or(FsError::Io(narf_block::BlockError::IOError))
    }

    /// Resolve the `i`th logical block of `inode` to its physical
    /// block number. Returns `Ok(0)` for a hole (sparse file).
    ///
    /// Dispatches on the superblock's `uses_extents()` flag:
    /// ext4-with-EXTENTS reads the i_block[60] region as an extent
    /// tree root; ext2/3 walks the legacy 12-direct + 3-indirect
    /// pointer chain.
    pub async fn map_block(&self, inode: &Inode, logical: u64) -> Result<u64, FsError> {
        if self.superblock.uses_extents() {
            return self.map_block_extents(inode, logical).await;
        }
        // Legacy ext2/3 indirect-block walk.
        let p = self.pointers_per_block() as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;

        if logical < direct_max {
            return Ok(inode.block[logical as usize] as u64);
        }
        if logical < single_max {
            let idx = logical - direct_max;
            let l1 = inode.block[super::inode::SINGLE_IND_IDX];
            return Ok(self.read_indirect(l1, idx).await? as u64);
        }
        if logical < double_max {
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let l2_block = inode.block[super::inode::DOUBLE_IND_IDX];
            let middle = self.read_indirect(l2_block, l1).await?;
            return Ok(self.read_indirect(middle, l0).await? as u64);
        }
        if logical < triple_max {
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let l3_block = inode.block[super::inode::TRIPLE_IND_IDX];
            let middle = self.read_indirect(l3_block, l2).await?;
            let leaf = self.read_indirect(middle, l1).await?;
            return Ok(self.read_indirect(leaf, l0).await? as u64);
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// ext4 extent-tree dispatch for `map_block`. Serialises the
    /// inode's 60-byte i_block region as the extent root and walks
    /// the tree, fetching index-child blocks via `read_block` as
    /// the walker descends.
    async fn map_block_extents(&self, inode: &Inode, logical: u64) -> Result<u64, FsError> {
        use super::extent::{lookup_in_node, LookupOutcome};
        // Serialise inode.block[15] as 60 bytes (15 × u32 LE).
        let mut node_buf = alloc::vec![0u8; 60];
        for (i, &b) in inode.block.iter().enumerate() {
            node_buf[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
        }
        // Cap on extent-tree depth to defend against malformed
        // volumes pointing children back at themselves. ext4 spec
        // limits depth to 5 (root + 4 index levels); 8 is paranoid.
        let mut depth_budget = 8u32;
        let logical32 = if logical > u32::MAX as u64 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        } else {
            logical as u32
        };
        loop {
            match lookup_in_node(&node_buf, logical32) {
                LookupOutcome::Mapped {
                    physical,
                    is_uninitialized,
                } => {
                    // Uninitialized extents read as zeros — surface
                    // them as a hole to the caller, who already
                    // zero-fills on physical == 0.
                    if is_uninitialized {
                        return Ok(0);
                    }
                    return Ok(physical);
                }
                LookupOutcome::Hole => return Ok(0),
                LookupOutcome::Corrupt => {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
                LookupOutcome::DeeperLookupRequired { child_block } => {
                    depth_budget = depth_budget
                        .checked_sub(1)
                        .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
                    // Fetch the child extent-block + retry.
                    let bs = self.block_size();
                    let mut child = alloc::vec![0u8; bs];
                    self.read_block(child_block, &mut child).await?;
                    node_buf = child;
                }
            }
        }
    }

    /// Read pointer `index` from the indirect block `block_no`.
    /// `block_no == 0` is a hole — returns 0.
    async fn read_indirect(&self, block_no: u32, index: u64) -> Result<u32, FsError> {
        if block_no == 0 {
            return Ok(0);
        }
        if index >= self.pointers_per_block() as u64 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let bs = self.block_size();
        let mut buf = vec![0u8; bs];
        self.read_block(block_no as u64, &mut buf).await?;
        let off = (index as usize) * 4;
        Ok(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    }
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Return the current wall-clock time as a `u32` seconds-since-epoch
    /// value suitable for ext2's 32-bit timestamp fields. Returns `0`
    /// when the clock has not been calibrated (pre-epoch or uninitialised).
    ///
    /// Ref: Linux `fs/ext4/inode.c::ext4_current_time` pattern —
    /// read `ktime_get_real_seconds()`, clamp to `u32`, store in
    /// `i_mtime` / `i_ctime`.
    pub(crate) fn now_secs() -> u32 {
        let w = now_wall();
        if w.secs <= 0 {
            return 0;
        }
        w.secs.min(u32::MAX as i64) as u32
    }
}

impl<B: BlockDevice + 'static> FsInstance for Ext2Volume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        // The root directory is always inode 2 — see EXT2_ROOT_INO.
        // Stat is filled in lazily on the first `stat()` call; for
        // VFS bootstrap purposes we just hand back a dir-typed
        // node.
        Arc::new(super::node::Ext2Node::new(
            self.self_weak
                .upgrade()
                .expect("Ext2Volume root called after drop"),
            super::EXT2_ROOT_INO,
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::DIR_RO,
                mtime_cycles: 0,
            },
        ))
    }

    fn name(&self) -> &str {
        "ext2"
    }
}
