//! MINIX volume management.
//!
//! Clean-room. Layout / region-math derives from:
//! - Tanenbaum, *Operating Systems: Design and Implementation*
//!   (1st ed., Ch. 5) — defines the block ordering: boot block,
//!   superblock, inode bitmap, zone bitmap, inode table, data
//!   zones; and that the superblock lives at byte offset 1024.
//! - Tanenbaum & Bos, *Modern Operating Systems* (4th ed.), §4.6 —
//!   covers V3 / `s_block_size`.
//!
//! The driver issues **logical-block-sized** reads against the
//! underlying `BlockDevice`. MINIX block size (1 KiB / 4 KiB) is
//! independent of device LBS (512 / 4096); we read enough
//! consecutive sectors to cover one MINIX block.
//!
//! Cap-bound DMA: a single `Cap<DmaBuffer, Write>` is minted at
//! `mount()` and reused for every read. `Cap::bootstrap` is never
//! called from a per-call hot path (project memo).
//!
//! TODO: write paths + bitmap allocator.

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{DirOps, FsError, FsInstance};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::sync::IrqSafeSpinLock;

use super::superblock::Superblock;

/// Cap → DmaBuffer pair owned by a MinixVolume. The cap is minted
/// once at `mount()` via `narf_io::register_with_cap` and is the
/// load-bearing identifier in every `BlockRequest::buffer`. Drop
/// calls `unregister`, which bumps the epoch + frees the registry
/// slot + releases the underlying frame.
#[derive(Debug)]
struct VolumeIo {
    /// Owning cap for the registered DMA scratch buffer.
    cap: Cap<DmaBuffer, Write>,
    /// Logical block size of the underlying device — every transfer
    /// is exactly this many bytes.
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

/// Mounted MINIX volume.
#[derive(Debug)]
pub struct MinixVolume<B: BlockDevice> {
    pub device: Arc<B>,
    pub sb: Superblock,
    pub domain: DomainId,
    pub self_weak: Weak<MinixVolume<B>>,
    /// Per-volume scratch buffer + cap. Same lock discipline as the
    /// FAT driver — held synchronously during the copy span only,
    /// never across an `await`.
    io: IrqSafeSpinLock<VolumeIo>,
}

impl<B: BlockDevice + 'static> MinixVolume<B> {
    /// Mount a MINIX volume. Reads the block at byte offset 1024 of
    /// the device, validates the magic, decodes the superblock, and
    /// returns an Arc-owned volume.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let lbs = device.logical_block_size() as usize;
        if lbs == 0 || 1024 % lbs != 0 && lbs % 1024 != 0 {
            // We support LBS that evenly divides 1024 (e.g. 512) or
            // is a multiple of 1024 (e.g. 4096). Anything else is
            // pathological — a 768-byte sector device would force
            // partial-block reads we'd rather not support.
            return Err(FsError::Unsupported);
        }
        let buffer = alloc_coherent(lbs.max(1024), domain)
            .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap, lbs };

        // Superblock lives at byte offset 1024. Read the sector(s)
        // that span it.
        let sb_lba = 1024u64 / lbs as u64;
        let sb_off_in_sector = (1024usize) % lbs;
        // We need at least 28 bytes of superblock; on a 4096-LBS
        // device the whole superblock fits in one sector, on a
        // 512-LBS device it spans 4. Read 1024 bytes (= 2 sectors
        // on a 512-LBS device, or 1 on a 1024+ LBS).
        let sb_bytes = 1024usize;
        let n_sectors = sb_bytes.div_ceil(lbs);
        let mut buf = vec![0u8; n_sectors * lbs];
        for i in 0..n_sectors {
            let offset = i * lbs;
            Self::read_sector_into(&*device, &io, sb_lba + i as u64, &mut buf[offset..offset + lbs])
                .await?;
        }
        let sb = match Superblock::decode(&buf, sb_off_in_sector) {
            Some(sb) => sb,
            None => {
                // Drop io explicitly — its Drop will unregister.
                return Err(FsError::Unsupported);
            }
        };

        Ok(Arc::new_cyclic(|self_weak| MinixVolume {
            device,
            sb,
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
        }))
    }

    /// Read one device sector (LBS bytes) into `dst`. `dst.len()`
    /// must equal LBS.
    pub async fn read_sector(&self, lba: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let lbs = self.io.lock().lbs;
        if dst.len() != lbs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let cap = { self.io.lock().cap };
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
        let completion = self.device.submit(req).await;
        completion.result.map_err(FsError::Io)?;

        let buf = self
            .io
            .lock()
            .buffer()
            .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
        // SAFETY: registry holds the only `Arc<DmaBuffer>` outside this
        // clone; MINIX serialises sector ops via the outer spinlock.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
        dst.copy_from_slice(src);
        Ok(())
    }

    /// Read one MINIX *block* (`sb.block_size` bytes) into `dst`.
    /// `dst.len()` must equal `sb.block_size`. Issues however many
    /// device sector reads are needed to span one MINIX block.
    pub async fn read_block(&self, block_no: u32, dst: &mut [u8]) -> Result<(), FsError> {
        let bs = self.sb.block_size as usize;
        if dst.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let lbs = self.io.lock().lbs;
        let start_lba = block_no as u64 * bs as u64 / lbs as u64;
        if bs >= lbs {
            // MINIX block is a multiple of LBS: read N sectors.
            let n = bs / lbs;
            for i in 0..n {
                let offset = i * lbs;
                self.read_sector(start_lba + i as u64, &mut dst[offset..offset + lbs])
                    .await?;
            }
        } else {
            // MINIX block is smaller than LBS (e.g. 1 KiB block on
            // 4 KiB sector device): read the enclosing sector, then
            // copy the relevant chunk. This is unusual but the spec
            // allows it for V3-with-large-sector volumes.
            let mut sector = vec![0u8; lbs];
            self.read_sector(start_lba, &mut sector).await?;
            let off_in_sector = (block_no as usize * bs) % lbs;
            dst.copy_from_slice(&sector[off_in_sector..off_in_sector + bs]);
        }
        Ok(())
    }

    /// Read one MINIX zone (`sb.zone_size()` bytes). Identical to
    /// `read_block` when `s_log_zone_size == 0` (always, in
    /// practice).
    pub async fn read_zone(&self, zone_no: u32, dst: &mut [u8]) -> Result<(), FsError> {
        let zs = self.sb.zone_size() as usize;
        if dst.len() != zs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let blocks_per_zone = (1u32 << self.sb.log_zone_size as u32) as usize;
        let bs = self.sb.block_size as usize;
        for i in 0..blocks_per_zone {
            let block = zone_no.checked_mul(blocks_per_zone as u32)
                .and_then(|b| b.checked_add(i as u32))
                .ok_or(FsError::Io(narf_block::BlockError::InvalidRange))?;
            self.read_block(block, &mut dst[i * bs..(i + 1) * bs]).await?;
        }
        Ok(())
    }

    /// Read inode `ino` (1-based) from the inode table.
    pub async fn read_inode(&self, ino: u32) -> Result<super::inode::Inode, FsError> {
        let (block, off_in_block) = self
            .sb
            .inode_location(ino)
            .ok_or(FsError::NotFound)?;
        let bs = self.sb.block_size as usize;
        let mut buf = vec![0u8; bs];
        self.read_block(block, &mut buf).await?;
        super::inode::Inode::decode(self.sb.version, &buf, off_in_block as usize)
            .ok_or(FsError::Io(narf_block::BlockError::IOError))
    }

    /// Resolve `block_in_file` (zone-sized index into the file) to
    /// an absolute zone number, walking the direct / indirect /
    /// double-indirect / triple-indirect tables as needed.
    /// Returns `None` for a hole (zero zone pointer along the path).
    pub async fn map_block(
        &self,
        inode: &super::inode::Inode,
        block_in_file: u32,
    ) -> Result<Option<u32>, FsError> {
        use super::inode::{DBL_SLOT, DIRECT_ZONES, IND_SLOT, TRI_SLOT};
        let zpb = self.sb.zone_ptrs_per_block();
        let direct = DIRECT_ZONES as u32;
        if block_in_file < direct {
            let z = inode.zones[block_in_file as usize];
            return Ok(if z == 0 { None } else { Some(z) });
        }
        let mut idx = block_in_file - direct;

        // Single-indirect.
        if idx < zpb {
            let ind = inode.zones[IND_SLOT];
            if ind == 0 {
                return Ok(None);
            }
            return Ok(self.read_zone_ptr(ind, idx).await?);
        }
        idx -= zpb;

        // Double-indirect.
        if idx < zpb * zpb {
            let dbl = inode.zones[DBL_SLOT];
            if dbl == 0 {
                return Ok(None);
            }
            let outer = idx / zpb;
            let inner = idx % zpb;
            let mid = match self.read_zone_ptr(dbl, outer).await? {
                Some(m) => m,
                None => return Ok(None),
            };
            return Ok(self.read_zone_ptr(mid, inner).await?);
        }
        idx -= zpb * zpb;

        // Triple-indirect (V2/V3 only).
        if matches!(self.sb.version, super::MinixVersion::V1) {
            return Ok(None);
        }
        let tri = inode.zones[TRI_SLOT];
        if tri == 0 {
            return Ok(None);
        }
        let outer = idx / (zpb * zpb);
        let mid_idx = (idx / zpb) % zpb;
        let inner = idx % zpb;
        let mid = match self.read_zone_ptr(tri, outer).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let inner_blk = match self.read_zone_ptr(mid, mid_idx).await? {
            Some(i) => i,
            None => return Ok(None),
        };
        Ok(self.read_zone_ptr(inner_blk, inner).await?)
    }

    /// Read the `idx`-th zone pointer from the indirect block at
    /// `block_no`. Returns `None` if the slot is zero (hole).
    async fn read_zone_ptr(&self, block_no: u32, idx: u32) -> Result<Option<u32>, FsError> {
        let bs = self.sb.block_size as usize;
        let mut buf = vec![0u8; bs];
        self.read_block(block_no, &mut buf).await?;
        let zps = self.sb.zone_ptr_size();
        let off = idx as usize * zps;
        if off + zps > bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let z = match self.sb.version {
            super::MinixVersion::V1 => {
                u16::from_le_bytes([buf[off], buf[off + 1]]) as u32
            }
            super::MinixVersion::V2 | super::MinixVersion::V3 => u32::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]),
        };
        Ok(if z == 0 { None } else { Some(z) })
    }

    /// Read up to `dst.len()` bytes from `inode` starting at
    /// `offset`. Holes read back as zero. Returns the number of
    /// bytes read; a return value < `dst.len()` and < remaining file
    /// size is impossible — we always satisfy as much as the file
    /// holds.
    pub async fn read_file(
        &self,
        inode: &super::inode::Inode,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, FsError> {
        let size = inode.size as u64;
        if offset >= size {
            return Ok(0);
        }
        let zs = self.sb.zone_size() as u64;
        let to_read = core::cmp::min(dst.len() as u64, size - offset);
        let mut total = 0usize;
        let mut remaining = to_read as usize;
        let mut cur_off = offset;

        while remaining > 0 {
            let block_in_file = (cur_off / zs) as u32;
            let zone_offset = (cur_off % zs) as usize;
            let n = core::cmp::min(remaining, zs as usize - zone_offset);

            let zone = self.map_block(inode, block_in_file).await?;
            match zone {
                Some(zone_no) => {
                    let mut zbuf = vec![0u8; zs as usize];
                    self.read_zone(zone_no, &mut zbuf).await?;
                    dst[total..total + n]
                        .copy_from_slice(&zbuf[zone_offset..zone_offset + n]);
                }
                None => {
                    // Hole — zero-fill.
                    for b in &mut dst[total..total + n] {
                        *b = 0;
                    }
                }
            }
            total += n;
            remaining -= n;
            cur_off += n as u64;
        }
        Ok(total)
    }

    /// Read the full directory contents of `inode` (which must be a
    /// directory) into a `Vec<u8>` and return it. Sized at
    /// `inode.size` bytes.
    pub async fn read_dir_bytes(
        &self,
        inode: &super::inode::Inode,
    ) -> Result<Vec<u8>, FsError> {
        let mut out = vec![0u8; inode.size as usize];
        let n = self.read_file(inode, 0, &mut out).await?;
        out.truncate(n);
        Ok(out)
    }

    // Helper used during mount(), before the volume Arc exists.
    async fn read_sector_into(
        device: &B,
        io: &VolumeIo,
        lba: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        if dst.len() != io.lbs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
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
        // SAFETY: see read_sector.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), io.lbs) };
        dst.copy_from_slice(src);
        Ok(())
    }
}

impl<B: BlockDevice + 'static> FsInstance for MinixVolume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        // Root inode in MINIX is #1 — NOT 2 (that's ext2). Tanenbaum
        // §5: inode 0 is reserved (always-free in the bitmap), inode
        // 1 is the root directory.
        Arc::new(super::node::MinixNode::new(
            self.self_weak
                .upgrade()
                .expect("MinixVolume root called after drop"),
            1,
        ))
    }

    fn name(&self) -> &str {
        match self.sb.version {
            super::MinixVersion::V1 => "minix1",
            super::MinixVersion::V2 => "minix2",
            super::MinixVersion::V3 => "minix3",
        }
    }
}
