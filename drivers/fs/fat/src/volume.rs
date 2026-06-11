//! FAT Volume management.
//!
//! Clean-room implementation. Volume layout, BPB / FAT region math,
//! cluster-to-LBA mapping, FSInfo accounting, and the cluster-chain
//! allocator/free routines are all derived strictly from the public
//! references below — no GPL fs/fat/* (Linux) or LGPL FatFs sources
//! were consulted while writing this file.
//!
//! References:
//! - Microsoft FAT File System Specification (FATGEN v1.03), §3 (BPB),
//!   §4 (FAT region math), §5 (FSInfo).
//!   <https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf>
//! - UEFI Specification v2.10 §13.3 (FAT File System Format).
//!   <https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format>
//! - OSDev Wiki, "FAT" (algorithmic descriptions only — no code copied).
//!   <https://wiki.osdev.org/FAT>

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{DirOps, FsError, FsInstance};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::sync::IrqSafeSpinLock;

use super::bpb::{Bpb, Fat32ExtBpb};
use super::fsinfo::FsInfo;
use super::FatVersion;

/// Cap → DmaBuffer pair owned by a FatVolume. The cap is minted
/// once at `mount()` via `narf_io::register_with_cap` and is the
/// load-bearing identifier in every `BlockRequest::buffer`. Drop
/// calls `unregister`, which bumps the epoch + frees the registry
/// slot + releases the underlying frame.
#[derive(Debug)]
struct VolumeIo {
    /// Owning cap for the registered DMA scratch buffer. We hold
    /// the `Write`-typed authority so we can mutate the buffer
    /// before submitting writes; reads derive a `Read` cap from
    /// this on the fly (`derive` does NOT bump the epoch and does
    /// NOT allocate a new object-table slot — see
    /// `capabilities::Cap::derive` for the contract).
    cap: Cap<DmaBuffer, Write>,
    /// Logical block size — every transfer is exactly this many
    /// bytes. Cached so the helpers don't have to re-query the
    /// device on every op.
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

#[derive(Debug)]
pub struct FatVolume<B: BlockDevice> {
    pub device: Arc<B>,
    pub bpb: Bpb,
    pub fat32_ext: Option<Fat32ExtBpb>,
    pub fsinfo: IrqSafeSpinLock<Option<FsInfo>>,
    pub version: FatVersion,
    pub domain: DomainId,
    pub self_weak: Weak<FatVolume<B>>,
    /// Per-volume scratch buffer + cap. Wrapped in a spinlock so
    /// every sector op holds it for the synchronous-copy span only
    /// and never across an `await` (the lock would otherwise
    /// deadlock under cooperative async). FAT operations are
    /// inherently sequential — the lock contention is not a hot
    /// concern.
    io: IrqSafeSpinLock<VolumeIo>,
}

impl<B: BlockDevice + 'static> FatVolume<B> {
    /// Mount a FAT volume by reading sector 0 (the BPB), validating
    /// the 0xAA55 signature, detecting FAT12/16/32 by cluster
    /// count, and (for FAT32) loading the FSInfo sector.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let lbs = device.logical_block_size() as usize;
        let buffer = alloc_coherent(lbs, domain)
            .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap, lbs };

        // BPB — sector 0.
        let mut bpb_bytes = vec![0u8; lbs];
        Self::read_sector_into(&*device, &io, 0, &mut bpb_bytes).await?;

        if u16::from_le_bytes([bpb_bytes[510], bpb_bytes[511]]) != 0xAA55 {
            unregister(io.cap);
            core::mem::forget(io); // unregister already ran; skip Drop
            return Err(FsError::Unsupported);
        }

        // SAFETY: Bpb is `#[repr(C, packed)]` and the first
        // `size_of::<Bpb>()` bytes of any FAT BPB exactly mirror
        // its layout — the Microsoft spec literally specifies the
        // on-disk byte order. The bytes were just read from disk
        // into a heap buffer we own, so the read is a plain memcpy
        // through a properly-aligned u8 source.
        let bpb: Bpb = unsafe { core::ptr::read_unaligned(bpb_bytes.as_ptr() as *const Bpb) };

        let fat32_ext = if bpb.fat_sz_16 == 0 {
            // SAFETY: Fat32ExtBpb sits at offset 36 of the BPB on a
            // FAT32 volume; we only enter this branch when fat_sz_16
            // is zero, which the spec calls out as the FAT32 marker.
            // The packed layout matches FATGEN §3 verbatim.
            let ext: Fat32ExtBpb = unsafe {
                core::ptr::read_unaligned(bpb_bytes.as_ptr().add(36) as *const Fat32ExtBpb)
            };
            Some(ext)
        } else {
            None
        };

        let version = bpb.detect_version(fat32_ext.as_ref());

        let mut fsinfo = None;
        if version == FatVersion::Fat32 {
            if let Some(ref ext) = fat32_ext {
                let mut info_bytes = vec![0u8; lbs];
                if Self::read_sector_into(&*device, &io, ext.fs_info as u64, &mut info_bytes)
                    .await
                    .is_ok()
                {
                    // SAFETY: same packed-layout argument as Bpb.
                    let info: FsInfo =
                        unsafe { core::ptr::read_unaligned(info_bytes.as_ptr() as *const FsInfo) };
                    if info.is_valid() {
                        fsinfo = Some(info);
                    }
                }
            }
        }

        Ok(Arc::new_cyclic(|self_weak| FatVolume {
            device,
            bpb,
            fat32_ext,
            fsinfo: IrqSafeSpinLock::new(fsinfo),
            version,
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
        }))
    }

    pub fn first_data_sector(&self) -> u32 {
        let root_dir_sectors =
            (self.bpb.root_ent_cnt as u32 * 32).div_ceil(self.bpb.bytes_per_sec as u32);
        let fat_sz = self.bpb.fat_size(self.fat32_ext.as_ref());
        self.bpb.rsvd_sec_cnt as u32 + (self.bpb.num_fats as u32 * fat_sz) + root_dir_sectors
    }

    pub fn first_sector_of_cluster(&self, cluster: u32) -> u32 {
        ((cluster - 2) * self.bpb.sec_per_clus as u32) + self.first_data_sector()
    }

    pub fn total_data_clusters(&self) -> u32 {
        let root_dir_sectors =
            (self.bpb.root_ent_cnt as u32 * 32).div_ceil(self.bpb.bytes_per_sec as u32);
        let fat_sz = self.bpb.fat_size(self.fat32_ext.as_ref());
        let data_sectors = self.bpb.total_sectors()
            - (self.bpb.rsvd_sec_cnt as u32
                + (self.bpb.num_fats as u32 * fat_sz)
                + root_dir_sectors);
        data_sectors / self.bpb.sec_per_clus as u32
    }

    pub fn sector_of_fat_entry(&self, cluster: u32) -> (u32, usize) {
        let fat_offset = match self.version {
            FatVersion::Fat12 => cluster + (cluster / 2),
            FatVersion::Fat16 => cluster * 2,
            FatVersion::Fat32 => cluster * 4,
        };
        let sec_num = self.bpb.rsvd_sec_cnt as u32 + (fat_offset / self.bpb.bytes_per_sec as u32);
        let ent_offset = (fat_offset % self.bpb.bytes_per_sec as u32) as usize;
        (sec_num, ent_offset)
    }

    /// Issue a one-sector read into `dst`. `dst` must be exactly
    /// the device's logical block size; shorter slices return
    /// `Io(InvalidRange)`. Internally serialises on the volume's
    /// scratch buffer + cap.
    pub async fn read_sector(&self, lba: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let lbs = self.io.lock().lbs;
        if dst.len() != lbs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        // We can't hold the spinlock across the await, so snapshot
        // the cap (it's `Copy`), do the I/O, then re-acquire to
        // copy out of the registered buffer.
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
        // SAFETY: the registry holds the only `Arc<DmaBuffer>`
        // outside this clone; FAT serialises sector ops via the
        // outer spinlock so no other CPU/task is racing the buffer
        // bytes during this copy. Identity-mapped phys backs the
        // read.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
        dst.copy_from_slice(src);
        Ok(())
    }

    /// Issue a one-sector FUA write from `src`. Same length contract
    /// as [`read_sector`].
    pub async fn write_sector(&self, lba: u64, src: &[u8]) -> Result<(), FsError> {
        let lbs = self.io.lock().lbs;
        if src.len() != lbs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        // Stage data into the volume's registered buffer.
        let cap = {
            let g = self.io.lock();
            let buf = g
                .buffer()
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: see read_sector — same single-CPU
            // cooperative serialisation.
            let dst = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), lbs) };
            dst.copy_from_slice(src);
            g.cap
        };
        let req = BlockRequest {
            op: BlockOp::Write { fua: true },
            lba,
            blocks: 1,
            buffer: cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        let completion = self.device.submit(req).await;
        completion.result.map_err(FsError::Io)
    }

    /// `read_sector` variant usable before the `FatVolume` Arc
    /// exists — `mount()` calls this through a `&VolumeIo`
    /// directly. Same contract as [`read_sector`].
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

    pub async fn next_cluster(&self, cluster: u32) -> Result<super::fat::FatEntry, FsError> {
        let (sec_num, ent_offset) = self.sector_of_fat_entry(cluster);
        let lbs = self.io.lock().lbs;
        let mut buf = vec![0u8; lbs];
        self.read_sector(sec_num as u64, &mut buf).await?;
        Ok(super::fat::parse_entry(self.version, ent_offset, &buf))
    }

    pub async fn update_fat_entry(&self, cluster: u32, value: u32) -> Result<(), FsError> {
        let (sec_num, ent_offset) = self.sector_of_fat_entry(cluster);
        let lbs = self.io.lock().lbs;
        let mut buf = vec![0u8; lbs];
        self.read_sector(sec_num as u64, &mut buf).await?;
        super::fat::write_entry(self.version, ent_offset, &mut buf, value);
        let fat_sz = self.bpb.fat_size(self.fat32_ext.as_ref());
        for i in 0..self.bpb.num_fats {
            let fat_sec = sec_num + (i as u32 * fat_sz);
            self.write_sector(fat_sec as u64, &buf).await?;
        }
        Ok(())
    }

    pub async fn allocate_cluster(&self) -> Result<u32, FsError> {
        let hint = {
            let info = self.fsinfo.lock();
            info.as_ref().map(|i| i.nxt_free).unwrap_or(2)
        };
        let mut cluster = if hint >= 2 { hint } else { 2 };
        let total = self.total_data_clusters() + 2;
        let start_cluster = cluster;
        loop {
            match self.next_cluster(cluster).await? {
                super::fat::FatEntry::Free => {
                    let eoc = match self.version {
                        FatVersion::Fat12 => 0x0FFF,
                        FatVersion::Fat16 => 0xFFFF,
                        FatVersion::Fat32 => 0x0FFFFFFF,
                    };
                    self.update_fat_entry(cluster, eoc).await?;
                    {
                        let mut info = self.fsinfo.lock();
                        if let Some(ref mut i) = *info {
                            i.nxt_free = cluster + 1;
                            if i.free_count != 0xFFFFFFFF {
                                i.free_count = i.free_count.saturating_sub(1);
                            }
                        }
                    }
                    self.flush_fsinfo().await?;
                    return Ok(cluster);
                }
                _ => {
                    cluster += 1;
                    if cluster >= total {
                        cluster = 2;
                    }
                    if cluster == start_cluster {
                        return Err(FsError::Busy);
                    }
                }
            }
        }
    }

    pub async fn free_cluster(&self, cluster: u32) -> Result<(), FsError> {
        self.update_fat_entry(cluster, 0).await?;
        {
            let mut info = self.fsinfo.lock();
            if let Some(ref mut i) = *info {
                // 0xFFFFFFFF is the FSInfo "unknown free count" sentinel; a
                // saturating add keeps it pinned at the sentinel and otherwise
                // increments by one.
                i.free_count = i.free_count.saturating_add(1);
                if cluster < i.nxt_free {
                    i.nxt_free = cluster;
                }
            }
        }
        self.flush_fsinfo().await?;
        Ok(())
    }

    pub async fn flush_fsinfo(&self) -> Result<(), FsError> {
        let lba = if let Some(ref ext) = self.fat32_ext {
            ext.fs_info as u64
        } else {
            return Ok(());
        };
        let lbs = self.io.lock().lbs;
        let mut buf: Vec<u8> = vec![0u8; lbs];
        let snapshot = match *self.fsinfo.lock() {
            Some(ref i) => *i,
            None => return Ok(()),
        };
        // SAFETY: FsInfo is `#[repr(C, packed)]` with size <= one
        // sector; the packed layout is the on-disk format. Source
        // is a stack copy we just took, dest is a fresh heap slice.
        let info_bytes = unsafe {
            core::slice::from_raw_parts(
                &snapshot as *const FsInfo as *const u8,
                core::mem::size_of::<FsInfo>(),
            )
        };
        let n = info_bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&info_bytes[..n]);
        self.write_sector(lba, &buf).await?;
        Ok(())
    }
}

impl<B: BlockDevice + 'static> FsInstance for FatVolume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let first_cluster = if self.version == super::FatVersion::Fat32 {
            self.fat32_ext.as_ref().unwrap().root_clus
        } else {
            0 // FAT12/16: root sits in the fixed root directory region.
        };
        Arc::new(super::node::FatNode::new(
            self.self_weak
                .upgrade()
                .expect("FatVolume root called after drop"),
            first_cluster,
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::DIR_RO,
                mtime_cycles: 0,
            },
            None,
        ))
    }

    fn name(&self) -> &str {
        match self.version {
            FatVersion::Fat12 => "fat12",
            FatVersion::Fat16 => "fat16",
            FatVersion::Fat32 => "fat32",
        }
    }
}
