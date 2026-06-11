//! exFAT Volume management.
//!
//! Clean-room. Mount reads sector 0, validates the §3.1.2
//! `EXFAT   ` signature + the §3.1.19 `0xAA55` boot signature,
//! decodes the shift fields, then walks the root directory to find
//! the §7.1 Allocation Bitmap entry and the §7.2 Up-case Table
//! entry. The bitmap is left on disk (we don't need it for read-
//! only mount); the up-case table is decompressed into memory and
//! cached on the volume so all subsequent lookups can do
//! case-insensitive UTF-16 comparison without re-reading it.
//!
//! References:
//! - exFAT file system specification (Microsoft, 2019),
//!   §3.1 Main Boot Sector, §3.3 FAT, §6 Directory Structure,
//!   §7.1 Allocation Bitmap, §7.2 Up-case Table.
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{DirOps, FsError, FsInstance};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::sync::IrqSafeSpinLock;

use super::boot::{ExfatBootSector, BOOT_SIGNATURE};
use super::dir::{
    entry_type, AllocationBitmapEntry, StreamExtensionEntry, UpcaseTableEntry, DIR_ENTRY_SIZE,
};
use super::fat::{self, FatEntry};
use super::upcase::UpcaseTable;

/// Cap → DmaBuffer pair owned by an ExfatVolume. Mirrors the
/// `VolumeIo` pattern from the FAT driver. The cap is minted ONCE
/// at `mount()` via `narf_io::register_with_cap`; never call
/// `Cap::bootstrap` from a hot path (per the project's hot-path
/// caveat).
#[derive(Debug)]
struct VolumeIo {
    /// Owning `Write` cap; reads derive a `Read` cap on the fly
    /// (which doesn't bump the registry epoch).
    cap: Cap<DmaBuffer, Write>,
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

/// Mounted exFAT volume. All on-disk geometry is decoded once at
/// mount and cached as plain fields; the up-case table is loaded
/// once and shared.
#[derive(Debug)]
pub struct ExfatVolume<B: BlockDevice> {
    pub device: Arc<B>,
    pub boot: ExfatBootSector,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub bytes_per_cluster: u32,
    /// Cached up-case table (decompressed). REQUIRED for correct
    /// case-insensitive name comparison — populated during mount.
    pub upcase: Arc<UpcaseTable>,
    pub domain: DomainId,
    pub self_weak: Weak<ExfatVolume<B>>,
    io: IrqSafeSpinLock<VolumeIo>,
}

impl<B: BlockDevice + 'static> ExfatVolume<B> {
    /// Mount an exFAT volume. Reads sector 0, validates the
    /// signatures, walks the root directory cluster chain to load
    /// the up-case table, and returns a ready-to-use Arc.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let lbs = device.logical_block_size() as usize;
        let buffer = alloc_coherent(lbs, domain)
            .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap, lbs };

        // §3.1 Main Boot Sector.
        let mut boot_bytes = vec![0u8; lbs];
        Self::read_sector_into(&*device, &io, 0, &mut boot_bytes).await?;

        // §3.1.19 — trailing 0xAA55.
        if u16::from_le_bytes([boot_bytes[510], boot_bytes[511]]) != BOOT_SIGNATURE {
            unregister(io.cap);
            core::mem::forget(io);
            return Err(FsError::Unsupported);
        }

        // SAFETY: `ExfatBootSector` is `#[repr(C, packed)]` and
        // covers the leading bytes of an exFAT main boot sector
        // exactly per §3.1; we just read those bytes off disk into
        // a heap buffer we own.
        let boot: ExfatBootSector =
            unsafe { core::ptr::read_unaligned(boot_bytes.as_ptr() as *const ExfatBootSector) };

        if !boot.has_exfat_signature() || !boot.shifts_in_range() {
            unregister(io.cap);
            core::mem::forget(io);
            return Err(FsError::Unsupported);
        }

        // Sanity: bytes-per-sector reported by the boot sector
        // must match what the device returned. Refusing the mount
        // is safer than guessing.
        let bytes_per_sector = boot.bytes_per_sector();
        let sectors_per_cluster = boot.sectors_per_cluster();
        let bytes_per_cluster = boot.bytes_per_cluster();
        if bytes_per_sector as usize != lbs {
            unregister(io.cap);
            core::mem::forget(io);
            return Err(FsError::Unsupported);
        }

        // Walk the root directory once at mount to find the
        // up-case table (§7.2). The bitmap entry (§7.1) location
        // is also captured for the future write path; we don't
        // need the bitmap contents for read-only mount.
        let upcase = Self::load_upcase_at_mount(&*device, &io, &boot).await?;

        Ok(Arc::new_cyclic(|self_weak| ExfatVolume {
            device,
            boot,
            bytes_per_sector,
            sectors_per_cluster,
            bytes_per_cluster,
            upcase: Arc::new(upcase),
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
        }))
    }

    /// LBA of the first sector of `cluster` in the cluster heap.
    /// §3.1.8 fixes ClusterHeapOffset and §3.1.10 fixes the first
    /// valid cluster index at 2.
    pub fn first_sector_of_cluster(&self, cluster: u32) -> u64 {
        self.boot.cluster_heap_offset as u64
            + (cluster as u64 - 2) * self.sectors_per_cluster as u64
    }

    /// Read one sector into `dst`. `dst.len()` must equal the
    /// volume's logical block size.
    pub async fn read_sector(&self, lba: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let lbs = self.io.lock().lbs;
        if dst.len() != lbs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        // Snapshot the cap (it's `Copy`); we cannot hold the
        // spinlock across the await.
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
        // SAFETY: Same single-CPU cooperative serialisation as the
        // FAT driver's read_sector — outer spinlock guards the
        // bytes for the duration of the copy.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
        dst.copy_from_slice(src);
        Ok(())
    }

    /// Write one sector (LBS bytes) from `src` to `lba`. Inverse
    /// of `read_sector`.
    pub async fn write_sector(&self, lba: u64, src: &[u8]) -> Result<(), FsError> {
        let lbs = self.io.lock().lbs;
        if src.len() != lbs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        // Stage into the DMA buffer.
        {
            let buf = self
                .io
                .lock()
                .buffer()
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: same single-CPU cooperative serialisation as
            // read_sector.
            let dst = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), lbs) };
            dst.copy_from_slice(src);
        }
        let cap = { self.io.lock().cap };
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
        Ok(())
    }

    /// Pre-`Arc` variant of `read_sector` — `mount()` calls this
    /// through a `&VolumeIo` directly because the volume Arc
    /// doesn't exist yet.
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

    /// Look up the next cluster in a chain via the FAT (§3.3).
    pub async fn next_cluster(&self, cluster: u32) -> Result<FatEntry, FsError> {
        let (sector, byte_in_sector) =
            fat::entry_location(self.boot.fat_offset, self.bytes_per_sector, cluster);
        let lbs = self.io.lock().lbs;
        let mut buf = vec![0u8; lbs];
        self.read_sector(sector, &mut buf).await?;
        Ok(fat::parse_entry(&buf, byte_in_sector))
    }

    /// Read up to `out.len()` bytes from a cluster chain starting
    /// at `start_cluster`, beginning at byte offset `offset` into
    /// the chain. Honours the §7.6.5 NoFatChain flag: if set, the
    /// data is one contiguous extent of `data_length` bytes and
    /// the FAT is not consulted.
    pub async fn read_chain(
        &self,
        start_cluster: u32,
        no_fat_chain: bool,
        data_length: u64,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, FsError> {
        if start_cluster < 2 || offset >= data_length || out.is_empty() {
            return Ok(0);
        }
        let want = (out.len() as u64).min(data_length - offset);
        let mut total: usize = 0;
        let bytes_per_cluster = self.bytes_per_cluster as u64;
        let lbs = self.bytes_per_sector as u64;

        // Cluster index relative to start_cluster.
        let mut cluster_idx_to_skip = offset / bytes_per_cluster;
        let mut byte_in_cluster = offset % bytes_per_cluster;

        // Resolve the starting cluster — for NoFatChain it's just
        // arithmetic; otherwise walk the FAT.
        let mut current_cluster = if no_fat_chain {
            start_cluster + cluster_idx_to_skip as u32
        } else {
            let mut c = start_cluster;
            for _ in 0..cluster_idx_to_skip {
                match self.next_cluster(c).await? {
                    FatEntry::Next(n) => c = n,
                    _ => return Err(FsError::Io(narf_block::BlockError::IOError)),
                }
            }
            c
        };
        let _ = &mut cluster_idx_to_skip;

        let lbs_us = lbs as usize;
        let mut sector_buf = vec![0u8; lbs_us];
        let mut remaining = want;
        while remaining > 0 {
            let lba_start = self.first_sector_of_cluster(current_cluster);
            while byte_in_cluster < bytes_per_cluster && remaining > 0 {
                let sector_in_cluster = byte_in_cluster / lbs;
                let byte_in_sector = (byte_in_cluster % lbs) as usize;
                let lba = lba_start + sector_in_cluster;
                self.read_sector(lba, &mut sector_buf).await?;
                let n = (remaining as usize).min(lbs_us - byte_in_sector);
                out[total..total + n]
                    .copy_from_slice(&sector_buf[byte_in_sector..byte_in_sector + n]);
                total += n;
                remaining -= n as u64;
                byte_in_cluster += n as u64;
            }
            if remaining > 0 {
                byte_in_cluster = 0;
                if no_fat_chain {
                    current_cluster += 1;
                } else {
                    match self.next_cluster(current_cluster).await? {
                        FatEntry::Next(n) => current_cluster = n,
                        _ => break,
                    }
                }
            }
        }
        Ok(total)
    }

    /// Read the entire byte stream described by a (first_cluster,
    /// data_length, no_fat_chain) triple into a freshly-allocated
    /// `Vec`. Used at mount to slurp the up-case table.
    pub async fn read_stream_to_vec(
        &self,
        start_cluster: u32,
        no_fat_chain: bool,
        data_length: u64,
    ) -> Result<Vec<u8>, FsError> {
        let mut out = vec![0u8; data_length as usize];
        let mut got = 0usize;
        while (got as u64) < data_length {
            let n = self
                .read_chain(
                    start_cluster,
                    no_fat_chain,
                    data_length,
                    got as u64,
                    &mut out[got..],
                )
                .await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        out.truncate(got);
        Ok(out)
    }

    /// Walk the root directory at mount time looking for the
    /// up-case table directory entry (§7.2). Returns the
    /// decompressed table. A volume with no up-case entry falls
    /// back to the ASCII-only table.
    async fn load_upcase_at_mount(
        device: &B,
        io: &VolumeIo,
        boot: &ExfatBootSector,
    ) -> Result<UpcaseTable, FsError> {
        let bps = boot.bytes_per_sector();
        let spc = boot.sectors_per_cluster();
        let bytes_per_cluster = (bps as u64) * (spc as u64);
        let mut cluster = boot.first_cluster_of_root_directory;
        let lbs = io.lbs;
        let mut sector_buf = vec![0u8; lbs];

        // Scan up to a safe bound (the up-case table entry sits
        // very early in the root directory on every well-formed
        // exFAT volume). The bound prevents a runaway loop on a
        // corrupt FAT chain.
        const MAX_SECTORS_TO_SCAN: u32 = 1024;
        let mut sectors_scanned: u32 = 0;
        let mut sector_in_cluster: u32 = 0;

        while sectors_scanned < MAX_SECTORS_TO_SCAN {
            let lba = boot.cluster_heap_offset as u64
                + (cluster as u64 - 2) * spc as u64
                + sector_in_cluster as u64;
            Self::read_sector_into(device, io, lba, &mut sector_buf).await?;

            let entries_per_sector = lbs / DIR_ENTRY_SIZE;
            for slot in 0..entries_per_sector {
                let off = slot * DIR_ENTRY_SIZE;
                let etype = sector_buf[off];
                if etype == entry_type::END_OF_DIRECTORY {
                    // Hit the end of the directory before finding
                    // an up-case entry — fall back to ASCII.
                    return Ok(UpcaseTable::ascii_fallback());
                }
                if etype == entry_type::UPCASE_TABLE {
                    // SAFETY: 32-byte packed layout from §7.2;
                    // the bytes were just read off disk into a
                    // heap buffer we own.
                    let upcase: UpcaseTableEntry = unsafe {
                        core::ptr::read_unaligned(
                            sector_buf.as_ptr().add(off) as *const UpcaseTableEntry
                        )
                    };
                    let first_cluster = upcase.first_cluster;
                    let data_length = upcase.data_length;
                    // Read the table stream from the cluster heap.
                    // Up-case tables on small images are usually
                    // contiguous (NoFatChain semantically), but
                    // §7.2 doesn't actually expose a NoFatChain
                    // flag here — we walk the FAT.
                    return Self::read_upcase_stream(device, io, boot, first_cluster, data_length)
                        .await;
                }
            }

            sector_in_cluster += 1;
            sectors_scanned += 1;
            if sector_in_cluster >= spc {
                sector_in_cluster = 0;
                // Walk to the next cluster in the root chain.
                let (fat_sec, fat_off) = fat::entry_location(boot.fat_offset, bps, cluster);
                Self::read_sector_into(device, io, fat_sec, &mut sector_buf).await?;
                match fat::parse_entry(&sector_buf, fat_off) {
                    FatEntry::Next(n) => cluster = n,
                    _ => return Ok(UpcaseTable::ascii_fallback()),
                }
                let _ = bytes_per_cluster;
            }
        }
        Ok(UpcaseTable::ascii_fallback())
    }

    /// Slurp the up-case table stream from the cluster heap by
    /// walking the FAT. (Pre-Arc helper used at mount time.)
    async fn read_upcase_stream(
        device: &B,
        io: &VolumeIo,
        boot: &ExfatBootSector,
        start_cluster: u32,
        data_length: u64,
    ) -> Result<UpcaseTable, FsError> {
        let lbs = io.lbs;
        let bps = boot.bytes_per_sector();
        let spc = boot.sectors_per_cluster();
        let bytes_per_cluster = (bps as u64) * (spc as u64);

        let mut bytes = vec![0u8; data_length as usize];
        let mut written: u64 = 0;
        let mut cluster = start_cluster;
        let mut sector_buf = vec![0u8; lbs];
        while written < data_length {
            let lba_start = boot.cluster_heap_offset as u64 + (cluster as u64 - 2) * spc as u64;
            for s in 0..spc as u64 {
                if written >= data_length {
                    break;
                }
                Self::read_sector_into(device, io, lba_start + s, &mut sector_buf).await?;
                let n = ((data_length - written) as usize).min(lbs);
                bytes[written as usize..written as usize + n].copy_from_slice(&sector_buf[..n]);
                written += n as u64;
            }
            if written < data_length {
                let (fat_sec, fat_off) = fat::entry_location(boot.fat_offset, bps, cluster);
                Self::read_sector_into(device, io, fat_sec, &mut sector_buf).await?;
                match fat::parse_entry(&sector_buf, fat_off) {
                    FatEntry::Next(n) => cluster = n,
                    _ => break,
                }
            }
            let _ = bytes_per_cluster;
        }
        Ok(UpcaseTable::decompress(&bytes))
    }

    // ── Bitmap allocator (§7.1) ─────────────────────────────────

    /// Read one cluster from the cluster heap into `dst`.
    /// `dst.len()` must equal `self.bytes_per_cluster`.
    pub async fn read_cluster(&self, cluster: u32, dst: &mut [u8]) -> Result<(), FsError> {
        if dst.len() != self.bytes_per_cluster as usize {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let lba_start = self.first_sector_of_cluster(cluster);
        let lbs = self.bytes_per_sector as usize;
        for s in 0..self.sectors_per_cluster as u64 {
            let off = (s as usize) * lbs;
            self.read_sector(lba_start + s, &mut dst[off..off + lbs])
                .await?;
        }
        Ok(())
    }

    /// Write one cluster from `src` to the cluster heap. Inverse of
    /// `read_cluster`.
    pub async fn write_cluster(&self, cluster: u32, src: &[u8]) -> Result<(), FsError> {
        if src.len() != self.bytes_per_cluster as usize {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let lba_start = self.first_sector_of_cluster(cluster);
        let lbs = self.bytes_per_sector as usize;
        for s in 0..self.sectors_per_cluster as u64 {
            let off = (s as usize) * lbs;
            self.write_sector(lba_start + s, &src[off..off + lbs])
                .await?;
        }
        Ok(())
    }

    /// Write a FAT entry — used when extending a cluster chain.
    /// §3.3: each FAT entry is a 4-byte little-endian cluster
    /// number; `value` may be a next-cluster pointer or one of the
    /// §3.3.1 sentinels (`FAT_END_OF_CHAIN`, `FAT_BAD_CLUSTER`).
    pub async fn write_fat_entry(&self, cluster: u32, value: u32) -> Result<(), FsError> {
        let (sector, byte_in_sector) =
            fat::entry_location(self.boot.fat_offset, self.bytes_per_sector, cluster);
        let lbs = self.io.lock().lbs;
        let mut buf = vec![0u8; lbs];
        self.read_sector(sector, &mut buf).await?;
        buf[byte_in_sector..byte_in_sector + 4].copy_from_slice(&value.to_le_bytes());
        self.write_sector(sector, &buf).await
    }

    /// Allocate `n` contiguous clusters from the §7.1 Allocation
    /// Bitmap, mark them used, and return the starting cluster
    /// number. Uses a first-fit scan over the bitmap stream. Sets
    /// the new clusters' FAT entries to either `next` (chain) or
    /// `FAT_END_OF_CHAIN` (last).
    ///
    /// On exFAT bit 0 of the bitmap corresponds to cluster 2 (the
    /// first valid data cluster per §3.1.10). Returns
    /// `FsError::NoSpace` when no run of `n` clusters is free.
    pub async fn alloc_clusters(&self, n: u32) -> Result<u32, FsError> {
        if n == 0 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let (bm_first, bm_len) = self
            .locate_bitmap()
            .await?
            .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
        let bytes_per_cluster = self.bytes_per_cluster as u64;
        let cluster_count = self.boot.cluster_count;
        // Stream the bitmap one cluster at a time.
        let mut buf = vec![0u8; self.bytes_per_cluster as usize];
        let mut run_start: Option<u32> = None;
        let mut run_len: u32 = 0;
        let mut bm_cluster = bm_first;
        let mut bm_off: u64 = 0;
        while bm_off < bm_len {
            self.read_cluster(bm_cluster, &mut buf).await?;
            let to_consume = ((bm_len - bm_off) as usize).min(buf.len());
            for (byte_idx, &byte) in buf.iter().enumerate().take(to_consume) {
                for bit in 0..8u32 {
                    let bit_index = (bm_off as u32 * 8) + byte_idx as u32 * 8 + bit;
                    if bit_index >= cluster_count {
                        break;
                    }
                    let cluster = bit_index + 2; // §3.1.10
                    let used = (byte >> bit) & 1 != 0;
                    if used {
                        run_start = None;
                        run_len = 0;
                    } else {
                        if run_start.is_none() {
                            run_start = Some(cluster);
                        }
                        run_len += 1;
                        if run_len == n {
                            // Found enough; mark them and write back.
                            let start = run_start.unwrap();
                            self.set_bitmap_range(bm_first, start, n, true).await?;
                            // Build a chain in the FAT.
                            for i in 0..n {
                                let c = start + i;
                                let v = if i + 1 == n {
                                    fat::FAT_END_OF_CHAIN
                                } else {
                                    start + i + 1
                                };
                                self.write_fat_entry(c, v).await?;
                            }
                            return Ok(start);
                        }
                    }
                }
            }
            bm_off += to_consume as u64;
            // Step to next cluster of the bitmap chain.
            if bm_off < bm_len {
                match self.next_cluster(bm_cluster).await? {
                    FatEntry::Next(c) => bm_cluster = c,
                    _ => return Err(FsError::NoSpace),
                }
            }
            let _ = bytes_per_cluster;
        }
        Err(FsError::NoSpace)
    }

    /// Mark a contiguous run of clusters used/free in the
    /// allocation bitmap. The bitmap stream is treated as a flat
    /// byte sequence indexed by `(cluster - 2)`-th bit.
    pub async fn set_bitmap_range(
        &self,
        bm_first_cluster: u32,
        start_cluster: u32,
        n: u32,
        used: bool,
    ) -> Result<(), FsError> {
        if start_cluster < 2 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        // We do this one byte at a time across the bitmap stream;
        // each cluster of the bitmap holds `bytes_per_cluster` bytes
        // (=8*bytes_per_cluster bits = up to that many clusters
        // represented).
        let bytes_per_cluster = self.bytes_per_cluster as u64;
        for offset in 0..n {
            let bit_index = (start_cluster + offset - 2) as u64;
            let byte_offset = bit_index / 8;
            let bit_in_byte = (bit_index % 8) as u8;
            // Locate which cluster of the bitmap stream holds the
            // byte and at what offset within that cluster.
            let bm_cluster_idx = byte_offset / bytes_per_cluster;
            let off_in_cluster = (byte_offset % bytes_per_cluster) as usize;
            // Walk the bitmap chain to the right cluster.
            let mut current = bm_first_cluster;
            for _ in 0..bm_cluster_idx {
                match self.next_cluster(current).await? {
                    FatEntry::Next(c) => current = c,
                    _ => return Err(FsError::Io(narf_block::BlockError::IOError)),
                }
            }
            let mut buf = vec![0u8; self.bytes_per_cluster as usize];
            self.read_cluster(current, &mut buf).await?;
            if used {
                buf[off_in_cluster] |= 1u8 << bit_in_byte;
            } else {
                buf[off_in_cluster] &= !(1u8 << bit_in_byte);
            }
            self.write_cluster(current, &buf).await?;
        }
        Ok(())
    }

    /// Free a cluster chain starting at `start_cluster`. Walks the
    /// FAT, clearing the bitmap and FAT entry of every cluster in
    /// the chain. Idempotent on already-cleared chains.
    pub async fn free_chain(&self, start_cluster: u32) -> Result<(), FsError> {
        let (bm_first, _bm_len) = self
            .locate_bitmap()
            .await?
            .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
        let mut current = start_cluster;
        let mut steps = 0u32;
        loop {
            let next = self.next_cluster(current).await?;
            self.set_bitmap_range(bm_first, current, 1, false).await?;
            self.write_fat_entry(current, 0).await?;
            match next {
                FatEntry::Next(c) => current = c,
                FatEntry::EndOfChain | FatEntry::Free => break,
                FatEntry::Bad | FatEntry::Reserved(_) => break,
            }
            steps += 1;
            // Cap the walk so a corrupt chain doesn't loop forever.
            if steps > self.boot.cluster_count {
                return Err(FsError::Io(narf_block::BlockError::IOError));
            }
        }
        Ok(())
    }

    /// Locate the §7.1 Allocation Bitmap directory entry by
    /// scanning the root directory. Returned as the (first_cluster,
    /// data_length) pair so callers can read the bitmap stream.
    /// Used by the bitmap allocator above.
    pub async fn locate_bitmap(&self) -> Result<Option<(u32, u64)>, FsError> {
        let lbs = self.io.lock().lbs;
        let mut sector_buf = vec![0u8; lbs];
        let mut cluster = self.boot.first_cluster_of_root_directory;
        let mut sector_in_cluster: u32 = 0;
        let mut scanned: u32 = 0;
        while scanned < 1024 {
            let lba = self.first_sector_of_cluster(cluster) + sector_in_cluster as u64;
            self.read_sector(lba, &mut sector_buf).await?;
            for slot in 0..(lbs / DIR_ENTRY_SIZE) {
                let off = slot * DIR_ENTRY_SIZE;
                let etype = sector_buf[off];
                if etype == entry_type::END_OF_DIRECTORY {
                    return Ok(None);
                }
                if etype == entry_type::ALLOCATION_BITMAP {
                    // SAFETY: 32-byte packed layout from §7.1.
                    let bm: AllocationBitmapEntry = unsafe {
                        core::ptr::read_unaligned(
                            sector_buf.as_ptr().add(off) as *const AllocationBitmapEntry
                        )
                    };
                    let fc = bm.first_cluster;
                    let dl = bm.data_length;
                    return Ok(Some((fc, dl)));
                }
            }
            sector_in_cluster += 1;
            scanned += 1;
            if sector_in_cluster >= self.sectors_per_cluster {
                sector_in_cluster = 0;
                match self.next_cluster(cluster).await? {
                    FatEntry::Next(n) => cluster = n,
                    _ => return Ok(None),
                }
            }
        }
        Ok(None)
    }

    /// Suppress "unused" lint on `StreamExtensionEntry`'s typed
    /// fields when only used through `read_unaligned`.
    #[allow(dead_code)]
    fn _stream_field_anchor(&self, e: &StreamExtensionEntry) -> u64 {
        e.data_length
    }
}

impl<B: BlockDevice + 'static> FsInstance for ExfatVolume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let first_cluster = self.boot.first_cluster_of_root_directory;
        Arc::new(super::node::ExfatNode::new_root(
            self.self_weak
                .upgrade()
                .expect("ExfatVolume::root called after drop"),
            first_cluster,
        ))
    }

    fn name(&self) -> &str {
        "exfat"
    }
}
