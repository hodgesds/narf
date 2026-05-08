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
    entry_type, AllocationBitmapEntry, StreamExtensionEntry, UpcaseTableEntry,
    DIR_ENTRY_SIZE,
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
            let lba =
                boot.cluster_heap_offset as u64
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
                            sector_buf.as_ptr().add(off) as *const UpcaseTableEntry,
                        )
                    };
                    let first_cluster = upcase.first_cluster;
                    let data_length = upcase.data_length;
                    // Read the table stream from the cluster heap.
                    // Up-case tables on small images are usually
                    // contiguous (NoFatChain semantically), but
                    // §7.2 doesn't actually expose a NoFatChain
                    // flag here — we walk the FAT.
                    return Self::read_upcase_stream(
                        device,
                        io,
                        boot,
                        first_cluster,
                        data_length,
                    )
                    .await;
                }
            }

            sector_in_cluster += 1;
            sectors_scanned += 1;
            if sector_in_cluster >= spc {
                sector_in_cluster = 0;
                // Walk to the next cluster in the root chain.
                let (fat_sec, fat_off) =
                    fat::entry_location(boot.fat_offset, bps, cluster);
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
                bytes[written as usize..written as usize + n]
                    .copy_from_slice(&sector_buf[..n]);
                written += n as u64;
            }
            if written < data_length {
                let (fat_sec, fat_off) =
                    fat::entry_location(boot.fat_offset, bps, cluster);
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

    /// Locate the §7.1 Allocation Bitmap directory entry by
    /// scanning the root directory. Returned as the (first_cluster,
    /// data_length) pair so callers can read the bitmap stream.
    /// Currently unused by the read-only mount; kept for the
    /// future write path. (TODO: bitmap-backed allocator.)
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
                            sector_buf.as_ptr().add(off) as *const AllocationBitmapEntry,
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
