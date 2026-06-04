//! FAT Node and Directory/File Operations.
//!
//! Clean-room implementation. Directory scanning (SFN + LFN reassembly,
//! checksum gating, 0xE5/0x00 sentinels), entry creation/deletion,
//! cluster-chain walk for read/write/truncate, "." and ".." emission
//! during mkdir, and rename slot-reuse — all derived strictly from
//! the public Microsoft / UEFI / OSDev references. No GPL Linux
//! `fs/fat/*` or LGPL FatFs sources were consulted.
//!
//! References:
//! - Microsoft FAT File System Specification (FATGEN v1.03):
//!     §6 Directory Structure (32-byte SFN entry layout, attribute
//!     bits, first-cluster split, file-size field).
//!     §7 Long File Names (LFN entry layout, ord byte + 0x40 last-
//!     entry mask, LFN-to-SFN checksum algorithm pseudocode on p.28).
//!   <https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf>
//! - UEFI Specification v2.10 §13.3.
//!   <https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format>
//! - OSDev Wiki, "FAT — Reading the Boot Sector / Directory Table".
//!   <https://wiki.osdev.org/FAT>

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use super::dir::{
    attr, calculate_checksum, to_dos_time, DirEntry as RawDirEntry, LfnEntry, LFN_ENTRY_LAST_MASK,
};
use super::volume::FatVolume;

#[derive(Debug, Copy, Clone)]
pub struct FatNodeState {
    pub first_cluster: u32,
    pub stat: Stat,
}

#[derive(Debug)]
pub struct FatNode<B: BlockDevice> {
    pub volume: Arc<FatVolume<B>>,
    pub state: IrqSafeSpinLock<FatNodeState>,
    pub entry_location: Option<(u64, usize)>, // (LBA, offset in sector)
}

const DIR_ENTRY_SIZE: usize = 32;
const SFN_LEN: usize = 11;

// ── Directory scanner ──────────────────────────────────────────────

/// Walks a FAT directory chain entry-by-entry, reassembling LFN
/// runs into UTF-8 names. The scanner owns a heap-allocated sector
/// buffer (re-loaded from disk via `volume.read_sector` whenever
/// the cursor crosses a sector boundary) — no raw `phys_addr`
/// access leaks out of `volume.rs`.
struct DirectoryScanner<B: BlockDevice> {
    volume: Arc<FatVolume<B>>,
    /// Current cluster (or 0 for the FAT12/16 fixed root region).
    current_cluster: Option<u32>,
    sector_in_cluster: u32,
    entry_in_sector: u32,
    /// Last sector loaded from disk; `None` until the first read.
    sector: Option<(u64, Vec<u8>)>,
    /// Reassembly buffer for the active LFN run (max 255 chars,
    /// rounded up to 256 for slot math).
    lfn_buffer: [u16; 256],
    lfn_len: usize,
    lfn_checksum: u8,
}

impl<B: BlockDevice + 'static> DirectoryScanner<B> {
    fn new(volume: Arc<FatVolume<B>>, first_cluster: u32) -> Self {
        Self {
            volume,
            current_cluster: Some(first_cluster),
            sector_in_cluster: 0,
            entry_in_sector: 0,
            sector: None,
            lfn_buffer: [0; 256],
            lfn_len: 0,
            lfn_checksum: 0,
        }
    }

    /// LBA of the sector currently being scanned.
    fn current_lba(&self) -> Option<u64> {
        let cluster = self.current_cluster?;
        let lbs = self.volume.bpb.bytes_per_sec as u64;
        let _ = lbs;
        if cluster == 0 {
            // FAT12/16 fixed root.
            let root_dir_sectors = ((self.volume.bpb.root_ent_cnt as u32 * 32)
                + (self.volume.bpb.bytes_per_sec as u32 - 1))
                / self.volume.bpb.bytes_per_sec as u32;
            if self.sector_in_cluster >= root_dir_sectors {
                return None;
            }
            let fat_sz = self.volume.bpb.fat_size(self.volume.fat32_ext.as_ref());
            let first_root_sec =
                self.volume.bpb.rsvd_sec_cnt as u32 + (self.volume.bpb.num_fats as u32 * fat_sz);
            Some(first_root_sec as u64 + self.sector_in_cluster as u64)
        } else {
            Some(
                self.volume.first_sector_of_cluster(cluster) as u64 + self.sector_in_cluster as u64,
            )
        }
    }

    async fn ensure_sector_loaded(&mut self, lba: u64) -> Result<(), FsError> {
        let lbs = self.volume.bpb.bytes_per_sec as usize;
        let need_load = match self.sector {
            Some((cached, _)) if cached == lba => false,
            _ => true,
        };
        if need_load {
            let mut buf = vec![0u8; lbs];
            self.volume.read_sector(lba, &mut buf).await?;
            self.sector = Some((lba, buf));
        }
        Ok(())
    }

    async fn next(&mut self) -> Result<Option<(String, RawDirEntry, u64, usize)>, FsError> {
        loop {
            let lba = match self.current_lba() {
                Some(l) => l,
                None => return Ok(None),
            };
            self.ensure_sector_loaded(lba).await?;

            let entries_per_sector = (self.volume.bpb.bytes_per_sec as u32) / DIR_ENTRY_SIZE as u32;
            while self.entry_in_sector < entries_per_sector {
                let offset = (self.entry_in_sector as usize) * DIR_ENTRY_SIZE;
                let entry = read_dir_entry(&self.sector.as_ref().unwrap().1, offset);

                if entry.is_end() {
                    return Ok(None);
                }
                if entry.is_free() {
                    self.lfn_len = 0;
                    self.entry_in_sector += 1;
                    continue;
                }
                if entry.is_lfn() {
                    let lfn = read_lfn_entry(&self.sector.as_ref().unwrap().1, offset);
                    let ord = lfn.ord;
                    let is_last = (ord & LFN_ENTRY_LAST_MASK) != 0;
                    if is_last {
                        self.lfn_len = 0;
                        self.lfn_checksum = lfn.chksum;
                    } else if lfn.chksum != self.lfn_checksum {
                        self.lfn_len = 0;
                    }

                    let index = (ord & !LFN_ENTRY_LAST_MASK) as usize;
                    if index > 0 && index <= 20 {
                        let pos = (index - 1) * 13;
                        let len = lfn.extract_name(&mut self.lfn_buffer[pos..pos + 13]);
                        if is_last {
                            self.lfn_len = pos + len;
                        }
                    }
                    self.entry_in_sector += 1;
                    continue;
                }
                if (entry.attr & attr::VOLUME_ID) != 0 {
                    self.lfn_len = 0;
                    self.entry_in_sector += 1;
                    continue;
                }

                // SFN entry — reassemble the displayable name.
                let name =
                    if self.lfn_len > 0 && calculate_checksum(&entry.name) == self.lfn_checksum {
                        String::from_utf16_lossy(&self.lfn_buffer[..self.lfn_len])
                    } else {
                        sfn_to_string(&entry.name)
                    };
                self.lfn_len = 0;
                self.entry_in_sector += 1;
                return Ok(Some((name, entry, lba, offset)));
            }

            // Sector exhausted — advance.
            self.entry_in_sector = 0;
            self.sector_in_cluster += 1;
            if let Some(cluster) = self.current_cluster {
                if cluster != 0 && self.sector_in_cluster >= self.volume.bpb.sec_per_clus as u32 {
                    self.sector_in_cluster = 0;
                    match self.volume.next_cluster(cluster).await? {
                        super::fat::FatEntry::Next(next) => {
                            self.current_cluster = Some(next);
                        }
                        _ => self.current_cluster = None,
                    }
                }
            }
            self.sector = None;
        }
    }
}

// ── Byte-layout helpers ─────────────────────────────────────────────

fn read_dir_entry(buf: &[u8], offset: usize) -> RawDirEntry {
    // SAFETY: `RawDirEntry` is `#[repr(C, packed)]` with a 32-byte
    // layout that exactly matches the on-disk format (FATGEN §6).
    // The buffer is a freshly-read sector copy we own; we read at
    // a byte offset that the caller has bounded to
    // `entries_per_sector * 32`.
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const RawDirEntry) }
}

fn read_lfn_entry(buf: &[u8], offset: usize) -> LfnEntry {
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    // SAFETY: `LfnEntry` is `#[repr(C, packed)]`, also 32 bytes;
    // we only call this after `RawDirEntry::is_lfn()` returns true
    // for the same offset, so the bytes really do encode an LFN
    // entry per FATGEN §7.
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const LfnEntry) }
}

fn write_dir_entry(buf: &mut [u8], offset: usize, entry: &RawDirEntry) {
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    // SAFETY: same packed-layout argument as `read_dir_entry`.
    unsafe {
        core::ptr::write_unaligned(buf.as_mut_ptr().add(offset) as *mut RawDirEntry, *entry);
    }
}

fn write_lfn_entry(buf: &mut [u8], offset: usize, entry: &LfnEntry) {
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    // SAFETY: same packed-layout argument as `read_lfn_entry`.
    unsafe {
        core::ptr::write_unaligned(buf.as_mut_ptr().add(offset) as *mut LfnEntry, *entry);
    }
}

fn sfn_to_string(name: &[u8; SFN_LEN]) -> String {
    let mut s = String::new();
    let mut name_len = 8;
    while name_len > 0 && name[name_len - 1] == b' ' {
        name_len -= 1;
    }
    for &b in &name[0..name_len] {
        s.push(b as char);
    }
    let mut ext_len = 3;
    while ext_len > 0 && name[8 + ext_len - 1] == b' ' {
        ext_len -= 1;
    }
    if ext_len > 0 {
        s.push('.');
        for &b in &name[8..8 + ext_len] {
            s.push(b as char);
        }
    }
    s
}

// ── Per-entry write enum (avoids transmute between RawDirEntry/LfnEntry) ──

#[derive(Copy, Clone)]
enum DirSlotWrite {
    Sfn(RawDirEntry),
    Lfn(LfnEntry),
}

impl<B: BlockDevice + 'static> FatNode<B> {
    pub fn new(
        volume: Arc<FatVolume<B>>,
        first_cluster: u32,
        stat: Stat,
        entry_location: Option<(u64, usize)>,
    ) -> Self {
        Self {
            volume,
            state: IrqSafeSpinLock::new(FatNodeState {
                first_cluster,
                stat,
            }),
            entry_location,
        }
    }

    fn stat_from_entry(&self, entry: &RawDirEntry) -> Stat {
        let sector_size = self.volume.bpb.bytes_per_sec as u64;
        Stat {
            size: entry.file_size as u64,
            blocks: (entry.file_size as u64).div_ceil(sector_size),
            mode: Mode {
                file_type: if entry.is_directory() {
                    FileType::Dir
                } else {
                    FileType::File
                },
                perms: if (entry.attr & attr::READ_ONLY) != 0 {
                    0o444
                } else {
                    0o666
                },
            },
            mtime_cycles: 0,
        }
    }

    pub async fn truncate_async(&self, len: u64) -> Result<(), FsError> {
        let (old_size, mut cluster) = {
            let g = self.state.lock();
            (g.stat.size, g.first_cluster)
        };
        if len == old_size {
            return Ok(());
        }

        if len < old_size {
            let bytes_per_cluster =
                self.volume.bpb.bytes_per_sec as u64 * self.volume.bpb.sec_per_clus as u64;
            let last_cluster_index = if len == 0 {
                0
            } else {
                (len - 1) / bytes_per_cluster
            };

            if cluster < 2 {
                // Block-scope the IrqSafeSpinLock guard so it's
                // dropped *before* the .await below. The
                // !Send-marker on IrqSafeSpinLockGuard catches
                // missed drops at compile time; explicit `drop(g)`
                // doesn't shrink the future's captured-state
                // lifetime in async fns the way it does in sync
                // code.
                {
                    let mut g = self.state.lock();
                    g.stat.size = len;
                    g.stat.blocks = len.div_ceil(self.volume.bpb.bytes_per_sec as u64);
                }
                self.sync_metadata().await?;
                return Ok(());
            }

            let mut clusters_walked = 0;
            let max_clusters = self.volume.total_data_clusters() + 2;
            for _ in 0..last_cluster_index {
                match self.volume.next_cluster(cluster).await? {
                    super::fat::FatEntry::Next(next) => cluster = next,
                    _ => break,
                }
                clusters_walked += 1;
                if clusters_walked > max_clusters {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
            }

            let first_to_free = if len == 0 {
                let mut g = self.state.lock();
                let f = g.first_cluster;
                g.first_cluster = 0;
                f
            } else {
                match self.volume.next_cluster(cluster).await? {
                    super::fat::FatEntry::Next(next) => {
                        let eoc = match self.volume.version {
                            super::FatVersion::Fat12 => 0x0FFF,
                            super::FatVersion::Fat16 => 0xFFFF,
                            super::FatVersion::Fat32 => 0x0FFF_FFFF,
                        };
                        self.volume.update_fat_entry(cluster, eoc).await?;
                        next
                    }
                    _ => 0,
                }
            };

            let mut current = first_to_free;
            while current >= 2 {
                match self.volume.next_cluster(current).await? {
                    super::fat::FatEntry::Next(next) => {
                        self.volume.update_fat_entry(current, 0).await?;
                        current = next;
                    }
                    super::fat::FatEntry::EndOfChain => {
                        self.volume.update_fat_entry(current, 0).await?;
                        break;
                    }
                    _ => break,
                }
            }
        }

        {
            let mut g = self.state.lock();
            g.stat.size = len;
            g.stat.blocks = len.div_ceil(self.volume.bpb.bytes_per_sec as u64);
        }
        self.sync_metadata().await?;
        Ok(())
    }

    fn generate_lfn_entries(&self, name: &str, sfn_checksum: u8) -> Vec<LfnEntry> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let n_entries = utf16.len().div_ceil(13);
        let mut entries = Vec::with_capacity(n_entries);

        for i in 0..n_entries {
            let ord = (i + 1) as u8;
            let mut lfn = LfnEntry {
                ord: if i == n_entries - 1 {
                    ord | LFN_ENTRY_LAST_MASK
                } else {
                    ord
                },
                name1: [0xFFFF; 5],
                attr: attr::LONG_NAME,
                type_res: 0,
                chksum: sfn_checksum,
                name2: [0xFFFF; 6],
                fst_clus_lo: 0,
                name3: [0xFFFF; 2],
            };

            let mut current = i * 13;
            for j in 0..5 {
                if current < utf16.len() {
                    lfn.name1[j] = utf16[current];
                    current += 1;
                } else if current == utf16.len() {
                    lfn.name1[j] = 0;
                    current += 1;
                }
            }
            for j in 0..6 {
                if current < utf16.len() {
                    lfn.name2[j] = utf16[current];
                    current += 1;
                } else if current == utf16.len() {
                    lfn.name2[j] = 0;
                    current += 1;
                }
            }
            for j in 0..2 {
                if current < utf16.len() {
                    lfn.name3[j] = utf16[current];
                    current += 1;
                } else if current == utf16.len() {
                    lfn.name3[j] = 0;
                    current += 1;
                }
            }
            entries.push(lfn);
        }
        entries.reverse();
        entries
    }

    fn generate_sfn(&self, name: &str) -> [u8; SFN_LEN] {
        let mut sfn = [b' '; SFN_LEN];
        let mut parts = name.splitn(2, '.');
        let base = parts.next().unwrap_or("");
        let ext = parts.next().unwrap_or("");

        let is_valid_sfn_char =
            |c: u8| -> bool { c.is_ascii_alphanumeric() || b"$%'-_@~`!()^{}#&".contains(&c) };

        let mut base_idx = 0;
        for &b in base.as_bytes() {
            if base_idx >= 8 {
                break;
            }
            if is_valid_sfn_char(b) {
                sfn[base_idx] = b.to_ascii_uppercase();
                base_idx += 1;
            }
        }
        let mut ext_idx = 0;
        for &b in ext.as_bytes() {
            if ext_idx >= 3 {
                break;
            }
            if is_valid_sfn_char(b) {
                sfn[8 + ext_idx] = b.to_ascii_uppercase();
                ext_idx += 1;
            }
        }
        sfn
    }

    fn needs_lfn(&self, name: &str) -> bool {
        let mut parts = name.splitn(2, '.');
        let base = parts.next().unwrap_or("");
        let ext = parts.next().unwrap_or("");

        if base.len() > 8 || ext.len() > 3 {
            return true;
        }
        let is_sfn_char = |c: char| -> bool {
            c.is_ascii_uppercase() || c.is_ascii_digit() || "$%'-_@~`!()^{}#&".contains(c)
        };
        for c in base.chars() {
            if !is_sfn_char(c) {
                return true;
            }
        }
        for c in ext.chars() {
            if !is_sfn_char(c) {
                return true;
            }
        }
        false
    }

    pub async fn sync_metadata(&self) -> Result<(), FsError> {
        let (lba, offset) = match self.entry_location {
            Some(loc) => loc,
            None => return Ok(()),
        };
        let lbs = self.volume.bpb.bytes_per_sec as usize;
        let mut sector = vec![0u8; lbs];
        self.volume.read_sector(lba, &mut sector).await?;

        let mut entry = read_dir_entry(&sector, offset);
        let (size, first_cluster, mtime_cycles) = {
            let g = self.state.lock();
            (g.stat.size, g.first_cluster, g.stat.mtime_cycles)
        };
        entry.file_size = size as u32;
        entry.fst_clus_lo = (first_cluster & 0xFFFF) as u16;
        entry.fst_clus_hi = (first_cluster >> 16) as u16;
        let (dos_date, dos_time) = to_dos_time(mtime_cycles);
        entry.wrt_date = dos_date;
        entry.wrt_time = dos_time;
        write_dir_entry(&mut sector, offset, &entry);
        self.volume.write_sector(lba, &sector).await
    }

    /// Write a contiguous run of directory slot entries starting at
    /// `(lba, offset)`. The runs come from `create` / `mkdir` which
    /// build them as `DirSlotWrite::{Lfn, Sfn}`.
    async fn write_dir_slots(
        &self,
        lba: u64,
        offset: usize,
        entries: &[DirSlotWrite],
    ) -> Result<(), FsError> {
        let lbs = self.volume.bpb.bytes_per_sec as usize;
        let mut current_lba = lba;
        let mut current_offset = offset;
        let mut sector: Option<Vec<u8>> = None;
        let mut sector_lba: u64 = 0;

        for slot in entries {
            if current_offset >= lbs {
                if let Some(buf) = sector.take() {
                    self.volume.write_sector(sector_lba, &buf).await?;
                }
                current_lba += 1;
                current_offset = 0;
            }
            if sector.is_none() {
                let mut buf = vec![0u8; lbs];
                self.volume.read_sector(current_lba, &mut buf).await?;
                sector = Some(buf);
                sector_lba = current_lba;
            }
            let buf = sector.as_mut().unwrap();
            match slot {
                DirSlotWrite::Sfn(e) => write_dir_entry(buf, current_offset, e),
                DirSlotWrite::Lfn(e) => write_lfn_entry(buf, current_offset, e),
            }
            current_offset += DIR_ENTRY_SIZE;
        }
        if let Some(buf) = sector.take() {
            self.volume.write_sector(sector_lba, &buf).await?;
        }
        Ok(())
    }

    /// Locate `n` consecutive free directory slots in this dir. If
    /// the chain is full and we're on a non-fixed-root dir, allocate
    /// + zero a new cluster and link it in.
    async fn find_free_slots(&self, n: u32) -> Result<(u64, usize), FsError> {
        let mut scanner = DirectoryScanner::new(self.volume.clone(), {
            let g = self.state.lock();
            g.first_cluster
        });
        let lbs = self.volume.bpb.bytes_per_sec as usize;
        let entries_per_sector = (lbs / DIR_ENTRY_SIZE) as u32;

        let mut contiguous_found: u32 = 0;
        let mut first_lba: u64 = 0;
        let mut first_offset: usize = 0;

        loop {
            let lba = match scanner.current_lba() {
                Some(l) => l,
                None => break,
            };
            scanner.ensure_sector_loaded(lba).await?;

            while scanner.entry_in_sector < entries_per_sector {
                let offset = scanner.entry_in_sector as usize * DIR_ENTRY_SIZE;
                let entry = read_dir_entry(&scanner.sector.as_ref().unwrap().1, offset);

                if entry.is_free() || entry.is_end() {
                    if contiguous_found == 0 {
                        first_lba = lba;
                        first_offset = offset;
                    }
                    contiguous_found += 1;
                    if contiguous_found >= n {
                        return Ok((first_lba, first_offset));
                    }
                } else {
                    contiguous_found = 0;
                }
                scanner.entry_in_sector += 1;
            }

            scanner.entry_in_sector = 0;
            scanner.sector_in_cluster += 1;
            if let Some(cluster) = scanner.current_cluster {
                if cluster != 0 && scanner.sector_in_cluster >= self.volume.bpb.sec_per_clus as u32
                {
                    scanner.sector_in_cluster = 0;
                    match self.volume.next_cluster(cluster).await? {
                        super::fat::FatEntry::Next(next) => {
                            scanner.current_cluster = Some(next);
                        }
                        super::fat::FatEntry::EndOfChain => {
                            // Extend the directory by one cluster.
                            let next = self.volume.allocate_cluster().await?;
                            self.volume.update_fat_entry(cluster, next).await?;
                            let zero = vec![0u8; lbs];
                            let start_lba = self.volume.first_sector_of_cluster(next) as u64;
                            for i in 0..self.volume.bpb.sec_per_clus {
                                self.volume
                                    .write_sector(start_lba + i as u64, &zero)
                                    .await?;
                            }
                            scanner.current_cluster = Some(next);
                        }
                        _ => scanner.current_cluster = None,
                    }
                }
            }
            scanner.sector = None;
        }
        Err(FsError::NoSpace)
    }

    /// Build the SFN + (optional) LFN slot run for a new entry.
    fn build_slot_run(&self, name: &str, sfn_template: RawDirEntry) -> Vec<DirSlotWrite> {
        let sfn = self.generate_sfn(name);
        let mut sfn_entry = sfn_template;
        sfn_entry.name = sfn;

        let mut slots: Vec<DirSlotWrite> = Vec::new();
        if self.needs_lfn(name) {
            let chksum = calculate_checksum(&sfn);
            for lfn in self.generate_lfn_entries(name, chksum) {
                slots.push(DirSlotWrite::Lfn(lfn));
            }
        }
        slots.push(DirSlotWrite::Sfn(sfn_entry));
        slots
    }

    /// Tombstone a directory slot at `(lba, offset)` by writing
    /// 0xE5 to its first byte. Callers that built an LFN run before
    /// the SFN need to walk back and tombstone every preceding LFN
    /// slot — this helper handles a single slot.
    async fn tombstone_slot(&self, lba: u64, offset: usize) -> Result<(), FsError> {
        let lbs = self.volume.bpb.bytes_per_sec as usize;
        let mut sector = vec![0u8; lbs];
        self.volume.read_sector(lba, &mut sector).await?;
        sector[offset] = 0xE5;
        self.volume.write_sector(lba, &sector).await
    }

    /// Free the cluster chain starting at `start`. EndOfChain or
    /// Free terminates. Bad/Reserved entries are left in place.
    async fn free_chain(&self, start: u32) -> Result<(), FsError> {
        let mut cluster = start;
        while cluster >= 2 {
            let next = self.volume.next_cluster(cluster).await?;
            self.volume.free_cluster(cluster).await?;
            match next {
                super::fat::FatEntry::Next(n) => cluster = n,
                _ => break,
            }
        }
        Ok(())
    }
}

impl<B: BlockDevice + 'static> FileOps for FatNode<B> {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let (size, mut cluster) = {
                let g = self.state.lock();
                (g.stat.size, g.first_cluster)
            };
            if offset >= size {
                return Ok(0);
            }
            let mut remaining = core::cmp::min(buf.len() as u64, size - offset);
            let mut total_read = 0usize;

            let lbs = self.volume.bpb.bytes_per_sec as u64;
            let bytes_per_cluster = lbs * self.volume.bpb.sec_per_clus as u64;
            let cluster_index = offset / bytes_per_cluster;
            let mut cluster_offset = offset % bytes_per_cluster;

            if cluster < 2 {
                return Err(FsError::Io(narf_block::BlockError::IOError));
            }

            let max_clusters = self.volume.total_data_clusters() + 2;
            let mut walked = 0;
            for _ in 0..cluster_index {
                match self.volume.next_cluster(cluster).await? {
                    super::fat::FatEntry::Next(next) => cluster = next,
                    _ => return Err(FsError::Io(narf_block::BlockError::IOError)),
                }
                walked += 1;
                if walked > max_clusters {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
            }

            let lbs_us = lbs as usize;
            let mut sector = vec![0u8; lbs_us];
            while remaining > 0 {
                let lba_start = self.volume.first_sector_of_cluster(cluster) as u64;
                let mut sector_in_cluster = (cluster_offset / lbs) as u32;
                let mut sector_offset = (cluster_offset % lbs) as usize;
                while sector_in_cluster < self.volume.bpb.sec_per_clus as u32 && remaining > 0 {
                    let lba = lba_start + sector_in_cluster as u64;
                    self.volume.read_sector(lba, &mut sector).await?;
                    let n = core::cmp::min(remaining as usize, lbs_us - sector_offset);
                    buf[total_read..total_read + n]
                        .copy_from_slice(&sector[sector_offset..sector_offset + n]);
                    total_read += n;
                    remaining -= n as u64;
                    sector_in_cluster += 1;
                    sector_offset = 0;
                }
                if remaining > 0 {
                    match self.volume.next_cluster(cluster).await? {
                        super::fat::FatEntry::Next(next) => {
                            cluster = next;
                            cluster_offset = 0;
                        }
                        _ => break,
                    }
                }
            }
            Ok(total_read)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let mut total_written = 0usize;
            let mut remaining = buf.len();
            let lbs = self.volume.bpb.bytes_per_sec as u64;
            let bytes_per_cluster = lbs * self.volume.bpb.sec_per_clus as u64;

            let mut cluster = {
                let g = self.state.lock();
                g.first_cluster
            };
            if cluster == 0 && remaining > 0 {
                let new_clus = self.volume.allocate_cluster().await?;
                {
                    let mut g = self.state.lock();
                    g.first_cluster = new_clus;
                }
                self.sync_metadata().await?;
                cluster = new_clus;
            }
            if cluster < 2 && remaining > 0 {
                return Err(FsError::Io(narf_block::BlockError::IOError));
            }

            let cluster_index = offset / bytes_per_cluster;
            let mut cluster_offset = offset % bytes_per_cluster;
            let max_clusters = self.volume.total_data_clusters() + 2;
            let mut walked = 0;
            for _ in 0..cluster_index {
                match self.volume.next_cluster(cluster).await? {
                    super::fat::FatEntry::Next(next) => cluster = next,
                    super::fat::FatEntry::EndOfChain => {
                        let next = self.volume.allocate_cluster().await?;
                        self.volume.update_fat_entry(cluster, next).await?;
                        cluster = next;
                    }
                    _ => return Err(FsError::Io(narf_block::BlockError::IOError)),
                }
                walked += 1;
                if walked > max_clusters {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
            }

            let lbs_us = lbs as usize;
            let mut sector = vec![0u8; lbs_us];
            while remaining > 0 {
                let lba_start = self.volume.first_sector_of_cluster(cluster) as u64;
                let mut sector_in_cluster = (cluster_offset / lbs) as u32;
                let mut sector_offset = (cluster_offset % lbs) as usize;
                while sector_in_cluster < self.volume.bpb.sec_per_clus as u32 && remaining > 0 {
                    let lba = lba_start + sector_in_cluster as u64;
                    let n = core::cmp::min(remaining, lbs_us - sector_offset);
                    if n < lbs_us {
                        // Partial-sector write — read-modify-write
                        // so we don't clobber the surrounding bytes.
                        self.volume.read_sector(lba, &mut sector).await?;
                    }
                    sector[sector_offset..sector_offset + n]
                        .copy_from_slice(&buf[total_written..total_written + n]);
                    self.volume.write_sector(lba, &sector).await?;
                    total_written += n;
                    remaining -= n;
                    sector_in_cluster += 1;
                    sector_offset = 0;
                }
                if remaining > 0 {
                    match self.volume.next_cluster(cluster).await? {
                        super::fat::FatEntry::Next(next) => {
                            cluster = next;
                            cluster_offset = 0;
                        }
                        super::fat::FatEntry::EndOfChain => {
                            let next = self.volume.allocate_cluster().await?;
                            self.volume.update_fat_entry(cluster, next).await?;
                            cluster = next;
                            cluster_offset = 0;
                        }
                        _ => break,
                    }
                }
            }

            let new_size_needed = {
                let g = self.state.lock();
                offset + total_written as u64 > g.stat.size
            };
            if new_size_needed {
                {
                    let mut g = self.state.lock();
                    g.stat.size = offset + total_written as u64;
                    g.stat.blocks = g.stat.size.div_ceil(self.volume.bpb.bytes_per_sec as u64);
                }
                self.sync_metadata().await?;
            }
            Ok(total_written)
        })
    }

    fn stat(&self) -> Stat {
        let g = self.state.lock();
        g.stat
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { self.truncate_async(len).await })
    }
}

impl<B: BlockDevice + 'static> DirOps for FatNode<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // FAT lookups are inherently async (sector reads). The
        // sync API is unsupported here — the VFS prefers
        // `lookup_async` automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            while let Some((found, entry, lba, offset)) = scanner.next().await? {
                if found.eq_ignore_ascii_case(name) {
                    let stat = self.stat_from_entry(&entry);
                    return Ok(Arc::new(FatNode::new(
                        self.volume.clone(),
                        entry.first_cluster(),
                        stat,
                        Some((lba, offset)),
                    )) as Arc<dyn FileOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            while let Some((found, entry, lba, offset)) = scanner.next().await? {
                if found.eq_ignore_ascii_case(name) && entry.is_directory() {
                    let stat = self.stat_from_entry(&entry);
                    return Ok(Arc::new(FatNode::new(
                        self.volume.clone(),
                        entry.first_cluster(),
                        stat,
                        Some((lba, offset)),
                    )) as Arc<dyn DirOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Disk-backed FS — sync iteration is not supported. Use
        // `enumerate_async`.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            let mut out = Vec::new();
            let mut count = 0;
            while let Some((name, entry, _, _)) = scanner.next().await? {
                if count >= cursor {
                    let ft = if entry.is_directory() {
                        FileType::Dir
                    } else {
                        FileType::File
                    };
                    out.push((name, ft));
                    if out.len() >= max {
                        break;
                    }
                }
                count += 1;
            }
            Ok(out)
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let template = RawDirEntry {
                name: [b' '; SFN_LEN],
                attr: attr::ARCHIVE,
                nt_res: 0,
                crt_time_tehnth: 0,
                crt_time: 0,
                crt_date: 0,
                lst_acc_date: 0,
                fst_clus_hi: 0,
                wrt_time: 0,
                wrt_date: 0,
                fst_clus_lo: 0,
                file_size: 0,
            };
            let slots = self.build_slot_run(name, template);
            let (lba, offset) = self.find_free_slots(slots.len() as u32).await?;
            self.write_dir_slots(lba, offset, &slots).await?;

            // The SFN slot is the LAST one written; locate it for
            // the new node's `entry_location`.
            let sfn_index = slots.len() - 1;
            let sfn_byte_offset = offset + sfn_index * DIR_ENTRY_SIZE;
            let lbs = self.volume.bpb.bytes_per_sec as usize;
            let sfn_lba = lba + (sfn_byte_offset / lbs) as u64;
            let sfn_off_in_sector = sfn_byte_offset % lbs;

            Ok(Arc::new(FatNode::new(
                self.volume.clone(),
                0,
                Stat {
                    size: 0,
                    blocks: 0,
                    mode: Mode::FILE_RW,
                    mtime_cycles: 0,
                },
                Some((sfn_lba, sfn_off_in_sector)),
            )) as Arc<dyn FileOps>)
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let new_clus = self.volume.allocate_cluster().await?;
            let template = RawDirEntry {
                name: [b' '; SFN_LEN],
                attr: attr::DIRECTORY,
                nt_res: 0,
                crt_time_tehnth: 0,
                crt_time: 0,
                crt_date: 0,
                lst_acc_date: 0,
                fst_clus_hi: (new_clus >> 16) as u16,
                wrt_time: 0,
                wrt_date: 0,
                fst_clus_lo: (new_clus & 0xFFFF) as u16,
                file_size: 0,
            };
            let slots = self.build_slot_run(name, template);
            let (lba, offset) = self.find_free_slots(slots.len() as u32).await?;
            self.write_dir_slots(lba, offset, &slots).await?;

            // Initialise "." and ".." in the new directory's first
            // cluster, then zero-fill the rest of the cluster.
            let lbs = self.volume.bpb.bytes_per_sec as usize;
            let mut first_sector = vec![0u8; lbs];
            let dot = RawDirEntry {
                name: *b".          ",
                attr: attr::DIRECTORY,
                nt_res: 0,
                crt_time_tehnth: 0,
                crt_time: 0,
                crt_date: 0,
                lst_acc_date: 0,
                fst_clus_hi: (new_clus >> 16) as u16,
                wrt_time: 0,
                wrt_date: 0,
                fst_clus_lo: (new_clus & 0xFFFF) as u16,
                file_size: 0,
            };
            let dotdot_clus = {
                let g = self.state.lock();
                g.first_cluster
            };
            let dotdot = RawDirEntry {
                name: *b"..         ",
                attr: attr::DIRECTORY,
                nt_res: 0,
                crt_time_tehnth: 0,
                crt_time: 0,
                crt_date: 0,
                lst_acc_date: 0,
                fst_clus_hi: (dotdot_clus >> 16) as u16,
                wrt_time: 0,
                wrt_date: 0,
                fst_clus_lo: (dotdot_clus & 0xFFFF) as u16,
                file_size: 0,
            };
            write_dir_entry(&mut first_sector, 0, &dot);
            write_dir_entry(&mut first_sector, DIR_ENTRY_SIZE, &dotdot);

            let start_lba = self.volume.first_sector_of_cluster(new_clus) as u64;
            self.volume.write_sector(start_lba, &first_sector).await?;
            // Zero-fill the remaining sectors in the cluster so old
            // tenant bytes don't masquerade as live entries.
            let zero = vec![0u8; lbs];
            for i in 1..self.volume.bpb.sec_per_clus {
                self.volume
                    .write_sector(start_lba + i as u64, &zero)
                    .await?;
            }

            let sfn_index = slots.len() - 1;
            let sfn_byte_offset = offset + sfn_index * DIR_ENTRY_SIZE;
            let sfn_lba = lba + (sfn_byte_offset / lbs) as u64;
            let sfn_off_in_sector = sfn_byte_offset % lbs;

            Ok(Arc::new(FatNode::new(
                self.volume.clone(),
                new_clus,
                Stat {
                    size: 0,
                    blocks: self.volume.bpb.sec_per_clus as u64,
                    mode: Mode::DIR_RW,
                    mtime_cycles: 0,
                },
                Some((sfn_lba, sfn_off_in_sector)),
            )) as Arc<dyn DirOps>)
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            while let Some((found, entry, lba, offset)) = scanner.next().await? {
                if found.eq_ignore_ascii_case(name) {
                    if entry.is_directory() {
                        return Err(FsError::InvalidPath);
                    }
                    self.tombstone_slot(lba, offset).await?;
                    let first = entry.first_cluster();
                    if first >= 2 {
                        self.free_chain(first).await?;
                    }
                    return Ok(());
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            while let Some((found, entry, lba, offset)) = scanner.next().await? {
                if found.eq_ignore_ascii_case(name) {
                    if !entry.is_directory() {
                        return Err(FsError::InvalidPath);
                    }
                    let mut sub = DirectoryScanner::new(self.volume.clone(), entry.first_cluster());
                    while let Some((n, _, _, _)) = sub.next().await? {
                        if n != "." && n != ".." {
                            return Err(FsError::Busy);
                        }
                    }
                    self.tombstone_slot(lba, offset).await?;
                    let first = entry.first_cluster();
                    if first >= 2 {
                        self.free_chain(first).await?;
                    }
                    return Ok(());
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // Locate source.
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            let mut src = None;
            while let Some((n, entry, lba, offset)) = scanner.next().await? {
                if n.eq_ignore_ascii_case(old_name) {
                    src = Some((entry, lba, offset));
                    break;
                }
            }
            let (mut entry, old_lba, old_offset) = src.ok_or(FsError::NotFound)?;

            // Verify destination doesn't already exist.
            let mut check = DirectoryScanner::new(self.volume.clone(), {
                let g = self.state.lock();
                g.first_cluster
            });
            while let Some((n, _, _, _)) = check.next().await? {
                if n.eq_ignore_ascii_case(new_name) {
                    return Err(FsError::Busy);
                }
            }

            // Reserve a new slot run (LFN + SFN if needed) and
            // write it. Renaming preserves the first-cluster / file-
            // size / attribute fields.
            entry.name = self.generate_sfn(new_name);
            let mut slots: Vec<DirSlotWrite> = Vec::new();
            if self.needs_lfn(new_name) {
                let chksum = calculate_checksum(&entry.name);
                for lfn in self.generate_lfn_entries(new_name, chksum) {
                    slots.push(DirSlotWrite::Lfn(lfn));
                }
            }
            slots.push(DirSlotWrite::Sfn(entry));

            let (new_lba, new_offset) = self.find_free_slots(slots.len() as u32).await?;
            self.write_dir_slots(new_lba, new_offset, &slots).await?;
            self.tombstone_slot(old_lba, old_offset).await?;
            Ok(())
        })
    }
}
