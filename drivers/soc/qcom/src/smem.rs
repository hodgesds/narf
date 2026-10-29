//! Qualcomm shared memory (SMEM) manager.
//!
//! Linux `drivers/soc/qcom/smem.c`. SMEM is a carve-out shared by every
//! processor on the SoC. Region layout:
//!
//! - offset 0: `struct smem_header` — 4 legacy proc_comm slots (16 B
//!   each), `version[32]`, `initialized`, `free_offset`, `available`,
//!   `reserved`, then the 512-entry global TOC (16 B each).
//! - last 4 KiB: `struct smem_ptable` (`$TOC`), the private-partition
//!   table, followed by an optional `struct smem_info` (`SIII`) carrying
//!   the item count.
//!
//! `version[SMEM_MASTER_SBL_VERSION_INDEX] >> 16` selects the scheme:
//! 11 = global heap (items in the TOC), 12 = global partition (items in
//! the partition whose hosts are both `0xfffe`). Private partitions
//! between the application processor (host 0) and a remote host hold
//! that pair's items in an uncached list growing up from the partition
//! header and a cached list growing down from the end.
//!
//! All access goes through [`RegIo`] (32-bit aligned words; every field
//! this module touches is 4-byte aligned), so the region can be the real
//! write-combined mapping or a RAM fixture.

use alloc::vec::Vec;

use crate::hwlock::{HwLockError, HwSpinlock, SMEM_LOCK_TIMEOUT_MS};
use crate::io::RegIo;

pub const SMEM_MASTER_SBL_VERSION_INDEX: u32 = 7;
pub const SMEM_GLOBAL_HEAP_VERSION: u32 = 11;
pub const SMEM_GLOBAL_PART_VERSION: u32 = 12;
pub const SMEM_ITEM_LAST_FIXED: u32 = 8;
pub const SMEM_ITEM_COUNT: u32 = 512;
pub const SMEM_HOST_APPS: u16 = 0;
pub const SMEM_GLOBAL_HOST: u16 = 0xfffe;
pub const SMEM_HOST_COUNT: u16 = 20;
/// `QCOM_SMEM_HOST_ANY`.
pub const SMEM_HOST_ANY: u16 = 0xffff;
pub const SMEM_PRIVATE_CANARY: u16 = 0xa5a5;
pub const PTABLE_MAGIC: [u8; 4] = *b"$TOC";
pub const PART_MAGIC: [u8; 4] = *b"$PRT";
pub const INFO_MAGIC: [u8; 4] = *b"SIII";

/// `smem_header` field offsets.
pub const HDR_VERSION: u32 = 64;
pub const HDR_INITIALIZED: u32 = 64 + 128;
pub const HDR_FREE_OFFSET: u32 = HDR_INITIALIZED + 4;
pub const HDR_AVAILABLE: u32 = HDR_INITIALIZED + 8;
pub const HDR_TOC: u32 = HDR_INITIALIZED + 16;
/// `smem_ptable` header and entry sizes.
pub const PTABLE_HDR: u32 = 32;
pub const PTABLE_ENTRY: u32 = 48;
/// `smem_partition_header` size.
pub const PART_HDR: u32 = 32;
/// `smem_private_entry` size.
pub const PRIV_ENTRY: u32 = 16;
pub const PTABLE_SIZE: u32 = 0x1000;

/// SMEM failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmemError {
    /// The header version is neither 11 nor 12.
    UnsupportedVersion(u32),
    /// Missing or bad `$TOC` where version 12 requires one.
    BadPtable,
    /// Partition header magic/host/size mismatch.
    BadPartition,
    /// A private-entry canary is wrong (`-EINVAL`, "bad canary").
    BadCanary,
    /// Item not present (`-ENXIO` / `-ENOENT`).
    NotFound,
    /// Item id beyond the item count, or a fixed item on alloc.
    BadItem,
    /// Item already allocated (`-EEXIST`).
    Exists,
    /// Partition / heap full (`-ENOSPC` / `-ENOMEM`).
    NoSpace,
    /// An entry points outside its partition or region.
    OutOfBounds,
    /// The SMEM hardware lock could not be taken.
    Lock(HwLockError),
}

impl From<HwLockError> for SmemError {
    fn from(e: HwLockError) -> Self {
        SmemError::Lock(e)
    }
}

/// An item: byte offset within the region and usable length.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SmemItem {
    pub offset: u32,
    pub len: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Partition {
    base: u32,
    size: u32,
    cacheline: u32,
}

/// A probed SMEM region.
#[derive(Debug)]
pub struct Smem<R: RegIo> {
    mem: R,
    size: u32,
    item_count: u32,
    global: Option<Partition>,
    partitions: [Option<Partition>; SMEM_HOST_COUNT as usize],
    version: u32,
}

const fn align(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}

impl<R: RegIo> Smem<R> {
    fn magic(&self, off: u32) -> [u8; 4] {
        self.mem.read32(off).to_le_bytes()
    }
    fn lo16(&self, off: u32) -> u16 {
        self.mem.read32(off) as u16
    }
    fn hi16(&self, off: u32) -> u16 {
        (self.mem.read32(off) >> 16) as u16
    }

    /// `qcom_smem_probe` over a `size`-byte region mapped as `mem`.
    pub fn probe(mem: R, size: u32) -> Result<Self, SmemError> {
        let mut s = Self {
            mem,
            size,
            item_count: SMEM_ITEM_COUNT,
            global: None,
            partitions: [None; SMEM_HOST_COUNT as usize],
            version: 0,
        };
        if size < PTABLE_SIZE + HDR_TOC {
            return Err(SmemError::OutOfBounds);
        }
        let v = s
            .mem
            .read32(HDR_VERSION + SMEM_MASTER_SBL_VERSION_INDEX * 4)
            >> 16;
        s.version = v;
        match v {
            SMEM_GLOBAL_PART_VERSION => {
                s.item_count = s.read_item_count();
                s.set_global_partition()?;
            }
            SMEM_GLOBAL_HEAP_VERSION => s.item_count = SMEM_ITEM_COUNT,
            other => return Err(SmemError::UnsupportedVersion(other)),
        }
        s.enumerate_partitions(SMEM_HOST_APPS)?;
        Ok(s)
    }

    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn item_count(&self) -> u32 {
        self.item_count
    }
    /// The underlying region accessor (for SMP2P item access).
    pub fn mem(&self) -> &R {
        &self.mem
    }

    fn ptable(&self) -> Option<u32> {
        let p = self.size - PTABLE_SIZE;
        if self.magic(p) != PTABLE_MAGIC || self.mem.read32(p + 4) != 1 {
            return None;
        }
        Some(p)
    }

    fn ptable_entries(&self) -> u32 {
        self.ptable()
            .map(|p| self.mem.read32(p + 8))
            .unwrap_or(0)
            .min((PTABLE_SIZE - PTABLE_HDR) / PTABLE_ENTRY)
    }

    /// `qcom_smem_get_item_count`.
    fn read_item_count(&self) -> u32 {
        let Some(p) = self.ptable() else {
            return SMEM_ITEM_COUNT;
        };
        let info = p + PTABLE_HDR + self.ptable_entries() * PTABLE_ENTRY;
        if info + 20 > self.size || self.magic(info) != INFO_MAGIC {
            return SMEM_ITEM_COUNT;
        }
        self.lo16(info + 16) as u32
    }

    /// (offset, size, host0, host1, cacheline) of ptable entry `i`.
    fn ptable_entry(&self, i: u32) -> (u32, u32, u16, u16, u32) {
        let e = self.ptable().unwrap_or(0) + PTABLE_HDR + i * PTABLE_ENTRY;
        (
            self.mem.read32(e),
            self.mem.read32(e + 4),
            self.lo16(e + 12),
            self.hi16(e + 12),
            self.mem.read32(e + 16),
        )
    }

    /// `qcom_smem_partition_header` validation.
    fn partition(
        &self,
        off: u32,
        size: u32,
        h0: u16,
        h1: u16,
        cl: u32,
    ) -> Result<Partition, SmemError> {
        if off.checked_add(size).is_none_or(|e| e > self.size) || size < PART_HDR {
            return Err(SmemError::BadPartition);
        }
        if self.magic(off) != PART_MAGIC
            || self.lo16(off + 4) != h0
            || self.hi16(off + 4) != h1
            || self.mem.read32(off + 8) != size
            || self.mem.read32(off + 12) > size
        {
            return Err(SmemError::BadPartition);
        }
        Ok(Partition {
            base: off,
            size,
            cacheline: cl.max(1),
        })
    }

    /// `qcom_smem_set_global_partition`.
    fn set_global_partition(&mut self) -> Result<(), SmemError> {
        if self.ptable().is_none() {
            return Err(SmemError::BadPtable);
        }
        for i in 0..self.ptable_entries() {
            let (off, size, h0, h1, cl) = self.ptable_entry(i);
            if off == 0 || size == 0 {
                continue;
            }
            if h0 == SMEM_GLOBAL_HOST && h1 == SMEM_GLOBAL_HOST {
                self.global = Some(self.partition(off, size, h0, h1, cl)?);
                return Ok(());
            }
        }
        Err(SmemError::BadPtable)
    }

    /// `qcom_smem_enumerate_partitions`.
    fn enumerate_partitions(&mut self, local: u16) -> Result<(), SmemError> {
        if self.ptable().is_none() {
            return Ok(());
        }
        for i in 0..self.ptable_entries() {
            let (off, size, h0, h1, cl) = self.ptable_entry(i);
            if off == 0 || size == 0 {
                continue;
            }
            let remote = if h0 == local {
                h1
            } else if h1 == local {
                h0
            } else {
                continue;
            };
            if remote >= SMEM_HOST_COUNT || self.partitions[remote as usize].is_some() {
                return Err(SmemError::BadPartition);
            }
            self.partitions[remote as usize] = Some(self.partition(off, size, h0, h1, cl)?);
        }
        Ok(())
    }

    fn part_for(&self, host: u16) -> Option<Partition> {
        if host < SMEM_HOST_COUNT {
            if let Some(p) = self.partitions[host as usize] {
                return Some(p);
            }
        }
        self.global
    }

    /// `qcom_smem_get`.
    pub fn get(&self, host: u16, item: u32) -> Result<SmemItem, SmemError> {
        if item >= self.item_count {
            return Err(SmemError::BadItem);
        }
        match self.part_for(host) {
            Some(p) => self.get_private(p, item),
            None => self.get_global(item),
        }
    }

    fn get_global(&self, item: u32) -> Result<SmemItem, SmemError> {
        let e = HDR_TOC + item * 16;
        if self.mem.read32(e) == 0 {
            return Err(SmemError::NotFound);
        }
        let off = self.mem.read32(e + 4);
        let size = self.mem.read32(e + 8);
        if off.checked_add(size).is_none_or(|end| end > self.size) {
            return Err(SmemError::OutOfBounds);
        }
        Ok(SmemItem {
            offset: off,
            len: size,
        })
    }

    fn get_private(&self, p: Partition, item: u32) -> Result<SmemItem, SmemError> {
        let end_part = p.base + p.size;
        let mut e = p.base + PART_HDR;
        let end = p.base + self.mem.read32(p.base + 12);
        while e < end {
            if self.lo16(e) != SMEM_PRIVATE_CANARY {
                return Err(SmemError::BadCanary);
            }
            let size = self.mem.read32(e + 4);
            let pad_data = self.lo16(e + 8) as u32;
            let pad_hdr = self.hi16(e + 8) as u32;
            if self.hi16(e) as u32 == item {
                if size > p.size || pad_data > size {
                    return Err(SmemError::OutOfBounds);
                }
                let at = e + PRIV_ENTRY + pad_hdr;
                if at + size > end_part {
                    return Err(SmemError::OutOfBounds);
                }
                return Ok(SmemItem {
                    offset: at,
                    len: size - pad_data,
                });
            }
            e = e
                .checked_add(PRIV_ENTRY + pad_hdr + size)
                .ok_or(SmemError::OutOfBounds)?;
        }
        if e > end_part {
            return Err(SmemError::OutOfBounds);
        }
        // Cached list: entries grow down from the partition end.
        let cl = p.cacheline;
        let first = end_part - align(PRIV_ENTRY, cl);
        let last = p.base + self.mem.read32(p.base + 16);
        if last > end_part {
            return Err(SmemError::OutOfBounds);
        }
        let mut e = first;
        while e > last {
            if self.lo16(e) != SMEM_PRIVATE_CANARY {
                return Err(SmemError::BadCanary);
            }
            let size = self.mem.read32(e + 4);
            let pad_data = self.lo16(e + 8) as u32;
            if self.hi16(e) as u32 == item {
                if size > p.size || pad_data > size || size > e - p.base {
                    return Err(SmemError::OutOfBounds);
                }
                return Ok(SmemItem {
                    offset: e - size,
                    len: size - pad_data,
                });
            }
            e = e
                .checked_sub(size + align(PRIV_ENTRY, cl))
                .ok_or(SmemError::OutOfBounds)?;
        }
        Err(SmemError::NotFound)
    }

    /// `qcom_smem_alloc`, under the SMEM hardware lock.
    pub async fn alloc<L: HwSpinlock>(
        &self,
        lock: &L,
        host: u16,
        item: u32,
        size: u32,
    ) -> Result<(), SmemError> {
        if item < SMEM_ITEM_LAST_FIXED || item >= self.item_count {
            return Err(SmemError::BadItem);
        }
        lock.lock(SMEM_LOCK_TIMEOUT_MS).await?;
        let r = match self.part_for(host) {
            Some(p) => self.alloc_private(p, item, size),
            None => self.alloc_global(item, size),
        };
        lock.unlock()?;
        r
    }

    fn alloc_private(&self, p: Partition, item: u32, size: u32) -> Result<(), SmemError> {
        let end_part = p.base + p.size;
        let mut hdr = p.base + PART_HDR;
        let end = p.base + self.mem.read32(p.base + 12);
        let cached = p.base + self.mem.read32(p.base + 16);
        if end > end_part || cached > end_part {
            return Err(SmemError::OutOfBounds);
        }
        while hdr < end {
            if self.lo16(hdr) != SMEM_PRIVATE_CANARY {
                return Err(SmemError::BadCanary);
            }
            if self.hi16(hdr) as u32 == item {
                return Err(SmemError::Exists);
            }
            hdr += PRIV_ENTRY + self.hi16(hdr + 8) as u32 + self.mem.read32(hdr + 4);
        }
        if hdr > end_part {
            return Err(SmemError::OutOfBounds);
        }
        let asize = align(size, 8);
        let alloc_size = PRIV_ENTRY + asize;
        if hdr + alloc_size > cached {
            return Err(SmemError::NoSpace);
        }
        self.mem
            .write32(hdr, SMEM_PRIVATE_CANARY as u32 | (item << 16));
        self.mem.write32(hdr + 4, asize);
        self.mem.write32(hdr + 8, asize - size);
        self.mem.write32(hdr + 12, 0);
        // The header is complete before the free offset moves (Linux wmb):
        // RegIo writes are ordered device/WC stores.
        let free = self.mem.read32(p.base + 12);
        self.mem.write32(p.base + 12, free + alloc_size);
        Ok(())
    }

    fn alloc_global(&self, item: u32, size: u32) -> Result<(), SmemError> {
        let e = HDR_TOC + item * 16;
        if self.mem.read32(e) != 0 {
            return Err(SmemError::Exists);
        }
        let size = align(size, 8);
        let avail = self.mem.read32(HDR_AVAILABLE);
        if size > avail {
            return Err(SmemError::NoSpace);
        }
        let free = self.mem.read32(HDR_FREE_OFFSET);
        self.mem.write32(e + 4, free);
        self.mem.write32(e + 8, size);
        self.mem.write32(e, 1);
        self.mem.write32(HDR_FREE_OFFSET, free + size);
        self.mem.write32(HDR_AVAILABLE, avail - size);
        Ok(())
    }

    /// Read `len` bytes of an item (crash-reason strings).
    pub fn read_bytes(&self, item: SmemItem, max: usize) -> Vec<u8> {
        let n = (item.len as usize).min(max);
        let mut out = Vec::with_capacity(n);
        let base = item.offset & !3;
        let skew = (item.offset & 3) as usize;
        let mut i = 0usize;
        while out.len() < n {
            let w = self.mem.read32(base + (i as u32) * 4).to_le_bytes();
            for (j, b) in w.iter().enumerate() {
                let pos = i * 4 + j;
                if pos >= skew && out.len() < n {
                    out.push(*b);
                }
            }
            i += 1;
        }
        out
    }
}
