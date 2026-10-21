//! Reservations within an explicitly owned, CPU-visible VRAM range, and
//! (`UnmappedPool`) within owned VRAM past the CPU-visible BAR.
//!
//! This allocator never infers free VRAM from a BAR's size. Its bootstrap
//! caller must exclude firmware, scanout, PSP/TMR and discovery allocations.
use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;
use narf_bus::MmioRegion;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Exhausted,
    /// [`Pool::claim`]: a reservation already holds part of the range.
    Busy,
}
#[derive(Debug)]
struct Inner {
    mapping: MmioRegion,
    address: u64,
    used: IrqSafeSpinLock<Vec<Range<u64>>>,
    /// The entries of `used` that are permanent exclusions (the bootstrap
    /// inventory and [`Pool::claim`]s), never reservations. Locked after
    /// `used`.
    protected: IrqSafeSpinLock<Vec<Range<u64>>>,
    /// Published ranges whose reservation was dropped: still excluded
    /// (hardware may reach them) until a proven power cycle reclaims them.
    retired: IrqSafeSpinLock<Vec<Range<u64>>>,
}
#[derive(Clone, Debug)]
pub struct Pool(Arc<Inner>);
impl Pool {
    /// # Safety
    /// `mapping` must permanently map the GPU VRAM at `address`, not system
    /// RAM or an arbitrary PCI BAR. This whole range must be exclusively free
    /// for this pool, including from BIOS, PSP and all other GPU clients.
    /// Retain that exclusion even if an allocation is quarantined or leaked.
    pub unsafe fn from_owned_range(mapping: MmioRegion, address: u64) -> Result<Self, Error> {
        // SAFETY: the whole aperture is owned and has no protected holes.
        unsafe { Self::from_owned_aperture(mapping, address, &[]) }
    }
    /// Create a pool with permanently protected, aperture-relative byte ranges.
    /// Exclusions are rounded outward to pages and overlapping ranges merged.
    ///
    /// # Safety
    /// The mapping/ownership contract of `from_owned_range` applies to all
    /// bytes outside `protected`. Every existing client must be represented,
    /// and future clients must allocate from this pool. Protected ranges remain
    /// excluded for the pool's lifetime, even when its allocations are freed.
    pub unsafe fn from_owned_aperture(
        mapping: MmioRegion,
        address: u64,
        protected: &[Range<u64>],
    ) -> Result<Self, Error> {
        if mapping.len == 0
            || mapping.len % 4096 != 0
            || mapping.virt % 4096 != 0
            || mapping.phys.raw() % 4096 != 0
            || address % 4096 != 0
            || address
                .checked_add(mapping.len)
                .is_none_or(|end| end > 1 << 48)
            || mapping.virt.checked_add(mapping.len).is_none()
            || mapping.phys.raw().checked_add(mapping.len).is_none()
        {
            return Err(Error::Invalid);
        }
        let mut used: Vec<Range<u64>> = Vec::new();
        used.try_reserve_exact(protected.len())
            .map_err(|_| Error::Exhausted)?;
        for range in protected {
            if range.start >= range.end || range.end > mapping.len {
                return Err(Error::Invalid);
            }
            let end = range.end.checked_add(4095).ok_or(Error::Invalid)? & !4095;
            used.push((range.start & !4095)..end);
        }
        used.sort_unstable_by_key(|range| range.start);
        let mut count = 0;
        for index in 0..used.len() {
            let range = used[index].clone();
            if count != 0 && range.start <= used[count - 1].end {
                used[count - 1].end = used[count - 1].end.max(range.end);
            } else {
                used[count] = range;
                count += 1;
            }
        }
        used.truncate(count);
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(used.len())
            .map_err(|_| Error::Exhausted)?;
        protected.extend(used.iter().cloned());
        Ok(Self(Arc::new(Inner {
            mapping,
            address,
            used: IrqSafeSpinLock::new(used),
            protected: IrqSafeSpinLock::new(protected),
            retired: IrqSafeSpinLock::new(Vec::new()),
        })))
    }
    /// Return every retired range (a dropped reservation that was exposed
    /// to hardware) to the pool. Returns the bytes reclaimed.
    ///
    /// # Safety
    /// No device or CPU access can reach a retired range any more: every
    /// owner that published one was quiesced and dropped, and the GPU went
    /// through a full power cycle or reset since (S3/BACO resume post).
    pub(crate) unsafe fn reclaim_retired(&self) -> u64 {
        let retired = core::mem::take(&mut *self.0.retired.lock());
        let mut used = self.0.used.lock();
        let mut bytes = 0;
        for range in retired {
            let before = used.len();
            used.retain(|r| *r != range);
            if used.len() != before {
                bytes += range.end - range.start;
            }
        }
        bytes
    }
    /// Bytes held by dropped-but-published reservations.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn retired(&self) -> u64 {
        self.0.retired.lock().iter().map(|r| r.end - r.start).sum()
    }
    pub fn reserve(&self, size: u64) -> Result<Reservation, Error> {
        self.reserve_aligned(size, 4096)
    }
    /// Reserve with a power-of-two GPU-address alignment (PSP TMR needs 1 MiB).
    /// Padding remains available to other allocations.
    pub fn reserve_aligned(&self, size: u64, alignment: u64) -> Result<Reservation, Error> {
        let mut used = self.0.used.lock();
        let range = place(
            &mut used,
            self.0.address,
            self.0.mapping.len,
            size,
            alignment,
        )?;
        Ok(Reservation {
            pool: self.0.clone(),
            range,
            reusable: true,
        })
    }
    /// amdgpu_vram_mgr_new's GFX12_DCC | VRAM_CONTIGUOUS placement
    /// (`place_dcc`): `size` bytes starting at a multiple of `alignment`
    /// (gmc_v12_0_get_dcc_alignment, counted from VRAM offset 0 at GPU
    /// address `origin`) inside a [`dcc_block_size`] block at its own
    /// alignment. Only the trimmed range is held. Where no such block is
    /// free, reserve `size` bytes at the first multiple of `alignment`.
    /// This native fallback remains contiguous and DCC-aligned without
    /// requiring the temporary block used by Linux's buddy allocator.
    pub fn reserve_dcc(
        &self,
        size: u64,
        alignment: u64,
        origin: u64,
    ) -> Result<Reservation, Error> {
        let mut used = self.0.used.lock();
        let range = place_dcc(
            &mut used,
            self.0.address,
            self.0.mapping.len,
            size,
            alignment,
            origin,
        )?;
        Ok(Reservation {
            pool: self.0.clone(),
            range,
            reusable: true,
        })
    }
    pub fn available(&self) -> u64 {
        self.0.mapping.len
            - self
                .0
                .used
                .lock()
                .iter()
                .map(|r| r.end - r.start)
                .sum::<u64>()
    }
    /// The whole aperture, protected ranges included.
    pub fn size(&self) -> u64 {
        self.0.mapping.len
    }
    /// Permanently exclude the aperture-relative `range` (rounded out to
    /// pages), as `amdgpu_bo_create_kernel_at` pins a firmware-owned range
    /// at a fixed offset: it may overlap existing protected ranges, which
    /// it merges with, but `Busy` if any reservation (live or retired)
    /// already holds part of it, and `Invalid` past the aperture.
    pub fn claim(&self, range: Range<u64>) -> Result<(), Error> {
        claim(
            &mut self.0.used.lock(),
            &mut self.0.protected.lock(),
            self.0.mapping.len,
            range,
        )
    }
    pub(crate) fn mapping(&self) -> MmioRegion {
        self.0.mapping
    }
    pub(crate) fn address(&self) -> u64 {
        self.0.address
    }
}

/// First fit of `size` bytes (rounded up to pages) at a power-of-two
/// `alignment` of the GPU address, within `len` bytes from `address`,
/// recorded in the sorted `used` list.
fn place(
    used: &mut Vec<Range<u64>>,
    address: u64,
    len: u64,
    size: u64,
    alignment: u64,
) -> Result<Range<u64>, Error> {
    if alignment < 4096 || !alignment.is_power_of_two() {
        return Err(Error::Invalid);
    }
    place_at(used, len, size, |offset: u64| {
        address
            .checked_add(offset)
            .and_then(|address| address.checked_add(alignment - 1))
            .map(|address| address & !(alignment - 1))
            .and_then(|aligned| aligned.checked_sub(address))
            .ok_or(Error::Exhausted)
    })
}

/// First fit of `size` bytes (rounded up to pages) starting at a multiple
/// of `alignment` (any multiple of a page) counted from GPU address
/// `origin`, within `len` bytes from `address`.
fn place_multiple(
    used: &mut Vec<Range<u64>>,
    address: u64,
    len: u64,
    size: u64,
    alignment: u64,
    origin: u64,
) -> Result<Range<u64>, Error> {
    if alignment == 0 || alignment % 4096 != 0 {
        return Err(Error::Invalid);
    }
    place_at(used, len, size, |offset: u64| {
        address
            .checked_add(offset)
            .and_then(|at| at.checked_sub(origin))
            .and_then(|from| from.checked_next_multiple_of(alignment))
            .and_then(|from| from.checked_add(origin))
            .and_then(|at| at.checked_sub(address))
            .ok_or(Error::Exhausted)
    })
}

/// First fit of `size` bytes (rounded up to pages) at the first start
/// `align` gives at or past each free offset, recorded in the sorted
/// `used` list.
fn place_at(
    used: &mut Vec<Range<u64>>,
    len: u64,
    size: u64,
    align: impl Fn(u64) -> Result<u64, Error>,
) -> Result<Range<u64>, Error> {
    let size = size.checked_add(4095).ok_or(Error::Invalid)? & !4095;
    if size == 0 {
        return Err(Error::Invalid);
    }
    let mut start = align(0)?;
    let mut index = 0;
    while index < used.len() {
        if start
            .checked_add(size)
            .is_some_and(|end| end <= used[index].start)
        {
            break;
        }
        start = align(start.max(used[index].end))?;
        index += 1;
    }
    let end = start.checked_add(size).ok_or(Error::Exhausted)?;
    if end > len {
        return Err(Error::Exhausted);
    }
    used.try_reserve(1).map_err(|_| Error::Exhausted)?;
    used.insert(index, start..end);
    Ok(start..end)
}

/// amdgpu_vram_mgr_new's block for a GFX12_DCC | VRAM_CONTIGUOUS buffer of
/// `size` bytes at DCC alignment `alignment` (adjust_dcc_size):
/// `roundup_pow_of_two(size + alignment)`, kept in the 32-bit `dcc_size`
/// Linux stores it in (0 once it no longer fits, which Linux cannot place).
pub const fn dcc_block_size(size: u64, alignment: u64) -> u64 {
    match size.checked_add(alignment) {
        Some(n) => match n.checked_next_power_of_two() {
            Some(block) => block as u32 as u64,
            None => 0,
        },
        None => 0,
    }
}

/// Where amdgpu_vram_mgr_new trims a DCC buffer's block starting at VRAM
/// offset `block_start`: `roundup(block_start, alignment)`.
pub const fn dcc_trim_start(block_start: u64, alignment: u64) -> Option<u64> {
    block_start.checked_next_multiple_of(alignment)
}

/// `place` of a GFX12 DCC buffer as amdgpu_vram_mgr_new places it: the
/// [`dcc_block_size`] block of `size` (pages) and `alignment` first, at its
/// own (power-of-two) alignment as the buddy allocator hands one out, then
/// trimmed (gpu_buddy_block_trim) to `size` bytes from the block's first
/// multiple of `alignment` past `origin` (the GPU address of VRAM offset
/// 0, which the buddy offsets count from). The rest of the block stays
/// free, as the trim returns it.
///
/// When no whole block fits, this range allocator can reserve the final
/// contiguous, DCC-aligned range directly. This is a native fallback, not
/// Linux's ENOSPC retry: Linux retains the BO's VRAM_CONTIGUOUS flag and
/// its DCC block rounding when dropping the buddy contiguous-allocation
/// flag. Both native paths preserve the hardware's final address and size
/// constraints; only the preferred path needs a temporary larger block.
fn place_dcc(
    used: &mut Vec<Range<u64>>,
    address: u64,
    len: u64,
    size: u64,
    alignment: u64,
    origin: u64,
) -> Result<Range<u64>, Error> {
    let size = size.checked_add(4095).ok_or(Error::Invalid)? & !4095;
    let block = dcc_block_size(size, alignment);
    if size == 0 || alignment == 0 || alignment % 4096 != 0 || block < 4096 {
        return Err(Error::Invalid);
    }
    let range = match place_multiple(used, address, len, block, block, origin) {
        Ok(range) => range,
        Err(Error::Exhausted) => {
            return place_multiple(used, address, len, size, alignment, origin);
        }
        Err(e) => return Err(e),
    };
    let trimmed = address
        .checked_add(range.start)
        .and_then(|at| at.checked_sub(origin))
        .and_then(|offset| dcc_trim_start(offset, alignment))
        .and_then(|offset| offset.checked_add(origin))
        .and_then(|at| at.checked_sub(address))
        .filter(|&start| start.checked_add(size).is_some_and(|end| end <= range.end));
    let index = used
        .iter()
        .position(|r| *r == range)
        .ok_or(Error::Invalid)?;
    let Some(start) = trimmed else {
        used.remove(index);
        return Err(Error::Invalid);
    };
    used[index] = start..start + size;
    Ok(start..start + size)
}

/// Merge `range` into both the sorted `used` list and its `protected`
/// subset, refusing to cover any `used` entry that is not protected.
fn claim(
    used: &mut Vec<Range<u64>>,
    protected: &mut Vec<Range<u64>>,
    len: u64,
    range: Range<u64>,
) -> Result<(), Error> {
    let start = range.start & !4095;
    let end = range.end.checked_add(4095).ok_or(Error::Invalid)? & !4095;
    if start >= end || end > len {
        return Err(Error::Invalid);
    }
    let overlapping = |r: &Range<u64>| r.start < end && start < r.end;
    if used
        .iter()
        .any(|r| overlapping(r) && !protected.contains(r))
    {
        return Err(Error::Busy);
    }
    let merged = used
        .iter()
        .filter(|r| overlapping(r))
        .fold(start..end, |m, r| m.start.min(r.start)..m.end.max(r.end));
    used.try_reserve(1).map_err(|_| Error::Exhausted)?;
    protected.try_reserve(1).map_err(|_| Error::Exhausted)?;
    used.retain(|r| !overlapping(r));
    protected.retain(|r| !overlapping(r));
    let at = used.partition_point(|r| r.start < merged.start);
    used.insert(at, merged.clone());
    protected.push(merged);
    Ok(())
}

/// Owned VRAM with no CPU mapping: what lies beyond a BAR that shows only a
/// prefix of VRAM. Only the GPU can touch it, so whoever hands a range out
/// must have the GPU clear it first.
#[derive(Debug)]
struct Unmapped {
    address: u64,
    len: u64,
    used: IrqSafeSpinLock<Vec<Range<u64>>>,
    /// As `Inner::protected`.
    protected: IrqSafeSpinLock<Vec<Range<u64>>>,
}
#[derive(Clone, Debug)]
pub struct UnmappedPool(Arc<Unmapped>);
impl UnmappedPool {
    /// `len` bytes of VRAM at GPU address `address`, less the
    /// pool-relative `protected` ranges, which stay excluded for good.
    ///
    /// # Safety
    /// As `Pool::from_owned_aperture`, for VRAM no CPU mapping reaches:
    /// every byte outside `protected` is exclusively this pool's.
    pub unsafe fn from_owned(
        address: u64,
        len: u64,
        protected: &[Range<u64>],
    ) -> Result<Self, Error> {
        if len == 0
            || len % 4096 != 0
            || address % 4096 != 0
            || address.checked_add(len).is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        let mut used: Vec<Range<u64>> = Vec::new();
        used.try_reserve_exact(protected.len())
            .map_err(|_| Error::Exhausted)?;
        for range in protected {
            if range.start >= range.end || range.end > len {
                return Err(Error::Invalid);
            }
            let end = range.end.checked_add(4095).ok_or(Error::Invalid)? & !4095;
            used.push((range.start & !4095)..end);
        }
        used.sort_unstable_by_key(|range| range.start);
        let mut merged: Vec<Range<u64>> = Vec::new();
        merged
            .try_reserve_exact(used.len())
            .map_err(|_| Error::Exhausted)?;
        for range in used {
            match merged.last_mut() {
                Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
                _ => merged.push(range),
            }
        }
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(merged.len())
            .map_err(|_| Error::Exhausted)?;
        protected.extend(merged.iter().cloned());
        Ok(Self(Arc::new(Unmapped {
            address,
            len,
            used: IrqSafeSpinLock::new(merged),
            protected: IrqSafeSpinLock::new(protected),
        })))
    }
    /// Reserve `size` bytes at a power-of-two GPU-address `alignment`.
    pub fn reserve_aligned(&self, size: u64, alignment: u64) -> Result<UnmappedReservation, Error> {
        let range = place(
            &mut self.0.used.lock(),
            self.0.address,
            self.0.len,
            size,
            alignment,
        )?;
        Ok(UnmappedReservation {
            pool: self.0.clone(),
            range,
        })
    }
    /// [`Pool::reserve_dcc`] past the BAR.
    pub fn reserve_dcc(
        &self,
        size: u64,
        alignment: u64,
        origin: u64,
    ) -> Result<UnmappedReservation, Error> {
        let range = place_dcc(
            &mut self.0.used.lock(),
            self.0.address,
            self.0.len,
            size,
            alignment,
            origin,
        )?;
        Ok(UnmappedReservation {
            pool: self.0.clone(),
            range,
        })
    }
    pub fn available(&self) -> u64 {
        self.0.len
            - self
                .0
                .used
                .lock()
                .iter()
                .map(|r| r.end - r.start)
                .sum::<u64>()
    }
    pub fn address(&self) -> u64 {
        self.0.address
    }
    pub fn size(&self) -> u64 {
        self.0.len
    }
    /// As [`Pool::claim`], for a pool-relative range.
    pub fn claim(&self, range: Range<u64>) -> Result<(), Error> {
        claim(
            &mut self.0.used.lock(),
            &mut self.0.protected.lock(),
            self.0.len,
            range,
        )
    }
}
/// A range of an [`UnmappedPool`], returned to it on drop: its holder must
/// keep it until the GPU can no longer reach it.
#[derive(Debug)]
pub struct UnmappedReservation {
    pool: Arc<Unmapped>,
    range: Range<u64>,
}
impl UnmappedReservation {
    pub fn address(&self) -> u64 {
        self.pool.address + self.range.start
    }
    pub fn size(&self) -> u64 {
        self.range.end - self.range.start
    }
}
impl Drop for UnmappedReservation {
    fn drop(&mut self) {
        self.pool.used.lock().retain(|r| *r != self.range);
    }
}

/// Dropping an unpublished/stopped reservation returns it to the pool.
/// Once exposed to hardware it must be explicitly marked stopped by its owner.
#[derive(Debug)]
pub struct Reservation {
    pool: Arc<Inner>,
    range: Range<u64>,
    reusable: bool,
}
impl Reservation {
    pub fn address(&self) -> u64 {
        self.pool.address + self.range.start
    }
    pub fn size(&self) -> u64 {
        self.range.end - self.range.start
    }
    pub(crate) fn mapping(&self) -> MmioRegion {
        let map = self.pool.mapping;
        MmioRegion {
            phys: narf_memory::PhysAddr::new(map.phys.raw() + self.range.start),
            virt: map.virt + self.range.start,
            len: self.size(),
            kind: map.kind,
        }
    }
    pub(crate) fn publish(&mut self) {
        self.reusable = false;
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn reusable_for_test(&self) -> bool {
        self.reusable
    }
    /// # Safety
    /// The owning engine is reset/disabled and can no longer access this range.
    pub(crate) unsafe fn stopped(&mut self) {
        self.reusable = true;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.reusable {
            self.pool.used.lock().retain(|r| *r != self.range);
        } else {
            // Keep the exclusion record alive even when the last pool handle
            // is dropped. Recovery must not recycle unknown device ownership;
            // only `Pool::reclaim_retired` after a proven power cycle may.
            self.pool.retired.lock().push(self.range.clone());
            core::mem::forget(self.pool.clone());
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn vram_reservations_reuse_only_quiescent_ranges() -> TestResult {
        let map = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 16384,
            kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
        };
        // SAFETY: bookkeeping-only model; no mapping access is performed.
        let pool = unsafe { Pool::from_owned_range(map, 0x1_0000_0000) }.unwrap();
        let first = pool.reserve(1).unwrap();
        let mut second = pool.reserve(4096).unwrap();
        if first.address() + 4096 != second.address() {
            return TestResult::Fail("overlapping VRAM allocation");
        }
        drop(first);
        let mut reused = pool.reserve(4096).unwrap();
        if reused.address() != 0x1_0000_0000 {
            return TestResult::Fail("free range not reused");
        }
        reused.publish();
        drop(reused);
        second.publish();
        // SAFETY: model has no active hardware accesses.
        unsafe {
            second.stopped();
        }
        drop(second);
        if pool.available() != 12288 || pool.reserve(u64::MAX).is_ok() {
            return TestResult::Fail("VRAM quarantine or overflow");
        }
        let rest = pool.reserve(12288).unwrap();
        if rest.address() != 0x1_0000_1000 || pool.reserve(1).is_ok() {
            return TestResult::Fail("quarantined range recycled");
        }
        TestResult::Pass
    }
    /// A published reservation dropped by its owner stays excluded until a
    /// proven power cycle reclaims it; live and protected ranges never are.
    fn vram_retired_ranges_return_only_on_reclaim() -> TestResult {
        let map = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 5 * 4096,
            kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
        };
        // SAFETY: bookkeeping-only model; no mapping access is performed.
        let pool = unsafe {
            Pool::from_owned_aperture(
                map,
                0x1_0000_0000,
                core::slice::from_ref(&(4 * 4096..5 * 4096)),
            )
        }
        .unwrap();
        let mut old = pool.reserve(2 * 4096).unwrap();
        old.publish();
        let mut kept = pool.reserve(4096).unwrap();
        kept.publish();
        drop(old);
        if pool.retired() != 2 * 4096 || pool.available() != 4096 {
            return TestResult::Fail("dropped published range not retired");
        }
        // SAFETY: model; no hardware can reach the retired range.
        let reclaimed = unsafe { pool.reclaim_retired() };
        if reclaimed != 2 * 4096 || pool.retired() != 0 || pool.available() != 3 * 4096 {
            return TestResult::Fail("reclaim must return exactly the retired range");
        }
        let again = pool.reserve(2 * 4096).unwrap();
        if again.address() != 0x1_0000_0000 || pool.reserve(2 * 4096).is_ok() {
            return TestResult::Fail("reclaimed range not reused, or a live/protected one was");
        }
        // SAFETY: as above; nothing is retired now.
        if unsafe { pool.reclaim_retired() } != 0 || kept.address() != 0x1_0000_2000 {
            return TestResult::Fail("reclaim touched a live reservation");
        }
        TestResult::Pass
    }
    fn vram_unmapped_pool_keeps_protected_ranges() -> TestResult {
        const BASE: u64 = 0x1_1000_0000;
        // SAFETY: bookkeeping-only model; there is no mapping to touch.
        let bad = unsafe {
            UnmappedPool::from_owned(
                BASE,
                0x10_0000,
                core::slice::from_ref(&(0x8_0000..0x10_0001)),
            )
        };
        if bad.is_ok() {
            return TestResult::Fail("protected range past the pool accepted");
        }
        // SAFETY: as above.
        let pool = unsafe {
            UnmappedPool::from_owned(BASE, 0x10_0000, &[0x4_0000..0x4_0800, 0x4_0100..0x6_0000])
        }
        .unwrap();
        if pool.available() != 0x10_0000 - 0x2_0000 || pool.size() != 0x10_0000 {
            return TestResult::Fail("protected ranges not merged to pages");
        }
        let first = pool.reserve_aligned(0x3_0000, 4096).unwrap();
        let aligned = pool.reserve_aligned(0x1000, 0x8_0000).unwrap();
        let gap = pool.reserve_aligned(0x1_0000, 4096).unwrap();
        if first.address() != BASE
            || first.size() != 0x3_0000
            || aligned.address() != BASE + 0x8_0000
            || gap.address() != BASE + 0x3_0000
        {
            return TestResult::Fail("unmapped placement crossed a protected range");
        }
        if pool.reserve_aligned(0x8_0000, 4096).is_ok()
            || pool.reserve_aligned(4096, 3 << 12).is_ok()
        {
            return TestResult::Fail("oversized or misaligned reservation accepted");
        }
        drop(first);
        if pool.reserve_aligned(0x3_0000, 4096).unwrap().address() != BASE {
            return TestResult::Fail("released range not reused");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        vram_reservations_reuse_only_quiescent_ranges
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        vram_retired_ranges_return_only_on_reclaim
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        vram_unmapped_pool_keeps_protected_ranges
    );
    /// `claim` pins a fixed range as amdgpu_bo_create_kernel_at does: over
    /// protected ranges (merging), never over a live or retired reservation.
    fn vram_claim_pins_fixed_ranges_over_protection_only() -> TestResult {
        let map = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 16 * 4096,
            kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
        };
        // SAFETY: bookkeeping-only model; no mapping access is performed.
        let pool = unsafe {
            Pool::from_owned_aperture(
                map,
                0x1_0000_0000,
                core::slice::from_ref(&(14 * 4096..16 * 4096)),
            )
        }
        .unwrap();
        let live = pool.reserve(4096).unwrap();
        let mut retired = pool.reserve(4096).unwrap();
        retired.publish();
        drop(retired);
        if pool.claim(0..4096) != Err(Error::Busy)
            || pool.claim(4096..8192) != Err(Error::Busy)
            || pool.claim(15 * 4096..17 * 4096) != Err(Error::Invalid)
            || pool.claim(4096..4096) != Err(Error::Invalid)
        {
            return TestResult::Fail("claim over a reservation or past the aperture");
        }
        // Overlapping and extending the protected tail, unaligned.
        if pool.claim(12 * 4096 + 1..15 * 4096).is_err() || pool.available() != 10 * 4096 {
            return TestResult::Fail("claim over protection not merged");
        }
        // The pin is permanent and a second claim over it is idempotent.
        if pool.claim(12 * 4096..13 * 4096).is_err() || pool.available() != 10 * 4096 {
            return TestResult::Fail("claim over a claim");
        }
        let rest = pool.reserve(10 * 4096).unwrap();
        if rest.address() != 0x1_0000_2000 || pool.reserve(1).is_ok() {
            return TestResult::Fail("claimed range handed out");
        }
        drop((live, rest));
        // SAFETY: bookkeeping-only model.
        let unmapped = unsafe { UnmappedPool::from_owned(0x2_0000_0000, 8 * 4096, &[]) }.unwrap();
        let held = unmapped.reserve_aligned(4096, 4096).unwrap();
        if unmapped.claim(0..4096) != Err(Error::Busy)
            || unmapped.claim(4096..8 * 4096).is_err()
            || unmapped.available() != 0
        {
            return TestResult::Fail("unmapped claim");
        }
        drop(held);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        vram_claim_pins_fixed_ranges_over_protection_only
    );
}
