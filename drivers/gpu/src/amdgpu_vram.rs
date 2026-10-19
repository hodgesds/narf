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
}
#[derive(Debug)]
struct Inner {
    mapping: MmioRegion,
    address: u64,
    used: IrqSafeSpinLock<Vec<Range<u64>>>,
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
        Ok(Self(Arc::new(Inner {
            mapping,
            address,
            used: IrqSafeSpinLock::new(used),
        })))
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
    let size = size.checked_add(4095).ok_or(Error::Invalid)? & !4095;
    if size == 0 {
        return Err(Error::Invalid);
    }
    let align = |offset: u64| {
        address
            .checked_add(offset)
            .and_then(|address| address.checked_add(alignment - 1))
            .map(|address| address & !(alignment - 1))
            .and_then(|aligned| aligned.checked_sub(address))
            .ok_or(Error::Exhausted)
    };
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

/// Owned VRAM with no CPU mapping: what lies beyond a BAR that shows only a
/// prefix of VRAM. Only the GPU can touch it, so whoever hands a range out
/// must have the GPU clear it first.
#[derive(Debug)]
struct Unmapped {
    address: u64,
    len: u64,
    used: IrqSafeSpinLock<Vec<Range<u64>>>,
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
        Ok(Self(Arc::new(Unmapped {
            address,
            len,
            used: IrqSafeSpinLock::new(merged),
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
            // is dropped. Recovery must not recycle unknown device ownership.
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
        vram_unmapped_pool_keeps_protected_ranges
    );
}
