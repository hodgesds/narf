//! Reservations within an explicitly owned, CPU-visible VRAM range.
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
        if alignment < 4096 || !alignment.is_power_of_two() {
            return Err(Error::Invalid);
        }
        let size = size.checked_add(4095).ok_or(Error::Invalid)? & !4095;
        if size == 0 {
            return Err(Error::Invalid);
        }
        let mut used = self.0.used.lock();
        let align = |offset: u64| {
            self.0
                .address
                .checked_add(offset)
                .and_then(|address| address.checked_add(alignment - 1))
                .map(|address| address & !(alignment - 1))
                .and_then(|address| address.checked_sub(self.0.address))
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
        if end > self.0.mapping.len {
            return Err(Error::Exhausted);
        }
        used.try_reserve(1).map_err(|_| Error::Exhausted)?;
        used.insert(index, start..end);
        Ok(Reservation {
            pool: self.0.clone(),
            range: start..end,
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
    pub(crate) fn mapping(&self) -> MmioRegion {
        self.0.mapping
    }
    pub(crate) fn address(&self) -> u64 {
        self.0.address
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
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        vram_reservations_reuse_only_quiescent_ranges
    );
}
