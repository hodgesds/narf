//! Per-domain IOVA allocator.
//!
//! A simplified Linux `drivers/iommu/iova.c` (`struct iova_domain`):
//! allocations are page-frame ranges, searched top-down from a caller
//! limit (`__alloc_and_insert_iova_range`), and size-aligned to the next
//! power of two when asked (`alloc_iova(.., size_aligned = true)`, the
//! mode `iommu_dma_alloc_iova` always uses). The rbtree becomes a
//! `BTreeMap<pfn_lo, pfn_hi>`; the per-CPU rcache is not modelled.
//!
//! **No reuse before IOTLB invalidation completes.** The allocator itself
//! only frees what it is told to; the ordering lives in
//! [`crate::iommu::IommuDomain`], which frees an IOVA only after its PTEs
//! are cleared AND the backend's IOTLB flush + completion wait returned
//! (Linux `__iommu_dma_unmap`: `iommu_unmap_fast` → `iommu_iotlb_sync` →
//! `iommu_dma_free_iova`). A range whose flush failed is never freed
//! ([`IovaAllocator::quarantine`]) — a stale IOTLB entry could still
//! translate it.

extern crate alloc;

use alloc::collections::BTreeMap;

/// IOVA page-frame allocator for one translation domain.
#[derive(Debug, Clone)]
pub struct IovaAllocator {
    /// First allocatable pfn (Linux `iovad->start_pfn`; pfn 0 is never
    /// handed out so a zero DMA address stays an obvious bug).
    start_pfn: u64,
    /// One past the last pfn the domain's page table can translate.
    end_pfn: u64,
    /// Live and reserved ranges: `pfn_lo -> pfn_hi` (inclusive).
    ranges: BTreeMap<u64, u64>,
    /// Ranges parked forever because their invalidation did not complete.
    quarantined: u64,
}

impl IovaAllocator {
    /// Allocator over `[start_pfn, end_pfn)`. `start_pfn` is clamped to 1
    /// (Linux `init_iova_domain` with `start_pfn >= 1`).
    pub fn new(start_pfn: u64, end_pfn: u64) -> Self {
        Self {
            start_pfn: start_pfn.max(1),
            end_pfn,
            ranges: BTreeMap::new(),
            quarantined: 0,
        }
    }

    /// Permanently reserve `[pfn_lo, pfn_hi]` (Linux `reserve_iova`), e.g.
    /// the x86 MSI doorbell window. Overlap with an existing range is
    /// merged into one reservation.
    pub fn reserve(&mut self, pfn_lo: u64, pfn_hi: u64) {
        if pfn_lo > pfn_hi {
            return;
        }
        let mut lo = pfn_lo;
        let mut hi = pfn_hi;
        let overlapping: alloc::vec::Vec<u64> = self
            .ranges
            .range(..=pfn_hi)
            .filter(|(_, &h)| h >= pfn_lo)
            .map(|(&l, _)| l)
            .collect();
        for l in overlapping {
            if let Some(h) = self.ranges.remove(&l) {
                lo = lo.min(l);
                hi = hi.max(h);
            }
        }
        self.ranges.insert(lo, hi);
    }

    /// Allocate `pages` pfns whose last pfn is `<= limit_pfn`, highest
    /// fit first. With `size_aligned`, the start is aligned to
    /// `pages.next_power_of_two()` (Linux `iova_get_pad`-free variant of
    /// `__alloc_and_insert_iova_range`). Returns the first pfn.
    pub fn alloc(&mut self, pages: u64, limit_pfn: u64, size_aligned: bool) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        let align = if size_aligned {
            pages.checked_next_power_of_two()?
        } else {
            1
        };
        let limit = limit_pfn.min(self.end_pfn.checked_sub(1)?);
        // Walk gaps from the top down: each gap is (gap_lo, gap_hi).
        let mut gap_hi = limit;
        let mut iter = self.ranges.range(..=limit).rev().peekable();
        // A range straddling `limit` caps the first gap below it.
        loop {
            let (gap_lo, next_hi) = match iter.peek() {
                Some((&lo, &hi)) => {
                    if hi >= gap_hi {
                        // Range covers the top of the gap; move below it.
                        gap_hi = lo.checked_sub(1)?;
                        iter.next();
                        continue;
                    }
                    (hi + 1, Some(lo))
                }
                None => (self.start_pfn, None),
            };
            if gap_hi >= gap_lo && gap_hi - gap_lo + 1 >= pages {
                let start = (gap_hi + 1 - pages) & !(align - 1);
                if start >= gap_lo && start >= self.start_pfn {
                    self.ranges.insert(start, start + pages - 1);
                    return Some(start);
                }
            }
            let lo = next_hi?;
            iter.next();
            gap_hi = lo.checked_sub(1)?;
        }
    }

    /// Reserve exactly `[pfn, pfn + pages)` for a caller-chosen IOVA.
    /// Fails when any page is already allocated, reserved or out of range.
    pub fn alloc_fixed(&mut self, pfn: u64, pages: u64) -> bool {
        let Some(last) = pfn.checked_add(pages).and_then(|e| e.checked_sub(1)) else {
            return false;
        };
        if pages == 0 || pfn < self.start_pfn || last >= self.end_pfn {
            return false;
        }
        if self.ranges.range(..=last).any(|(_, &h)| h >= pfn) {
            return false;
        }
        self.ranges.insert(pfn, last);
        true
    }

    /// Free the range starting at `pfn` (Linux `free_iova`). The caller
    /// must already have completed IOTLB invalidation for it. Returns the
    /// freed page count, or `None` if `pfn` does not start a range.
    pub fn free(&mut self, pfn: u64) -> Option<u64> {
        self.ranges.remove(&pfn).map(|hi| hi - pfn + 1)
    }

    /// Keep the range starting at `pfn` allocated forever: its IOTLB
    /// invalidation did not complete, so reuse could alias a stale
    /// translation. Returns the parked page count.
    pub fn quarantine(&mut self, pfn: u64) -> Option<u64> {
        let pages = self.ranges.get(&pfn).map(|&hi| hi - pfn + 1)?;
        self.quarantined += pages;
        Some(pages)
    }

    /// Pages parked by [`Self::quarantine`].
    pub fn quarantined_pages(&self) -> u64 {
        self.quarantined
    }

    /// Size in pages of the range starting at `pfn`.
    pub fn range_pages(&self, pfn: u64) -> Option<u64> {
        self.ranges.get(&pfn).map(|&hi| hi - pfn + 1)
    }

    /// Number of ranges (allocations + reservations).
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }
}
