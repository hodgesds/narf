//! Sparse physical backing indexed by blocks of virtual page offsets.
//!
//! The logical length records the prefix admitted by callers; absent blocks
//! inside that prefix read as zero. It never determines storage allocation.

use alloc::vec::Vec;
use core::ops::Index;

use crate::PhysAddr;

const BLOCK_PAGES: usize = 64;
static ZERO: PhysAddr = PhysAddr::new(0);

#[derive(Clone, Debug)]
struct Block {
    first: usize,
    slots: [PhysAddr; BLOCK_PAGES],
}

/// Allocation failure while preparing region backing metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackingAllocError;

/// Sparse page-offset map. Slots are grouped in 64-page blocks in a sorted
/// directory. Lookup is logarithmic in allocated blocks. Sequential growth is
/// amortized; a distant fault allocates one block, irrespective of its offset.
///
/// This owns metadata, not frame references: cloning never retains frames and
/// dropping never frees them. AddressSpace owns those transactions.
#[derive(Clone, Debug, Default)]
pub struct RegionBacking {
    blocks: Vec<Block>,
    len: usize,
    #[cfg(any(test, feature = "kernel-test"))]
    fail_next_reserve: bool,
}

impl PartialEq for RegionBacking {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .indexed()
                .filter(|(_, p)| p.raw() != 0)
                .eq(other.indexed().filter(|(_, p)| p.raw() != 0))
    }
}
impl Eq for RegionBacking {}

impl RegionBacking {
    pub const fn new() -> Self {
        Self {
            blocks: Vec::new(),
            len: 0,
            #[cfg(any(test, feature = "kernel-test"))]
            fail_next_reserve: false,
        }
    }

    /// Convert a dense builder without taking ownership of its frames. Empty
    /// blocks are omitted; failure leaves the caller's builder untouched.
    pub fn try_from_slice(phys: &[PhysAddr]) -> Result<Self, BackingAllocError> {
        let count = phys
            .chunks(BLOCK_PAGES)
            .filter(|slots| slots.iter().any(|p| p.raw() != 0))
            .count();
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|_| BackingAllocError)?;
        for (index, slots) in phys.chunks(BLOCK_PAGES).enumerate() {
            if slots.iter().all(|p| p.raw() == 0) {
                continue;
            }
            let mut block = Block {
                first: index * BLOCK_PAGES,
                slots: [ZERO; BLOCK_PAGES],
            };
            block.slots[..slots.len()].copy_from_slice(slots);
            blocks.push(block);
        }
        Ok(Self {
            blocks,
            len: phys.len(),
            #[cfg(any(test, feature = "kernel-test"))]
            fail_next_reserve: false,
        })
    }

    /// Logical prefix length. This is NOT the number of allocated slots.
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn allocated_slots(&self) -> usize {
        self.blocks.len() * BLOCK_PAGES
    }

    /// Heap payload retained by the block directory, including spare capacity.
    pub fn metadata_bytes(&self) -> usize {
        self.blocks.capacity() * core::mem::size_of::<Block>()
    }

    fn block_position(&self, index: usize) -> Result<usize, usize> {
        self.blocks
            .binary_search_by_key(&(index / BLOCK_PAGES * BLOCK_PAGES), |b| b.first)
    }

    pub fn get(&self, index: usize) -> Option<&PhysAddr> {
        if index >= self.len {
            return None;
        }
        Some(
            self.block_position(index)
                .map_or(&ZERO, |b| &self.blocks[b].slots[index % BLOCK_PAGES]),
        )
    }

    pub fn first(&self) -> Option<&PhysAddr> {
        self.get(0)
    }
    pub fn last(&self) -> Option<&PhysAddr> {
        self.len.checked_sub(1).and_then(|i| self.get(i))
    }

    /// Prepare the block before publishing a frame or entering an external
    /// fault handler. Failure leaves both contents and logical length intact.
    pub fn reserve_slot(&mut self, index: usize) -> Result<(), BackingAllocError> {
        let len = index.checked_add(1).ok_or(BackingAllocError)?;
        if let Err(at) = self.block_position(index) {
            #[cfg(any(test, feature = "kernel-test"))]
            if core::mem::take(&mut self.fail_next_reserve) {
                return Err(BackingAllocError);
            }
            self.blocks.try_reserve(1).map_err(|_| BackingAllocError)?;
            self.blocks.insert(
                at,
                Block {
                    first: index / BLOCK_PAGES * BLOCK_PAGES,
                    slots: [ZERO; BLOCK_PAGES],
                },
            );
        }
        self.len = self.len.max(len);
        Ok(())
    }

    /// Mutate only an explicitly reserved block; never allocates.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut PhysAddr> {
        if index >= self.len {
            return None;
        }
        let at = self.block_position(index).ok()?;
        Some(&mut self.blocks[at].slots[index % BLOCK_PAGES])
    }

    /// Allocated slots with their original virtual page indices. Missing
    /// blocks are skipped; callers must never enumerate these values to infer
    /// virtual offsets.
    pub fn indexed(&self) -> impl DoubleEndedIterator<Item = (usize, &PhysAddr)> + '_ {
        self.indexed_range(0, self.len)
    }

    pub fn indexed_range(
        &self,
        first: usize,
        end: usize,
    ) -> impl DoubleEndedIterator<Item = (usize, &PhysAddr)> + '_ {
        self.chunks(first, end)
            .flat_map(|(first, slots)| slots.iter().enumerate().map(move |(i, p)| (first + i, p)))
    }

    /// Bounded contiguous slices, paired with absolute region page offsets.
    pub fn chunks(
        &self,
        first: usize,
        end: usize,
    ) -> impl DoubleEndedIterator<Item = (usize, &[PhysAddr])> + '_ {
        let end = end.min(self.len);
        let lo = self
            .blocks
            .partition_point(|b| b.first.saturating_add(BLOCK_PAGES) <= first);
        let hi = if first < end {
            self.blocks.partition_point(|b| b.first < end).max(lo)
        } else {
            lo
        };
        self.blocks[lo..hi].iter().map(move |b| {
            let start = first.max(b.first);
            let last = end.min(b.first.saturating_add(BLOCK_PAGES));
            (start, &b.slots[start - b.first..last - b.first])
        })
    }

    /// Logical-slot iterator, including implicit zeros. Use `indexed` or
    /// `chunks` for ownership/PTE walks so their cost tracks allocated blocks.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &PhysAddr> + ExactSizeIterator + '_ {
        (0..self.len).map(|i| self.get(i).unwrap())
    }

    pub fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        self.len = len;
        let keep = self.blocks.partition_point(|b| b.first < len);
        self.blocks.truncate(keep);
        if let Some(b) = self.blocks.last_mut() {
            let used = len.saturating_sub(b.first).min(BLOCK_PAGES);
            b.slots[used..].fill(ZERO);
        }
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.len = 0;
    }

    pub fn try_window(&self, first: usize, pages: usize) -> Result<Self, BackingAllocError> {
        let end = first.saturating_add(pages).min(self.len);
        let mut copy = Self::new();
        copy.len = end.saturating_sub(first);
        // An unaligned source block may straddle two destination blocks, and
        // neighboring source chunks may share the boundary block. Count the
        // distinct destination keys before allocating so aligned copies do
        // not retain twice the necessary metadata capacity.
        let mut count = 0usize;
        let mut previous = None;
        for (start, slots) in self.chunks(first, end) {
            let lo = (start - first) / BLOCK_PAGES;
            let hi = (start - first + slots.len() - 1) / BLOCK_PAGES;
            count += usize::from(previous != Some(lo)) + usize::from(hi != lo);
            previous = Some(hi);
        }
        copy.blocks
            .try_reserve_exact(count)
            .map_err(|_| BackingAllocError)?;
        for (start, slots) in self.chunks(first, end) {
            for (i, &p) in slots.iter().enumerate() {
                // Preserve reserved zero slots as well: fault claims and swap
                // slots can be in flight while metadata is split or cloned.
                let index = start + i - first;
                copy.reserve_slot(index)?;
                *copy.get_mut(index).unwrap() = p;
            }
        }
        Ok(copy)
    }

    pub fn try_clone(&self) -> Result<Self, BackingAllocError> {
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(self.blocks.len())
            .map_err(|_| BackingAllocError)?;
        blocks.extend_from_slice(&self.blocks);
        Ok(Self {
            blocks,
            len: self.len,
            #[cfg(any(test, feature = "kernel-test"))]
            fail_next_reserve: false,
        })
    }

    /// Reserve for a dense append. Sparse copies must use `try_window` or
    /// `try_clone`, which reserve by allocated blocks rather than logical len.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), BackingAllocError> {
        let blocks = additional
            .checked_add(BLOCK_PAGES - 1)
            .ok_or(BackingAllocError)?
            / BLOCK_PAGES;
        self.blocks
            .try_reserve(blocks.saturating_add(usize::from(additional != 0)))
            .map_err(|_| BackingAllocError)
    }

    pub fn resize(&mut self, len: usize, value: PhysAddr) {
        if len <= self.len {
            self.truncate(len);
            return;
        }
        if value.raw() == 0 {
            self.len = len;
            return;
        }
        while self.len < len {
            self.push(value);
        }
    }

    pub fn push(&mut self, value: PhysAddr) {
        let index = self.len;
        if value.raw() != 0 {
            self.reserve_slot(index)
                .expect("region backing allocation failed");
            *self.get_mut(index).unwrap() = value;
        } else {
            self.len = self
                .len
                .checked_add(1)
                .expect("region backing length overflow");
        }
    }
}

impl From<Vec<PhysAddr>> for RegionBacking {
    fn from(phys: Vec<PhysAddr>) -> Self {
        Self::try_from_slice(&phys).expect("region backing allocation failed")
    }
}
impl FromIterator<PhysAddr> for RegionBacking {
    fn from_iter<T: IntoIterator<Item = PhysAddr>>(iter: T) -> Self {
        let mut backing = Self::new();
        for phys in iter {
            backing.push(phys);
        }
        backing
    }
}
impl Index<usize> for RegionBacking {
    type Output = PhysAddr;
    fn index(&self, index: usize) -> &PhysAddr {
        self.get(index).expect("region backing index out of bounds")
    }
}

impl core::ops::IndexMut<usize> for RegionBacking {
    fn index_mut(&mut self, index: usize) -> &mut PhysAddr {
        self.get_mut(index)
            .expect("region backing slot was not reserved")
    }
}
impl RegionBacking {
    pub fn append(&mut self, other: &mut Self) {
        let first = self.len;
        let end = first
            .checked_add(other.len)
            .expect("region backing length overflow");
        for (i, &p) in other.indexed() {
            let index = first + i;
            self.reserve_slot(index)
                .expect("region backing allocation failed");
            *self.get_mut(index).unwrap() = p;
        }
        self.len = end;
        other.clear();
    }
    pub fn for_each_chunk_mut(
        &mut self,
        first: usize,
        end: usize,
        mut f: impl FnMut(usize, &mut [PhysAddr]),
    ) {
        let end = end.min(self.len);
        for block in &mut self.blocks {
            let start = first.max(block.first);
            let last = end.min(block.first.saturating_add(BLOCK_PAGES));
            if start < last {
                f(
                    start,
                    &mut block.slots[start - block.first..last - block.first],
                );
            }
        }
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;

    fn distant_and_split() -> Result<(), &'static str> {
        let mut backing = RegionBacking::new();
        for i in [0, 63, 64, 65, 1 << 28] {
            backing.reserve_slot(i).map_err(|_| "reserve failed")?;
            *backing.get_mut(i).ok_or("reserved slot missing")? =
                PhysAddr::new((i as u64 + 1) * 4096);
        }
        if backing.allocated_slots() != 192 || backing.metadata_bytes() > 4096 {
            return Err("distant offset consumed proportional metadata");
        }
        if backing[1].raw() != 0 || backing[(1 << 28) - 1].raw() != 0 {
            return Err("absent block is not demand-zero");
        }
        let split = backing
            .try_window(63, 1 << 28)
            .map_err(|_| "split failed")?;
        let actual: Vec<_> = split
            .indexed()
            .filter(|(_, p)| p.raw() != 0)
            .map(|(i, p)| (i, p.raw()))
            .collect();
        let expected = [
            (0, 64 * 4096),
            (1, 65 * 4096),
            (2, 66 * 4096),
            ((1 << 28) - 63, ((1u64 << 28) + 1) * 4096),
        ];
        if actual != expected {
            return Err("unaligned split changed page offsets or frames");
        }
        for (first, end) in [(1, 1), (65, 64), (66, 66), ((1 << 28) + 1, (1 << 28) + 2)] {
            if backing.indexed_range(first, end).next().is_some() {
                return Err("empty interval produced a slot");
            }
        }
        let before = backing.try_clone().map_err(|_| "clone failed")?;
        if backing.reserve_slot(usize::MAX).is_ok() || backing != before {
            return Err("failed reservation mutated backing");
        }
        backing.fail_next_reserve = true;
        if backing.reserve_slot((1 << 28) + 64).is_ok() || backing != before {
            return Err("metadata allocation failure changed backing");
        }
        backing
            .reserve_slot((1 << 28) + 64)
            .map_err(|_| "reservation retry failed")?;
        // Publication into the reserved slot does not allocate, including
        // when a subsequent block reservation is configured to fail.
        backing.fail_next_reserve = true;
        *backing
            .get_mut((1 << 28) + 64)
            .ok_or("retry slot missing")? = PhysAddr::new(0x8000);
        if !backing.fail_next_reserve {
            return Err("publication allocated metadata");
        }
        backing.fail_next_reserve = false;
        backing.truncate(64);
        backing.resize(1 << 29, ZERO);
        if backing[64].raw() != 0 || backing[1 << 28].raw() != 0 || backing.allocated_slots() != 64
        {
            return Err("truncate/grow resurrected discarded backing");
        }
        Ok(())
    }

    fn dense_model() -> Result<(), &'static str> {
        let mut seed = 41u64;
        let mut backing = RegionBacking::new();
        let mut model = Vec::new();
        for _ in 0..1000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let i = (seed as usize >> 16) % 300;
            backing
                .reserve_slot(i)
                .map_err(|_| "model reserve failed")?;
            model.resize(model.len().max(i + 1), ZERO);
            let value = PhysAddr::new(seed & 0xFFFFF000);
            *backing.get_mut(i).ok_or("reserved model slot missing")? = value;
            model[i] = value;
            if !backing.iter().copied().eq(model.iter().copied()) {
                return Err("sparse values differ from dense model");
            }
            let first = i / 2;
            let copy = backing
                .try_window(first, i)
                .map_err(|_| "model split failed")?;
            if !copy
                .iter()
                .copied()
                .eq(model[first..(first + i).min(model.len())].iter().copied())
            {
                return Err("sparse split differs from dense model");
            }
            if i % 17 == 0 {
                backing.truncate(i);
                model.truncate(i);
            }
        }
        Ok(())
    }

    #[test]
    fn sparse_backing_distant_split() {
        distant_and_split().unwrap();
    }
    #[test]
    fn sparse_backing_dense_model() {
        dense_model().unwrap();
    }

    #[cfg(feature = "kernel-test")]
    fn smoke_sparse_backing_distant_split() -> narf_kernel_test::TestResult {
        match distant_and_split() {
            Ok(()) => narf_kernel_test::TestResult::Pass,
            Err(e) => narf_kernel_test::TestResult::Fail(e),
        }
    }
    #[cfg(feature = "kernel-test")]
    fn smoke_sparse_backing_dense_model() -> narf_kernel_test::TestResult {
        match dense_model() {
            Ok(()) => narf_kernel_test::TestResult::Pass,
            Err(e) => narf_kernel_test::TestResult::Fail(e),
        }
    }
    #[cfg(feature = "kernel-test")]
    narf_kernel_test::kernel_test_in!("memory", smoke_sparse_backing_distant_split);
    #[cfg(feature = "kernel-test")]
    narf_kernel_test::kernel_test_in!("memory", smoke_sparse_backing_dense_model);
}
