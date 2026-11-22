//! The hibernation snapshot (S4 lane 5): Linux's
//! `hibernate_preallocate_memory` and `swsusp_save`
//! (`kernel/power/snapshot.c`).
//!
//! [`preallocate`] runs while the system is live. It counts the saveable
//! frames ([`narf_memory::frame::for_each_saveable_frame`] over
//! [`narf_memory::frame::saveable_ram_ranges`]), takes one free frame per
//! saveable frame plus a margin to hold the copies, and reserves the list
//! of saved frame numbers. [`Prealloc::take`] runs once the devices are
//! frozen, with interrupts off on the only CPU running. It copies every
//! saveable frame, except the copy frames, and allocates nothing while it
//! does. The [`Snapshot`] is then the system's memory at that instant,
//! which lane 6 streams to the image.
//!
//! The copy needs as much free memory as is in use. Linux first shrinks
//! the page cache to make room (`hibernate_preallocate_memory`'s reclaim);
//! NARF fails the hibernation with [`SnapshotError::NoMemory`].

use alloc::vec::Vec;

use narf_memory::frame::{self, PhysFrame, PAGE_SHIFT, PAGE_SIZE};
use narf_memory::PhysAddr;

/// Why a snapshot could not be taken. Either way, no copy frame is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Fewer free frames than the copy needs: `needed` copies, `got` taken.
    NoMemory { needed: u64, got: u64 },
    /// More frames were in use at the copy than the preallocation's margin
    /// allowed for.
    Grew { copies: u64 },
}

/// Copies beyond the frames counted: the preallocation's own bookkeeping
/// and whatever the steps before the copy (device freezing) allocate.
fn margin(count: u64) -> u64 {
    count / 32 + 1024
}

/// The saveable frames in `ranges` right now.
fn count_saveable(ranges: &[(u64, u64)]) -> u64 {
    let mut count = 0;
    for &(start, end) in ranges {
        frame::for_each_saveable_frame(start, end, |_| count += 1);
    }
    count
}

fn pfn_of(frame: PhysFrame) -> u64 {
    frame.start_address().raw() >> PAGE_SHIFT
}

/// The copy frames and the saved frame numbers, filled by
/// [`Prealloc::take`]. Dropping it frees every copy frame.
#[derive(Debug)]
pub struct Snapshot {
    /// Frame `i` of the image is the copy of `pfns[i]`, in walk order.
    pfns: Vec<u64>,
    copies: Vec<PhysFrame>,
    len: usize,
}

impl Snapshot {
    /// Saved frames.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The saved frame numbers, ascending.
    pub fn pfns(&self) -> &[u64] {
        &self.pfns[..self.len]
    }

    /// Saved frame `i`: its frame number and the copy of its contents.
    pub fn page(&self, i: usize) -> (u64, &[u8; PAGE_SIZE as usize]) {
        assert!(i < self.len, "snapshot page {i} of {}", self.len);
        // SAFETY: `copies[i]` is a frame this snapshot owns, reached through
        // the direct map; nothing writes it after the copy.
        let page = unsafe { &*self.copies[i].start_address().kernel_ptr::<[u8; 4096]>() };
        (self.pfns[i], page)
    }

    /// Free the copy frames the snapshot did not use, once interrupts are
    /// back on, so the image write has the memory.
    pub fn release_spare(&mut self) {
        if self.copies.len() > self.len {
            frame::free_frame_batch(&self.copies[self.len..]);
            self.copies.truncate(self.len);
        }
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        frame::free_frame_batch(&self.copies);
    }
}

/// `hibernate_preallocate_memory`'s result: the copy frames and the marks
/// that keep them out of the copy. The snapshot fills it in place, so the
/// kernel restored from the image still owns its copy frames and frees
/// them by dropping it (`swsusp_free`). The restore resumes above the copy,
/// where nothing else would.
#[derive(Debug)]
pub struct Prealloc {
    ranges: Vec<(u64, u64)>,
    /// One bit per frame below the top of the ranges: set for a copy frame.
    taken: Vec<u64>,
    snapshot: Snapshot,
}

impl Prealloc {
    /// Copy frames reserved.
    pub fn capacity(&self) -> usize {
        self.snapshot.copies.len()
    }

    /// `swsusp_save`: copy every saveable frame except the copy frames into
    /// [`Self::snapshot`].
    ///
    /// # Safety
    /// Interrupts are off and no other CPU runs, so no frame changes
    /// between the walk and the copy and the allocator's state is still.
    /// Devices are frozen, so no DMA writes memory meanwhile.
    pub unsafe fn take(&mut self) -> Result<(), SnapshotError> {
        let Self {
            ranges,
            taken,
            snapshot,
        } = self;
        let is_taken = |pfn: u64| {
            taken
                .get((pfn / 64) as usize)
                .is_some_and(|word| word & (1 << (pfn % 64)) != 0)
        };
        let mut n = 0;
        let mut grew = false;
        for &(start, end) in ranges.iter() {
            frame::for_each_saveable_frame(start, end, |pfn| {
                if grew || is_taken(pfn) {
                    return;
                }
                if n == snapshot.copies.len() {
                    grew = true;
                    return;
                }
                let src = PhysAddr::new(pfn << PAGE_SHIFT).kernel_ptr::<u8>();
                let dst = snapshot.copies[n].start_address().kernel_mut_ptr::<u8>();
                // SAFETY: `src` is a RAM frame, which the direct map covers;
                // `dst` is a copy frame this snapshot owns. They differ: a
                // copy frame is never saved.
                unsafe { core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE as usize) };
                snapshot.pfns[n] = pfn;
                n += 1;
            });
        }
        if grew {
            return Err(SnapshotError::Grew {
                copies: snapshot.copies.len() as u64,
            });
        }
        snapshot.len = n;
        Ok(())
    }

    /// The snapshot [`Self::take`] filled.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// [`Snapshot::release_spare`].
    pub fn release_spare(&mut self) {
        self.snapshot.release_spare();
    }
}

/// `hibernate_preallocate_memory`: reserve the copy frames for a snapshot
/// of the memory in use now.
pub fn preallocate() -> Result<Prealloc, SnapshotError> {
    let ranges = frame::saveable_ram_ranges();
    let count = count_saveable(&ranges);
    let needed = count + margin(count);
    let top = ranges.last().map_or(0, |&(_, end)| end);
    let mut snapshot = Snapshot {
        pfns: Vec::new(),
        copies: Vec::new(),
        len: 0,
    };
    let mut taken = Vec::new();
    let reserved = snapshot.copies.try_reserve_exact(needed as usize).is_ok()
        && snapshot.pfns.try_reserve_exact(needed as usize).is_ok()
        && taken.try_reserve_exact(top.div_ceil(64) as usize).is_ok();
    if !reserved {
        return Err(SnapshotError::NoMemory { needed, got: 0 });
    }
    snapshot.pfns.resize(needed as usize, 0);
    taken.resize(top.div_ceil(64) as usize, 0u64);
    while (snapshot.copies.len() as u64) < needed {
        let Ok(copy) = frame::alloc_frame() else {
            // Dropping the snapshot frees what was taken.
            return Err(SnapshotError::NoMemory {
                needed,
                got: snapshot.copies.len() as u64,
            });
        };
        let pfn = pfn_of(copy);
        if let Some(word) = taken.get_mut((pfn / 64) as usize) {
            *word |= 1 << (pfn % 64);
        }
        snapshot.copies.push(copy);
    }
    Ok(Prealloc {
        ranges,
        taken,
        snapshot,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "snapshot_tests.rs"]
mod tests;
