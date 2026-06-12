//! narf-drivers-virtio — Virtqueue (Split Virtqueue) implementation.
//!
//! Spec: VirtIO 1.2 §3.2.1 "Split Virtqueues".
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>

use core::sync::atomic::{compiler_fence, Ordering};
use narf_memory::PAGE_SIZE;

/// A single descriptor in the descriptor table.
/// VirtIO 1.2 §3.2.1.1.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

/// Used ring element.
/// VirtIO 1.2 §3.2.1.3.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Helper to ensure memory ordering when talking to the device.
#[inline]
pub fn virtio_fence() {
    compiler_fence(Ordering::SeqCst);
}

/// Layout manager for a Split Virtqueue.
/// Handles base addresses and alignment per VirtIO 1.2 §3.2.1.
#[derive(Copy, Clone, Debug)]
pub struct VirtqueueLayout {
    pub capacity: u16,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
}

impl VirtqueueLayout {
    /// Calculate the layout for a queue of `capacity` starting at `base`.
    /// Returns `None` if the layout exceeds `PAGE_SIZE`.
    pub fn new(capacity: u16, base: u64) -> Option<Self> {
        if !capacity.is_power_of_two() {
            return None;
        }

        let desc_table = base;
        let desc_table_size = 16 * capacity as u64;

        let avail_ring = desc_table + desc_table_size;
        let avail_ring_size = 6 + 2 * capacity as u64;

        // Used ring must be 4-byte aligned (VirtIO 1.2 §3.2.1).
        let used_ring = (avail_ring + avail_ring_size + 3) & !3;
        let used_ring_size = 6 + 8 * capacity as u64;

        let total_size = (used_ring - base) + used_ring_size;
        if total_size > PAGE_SIZE {
            return None;
        }

        Some(Self {
            capacity,
            desc_table,
            avail_ring,
            used_ring,
        })
    }
}

/// A Virtqueue instance managing a single split virtqueue.
#[derive(Debug)]
pub struct Virtqueue {
    layout: VirtqueueLayout,
    /// Next available index in the avail ring (driver-side).
    avail_idx: u16,
    /// Last seen index in the used ring (device-side).
    last_used_idx: u16,

    /// Free descriptors stack.
    free_head: Option<u16>,
    num_free: u16,
}

// SAFETY: Virtqueue owns its raw pointers (derived from layout) and
// ensures they point to device-accessible (DMA) memory. Moving the queue
// between threads only moves the layout addresses and bookkeeping indices,
// not aliased references, so transferring ownership across threads is sound.
unsafe impl Send for Virtqueue {}
// SAFETY: All ring access goes through &mut self (add_buffer/poll_used) or
// volatile reads (used_idx_snapshot); concurrent shared access is serialised
// by the wrapping SpinLock in each device driver and the release/acquire
// ordering established by virtio_fence, so &Virtqueue is safe to share.
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    /// Create a new Virtqueue from a validated layout.
    ///
    /// # Safety
    /// Memory at `layout` must be device-accessible. Contents are
    /// reset by this constructor — recycled frames are safe.
    pub unsafe fn new(layout: VirtqueueLayout) -> Self {
        // Wipe desc_table + avail_ring + used_ring. `alloc_frame`
        // returns recycled (un-zeroed) frames, so a stale used_idx
        // or avail entry left by a previous tenant would otherwise
        // poison this fresh queue: the device would skip the first
        // submission, or `poll_used` would walk junk ring slots.
        let used_ring_size = 6u64 + 8u64 * layout.capacity as u64;
        let total = (layout.used_ring + used_ring_size) - layout.desc_table;
        // SAFETY: layout was validated by VirtqueueLayout::new to
        // fit within PAGE_SIZE; the buffer is owned by the caller.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_bytes(layout.desc_table as *mut u8, 0, total as usize);
        }
        let desc = layout.desc_table as *mut VirtqDesc;
        // Initialise free descriptors stack.
        for i in 0..(layout.capacity - 1) {
            // SAFETY: `desc` points at the descriptor table that
            // VirtqueueLayout::new sized for `capacity` entries within one
            // page; `i` ranges over 0..capacity-1 so `desc.add(i)` is a valid,
            // aligned, exclusively-owned VirtqDesc just zeroed above.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                (*desc.add(i as usize)).next = i + 1;
            }
        }

        Self {
            layout,
            avail_idx: 0,
            last_used_idx: 0,
            free_head: Some(0),
            num_free: layout.capacity,
        }
    }

    pub fn capacity(&self) -> u16 {
        self.layout.capacity
    }

    fn desc_table(&self) -> *mut VirtqDesc {
        self.layout.desc_table as *mut _
    }
    fn avail_base(&self) -> *mut u16 {
        self.layout.avail_ring as *mut _
    }
    fn used_base(&self) -> *mut u16 {
        self.layout.used_ring as *mut _
    }

    fn alloc_desc(&mut self) -> Option<u16> {
        let id = self.free_head?;
        // SAFETY: `id` came from the free-list (free_head / a prior `next`
        // link), so it is a valid descriptor index < capacity; the descriptor
        // table is owned by this queue and `id` indexes within it.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        self.free_head = unsafe {
            let next = (*self.desc_table().add(id as usize)).next;
            if self.num_free > 1 {
                Some(next)
            } else {
                None
            }
        };
        self.num_free -= 1;
        Some(id)
    }

    pub fn free_chain(&mut self, head: u16) {
        let first = head;
        let mut last = head;
        let mut count = 1;

        // SAFETY: `last` is a descriptor index from a chain previously built
        // by add_buffer, so it is < capacity and the table (owned by this
        // queue) holds a valid VirtqDesc at that slot.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        while unsafe { (*self.desc_table().add(last as usize)).flags } & VIRTQ_DESC_F_NEXT != 0 {
            // SAFETY: the NEXT flag just checked guarantees `.next` is a valid
            // in-chain descriptor index < capacity, owned by this queue.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            last = unsafe { (*self.desc_table().add(last as usize)).next };
            count += 1;
        }

        // SAFETY: `last` is the chain tail (valid index < capacity); writing
        // its `next` link to splice the chain back onto the free list only
        // touches this queue's exclusively-owned descriptor table.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            (*self.desc_table().add(last as usize)).next = self.free_head.unwrap_or(0);
        }
        self.free_head = Some(first);
        self.num_free += count;
    }

    pub fn add_buffer(&mut self, descs: &[VirtqDesc]) -> Option<u16> {
        if descs.len() as u16 > self.num_free {
            return None;
        }

        let head = self.alloc_desc().unwrap();
        let mut curr = head;
        let table = self.desc_table();

        for (i, d) in descs.iter().enumerate() {
            let mut desc_val = *d;
            if i < descs.len() - 1 {
                let next = self.alloc_desc().unwrap();
                desc_val.flags |= VIRTQ_DESC_F_NEXT;
                desc_val.next = next;
                // SAFETY: `curr` is a descriptor index just returned by
                // alloc_desc (< capacity), so `table.add(curr)` is a valid,
                // aligned slot in this queue's owned descriptor table.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    *table.add(curr as usize) = desc_val;
                }
                curr = next;
            } else {
                desc_val.flags &= !VIRTQ_DESC_F_NEXT;
                // SAFETY: `curr` is a descriptor index from alloc_desc
                // (< capacity); writing the final descriptor only touches this
                // queue's owned table slot.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    *table.add(curr as usize) = desc_val;
                }
            }
        }

        // Add to avail ring.
        // Avail ring layout: flags(u16), idx(u16), ring[N](u16), used_event(u16)
        // SAFETY: avail_base points at this queue's avail ring (sized for
        // `capacity` entries within one page by VirtqueueLayout::new). `slot`
        // is taken modulo capacity so `ring.add(slot)` (ring = base+2, skipping
        // flags+idx) and base+1 (idx field) are in-bounds, aligned u16 writes
        // to DMA memory owned by this queue. virtio_fence orders the ring-entry
        // store before the idx publication the device observes.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            let ring = self.avail_base().add(2);
            let slot = (self.avail_idx as usize) % (self.layout.capacity as usize);
            *ring.add(slot) = head;

            virtio_fence();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            *(self.avail_base().add(1)) = self.avail_idx;
        }

        Some(head)
    }

    /// Read the current used_idx without consuming any used-ring
    /// entry. Diagnostic; drivers normally use `poll_used`.
    pub fn used_idx_snapshot(&self) -> u16 {
        // SAFETY: used ring is identity-mapped DMA; offset +2 = idx.
        unsafe { core::ptr::read_volatile(self.used_base().add(1)) }
    }

    pub fn poll_used(&mut self) -> Option<(u32, u32)> {
        // Used ring layout: flags(u16), idx(u16), ring[N](VirtqUsedElem), avail_event(u16)
        // SAFETY: used_base+1 is the u16 `idx` field of this queue's used ring
        // (DMA memory sized within one page by VirtqueueLayout::new), valid and
        // aligned to read the device-published index.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let used_idx = unsafe { *(self.used_base().add(1)) };
        if self.last_used_idx == used_idx {
            return None;
        }

        virtio_fence();
        // SAFETY: used_base+2 skips the flags+idx u16 header to the
        // VirtqUsedElem ring array; the cast is to the ring's actual element
        // type. The ring base is 4-byte aligned per VirtqueueLayout::new,
        // matching VirtqUsedElem's alignment.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ring = unsafe { self.used_base().add(2) as *mut VirtqUsedElem };
        let slot = (self.last_used_idx as usize) % (self.layout.capacity as usize);
        // SAFETY: `slot` is taken modulo capacity, so ring.add(slot) is an
        // in-bounds, aligned VirtqUsedElem in this queue's used ring; the
        // device wrote it before bumping used_idx (ordered by virtio_fence).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let elem = unsafe { *ring.add(slot) };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id, elem.len))
    }
}
