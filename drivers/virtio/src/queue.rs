//! narf-drivers-virtio — Virtqueue (Split Virtqueue) implementation.
//!
//! Spec: VirtIO 1.2 §3.2.1 "Split Virtqueues".

use core::sync::atomic::{compiler_fence, Ordering};
use narf_memory::PAGE_SIZE;

/// A single descriptor in the descriptor table.
/// VirtIO 1.2 §3.2.1.1.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtqDesc {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

pub const VIRTQ_DESC_F_NEXT:     u16 = 1;
pub const VIRTQ_DESC_F_WRITE:    u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

/// Used ring element.
/// VirtIO 1.2 §3.2.1.3.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtqUsedElem {
    pub id:  u32,
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
    pub capacity:   u16,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring:  u64,
}

impl VirtqueueLayout {
    /// Calculate the layout for a queue of `capacity` starting at `base`.
    /// Returns `None` if the layout exceeds `PAGE_SIZE`.
    pub fn new(capacity: u16, base: u64) -> Option<Self> {
        if !capacity.is_power_of_two() { return None; }

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

        Some(Self { capacity, desc_table, avail_ring, used_ring })
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
    num_free:  u16,
}

// SAFETY: Virtqueue owns its raw pointers (derived from layout) and
// ensures they point to device-accessible (DMA) memory. Synchronisation
// is handled by the device-driver protocol (release/acquire via
// virtio_fence) and the wrapping SpinLock in the device driver.
unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    /// Create a new Virtqueue from a validated layout.
    ///
    /// # Safety
    /// Memory at `layout` must be zeroed and device-accessible.
    pub unsafe fn new(layout: VirtqueueLayout) -> Self {
        let desc = layout.desc_table as *mut VirtqDesc;
        // Initialise free descriptors stack.
        for i in 0..(layout.capacity - 1) {
            unsafe { (*desc.add(i as usize)).next = i + 1; }
        }

        Self {
            layout,
            avail_idx: 0,
            last_used_idx: 0,
            free_head: Some(0),
            num_free: layout.capacity,
        }
    }

    pub fn capacity(&self) -> u16 { self.layout.capacity }

    fn desc_table(&self) -> *mut VirtqDesc { self.layout.desc_table as *mut _ }
    fn avail_base(&self) -> *mut u16 { self.layout.avail_ring as *mut _ }
    fn used_base(&self)  -> *mut u16 { self.layout.used_ring as *mut _ }

    fn alloc_desc(&mut self) -> Option<u16> {
        let id = self.free_head?;
        self.free_head = unsafe {
            let next = (*self.desc_table().add(id as usize)).next;
            if self.num_free > 1 { Some(next) } else { None }
        };
        self.num_free -= 1;
        Some(id)
    }

    pub fn free_chain(&mut self, head: u16) {
        let first = head;
        let mut last = head;
        let mut count = 1;

        while unsafe { (*self.desc_table().add(last as usize)).flags } & VIRTQ_DESC_F_NEXT != 0 {
            last = unsafe { (*self.desc_table().add(last as usize)).next };
            count += 1;
        }

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
                unsafe { *table.add(curr as usize) = desc_val; }
                curr = next;
            } else {
                desc_val.flags &= !VIRTQ_DESC_F_NEXT;
                unsafe { *table.add(curr as usize) = desc_val; }
            }
        }

        // Add to avail ring.
        // Avail ring layout: flags(u16), idx(u16), ring[N](u16), used_event(u16)
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
        let used_idx = unsafe { *(self.used_base().add(1)) };
        if self.last_used_idx == used_idx {
            return None;
        }

        virtio_fence();
        let ring = unsafe { self.used_base().add(2) as *mut VirtqUsedElem };
        let slot = (self.last_used_idx as usize) % (self.layout.capacity as usize);
        let elem = unsafe { *ring.add(slot) };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id, elem.len))
    }
}
