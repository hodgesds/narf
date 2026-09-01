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

// Virtqueue memory barriers, split by ordering requirement (the Linux
// `virt_wmb`/`virt_rmb`/`virt_mb` model). The device is a peer agent
// (QEMU I/O thread under KVM/MTTCG, or real hardware), so the driver's
// ring accesses must be ordered *as the device observes them*.
//
// x86 is TSO: it never reorders store→store or load→load, so `wmb`/`rmb`
// need only a compiler barrier (matching Linux, where they compile to
// `barrier()`). It *does* reorder store→load, so a full barrier must be a
// real hardware `mfence` — a compiler barrier is not enough there. The
// three-way split keeps the cheap barrier on the hot wmb/rmb paths while
// using a true fence exactly where store→load ordering demands it.

/// Write barrier: order prior ring-entry stores before a following index
/// publication the device reads (store→store).
#[inline]
pub fn virtio_wmb() {
    compiler_fence(Ordering::Release);
}

/// Read barrier: order a prior index load before following ring-entry
/// loads (load→load).
#[inline]
pub fn virtio_rmb() {
    compiler_fence(Ordering::Acquire);
}

/// Full barrier: order a prior store to a ring index before a following
/// load of the device's own ring state (store→load). MUST be a real
/// hardware fence on x86 — the CPU is permitted to reorder store→load, so
/// a compiler barrier here lets the driver read a stale device flag (e.g.
/// `needs_kick`) and skip a notification the device needed, wedging the
/// queue.
#[inline]
pub fn virtio_mb() {
    core::sync::atomic::fence(Ordering::SeqCst);
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

    /// VIRTIO_RING_F_EVENT_IDX negotiated. When set, `needs_kick` consults the
    /// device-published `avail_event` (via `vring_need_event`) instead of the
    /// coarse VIRTQ_USED_F_NO_NOTIFY flag, suppressing far more TX-notify
    /// VM-exits under load (each notify is a VM-exit to QEMU; on the SLIRP
    /// backend that host crossing dominates the feed cost).
    event_idx: bool,
    /// The `avail_idx` value at the last notification the driver sent —
    /// `old_idx` for `vring_need_event`.
    last_notify_avail: u16,
}

/// Linux `vring_need_event`: with EVENT_IDX, notify the device iff its
/// published `event_idx` (the avail index it wants a kick at) lies in the
/// window of avail indices we just published `(old_idx, new_idx]`. Wrapping
/// u16 arithmetic per the virtio spec §2.7.10.
#[inline]
fn vring_need_event(event_idx: u16, new_idx: u16, old_idx: u16) -> bool {
    new_idx.wrapping_sub(event_idx).wrapping_sub(1) < new_idx.wrapping_sub(old_idx)
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
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(layout.desc_table).kernel_mut_ptr::<u8>(),
                0,
                total as usize,
            );
        }
        let desc = narf_memory::PhysAddr::new(layout.desc_table).kernel_mut_ptr::<VirtqDesc>();
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
            event_idx: false,
            last_notify_avail: 0,
        }
    }

    pub fn capacity(&self) -> u16 {
        self.layout.capacity
    }

    /// Enable the EVENT_IDX notification protocol on this queue (call once at
    /// bring-up if the transport negotiated VIRTIO_RING_F_EVENT_IDX).
    pub fn set_event_idx(&mut self, on: bool) {
        self.event_idx = on;
    }

    // `layout.*` are DEVICE addresses — they are what gets programmed into
    // the queue registers (`write64_split(CC_QUEUE_DESC, layout.desc_table)`),
    // so they must stay physical there. The CPU cannot dereference them
    // directly: virtio I/O runs on whatever address space the calling task
    // has, and user address spaces no longer carry the low identity map.
    // Casting these to pointers faulted the moment a userspace process drove
    // the NIC — `netserve: accepted connection` then #PF in `poll_used`.
    fn desc_table(&self) -> *mut VirtqDesc {
        narf_memory::PhysAddr::new(self.layout.desc_table).kernel_mut_ptr::<VirtqDesc>()
    }
    fn avail_base(&self) -> *mut u16 {
        narf_memory::PhysAddr::new(self.layout.avail_ring).kernel_mut_ptr::<u16>()
    }
    fn used_base(&self) -> *mut u16 {
        narf_memory::PhysAddr::new(self.layout.used_ring).kernel_mut_ptr::<u16>()
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
                // `write_volatile`: this is DMA memory the device reads, so
                // the store must not be elided/cached by the compiler (it
                // can't prove the device is a reader). Mirrors the
                // `read_volatile` on the used-ring side. Matters under KVM,
                // where the device runs on another host CPU asynchronously.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    core::ptr::write_volatile(table.add(curr as usize), desc_val);
                }
                curr = next;
            } else {
                desc_val.flags &= !VIRTQ_DESC_F_NEXT;
                // SAFETY: `curr` is a descriptor index from alloc_desc
                // (< capacity); writing the final descriptor only touches this
                // queue's owned table slot. `write_volatile`: DMA memory the
                // device reads (see the next-descriptor write above).
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    core::ptr::write_volatile(table.add(curr as usize), desc_val);
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
            // `write_volatile` for both DMA-ring stores the device reads.
            // A plain store lets the compiler elide/coalesce it (it can't
            // prove the device is a reader), so under KVM — where the device
            // polls these from another host CPU — a posted buffer could be
            // invisible and the queue would stall. `virtio_fence` keeps the
            // ring-entry store ordered before the idx publication.
            core::ptr::write_volatile(ring.add(slot), head);

            virtio_wmb();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            core::ptr::write_volatile(self.avail_base().add(1), self.avail_idx);
        }

        Some(head)
    }

    /// Read the current used_idx without consuming any used-ring
    /// entry. Diagnostic; drivers normally use `poll_used`.
    pub fn used_idx_snapshot(&self) -> u16 {
        // SAFETY: used ring is identity-mapped DMA; offset +2 = idx.
        unsafe { core::ptr::read_volatile(self.used_base().add(1)) }
    }

    /// Non-mutating queue state for fatal-path diagnostics.
    ///
    /// The tuple is `(avail_idx, last_used_idx, device_used_idx, num_free)`.
    /// Reading it does not consume a completion.
    pub fn diagnostic_snapshot(&self) -> (u16, u16, u16, u16) {
        (
            self.avail_idx,
            self.last_used_idx,
            self.used_idx_snapshot(),
            self.num_free,
        )
    }

    /// Returns true if the device requested a notification (kick) for this queue.
    /// In VIRTIO 1.0 (without EVENT_IDX), this is checked via the `used` ring's
    /// flags. If `VIRTQ_USED_F_NO_NOTIFY` (bit 0) is set, the device is actively
    /// processing the queue and does not need a kick.
    pub fn needs_kick(&mut self) -> bool {
        // Full barrier: our prior `avail_idx` store (in `submit`) must be
        // visible to the device before we load its notification state, or the
        // store→load reorder x86 permits lets us read stale state and skip a
        // kick the device needed. Requires a real hardware fence.
        virtio_mb();
        if self.event_idx {
            // EVENT_IDX: the device publishes `avail_event` (the avail index it
            // wants a kick at) in the last u16 of the used ring. Notify only
            // when our newly-published range crosses it. Used ring layout:
            // flags(u16) idx(u16) ring[N](8B) avail_event(u16) → avail_event is
            // at u16 offset 2 + N*4.
            let cap = self.layout.capacity as usize;
            // SAFETY: used ring is DMA memory sized for `capacity` entries plus
            // the trailing avail_event u16 by VirtqueueLayout::new.
            let avail_event =
                unsafe { core::ptr::read_volatile(self.used_base().add(2 + cap * 4)) };
            let new_idx = self.avail_idx;
            let old_idx = self.last_notify_avail;
            let need = vring_need_event(avail_event, new_idx, old_idx);
            if need {
                self.last_notify_avail = new_idx;
            }
            return need;
        }
        // VIRTIO 1.0 fallback: the coarse VIRTQ_USED_F_NO_NOTIFY flag.
        // SAFETY: used ring is identity-mapped DMA; offset +0 = flags.
        let flags = unsafe { core::ptr::read_volatile(self.used_base()) };
        (flags & 1) == 0
    }

    pub fn poll_used(&mut self) -> Option<(u32, u32)> {
        // Used ring layout: flags(u16), idx(u16), ring[N](VirtqUsedElem), avail_event(u16)
        // SAFETY: used_base+1 is the u16 `idx` field of this queue's used ring
        // (DMA memory sized within one page by VirtqueueLayout::new), valid and
        // aligned to read the device-published index.
        // `read_volatile`: the device bumps this index from another host CPU
        // under KVM. A plain read lets the compiler hoist/cache it (this is
        // called in a tight drain loop), so a stale value would make
        // `poll_used` report "no completion" forever — RX/TX wedges. Plain
        // reads happen to work under TCG only because the device updates the
        // ring synchronously inside the notify MMIO write.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let used_idx = unsafe { core::ptr::read_volatile(self.used_base().add(1)) };
        if self.last_used_idx == used_idx {
            return None;
        }

        virtio_rmb();
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
        // `read_volatile`: DMA memory written by the device (see used_idx).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let elem = unsafe { core::ptr::read_volatile(ring.add(slot)) };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        // EVENT_IDX: publish `used_event` = the index we've now consumed, so the
        // device raises the next interrupt only when a NEW completion arrives
        // (used_idx passes this). Without EVENT_IDX the device honours the avail
        // ring's NO_INTERRUPT flag instead; with it negotiated, the flag is
        // ignored and used_event is the sole interrupt control — so an RX queue
        // whose forwarder parks on the IRQ would never wake without this write.
        // Avail ring layout: flags(u16) idx(u16) ring[N](u16) used_event(u16) →
        // used_event is at u16 offset 2 + N.
        if self.event_idx {
            let cap = self.layout.capacity as usize;
            // SAFETY: avail ring is DMA memory sized for `capacity` entries plus
            // the trailing used_event u16 by VirtqueueLayout::new.
            unsafe {
                core::ptr::write_volatile(self.avail_base().add(2 + cap), self.last_used_idx);
            }
        }
        Some((elem.id, elem.len))
    }

    /// Enable used-ring interrupts and re-check for an already-pending
    /// completion — the Linux `virtqueue_enable_cb()` sequence, run by a poller
    /// right before it commits to parking on the IRQ.
    ///
    /// Returns `true` if the device has ALREADY published a completion we have
    /// not consumed. The caller MUST then drain instead of parking: the device
    /// may have suppressed the interrupt for that completion (EVENT_IDX arm
    /// race, or QEMU/SLIRP used-ring interrupt coalescing), so `wait_for_irq`
    /// would sleep out its deadline on a frame that is already sitting in the
    /// ring — the missed-interrupt that gives sequential off-box request/reply
    /// its p99 tail. Arming BEFORE the re-read (with the barrier between) is
    /// load-bearing: it guarantees the device raises an interrupt for any
    /// completion it publishes AFTER our re-read, so a frame in the tiny window
    /// between the read and the park still wakes us.
    pub fn enable_used_cb_and_pending(&mut self) -> bool {
        if self.event_idx {
            // EVENT_IDX: arm `used_event` at the index we've consumed so the
            // device interrupts on the next completion. Same store `poll_used`
            // makes on consume, but done explicitly here for the empty-drain
            // case where nothing was consumed this round.
            let cap = self.layout.capacity as usize;
            // SAFETY: avail ring is DMA memory sized for `capacity` entries plus
            // the trailing used_event u16 (VirtqueueLayout::new); offset 2 + cap.
            unsafe {
                core::ptr::write_volatile(self.avail_base().add(2 + cap), self.last_used_idx);
            }
        } else {
            // No EVENT_IDX: clear VRING_AVAIL_F_NO_INTERRUPT (avail flags @ off 0)
            // so the device raises used-ring interrupts.
            // SAFETY: avail_base is the avail ring's `flags` u16 (DMA memory).
            unsafe {
                core::ptr::write_volatile(self.avail_base(), 0u16);
            }
        }
        // Store-load barrier: the arm above must be visible to the device
        // before we load `used.idx`, mirroring virtqueue_enable_cb's mb().
        virtio_mb();
        // SAFETY: used_base+1 is the device-published `used.idx` (see poll_used).
        let used_idx = unsafe { core::ptr::read_volatile(self.used_base().add(1)) };
        used_idx != self.last_used_idx
    }
}
