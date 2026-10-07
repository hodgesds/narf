//! AMDGPU GFX / SDMA ring submission scaffolding — clean-room.
//!
//! Reference: AMD KGD (Kernel-mode Graphics Driver) public ring
//! protocol notes + the public PM4 packet format reference.
//!
//! ## Ring layout
//!
//! Each submission queue is a power-of-two-sized circular buffer
//! of 32-bit dwords. The host maintains a `wptr` (write pointer)
//! that advances as packets are appended; the GPU maintains an
//! independent `rptr` (read pointer) it advances as packets
//! retire. Both pointers are dword-granularity and wrap at
//! `RING_SIZE_DW`.
//!
//! ```text
//! ring buffer (RING_SIZE_DW × 4 bytes, DMA-coherent)
//! +--------+--------+--------+--------+--------+
//! | dword0 | dword1 | dword2 | ...    | dwordN |
//! +--------+--------+--------+--------+--------+
//!         ^                  ^
//!         rptr (GPU)         wptr (host)
//! ```
//!
//! Doorbell ring: write `wptr` to a per-queue doorbell offset
//! within BAR2. The doorbell hardware notifies the GPU that
//! `wptr` advanced.
//!
//! ## Pointers are free-running
//!
//! `wptr` and `rptr` count dwords ever written and ever consumed; they are
//! masked only when used as an index. That is Linux's model
//! (`ring->wptr & ring->buf_mask`) and it exists so `wptr == rptr` means EMPTY
//! and `wptr - rptr == RING_SIZE_DW` means FULL. A ring that stored the masked
//! pointers could not tell those two apart and would have to waste a dword to
//! keep them distinct.
//!
//! ## Filler is a NOP PACKET, not zero
//!
//! An unwritten ring dword must decode to something harmless, and **zero does
//! not**: a zero dword is PM4 TYPE0 with register 0 and count 0, which tells
//! the command processor to write the following dword into register 0. Linux
//! fills with `PACKET3(PACKET3_NOP, 0x3FFF)` (`gfx_v11_0.c`'s `.nop`), and so
//! does this.
//!
//! LINUX-GAP: the GPU's `rptr` is passed in by the caller rather than read
//! back. Linux has the engine write it to a host page (`ring->rptr_gpu_addr`)
//! and reads it from there; wiring that up needs the queue descriptor the
//! firmware consumes, which needs firmware. Until then a caller that does not
//! know the real `rptr` must pass 0 and treat the ring as write-once.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId, MmioRegion};

/// Doorbell BAR (BAR2 on Vega/Navi). Each per-queue doorbell is
/// 8 bytes wide; queue index N lives at offset `N * 8`.
pub const DOORBELL_STRIDE_BYTES: u64 = 8;

/// Ring size in dwords. 1024 is a comfortable middle-ground —
/// enough headroom for ~50 PM4 IB-submission groups before the
/// host has to wait on the GPU; small enough that one 4-KiB DMA
/// page covers the full ring.
pub const RING_SIZE_DW: usize = 1024;
const RING_BYTES: usize = RING_SIZE_DW * 4;

/// One GFX or SDMA submission ring. Backed by a DMA-coherent
/// page; the GPU reads from `phys_addr()` directly.
#[derive(Debug)]
pub struct Ring {
    /// DMA-coherent backing of the ring buffer.
    backing: DmaBuffer,
    /// Host-side write pointer, in dwords ever written. Free-running: masked
    /// only when indexing. See the module header.
    wptr_dw: u64,
    /// Per-queue doorbell offset within BAR2.
    doorbell_off: u64,
    /// Queue index for diagnostics.
    pub queue_idx: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    /// Allocation of the ring backing failed.
    NoMemory,
    /// The packet is larger than the ring could ever hold.
    TooLarge,
    /// The GPU has not consumed enough for this packet to fit. The caller
    /// waits for `rptr` to advance and retries — overwriting unconsumed
    /// dwords would corrupt a command the engine is still executing.
    Full,
}

/// `PACKET3(PACKET3_NOP, 0x3FFF)` — `gfx_v11_0.c`'s `.nop`.
///
/// A whole-ring filler and the padding between packets. The count field is
/// maximal because the header alone is the no-op: the command processor skips
/// `count + 1` following dwords, so one header covers the rest of the ring.
pub const NOP_DW: u32 =
    crate::amdgpu_pm4_defs::packet3(crate::amdgpu_pm4_defs::PACKET3_NOP, 0x3FFF);

impl Ring {
    /// Allocate a fresh ring + compute its doorbell offset for
    /// the given queue index.
    pub fn new(queue_idx: u16) -> Result<Self, RingError> {
        let backing =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| RingError::NoMemory)?;
        // Fill with the NOP PACKET. This used to write zeros, described as
        // "PM4 TYPE0 with count 0 = a benign 1-dword no-op" — it is not one.
        // A zero dword IS a TYPE0 header, naming register 0 with a count of 0,
        // which tells the command processor to write the NEXT dword into
        // register 0. An engine that ran off the end of the written region
        // would walk the rest of the ring writing zeros into register 0.
        // SAFETY: identity-mapped DMA-coherent page; we own it.
        unsafe {
            for i in 0..RING_SIZE_DW {
                core::ptr::write_volatile(backing.cpu_mut_ptr_at::<u32>((i * 4) as u64), NOP_DW);
            }
        }
        Ok(Self {
            backing,
            wptr_dw: 0,
            doorbell_off: queue_idx as u64 * DOORBELL_STRIDE_BYTES,
            queue_idx,
        })
    }

    /// Phys address of the ring's first dword. Programmed into
    /// the GPU's CP_RB_BASE / SDMA_GFX_RB_BASE registers at GFX
    /// bring-up.
    pub fn phys_addr(&self) -> u64 {
        self.backing.dma_addr().raw()
    }

    /// Host write-pointer, in dwords ever written.
    pub fn wptr(&self) -> u64 {
        self.wptr_dw
    }

    /// Dwords the GPU has not yet consumed, given its `rptr`.
    pub fn used_dw(&self, rptr_dw: u64) -> u64 {
        self.wptr_dw.wrapping_sub(rptr_dw)
    }

    /// Dwords that may be written without overwriting unconsumed commands.
    pub fn free_dw(&self, rptr_dw: u64) -> u64 {
        (RING_SIZE_DW as u64).saturating_sub(self.used_dw(rptr_dw))
    }

    /// One dword at the masked index, for tests and for dumping a hung ring.
    ///
    /// # Safety
    /// The ring's backing must still be mapped.
    pub unsafe fn peek(&self, index_dw: u64) -> u32 {
        let off = (index_dw & (RING_SIZE_DW as u64 - 1)) * 4;
        // SAFETY: the index is masked into the ring, and the caller holds the
        // backing alive.
        unsafe { core::ptr::read_volatile(self.backing.cpu_ptr_at::<u32>(off)) }
    }

    /// Write one dword at the current wptr and advance it, wrapping.
    ///
    /// # Safety
    /// The caller has already checked there is room.
    unsafe fn put(&mut self, value: u32) {
        let off = (self.wptr_dw & (RING_SIZE_DW as u64 - 1)) * 4;
        // SAFETY: the offset is masked into the ring's own page.
        unsafe {
            core::ptr::write_volatile(self.backing.cpu_mut_ptr_at::<u32>(off), value);
        }
        self.wptr_dw = self.wptr_dw.wrapping_add(1);
    }

    /// Pad with `count` NOP dwords, wrapping as needed
    /// (`amdgpu_ring_insert_nop`).
    ///
    /// # Safety
    /// As [`Ring::submit`].
    pub unsafe fn insert_nop(&mut self, count: usize, rptr_dw: u64) -> Result<u64, RingError> {
        if count as u64 > self.free_dw(rptr_dw) {
            return Err(RingError::Full);
        }
        for _ in 0..count {
            // SAFETY: room checked above.
            unsafe { self.put(NOP_DW) };
        }
        Ok(self.wptr_dw)
    }

    /// Pad with NOPs until the write pointer is a multiple of `align_dw`.
    ///
    /// GFX11 wants an indirect-buffer packet aligned so the command processor
    /// fetches it in one burst; `amdgpu_ring_commit` pads to
    /// `ring->funcs->align_mask` for the same reason.
    ///
    /// # Safety
    /// As [`Ring::submit`].
    pub unsafe fn align_to(&mut self, align_dw: u64, rptr_dw: u64) -> Result<u64, RingError> {
        if align_dw <= 1 || !align_dw.is_power_of_two() {
            return Err(RingError::TooLarge);
        }
        let pad = (align_dw - (self.wptr_dw & (align_dw - 1))) & (align_dw - 1);
        // SAFETY: delegated.
        unsafe { self.insert_nop(pad as usize, rptr_dw) }
    }

    /// Doorbell BAR2 byte offset for this queue.
    pub fn doorbell_offset(&self) -> u64 {
        self.doorbell_off
    }

    /// Append `packet` (already-formatted dwords) to the ring.
    /// Returns the new wptr in dwords.
    ///
    /// Stage-4 cut: rejects the packet with
    /// `NotEnoughRoomBeforeWrap` rather than emitting a NOP
    /// filler when the packet would straddle the ring boundary.
    /// The Stage-5 expansion adds a `nop_to_wrap()` helper.
    ///
    /// # Safety
    /// Caller serialises ring access. Submission to a live GPU
    /// engine additionally requires the GFX firmware to be
    /// loaded; otherwise the ring sits idle.
    pub unsafe fn submit(&mut self, packet: &[u32], rptr_dw: u64) -> Result<u64, RingError> {
        if packet.len() > RING_SIZE_DW {
            return Err(RingError::TooLarge);
        }
        // The check is against what the GPU has CONSUMED, not against the end
        // of the buffer. A ring is circular: a packet may straddle the wrap
        // freely, and what it must never do is overwrite a dword the engine
        // has not read yet.
        if packet.len() as u64 > self.free_dw(rptr_dw) {
            return Err(RingError::Full);
        }
        for &w in packet {
            // SAFETY: room checked above.
            unsafe { self.put(w) };
        }
        // The dwords must be visible before the doorbell announces them.
        compiler_fence(Ordering::SeqCst);
        Ok(self.wptr_dw)
    }

    /// Ring the per-queue doorbell. Writes `wptr` to BAR2 +
    /// `doorbell_off`; the GPU's doorbell hardware translates that
    /// into a "ring wptr advanced" signal to the engine.
    ///
    /// # Safety
    /// `bar2` must map the doorbell window of the corresponding
    /// AMD GPU; caller owns the doorbell range exclusively while
    /// this queue is alive.
    pub unsafe fn ring_doorbell(&self, bar2: &MmioRegion) {
        // Doorbell is 64-bit, but only the low 32 bits carry the
        // wptr; the upper 32 are reserved.
        // SAFETY: caller-asserted ownership.
        unsafe {
            bar2.write32(self.doorbell_off, self.wptr_dw as u32);
            bar2.write32(self.doorbell_off + 4, 0);
        }
    }
}
