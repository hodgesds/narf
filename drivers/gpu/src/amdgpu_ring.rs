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
//! ## Stage-4 cut
//!
//! - Allocate a 4-KiB DMA-coherent ring (256 dwords).
//! - Append PM4 packet bytes to the ring with `submit_packet`.
//! - Compute the doorbell BAR2 offset from a per-queue index.
//! - Stop short of actually writing the doorbell — without
//!   firmware loaded the GPU isn't reading the ring, so the
//!   doorbell write would be a no-op anyway. The Stage-5 path
//!   that fires post-firmware-load lights up the doorbell.

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
    /// Host-side write pointer in dwords. Advances as packets
    /// are appended; wraps at `RING_SIZE_DW`.
    wptr_dw: usize,
    /// Per-queue doorbell offset within BAR2.
    doorbell_off: u64,
    /// Queue index for diagnostics.
    pub queue_idx: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    /// Allocation of the ring backing failed.
    NoMemory,
    /// Packet wouldn't fit in the contiguous tail of the ring
    /// before wrap. Stage-4 doesn't yet emit a NOP filler — the
    /// caller retries after the host's wptr returns to ring base.
    NotEnoughRoomBeforeWrap,
}

impl Ring {
    /// Allocate a fresh ring + compute its doorbell offset for
    /// the given queue index.
    pub fn new(queue_idx: u16) -> Result<Self, RingError> {
        let backing =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| RingError::NoMemory)?;
        // Zero the ring so an unprogrammed engine reads NOPs
        // (PM4 TYPE0 with count 0 = a benign 1-dword no-op).
        let phys = backing.phys_addr().raw();
        // SAFETY: identity-mapped DMA-coherent page; we own it.
        unsafe {
            for i in 0..RING_SIZE_DW {
                core::ptr::write_volatile((phys + (i * 4) as u64) as *mut u32, 0);
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
        self.backing.phys_addr().raw()
    }

    /// Current host write-pointer (in dwords).
    pub fn wptr(&self) -> usize {
        self.wptr_dw
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
    pub unsafe fn submit(&mut self, packet: &[u32]) -> Result<usize, RingError> {
        if self.wptr_dw + packet.len() > RING_SIZE_DW {
            return Err(RingError::NotEnoughRoomBeforeWrap);
        }
        let phys = self.backing.phys_addr().raw();
        for (i, &w) in packet.iter().enumerate() {
            let off = ((self.wptr_dw + i) * 4) as u64;
            // SAFETY: `phys` is the base of the ring's identity-mapped DMA
            // page from `backing`, so `phys + off` is a valid, 4-byte-aligned
            // address (`off` is a dword multiple). `wptr_dw + packet.len() <=
            // RING_SIZE_DW` was checked above, so `off` stays within the page.
            unsafe {
                core::ptr::write_volatile((phys + off) as *mut u32, w);
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.wptr_dw += packet.len();
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
