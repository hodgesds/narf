//! Page-flipping + VBLANK.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/wndw.c`**
//!   — Maxwell+ window (overlay/cursor/scanout) submission. The
//!   atomic flip happens here.
//! - **`drivers/gpu/drm/nouveau/dispnv50/curs.c`** + per-family
//!   `curs507a.c` / `cursc37a.c` — cursor / scanout-buffer
//!   doorbell.
//! - **`drivers/gpu/drm/nouveau/dispnv50/head*.c`** — VBLANK IRQ
//!   handling per family.
//!
//! ## Concept
//!
//! Page-flipping is the atomic swap of the scanout buffer at
//! VBLANK. The driver double-buffers a `front` and `back` and
//! tells the display engine to flip — internally that programs
//! the WNDW (window) class to retarget its scanout pointer at
//! the new buffer, taking effect on the next VBLANK boundary.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// One flip request — the buffer descriptor + the fence that
/// fires when the GPU acknowledges the flip queued.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlipRequest {
    /// VRAM phys-addr of the framebuffer the head should scan out.
    pub fb_phys: u64,
    /// Pitch (bytes per scanline).
    pub pitch: u32,
    /// Format code (BGRA8888 = 0x4, ARGB8888 = 0x5, …).
    pub format: u8,
    /// Seqno the GPU will write when the flip retires.
    pub seqno: u64,
}

/// Per-CRTC flip queue. Single-buffered request slot; the upper
/// KMS layer enqueues a request after VBLANK, the IRQ handler
/// fires `Completed` when the GPU's WNDW class drains it.
#[derive(Debug)]
pub struct FlipQueue {
    /// Pending flip; `None` when the queue is idle.
    pending: AtomicU64,
    /// Last VBLANK frame counter the IRQ handler observed.
    last_vblank: AtomicU64,
}

impl FlipQueue {
    pub const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            last_vblank: AtomicU64::new(0),
        }
    }

    /// Enqueue a flip. Returns `false` if the slot is busy.
    pub fn enqueue(&self, req: &FlipRequest) -> bool {
        self.pending
            .compare_exchange(0, req.seqno, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// IRQ handler call — VBLANK fired. If a flip was pending,
    /// returns its seqno (and clears the slot).
    pub fn on_vblank(&self, frame_counter: u64) -> Option<u64> {
        self.last_vblank.store(frame_counter, Ordering::Release);
        let seq = self.pending.swap(0, Ordering::AcqRel);
        if seq != 0 {
            Some(seq)
        } else {
            None
        }
    }

    /// Current VBLANK counter (frames observed since boot).
    pub fn vblank_counter(&self) -> u64 {
        self.last_vblank.load(Ordering::Acquire)
    }

    /// True if a flip is in flight.
    pub fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire) != 0
    }
}

impl Default for FlipQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ── HEAD VBLANK interrupt bit ────────────────────────────────────

/// HEAD interrupt-status bit for VBLANK. Per-family stride is
/// 0x400; the bit position within HEAD's IRQ register is stable
/// Maxwell→Ada. Cite `dispnv50/head*.c::*_head_vblank_*`.
pub const HEAD_INTR_VBLANK: u32 = 1 << 4;
/// HEAD IRQ-status register offset within a HEAD block.
pub const HEAD_INTR_STATUS: u64 = 0x0000_0090;
/// HEAD IRQ-enable register offset within a HEAD block.
pub const HEAD_INTR_ENABLE: u64 = 0x0000_0094;

// ── Live page-flip helpers (item 14) ─────────────────────────────
//
// Cite `dispnv50/wndw.c::nv50_wndw_atomic_update` + `core507d.c::
// core507d_update`. The flip pushes a HEAD_SET_OFFSET update on the
// disp-core channel, then kicks the disp doorbell, which makes the
// new scanout pointer live on the next VBLANK boundary.
//
// We expose:
// - `stage_flip` — stage the offset write + UPDATE method into a
//   pushbuffer.
// - `kick_flip` — write the new PUT pointer to the channel MMIO.
// - `drain_completed` — VBLANK IRQ handler entrypoint; drains the
//   pending request, returning the seqno (or None when no flip was
//   queued for this VBLANK).
//
// `present_now` is the convenience that wraps stage_flip + kick.

/// Stage a flip: HEAD_SET_OFFSET + UPDATE. Cite
/// `dispnv50/head507d.c::head507d_core_set` for the OFFSET write
/// shape (`fb_offset_bytes >> 8`).
pub fn stage_flip(
    pb: &mut crate::pb::PbBuilder<'_>,
    head: u8,
    fb_phys: u64,
) -> Result<(), crate::pb::PbError> {
    use crate::disp::nv50::{head_method, NV507D_HEAD_SET_OFFSET, NV507D_UPDATE};
    // 1. Programme the new scanout offset.
    pb.write_inc(
        head_method(NV507D_HEAD_SET_OFFSET, head),
        &[(fb_phys >> 8) as u32],
    )?;
    // 2. UPDATE method, interlock = 0.
    pb.write_inc(NV507D_UPDATE, &[0])?;
    Ok(())
}

/// Ring the disp doorbell to make the just-staged flip live.
/// Cite `dispnv50/disp.c::nv50_dmac_kick`.
///
/// # Safety
/// `chan_mmio` is the disp-core channel user-MMIO window.
/// `put_byte_offset` is the byte position of the next free word
/// in the channel pushbuffer (i.e. the value the host wants the
/// hardware's GET pointer to chase up to).
pub unsafe fn kick_flip(chan_mmio: &narf_driver_runtime::MmioRegion, put_byte_offset: u32) {
    // SAFETY: caller's responsibility.
    unsafe {
        crate::disp::nv50::doorbell_kick(chan_mmio, put_byte_offset);
    }
}

/// Convenience: stage + kick. `pb_byte_base` is the byte offset
/// within the channel's circular pushbuffer where this flip's
/// methods start; `pb_byte_base + pb.len()` is the new PUT.
///
/// # Safety
/// As for `kick_flip` plus exclusive access to `pb`.
pub unsafe fn present_now(
    chan_mmio: &narf_driver_runtime::MmioRegion,
    pb: &mut crate::pb::PbBuilder<'_>,
    pb_byte_base: u32,
    head: u8,
    fb_phys: u64,
) -> Result<u32, crate::pb::PbError> {
    stage_flip(pb, head, fb_phys)?;
    let put = pb_byte_base + pb.len() as u32;
    // SAFETY: caller's responsibility.
    unsafe {
        kick_flip(chan_mmio, put);
    }
    Ok(put)
}

impl FlipQueue {
    /// IRQ handler entry. Reads the HEAD VBLANK status bit; if set,
    /// drains the pending flip and returns its seqno + the new
    /// VBLANK counter.
    ///
    /// # Safety
    /// `bar0` is the kernel-mapped BAR0 view; `head_offset` is the
    /// HEAD base (per `disp::nv50::head_base(i)`). Exclusive access.
    pub unsafe fn drain_completed(
        &self,
        bar0: &narf_driver_runtime::MmioRegion,
        head_offset: u64,
        frame_counter: u64,
    ) -> Option<u64> {
        // SAFETY: caller's responsibility.
        let intr_status = unsafe { bar0.read32(head_offset + HEAD_INTR_STATUS) };
        if intr_status & HEAD_INTR_VBLANK == 0 {
            return None;
        }
        // Acknowledge the IRQ by writing the same bit back.
        // SAFETY: same.
        unsafe {
            bar0.write32(head_offset + HEAD_INTR_STATUS, HEAD_INTR_VBLANK);
        }
        self.on_vblank(frame_counter)
    }

    /// Enable VBLANK IRQ on the specified HEAD.
    ///
    /// # Safety
    /// `bar0` is the BAR0 view; `head_offset` is the HEAD base.
    pub unsafe fn enable_vblank(&self, bar0: &narf_driver_runtime::MmioRegion, head_offset: u64) {
        // SAFETY: caller's responsibility.
        unsafe {
            let en = bar0.read32(head_offset + HEAD_INTR_ENABLE);
            bar0.write32(head_offset + HEAD_INTR_ENABLE, en | HEAD_INTR_VBLANK);
        }
    }

    /// Disable VBLANK IRQ.
    ///
    /// # Safety
    /// Same.
    pub unsafe fn disable_vblank(&self, bar0: &narf_driver_runtime::MmioRegion, head_offset: u64) {
        // SAFETY: caller's responsibility.
        unsafe {
            let en = bar0.read32(head_offset + HEAD_INTR_ENABLE);
            bar0.write32(head_offset + HEAD_INTR_ENABLE, en & !HEAD_INTR_VBLANK);
        }
    }
}
