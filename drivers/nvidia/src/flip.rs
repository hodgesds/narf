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
