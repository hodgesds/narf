//! Fences — GPU submission completion tracking.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nouveau_fence.c`**
//!   — generic fence allocation + signal handling.
//! - **`drivers/gpu/drm/nouveau/nv50_fence.c`** / **`nv84_fence.c`**
//!   / **`nvc0_fence.c`** / **`gv100_fence.c`** — per-family
//!   fence backing implementations.
//!
//! ## Concept
//!
//! Each channel has a semaphore-style fence object in VRAM: a
//! 32-bit (or 64-bit on Volta+) word the GPU writes when a
//! pushbuffer entry retires. The host reads the word back to
//! know whether a submission has finished.
//!
//! The driver allocates one fence object per channel, treats it
//! as a monotonic counter, and includes a "write this seqno on
//! complete" semaphore method at the end of each batch.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// One fence object — VRAM-backed monotonic counter.
#[derive(Debug)]
pub struct Fence {
    /// VRAM phys-addr where the GPU writes the current seqno.
    pub phys_addr: u64,
    /// Next seqno the host will issue.
    next_seq: AtomicU64,
    /// Last seqno we observed the GPU complete.
    last_signalled: AtomicU64,
}

impl Fence {
    pub const fn new(phys_addr: u64) -> Self {
        Self {
            phys_addr,
            next_seq: AtomicU64::new(1),
            last_signalled: AtomicU64::new(0),
        }
    }

    /// Mint a new seqno (host-side). Returns the value the GPU
    /// will write back when this submission retires.
    pub fn alloc_seqno(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Update the "GPU has reached this seqno" watermark.
    pub fn observe_signalled(&self, seq: u64) {
        // Monotonic max.
        let mut cur = self.last_signalled.load(Ordering::Acquire);
        while seq > cur {
            match self.last_signalled.compare_exchange_weak(
                cur,
                seq,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(new) => cur = new,
            }
        }
    }

    /// True if `seq` has already retired on the GPU.
    pub fn is_signalled(&self, seq: u64) -> bool {
        self.last_signalled.load(Ordering::Acquire) >= seq
    }

    /// Current "high water mark" — the host's view of how far the
    /// GPU has progressed.
    pub fn highwater(&self) -> u64 {
        self.last_signalled.load(Ordering::Acquire)
    }
}

// ── Semaphore methods (subset) ───────────────────────────────────
//
// Cite `include/nvhw/class/cl906f.h` (FermiChannelGpfifoA) —
// these method addresses are stable Fermi→Ada.

/// SEMAPHOREA — high 32 bits of the semaphore VA.
pub const SEMAPHOREA: u16 = 0x0010;
/// SEMAPHOREB — low 32 bits of the semaphore VA.
pub const SEMAPHOREB: u16 = 0x0014;
/// SEMAPHOREC — payload (the seqno we write).
pub const SEMAPHOREC: u16 = 0x0018;
/// SEMAPHORED — operation: RELEASE (write) / ACQUIRE (wait).
pub const SEMAPHORED: u16 = 0x001C;

/// SEMAPHORED.OPERATION = RELEASE — write the payload.
pub const SEMAPHORED_RELEASE: u32 = 0x00000001;
/// SEMAPHORED.OPERATION = ACQUIRE_GREATER_EQUAL — block until
/// `*sem >= payload`.
pub const SEMAPHORED_ACQUIRE_GEQ: u32 = 0x00000004;
