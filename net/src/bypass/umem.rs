//! UMEM — registered userspace memory region.
//!
//! Cap-gated, DMA-coherent buffer pool that a kernel-bypass socket
//! treats as its packet arena. Modeled on Linux AF_XDP's `xdp_umem`
//! (see `linux/net/xdp/xdp_umem.c::xdp_umem_create`): one contiguous
//! region, carved into equal-sized frames of `frame_size` bytes.
//!
//! NARF divergence: rather than letting userspace mmap arbitrary
//! pages and call `bind(2)`, the kernel hands back a
//! `Cap<UmemRegion, Invoke>` after a successful `register`. The
//! userspace daemon presents that cap on every subsequent UMEM op
//! (FILL frame post, RX frame return, TX frame submit, COMPLETION
//! frame reclaim). Revoking the cap revokes the entire region's
//! authority in O(1) and the next op surfaces `AccessDenied`.
//!
//! Frame indices are 32-bit so they fit alongside ring-slot
//! metadata in a single 8-byte SPSC slot. `frame_size` must be a
//! power of two (current spec: 2048 or 4096). `nb_frames` is
//! `size / frame_size` and is capped at 2^31 so wrap-arithmetic on
//! the indices can't alias.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Invoke};
use narf_io::DmaBuffer;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for a registered UMEM region. `Cap<UmemRegion,
/// Invoke>` is the authority to read frame bytes, post to the
/// FILL/TX rings, or reclaim from RX/COMPLETION.
#[derive(Debug)]
pub struct UmemRegion;

impl CapType for UmemRegion {
    const KIND: CapKind = CapKind::DmaBuffer;
}

/// Minimum supported UMEM frame size (bytes). Matches XDP's
/// `XDP_UMEM_MIN_CHUNK_SIZE` floor of 2048.
pub const MIN_FRAME_SIZE: u32 = 2048;

/// Maximum supported UMEM frame size. Linux clamps to PAGE_SIZE for
/// the IO-MMU mapping; NARF's `narf_io::alloc_coherent` is single-page
/// today so we mirror.
pub const MAX_FRAME_SIZE: u32 = 4096;

/// Maximum number of frames a single UMEM may carry. Higher than a
/// page is fine; the limit avoids 32-bit index aliasing.
pub const MAX_NB_FRAMES: u32 = 1 << 30;

/// UMEM registration errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UmemError {
    /// `frame_size` not a power of two or outside `[MIN_FRAME_SIZE,
    /// MAX_FRAME_SIZE]`.
    InvalidFrameSize,
    /// `size` not a multiple of `frame_size` or `size == 0`.
    InvalidSize,
    /// Computed `nb_frames` exceeds `MAX_NB_FRAMES`.
    TooManyFrames,
    /// Backing-store allocation failed.
    NoMemory,
    /// The presented authority cap is revoked / wrong-type.
    AccessDenied,
    /// FILL/COMPLETION ring drained an out-of-range frame index.
    InvalidFrameIndex,
    /// Operation requires the region to be live.
    Revoked,
}

/// Snapshot of a UMEM region's geometry. Returned to userspace at
/// registration so the daemon can compute frame addresses without
/// re-reading kernel state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UmemDesc {
    /// Physical address of frame 0.
    pub base_phys: u64,
    /// Kernel-virtual address of frame 0.
    pub base_virt: u64,
    /// Total region size in bytes.
    pub size: u32,
    /// Frame size in bytes (power of two).
    pub frame_size: u32,
    /// Number of frames = `size / frame_size`.
    pub nb_frames: u32,
}

/// A registered UMEM region. The kernel holds an `Arc<UmemRegion>`
/// while a bypass socket is bound to it; the userspace daemon holds
/// the corresponding `Cap<UmemRegion, Invoke>`. Both must outlive
/// any in-flight FILL/RX/TX/COMPLETION frame index.
pub struct Umem {
    desc: UmemDesc,
    /// Backing storage. Single page today (see [`MAX_FRAME_SIZE`]).
    buf: DmaBuffer,
    /// Cap minted at registration. Stored so we can re-check on every
    /// op without trusting the caller to re-present.
    cap: Cap<UmemRegion, Invoke>,
    /// `true` after `revoke()`. Subsequent ops short-circuit to
    /// [`UmemError::Revoked`] without going to the object table.
    revoked: AtomicBool,
}

impl core::fmt::Debug for Umem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Umem")
            .field("desc", &self.desc)
            .field("revoked", &self.revoked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Umem {
    /// Register a UMEM region of `size` bytes carved into
    /// `frame_size`-byte frames. Allocates DMA-coherent backing
    /// store via `narf_io::alloc_coherent` and mints a fresh
    /// `Cap<UmemRegion, Invoke>`.
    ///
    /// Linux ref: `xdp_umem_create` /
    /// `xdp_umem_reg` in `net/xdp/xdp_umem.c`.
    pub fn register(size: u32, frame_size: u32) -> Result<Arc<Self>, UmemError> {
        if frame_size < MIN_FRAME_SIZE
            || frame_size > MAX_FRAME_SIZE
            || !frame_size.is_power_of_two()
        {
            return Err(UmemError::InvalidFrameSize);
        }
        if size == 0 || size % frame_size != 0 {
            return Err(UmemError::InvalidSize);
        }
        let nb_frames = size / frame_size;
        if nb_frames > MAX_NB_FRAMES {
            return Err(UmemError::TooManyFrames);
        }
        // Backing store. The DmaBuffer is page-rounded; we use `size`
        // up to the buffer's actual length as the live region.
        let buf = narf_io::alloc_coherent(size as usize, DomainId::USERSPACE_K)
            .map_err(|_| UmemError::NoMemory)?;
        let base_phys = buf.phys_addr().as_u64();
        let base_virt = buf.as_ptr() as u64;
        let cap = Cap::<UmemRegion, Invoke>::bootstrap();
        Ok(Arc::new(Self {
            desc: UmemDesc {
                base_phys,
                base_virt,
                size,
                frame_size,
                nb_frames,
            },
            buf,
            cap,
            revoked: AtomicBool::new(false),
        }))
    }

    /// Region descriptor — geometry the userspace daemon needs to
    /// compute frame addresses.
    #[inline]
    pub fn desc(&self) -> UmemDesc {
        self.desc
    }

    /// Cap returned to userspace at registration. Subsequent ops
    /// must present this exact cap (epoch-checked).
    #[inline]
    pub fn cap(&self) -> Cap<UmemRegion, Invoke> {
        self.cap
    }

    /// Number of frames in the pool.
    #[inline]
    pub fn nb_frames(&self) -> u32 {
        self.desc.nb_frames
    }

    /// Frame size in bytes.
    #[inline]
    pub fn frame_size(&self) -> u32 {
        self.desc.frame_size
    }

    /// Total region size in bytes.
    #[inline]
    pub fn size(&self) -> u32 {
        self.desc.size
    }

    /// Validate a frame index against the region geometry.
    #[inline]
    pub fn frame_in_bounds(&self, frame_idx: u32) -> bool {
        frame_idx < self.desc.nb_frames
    }

    /// Read access to the bytes of `frame_idx`. Returns `None` if
    /// the index is out of range or the cap has been revoked.
    pub fn frame_bytes(&self, frame_idx: u32) -> Option<&[u8]> {
        self.check()?;
        if !self.frame_in_bounds(frame_idx) {
            return None;
        }
        let off = (frame_idx as usize) * (self.desc.frame_size as usize);
        let end = off + (self.desc.frame_size as usize);
        Some(&self.buf.as_slice()[off..end])
    }

    /// Mutable read access. Same gating as [`Self::frame_bytes`].
    /// Internal: drivers write RX into this; userspace TX is staged
    /// here before the TX-ring producer.
    pub fn frame_bytes_mut(&mut self, frame_idx: u32) -> Option<&mut [u8]> {
        if self.revoked.load(Ordering::Acquire) {
            return None;
        }
        self.cap.check_live().ok()?;
        if !self.frame_in_bounds(frame_idx) {
            return None;
        }
        let off = (frame_idx as usize) * (self.desc.frame_size as usize);
        let end = off + (self.desc.frame_size as usize);
        Some(&mut self.buf.as_mut_slice()[off..end])
    }

    /// Cap + soft-revoke check.
    fn check(&self) -> Option<()> {
        if self.revoked.load(Ordering::Acquire) {
            return None;
        }
        self.cap.check_live().ok()
    }

    /// Verify that an externally presented cap matches the one
    /// minted at registration and the cap is still live. The
    /// per-region `revoked` bit short-circuits before the object
    /// table; revocation of either the cap or the region surfaces
    /// the same `AccessDenied`.
    pub fn authorise(&self, presented: &Cap<UmemRegion, Invoke>) -> Result<(), UmemError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(UmemError::Revoked);
        }
        if presented.slot().index != self.cap.slot().index {
            return Err(UmemError::AccessDenied);
        }
        presented.check_live().map_err(|_| UmemError::AccessDenied)?;
        Ok(())
    }

    /// Soft-revoke: subsequent ops surface `Revoked` without going
    /// to the object table. Idempotent.
    pub fn revoke_soft(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    /// Snapshot a frame's payload as an owned `Vec<u8>` — used by
    /// tests + by the FILL-to-RX path when the classifier needs to
    /// hand a buffer to a non-bypass consumer.
    pub fn frame_copy(&self, frame_idx: u32) -> Option<Vec<u8>> {
        self.frame_bytes(frame_idx).map(|s| s.to_vec())
    }
}

/// Per-UMEM map errors. Re-exported so callers don't need to import
/// the cap module's error type to talk about UMEM auth failures.
pub type UmemResult<T> = Result<T, UmemError>;

impl From<CapError> for UmemError {
    fn from(_: CapError) -> Self {
        UmemError::AccessDenied
    }
}

// ── Free-list helper ────────────────────────────────────────────
//
// The FILL ring is the "frames the kernel may write into" list and
// COMPLETION is "frames the kernel finished sending". They're both
// just queues of `u32` indices, but the bookkeeping below tracks
// which indices are *currently held by which subsystem* so a
// double-post (userspace pushes the same index to FILL twice) can
// be detected as a smoke during testing.

/// Per-frame ownership state. Used to assert the zero-copy invariant:
/// at any instant a frame is in exactly one of these states.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameOwner {
    /// In FILL — kernel may write RX into it.
    Fill,
    /// In RX ring — userspace owns it, must return to FILL.
    Rx,
    /// In TX ring — userspace handed it off, driver owns it.
    Tx,
    /// In COMPLETION — userspace must reclaim and either reuse or
    /// recycle.
    Completion,
    /// Free / freshly created, never posted.
    Free,
}

/// Optional ownership tracker. Cheap to consult; enabled by tests.
/// In a production build the per-socket rings carry the only
/// authoritative state — this struct is for smokes that verify the
/// invariant.
#[derive(Debug)]
pub struct OwnerTracker {
    states: IrqSafeSpinLock<Vec<FrameOwner>>,
}

impl OwnerTracker {
    /// Build a fresh tracker — all frames start [`FrameOwner::Free`].
    pub fn new(nb_frames: u32) -> Self {
        let mut v = Vec::with_capacity(nb_frames as usize);
        for _ in 0..nb_frames {
            v.push(FrameOwner::Free);
        }
        Self {
            states: IrqSafeSpinLock::new(v),
        }
    }

    /// Transition `idx` from `expected` to `next`. Returns `false`
    /// on a mis-state (e.g. double-post to FILL).
    pub fn transition(&self, idx: u32, expected: FrameOwner, next: FrameOwner) -> bool {
        let mut g = self.states.lock();
        let i = idx as usize;
        if i >= g.len() {
            return false;
        }
        if g[i] != expected {
            return false;
        }
        g[i] = next;
        true
    }

    /// Read the current state of `idx`.
    pub fn state(&self, idx: u32) -> Option<FrameOwner> {
        self.states.lock().get(idx as usize).copied()
    }
}
