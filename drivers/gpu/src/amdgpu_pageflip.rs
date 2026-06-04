//! AMD page-flip + cursor — atomic surface updates.
//!
//! Page flipping in DCN happens by updating
//! `HUBP_PRIMARY_SURFACE_ADDRESS_*` "behind" a double-buffered
//! register pair. The next OTG vsync latches the new value and
//! the GPU starts scanning from the new framebuffer; the host
//! gets a `FLIP_DONE` IH packet once the latch retires.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/display/dc/dcn20/dcn20_hubp.c`
//!   (`hubp2_program_surface_flip_and_addr`)
//! - Linux `drivers/gpu/drm/amd/display/dc/dcn35/dcn35_hubp.c`
//!   (`hubp35_program_surface_flip_and_addr` — same shape, DCN35
//!   register-bus offsets)
//! - Linux `drivers/gpu/drm/amd/display/amdgpu_dm.c::amdgpu_dm_commit_planes`
//!   — atomic-commit entry the KMS surface calls into.
//! - Linux `drivers/gpu/drm/amd/display/dc/dcn20/dcn20_dpp.c` —
//!   cursor planes live in DPP, not HUBP.
//!
//! GPL-2.0-or-later; structural patterns adapted directly.
//!
//! ## Scope
//!
//! - **Primary plane flip** — atomic surface update producing a
//!   `(addr_lo, addr_hi)` write pair the driver writes to BAR5
//!   at the right register-bus offsets.
//! - **Cursor plane** — DCN's cursor sits in DPP (per-pipe) and
//!   carries position + size + a small format enum.
//! - **Flip queue** — a per-CRTC ring of pending flips; the
//!   FLIP_DONE IRQ retires the head. Triple-buffering is
//!   represented by a queue length of 3.
//! - **No MMIO** — pure codec. Driver core dispatches the writes.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::amdgpu_dcn::DcnWrite;

// ── HUBP / DPP register offsets ──────────────────────────────────
//
// HUBP_PRIMARY_SURFACE_ADDRESS lives at offset 0x00A4 from
// the per-pipe HUBP base (DCN1+; identical through DCN35 with
// only the *base* shifted per IP version).
//
// DPP cursor offsets in DCN2 / DCN3 (per public reference):
//   CURSOR_CONTROL       — bits[0] = enable, bits[3:1] = format
//   CURSOR_POSITION      — packed (Y << 16) | X
//   CURSOR_SIZE          — packed (H << 16) | W
//   CURSOR_SURFACE_ADDR  — low 32 bits of cursor's surface phys
//   CURSOR_SURFACE_ADDR_HI — high 32 bits

/// HUBP primary surface address (low) — relative to HUBP base.
pub const HUBP_PRIMARY_SURFACE_ADDRESS_REL: u32 = 0x00A4;
/// HUBP primary surface address (high) — relative to HUBP base.
pub const HUBP_PRIMARY_SURFACE_ADDRESS_HIGH_REL: u32 = 0x00A0;
/// DPP cursor control — bit 0 enable.
pub const DPP_CURSOR_CONTROL_REL: u32 = 0x00B0;
/// DPP cursor position — `(Y << 16) | X`.
pub const DPP_CURSOR_POSITION_REL: u32 = 0x00B4;
/// DPP cursor size — `(H << 16) | W`. Caps at 256x256 in DCN.
pub const DPP_CURSOR_SIZE_REL: u32 = 0x00B8;
/// DPP cursor surface address (low).
pub const DPP_CURSOR_SURFACE_ADDR_REL: u32 = 0x00BC;
/// DPP cursor surface address (high).
pub const DPP_CURSOR_SURFACE_ADDR_HI_REL: u32 = 0x00C0;

/// Cursor enable bit.
pub const DPP_CURSOR_ENABLE: u32 = 1 << 0;
/// Cursor format: ARGB8888 (the only format we care about).
pub const DPP_CURSOR_FORMAT_ARGB8888: u32 = 0x4 << 1;

// ── Pixel format ─────────────────────────────────────────────────

/// Pixel format the primary plane carries. The flip codec
/// doesn't reprogram format on flip — that lives in the modeset
/// path — but we record it on the flip so the driver can
/// validate alignment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit XRGB8888 — most common.
    Xrgb8888,
    /// 32-bit ARGB8888 — alpha-aware.
    Argb8888,
    /// 16-bit RGB565 — legacy / low-bandwidth.
    Rgb565,
}

impl PixelFormat {
    /// Bytes per pixel.
    pub const fn bpp(self) -> u32 {
        match self {
            PixelFormat::Xrgb8888 | PixelFormat::Argb8888 => 4,
            PixelFormat::Rgb565 => 2,
        }
    }

    /// `true` if the surface stride is valid for this format
    /// (DCN requires 256-byte alignment).
    pub fn validate_stride(self, stride_bytes: u32) -> bool {
        stride_bytes != 0 && stride_bytes & 0xFF == 0
    }
}

// ── Page-flip request + response ─────────────────────────────────

/// One page-flip request — `(new_phys, format, generation)`.
/// `generation` is a host-side counter the IRQ matches against to
/// retire the right flip when FLIP_DONE fires.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PageFlipRequest {
    /// Phys address of the new primary plane's framebuffer.
    pub surface_phys: u64,
    pub format: PixelFormat,
    /// Stride in bytes; must be a multiple of 256.
    pub stride_bytes: u32,
    /// Host-side flip sequence number. Returned in FLIP_DONE.
    pub generation: u64,
}

/// Outcome of building the flip writes.
#[derive(Clone, Debug)]
pub struct PageFlipWrites {
    pub writes: Vec<DcnWrite>,
    /// Generation echoed in the corresponding FLIP_DONE IH packet.
    pub generation: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlipError {
    /// Stride violates DCN's 256-byte alignment.
    BadStride,
    /// Surface address violates DCN's 256-byte alignment.
    BadSurface,
    /// Pipe's flip queue is full — caller must wait for FLIP_DONE
    /// on the head before pushing another.
    QueueFull,
    /// FLIP_DONE arrived but no pending flip matches the generation.
    SpuriousFlipDone,
}

/// Build the MMIO writes that retire `req` on the next vsync of
/// `hubp_base`'s pipe.
///
/// Two-write sequence:
///   1. `HUBP_PRIMARY_SURFACE_ADDRESS_HIGH = phys[63:32]`
///   2. `HUBP_PRIMARY_SURFACE_ADDRESS      = phys[31:0]`
///
/// Order matters: writing HIGH first then LOW arms the
/// double-buffer with the full 64-bit address; the latch
/// happens when the LOW write retires. The next OTG vsync
/// flips the pipe.
pub fn build_flip(hubp_base: u32, req: &PageFlipRequest) -> Result<PageFlipWrites, FlipError> {
    if !req.format.validate_stride(req.stride_bytes) {
        return Err(FlipError::BadStride);
    }
    if req.surface_phys & 0xFF != 0 {
        return Err(FlipError::BadSurface);
    }
    let writes = alloc::vec![
        DcnWrite {
            addr: hubp_base + HUBP_PRIMARY_SURFACE_ADDRESS_HIGH_REL,
            value: (req.surface_phys >> 32) as u32,
        },
        DcnWrite {
            addr: hubp_base + HUBP_PRIMARY_SURFACE_ADDRESS_REL,
            value: req.surface_phys as u32,
        },
    ];
    Ok(PageFlipWrites {
        writes,
        generation: req.generation,
    })
}

// ── Per-CRTC flip queue ──────────────────────────────────────────

/// Per-CRTC flip queue. Triple-buffered = 3 slots. The head is
/// the currently-scanning surface; the rest are pending. The
/// FLIP_DONE IRQ pops the head; the next pending becomes the
/// scanning surface.
#[derive(Clone, Debug)]
pub struct FlipQueue {
    /// Pending flips, oldest first. The first entry is currently
    /// scanning; the second is the next-to-flip-to.
    pending: VecDeque<PageFlipRequest>,
    /// Maximum simultaneously-tracked flips.
    capacity: usize,
    /// Monotonic flip generation counter.
    next_generation: u64,
}

impl FlipQueue {
    /// Mint a new queue with the given depth (triple-buffered
    /// → 3, double-buffered → 2).
    pub fn new(depth: usize) -> Self {
        Self {
            pending: VecDeque::with_capacity(depth),
            capacity: depth.max(1),
            next_generation: 1,
        }
    }

    /// Allocate the next generation counter for a flip about to
    /// be enqueued. Callers usually go through [`Self::enqueue`];
    /// this is exposed for code that builds the request then
    /// hands it to a different submitter.
    pub fn allocate_generation(&mut self) -> u64 {
        let g = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        g
    }

    /// Enqueue a flip. Assigns the generation. Returns the
    /// generation so the caller can correlate with FLIP_DONE.
    /// Fails with `QueueFull` if the queue is at capacity.
    pub fn enqueue(
        &mut self,
        surface_phys: u64,
        format: PixelFormat,
        stride_bytes: u32,
    ) -> Result<PageFlipRequest, FlipError> {
        if self.pending.len() >= self.capacity {
            return Err(FlipError::QueueFull);
        }
        let req = PageFlipRequest {
            surface_phys,
            format,
            stride_bytes,
            generation: self.allocate_generation(),
        };
        self.pending.push_back(req);
        Ok(req)
    }

    /// Retire the matching pending flip on FLIP_DONE. The IH
    /// packet carries the generation in its payload; this finds
    /// the matching entry and pops it. Returns the retired
    /// request for IRQ-side handoff (vsync events, fence retire).
    ///
    /// FLIP_DONE for a generation that isn't pending surfaces as
    /// `SpuriousFlipDone` — the driver should log + drop rather
    /// than mishandle.
    pub fn retire(&mut self, generation: u64) -> Result<PageFlipRequest, FlipError> {
        // The head of the queue is what just latched. Validate
        // that the generation matches; an out-of-order retire
        // is a hardware bug or a host bookkeeping error.
        match self.pending.front() {
            Some(head) if head.generation == generation => Ok(self.pending.pop_front().unwrap()),
            _ => Err(FlipError::SpuriousFlipDone),
        }
    }

    /// Length of pending queue.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// `true` if the queue has space for another flip.
    pub fn has_capacity(&self) -> bool {
        self.pending.len() < self.capacity
    }

    /// Peek at the currently-scanning request (the head).
    pub fn current(&self) -> Option<&PageFlipRequest> {
        self.pending.front()
    }

    /// Drain — used on CRTC teardown.
    pub fn drain(&mut self) {
        self.pending.clear();
    }
}

// ── Cursor plane ─────────────────────────────────────────────────

/// Cursor state for one DPP pipe. DCN's cursor is per-pipe; on
/// multi-monitor setups each pipe has its own cursor and the
/// compositor decides who draws it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CursorState {
    /// Cursor visible? Disabled cursors leave their position
    /// register at the last value (no behaviour change vs
    /// always-write).
    pub enabled: bool,
    /// X coordinate, in scanlines.
    pub x: i16,
    /// Y coordinate.
    pub y: i16,
    /// Width in pixels (capped at 256 by DCN).
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// Phys address of the cursor's image buffer (always
    /// ARGB8888). 256-byte aligned.
    pub surface_phys: u64,
}

impl Default for CursorState {
    fn default() -> Self {
        Self {
            enabled: false,
            x: 0,
            y: 0,
            width: 64,
            height: 64,
            surface_phys: 0,
        }
    }
}

impl CursorState {
    /// `true` if the cursor parameters are programmable. DCN
    /// limits: width / height ≤ 256, surface 256-byte aligned.
    pub fn validate(&self) -> bool {
        self.width <= 256
            && self.height <= 256
            && self.width > 0
            && self.height > 0
            && (self.surface_phys & 0xFF) == 0
    }
}

/// Build the cursor-program writes for `dpp_base`'s pipe.
pub fn build_cursor(dpp_base: u32, st: &CursorState) -> Result<Vec<DcnWrite>, FlipError> {
    if !st.validate() {
        return Err(FlipError::BadSurface);
    }
    let mut writes = Vec::with_capacity(5);
    if st.enabled {
        // Surface address (HI / LO) first — register order matches
        // DCN's per-pipe cursor latch.
        writes.push(DcnWrite {
            addr: dpp_base + DPP_CURSOR_SURFACE_ADDR_HI_REL,
            value: (st.surface_phys >> 32) as u32,
        });
        writes.push(DcnWrite {
            addr: dpp_base + DPP_CURSOR_SURFACE_ADDR_REL,
            value: st.surface_phys as u32,
        });
        writes.push(DcnWrite {
            addr: dpp_base + DPP_CURSOR_SIZE_REL,
            value: ((st.height as u32) << 16) | (st.width as u32),
        });
        writes.push(DcnWrite {
            addr: dpp_base + DPP_CURSOR_POSITION_REL,
            value: ((st.y as u16 as u32) << 16) | (st.x as u16 as u32),
        });
        writes.push(DcnWrite {
            addr: dpp_base + DPP_CURSOR_CONTROL_REL,
            value: DPP_CURSOR_ENABLE | DPP_CURSOR_FORMAT_ARGB8888,
        });
    } else {
        // Disabling — only flip the control bit. Position survives.
        writes.push(DcnWrite {
            addr: dpp_base + DPP_CURSOR_CONTROL_REL,
            value: 0,
        });
    }
    Ok(writes)
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pageflip_build_emits_hi_then_lo() -> TestResult {
        let req = PageFlipRequest {
            surface_phys: 0x1_0000_0100,
            format: PixelFormat::Xrgb8888,
            stride_bytes: 1920 * 4,
            generation: 42,
        };
        let r = build_flip(0x4000, &req).expect("build_flip");
        if r.writes.len() != 2 {
            return TestResult::Fail("flip should emit 2 writes");
        }
        // HIGH first, LOW second — the latch fires on LOW.
        if r.writes[0].addr != 0x4000 + HUBP_PRIMARY_SURFACE_ADDRESS_HIGH_REL {
            return TestResult::Fail("first write should be HIGH");
        }
        if r.writes[0].value != 1 {
            return TestResult::Fail("HIGH value wrong");
        }
        if r.writes[1].addr != 0x4000 + HUBP_PRIMARY_SURFACE_ADDRESS_REL {
            return TestResult::Fail("second write should be LOW");
        }
        if r.writes[1].value != 0x0000_0100 {
            return TestResult::Fail("LOW value wrong");
        }
        if r.generation != 42 {
            return TestResult::Fail("generation not echoed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_pageflip_build_emits_hi_then_lo);

    fn smoke_pageflip_rejects_misaligned() -> TestResult {
        // Stride must be 256-byte aligned.
        let mut req = PageFlipRequest {
            surface_phys: 0x1000_0000,
            format: PixelFormat::Xrgb8888,
            stride_bytes: 1920 * 4 + 1,
            generation: 1,
        };
        if !matches!(build_flip(0, &req), Err(FlipError::BadStride)) {
            return TestResult::Fail("misaligned stride should fail");
        }
        req.stride_bytes = 1920 * 4;
        req.surface_phys = 0x1000_0001;
        if !matches!(build_flip(0, &req), Err(FlipError::BadSurface)) {
            return TestResult::Fail("misaligned surface should fail");
        }
        // 0-stride invalid.
        req.surface_phys = 0x1000_0000;
        req.stride_bytes = 0;
        if !matches!(build_flip(0, &req), Err(FlipError::BadStride)) {
            return TestResult::Fail("zero stride should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_pageflip_rejects_misaligned);

    fn smoke_flip_queue_lifecycle() -> TestResult {
        let mut q = FlipQueue::new(3);
        let r1 = q
            .enqueue(0x1000_0000, PixelFormat::Xrgb8888, 7680)
            .expect("e1");
        let r2 = q
            .enqueue(0x2000_0000, PixelFormat::Xrgb8888, 7680)
            .expect("e2");
        let r3 = q
            .enqueue(0x3000_0000, PixelFormat::Xrgb8888, 7680)
            .expect("e3");
        if q.pending_len() != 3 {
            return TestResult::Fail("queue depth wrong after 3 enqueues");
        }
        if q.has_capacity() {
            return TestResult::Fail("queue should be full");
        }
        // 4th enqueue rejected.
        if q.enqueue(0x4000_0000, PixelFormat::Xrgb8888, 7680) != Err(FlipError::QueueFull) {
            return TestResult::Fail("over-capacity enqueue not rejected");
        }
        // Retire in order; out-of-order retire is rejected.
        if q.retire(r2.generation) != Err(FlipError::SpuriousFlipDone) {
            return TestResult::Fail("out-of-order retire not rejected");
        }
        let retired = q.retire(r1.generation).expect("retire head");
        if retired.surface_phys != r1.surface_phys {
            return TestResult::Fail("retired wrong head");
        }
        if q.pending_len() != 2 {
            return TestResult::Fail("queue depth wrong after retire");
        }
        q.retire(r2.generation).expect("retire r2");
        q.retire(r3.generation).expect("retire r3");
        if q.pending_len() != 0 {
            return TestResult::Fail("queue not drained");
        }
        // Empty retire returns spurious.
        if q.retire(99) != Err(FlipError::SpuriousFlipDone) {
            return TestResult::Fail("retire on empty queue not spurious");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_flip_queue_lifecycle);

    fn smoke_flip_queue_drain_resets() -> TestResult {
        let mut q = FlipQueue::new(3);
        q.enqueue(0x1000_0000, PixelFormat::Xrgb8888, 7680)
            .expect("e1");
        q.enqueue(0x2000_0000, PixelFormat::Xrgb8888, 7680)
            .expect("e2");
        q.drain();
        if q.pending_len() != 0 {
            return TestResult::Fail("drain didn't empty queue");
        }
        if !q.has_capacity() {
            return TestResult::Fail("drained queue not empty for capacity");
        }
        // Generation counter survives drain — wrap-protection.
        let r = q
            .enqueue(0x3000_0000, PixelFormat::Xrgb8888, 7680)
            .expect("e3");
        if r.generation < 3 {
            return TestResult::Fail("generation counter reset on drain");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_flip_queue_drain_resets);

    fn smoke_cursor_build_writes_and_disable() -> TestResult {
        let st = CursorState {
            enabled: true,
            x: 100,
            y: 200,
            width: 64,
            height: 64,
            surface_phys: 0x1_0000_2000,
        };
        let w = build_cursor(0x6000, &st).expect("build_cursor enabled");
        if w.len() != 5 {
            return TestResult::Fail("enabled cursor should emit 5 writes");
        }
        // Last write is CONTROL — enable + format.
        let last = w.last().unwrap();
        if last.addr != 0x6000 + DPP_CURSOR_CONTROL_REL {
            return TestResult::Fail("last write should be CONTROL");
        }
        if last.value & DPP_CURSOR_ENABLE == 0 {
            return TestResult::Fail("CONTROL missing enable bit");
        }
        if last.value & DPP_CURSOR_FORMAT_ARGB8888 == 0 {
            return TestResult::Fail("CONTROL missing format");
        }
        // POSITION encodes (Y << 16) | X.
        let pos = w
            .iter()
            .find(|w| w.addr == 0x6000 + DPP_CURSOR_POSITION_REL)
            .unwrap();
        if pos.value != (200 << 16) | 100 {
            return TestResult::Fail("position encoding wrong");
        }
        // SIZE encodes (H << 16) | W.
        let sz = w
            .iter()
            .find(|w| w.addr == 0x6000 + DPP_CURSOR_SIZE_REL)
            .unwrap();
        if sz.value != (64 << 16) | 64 {
            return TestResult::Fail("size encoding wrong");
        }
        // Disabled cursor → only CONTROL = 0.
        let disabled = CursorState {
            enabled: false,
            ..st
        };
        let w = build_cursor(0x6000, &disabled).expect("build_cursor disabled");
        if w.len() != 1 {
            return TestResult::Fail("disabled should emit only 1 write");
        }
        if w[0].value != 0 {
            return TestResult::Fail("disable should write 0 to control");
        }
        // Validate gates oversized cursors.
        let oversized = CursorState { width: 512, ..st };
        if build_cursor(0x6000, &oversized) != Err(FlipError::BadSurface) {
            return TestResult::Fail("oversized cursor not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cursor_build_writes_and_disable);
}
