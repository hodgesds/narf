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
//! - Register ids are `dcn_3_1_4_offset.h`/`_sh_mask.h`. Phoenix is
//!   DCN 3.1.4, so dcn35's offsets do not apply.
//! - Linux `drivers/gpu/drm/amd/display/amdgpu_dm.c::amdgpu_dm_commit_planes`
//!   — atomic-commit entry the KMS surface calls into.
//! - Linux `drivers/gpu/drm/amd/display/dc/hubp/dcn20/dcn20_hubp.c`
//!   (`hubp2_cursor_set_attributes`, `hubp2_cursor_set_position`) —
//!   the cursor's address, size, position and control are HUBP
//!   registers, in the `CURSOR0_n` block beside the surface
//!   addresses. Only its colour keying
//!   (`CNVC_CUR0_CURSOR0_CONTROL`) is in DPP.
//!
//! GPL-2.0-or-later; structural patterns adapted directly.
//!
//! ## Scope
//!
//! - **Primary plane flip** — atomic surface update producing a
//!   `(addr_lo, addr_hi)` write pair the driver writes to BAR5
//!   at the right register-bus offsets.
//! - **Cursor plane** — per-pipe, in HUBP's `CURSOR0_n` block,
//!   carrying address, size, position and a packed control word.
//! - **Flip queue** — a per-CRTC ring of pending flips; the
//!   FLIP_DONE IRQ retires the head. Triple-buffering is
//!   represented by a queue length of 3.
//! - **No MMIO** — pure codec. Driver core dispatches the writes.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::amdgpu_dcn::DcnWrite;

// ── HUBP register dword ids (DCN 3.1.4) ──────────────────────────
//
// Absolute dword ids from `dcn_3_1_4_offset.h`, the way the headers express
// them and the way the live DCN modules address them, with the per-pipe
// stride applied here.
//
// LINUX-GAP: `DcnWrite::addr` carries a block-relative *byte* offset
// everywhere else in `amdgpu_dcn`, against per-block base constants that
// match no header dword id. The writes built here are absolute dword ids
// instead, because that is what can be checked against the header. The two
// conventions are reconciled when `amdgpu_dcn`'s addressing is restructured.

/// `regHUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS` and `_HIGH`, BASE_IDX 2. Low
/// is **below** high, as it is for every HUBP address pair.
pub const DCSURF_PRIMARY_SURFACE_ADDRESS: u32 = 0x060a;
pub const DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH: u32 = 0x060b;

/// The cursor is **not** in DPP. `CURSOR_CONTROL`, the surface address pair,
/// `CURSOR_SIZE` and `CURSOR_POSITION` are the `CURSOR0_n` block alongside
/// HUBP, which is why `dcn20_hubp.c` programs them. Only the cursor's colour
/// keying (`CNVC_CUR0_CURSOR0_CONTROL`, 0x0cf1) lives in DPP, and this does
/// not touch it.
///
/// Their order is CONTROL, ADDRESS, ADDRESS_HIGH, SIZE, POSITION — the
/// address pair sits between the control and the geometry, not after it.
pub const CURSOR_CONTROL: u32 = 0x0678;
pub const CURSOR_SURFACE_ADDRESS: u32 = 0x0679;
pub const CURSOR_SURFACE_ADDRESS_HIGH: u32 = 0x067a;
pub const CURSOR_SIZE: u32 = 0x067b;
pub const CURSOR_POSITION: u32 = 0x067c;

/// Pipe stride, 0xDC dwords: `regHUBPREQ1_DCSURF_PRIMARY_SURFACE_ADDRESS` is
/// 0x06e6 and `regCURSOR0_1_CURSOR_CONTROL` is 0x0754, both 0xDC above pipe
/// zero's.
pub const HUBP_PIPE_STRIDE: u32 = 0xDC;
/// DCN 3.1.4 has four HUBPs (`dcn314_resource.c`).
pub const HUBP_PIPES: u8 = 4;

// `CURSOR_CONTROL` fields (`dcn_3_1_4_sh_mask.h`).
pub const CURSOR_ENABLE: u32 = 1 << 0;
pub const CURSOR_2X_MAGNIFY: u32 = 1 << 4;
/// `CURSOR_MODE` is three bits at **8** (mask 0x700), not three bits at 1.
pub const CURSOR_MODE_SHIFT: u32 = 8;
pub const CURSOR_MODE_MASK: u32 = 0x0000_0700;
/// `enum dc_cursor_color_format`: MONO 0, COLOR_1BIT_AND 1,
/// COLOR_PRE_MULTIPLIED_ALPHA 2 — the mode an ARGB8888 cursor uses.
pub const CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA: u32 = 2;
/// `CURSOR_PITCH` is two bits at 16, and the encoding is not the pitch:
/// `enum cursor_pitch` is 0 for 64 pixels, 1 for 128, 2 for 256
/// (`hubp1_get_cursor_pitch`).
pub const CURSOR_PITCH_SHIFT: u32 = 16;
pub const CURSOR_PITCH_64_PIXELS: u32 = 0;
pub const CURSOR_PITCH_128_PIXELS: u32 = 1;
pub const CURSOR_PITCH_256_PIXELS: u32 = 2;
/// `CURSOR_LINES_PER_CHUNK`, bits 27:24.
///
/// LINUX-GAP: `hubp2_cursor_set_attributes` also programs this, from a
/// width-and-format table, and writes `CURSOR_SETTINGS` (0x065c) with the
/// cursor's HDL schedule. Neither is written here, so the cursor fetch is
/// left at whatever the firmware set.
pub const CURSOR_LINES_PER_CHUNK_SHIFT: u32 = 24;

/// `CURSOR_SIZE`: width is bits 24:16 (mask `0x01FF0000`), height bits 8:0 —
/// **width high, height low**. Nine bits each, so 256 fits and 512 does not.
pub const CURSOR_WIDTH_SHIFT: u32 = 16;
/// `CURSOR_POSITION`: X is bits 29:16 (mask `0x3FFF0000`), Y bits 13:0 —
/// **X high, Y low**.
pub const CURSOR_X_POSITION_SHIFT: u32 = 16;

/// The dword id of `reg` for `pipe`.
pub const fn for_pipe(reg: u32, pipe: u8) -> u32 {
    reg + (pipe as u32) * HUBP_PIPE_STRIDE
}

/// `hubp1_get_cursor_pitch`: the field holds an encoding, and an unrecognised
/// pitch falls back to the 64-pixel encoding rather than being passed through.
pub const fn cursor_pitch_encoding(width: u16) -> u32 {
    match width {
        128 => CURSOR_PITCH_128_PIXELS,
        256 => CURSOR_PITCH_256_PIXELS,
        _ => CURSOR_PITCH_64_PIXELS,
    }
}

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

/// Build the MMIO writes that retire `req` on the next vsync of `pipe`.
///
/// Two-write sequence:
///   1. `DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH = phys[63:32]`
///   2. `DCSURF_PRIMARY_SURFACE_ADDRESS      = phys[31:0]`
///
/// Order matters: writing HIGH first then LOW arms the double-buffer with the
/// full 64-bit address; the latch happens when the LOW write retires, which
/// is why the low half is the register that sits lower in the map and is
/// written last. The next OTG vsync flips the pipe.
///
/// `DcnWrite::addr` is an absolute dword id here, not a block-relative byte
/// offset — see the register block above.
pub fn build_flip(pipe: u8, req: &PageFlipRequest) -> Result<PageFlipWrites, FlipError> {
    if pipe >= HUBP_PIPES {
        return Err(FlipError::BadSurface);
    }
    if !req.format.validate_stride(req.stride_bytes) {
        return Err(FlipError::BadStride);
    }
    if req.surface_phys & 0xFF != 0 {
        return Err(FlipError::BadSurface);
    }
    let writes = alloc::vec![
        DcnWrite {
            addr: for_pipe(DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH, pipe),
            value: (req.surface_phys >> 32) as u32,
        },
        DcnWrite {
            addr: for_pipe(DCSURF_PRIMARY_SURFACE_ADDRESS, pipe),
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

/// Build the cursor-program writes for `pipe`, in `hubp2_cursor_set_attributes`
/// order: address high, address, size, then control.
pub fn build_cursor(pipe: u8, st: &CursorState) -> Result<Vec<DcnWrite>, FlipError> {
    if pipe >= HUBP_PIPES || !st.validate() {
        return Err(FlipError::BadSurface);
    }
    let mut writes = Vec::with_capacity(5);
    if st.enabled {
        writes.push(DcnWrite {
            addr: for_pipe(CURSOR_SURFACE_ADDRESS_HIGH, pipe),
            value: (st.surface_phys >> 32) as u32,
        });
        writes.push(DcnWrite {
            addr: for_pipe(CURSOR_SURFACE_ADDRESS, pipe),
            value: st.surface_phys as u32,
        });
        // Width occupies the high half and height the low half, not the
        // other way round.
        writes.push(DcnWrite {
            addr: for_pipe(CURSOR_SIZE, pipe),
            value: ((st.width as u32) << CURSOR_WIDTH_SHIFT) | (st.height as u32),
        });
        // Likewise X high, Y low.
        writes.push(DcnWrite {
            addr: for_pipe(CURSOR_POSITION, pipe),
            value: ((st.x as u16 as u32) << CURSOR_X_POSITION_SHIFT) | (st.y as u16 as u32),
        });
        writes.push(DcnWrite {
            addr: for_pipe(CURSOR_CONTROL, pipe),
            value: CURSOR_ENABLE
                | (CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA << CURSOR_MODE_SHIFT)
                | (cursor_pitch_encoding(st.width) << CURSOR_PITCH_SHIFT),
        });
    } else {
        // Disabling — only clear the enable bit. Position survives.
        writes.push(DcnWrite {
            addr: for_pipe(CURSOR_CONTROL, pipe),
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
        // Pipe 2, so the stride is exercised rather than cancelling out.
        let r = build_flip(2, &req).expect("build_flip");
        if r.writes.len() != 2 {
            return TestResult::Fail("flip should emit 2 writes");
        }
        // HIGH first, LOW second — the latch fires on LOW. Dword ids from
        // `dcn_3_1_4_offset.h`: pipe 0 is 0x060a/0x060b, pipe 2 is 0xDC * 2
        // above, which the header spells regHUBPREQ2_… 0x07c2/0x07c3.
        if r.writes[0].addr != 0x07c3 {
            return TestResult::Fail("first write should be the HIGH half, at 0x07c3");
        }
        if r.writes[0].value != 1 {
            return TestResult::Fail("HIGH value wrong");
        }
        if r.writes[1].addr != 0x07c2 {
            return TestResult::Fail("second write should be LOW, the register below HIGH");
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
        // A 48-pixel-tall cursor so width and height are distinguishable.
        let st = CursorState { height: 48, ..st };
        let w = build_cursor(1, &st).expect("build_cursor enabled");
        if w.len() != 5 {
            return TestResult::Fail("enabled cursor should emit 5 writes");
        }
        // Dword ids from `dcn_3_1_4_offset.h`, pipe 1 = pipe 0 + 0xDC:
        // CONTROL 0x0754, ADDRESS 0x0755, ADDRESS_HIGH 0x0756, SIZE 0x0757,
        // POSITION 0x0758. The address pair sits between control and
        // geometry; these are HUBP registers, not DPP.
        if w[0].addr != 0x0756 || w[1].addr != 0x0755 {
            return TestResult::Fail("cursor address pair is 0x0755/0x0756 on pipe 1");
        }
        let last = w.last().unwrap();
        if last.addr != 0x0754 {
            return TestResult::Fail("last write should be CURSOR_CONTROL at 0x0754");
        }
        if last.value & 1 == 0 {
            return TestResult::Fail("CONTROL missing enable bit");
        }
        // CURSOR_MODE is three bits at 8, and premultiplied-alpha ARGB is 2.
        if last.value & 0x0000_0700 != 2 << 8 {
            return TestResult::Fail("CURSOR_MODE is bits 10:8, value 2 for premultiplied ARGB");
        }
        // CURSOR_PITCH is two bits at 16, and 64 pixels encodes as zero.
        if last.value & 0x0003_0000 != 0 {
            return TestResult::Fail("a 64-pixel-wide cursor encodes pitch zero");
        }
        // POSITION packs X high, Y low.
        let pos = w.iter().find(|w| w.addr == 0x0758).unwrap();
        if pos.value != (100 << 16) | 200 {
            return TestResult::Fail("CURSOR_POSITION is X at 16 and Y at 0");
        }
        // SIZE packs width high, height low.
        let sz = w.iter().find(|w| w.addr == 0x0757).unwrap();
        if sz.value != (64 << 16) | 48 {
            return TestResult::Fail("CURSOR_SIZE is width at 16 and height at 0");
        }
        // A 256-wide cursor takes the 256-pixel pitch encoding, which is 2 —
        // the field holds an encoding, not the pitch.
        let wide = CursorState { width: 256, ..st };
        let w2 = build_cursor(1, &wide).expect("build_cursor wide");
        if w2.last().unwrap().value & 0x0003_0000 != 2 << 16 {
            return TestResult::Fail("a 256-pixel-wide cursor encodes pitch two");
        }
        // Disabled cursor → only CONTROL = 0.
        let disabled = CursorState {
            enabled: false,
            ..st
        };
        let w = build_cursor(1, &disabled).expect("build_cursor disabled");
        if w.len() != 1 {
            return TestResult::Fail("disabled should emit only 1 write");
        }
        if w[0].value != 0 {
            return TestResult::Fail("disable should write 0 to control");
        }
        // Validate gates oversized cursors.
        let oversized = CursorState { width: 512, ..st };
        if build_cursor(1, &oversized) != Err(FlipError::BadSurface) {
            return TestResult::Fail("oversized cursor not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_cursor_build_writes_and_disable);

    /// The per-pipe stride and the register ids, as `dcn_3_1_4_offset.h`
    /// spells them for each of the four pipes.
    fn smoke_pageflip_pipe_stride_matches_header() -> TestResult {
        // regHUBPREQ{0..3}_DCSURF_PRIMARY_SURFACE_ADDRESS.
        let surface = [0x060a, 0x06e6, 0x07c2, 0x089e];
        // regCURSOR0_{0..3}_CURSOR_CONTROL.
        let cursor = [0x0678, 0x0754, 0x0830, 0x090c];
        for pipe in 0..HUBP_PIPES {
            if for_pipe(DCSURF_PRIMARY_SURFACE_ADDRESS, pipe) != surface[pipe as usize] {
                return TestResult::Fail("HUBPREQ surface address stride");
            }
            if for_pipe(CURSOR_CONTROL, pipe) != cursor[pipe as usize] {
                return TestResult::Fail("CURSOR0 control stride");
            }
        }
        // The cursor block sits above the surface addresses in the same
        // per-pipe window, which is why one stride serves both.
        if HUBP_PIPE_STRIDE != 0xDC {
            return TestResult::Fail("the per-pipe stride is 0xDC dwords");
        }
        // A pipe beyond the four DCN314 has is refused rather than
        // addressing the next block along.
        let req = PageFlipRequest {
            surface_phys: 0x1000,
            format: PixelFormat::Xrgb8888,
            stride_bytes: 1024,
            generation: 0,
        };
        if build_flip(HUBP_PIPES, &req).is_ok() {
            return TestResult::Fail("out-of-range pipe accepted");
        }
        if build_cursor(HUBP_PIPES, &CursorState::default()).is_ok() {
            return TestResult::Fail("out-of-range cursor pipe accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_pageflip_pipe_stride_matches_header);
}
