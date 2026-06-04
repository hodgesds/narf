//! AMD DC (Display Core) — pipeline state machine.
//!
//! DC is the high-level orchestrator above the per-IP register
//! sequencers in [`crate::amdgpu_dcn`]. Linux's DC layer
//! (`drivers/gpu/drm/amd/display/dc/`) handles:
//!
//! - **State validation** — every commit goes through
//!   `dc_validate_global_state` before any MMIO fires.
//! - **Resource allocation** — assigning a physical HUBP /
//!   DPP / OPP / MPC tree to a logical stream.
//! - **Pipeline construction** — chaining HUBP → DPP → MPC →
//!   OPP → OPTC per active stream.
//! - **State diff + commit** — only the registers that differ
//!   between old and new state get written.
//!
//! This module ports the *state* machine — not the per-IP
//! register sequencer (that's still [`crate::amdgpu_dcn`]) —
//! so the driver can validate a full pipeline before any
//! MMIO and apply only the diff on commit.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/display/dc/core/dc.c` — top
//!   level. Functions: `dc_commit_streams`, `dc_validate_global_state`.
//! - Linux `drivers/gpu/drm/amd/display/dc/core/dc_resource.c` —
//!   resource pool + pipe_ctx allocation.
//! - Linux `drivers/gpu/drm/amd/display/dc/core/dc_state.c` —
//!   state lifecycle.
//! - Linux `drivers/gpu/drm/amd/display/dc/dc_stream.h` — stream
//!   + plane shapes.
//!
//! Linux is GPL-2.0-or-later (matches NARF); structural patterns
//! adapted directly.
//!
//! ## Pipeline
//!
//! ```text
//!   per stream:
//!     HUBP (input fetch)
//!       ↓
//!     DPP  (DRR / scaling / gamma)
//!       ↓
//!     MPC  (multi-plane composition / blending)
//!       ↓
//!     OPP  (output processing)
//!       ↓
//!     OPTC (output timing generator → encoder)
//! ```
//!
//! Each block has an IP-version-specific register layout; the
//! state machine here is generation-agnostic. Per-version
//! register writes live in [`crate::amdgpu_dcn`] and the
//! future `amdgpu_dc/dcn20.rs` / `amdgpu_dc/dcn35.rs` modules.
//!
//! ## Scope
//!
//! - **Pipeline state** — what's currently programmed, in a
//!   validated form.
//! - **Resource pool** — which physical pipes are free.
//! - **Validate + diff** — produces a `PipelineDiff` between
//!   states for incremental commit.
//! - **No MMIO**: pure state. Diff dispatches go through the
//!   existing `amdgpu_dcn::execute_modeset` and the new
//!   `amdgpu_pageflip::build_flip` paths.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_dcn::ModeTiming;
use crate::amdgpu_modeset::CrtcState;

// ── Plane ────────────────────────────────────────────────────────

/// Plane kind. DC supports primary, overlay, and cursor planes
/// per stream; this scaffold covers primary + cursor, since the
/// overlay-plane path is layered on top of MPC blending which
/// arrives in a later stage.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PlaneKind {
    Primary,
    Cursor,
}

/// Pixel encoding the plane carries. Mirrors DCN's
/// `dc_pixel_encoding` (RGB, YCbCr 4:4:4 / 4:2:2 / 4:2:0).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelEncoding {
    /// 8-bpc / 10-bpc / 12-bpc RGB. Default for desktop scanout.
    Rgb,
    /// YCbCr 4:4:4 — full color resolution.
    Ycbcr444,
    /// YCbCr 4:2:2 — chroma subsampled horizontally.
    Ycbcr422,
    /// YCbCr 4:2:0 — chroma subsampled horizontally + vertically.
    /// Required for 4K60 over single-link HDMI 2.0.
    Ycbcr420,
}

/// Color depth, in bits per component.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    Bpc6,
    Bpc8,
    Bpc10,
    Bpc12,
    Bpc16,
}

impl ColorDepth {
    /// Wire bits per component (matches DCN
    /// `OUTPUT_FORMAT_COLOR_DEPTH` encoding).
    pub const fn bpc(self) -> u8 {
        match self {
            ColorDepth::Bpc6 => 6,
            ColorDepth::Bpc8 => 8,
            ColorDepth::Bpc10 => 10,
            ColorDepth::Bpc12 => 12,
            ColorDepth::Bpc16 => 16,
        }
    }
}

/// One plane in a stream. The primary plane carries the
/// scanout framebuffer; cursor planes carry the OS pointer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Plane {
    pub kind: PlaneKind,
    /// VRAM phys of the plane's surface buffer.
    pub surface_phys: u64,
    /// Stride in pixels.
    pub stride_pixels: u32,
    pub width: u32,
    pub height: u32,
    pub encoding: PixelEncoding,
    pub color_depth: ColorDepth,
}

// ── Stream ───────────────────────────────────────────────────────

/// One display stream. Mirrors Linux's `dc_stream_state` —
/// one stream per active connector + CRTC pair.
#[derive(Clone, Debug)]
pub struct Stream {
    /// Connector this stream presents to.
    pub connector_idx: u8,
    /// CRTC (OTG) driving the stream.
    pub crtc_idx: u8,
    /// Display timing (the OTG's mode).
    pub timing: ModeTiming,
    /// Planes composited into this stream. Index 0 = primary.
    pub planes: Vec<Plane>,
    /// Output color depth — the OPP programs this.
    pub output_color_depth: ColorDepth,
    /// `true` if the OPTC's master enable is set (scanout
    /// running).
    pub active: bool,
}

impl Stream {
    /// Returns the primary plane, if any.
    pub fn primary(&self) -> Option<&Plane> {
        self.planes.iter().find(|p| p.kind == PlaneKind::Primary)
    }
}

// ── Pipeline (DC state) ──────────────────────────────────────────

/// One physical pipe in the resource pool. Tracks which logical
/// stream owns the pipe's HUBP / DPP / OPP / OPTC quad.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PipeAlloc {
    /// Physical pipe index (0..n).
    pub hw_idx: u8,
    /// Logical stream that owns this pipe. `None` = free.
    pub stream_idx: Option<u8>,
}

/// Full DC state — what's currently programmed.
#[derive(Clone, Debug)]
pub struct DcState {
    pub streams: Vec<Stream>,
    pub pipes: Vec<PipeAlloc>,
}

impl Default for DcState {
    fn default() -> Self {
        Self {
            streams: Vec::new(),
            pipes: Vec::new(),
        }
    }
}

impl DcState {
    /// Mint a fresh state with `n_pipes` free pipes.
    pub fn new(n_pipes: u8) -> Self {
        let pipes = (0..n_pipes)
            .map(|i| PipeAlloc {
                hw_idx: i,
                stream_idx: None,
            })
            .collect();
        Self {
            streams: Vec::new(),
            pipes,
        }
    }

    /// Allocate a free pipe to the given logical stream. Returns
    /// the hw_idx the stream owns now. `NoFreePipe` if all are
    /// taken.
    pub fn allocate_pipe(&mut self, stream_idx: u8) -> Result<u8, DcError> {
        for pipe in &mut self.pipes {
            if pipe.stream_idx.is_none() {
                pipe.stream_idx = Some(stream_idx);
                return Ok(pipe.hw_idx);
            }
        }
        Err(DcError::NoFreePipe)
    }

    /// Free the pipe currently owned by `stream_idx`.
    pub fn release_pipes(&mut self, stream_idx: u8) {
        for pipe in &mut self.pipes {
            if pipe.stream_idx == Some(stream_idx) {
                pipe.stream_idx = None;
            }
        }
    }

    /// Add a stream to the state. Allocates a pipe + records it.
    pub fn add_stream(&mut self, stream: Stream) -> Result<u8, DcError> {
        // The stream is appended at the next index; allocate
        // against that index.
        let new_idx = self.streams.len() as u8;
        let _pipe = self.allocate_pipe(new_idx)?;
        self.streams.push(stream);
        Ok(new_idx)
    }

    /// Remove `stream_idx` from the state. Reindexes higher-
    /// indexed streams down by one and updates pipe ownership.
    pub fn remove_stream(&mut self, stream_idx: u8) -> Result<(), DcError> {
        if (stream_idx as usize) >= self.streams.len() {
            return Err(DcError::NoSuchStream);
        }
        self.release_pipes(stream_idx);
        self.streams.remove(stream_idx as usize);
        // Reindex pipe owners > stream_idx.
        for pipe in &mut self.pipes {
            if let Some(o) = pipe.stream_idx {
                if o > stream_idx {
                    pipe.stream_idx = Some(o - 1);
                }
            }
        }
        Ok(())
    }

    /// `Stream::active` flag flip helper. Used at the end of
    /// commit when OPTC_MASTER_EN is written.
    pub fn mark_active(&mut self, stream_idx: u8, active: bool) {
        if let Some(s) = self.streams.get_mut(stream_idx as usize) {
            s.active = active;
        }
    }

    /// Count active streams. Used by power management to decide
    /// DPM levels.
    pub fn active_count(&self) -> usize {
        self.streams.iter().filter(|s| s.active).count()
    }
}

// ── Validation ───────────────────────────────────────────────────

/// Validate a candidate state before commit. Mirrors Linux's
/// `dc_validate_global_state`: surfaces inconsistencies the
/// pipeline can't physically program.
pub fn validate_state(state: &DcState) -> Result<(), DcError> {
    // 1. Every stream must own a pipe.
    for (i, _s) in state.streams.iter().enumerate() {
        let owns = state.pipes.iter().any(|p| p.stream_idx == Some(i as u8));
        if !owns {
            return Err(DcError::StreamMissingPipe);
        }
    }
    // 2. No pipe may own a stream that doesn't exist.
    for pipe in &state.pipes {
        if let Some(idx) = pipe.stream_idx {
            if (idx as usize) >= state.streams.len() {
                return Err(DcError::DanglingPipe);
            }
        }
    }
    // 3. Each stream must have a primary plane.
    for s in &state.streams {
        if s.primary().is_none() {
            return Err(DcError::MissingPrimaryPlane);
        }
    }
    // 4. Stream timings must be sane.
    for s in &state.streams {
        if s.timing.h_active == 0 || s.timing.v_active == 0 {
            return Err(DcError::InvalidTiming);
        }
        if s.timing.h_total < s.timing.h_active || s.timing.v_total < s.timing.v_active {
            return Err(DcError::InvalidTiming);
        }
    }
    // 5. Streams cannot target the same CRTC (one OTG per
    //    output).
    for (i, a) in state.streams.iter().enumerate() {
        for b in state.streams.iter().skip(i + 1) {
            if a.crtc_idx == b.crtc_idx {
                return Err(DcError::ConflictingCrtc);
            }
        }
    }
    Ok(())
}

// ── Diff + commit ────────────────────────────────────────────────

/// One pipeline action the commit path takes. Output of
/// [`diff_state`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipelineAction {
    /// Stream `stream_idx` was added. Caller programs a full
    /// modeset (HUBP + DPP + MPC + OPP + OPTC).
    StreamAdded {
        stream_idx: u8,
        crtc_idx: u8,
        connector_idx: u8,
    },
    /// Stream `stream_idx` was removed. Caller disables the
    /// stream's pipe.
    StreamRemoved { crtc_idx: u8 },
    /// Stream `stream_idx`'s primary surface address changed.
    /// Caller does a page-flip (HUBP_PRIMARY_SURFACE_ADDRESS_*
    /// rewrite).
    PrimaryFlip { stream_idx: u8, new_phys: u64 },
    /// Stream `stream_idx`'s timing changed — full modeset
    /// (cannot live-reprogram OTG).
    TimingChanged { stream_idx: u8 },
    /// Stream `stream_idx`'s plane composition changed —
    /// reprogram MPC tree.
    PlanesChanged { stream_idx: u8 },
    /// Active flag flipped — write OPTC_MASTER_EN.
    ActiveChanged { stream_idx: u8, active: bool },
}

/// Diff old → new state and produce the action sequence the
/// commit path executes. The sequence is in execution order
/// (removals first to free pipes, then modes, then flips).
pub fn diff_state(old: &DcState, new: &DcState) -> Vec<PipelineAction> {
    let mut actions = Vec::new();

    // 1. Pure-removals: streams in old that aren't in new (by
    //    CRTC index — the modeset identifier the driver tracks).
    for old_s in &old.streams {
        let still_present = new.streams.iter().any(|s| s.crtc_idx == old_s.crtc_idx);
        if !still_present {
            actions.push(PipelineAction::StreamRemoved {
                crtc_idx: old_s.crtc_idx,
            });
        }
    }

    // 2. Diff matching streams + add new.
    for (new_idx, new_s) in new.streams.iter().enumerate() {
        let new_idx = new_idx as u8;
        match old.streams.iter().find(|s| s.crtc_idx == new_s.crtc_idx) {
            None => {
                // Brand new.
                actions.push(PipelineAction::StreamAdded {
                    stream_idx: new_idx,
                    crtc_idx: new_s.crtc_idx,
                    connector_idx: new_s.connector_idx,
                });
            }
            Some(old_s) => {
                // Timing change → full modeset.
                if old_s.timing != new_s.timing {
                    actions.push(PipelineAction::TimingChanged {
                        stream_idx: new_idx,
                    });
                }
                // Active flag flipped.
                if old_s.active != new_s.active {
                    actions.push(PipelineAction::ActiveChanged {
                        stream_idx: new_idx,
                        active: new_s.active,
                    });
                }
                // Primary plane phys changed → page flip.
                let old_prim = old_s.primary();
                let new_prim = new_s.primary();
                if let (Some(op), Some(np)) = (old_prim, new_prim) {
                    if op.surface_phys != np.surface_phys {
                        actions.push(PipelineAction::PrimaryFlip {
                            stream_idx: new_idx,
                            new_phys: np.surface_phys,
                        });
                    }
                }
                // Plane composition changed (count or non-prim
                // delta) → MPC reprogram.
                if old_s.planes.len() != new_s.planes.len() {
                    actions.push(PipelineAction::PlanesChanged {
                        stream_idx: new_idx,
                    });
                }
            }
        }
    }
    actions
}

/// Apply a CRTC-state notification from [`amdgpu_modeset`] to a
/// DC state. Used to keep the DC view in sync with KMS-driven
/// state changes.
pub fn sync_crtc_state(state: &mut DcState, crtc_idx: u8, new: CrtcState) {
    for s in &mut state.streams {
        if s.crtc_idx == crtc_idx {
            s.active = matches!(new, CrtcState::Active);
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DcError {
    NoFreePipe,
    NoSuchStream,
    StreamMissingPipe,
    DanglingPipe,
    MissingPrimaryPlane,
    InvalidTiming,
    ConflictingCrtc,
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use crate::amdgpu_dcn::timing_for_mode;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn make_primary(phys: u64, w: u32, h: u32) -> Plane {
        Plane {
            kind: PlaneKind::Primary,
            surface_phys: phys,
            stride_pixels: w,
            width: w,
            height: h,
            encoding: PixelEncoding::Rgb,
            color_depth: ColorDepth::Bpc8,
        }
    }

    fn make_stream(connector_idx: u8, crtc_idx: u8, phys: u64) -> Stream {
        let timing = timing_for_mode(1920, 1080, 60).unwrap();
        Stream {
            connector_idx,
            crtc_idx,
            timing,
            planes: alloc::vec![make_primary(phys, 1920, 1080)],
            output_color_depth: ColorDepth::Bpc8,
            active: false,
        }
    }

    fn smoke_dc_pipe_pool_allocate() -> TestResult {
        let mut s = DcState::new(4);
        if s.pipes.len() != 4 {
            return TestResult::Fail("new(4) pipe count wrong");
        }
        let p1 = s.allocate_pipe(0).expect("alloc 0");
        if p1 != 0 {
            return TestResult::Fail("first alloc not pipe 0");
        }
        let p2 = s.allocate_pipe(1).expect("alloc 1");
        if p2 != 1 {
            return TestResult::Fail("second alloc not pipe 1");
        }
        s.release_pipes(0);
        // Re-allocate — should land at the just-freed pipe 0.
        let p3 = s.allocate_pipe(2).expect("re-alloc");
        if p3 != 0 {
            return TestResult::Fail("re-alloc didn't take freed slot");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_pipe_pool_allocate);

    fn smoke_dc_pipe_pool_exhausted() -> TestResult {
        let mut s = DcState::new(2);
        s.allocate_pipe(0).expect("a");
        s.allocate_pipe(1).expect("b");
        if s.allocate_pipe(2) != Err(DcError::NoFreePipe) {
            return TestResult::Fail("exhaustion not flagged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_pipe_pool_exhausted);

    fn smoke_dc_add_remove_stream_reindex() -> TestResult {
        let mut s = DcState::new(4);
        let s0 = s.add_stream(make_stream(0, 0, 0x1000_0000)).expect("a");
        let s1 = s.add_stream(make_stream(1, 1, 0x2000_0000)).expect("b");
        let s2 = s.add_stream(make_stream(2, 2, 0x3000_0000)).expect("c");
        if (s0, s1, s2) != (0, 1, 2) {
            return TestResult::Fail("stream idx alloc wrong");
        }
        if s.streams.len() != 3 {
            return TestResult::Fail("streams not appended");
        }
        // Remove middle — reindexes s2 → s1.
        s.remove_stream(1).expect("remove");
        if s.streams.len() != 2 {
            return TestResult::Fail("remove didn't shrink");
        }
        // The pipe that owned stream 2 should now own stream 1.
        let pipe_for_s1 = s.pipes.iter().find(|p| p.stream_idx == Some(1));
        if pipe_for_s1.is_none() {
            return TestResult::Fail("pipe reindex didn't happen");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_add_remove_stream_reindex);

    fn smoke_dc_validate_catches_missing_primary() -> TestResult {
        let mut s = DcState::new(4);
        s.add_stream(make_stream(0, 0, 0x1000_0000)).expect("add");
        // Clear planes — missing primary now.
        s.streams[0].planes.clear();
        if validate_state(&s) != Err(DcError::MissingPrimaryPlane) {
            return TestResult::Fail("missing primary not caught");
        }
        // Restore + clobber timing.
        s.streams[0]
            .planes
            .push(make_primary(0x1000_0000, 1920, 1080));
        s.streams[0].timing.h_active = 0;
        if validate_state(&s) != Err(DcError::InvalidTiming) {
            return TestResult::Fail("invalid timing not caught");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_validate_catches_missing_primary);

    fn smoke_dc_validate_catches_crtc_conflict() -> TestResult {
        let mut s = DcState::new(4);
        s.add_stream(make_stream(0, 1, 0x1000_0000)).expect("a");
        s.add_stream(make_stream(1, 1, 0x2000_0000)).expect("b");
        // Both streams target CRTC 1 → conflict.
        if validate_state(&s) != Err(DcError::ConflictingCrtc) {
            return TestResult::Fail("CRTC conflict not caught");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_validate_catches_crtc_conflict);

    fn smoke_dc_diff_add_remove_flip() -> TestResult {
        let mut old = DcState::new(4);
        old.add_stream(make_stream(0, 0, 0x1000_0000)).expect("a");
        old.add_stream(make_stream(1, 1, 0x2000_0000)).expect("b");

        let mut new = DcState::new(4);
        // Same as old but stream 0's primary flipped to a new phys.
        let mut s0 = make_stream(0, 0, 0x1000_0000);
        s0.planes[0].surface_phys = 0x1500_0000;
        new.add_stream(s0).expect("a'");
        // Stream 1 removed; stream 2 added on CRTC 2.
        new.add_stream(make_stream(2, 2, 0x3000_0000)).expect("c");

        let actions = diff_state(&old, &new);
        // Expect: remove crtc=1, flip stream 0, add stream new on CRTC 2.
        let has_remove = actions
            .iter()
            .any(|a| matches!(a, PipelineAction::StreamRemoved { crtc_idx: 1 }));
        let has_flip = actions.iter().any(|a| {
            matches!(
                a,
                PipelineAction::PrimaryFlip {
                    new_phys: 0x1500_0000,
                    ..
                }
            )
        });
        let has_add = actions
            .iter()
            .any(|a| matches!(a, PipelineAction::StreamAdded { crtc_idx: 2, .. }));
        if !has_remove {
            return TestResult::Fail("diff missed StreamRemoved");
        }
        if !has_flip {
            return TestResult::Fail("diff missed PrimaryFlip");
        }
        if !has_add {
            return TestResult::Fail("diff missed StreamAdded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_diff_add_remove_flip);

    fn smoke_dc_diff_timing_change() -> TestResult {
        let mut old = DcState::new(4);
        old.add_stream(make_stream(0, 0, 0x1000_0000)).expect("a");

        let mut new = DcState::new(4);
        let mut s = make_stream(0, 0, 0x1000_0000);
        s.timing = timing_for_mode(1366, 768, 60).unwrap();
        new.add_stream(s).expect("a'");

        let actions = diff_state(&old, &new);
        let has_timing = actions
            .iter()
            .any(|a| matches!(a, PipelineAction::TimingChanged { .. }));
        if !has_timing {
            return TestResult::Fail("diff missed TimingChanged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_diff_timing_change);

    fn smoke_dc_active_count_and_sync() -> TestResult {
        let mut s = DcState::new(4);
        s.add_stream(make_stream(0, 0, 0x1000_0000)).expect("a");
        s.add_stream(make_stream(1, 1, 0x2000_0000)).expect("b");
        if s.active_count() != 0 {
            return TestResult::Fail("new streams should not be active");
        }
        // CRTC went Active externally — sync.
        sync_crtc_state(&mut s, 0, CrtcState::Active);
        if s.active_count() != 1 {
            return TestResult::Fail("active sync didn't update");
        }
        sync_crtc_state(&mut s, 1, CrtcState::Active);
        if s.active_count() != 2 {
            return TestResult::Fail("multi-active sync wrong");
        }
        sync_crtc_state(&mut s, 0, CrtcState::Inactive);
        if s.active_count() != 1 {
            return TestResult::Fail("deactivate sync wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dc_active_count_and_sync);
}
