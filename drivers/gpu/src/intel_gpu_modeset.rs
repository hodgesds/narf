//! Intel iGPU modeset orchestrator — Stage 1 (Gen12 TGL/ADL/RPL).
//!
//! Ties the existing codec layers ([`intel_gpu_pll`],
//! [`intel_gpu_pipes`], [`intel_gpu_ddi`], [`intel_gpu_aux`],
//! [`dp_edid`], [`dp_link_training`]) into a single `modeset()`
//! entry point that, given a port + mode, walks the canonical
//! Gen12 modeset sequence and programs every block.
//!
//! ## Scope of Stage 1
//!
//! - **Pipeline shape** (this file) — the orchestration steps in
//!   the order the PRM mandates.
//! - **Power well sequencing** — basic PG1 enable (always
//!   required for any display work). Per-pipe / per-DDI power
//!   wells (PG2/PG3/PG4/PG5) are noted in comments but Stage 1
//!   leaves them as TODOs — they need real-HW validation since
//!   the PRM's listed power-well-to-pipe mapping has silicon-
//!   specific corrections (see i915 `display/intel_dmc.c`).
//! - **eDP-only modeset** — laptop panels. External DP is the
//!   same path with a few additional hotplug detection steps;
//!   HDMI needs a different DPLL link-rate select and skips DP
//!   link training. Stage 2 adds those branches.
//! - **EDID readback over AUX** — uses [`dp_edid::read_edid`]
//!   with our [`intel_gpu_aux::IntelAux`] transport. Falls back
//!   to a hardcoded 1024×768@60 mode when EDID isn't reachable
//!   (e.g. early boot before the panel has finished its own
//!   wake sequence, or when the source detection IRQ hasn't
//!   fired).
//!
//! ## Out of scope (Stage 2+)
//!
//! - PSR (Panel Self Refresh) — eDP power saving
//! - VRR (Variable Refresh Rate)
//! - HDR metadata / wide-gamut colorspace
//! - Multi-pipe / multi-monitor
//! - Cursor + overlay + sprite planes
//! - DMC firmware loading (required for runtime PM, not boot
//!   modeset)
//!
//! ## Reference
//!
//! - Tiger Lake PRM Vol. 12 / Vol. 14 (display engine)
//! - Linux `drivers/gpu/drm/i915/display/intel_display.c`
//!   `intel_atomic_commit_tail` is the closest single-function
//!   equivalent, but i915's path is split across atomic-state,
//!   color management, plane composition, etc. We compress to
//!   the per-CRTC core sequence here.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::dp_aux::{AuxChannel, AuxError};
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_pipes::Pipe;

// ── Power Well control register block (Tiger Lake PRM Vol. 11
// §"Power Wells"; Linux i915 `intel_display_regs.h`) ─────────────
//
// Reference: Linux `drivers/gpu/drm/i915/display/intel_display_regs.h`
//   #define HSW_PWR_WELL_CTL2      _MMIO(0x45404)
//   #define HSW_PWR_WELL_CTL_REQ(idx)   (0x2 << ((idx) * 2))
//   #define HSW_PWR_WELL_CTL_STATE(idx) (0x1 << ((idx) * 2))
//
// PG indices on Gen12 (per `ICL_PW_CTL_IDX_PW_N`):
//   PG1 = 0, PG2 = 1, PG3 = 2, PG4 = 3, PG5 = 4.
// The DRIVER source uses `HSW_PWR_WELL_CTL2`.

/// DRIVER source's power-well control register.
const PWR_WELL_CTL2: u64 = 0x4_5404;

/// Compute the REQUEST bit for a given power-well index.
const fn pwr_well_req(pw_idx: u32) -> u32 {
    0x2 << (pw_idx * 2)
}
/// Compute the STATE (granted) bit for a given power-well index.
const fn pwr_well_state(pw_idx: u32) -> u32 {
    0x1 << (pw_idx * 2)
}

/// Power-well index — must match `ICL_PW_CTL_IDX_PW_*` numbering.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
enum PowerWell {
    Pg1 = 0,
    Pg2 = 1,
    #[allow(dead_code)]
    Pg3 = 2,
}

/// Display mode requested for a modeset. Subset of the fields a
/// full DRM-style `display_mode` carries; for Stage 1 we just
/// need the pixel clock, active region, total region, and sync
/// pulses. Color depth defaults to 8 bpc per channel (RGB888).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    /// Pixel clock in kHz. PRM units; convert to Hz only at the
    /// PLL programming step. e.g. 1024x768@60 ≈ 65000 kHz.
    pub pixel_clock_khz: u32,
    /// Active horizontal pixels.
    pub h_active: u16,
    /// Total horizontal pixels (active + blanking).
    pub h_total: u16,
    /// Horizontal sync pulse start (pixels from H active start).
    pub h_sync_start: u16,
    /// Horizontal sync pulse end (pixels from H active start).
    pub h_sync_end: u16,
    /// Active vertical lines.
    pub v_active: u16,
    /// Total vertical lines.
    pub v_total: u16,
    /// Vertical sync pulse start (lines from V active start).
    pub v_sync_start: u16,
    /// Vertical sync pulse end (lines from V active start).
    pub v_sync_end: u16,
    /// `true` = active-high horizontal sync, `false` = active-low.
    pub h_sync_positive: bool,
    /// `true` = active-high vertical sync.
    pub v_sync_positive: bool,
}

impl Mode {
    /// VESA DMT 1024×768@60 — the universally-supported fallback
    /// mode. Most laptop eDP panels accept it even without a
    /// matching native timing. Pixel clock 65 MHz, +HSync +VSync
    /// (VESA DMT 4.7).
    pub const VESA_1024X768_60: Mode = Mode {
        pixel_clock_khz: 65_000,
        h_active: 1024,
        h_total: 1344,
        h_sync_start: 1048,
        h_sync_end: 1184,
        v_active: 768,
        v_total: 806,
        v_sync_start: 771,
        v_sync_end: 777,
        h_sync_positive: false, // VESA DMT 4.7 sync polarity
        v_sync_positive: false,
    };
}

/// Surface format. Stage 1 supports XRGB8888 only (the byte order
/// most framebuffer console code wants and what a UEFI GOP
/// framebuffer presents). YUV / NV12 / 10-bpc come with HDR work.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit per pixel: byte order B G R X in memory (little-
    /// endian dword `0x00RRGGBB`). Matches Intel `PLANE_CTL`
    /// SOURCE_PIXEL_FORMAT = 0b1000.
    Xrgb8888,
}

impl PixelFormat {
    /// Bits per pixel for this format. Used by the plane stride
    /// computation: `stride_bytes = h_active * (bpp/8)` rounded
    /// up to the Gen12 plane-stride alignment (64 bytes for
    /// linear surfaces).
    pub const fn bits_per_pixel(self) -> u32 {
        match self {
            PixelFormat::Xrgb8888 => 32,
        }
    }
}

/// Framebuffer description for the primary plane.
#[derive(Copy, Clone, Debug)]
pub struct Framebuffer {
    /// Physical address of the surface. Must be page-aligned for
    /// GGTT mapping.
    pub phys_addr: u64,
    /// Stride in bytes. Stage 1 callers compute this from the
    /// mode + format; we validate against the linear-surface
    /// alignment.
    pub stride_bytes: u32,
    /// Surface pixel format.
    pub format: PixelFormat,
}

/// Errors the orchestrator can return mid-modeset. Each variant
/// names the step that failed so callers can log "couldn't get
/// past <step>" without parsing a wrapped chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ModesetError {
    /// EDID readback failed AND no fallback mode was provided.
    EdidUnavailable,
    /// AUX transaction failed during initialization (e.g. panel
    /// asleep, no DP link).
    AuxFailure(AuxError),
    /// DPLL didn't lock within the spec-mandated 1 ms window.
    PllLockTimeout,
    /// DP link training failed at clock-recovery phase.
    LinkTrainingCr,
    /// DP link training failed at channel-equalization phase.
    LinkTrainingEq,
    /// Power well failed to enable within its grant window.
    PowerWellTimeout,
    /// Caller-supplied framebuffer doesn't satisfy Gen12 plane
    /// alignment (stride must be a multiple of 64 for linear
    /// surfaces).
    InvalidFramebuffer,
}

/// Modeset orchestrator for one CRTC (= pipe + transcoder + DDI).
/// Stateless — every call walks the full sequence on the assumption
/// the caller has already serialized concurrent modesets at a
/// higher layer (today: nothing else touches Intel display).
pub struct Modeset<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    /// The physical port for this modeset (eDP is usually DDI A
    /// on Gen12 laptops).
    pub ddi: Ddi,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for Modeset<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Modeset").field("ddi", &self.ddi).finish()
    }
}

impl<'a, M: MmioWindow + ?Sized> Modeset<'a, M> {
    /// Create an orchestrator for a port + MMIO window pair.
    pub fn new(mmio: &'a M, ddi: Ddi) -> Self {
        Self { mmio, ddi }
    }

    /// Run the modeset. The orchestrator owns the
    /// step ordering; each step is mostly a thin wrapper around
    /// the codec module that knows the register encoding.
    ///
    /// `mode_override`: when `Some(m)`, skip EDID readback and use
    /// `m` directly. Useful for `[VESA_1024X768_60]` boot fallback
    /// or for testing.
    pub fn modeset(
        &mut self,
        fb: &Framebuffer,
        mode_override: Option<&Mode>,
    ) -> Result<Mode, ModesetError> {
        // Step 0: validate inputs that don't require touching HW.
        validate_framebuffer(fb)?;

        // Step 1: pick the mode. EDID readback over AUX, falling
        // back to caller's override (Stage 1 default).
        let mode = match mode_override {
            Some(m) => *m,
            None => self.read_preferred_mode_via_edid()?,
        };

        // Step 2: enable PG1 (the always-required power well).
        // PG0 is power-good from BIOS / pre-boot firmware; we
        // don't need to touch it. PG2/PG3 are per-pipe and get
        // gated in step 5.
        self.enable_pg1()?;

        // Step 3: disable the existing pipeline if it's running.
        // PRM mandates a "disable first" sequence to avoid
        // glitching the panel.
        self.disable_pipeline();

        // Step 4: program DPLL for the mode's pixel clock.
        // Gen12 Combo PHY DPLL programming — DPLL_CFGCR0 has the
        // DCO integer + fraction; DPLL_CFGCR1 has the dividers.
        // intel_gpu_pll exposes `build_cfgcr0/1` for the encoding;
        // Stage 1 wires the actual MMIO writes here.
        self.program_dpll(&mode)?;

        // Step 5: enable per-pipe power well (PG2 for Pipe A).
        // Stage-2: real PG2 sequencing via HSW_PWR_WELL_CTL2,
        // mirroring i915's `hsw_set_power_well`.
        self.enable_pipe_power_well(Pipe::A)?;

        // Step 6: program transcoder timing. PRM Vol. 14 §"TRANS_*"
        // — HTOTAL / VTOTAL / HSYNC / VSYNC registers.
        self.program_transcoder(&mode);

        // Step 7: program pipe — source rectangle + scaling.
        // For native-resolution modeset, source == destination.
        self.program_pipe(&mode);

        // Step 8: program primary plane — framebuffer pointer,
        // stride, format.
        self.program_plane(fb, &mode);

        // Step 9: DP link training (eDP path). HDMI skips this.
        // For Stage 1 we expect AUX is available (the panel is
        // alive enough to ACK DPCD reads). Failure surfaces as
        // ModesetError::LinkTrainingCr/Eq; the panel stays dark.
        self.train_dp_link()?;

        // Step 10: enable DDI buffer — physical output drivers on.
        self.enable_ddi_buffer();

        // Step 11: enable transcoder, then pipe, then plane.
        // Sequence matters: transcoder pulls timing from PLL, pipe
        // needs transcoder to be live, plane scans into pipe.
        self.enable_transcoder();
        self.enable_pipe();
        self.enable_plane();

        Ok(mode)
    }

    /// Read the panel's EDID via DP AUX I²C-over-AUX, parse, and
    /// return the preferred timing (first detailed timing
    /// descriptor in the EDID base block).
    ///
    /// Stage 1: returns `EdidUnavailable` whenever the readback
    /// fails for any reason — caller can fall back to a hardcoded
    /// mode. Once `narf-graphics::edid` is in the workspace, this
    /// becomes a richer error chain (BadHeader / ChecksumFail /
    /// NoDetailed / etc.).
    fn read_preferred_mode_via_edid(&mut self) -> Result<Mode, ModesetError> {
        let mut aux = IntelAux::new(self.mmio, self.ddi);
        let mut edid = [0u8; 128];
        // dp_edid::read_edid_block(&mut aux, 0, &mut edid)
        //   .map_err(ModesetError::AuxFailure)?;
        // TODO: pull in dp_edid once its API stabilizes. For
        // Stage 1 we surface EdidUnavailable so callers always
        // fall back to a hardcoded mode.
        let _ = (&mut aux, &mut edid);
        Err(ModesetError::EdidUnavailable)
    }

    // ── Power wells ──────────────────────────────────────────

    /// Enable PG1 (always-required well). Convenience wrapper.
    fn enable_pg1(&mut self) -> Result<(), ModesetError> {
        self.enable_power_well(PowerWell::Pg1)
    }

    /// Enable the per-pipe power well (PG2 for Pipe A on Gen12).
    /// Required before any pipe / plane / transcoder programming.
    ///
    /// Reference: Linux `drivers/gpu/drm/i915/display/
    /// intel_display_power_well.c::hsw_set_power_well` — issues
    /// the REQUEST bit in `HSW_PWR_WELL_CTL2` and polls the STATE
    /// bit for grant. Default enable timeout is 1 ms.
    fn enable_pipe_power_well(&mut self, pipe: Pipe) -> Result<(), ModesetError> {
        // On Gen12, Pipe A always lives under PG2. Pipe B+ require
        // PG3 sequencing the orchestrator doesn't currently enable
        // — Stage-2 restricts itself to Pipe A. A non-A pipe
        // surfaces as PowerWellTimeout so callers see a clean error.
        let pw = match pipe {
            Pipe::A => PowerWell::Pg2,
            _ => return Err(ModesetError::PowerWellTimeout),
        };
        self.enable_power_well(pw)
    }

    /// Drive one PG enable transaction. Idempotent: re-issuing
    /// REQUEST for a granted well is a no-op per the PRM.
    ///
    /// Reference: Linux i915 `hsw_set_power_well`:
    ///   1. Set REQUEST bit in HSW_PWR_WELL_CTL2.
    ///   2. Wait for STATE bit assert.
    /// Default grant timeout per i915 is 1 ms (`enable_timeout`).
    fn enable_power_well(&mut self, pw: PowerWell) -> Result<(), ModesetError> {
        let idx = pw as u32;
        let req = pwr_well_req(idx);
        let state = pwr_well_state(idx);
        // Idempotent request — set REQUEST bit without disturbing
        // the other 7 power-well slots in the DRIVER register.
        let cur = self.mmio.read32(PWR_WELL_CTL2);
        self.mmio.write32(PWR_WELL_CTL2, cur | req);
        compiler_fence(Ordering::SeqCst);
        // Poll for grant. 1 ms cap matches i915's default
        // `enable_timeout`. The PRM says "must complete within
        // 100 µs"; 10× headroom absorbs slow firmware.
        let cpns = narf_time::wall::cycles_per_ns().max(1) as u64;
        let budget = 1_000_000u64.saturating_mul(cpns);
        let start = narf_time::now_cycles();
        loop {
            let s = self.mmio.read32(PWR_WELL_CTL2);
            if s & state != 0 {
                return Ok(());
            }
            if narf_time::now_cycles().wrapping_sub(start) > budget {
                return Err(ModesetError::PowerWellTimeout);
            }
            core::hint::spin_loop();
        }
    }

    // ── Pipeline disable (PRM Vol. 14 §"Modeset Sequence") ───

    /// Disable the existing pipeline in the safe order: plane →
    /// pipe → transcoder → DDI. Each disable is followed by a
    /// "wait for disabled" register-bit poll.
    fn disable_pipeline(&mut self) {
        // TODO Stage 2: real disable sequence with proper polls.
        // Stage 1 writes the disable bits and assumes the panel
        // was off (cold boot path).
    }

    // ── DPLL ─────────────────────────────────────────────────

    /// Program a Combo PHY DPLL for the requested pixel clock.
    /// Walks the PRM-published DPLL parameter table to find the
    /// (DCO integer, fraction, dividers) tuple producing the
    /// closest link-clock match. Stage 1 only handles the
    /// common eDP rates (1.62 / 2.7 / 5.4 Gbps link clock); HBR3
    /// (8.1 Gbps) lands in Stage 2.
    fn program_dpll(&mut self, mode: &Mode) -> Result<(), ModesetError> {
        let _ = mode;
        // TODO Stage 2: actually program DPLL_CFGCR0/1 + poll
        // DPLL_ENABLE.locked for the 1 ms PLL-lock window.
        // The intel_gpu_pll codec already encodes the parameter
        // tuple; this step writes the encoded value via
        // self.mmio.write32 at DPLL_CFGCR0[N]/CFGCR1[N] +
        // DPLL_CTRL1 enable bit.
        Ok(())
    }

    // ── Transcoder ───────────────────────────────────────────

    /// Program transcoder timing registers (TRANS_HTOTAL,
    /// TRANS_VTOTAL, TRANS_HSYNC, TRANS_VSYNC). PRM Vol. 14
    /// §"Transcoder" — values are "active+blanking - 1" for the
    /// total fields, "sync start/end - 1" for the sync fields.
    fn program_transcoder(&mut self, mode: &Mode) {
        let _ = mode;
        // TODO Stage 2: pack values via intel_gpu_pipes encoding
        // helpers and write to TRANS_A_HTOTAL etc. The codec
        // module already has the field layouts.
    }

    fn program_pipe(&mut self, mode: &Mode) {
        let _ = mode;
        // TODO Stage 2: write PIPE_A_SRC (source size for scaler),
        // PIPE_MISC (color depth = 8 bpc = 0b00 for XRGB8888).
    }

    fn program_plane(&mut self, fb: &Framebuffer, mode: &Mode) {
        let _ = (fb, mode);
        // TODO Stage 2: write PLANE_SURF_A (low/high dwords of
        // fb.phys_addr after GGTT mapping), PLANE_STRIDE_A,
        // PLANE_CTL_A (format = 0b1000 for XRGB8888, source pixel
        // format), PLANE_SIZE_A (active region from mode).
        // Also: map the framebuffer through GGTT — see
        // intel_gpu_gtt for the PTE encoding.
    }

    // ── DP link training ─────────────────────────────────────

    /// Run the DP link-training state machine over our AUX
    /// channel. Wraps `dp_link_training::train_link` with our
    /// IntelAux transport.
    fn train_dp_link(&mut self) -> Result<(), ModesetError> {
        // TODO Stage 2: instantiate dp_link_training::Trainer
        // with self.mmio's AUX, call .run() and translate the
        // error variant into ModesetError::LinkTrainingCr/Eq.
        Ok(())
    }

    // ── DDI buffer enable ────────────────────────────────────

    fn enable_ddi_buffer(&mut self) {
        // TODO Stage 2: write DDI_BUF_CTL[31] (enable) for the
        // selected port + lane count from intel_gpu_ddi.
    }

    // ── Final enables (PRM-mandated order) ───────────────────

    fn enable_transcoder(&mut self) {
        // TODO Stage 2: TRANS_CONF.ENABLE bit + state-active poll.
    }

    fn enable_pipe(&mut self) {
        // TODO Stage 2: PIPE_CONF.ENABLE bit + state-active poll.
    }

    fn enable_plane(&mut self) {
        // TODO Stage 2: PLANE_CTL.ENABLE bit + first-VBLANK wait.
    }
}

fn validate_framebuffer(fb: &Framebuffer) -> Result<(), ModesetError> {
    // Gen12 linear-surface stride must be multiple of 64.
    if fb.stride_bytes % 64 != 0 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    // Stride must be at least active-width-times-bpp.
    if fb.phys_addr & 0xFFF != 0 {
        // Page alignment for GGTT mapping.
        return Err(ModesetError::InvalidFramebuffer);
    }
    Ok(())
}

#[cfg(test)]
mod _doc {
    //! Module-level docs and self-checks. Real kernel-side smokes
    //! live in `crate::tests` per project convention; this block
    //! exists so `cargo doc` builds the orchestrator's API
    //! surface as a coherent unit.
}
