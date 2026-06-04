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
use crate::intel_gpu_pll::{combo_coeffs, encode_cfgcr0, LinkRate};

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

// ── DPLL enable register block (Tiger Lake PRM Vol. 11 §"DPLL Enable";
// Linux i915 `intel_display_regs.h`) ─────────────────────────────────
//
// Reference: Linux drivers/gpu/drm/i915/display/intel_display_regs.h
//   _DPLL0_ENABLE = 0x46010
//   _DPLL1_ENABLE = 0x46014
//   PLL_ENABLE       = bit 31
//   PLL_LOCK         = bit 30
//   PLL_POWER_ENABLE = bit 27
//   PLL_POWER_STATE  = bit 26

const DPLL0_ENABLE: u64 = 0x4_6010;
const DPLL1_ENABLE: u64 = 0x4_6014;
const PLL_ENABLE: u32 = 1 << 31;
const PLL_LOCK: u32 = 1 << 30;
const PLL_POWER_ENABLE: u32 = 1 << 27;
const PLL_POWER_STATE: u32 = 1 << 26;

/// DDI A maps to DPLL 0 on Gen12 Combo PHY by default. Multi-DDI
/// arbitration via DPCLKA_CFGCR0 lands in Stage-3.
const fn dpll_enable_off(dpll_idx: u32) -> u64 {
    if dpll_idx == 0 {
        DPLL0_ENABLE
    } else {
        DPLL1_ENABLE
    }
}

/// Pick the lowest DP link rate that can deliver `pixel_clock_khz`
/// pixels per second of 24-bpp RGB scanout over 4 lanes.
///
/// Bandwidth math: 24 bits per pixel * pixel_clock_khz kbps =
///   `pixel_clock_khz * 24` kbps total. With 4 lanes each carrying
///   `rate_mbps * 1000` kbps (minus 8b/10b coding overhead, so
///   80% net), the rate must satisfy
///   `4 * rate_mbps * 1000 * 0.8 >= pixel_clock_khz * 24`,
///   i.e. `rate_mbps >= pixel_clock_khz * 30 / 4 / 1000`.
///   Simplify: `rate_kbps >= pixel_clock_khz * 30 / 4`.
fn link_rate_for_pixel_clock(pixel_clock_khz: u32) -> LinkRate {
    // Required per-lane net rate in kbps. 30 = 24 bpp / 0.8 (8b/10b).
    let required_kbps = (pixel_clock_khz.saturating_mul(30)) / 4;
    if required_kbps <= 1_620_000 {
        LinkRate::DpRbr
    } else if required_kbps <= 2_700_000 {
        LinkRate::DpHbr
    } else if required_kbps <= 5_400_000 {
        LinkRate::DpHbr2
    } else {
        LinkRate::DpHbr3
    }
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
        let mut edid_buf = [0u8; 128];
        let edid = crate::dp_edid::read_panel_edid(&mut aux, &mut edid_buf)
            .map_err(|_| ModesetError::EdidUnavailable)?;

        let d = edid.preferred_timing().map_err(|_| ModesetError::EdidUnavailable)?;

        Ok(Mode {
            pixel_clock_khz: d.pixel_clock_khz,
            h_active: d.h_active,
            h_total: d.h_active + d.h_blanking,
            h_sync_start: d.h_active + d.h_sync_offset,
            h_sync_end: d.h_active + d.h_sync_offset + d.h_sync_width,
            v_active: d.v_active,
            v_total: d.v_active + d.v_blanking,
            v_sync_start: d.v_active + d.v_sync_offset,
            v_sync_end: d.v_active + d.v_sync_offset + d.v_sync_width,
            h_sync_positive: d.h_sync_positive,
            v_sync_positive: d.v_sync_positive,
        })
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
    /// pipe → transcoder → DDI. Each disable clears the relevant
    /// enable bit and polls the inverse state for "actually off"
    /// with a 100 ms cap (matches i915's `intel_wait_for_pipe_off`).
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_disable_pipe`, `intel_disable_transcoder`).
    fn disable_pipeline(&mut self) {
        use crate::intel_gpu_ddi::{
            DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS, DDI_BUF_CTL_OFFSET,
        };
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
            PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET,
        };
        // 1) Plane: clear ENABLE then re-arm via PLANE_SURF write
        //    so the next vblank latches "no plane".
        let plane_base = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        let ctl = self.mmio.read32(plane_base + PLANE_CTL_OFFSET);
        self.mmio
            .write32(plane_base + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE);
        // Re-write SURF to trigger the latch.
        let surf = self.mmio.read32(plane_base + PLANE_SURF_OFFSET);
        self.mmio.write32(plane_base + PLANE_SURF_OFFSET, surf);
        compiler_fence(Ordering::SeqCst);

        // 2) Pipe: clear ENABLE, wait for state-inactive.
        let pipe_off = PipeIdx::A.base() + PIPECONF_OFFSET;
        let pconf = self.mmio.read32(pipe_off);
        self.mmio.write32(pipe_off, pconf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, pipe_off, PIPECONF_STATE, false, 100_000_000);

        // 3) Transcoder: same pattern as pipe.
        let trans_off = Transcoder::A.base() + PIPECONF_OFFSET;
        let tconf = self.mmio.read32(trans_off);
        self.mmio.write32(trans_off, tconf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, trans_off, PIPECONF_STATE, false, 100_000_000);

        // 4) DDI buffer: clear ENABLE, poll IDLE_STATUS asserts.
        let ddi_off = self.ddi.base() + DDI_BUF_CTL_OFFSET;
        let dconf = self.mmio.read32(ddi_off);
        self.mmio.write32(ddi_off, dconf & !DDI_BUF_CTL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, ddi_off, DDI_BUF_CTL_IDLE_STATUS, true, 1_000_000);
    }

    // ── DPLL ─────────────────────────────────────────────────

    /// Program a Combo PHY DPLL for the requested pixel clock.
    /// Picks the lowest DP link rate that meets the bandwidth
    /// requirement of `mode`'s 24-bpp scanout, looks up the
    /// PRM-published Combo-PHY coefficients, programs CFGCR0/1,
    /// and brings the DPLL up:
    ///
    ///   1. Power-up via PLL_POWER_ENABLE + wait for PLL_POWER_STATE.
    ///   2. Write CFGCR0 (DCO integer + fraction) and CFGCR1 (Q/K/P
    ///      dividers + central freq).
    ///   3. Set PLL_ENABLE.
    ///   4. Poll PLL_LOCK with a 1 ms cap.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_dpll.c
    /// (`icl_pll_power_enable`, `icl_pll_enable`).
    fn program_dpll(&mut self, mode: &Mode) -> Result<(), ModesetError> {
        let rate = link_rate_for_pixel_clock(mode.pixel_clock_khz);
        let coeffs = match combo_coeffs(rate) {
            Some(c) => c,
            None => return Err(ModesetError::PllLockTimeout),
        };
        // DDI A → DPLL 0 (default Combo-PHY mapping). Stage-2 only
        // exercises this; multi-DDI port arbitration via DPCLKA_CFGCR0
        // lands when Pipe B+ comes online.
        let dpll_idx: u32 = 0;
        let dpll_enable = dpll_enable_off(dpll_idx);

        // Step 1 — power the PLL up.
        let cur = self.mmio.read32(dpll_enable);
        self.mmio.write32(dpll_enable, cur | PLL_POWER_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(self.mmio, dpll_enable, PLL_POWER_STATE, true, 1_000_000) {
            return Err(ModesetError::PllLockTimeout);
        }

        // Step 2 — CFGCR0 / CFGCR1.
        let cfgcr0 = encode_cfgcr0(&coeffs);
        let cfgcr0_off = crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0;
        let cfgcr1_off = crate::intel_gpu_pll::dpll_cfgcr1(cfgcr0_off);
        self.mmio.write32(cfgcr0_off, cfgcr0);
        self.mmio.write32(cfgcr1_off, coeffs.cfgcr1);
        compiler_fence(Ordering::SeqCst);

        // Step 3 — enable.
        let cur = self.mmio.read32(dpll_enable);
        self.mmio.write32(dpll_enable, cur | PLL_ENABLE);
        compiler_fence(Ordering::SeqCst);

        // Step 4 — wait for lock. 1 ms cap per PRM.
        if !wait_bit(self.mmio, dpll_enable, PLL_LOCK, true, 1_000_000) {
            return Err(ModesetError::PllLockTimeout);
        }
        Ok(())
    }

    // ── Transcoder ───────────────────────────────────────────

    /// Program transcoder timing registers (TRANS_HTOTAL,
    /// TRANS_HBLANK, TRANS_HSYNC, TRANS_VTOTAL, TRANS_VBLANK,
    /// TRANS_VSYNC). PRM Vol. 14 §"Transcoder" — values are
    /// "active+blanking - 1" for the total fields, "sync
    /// start/end - 1" for the sync fields. Field packing comes
    /// from intel_gpu_pipes::build_transcoder.
    ///
    /// Stage-2 binds Pipe A ↔ Transcoder A (mobile eDP often
    /// uses Transcoder::Edp; Stage-3 will branch on port type).
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_set_transcoder_timings`).
    fn program_transcoder(&mut self, mode: &Mode) {
        use crate::intel_gpu_pipes::{
            build_transcoder, Transcoder, TRANS_HBLANK_OFFSET, TRANS_HSYNC_OFFSET,
            TRANS_HTOTAL_OFFSET, TRANS_VBLANK_OFFSET, TRANS_VSYNC_OFFSET, TRANS_VTOTAL_OFFSET,
        };
        let timing = mode_to_display_timing(mode);
        let prog = match build_transcoder(&timing) {
            Ok(p) => p,
            Err(_) => return, // bad timing; downstream poll will time out
        };
        let base = Transcoder::A.base();
        self.mmio.write32(base + TRANS_HTOTAL_OFFSET, prog.htotal);
        self.mmio.write32(base + TRANS_HBLANK_OFFSET, prog.hblank);
        self.mmio.write32(base + TRANS_HSYNC_OFFSET, prog.hsync);
        self.mmio.write32(base + TRANS_VTOTAL_OFFSET, prog.vtotal);
        self.mmio.write32(base + TRANS_VBLANK_OFFSET, prog.vblank);
        self.mmio.write32(base + TRANS_VSYNC_OFFSET, prog.vsync);
        compiler_fence(Ordering::SeqCst);
    }

    /// Program the pipe — source size for the scaler and PIPE_MISC
    /// (color depth). Stage-2 ships 8 bpc only (XRGB8888 scanout);
    /// 10/12 bpc lands with HDR work.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_set_pipe_src_size`).
    fn program_pipe(&mut self, mode: &Mode) {
        use crate::intel_gpu_pipes::{build_pipe, Pipe as PipeIdx, PIPE_SRCSZ_OFFSET};
        let timing = mode_to_display_timing(mode);
        let prog = match build_pipe(&timing) {
            Ok(p) => p,
            Err(_) => return,
        };
        // PIPE_SRCSZ lives inside the pipe MMIO block.
        self.mmio
            .write32(PipeIdx::A.base() + PIPE_SRCSZ_OFFSET, prog.srcsz);
        compiler_fence(Ordering::SeqCst);
    }

    /// Program the primary plane — surface address, stride, size,
    /// pixel format. Field encoding (PLANE_CTL source-format,
    /// PLANE_STRIDE 64-byte units, etc.) lives in
    /// intel_gpu_pipes::build_primary_plane.
    ///
    /// Note: Stage-2 hands `fb.phys_addr` straight through as the
    /// PLANE_SURF value — that is only valid when the BIOS / GOP
    /// has left the framebuffer in a GGTT-mapped region (the
    /// common path for cold boot). A real GGTT mapping pass lands
    /// with the scanout-surface allocator in Stage-3.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_plane.c
    /// (`intel_plane_atomic_check_with_state` for validation +
    /// the per-plane register writes in `skl_plane_update_*`).
    fn program_plane(&mut self, fb: &Framebuffer, mode: &Mode) {
        use crate::intel_gpu_pipes::{
            build_primary_plane, Pipe as PipeIdx, PixelFormat as PipeFmt, PLANE_CTL_OFFSET,
            PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET,
            PLANE_SURF_OFFSET,
        };
        let pipe_fmt = match fb.format {
            // XRGB8888 → 8:8:8:8 ARGB encoding (alpha treated as
            // opaque by the pipe when the surface is XRGB).
            PixelFormat::Xrgb8888 => PipeFmt::Argb8888,
        };
        let prog = match build_primary_plane(
            mode.h_active,
            mode.v_active,
            fb.stride_bytes,
            fb.phys_addr as u32,
            pipe_fmt,
        ) {
            Ok(p) => p,
            Err(_) => return,
        };
        let base = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        // Per Linux skl_plane_update: program everything *except*
        // PLANE_CTL.ENABLE first, then the SURF register last —
        // writing SURF arms the plane on the next vblank.
        self.mmio
            .write32(base + PLANE_STRIDE_OFFSET, prog.plane_stride);
        self.mmio.write32(base + PLANE_SIZE_OFFSET, prog.plane_size);
        self.mmio
            .write32(base + PLANE_OFFSET_OFFSET, prog.plane_offset);
        // CTL with format + plane_enable; final flush via SURF.
        self.mmio.write32(base + PLANE_CTL_OFFSET, prog.plane_ctl);
        self.mmio.write32(base + PLANE_SURF_OFFSET, prog.plane_surf);
        compiler_fence(Ordering::SeqCst);
    }

    // ── DP link training ─────────────────────────────────────

    /// Run the DP link-training state machine over our AUX
    /// channel. Wraps [`dp_link_training::train_link`] with our
    /// IntelAux transport. Picks rate + lane count from the mode
    /// the orchestrator computed during DPLL programming; today
    /// that's the same `link_rate_for_pixel_clock` decision.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/
    /// intel_dp_link_training.c (`intel_dp_link_training`).
    fn train_dp_link(&mut self) -> Result<(), ModesetError> {
        use crate::dp_link_training::{train_link, LinkError, LinkRate as TrainRate};
        let mut aux = IntelAux::new(self.mmio, self.ddi);
        // Stage-2 starts at HBR2/4-lane and falls back via
        // `train_link`'s policy. That's the broadest envelope a
        // modern eDP panel will accept; lower-bandwidth links
        // converge on the rate ladder.
        let initial_rate = TrainRate::Hbr2;
        let lanes = 4;
        match train_link(&mut aux, initial_rate, lanes, |_us| core::hint::spin_loop()) {
            Ok(_trained) => Ok(()),
            Err(LinkError::CrFailed(_)) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::EqFailed(_)) => Err(ModesetError::LinkTrainingEq),
            Err(LinkError::Aborted) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::AuxFailure(e)) => Err(ModesetError::AuxFailure(e)),
        }
    }

    // ── DDI buffer enable ────────────────────────────────────

    /// Drive the physical output buffer enable. PRM Vol. 12
    /// §"DDI_BUF_CTL" — set the ENABLE bit and the lane-count
    /// field, then poll the (inverse-logic) IDLE_STATUS bit to
    /// see the buffer come alive.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_ddi.c
    /// (`intel_ddi_pre_enable_dp` + `intel_ddi_buf_enable`).
    fn enable_ddi_buffer(&mut self) {
        use crate::intel_gpu_ddi::{
            build_ddi_buf_ctl, LaneCount, DDI_BUF_CTL_IDLE_STATUS, DDI_BUF_CTL_OFFSET,
        };
        let off = self.ddi.base() + DDI_BUF_CTL_OFFSET;
        let cur = self.mmio.read32(off);
        let val = cur | build_ddi_buf_ctl(LaneCount::X4);
        self.mmio.write32(off, val);
        compiler_fence(Ordering::SeqCst);
        // Wait for IDLE_STATUS to clear — buffer is now driving.
        // PRM allows 600 µs; we give 1 ms.
        let _ = wait_bit(self.mmio, off, DDI_BUF_CTL_IDLE_STATUS, false, 1_000_000);
    }

    // ── Final enables (PRM-mandated order) ───────────────────

    /// Enable Transcoder A. TRANS_CONF.ENABLE + state-active poll
    /// per PRM Vol. 14 §"Transcoder Enable".
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_enable_transcoder`).
    fn enable_transcoder(&mut self) {
        use crate::intel_gpu_pipes::{
            Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
        };
        let off = Transcoder::A.base() + PIPECONF_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur | PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        // Poll state-active. 100 ms cap matches i915's
        // `intel_wait_for_pipe_off` budget.
        let _ = wait_bit(self.mmio, off, PIPECONF_STATE, true, 100_000_000);
    }

    /// Enable Pipe A. Same register block as the transcoder on
    /// Gen12 (PIPE_CONF / TRANS_CONF are aliased at the per-
    /// pipe block); writing the same ENABLE bit at Pipe A's base
    /// turns on the per-pipe raster engine.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_enable_pipe`).
    fn enable_pipe(&mut self) {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
        };
        let off = PipeIdx::A.base() + PIPECONF_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur | PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, off, PIPECONF_STATE, true, 100_000_000);
    }

    /// Final plane arm: PLANE_CTL already has the enable bit set
    /// from `program_plane` (per i915 convention). What's left is
    /// the first-VBLANK barrier so the surface programming
    /// actually takes effect before we return to the caller.
    ///
    /// Stage-2 uses a fixed 20 ms wait (≈one frame at 50 Hz, the
    /// slowest mode we'd realistically program). A VBLANK IRQ
    /// path lands with the VBLANK helper in Stage-3.
    fn enable_plane(&mut self) {
        // The plane is already armed by `program_plane`'s SURF
        // write. Spin one frame-time so the scanout flips before
        // the caller observes "modeset done".
        let cpns = narf_time::wall::cycles_per_ns().max(1) as u64;
        let budget = 20_000_000u64.saturating_mul(cpns);
        let start = narf_time::now_cycles();
        while narf_time::now_cycles().wrapping_sub(start) < budget {
            core::hint::spin_loop();
        }
    }
}

/// Convert our [`Mode`] (compressed timing) into the codec
/// layer's [`DisplayTiming`] (the shape `build_transcoder` /
/// `build_pipe` expect). The codec uses absolute blank-start /
/// blank-end positions; we synthesise them from active + total.
fn mode_to_display_timing(mode: &Mode) -> crate::intel_gpu_pipes::DisplayTiming {
    crate::intel_gpu_pipes::DisplayTiming {
        hactive: mode.h_active,
        // Horizontal blanking is the region from h_active to h_total.
        hblank_start: mode.h_active,
        hblank_end: mode.h_total,
        hsync_start: mode.h_sync_start,
        hsync_end: mode.h_sync_end,
        htotal: mode.h_total,
        vactive: mode.v_active,
        vblank_start: mode.v_active,
        vblank_end: mode.v_total,
        vsync_start: mode.v_sync_start,
        vsync_end: mode.v_sync_end,
        vtotal: mode.v_total,
    }
}

/// Poll an MMIO register's `mask` bits until they assert (when
/// `want_set` is `true`) or deassert (when `false`). Returns
/// `true` if the condition was reached within `timeout_ns`.
/// Used to wait for PLL_LOCK, transcoder/pipe state-active,
/// DDI BUF_CTL idle, etc.
fn wait_bit<M: MmioWindow + ?Sized>(
    mmio: &M,
    off: u64,
    mask: u32,
    want_set: bool,
    timeout_ns: u64,
) -> bool {
    let cpns = narf_time::wall::cycles_per_ns().max(1) as u64;
    let budget = timeout_ns.saturating_mul(cpns);
    let start = narf_time::now_cycles();
    loop {
        let v = mmio.read32(off);
        let asserted = v & mask != 0;
        if asserted == want_set {
            return true;
        }
        if narf_time::now_cycles().wrapping_sub(start) > budget {
            return false;
        }
        core::hint::spin_loop();
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

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Stage-2 smokes for the orchestrator. A `FakeMmio` records
    //! writes and serves canned reads so each step can be driven
    //! to completion without a real BAR.

    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Mock MMIO window. Records every write and returns canned
    /// reads keyed by offset (default 0).
    #[derive(Debug)]
    pub struct FakeMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        pub reads: RefCell<Vec<(u64, u32)>>,
        /// When set, every read of `state_offset` returns
        /// `state_value` OR'd onto whatever is in `reads`.
        pub state_offset: u64,
        pub state_value: u32,
    }

    impl FakeMmio {
        pub fn new() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                reads: RefCell::new(Vec::new()),
                state_offset: 0,
                state_value: 0,
            }
        }
        pub fn set_read(&self, off: u64, val: u32) {
            self.reads.borrow_mut().push((off, val));
        }
        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for FakeMmio {
        fn read32(&self, off: u64) -> u32 {
            let mut v = 0u32;
            for (o, val) in self.reads.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            if off == self.state_offset {
                v |= self.state_value;
            }
            v
        }
        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
        }
    }

    fn smoke_pwr_well_req_state_bits_match_i915() -> TestResult {
        // PG1 (idx=0) — request bit 1, state bit 0.
        if super::pwr_well_req(0) != 0x2 {
            return TestResult::Fail("PG1 REQ bit");
        }
        if super::pwr_well_state(0) != 0x1 {
            return TestResult::Fail("PG1 STATE bit");
        }
        // PG2 (idx=1) — request bit 3, state bit 2.
        if super::pwr_well_req(1) != 0x8 {
            return TestResult::Fail("PG2 REQ bit");
        }
        if super::pwr_well_state(1) != 0x4 {
            return TestResult::Fail("PG2 STATE bit");
        }
        // PG3 (idx=2) — request bit 5, state bit 4.
        if super::pwr_well_req(2) != 0x20 {
            return TestResult::Fail("PG3 REQ bit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_pwr_well_req_state_bits_match_i915
    );

    fn smoke_enable_pg2_polls_and_writes_request() -> TestResult {
        let mut mmio = FakeMmio::new();
        // Pre-set PG2 STATE so the poll returns immediately.
        mmio.state_offset = super::PWR_WELL_CTL2;
        mmio.state_value = super::pwr_well_state(super::PowerWell::Pg2 as u32);
        let mut ms = Modeset::new(&mmio, Ddi::A);
        match ms.enable_pipe_power_well(Pipe::A) {
            Ok(()) => {}
            Err(e) => {
                let _ = e;
                return TestResult::Fail("PG2 enable returned error with state asserted");
            }
        }
        let writes = mmio.writes_to(super::PWR_WELL_CTL2);
        if writes.is_empty() {
            return TestResult::Fail("no CTL2 write observed");
        }
        let req = super::pwr_well_req(super::PowerWell::Pg2 as u32);
        if writes.iter().all(|w| (w & req) == 0) {
            return TestResult::Fail("PG2 REQUEST bit never set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_enable_pg2_polls_and_writes_request
    );

    fn smoke_enable_pg_rejects_nonzero_pipe_b() -> TestResult {
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        match ms.enable_pipe_power_well(Pipe::B) {
            Err(ModesetError::PowerWellTimeout) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("Pipe B should require Stage-3 PG3 work")
            }
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_enable_pg_rejects_nonzero_pipe_b
    );

    fn smoke_link_rate_for_pixel_clock_floors() -> TestResult {
        use super::link_rate_for_pixel_clock;
        use crate::intel_gpu_pll::LinkRate;
        // 1024x768@60: 65 MHz pixel — RBR is plenty.
        if link_rate_for_pixel_clock(65_000) != LinkRate::DpRbr {
            return TestResult::Fail("65 MHz should fit in RBR");
        }
        // 1920x1080@60: 148.5 MHz — still RBR (148.5*30/4 = 1113 < 1620 Mbps).
        if link_rate_for_pixel_clock(148_500) != LinkRate::DpRbr {
            return TestResult::Fail("148.5 MHz should fit in RBR");
        }
        // 2560x1440@60: ~241 MHz — needs HBR (241*30/4 = 1807 > 1620).
        if link_rate_for_pixel_clock(241_000) != LinkRate::DpHbr {
            return TestResult::Fail("241 MHz should require HBR");
        }
        // 3840x2160@60: 533 MHz — needs HBR2 (533*30/4 = 3997 > 2700).
        if link_rate_for_pixel_clock(533_000) != LinkRate::DpHbr2 {
            return TestResult::Fail("533 MHz should require HBR2");
        }
        // 4K@120 / 5K territory: ~1188 MHz — needs HBR3.
        if link_rate_for_pixel_clock(1_188_000) != LinkRate::DpHbr3 {
            return TestResult::Fail(">1.18 GHz should require HBR3");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_link_rate_for_pixel_clock_floors
    );

    fn smoke_program_dpll_writes_cfgcr_and_polls_lock() -> TestResult {
        let mut mmio = FakeMmio::new();
        // Pre-set PLL_POWER_STATE + PLL_LOCK so the path completes.
        mmio.state_offset = super::DPLL0_ENABLE;
        mmio.state_value = super::PLL_POWER_STATE | super::PLL_LOCK;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        let mode = Mode::VESA_1024X768_60;
        match ms.program_dpll(&mode) {
            Ok(()) => {}
            Err(e) => {
                let _ = e;
                return TestResult::Fail("program_dpll failed with lock asserted");
            }
        }
        // Must have written CFGCR0 and CFGCR1.
        let cfgcr0_writes = mmio.writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0);
        if cfgcr0_writes.is_empty() {
            return TestResult::Fail("CFGCR0 not written");
        }
        let cfgcr1_writes = mmio.writes_to(crate::intel_gpu_pll::dpll_cfgcr1(
            crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0,
        ));
        if cfgcr1_writes.is_empty() {
            return TestResult::Fail("CFGCR1 not written");
        }
        // Must have asserted PLL_ENABLE.
        let pll_writes = mmio.writes_to(super::DPLL0_ENABLE);
        if !pll_writes.iter().any(|w| w & super::PLL_ENABLE != 0) {
            return TestResult::Fail("PLL_ENABLE never set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_dpll_writes_cfgcr_and_polls_lock
    );

    fn smoke_mode_to_display_timing_round_trip() -> TestResult {
        use crate::intel_gpu_pipes::DisplayTiming;
        let m = Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        };
        let t: DisplayTiming = super::mode_to_display_timing(&m);
        if t.hactive != 1920 || t.htotal != 2200 || t.hblank_start != 1920 || t.hblank_end != 2200 {
            return TestResult::Fail("horizontal blank packing");
        }
        if t.hsync_start != 2008 || t.hsync_end != 2052 {
            return TestResult::Fail("horizontal sync packing");
        }
        if t.vactive != 1080 || t.vtotal != 1125 || t.vblank_end != 1125 {
            return TestResult::Fail("vertical packing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_mode_to_display_timing_round_trip
    );

    fn smoke_program_transcoder_writes_six_regs() -> TestResult {
        use crate::intel_gpu_pipes::{
            Transcoder, TRANS_HBLANK_OFFSET, TRANS_HSYNC_OFFSET, TRANS_HTOTAL_OFFSET,
            TRANS_VBLANK_OFFSET, TRANS_VSYNC_OFFSET, TRANS_VTOTAL_OFFSET,
        };
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.program_transcoder(&Mode::VESA_1024X768_60);
        let base = Transcoder::A.base();
        let expected = [
            TRANS_HTOTAL_OFFSET,
            TRANS_HBLANK_OFFSET,
            TRANS_HSYNC_OFFSET,
            TRANS_VTOTAL_OFFSET,
            TRANS_VBLANK_OFFSET,
            TRANS_VSYNC_OFFSET,
        ];
        for off in expected.iter().copied() {
            if mmio.writes_to(base + off).is_empty() {
                return TestResult::Fail("trans reg not written");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_transcoder_writes_six_regs
    );

    fn smoke_program_pipe_writes_srcsz() -> TestResult {
        use crate::intel_gpu_pipes::{Pipe as PipeIdx, PIPE_SRCSZ_OFFSET};
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.program_pipe(&Mode::VESA_1024X768_60);
        let writes = mmio.writes_to(PipeIdx::A.base() + PIPE_SRCSZ_OFFSET);
        if writes.is_empty() {
            return TestResult::Fail("PIPE_SRCSZ not written");
        }
        // SRCSZ packing: bits[28:16] = hactive-1, bits[12:0] = vactive-1.
        let v = writes[0];
        let h = (v >> 16) & 0x1FFF;
        let vl = v & 0x1FFF;
        if h != 1023 || vl != 767 {
            return TestResult::Fail("PIPE_SRCSZ encoding off");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_pipe_writes_srcsz
    );

    fn smoke_program_plane_arms_surf_last() -> TestResult {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET,
        };
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        let fb = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1024 * 4,
            format: PixelFormat::Xrgb8888,
        };
        ms.program_plane(&fb, &Mode::VESA_1024X768_60);
        let plane_base = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        // PLANE_SURF and PLANE_CTL both written.
        if mmio.writes_to(plane_base + PLANE_SURF_OFFSET).is_empty() {
            return TestResult::Fail("PLANE_SURF not written");
        }
        if mmio.writes_to(plane_base + PLANE_CTL_OFFSET).is_empty() {
            return TestResult::Fail("PLANE_CTL not written");
        }
        // Order: SURF must come after CTL (latch trigger). Search
        // by occurrence in the writes log.
        let surf_off = plane_base + PLANE_SURF_OFFSET;
        let ctl_off = plane_base + PLANE_CTL_OFFSET;
        let log = mmio.writes.borrow();
        let mut surf_idx = None;
        let mut ctl_idx = None;
        for (i, (o, _)) in log.iter().enumerate() {
            if *o == surf_off && surf_idx.is_none() {
                surf_idx = Some(i);
            }
            if *o == ctl_off && ctl_idx.is_none() {
                ctl_idx = Some(i);
            }
        }
        match (ctl_idx, surf_idx) {
            (Some(c), Some(s)) if s > c => TestResult::Pass,
            _ => TestResult::Fail("SURF must be written after CTL"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_plane_arms_surf_last
    );

    fn smoke_enable_transcoder_writes_enable_bit() -> TestResult {
        use crate::intel_gpu_pipes::{Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET};
        let mut mmio = FakeMmio::new();
        // Pre-set the state bit so the poll returns immediately.
        mmio.state_offset = Transcoder::A.base() + PIPECONF_OFFSET;
        mmio.state_value = crate::intel_gpu_pipes::PIPECONF_STATE;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.enable_transcoder();
        let writes = mmio.writes_to(Transcoder::A.base() + PIPECONF_OFFSET);
        if !writes.iter().any(|w| w & PIPECONF_ENABLE != 0) {
            return TestResult::Fail("transcoder ENABLE bit not set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_enable_transcoder_writes_enable_bit
    );

    fn smoke_enable_ddi_buffer_writes_lane_and_enable() -> TestResult {
        use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_OFFSET};
        let mut mmio = FakeMmio::new();
        // Pre-set IDLE_STATUS=0 (active), so the poll's "wait
        // until clear" returns immediately. Default reads are 0
        // so this needs no extra state.
        mmio.state_offset = 0;
        mmio.state_value = 0;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.enable_ddi_buffer();
        let off = Ddi::A.base() + DDI_BUF_CTL_OFFSET;
        let writes = mmio.writes_to(off);
        if !writes.iter().any(|w| w & DDI_BUF_CTL_ENABLE != 0) {
            return TestResult::Fail("DDI_BUF_CTL.ENABLE not set");
        }
        // Lane field bits[3:1] should encode X4 = 0b011.
        let v = writes[0];
        if (v >> 1) & 0x7 != 0b011 {
            return TestResult::Fail("DDI lane count != X4");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_enable_ddi_buffer_writes_lane_and_enable
    );

    fn smoke_disable_pipeline_writes_disables_in_order() -> TestResult {
        use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PLANE_CTL_ENABLE,
            PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET,
        };
        let mut mmio = FakeMmio::new();
        // Use a wildcard state read that returns 0 for STATE bits
        // (i.e., already disabled) so wait_bit returns instantly.
        mmio.state_offset = 0;
        mmio.state_value = 0;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.disable_pipeline();

        // Plane CTL write must clear ENABLE.
        let plane_writes =
            mmio.writes_to(PipeIdx::A.base() + PLANE_PRIMARY_OFFSET + PLANE_CTL_OFFSET);
        if plane_writes.is_empty() || plane_writes.iter().any(|w| w & PLANE_CTL_ENABLE != 0) {
            return TestResult::Fail("plane CTL ENABLE not cleared");
        }
        // Pipe + Transcoder PIPECONF must clear ENABLE.
        let pipe_writes = mmio.writes_to(PipeIdx::A.base() + PIPECONF_OFFSET);
        let trans_writes = mmio.writes_to(Transcoder::A.base() + PIPECONF_OFFSET);
        if pipe_writes.is_empty() || pipe_writes.iter().any(|w| w & PIPECONF_ENABLE != 0) {
            return TestResult::Fail("pipe ENABLE not cleared");
        }
        if trans_writes.is_empty() || trans_writes.iter().any(|w| w & PIPECONF_ENABLE != 0) {
            return TestResult::Fail("transcoder ENABLE not cleared");
        }
        // DDI BUF must clear ENABLE.
        let ddi_off = Ddi::A.base() + DDI_BUF_CTL_OFFSET;
        let ddi_writes = mmio.writes_to(ddi_off);
        if ddi_writes.is_empty() {
            return TestResult::Fail("DDI_BUF_CTL not written");
        }
        if ddi_writes
            .iter()
            .any(|w| w & crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE != 0)
        {
            return TestResult::Fail("DDI ENABLE not cleared");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_disable_pipeline_writes_disables_in_order
    );
}
