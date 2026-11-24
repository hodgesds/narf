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
//!   required for any display work), plus the per-pipe wells:
//!   Pipe A under PG2, Pipe B under PG3, Pipe C under PG4 (the
//!   ICL+ power-well domain assignment in i915
//!   `display/intel_display_power_well.c`). Multi-pipe support
//!   (#1017) enables the well for the orchestrator's own pipe.
//! - **eDP-only modeset** — laptop panels. External DP is the
//!   same path with a few additional hotplug detection steps.
//!   HDMI has its own entry point ([`Modeset::modeset_hdmi`],
//!   #1019): a WRPLL DPLL select for the TMDS character clock
//!   and no DP link training.
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
//! - HDR metadata / wide-gamut colorspace
//! - Cursor + overlay + sprite planes
//! - DMC firmware loading (required for runtime PM, not boot
//!   modeset)
//!
//! VRR (Variable Refresh Rate) is NOT out of scope any more: the
//! foundation landed in #1768 (honest sink capability via
//! `intel_gpu_vrr::sink_vrr_range`, `vrr_enabled` in atomic
//! `CrtcState` forcing a modeset on toggle, and per-modeset timing
//! recompute from the committed mode + sink range). What remains in
//! later lanes is the sequencing (modeset/push/disable, #1769),
//! DPCD+PSR (#1770), CMRR (#1771) and readback (#1772).
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

use crate::dp_aux::AuxError;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_pipes::Pipe;
use crate::intel_gpu_pll::{combo_coeffs, decode_refclk_family, encode_cfgcr0, LinkRate, DSSM};

#[path = "intel_gpu_dp_training.rs"]
pub(crate) mod training;

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
    Pg3 = 2,
    Pg4 = 3,
}

/// `DP_TP_CTL` offset from the DDI base on Gen9 (SKL) and
/// Gen11 (ICL): the register is port-based, not
/// transcoder-based — `_DP_TP_CTL_A` = 0x64040. The same
/// value as `intel_gpu_gen12_combo_phy::DP_TP_CTL_OFFSET_GEN11`;
/// kept as this module's own copy because the combo-PHY
/// module's is private (the Gen11 MG PHY keeps its own copy
/// the same way).
const GEN9_DP_TP_CTL_OFFSET: u64 = 0x40;

/// `PIPE_MISC` (pipe base + 0x30) YCbCr bits: `PIPE_MISC_YUV420_ENABLE`
/// (27), `PIPE_MISC_YUV420_MODE_FULL_BLEND` (26),
/// `PIPE_MISC_OUTPUT_COLORSPACE_YUV` (11).
const PIPE_MISC_YUV420_ENABLE: u32 = 1 << 27;
const PIPE_MISC_YUV420_MODE_FULL_BLEND: u32 = 1 << 26;
const PIPE_MISC_OUTPUT_COLORSPACE_YUV: u32 = 1 << 11;
const PIPE_MISC_YUV_MASK: u32 =
    PIPE_MISC_YUV420_ENABLE | PIPE_MISC_YUV420_MODE_FULL_BLEND | PIPE_MISC_OUTPUT_COLORSPACE_YUV;
/// `PIPE_CSC_MODE(pipe)` (`_PIPE_A_CSC_MODE` 0x49028, pipe stride 0x100)
/// and `ICL_OUTPUT_CSC_ENABLE` (30).
const PIPE_CSC_MODE: u64 = 0x49028;
const ICL_OUTPUT_CSC_ENABLE: u32 = 1 << 30;
/// `PIPE_CSC_OUTPUT_COEFF_RY_GY(pipe)` (`_PIPE_A_OUTPUT_CSC_COEFF_RY_GY`
/// 0x49050); BY/RU_GU/BU/RV_GV/BV follow at +4 each, the pre-offsets at
/// +0x18/+0x1c/+0x20 and the post-offsets at +0x24/+0x28/+0x2c.
const PIPE_CSC_OUTPUT_COEFF_RY_GY: u64 = 0x49050;
const PIPE_COLOR_STRIDE: u64 = 0x100;
const GEN9_DP_TP_CTL_ENABLE: u32 = 1 << 31;
const GEN9_DP_TP_CTL_ENHANCED_FRAME_ENABLE: u32 = 1 << 18;
const GEN9_DP_TP_CTL_LINK_TRAIN_MASK: u32 = 0x7 << 8;
const GEN9_DP_TP_CTL_SCRAMBLE_DISABLE: u32 = 1 << 7;

/// `DDI_BUF_CTL` emphasis field (`DDI_BUF_EMP_MASK`, bits
/// 27:24): the `DDI_BUF_TRANS_SELECT(level)` the SKL
/// per-iteration level program writes (Linux
/// `intel_display_regs.h:2608-2609`).
const GEN9_DDI_BUF_EMP_MASK: u32 = 0xF << 24;

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
const DPLL2_ENABLE: u64 = 0x4_6018;
const PLL_ENABLE: u32 = 1 << 31;
const PLL_LOCK: u32 = 1 << 30;
const PLL_POWER_ENABLE: u32 = 1 << 27;
const PLL_POWER_STATE: u32 = 1 << 26;

/// The DPLL enable register for a Combo PHY DPLL index: the
/// block is a plain 4-byte stride from DPLL0 (i915
/// `_DPLL0_ENABLE` / `_DPLL1_ENABLE` / `_DPLL2_ENABLE`).
const fn dpll_enable_off(dpll_idx: u32) -> u64 {
    match dpll_idx {
        0 => DPLL0_ENABLE,
        1 => DPLL1_ENABLE,
        _ => DPLL2_ENABLE,
    }
}

/// Combo PHY DDIs A/B/C use DPLL 0/1/2. Type-C dispatches through
/// intel_gpu_gen12_tc before any combo-PLL programming or routing.
const fn dpll_index_for(ddi: Ddi) -> u32 {
    match ddi {
        Ddi::A => 0,
        Ddi::B => 1,
        Ddi::C => 2,
        _ => 0,
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
    /// Page-aligned GGTT byte offset of the surface, as consumed by
    /// PLANE_SURF. Despite the historical field name, this is not a
    /// host-physical address; the caller installs the GGTT mapping.
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
    /// No display programming sequence exists for this generation.
    UnsupportedGeneration,
    /// EDID readback failed AND no fallback mode was provided.
    EdidUnavailable,
    /// AUX transaction failed during initialization (e.g. panel
    /// asleep, no DP link).
    AuxFailure(AuxError),
    /// DPLL didn't lock within the spec-mandated 1 ms window.
    PllLockTimeout,
    /// The Gen12 CDCLK sequence (`intel_gpu_gen12_cdclk`)
    /// could not establish the floor clock: the pcode
    /// pre-notify was refused, the CDCLK PLL never locked, or
    /// the programmed clock did not read back. A pre-notify
    /// refusal leaves the previous clock untouched; a later
    /// failure may leave it mid-change, so the modeset stops.
    CdclkUnavailable,
    /// The probe-time Gen9 DMC load did not complete, so the
    /// display modeset refuses (the Q5 default: DMC is
    /// REQUIRED on Gen9, mirroring Gen12). The probe itself
    /// continues — GT / execlists still bind — and only the
    /// display modeset refuses, until a DMC load completes.
    DmcUnavailable,
    /// DP link training failed at clock-recovery phase.
    LinkTrainingCr,
    /// DP link training failed at channel-equalization phase.
    LinkTrainingEq,
    /// Power well failed to enable within its grant window.
    PowerWellTimeout,
    /// A DBUF slice never granted power after its
    /// `DBUF_CTL.POWER_REQUEST` — the watermark / DDB
    /// programming would point at unpowered SRAM.
    DbufPowerTimeout,
    /// The mode's TMDS character clock has no WRPLL solution
    /// (HDMI path, #1019): no divider lands the Combo-PHY DCO
    /// inside its window for this clock.
    HdmiClockUnsupported,
    /// Xe-LPG PHY message-bus failure (#1016): the C10/C20 PHY
    /// answered with its error bit set, or with an ACK that does
    /// not match the transaction (e.g. a wrong-generation PHY
    /// behind the port). The Gen12 path never produces this.
    PhyBusFailure,
    /// Invalid plane geometry, pitch or GGTT range. Linear pitch must
    /// be nonzero, 64-byte aligned and cover the active row.
    InvalidFramebuffer,
    /// Owned TGL+ RGB color setup could not prove Pipe A disabled, or
    /// its bypass register writes did not read back. Leave the pipe off.
    ColorPipelineUnavailable,
    /// A fixed display resource request or pipe-off repartition failed.
    DisplayResourceUnavailable,
    /// Local pipe/transcoder/DDI stop was not observed; retain all leases.
    PipelineStopUnavailable,
    /// The eDP panel power sequencer never reached the requested on or off
    /// state (`intel_pps.c::wait_panel_on` / `wait_panel_off`).
    PanelPowerTimeout,
    /// Link training failed at every configuration Linux's fallback
    /// (`intel_dp_get_link_train_fallback_values`) reaches.
    LinkTrainingExhausted,
    /// The selected DP link cannot carry the uncompressed RGB stream.
    LinkBandwidthInsufficient,
    /// MTL source enable, primary image or a fresh common frame was not observed.
    /// This is not evidence of complete sink training or visible pixels.
    PipelineEnableUnavailable,
    /// The MTL eDP panel's mode needs a DSC configuration Linux would not
    /// choose or this driver does not qualify; nothing was stopped.
    Dsc(crate::intel_gpu_xelpg_dsc::DscRefusal),
}

/// A negotiated link configuration handed to
/// [`Modeset::modeset_with_plan`]: the (rate, lanes) the shared
/// link-training core's negotiation picked for the stream
/// (`dp_link_training::NegotiatedLink`, #1092). The rate is the
/// training core's vendor-neutral `LinkRate`; conversion to the
/// PLL module's rate type happens inside the orchestrator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkPlan {
    /// Negotiated starting rate for training.
    pub rate: crate::dp_link_training::LinkRate,
    /// Negotiated lane count (1, 2, or 4).
    pub lanes: u8,
}

impl LinkPlan {
    fn check_rgb8_capacity(self, mode: &Mode) -> Result<(), ModesetError> {
        let demand = crate::dp_link_training::stream_demand_kbps(mode.pixel_clock_khz, 24);
        if self.rate.payload_kbps(self.lanes) < demand {
            return Err(ModesetError::LinkBandwidthInsufficient);
        }
        Ok(())
    }
}

/// Convert a training-core link rate to the PLL module's rate
/// type (the two enums encode the same four DP rates).
pub fn to_pll_rate(rate: crate::dp_link_training::LinkRate) -> LinkRate {
    use crate::dp_link_training::LinkRate as TrainRate;
    match rate {
        TrainRate::Rbr => LinkRate::DpRbr,
        TrainRate::Hbr => LinkRate::DpHbr,
        TrainRate::Hbr2 => LinkRate::DpHbr2,
        TrainRate::Hbr3 => LinkRate::DpHbr3,
    }
}

/// The link rate a run without a negotiated plan (the legacy panel
/// entry and the fixed-mode restore) starts training at, and so the
/// rate its link clock is first programmed for. The training
/// callbacks retune the clock when the fallback ladder steps down.
const UNPLANNED_START_RATE: crate::dp_link_training::LinkRate =
    crate::dp_link_training::LinkRate::Hbr2;

/// How the link-training step of a modeset run is satisfied.
/// The legacy eDP-shaped entry trains and discards the result
/// (historical behaviour); the plan entries train at the
/// negotiated configuration and consume the outcome; an MST
/// secondary stream's link was already trained by the primary
/// stream on the same DDI, so its run programs from the trained
/// configuration and must not touch the shared link blocks
/// (DPLL, DPCLKA routing, BUF_TRANS, training, DDI buffer).
enum LinkStep {
    Legacy,
    FixedMode,
    Plan(LinkPlan),
    Trained(crate::dp_link_training::TrainedLink),
}

/// Modeset orchestrator for one CRTC (= pipe + transcoder + DDI).
/// Stateless — every call walks the full sequence on the assumption
/// the caller has already serialized concurrent modesets at a
/// higher layer (today: nothing else touches Intel display).
///
/// Before #1017 the orchestrator was hardwired to Pipe A /
/// Transcoder A / DPLL0: an internal panel and an external
/// display could never be live at once, and every session —
/// including the DP Alt-Mode bridge on Type-C DDIs — funnelled
/// into the same pipe. [`Modeset::new`] keeps that Pipe A shape
/// exactly (every pre-existing caller and fixture is
/// byte-identical); [`Modeset::for_pipe`] binds the run to any
/// pipe, with ownership arbitrated by `intel_gpu_multipipe`.
pub struct Modeset<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    /// The physical port for this modeset (eDP is usually DDI A
    /// on Gen12 laptops).
    pub ddi: Ddi,
    /// The pipe (and, by the Gen12 same-index binding, the
    /// transcoder) this run programs.
    pipe: Pipe,
    /// Explicit DBUF share `(start_block, end_block)` for this
    /// pipe's primary plane, set by the multi-pipe coordinator
    /// when more than one pipe is active. `None` keeps the PRM
    /// pre-boot single-pipe programming.
    dbuf_share: Option<(u16, u16)>,
    gen12_family: Option<crate::intel_gpu_gt::Gen12Platform>,
    /// Gen11 platform when this run modesets an Ice Lake /
    /// Elkhart Lake / Jasper Lake part (Lane 5). Set by
    /// `modeset_display_family` from the chip; `None` on the
    /// Gen12 path. Drives the per-step Gen11 branches (ICL
    /// CDCLK / DPLL / watermarks / DDI tables, the Linux ICL
    /// step order, and the Gen11 plane admission).
    gen11_platform: Option<crate::intel_gpu_gt::Gen11Platform>,
    /// Gen9 platform when this run modesets a Skylake / Kaby
    /// Lake / Comet Lake part (Gen9 Lane 5). Set by
    /// `modeset_display_family` from the chip; `None` on every
    /// other path. Drives the per-step Gen9 branches (SKL
    /// CDCLK / DPLL / watermarks / DDI tables, the Linux SKL
    /// step order, and the SKL plane admission).
    gen9_platform: Option<crate::intel_gpu_gt::Gen9Platform>,
    /// The SKU family for the Gen9 table selection
    /// (`intel_gpu_gen9_ddi::sku_family_for_did`, from the
    /// chip's PCI device ID). Set alongside
    /// `gen9_platform` by `modeset_display_family`; `None`
    /// on every non-Gen9 path. The U/Y DDI tables cannot be
    /// resolved without it, so a Gen9 run without it fails
    /// closed.
    gen9_sku_family: Option<crate::intel_gpu_gen9_ddi::SkuFamily>,
    /// Tiger Lake UY (GT2) part — selects the UY HBR2
    /// combo-PHY table (`intel_gpu_gen12_combo_phy::is_tgl_uy`).
    /// Derived from the window's PCI device ID
    /// (`MmioWindow::tgl_uy`) at construction, so every path
    /// that builds a `Modeset` — panel, external DP, HDMI, MST
    /// — carries the real flag; `modeset_display_for_chip`
    /// re-asserts it from `ChipInfo` for the panel path.
    tgl_uy: bool,
    /// The built-in eDP panel's VBT bits — HOBL and low-vswing
    /// (`intel_gpu_gen12_combo_phy::VbtEdpSignal`), installed
    /// by probe and read by `modeset_display_family` (the
    /// `tgl_uy` precedent). Default false (the DP tables)
    /// everywhere else, including the external-DP path, which
    /// never drives the panel.
    edp_hobl: bool,
    edp_low_vswing: bool,
    tc_width: u8,
    /// Display-9 panel fitting (`set_gen9_panel_fit`): the pipe source
    /// size and the bound pipe scaler. `None` scans out at the mode size.
    gen9_panel_fit: Option<(u16, u16, crate::intel_gpu_xelpg_scaler::PipeScaler)>,
    /// The Gen11 combo PLL this run programmed for a port with no fixed
    /// one (EHL/JSL PORT_D, `arbitrate_combo_dpll`): clock routing and a
    /// mid-training retune use it.
    gen11_dpll: Option<crate::intel_gpu_gen11_dpll::IclDpllId>,
    /// HDMI to a DVI sink (`!has_hdmi_sink`): the transcoder runs
    /// `TRANS_DDI_MODE_SELECT_DVI`.
    hdmi_dvi: bool,
    /// HDMI bits per colour (8, 10 or 12): the port runs at the TMDS clock
    /// `pixel_clock * bpc / 8` with the matching `TRANS_DDI_BPC`.
    hdmi_bpc: u8,
    /// The HDMI entry drives YCbCr 4:2:0 (display 11/12).
    hdmi_ycbcr420: bool,
    /// Another pipe is live beside this run's, so the CDCLK it runs on
    /// cannot be reprogrammed here.
    shared_cdclk: bool,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for Modeset<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Modeset")
            .field("ddi", &self.ddi)
            .field("pipe", &self.pipe)
            .finish()
    }
}

impl<'a, M: MmioWindow + ?Sized> Modeset<'a, M> {
    /// Create an orchestrator for a port + MMIO window pair,
    /// bound to Pipe A (the historical single-pipe shape).
    pub fn new(mmio: &'a M, ddi: Ddi) -> Self {
        Self::for_pipe(mmio, ddi, Pipe::A)
    }

    /// Create an orchestrator bound to `pipe`. Pipe D is
    /// refused by the power-well step (Gen12 display here
    /// arbitrates pipes A–C; see `intel_gpu_multipipe`).
    pub fn for_pipe(mmio: &'a M, ddi: Ddi, pipe: Pipe) -> Self {
        Self {
            mmio,
            ddi,
            pipe,
            dbuf_share: None,
            gen12_family: mmio.gen12_display_family(),
            gen11_platform: None,
            gen9_platform: None,
            gen9_sku_family: None,
            tgl_uy: mmio.tgl_uy(),
            edp_hobl: false,
            edp_low_vswing: false,
            tc_width: 4,
            gen9_panel_fit: None,
            gen11_dpll: None,
            hdmi_dvi: false,
            hdmi_bpc: 8,
            hdmi_ycbcr420: false,
            shared_cdclk: false,
        }
    }

    /// Another pipe scans out beside this run's (the multi-pipe
    /// coordinator handed it a DBUF share). Linux raises CDCLK for a new
    /// pipe in an atomic commit that modesets every pipe the change
    /// touches (`intel_modeset_calc_cdclk`); this run does not own the
    /// other pipes, so a floor above the current CDCLK refuses with
    /// `CdclkUnavailable` at the CDCLK step instead of retuning the clock
    /// under a live pipe.
    pub fn set_shared_cdclk(&mut self, shared: bool) {
        self.shared_cdclk = shared;
    }

    /// The shared-CDCLK refusal: `current_khz` below this mode's floor.
    fn refuse_shared_cdclk(
        &self,
        current_khz: Option<u32>,
        mode: &Mode,
    ) -> Result<(), ModesetError> {
        let floor = mode.pixel_clock_khz.div_ceil(2);
        if self.shared_cdclk && current_khz.is_none_or(|khz| khz < floor) {
            return Err(ModesetError::CdclkUnavailable);
        }
        Ok(())
    }

    /// Drive the HDMI entry's link as YCbCr 4:2:0 (`sink_format ==
    /// INTEL_OUTPUT_FORMAT_YCBCR420`).
    pub(crate) fn set_hdmi_ycbcr420(&mut self, ycbcr420: bool) {
        self.hdmi_ycbcr420 = ycbcr420;
    }

    /// The HDMI entry's port depth (`intel_hdmi_compute_bpc`'s result);
    /// anything but 10 or 12 is 8.
    pub(crate) fn set_hdmi_bpc(&mut self, bpc: u8) {
        self.hdmi_bpc = if matches!(bpc, 10 | 12) { bpc } else { 8 };
    }

    /// Drive the HDMI entry's sink as DVI (`intel_ddi.c`: a TMDS output
    /// without `has_hdmi_sink` selects `TRANS_DDI_MODE_SELECT_DVI`).
    pub(crate) fn set_hdmi_dvi(&mut self, dvi: bool) {
        self.hdmi_dvi = dvi;
    }

    /// EHL/JSL PORT_D: a combo port (it drives PHY A) where every other
    /// DDI D is Type-C, so the `ddi >= D` Type-C dispatches skip it.
    fn is_gen11_combo_port_d(&self) -> bool {
        matches!(
            self.gen11_platform,
            Some(
                crate::intel_gpu_gt::Gen11Platform::ElkhartLake
                    | crate::intel_gpu_gt::Gen11Platform::JasperLake
            )
        ) && self.ddi == Ddi::D
    }

    /// Program the Gen11 combo PLL for `ddi` with `cfgcr0`/`cfgcr1`: the
    /// fixed `combo_dpll_id` assignment, or for EHL/JSL PORT_D the pool
    /// PLL `arbitrate_combo_dpll` picks. A shared PLL already runs the
    /// state and is left alone, as Linux enables a shared PLL once.
    fn enable_gen11_combo_pll(&mut self, cfgcr0: u32, cfgcr1: u32) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_dpll::{arbitrate_combo_dpll, combo_dpll_id, combo_pll_enable};
        let platform = self
            .gen11_platform
            .ok_or(ModesetError::UnsupportedGeneration)?;
        let (id, shared) = match combo_dpll_id(platform, self.ddi) {
            Some(id) => (id, false),
            None if self.is_gen11_combo_port_d() => {
                arbitrate_combo_dpll(self.mmio, platform, self.ddi, cfgcr0, cfgcr1)
                    .ok_or(ModesetError::DisplayResourceUnavailable)?
            }
            None => return Err(ModesetError::UnsupportedGeneration),
        };
        self.gen11_dpll = Some(id);
        if shared {
            return Ok(());
        }
        combo_pll_enable(self.mmio, id, cfgcr0, cfgcr1).map_err(|_| ModesetError::PllLockTimeout)
    }

    /// Fit a `src_w` x `src_h` pipe source to `native` (the panel's fixed
    /// mode, the one this run commits) with display 9's pipe scaler:
    /// Linux's `pch_panel_fitting` + `skl_update_scaler_crtc` +
    /// `skl_pfit_enable`. Gen9 runs only, after `set_gen9_platform`; a
    /// native-size source clears the fit.
    pub fn set_gen9_panel_fit(
        &mut self,
        native: &Mode,
        src_w: u16,
        src_h: u16,
        mode: crate::intel_gpu_xelpg_scaler::ScalingMode,
    ) -> Result<(), crate::intel_gpu_xelpg_scaler::ScalerRefusal> {
        if self.gen9_platform.is_none() {
            return Err(crate::intel_gpu_xelpg_scaler::ScalerRefusal::NoScaler);
        }
        self.gen9_panel_fit = crate::intel_gpu_xelpg_scaler::plan_display9(
            native,
            u32::from(src_w),
            u32::from(src_h),
            mode,
            crate::intel_gpu_xelpg_scaler::Filter::Default,
            self.pipe,
        )?
        .map(|scaler| (src_w, src_h, scaler));
        Ok(())
    }

    /// The pipe source and primary-plane size: the panel-fit source, or
    /// the mode's active area.
    fn pipe_source(&self, mode: &Mode) -> (u16, u16) {
        self.gen9_panel_fit
            .map_or((mode.h_active, mode.v_active), |(w, h, _)| (w, h))
    }

    /// Configure the run for `family`: the Gen12 family, or the Gen11 /
    /// Gen9 sub-platform (with the Gen9 SKU family) whose per-step
    /// branches the modeset takes.
    pub(crate) fn set_source_family(&mut self, family: crate::intel_gpu_aux::SourceFamily) {
        use crate::intel_gpu_aux::SourceFamily;
        match family {
            SourceFamily::Gen12(family) => self.set_gen12_family(family),
            SourceFamily::Gen11(platform) => {
                self.gen12_family = None;
                self.set_gen11_platform(platform);
            }
            SourceFamily::Gen9 { platform, sku } => {
                self.gen12_family = None;
                self.set_gen9_platform(platform);
                self.set_gen9_sku_family(sku);
            }
        }
    }

    pub(crate) fn set_gen12_family(&mut self, family: crate::intel_gpu_gt::Gen12Platform) {
        self.gen12_family = Some(family);
    }

    pub(crate) fn set_gen11_platform(&mut self, platform: crate::intel_gpu_gt::Gen11Platform) {
        self.gen11_platform = Some(platform);
    }

    pub(crate) fn set_gen9_platform(&mut self, platform: crate::intel_gpu_gt::Gen9Platform) {
        self.gen9_platform = Some(platform);
    }

    pub(crate) fn set_gen9_sku_family(&mut self, family: crate::intel_gpu_gen9_ddi::SkuFamily) {
        self.gen9_sku_family = Some(family);
    }

    /// Whether this run's DDI is a Type-C port: Gen12 DDI D
    /// and above (Dekel PHY), Gen11 IceLake DDI C and above
    /// (MG PHY, `intel_gpu_gen11_ddi::phy_for_port`).
    /// Elkhart/Jasper Lake have no TC ports. Gen9 has none
    /// either — SKL has no Type-C ports at all
    /// (`skl_display`: port mask A|B|C|D|E, all DP/HDMI/eDP)
    /// — so a Gen9 run is never a TC port. Type-C runs share
    /// one shape across generations: the port's own PLL + clock
    /// routing, training through the port's PHY (which enables
    /// the DDI buffer itself), and no post-training DPLL
    /// re-program or separate DDI-buffer enable.
    fn is_tc_port(&self) -> bool {
        if self.gen9_platform.is_some() {
            return false;
        }
        match self.gen11_platform {
            Some(platform) => {
                use crate::intel_gpu_gen11_ddi::{phy_for_port, Gen11Phy};
                matches!(phy_for_port(platform, self.ddi), Some(Gen11Phy::Mg { .. }))
            }
            None => self.ddi as u8 >= Ddi::D as u8,
        }
    }

    pub(crate) fn set_tgl_uy(&mut self, uy: bool) {
        self.tgl_uy = uy;
    }

    pub(crate) fn set_edp_hobl(&mut self, hobl: bool) {
        self.edp_hobl = hobl;
    }

    pub(crate) fn set_edp_low_vswing(&mut self, low_vswing: bool) {
        self.edp_low_vswing = low_vswing;
    }

    pub(crate) fn set_typec_width(&mut self, width: u8) {
        self.tc_width = width;
    }

    /// The pipe this run programs.
    pub fn pipe(&self) -> Pipe {
        self.pipe
    }

    /// The transcoder this run programs (same-index binding).
    /// Gen9 breaks the binding for the built-in panel: DDI A
    /// is the eDP port and its transcoder is the dedicated
    /// EDP transcoder (timing base 0x6F000, conf base
    /// 0x7F000 — Linux `PIPE_EDP_OFFSET` /
    /// `TRANSCODER_EDP_OFFSET`), not Transcoder A.
    fn transcoder(&self) -> crate::intel_gpu_pipes::Transcoder {
        if self.gen9_platform.is_some() && self.ddi == Ddi::A {
            return crate::intel_gpu_pipes::Transcoder::Edp;
        }
        self.pipe.transcoder()
    }

    /// The CRTC id this run programs (Pipe A→1, B→2, C→3, D→4), the
    /// `intel_gpu_vrr::VrrTranscoder` numbering.
    fn crtc_id(&self) -> u32 {
        self.pipe as u32 + 1
    }

    /// The VRR IP for this run's display family (unknown family keeps
    /// display 12's, as `program_transcoder` does).
    fn vrr_ip(&self) -> crate::intel_gpu_vrr::DisplayVrrIp {
        match self.gen12_family {
            Some(family) => crate::intel_gpu_vrr::DisplayVrrIp::from_gen12_platform(family),
            None => crate::intel_gpu_vrr::DisplayVrrIp::Gen12,
        }
    }

    /// Set the explicit DBUF share for this pipe's primary
    /// plane, as `(start_block, end_block)` in DBUF blocks
    /// (see `intel_gpu_multipipe::dbuf_shares`).
    pub fn set_dbuf_share(&mut self, start_block: u16, end_block: u16) {
        self.dbuf_share = Some((start_block, end_block));
    }

    /// Run the modeset. The orchestrator owns the
    /// step ordering; each step is mostly a thin wrapper around
    /// the codec module that knows the register encoding.
    ///
    /// `fallback_mode`: when `Some(m)`, skip EDID readback and use
    /// `m` directly. Useful for `[VESA_1024X768_60]` boot fallback
    /// or for testing.
    pub fn modeset(
        &mut self,
        primary_fb: &Framebuffer,
        fallback_mode: Option<&Mode>,
    ) -> Result<Mode, ModesetError> {
        self.modeset_impl(
            primary_fb,
            fallback_mode,
            LinkStep::Legacy,
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        )
        .map(|(mode, _)| mode)
    }

    /// Restore an admitted mode without replacing it with a new EDID mode.
    /// The caller has sized its scanout allocation for exactly this timing.
    pub fn modeset_fixed(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
    ) -> Result<Mode, ModesetError> {
        self.modeset_impl(
            primary_fb,
            Some(mode),
            LinkStep::FixedMode,
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        )
        .map(|(mode, _)| mode)
    }

    /// Run the modeset for an external DP sink whose link was
    /// negotiated ahead of time through the shared link-training
    /// core (`dp_link_training::negotiate`, #1092).
    ///
    /// Differences from the legacy eDP-shaped `modeset`:
    /// - the mode comes from the caller (`fallback_mode` is
    ///   required and used directly — the session layer owns
    ///   EDID on this path, including the extension blocks the
    ///   base-block read here cannot see);
    /// - the DPLL is programmed at the negotiated link rate, not
    ///   the pixel-clock floor;
    /// - M/N, `TRANS_DDI_FUNC_CTL` port width, the DDI buffer
    ///   lane field and link training all start from the plan;
    /// - if training settles somewhere else (the fallback
    ///   ladder walked), the DPLL, M/N, port width and
    ///   BUF_TRANS are reprogrammed to the *trained*
    ///   configuration before the DDI buffer enables, so what
    ///   the pipe streams at always matches the trained link.
    ///
    /// Returns the mode plus the link as actually trained.
    pub fn modeset_with_plan(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
        plan: LinkPlan,
    ) -> Result<(Mode, crate::dp_link_training::TrainedLink), ModesetError> {
        match self.modeset_impl(
            primary_fb,
            Some(mode),
            LinkStep::Plan(plan),
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        )? {
            (mode, Some(trained)) => Ok((mode, trained)),
            (_, None) => unreachable!("plan path always trains"),
        }
    }

    /// Run the modeset for the *primary* stream of a DP MST
    /// link (#1017): like [`Modeset::modeset_with_plan`], but
    /// the transcoder binds to the DDI in DP-MST mode
    /// (`TRANS_DDI_FUNC_CTL` mode = DP MST) from the start, so
    /// the link trains as an MST link and the branch device
    /// sees a multi-stream source.
    pub fn modeset_mst_primary(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
        plan: LinkPlan,
    ) -> Result<(Mode, crate::dp_link_training::TrainedLink), ModesetError> {
        match self.modeset_impl(
            primary_fb,
            Some(mode),
            LinkStep::Plan(plan),
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_MST,
        )? {
            (mode, Some(trained)) => Ok((mode, trained)),
            (_, None) => unreachable!("plan path always trains"),
        }
    }

    /// Run the modeset for a *secondary* stream of a DP MST
    /// link (#1017): the link on this DDI was already trained
    /// by the primary stream (`trained`), so this run programs
    /// only its own pipe/transcoder/plane — per-stream M/N,
    /// `TRANS_DDI_FUNC_CTL` in DP-MST mode, its DBUF share —
    /// and never touches the shared link blocks (DPLL, DPCLKA
    /// routing, BUF_TRANS, training, DDI buffer), which would
    /// disturb the streams already scanning out.
    pub fn modeset_mst_secondary(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
        trained: crate::dp_link_training::TrainedLink,
    ) -> Result<Mode, ModesetError> {
        self.modeset_impl(
            primary_fb,
            Some(mode),
            LinkStep::Trained(trained),
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_MST,
        )
        .map(|(mode, _)| mode)
    }

    /// Tear the pipeline down in the PRM's safe order (plane →
    /// pipe → transcoder → DDI buffer). Used on DP disconnect
    /// (#1092); the disable sequence itself is step 3 of every
    /// modeset.
    pub fn teardown(&mut self) {
        self.disable_pipeline();
    }
    /// Fallible migration for retained legacy sessions. Success is a local
    /// stop proof, never inferred from a write or a GT-reset completion.
    pub fn try_teardown(&mut self) -> Result<(), ModesetError> {
        self.check_stop_source()?;
        self.try_disable_pipe_pipeline()?;
        self.try_disable_ddi_buffer()
    }
    pub fn try_teardown_stream(&mut self) -> Result<(), ModesetError> {
        self.check_stop_source()?;
        self.try_disable_pipe_pipeline()
    }
    fn check_stop_source(&self) -> Result<(), ModesetError> {
        if self.gen11_platform.is_some() || self.gen9_platform.is_some() {
            if !self.mmio.display_access_ok() {
                return Err(ModesetError::PipelineStopUnavailable);
            }
            return Ok(());
        }
        if self.gen12_family.is_none() || self.gen12_family != self.mmio.gen12_display_family() {
            return Err(ModesetError::UnsupportedGeneration);
        }
        if !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        Ok(())
    }

    /// SKL plane admission (Gen11 Lane 5, Gen9 Lane 5): the
    /// SKL rules (`skl_universal_plane.c`) — a linear
    /// surface's stride is capped at 32 KiB
    /// (`skl_plane_max_stride`) and its GGTT offset must be
    /// 256 KiB aligned (`skl_plane_min_alignment`, the VT-d
    /// floor). The shared validation already checked 64-byte
    /// stride units and 4K surface alignment; this is the SKL
    /// pinning rule on top. A firmware surface that fails it
    /// refuses the takeover (the panel keeps scanning the
    /// firmware surface); the probe's owned allocation is
    /// 256 KiB aligned by construction.
    fn validate_framebuffer_skl(&self, fb: &Framebuffer) -> Result<(), ModesetError> {
        if fb.stride_bytes > crate::intel_gpu_scanout::skl_max_stride() {
            return Err(ModesetError::InvalidFramebuffer);
        }
        if fb.phys_addr % u64::from(crate::intel_gpu_scanout::skl_alignment()) != 0 {
            return Err(ModesetError::InvalidFramebuffer);
        }
        Ok(())
    }

    /// Run the modeset for an HDMI sink (#1019). The HDMI
    /// session layer owns EDID/DDC and hands the mode in, like
    /// the DP plan path; the sequence diverges from
    /// `modeset_impl` exactly where HDMI does:
    ///
    /// - the DPLL is programmed for the mode's TMDS character
    ///   clock with WRPLL-computed coefficients
    ///   (`intel_gpu_pll::hdmi_wrpll_coeffs`), not a DP link
    ///   rate;
    /// - there is no M/N (TMDS carries the pixel clock on the
    ///   wire), no BUF_TRANS load and no link training;
    /// - `TRANS_DDI_FUNC_CTL` binds in HDMI mode with the
    ///   scrambling / high-TMDS-character-rate bits the caller
    ///   resolved from the character rate (the SCDC side of
    ///   scrambling is the session's, programmed before this
    ///   runs — the register bits must not change while the
    ///   port is enabled).
    ///
    /// `scrambling` / `high_tmds_char_rate` are both set iff
    /// the character rate exceeds 340 Mcsc.
    pub fn modeset_hdmi(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
        scrambling: bool,
        high_tmds_char_rate: bool,
    ) -> Result<Mode, ModesetError> {
        // Gen9: DMC is REQUIRED (Q5 default, §12.6) — the
        // same gate `modeset_impl` applies, here because the
        // HDMI entry bypasses `modeset_impl` entirely.
        if self.gen9_platform.is_some() && !crate::intel_gpu_gen9_dmc::gen9_dmc_loaded() {
            return Err(ModesetError::DmcUnavailable);
        }
        // Gen9: the SKL modeset below (WRPLL row + SKL HDMI
        // table + Wa #1143 pulse) — never the TGL
        // `hdmi_wrpll_coeffs` search or the Gen12
        // `program_dpll_coeffs` writes. Lane 8.
        // Gen12 Type-C ports have no HDMI modeset here (their
        // DDI is a Dekel port); Gen11 TC ports do — the MG PHY
        // drives HDMI through the MG PLL + MG HDMI table below.
        if self.gen11_platform.is_none() && self.ddi as u8 >= Ddi::D as u8 {
            return Err(ModesetError::UnsupportedGeneration);
        }
        // YCbCr 4:2:0 output is display 10+ (`ycbcr_420_allowed`), and the
        // pipe scaler that downsamples it takes at most `skl_scaler_mode_valid`'s
        // width (Linux compares hdisplay with the max source height).
        if self.hdmi_ycbcr420 {
            let max = if self.gen11_platform.is_some() {
                4096
            } else {
                8192
            };
            if self.gen9_platform.is_some() {
                return Err(ModesetError::UnsupportedGeneration);
            }
            if u32::from(mode.h_active) > max {
                return Err(ModesetError::DisplayResourceUnavailable);
            }
        }
        validate_framebuffer_mode(primary_fb, mode)?;
        // Gen9 SKL admission, as the DP path applies it in
        // `modeset_impl` (`validate_framebuffer_skl`): a bad
        // stride or alignment fails before any HW write.
        if self.gen9_platform.is_some() {
            self.validate_framebuffer_skl(primary_fb)?;
        }

        // The port clock is the TMDS clock (`intel_hdmi_tmds_clock`).
        let format = if self.hdmi_ycbcr420 {
            crate::intel_gpu_hdmi::SinkFormat::Ycbcr420
        } else {
            crate::intel_gpu_hdmi::SinkFormat::Rgb
        };
        let port_clock =
            crate::intel_gpu_hdmi::tmds_clock_for(mode.pixel_clock_khz, self.hdmi_bpc, format);
        self.enable_pg1()?;
        self.disable_pipeline();
        // Gen9: the SKL WRPLL row (`program_dpll_gen9_hdmi`),
        // not the TGL coefficients — the search below is
        // skipped entirely for Gen9.
        if self.gen9_platform.is_some() {
            self.program_dpll_gen9_hdmi(port_clock)?;
        } else {
            let coeffs = match crate::intel_gpu_pll::hdmi_wrpll_coeffs(
                port_clock,
                // Same DSSM-strap family selection as the DP path
                // (Q6, #1024).
                decode_refclk_family(self.mmio.read32(DSSM)),
            ) {
                Some(c) => c,
                None => return Err(ModesetError::HdmiClockUnsupported),
            };
            // Gen11: the ICL combo PLL (DP path shares this) or the
            // MG PLL on a TC port — never the TGL CFGCR0
            // `program_dpll_coeffs` writes below.
            if self.gen11_platform.is_some() {
                self.program_dpll_gen11_hdmi(&coeffs, port_clock)?;
            } else {
                self.program_dpll_coeffs(&coeffs)?;
            }
        }
        self.program_cdclk_floor(mode)?;
        self.program_dpclka_routing()?;
        self.enable_pipe_power_well(self.pipe)?;
        self.program_transcoder(mode);
        self.program_pipe(mode);
        if self.hdmi_ycbcr420 {
            self.program_ycbcr420_output(mode);
        }
        self.program_pipe_misc_bpc();
        // No step 7b: HDMI has no M/N.
        self.program_trans_ddi_func_ctl_hdmi(scrambling, high_tmds_char_rate);
        self.enable_dbuf_slices()?;
        self.program_watermarks(mode, primary_fb);
        self.program_plane(primary_fb, mode);
        // No step 9: no link training on a TMDS link — but the
        // PHY still gets its signal levels: the SKL HDMI table
        // entry + I_boost + Wa #1143 pulse (Gen9), the ICL HDMI
        // table's default entry (combo ports) or the MG HDMI
        // table's default entry (TC ports), programmed before
        // the DDI buffer enables (Linux
        // `intel_ddi_pre_enable_hdmi` calls `set_signal_levels`;
        // the old "no BUF_TRANS load" note predates the PHY
        // model).
        if self.gen9_platform.is_some() {
            self.program_hdmi_levels_gen9()?;
        } else if let Some(platform) = self.gen11_platform {
            use crate::intel_gpu_gen11_ddi::{phy_for_port, Gen11Phy};
            match phy_for_port(platform, self.ddi) {
                Some(Gen11Phy::Mg { .. }) => {
                    let port = crate::intel_gpu_gen11_mg_phy::MgPort::new(self.ddi, platform)?;
                    port.set_hdmi_default_levels(self.mmio, port_clock)?;
                }
                _ => {
                    let phy = crate::intel_gpu_gen12_combo_phy::ComboPhy::new_gen11(
                        self.ddi, platform, false, false,
                    )?;
                    phy.set_hdmi_default_levels(self.mmio, port_clock)?;
                }
            }
        } else {
            let phy = crate::intel_gpu_gen12_combo_phy::ComboPhy::new(
                self.ddi,
                self.gen12_family,
                self.tgl_uy,
                false,
                false,
                false,
            )?;
            phy.set_hdmi_default_levels(self.mmio, port_clock)?;
        }
        self.enable_ddi_buffer(4);
        self.enable_transcoder();
        self.enable_pipe();
        self.enable_plane();
        Ok(*mode)
    }

    /// Bind this run's transcoder to the DDI in HDMI mode (8 bpc,
    /// the fixed 4-lane width, scrambling bits per the plan).
    fn program_trans_ddi_func_ctl_hdmi(&mut self, scrambling: bool, high_tmds_char_rate: bool) {
        use crate::intel_gpu_pipes::{build_trans_ddi_func_ctl_hdmi, TRANS_DDI_FUNC_CTL_OFFSET};
        let val = if self.hdmi_dvi {
            crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
                self.ddi as u8,
                crate::intel_gpu_pipes::TRANS_DDI_MODE_DVI,
                4,
            )
        } else {
            build_trans_ddi_func_ctl_hdmi(self.ddi as u8, scrambling, high_tmds_char_rate)
        };
        let val = self.trans_ddi_port(val);
        // TRANS_DDI_BPC_10 / _12 (bits 22:20); the builders set BPC_8.
        let val = match self.hdmi_bpc {
            10 => (val & !(7 << 20)) | (1 << 20),
            12 => (val & !(7 << 20)) | (3 << 20),
            _ => val,
        };
        self.mmio
            .write32(self.transcoder().base() + TRANS_DDI_FUNC_CTL_OFFSET, val);
        compiler_fence(Ordering::SeqCst);
    }

    /// The port select this run's display version takes: the builders
    /// encode display 12's `(index + 1) << 27`; display 9–11 use
    /// `index << 28`.
    fn trans_ddi_port(&self, val: u32) -> u32 {
        if self.gen11_platform.is_some() || self.gen9_platform.is_some() {
            crate::intel_gpu_pipes::with_pre_tgl_port(val, self.ddi as u8)
        } else {
            val
        }
    }

    /// Tear down only this run's pipe pipeline (plane → pipe →
    /// transcoder), leaving the DDI buffer and the shared link
    /// up. Used when one MST stream of several goes away
    /// (#1017): the surviving streams keep scanning out of the
    /// same DDI.
    pub fn teardown_stream(&mut self) {
        self.disable_pipe_pipeline();
    }

    fn modeset_impl(
        &mut self,
        primary_fb: &Framebuffer,
        fallback_mode: Option<&Mode>,
        link: LinkStep,
        ddi_mode: u32,
    ) -> Result<(Mode, Option<crate::dp_link_training::TrainedLink>), ModesetError> {
        // Gen9: DMC is REQUIRED (Q5 default, §12.6) — the
        // gate fires before any register is touched, on every
        // entry (legacy, plan, trained), not only the panel
        // entry (`modeset_display_family` gates the panel
        // path; this covers the plan/trained paths too).
        // Lane 8 removed the plan-path backstop here: the
        // external-output plan plumbing is now wired, so a
        // Gen9 run can modeset an external output.
        if self.gen9_platform.is_some() && !crate::intel_gpu_gen9_dmc::gen9_dmc_loaded() {
            return Err(ModesetError::DmcUnavailable);
        }
        // Step 0: validate inputs that don't require touching HW.
        validate_framebuffer(primary_fb)?;

        // The plan, where the run carries one (the legacy shape
        // derives its link parameters at the steps that consume
        // them; the already-trained shape takes them from the
        // trained link).
        let plan = match link {
            LinkStep::Plan(p) => Some(p),
            _ => None,
        };
        let already_trained = match link {
            LinkStep::Trained(t) => Some(t),
            _ => None,
        };
        let tc_port = self.is_tc_port();
        if tc_port {
            let lanes = plan
                .map(|plan| plan.lanes)
                .or_else(|| already_trained.map(|link| link.lanes))
                .unwrap_or(self.tc_width);
            if !matches!(lanes, 1 | 2 | 4) || lanes > self.tc_width {
                return Err(ModesetError::PhyBusFailure);
            }
        }

        // Step 1: sessions and resume supply an exact mode. Only legacy
        // discovery reads EDID and optionally falls back to the caller.
        let mode = if !matches!(link, LinkStep::Legacy) {
            match fallback_mode {
                Some(m) => *m,
                None => return Err(ModesetError::EdidUnavailable),
            }
        } else {
            match self.read_preferred_mode_via_edid() {
                Ok(m) => m,
                Err(_) => match fallback_mode {
                    Some(m) => *m,
                    None => return Err(ModesetError::EdidUnavailable),
                },
            }
        };

        validate_framebuffer_mode(primary_fb, &mode)?;
        // SKL plane admission (Gen11 Lane 5, Gen9 Lane 5):
        // the SKL stride cap and the 256 KiB surface
        // alignment, on top of the shared validation above.
        if self.gen11_platform.is_some() || self.gen9_platform.is_some() {
            self.validate_framebuffer_skl(primary_fb)?;
        }
        let tc_port_sst = tc_port && ddi_mode == crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST;
        if tc_port_sst {
            if let Some(plan) = plan {
                plan.check_rgb8_capacity(&mode)?;
            }
        }

        // Step 2: enable PG1 (the always-required power well).
        // PG0 is power-good from BIOS / pre-boot firmware; we
        // don't need to touch it. PG2/PG3 are per-pipe and get
        // gated in step 5.
        self.enable_pg1()?;

        // Step 3: disable the existing pipeline if it's running.
        // PRM mandates a "disable first" sequence to avoid
        // glitching the panel. An MST secondary stream disables
        // only its own pipe pipeline — the DDI buffer carries
        // the streams already live on this link and must stay
        // up (#1017).
        if already_trained.is_some() {
            self.disable_pipe_pipeline();
        } else {
            self.disable_pipeline();
        }

        // Step 4: program DPLL for the mode's pixel clock.
        // Gen12 Combo PHY DPLL programming — DPLL_CFGCR0 has the
        // DCO integer + fraction; DPLL_CFGCR1 has the dividers.
        // intel_gpu_pll exposes `build_cfgcr0/1` for the encoding;
        // Stage 1 wires the actual MMIO writes here. The DPLL
        // synthesises the *link* clock: on the plan path that is
        // the negotiated rate; a run without a plan takes the rate
        // its training starts at (`UNPLANNED_START_RATE`), so the
        // sink never trains against a clock for another rate. An
        // MST secondary
        // stream skips this entirely — the primary stream's run
        // already clocked the shared link, and re-running the
        // PLL power/enable sequence would glitch it.
        //
        // Gen11 follows Linux's order instead: CDCLK
        // (`intel_set_cdclk_pre_plane_update`) runs before DPLL
        // enable, so the floor is raised here and step 4b below
        // is skipped for Gen11 (see the branch there). Gen9
        // follows the same Linux order (`skl_set_cdclk` before
        // `skl_ddi_pll_enable`).
        if self.gen11_platform.is_some() || self.gen9_platform.is_some() {
            self.program_cdclk_floor(&mode)?;
        }
        // Gen11 Type-C: the FIA main-link lane count precedes the PLL
        // (`intel_ddi_pre_pll_enable` → `intel_tc_port_set_fia_lane_count`).
        if tc_port && already_trained.is_none() {
            if let Some(platform) = self.gen11_platform {
                let lanes = plan.map_or(self.tc_width, |plan| plan.lanes);
                crate::intel_gpu_gen11_mg_phy::MgPort::new(self.ddi, platform)?
                    .set_fia_lanes(self.mmio, lanes, false)?;
            }
        }
        match (plan, already_trained) {
            (Some(p), _) => self.program_dpll_with_rate(&mode, to_pll_rate(p.rate))?,
            (None, Some(_)) => {}
            (None, None) => {
                self.program_dpll_with_rate(&mode, to_pll_rate(UNPLANNED_START_RATE))?
            }
        }

        // Step 4b (lane 1, #1010): raise CDCLK to the floor this
        // pixel clock needs — PRM: "Pipe maximum pixel rate =
        // 2 * CDCLK frequency". The TGL model programs the DE
        // PLL ratio and CD2X divider for the smallest
        // `icl_cdclk_table` rung at or above the floor, with
        // pcode frequency-request notifies. Only raises; a
        // faster firmware CDCLK is left alone.
        //
        // Gen11 already raised the floor before step 4 (Linux
        // order); this step is Gen12-only. Gen9 likewise
        // raised it before step 4.
        if self.gen11_platform.is_none() && self.gen9_platform.is_none() {
            self.program_cdclk_floor(&mode)?;
        }

        // Step 4c (lane 1): route this DDI's DPLL to the DDI in
        // DPCLKA_CFGCR0 — select the PLL and turn the DDI clock
        // on in separate writes, per the PRM sequence. This
        // register was never written before lane 1. Skipped for
        // an MST secondary stream: routing is per-DDI and the
        // primary stream's run already latched it.
        if already_trained.is_none() {
            self.program_dpclka_routing()?;
        }

        // Step 5: enable the per-pipe power well for this run's
        // pipe (PG2 / PG3 / PG4 for Pipe A / B / C on Gen12),
        // via HSW_PWR_WELL_CTL2, mirroring i915's
        // `hsw_set_power_well`.
        self.enable_pipe_power_well(self.pipe)?;

        // Step 6: program transcoder timing. PRM Vol. 14 §"TRANS_*"
        // — HTOTAL / VTOTAL / HSYNC / VSYNC registers.
        self.program_transcoder(&mode);

        // Step 6b: VRR timings for the mode this run commits
        // (`intel_vrr_set_transcoder_timings` follows
        // `intel_set_transcoder_timings`).
        self.program_vrr_for_modeset(&mode)?;

        // Step 7: program pipe — source rectangle + scaling.
        // For native-resolution modeset, source == destination.
        self.program_pipe(&mode);

        // Step 7b (lane 1): DP data/link M/N for the stream
        // (24 bpp, uncompressed). LINK_N is written
        // last — it triggers the hardware update of all four.
        // Pre-training this carries the planned (or legacy
        // derived) link configuration; step 9b reprograms it
        // with the trained values after training, on every
        // path.
        // An MST stream's M/N is per-stream: every stream
        // programs its own transcoder's values from its mode
        // against the one trained link.
        match (plan, already_trained) {
            (Some(p), _) => self.program_mn_link(&mode, p.rate, p.lanes),
            (None, Some(t)) => self.program_mn_link(&mode, t.rate, t.lanes),
            (None, None) => self.program_mn(&mode),
        }

        // Step 7c (lane 1): bind the transcoder to the DDI port
        // (TRANS_DDI_FUNC_CTL, 8 bpc, planned lanes; DP-SST for
        // the single-stream entries, DP-MST for the MST stream
        // entries, #1017). Never written before lane 1 — routing
        // was firmware leftover.
        let func_ctl_lanes = plan
            .map(|p| p.lanes)
            .or_else(|| already_trained.map(|t| t.lanes))
            .unwrap_or(4);
        self.program_trans_ddi_func_ctl_mode(func_ctl_lanes, ddi_mode);

        // Step 7d (lane 1; extended by Q6 #1024): power the
        // DBUF slices, then program the latency-based
        // watermarks + DBUF allocation (or this pipe's explicit
        // share when the multi-pipe coordinator set one, #1017)
        // before the plane is armed; the PLANE_SURF write in
        // step 8 latches them.
        self.enable_dbuf_slices()?;
        self.program_watermarks(&mode, primary_fb);

        // Establish the shared TGL+ RGB/CSC bypass while the internal pipe
        // is still stopped. Live adoption never resets inherited color.
        if ddi_mode == crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST {
            self.initialize_internal_color()?;
            if self.pipe == Pipe::A && self.ddi == Ddi::A && self.dbuf_share.is_none() {
                if let Some(family) = self.gen12_family {
                    crate::intel_gpu_gen12_cursor_resources::setup(self.mmio, &mode, family)
                        .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
                }
            }
        }
        // Step 8: program primary plane — framebuffer pointer,
        // stride, format.
        self.program_plane(primary_fb, &mode);

        // Step 9: DP link training. HDMI skips this. We expect
        // AUX is available (the sink is alive enough to ACK DPCD
        // reads). Failure surfaces as
        // ModesetError::LinkTrainingCr/Eq; the panel stays dark.
        //
        // The combo path programs its PHY levels inside
        // `train_dp_link` (prepare at the start rate, then
        // per-iteration updates from the sink's level requests
        // via `TrainingAux`) — there is no preloaded table to
        // reload when training settles elsewhere; the callback
        // already re-selected the table for the settled rate.
        // The callback also retunes the DPLL mid-training when
        // the fallback ladder opens a retry attempt at a lower
        // rate (`ComboPhy::training_update`, pattern 1 after a
        // dirty Configure), so the settled rate's link clock is
        // already programmed when training completes; the
        // re-program below then rewrites the same rate on the
        // plan path, kept as a safety net — and on the legacy
        // path it is the only re-program: step 7b programmed
        // M/N for the pixel-clock floor rate, so without it M/N
        // would keep the start-rate values after a fallback
        // (#2358).
        //
        // An MST secondary stream skips the whole step: the
        // link is already trained and the PHY already programmed
        // by the primary stream's run on this DDI.
        let trained_link = match already_trained {
            Some(link) => Some(link),
            None => self.train_dp_link(plan)?.1,
        };

        if let Some(t) = trained_link {
            let trained = LinkPlan {
                rate: t.rate,
                lanes: t.lanes,
            };
            if tc_port_sst {
                trained.check_rgb8_capacity(&mode)?;
            }
            // The TC port's training callback already retuned the PLL and enabled
            // the source at the final width before the sink acknowledged it.
            if !tc_port && plan.is_some_and(|p| p.rate != t.rate) {
                self.program_dpll_with_rate(&mode, to_pll_rate(t.rate))?;
            }
            if already_trained.is_none() && plan != Some(trained) {
                self.program_mn_link(&mode, t.rate, t.lanes);
                self.program_trans_ddi_func_ctl_mode(t.lanes, ddi_mode);
            }
        }
        if !tc_port && already_trained.is_none() {
            self.enable_ddi_buffer(trained_link.map(|t| t.lanes).unwrap_or(4));
        }

        // Step 11: enable transcoder, then pipe, then plane.
        // Sequence matters: transcoder pulls timing from PLL, pipe
        // needs transcoder to be live, plane scans into pipe.
        self.enable_transcoder();
        // VRR enable, after the transcoder is live.
        self.enable_vrr_for_modeset()?;
        self.enable_pipe();
        self.enable_plane();

        Ok((mode, trained_link))
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

        let d = edid
            .preferred_timing()
            .map_err(|_| ModesetError::EdidUnavailable)?;

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
    /// Gen9: no-op — PW_1 (index 14) is DMC-handled and
    /// always on (`HSW_PWR_WELL_CTL2` index 14 is in the
    /// always-on set; Linux `skl_power_wells` marks it
    /// `always_on`). There is no REQUEST to issue.
    fn enable_pg1(&mut self) -> Result<(), ModesetError> {
        if self.gen9_platform.is_some() {
            return Ok(());
        }
        self.enable_power_well(PowerWell::Pg1 as u32)
    }

    /// Enable the per-pipe power well for `pipe`. Required
    /// before any pipe / plane / transcoder programming.
    ///
    /// The well assignment is the ICL+ power-well domain map
    /// (i915 `display/intel_display_power_well.c`,
    /// `icl_power_wells` / `tgl_power_wells`): Pipe A under PG2,
    /// Pipe B under PG3, Pipe C under PG4. Pipe D has no well
    /// in this driver's arbitration set (pipes A–C, #1017) and
    /// is refused with the same `PowerWellTimeout` a grant
    /// failure surfaces as, so callers see one clean error.
    ///
    /// Rocket Lake has no PW_2 (`rkl_power_wells`): Pipe A sits in
    /// PW_1 with transcoder A and DDI A/B, Pipe B under PW_3 and Pipe C
    /// under PW_4, so Pipe A requests no per-pipe well.
    ///
    /// Gen9 uses the SKL map instead (`skl_power_wells`):
    /// Pipe A is in no gated well (always-on set — the pipe,
    /// the EDP transcoder, the DDI A lanes and AUX A are all
    /// always on), and Pipes B/C sit under PW_2
    /// (`HSW_PWR_WELL_CTL2` index 15, which also covers the
    /// panel fitters B/C, transcoders A/B/C, DDI lanes B–E,
    /// VGA, audio and AUX B/C/D).
    ///
    /// Reference: Linux `drivers/gpu/drm/i915/display/
    /// intel_display_power_well.c::hsw_set_power_well` — issues
    /// the REQUEST bit in `HSW_PWR_WELL_CTL2` and polls the STATE
    /// bit for grant. Default enable timeout is 1 ms.
    fn enable_pipe_power_well(&mut self, pipe: Pipe) -> Result<(), ModesetError> {
        if self.gen9_platform.is_some() {
            return match pipe {
                Pipe::A => Ok(()),
                Pipe::B | Pipe::C => self.enable_power_well(15),
                Pipe::D => Err(ModesetError::PowerWellTimeout),
            };
        }
        if self.gen12_family == Some(crate::intel_gpu_gt::Gen12Platform::RocketLake) {
            return match pipe {
                Pipe::A => Ok(()),
                Pipe::B => self.enable_power_well(PowerWell::Pg3 as u32),
                Pipe::C => self.enable_power_well(PowerWell::Pg4 as u32),
                Pipe::D => Err(ModesetError::PowerWellTimeout),
            };
        }
        let pw = match pipe {
            Pipe::A => PowerWell::Pg2,
            Pipe::B => PowerWell::Pg3,
            Pipe::C => PowerWell::Pg4,
            Pipe::D => return Err(ModesetError::PowerWellTimeout),
        };
        self.enable_power_well(pw as u32)
    }

    /// Enable the DDI IO well for `ddi` (`intel_ddi_pre_enable`
    /// takes the port's IO well before any DDI buffer
    /// programming). Gen9 indices (`skl_power_wells`):
    /// DDI_IO_A_E 1 (ports A and E share it), DDI_IO_B 2,
    /// DDI_IO_C 3, DDI_IO_D 4. A no-op on the Gen12/Gen11
    /// paths, whose IO wells are owned by the combo/MG PHY
    /// bring-up.
    fn enable_ddi_io_well(&mut self, ddi: Ddi) -> Result<(), ModesetError> {
        if self.gen9_platform.is_none() {
            return Ok(());
        }
        let idx = match ddi {
            Ddi::A | Ddi::E => 1,
            Ddi::B => 2,
            Ddi::C => 3,
            Ddi::D => 4,
            // DDI F–I are Gen12-only Type-C ports with no SKL
            // IO well index — fail closed, never program a
            // made-up well.
            _ => return Err(ModesetError::UnsupportedGeneration),
        };
        self.enable_power_well(idx)
    }

    /// Drive one PG enable transaction. Idempotent: re-issuing
    /// REQUEST for a granted well is a no-op per the PRM.
    ///
    /// Reference: Linux i915 `hsw_set_power_well`:
    ///   1. Set REQUEST bit in HSW_PWR_WELL_CTL2.
    ///   2. Wait for STATE bit assert.
    ///
    /// Default grant timeout per i915 is 1 ms (`enable_timeout`).
    /// `idx` is the raw `HSW_PWR_WELL_CTL2` well index (the
    /// `PowerWell` enum's ICL numbering on the Gen12/Gen11
    /// path; the SKL indices — PW_2 15, DDI_IO_* 1–4 — on the
    /// Gen9 path).
    fn enable_power_well(&mut self, idx: u32) -> Result<(), ModesetError> {
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
        let budget = narf_time::wall::ns_to_cycles(1_000_000);
        let start = narf_time::now_cycles();
        loop {
            // read_poll_timeout: sample expiry before the read, so the read
            // that ends a timed-out wait follows the deadline.
            let expired = narf_time::now_cycles().wrapping_sub(start) > budget;
            let s = self.mmio.read32(PWR_WELL_CTL2);
            if s & state != 0 {
                return Ok(());
            }
            if expired {
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
        self.disable_pipe_pipeline();
        self.disable_ddi_buffer();
    }

    /// Steps 1–3 of the disable: this run's plane → pipe →
    /// transcoder, in that order. The DDI buffer is left alone,
    /// so an MST stream can be torn down without disturbing the
    /// other streams on its link (#1017).
    fn disable_pipe_pipeline(&mut self) {
        let _ = self.try_disable_pipe_pipeline();
    }
    fn try_disable_pipe_pipeline(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{
            PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE, PLANE_CTL_ENABLE, PLANE_CTL_OFFSET,
            PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET,
        };
        // 1) Plane: clear ENABLE then re-arm via PLANE_SURF write
        //    so the next vblank latches "no plane".
        let plane_base = self.pipe.base() + PLANE_PRIMARY_OFFSET;
        let ctl = self.mmio.read32(plane_base + PLANE_CTL_OFFSET);
        let surf = self.mmio.read32(plane_base + PLANE_SURF_OFFSET);
        if ctl == u32::MAX || surf == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.mmio
            .write32(plane_base + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE);
        // Re-write SURF to trigger the latch.
        self.mmio.write32(plane_base + PLANE_SURF_OFFSET, surf);
        compiler_fence(Ordering::SeqCst);

        // 2) Pipe: clear ENABLE, wait for state-inactive.
        let pipe_off = self.pipe.base() + PIPECONF_OFFSET;
        let pconf = self.mmio.read32(pipe_off);
        if pconf == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.mmio.write32(pipe_off, pconf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(self.mmio, pipe_off, PIPECONF_STATE, false, 100_000_000) {
            return Err(ModesetError::PipelineStopUnavailable);
        }

        // VRR off before the transcoder stops.
        self.disable_vrr_for_modeset();

        // 3) Transcoder: same pattern as pipe. On Gen12 the
        //    transcoder CONF register is aliased into the pipe
        //    block (same address as step 2's); the sequence is
        //    kept as the PRM lists it — two clears of the same
        //    bit are idempotent.
        let trans_off = self.transcoder().conf_base() + PIPECONF_OFFSET;
        let tconf = self.mmio.read32(trans_off);
        if tconf == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.mmio.write32(trans_off, tconf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(self.mmio, trans_off, PIPECONF_STATE, false, 100_000_000) {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        if self.mmio.read32(plane_base + PLANE_CTL_OFFSET) & PLANE_CTL_ENABLE != 0 {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        Ok(())
    }

    /// Step 4 of the disable: this run's DDI buffer off, polling
    /// IDLE_STATUS asserting.
    fn disable_ddi_buffer(&mut self) {
        let _ = self.try_disable_ddi_buffer();
    }
    fn try_disable_ddi_buffer(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_ddi::{
            DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS, DDI_BUF_CTL_OFFSET,
        };
        let ddi_off = self.ddi.base() + DDI_BUF_CTL_OFFSET;
        let dconf = self.mmio.read32(ddi_off);
        if dconf == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.mmio.write32(ddi_off, dconf & !DDI_BUF_CTL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(
            self.mmio,
            ddi_off,
            DDI_BUF_CTL_IDLE_STATUS,
            true,
            10_000_000,
        ) {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        if self.mmio.read32(ddi_off) & DDI_BUF_CTL_ENABLE != 0 {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        if self.gen9_platform.is_none()
            && self.ddi as u8 >= Ddi::D as u8
            && !self.is_gen11_combo_port_d()
        {
            crate::intel_gpu_gen12_tc::DklPort::new(self.mmio, self.ddi)?
                .stop_transport(self.mmio, self.transcoder())?;
        }
        Ok(())
    }

    // ── DPLL ─────────────────────────────────────────────────

    /// Program this run's DPLL for the link `rate` (the
    /// negotiated rate on the plan path, #1092; the training
    /// start rate otherwise). On a Combo PHY: look up the
    /// PRM-published coefficients, then
    ///
    ///   1. Power-up via PLL_POWER_ENABLE + wait for PLL_POWER_STATE.
    ///   2. Write CFGCR0 (DCO integer + fraction) and CFGCR1 (Q/K/P
    ///      dividers + central freq).
    ///   3. Set PLL_ENABLE.
    ///   4. Poll PLL_LOCK with a 1 ms cap.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_dpll.c
    /// (`icl_pll_power_enable`, `icl_pll_enable`).
    fn program_dpll_with_rate(&mut self, mode: &Mode, rate: LinkRate) -> Result<(), ModesetError> {
        if self.gen11_platform.is_some() && self.is_tc_port() {
            // Gen11 Type-C: the MG PLL for the link clock
            // (divisor search + ICL MG packing), not a combo PLL.
            let platform = self
                .gen11_platform
                .ok_or(ModesetError::UnsupportedGeneration)?;
            let port = crate::intel_gpu_gen11_mg_phy::MgPort::new(self.ddi, platform)?;
            let port_clock = crate::intel_gpu_gen12_combo_phy::port_clock_khz(rate)
                .ok_or(ModesetError::PllLockTimeout)?;
            return port.enable(
                self.mmio,
                port_clock,
                true,
                crate::intel_gpu_pll::refclk_khz(self.mmio.read32(DSSM)),
            );
        }
        // Gen9: the SKL DPLL (CFGCR1/2 + DPLL_CTRL1, never the
        // TGL CFGCR0 `program_dpll_coeffs` writes below, and
        // never the Dekel port enable — SKL has no TC ports).
        if self.gen9_platform.is_some() {
            return self.program_dpll_gen9(rate);
        }
        if self.ddi as u8 >= Ddi::D as u8 && !self.is_gen11_combo_port_d() {
            let port = crate::intel_gpu_gen12_tc::DklPort::new(self.mmio, self.ddi)?;
            return port.enable(
                self.mmio,
                rate,
                crate::intel_gpu_pll::refclk_khz(self.mmio.read32(DSSM)),
            );
        }
        // Gen11: the ICL combo PLL (CFGCR0 0x164000 + pll*0x80),
        // never the TGL CFGCR0 (0x164284) `program_dpll_coeffs`
        // writes below.
        if self.gen11_platform.is_some() {
            return self.program_dpll_gen11(rate);
        }
        // Reference-clock family from the DSSM strap (Q6,
        // #1024): a 24 MHz-strapped part programmed with the
        // 19.2 MHz rows gets a DCO 26% off target.
        let _ = mode; // rate is explicit; the mode drove its choice
        let family = decode_refclk_family(self.mmio.read32(DSSM));
        let coeffs = match combo_coeffs(rate, family) {
            Some(c) => c,
            None => return Err(ModesetError::PllLockTimeout),
        };
        self.program_dpll_coeffs(&coeffs)
    }

    /// Bring the Gen11 combo PLL up for `rate`:
    /// `combo_coeffs` under the DSSM reference family, then the
    /// ICL `combo_pll_enable` sequence (power, CFGCR0/1, enable,
    /// wait LOCK). The EHL/JSL div-fraction workaround is off:
    /// it applies only at a 38.4 MHz reference on EHL B0+
    /// steppings, which this driver does not model — a
    /// remainder, not a guess. The fixed assignment comes from
    /// `combo_dpll_id`: ICL A/B and EHL/JSL A/B/C. ICL TC ports
    /// never reach here (dispatched to the MG PLL in
    /// `program_dpll_with_rate`); EHL/JSL PORT_D takes a pool PLL
    /// (`enable_gen11_combo_pll`).
    fn program_dpll_gen11(&mut self, rate: LinkRate) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_dpll::calc_dpll_state;
        let family = decode_refclk_family(self.mmio.read32(DSSM));
        let coeffs = match combo_coeffs(rate, family) {
            Some(c) => c,
            None => return Err(ModesetError::PllLockTimeout),
        };
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        self.enable_gen11_combo_pll(cfgcr0, cfgcr1)
    }

    /// Bring the Gen9 SKL DPLL up for `rate`:
    /// `skl_ddi_dp_set_dpll_hw_state` — the DP `DPLL_CTRL1`
    /// state for the link clock, then `skl_ddi_pll_enable`
    /// (CTRL1 write, CTL enable, 5 ms `DPLL_STATUS` lock
    /// wait). The DPLL id comes from `skl_get_dpll`: eDP
    /// takes DPLL0 only; every other output takes the first
    /// of DPLL1/2/3. Lane 8: external outputs take the first
    /// of DPLL1/2/3 through the same pool call —
    /// `program_dpclka_routing` makes the same pick, so the
    /// DPLL program and the clock routing agree on the id.
    /// Multi-external arbitration (two simultaneous external
    /// outputs would both take DPLL1) is a remainder.
    fn program_dpll_gen9(&mut self, rate: LinkRate) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen9_dpll::{dp_state, dpll_pool, pll_enable, SklDpllId};
        let is_edp = self.ddi == Ddi::A;
        let id = dpll_pool(is_edp)
            .first()
            .copied()
            .unwrap_or(SklDpllId::Dpll0);
        let port_clock = crate::intel_gpu_gen12_combo_phy::port_clock_khz(rate)
            .ok_or(ModesetError::PllLockTimeout)?;
        let state = dp_state(port_clock).ok_or(ModesetError::PllLockTimeout)?;
        pll_enable(self.mmio, id, &state).map_err(|_| ModesetError::PllLockTimeout)
    }

    /// Bring the Gen9 SKL DPLL up for an HDMI mode:
    /// `skl_ddi_hdmi_pll_dividers` — the WRPLL row for the
    /// pixel clock under the fixed 24 MHz reference
    /// (`REFCLK_KHZ`; Lane 4's CDCLK hardcodes ref 24000, not
    /// the DSSM strap) — then `skl_ddi_pll_enable` (CTRL1,
    /// CFGCR1/2, CTL enable, 5 ms `DPLL_STATUS` lock wait).
    /// The DPLL id is the same first-of-pool pick
    /// `program_dpll_gen9` and `program_dpclka_routing`
    /// make, so the WRPLL program and the clock routing agree.
    fn program_dpll_gen9_hdmi(&mut self, pixel_clock_khz: u32) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen9_cdclk::REFCLK_KHZ;
        use crate::intel_gpu_gen9_dpll::{dpll_pool, hdmi_state, pll_enable, SklDpllId};
        let is_edp = self.ddi == Ddi::A;
        let id = dpll_pool(is_edp)
            .first()
            .copied()
            .unwrap_or(SklDpllId::Dpll0);
        let (state, _actual) =
            hdmi_state(pixel_clock_khz, REFCLK_KHZ).ok_or(ModesetError::HdmiClockUnsupported)?;
        pll_enable(self.mmio, id, &state).map_err(|_| ModesetError::PllLockTimeout)
    }

    /// Program the Gen9 HDMI signal levels: the SKL HDMI
    /// table's default entry at index 9
    /// (`hsw_prepare_hdmi_ddi_buffers`), the I_boost for that
    /// entry (`skl_ddi_set_iboost` — Linux
    /// `hsw_set_signal_levels` runs the I_boost step for HDMI,
    /// then returns: "HDMI ignores the rest"), and the Wa
    /// #1143 training-override pulse. VBT inputs are caller
    /// inputs until the modeset plumbs `intel_gpu_vbt`
    /// through, so the table's default level and boost rule.
    fn program_hdmi_levels_gen9(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_ddi::Output;
        use crate::intel_gpu_gen9_ddi::{
            hdmi_level, program_hdmi_buffer, select_table, set_iboost_for_level,
            wa1143_training_override_pulse,
        };
        let (platform, sku, _) = self.gen9_dp_inputs()?;
        let table = select_table(platform, sku, Output::Hdmi, false);
        let level = hdmi_level(None);
        if !program_hdmi_buffer(self.mmio, self.ddi, table, level, false) {
            return Err(ModesetError::UnsupportedGeneration);
        }
        if !set_iboost_for_level(self.mmio, self.ddi, table, level, 0, false) {
            return Err(ModesetError::UnsupportedGeneration);
        }
        if !wa1143_training_override_pulse(self.mmio, self.ddi) {
            return Err(ModesetError::UnsupportedGeneration);
        }
        Ok(())
    }

    /// Bring the Gen11 PLL up for an HDMI mode: the combo PLL
    /// with the WRPLL-computed coefficients on a combo port, or
    /// the MG PLL (divisor search at the TMDS character clock,
    /// HDMI DCO rule) on a Type-C port. The WRPLL coefficients
    /// are only consumed by the combo path — the MG path
    /// computes its own state from `pixel_clock_khz`.
    fn program_dpll_gen11_hdmi(
        &mut self,
        coeffs: &crate::intel_gpu_pll::DpllCoeffs,
        pixel_clock_khz: u32,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_dpll::calc_dpll_state;
        let platform = self
            .gen11_platform
            .ok_or(ModesetError::UnsupportedGeneration)?;
        match crate::intel_gpu_gen11_ddi::phy_for_port(platform, self.ddi) {
            Some(crate::intel_gpu_gen11_ddi::Gen11Phy::Mg { .. }) => {
                let port = crate::intel_gpu_gen11_mg_phy::MgPort::new(self.ddi, platform)?;
                port.enable(
                    self.mmio,
                    pixel_clock_khz,
                    false,
                    crate::intel_gpu_pll::refclk_khz(self.mmio.read32(DSSM)),
                )
            }
            Some(crate::intel_gpu_gen11_ddi::Gen11Phy::Combo) => {
                let (cfgcr0, cfgcr1) = calc_dpll_state(coeffs, false);
                self.enable_gen11_combo_pll(cfgcr0, cfgcr1)
            }
            None => Err(ModesetError::UnsupportedGeneration),
        }
    }

    /// Bring DPLL0 up with explicit coefficients: power, write
    /// CFGCR0/CFGCR1, enable, wait for lock. Shared by the DP
    /// rate path (fixed PRM rows) and the HDMI path (WRPLL-
    /// computed rows, #1019).
    fn program_dpll_coeffs(
        &mut self,
        coeffs: &crate::intel_gpu_pll::DpllCoeffs,
    ) -> Result<(), ModesetError> {
        // Combo PHY DDIs A/B/C program DPLL 0/1/2 respectively
        // (the DPCLKA default assignment). Type-C has already dispatched
        // to its per-port Dekel PLL; this path is combo-only.
        let dpll_idx: u32 = dpll_index_for(self.ddi);
        let dpll_enable = dpll_enable_off(dpll_idx);

        // Step 1 — power the PLL up.
        let cur = self.mmio.read32(dpll_enable);
        self.mmio.write32(dpll_enable, cur | PLL_POWER_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(self.mmio, dpll_enable, PLL_POWER_STATE, true, 1_000_000) {
            return Err(ModesetError::PllLockTimeout);
        }

        // Step 2 — CFGCR0 / CFGCR1.
        let cfgcr0 = encode_cfgcr0(coeffs);
        let cfgcr0_off = match dpll_idx {
            0 => crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0,
            1 => crate::intel_gpu_pll::DPLL_CFGCR0_DPLL1,
            _ => crate::intel_gpu_pll::DPLL_CFGCR0_DPLL2,
        };
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
    /// The transcoder bound is this run's pipe's same-index
    /// transcoder (mobile eDP on Pipe A uses Transcoder A on
    /// Gen12; the dedicated Edp transcoder is pre-Gen12).
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_set_transcoder_timings`).
    fn program_transcoder(&mut self, mode: &Mode) {
        use crate::intel_gpu_pipes::{
            build_transcoder, TRANS_HBLANK_OFFSET, TRANS_HSYNC_OFFSET, TRANS_HTOTAL_OFFSET,
            TRANS_VBLANK_OFFSET, TRANS_VSYNC_OFFSET, TRANS_VTOTAL_OFFSET,
        };
        let timing = mode_to_display_timing(mode);
        let prog = match build_transcoder(&timing) {
            Ok(p) => p,
            Err(_) => return, // bad timing; downstream poll will time out
        };
        let base = self.transcoder().base();
        // intel_set_transcoder_timings: display 13 (ADL-P and ADL-N,
        // xe_lpd_display) clears VBLANK_START (crtc_vblank_start = 1, the
        // hardware ignores it); display 12 (TGL and ADL-S, XE_D_DISPLAY)
        // keeps vactive - 1 + SCL. An unknown family keeps display 12's.
        use crate::intel_gpu_gt::Gen12Platform;
        let vblank = match self.gen12_family {
            Some(Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN) => prog.vblank_display13(),
            _ => prog.vblank,
        };
        self.mmio.write32(base + TRANS_HTOTAL_OFFSET, prog.htotal);
        self.mmio.write32(base + TRANS_HBLANK_OFFSET, prog.hblank);
        self.mmio.write32(base + TRANS_HSYNC_OFFSET, prog.hsync);
        self.mmio.write32(base + TRANS_VTOTAL_OFFSET, prog.vtotal);
        self.mmio.write32(base + TRANS_VBLANK_OFFSET, vblank);
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
        use crate::intel_gpu_pipes::{build_pipe, PIPE_SRCSZ_OFFSET};
        let timing = mode_to_display_timing(mode);
        let prog = match build_pipe(&timing) {
            Ok(p) => p,
            Err(_) => return,
        };
        let (src_w, src_h) = self.pipe_source(mode);
        let srcsz = if self.gen9_panel_fit.is_some() {
            (u32::from(src_w) - 1) << 16 | (u32::from(src_h) - 1)
        } else {
            prog.srcsz
        };
        // PIPE_SRCSZ lives inside the pipe MMIO block.
        self.mmio
            .write32(self.pipe.trans_base() + PIPE_SRCSZ_OFFSET, srcsz);
        // Display 9: skl_pfit_enable for a fitted source; otherwise
        // skl_detach_scalers frees whatever scaler an earlier owner bound.
        if self.gen9_platform.is_some() {
            let pipe = self.pipe;
            let writes = match self.gen9_panel_fit {
                Some((_, _, scaler)) => scaler.enable_writes(pipe),
                None => crate::intel_gpu_xelpg_scaler::disable_writes_display9(pipe),
            };
            for (reg, val) in writes {
                self.mmio.write32(reg, val);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// `bdw_set_pipe_misc`'s BPC field for an HDMI deep-colour pipe:
    /// `PIPE_MISC_BPC_10` at 10 bpc. At 12 bpc only display 13 has a
    /// pipe encoding (`PIPE_MISC_BPC_12_ADLP`); earlier displays leave the
    /// field at 8 bpc and the port alone runs 12. An 8 bpc run leaves
    /// `PIPE_MISC` as it found it.
    fn program_pipe_misc_bpc(&mut self) {
        let field = match (self.hdmi_bpc, self.gen12_family) {
            (10, _) => Some(1),
            (
                12,
                Some(
                    crate::intel_gpu_gt::Gen12Platform::AlderLakeP
                    | crate::intel_gpu_gt::Gen12Platform::AlderLakeN,
                ),
            ) => Some(4),
            (12, _) => Some(0),
            _ => None,
        };
        // `bdw_set_pipe_misc`: a 4:2:0 output sets the YUV colorspace, the
        // 4:2:0 enable and full-blend mode (display < 30).
        let yuv = if self.hdmi_ycbcr420 {
            PIPE_MISC_YUV420_ENABLE
                | PIPE_MISC_YUV420_MODE_FULL_BLEND
                | PIPE_MISC_OUTPUT_COLORSPACE_YUV
        } else {
            0
        };
        if field.is_none() && yuv == 0 {
            return;
        }
        let reg = self.pipe.base() + 0x30;
        let cur = self.mmio.read32(reg);
        let mut val = (cur & !PIPE_MISC_YUV_MASK) | yuv;
        if let Some(field) = field {
            val = (val & !(7 << 5)) | (field << 5);
        }
        self.mmio.write32(reg, val);
        compiler_fence(Ordering::SeqCst);
    }

    /// YCbCr 4:2:0 on the TMDS link (display 11/12): the pipe scaler at
    /// 1:1 does the chroma downsampling (`pch_panel_fitting` keeps the
    /// fitter on for a native 4:2:0 mode; `skl_pfit_enable` binds scaler 0
    /// in normal mode with the medium filter), and the output CSC converts
    /// to BT.709 limited-range YCbCr (`icl_assign_csc`'s
    /// `ilk_csc_matrix_rgb_to_ycbcr`, written by `icl_update_output_csc`,
    /// enabled by `ICL_OUTPUT_CSC_ENABLE`).
    fn program_ycbcr420_output(&mut self, mode: &Mode) {
        program_ycbcr420_pipe(self.mmio, self.pipe, mode);
    }

    /// Undo [`Modeset::program_ycbcr420_output`] once the pipe is down
    /// ([`clear_ycbcr420_pipe`]).
    pub(crate) fn clear_ycbcr420_output(&mut self) {
        clear_ycbcr420_pipe(self.mmio, self.pipe);
    }

    fn initialize_internal_color(&mut self) -> Result<(), ModesetError> {
        if self.pipe == Pipe::A && self.ddi == Ddi::A {
            crate::intel_gpu_color::initialize_rgb_bypass(self.mmio)
                .map_err(|_| ModesetError::ColorPipelineUnavailable)?;
        }
        Ok(())
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
            build_primary_plane, PixelFormat as PipeFmt, PLANE_CTL_OFFSET, PLANE_OFFSET_OFFSET,
            PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET, PLANE_SURF_OFFSET,
        };
        let pipe_fmt = match fb.format {
            // XRGB8888 → 8:8:8:8 ARGB encoding (alpha treated as
            // opaque by the pipe when the surface is XRGB).
            PixelFormat::Xrgb8888 => PipeFmt::Argb8888,
        };
        let (plane_w, plane_h) = self.pipe_source(mode);
        let prog = match build_primary_plane(
            plane_w,
            plane_h,
            fb.stride_bytes,
            fb.phys_addr as u32,
            pipe_fmt,
        ) {
            Ok(p) => p,
            Err(_) => return,
        };
        let base = self.pipe.base() + PLANE_PRIMARY_OFFSET;
        // Per Linux skl_plane_update: program everything *except*
        // PLANE_CTL.ENABLE first, then the SURF register last —
        // writing SURF arms the plane on the next vblank.
        self.mmio
            .write32(base + PLANE_STRIDE_OFFSET, prog.plane_stride);
        self.mmio.write32(base + PLANE_SIZE_OFFSET, prog.plane_size);
        self.mmio
            .write32(base + PLANE_OFFSET_OFFSET, prog.plane_offset);
        // CTL with format + plane_enable; final flush via SURF.
        let control = self.gen12_family.map_or(prog.plane_ctl, |family| {
            // This stopped modeset owns the exact PCI-selected display family.
            // Wa_22012358565 selects bit28 for display13 uncompressed cpp4.
            crate::intel_gpu_pipes::gen12_xrgb_control(family)
        });
        self.mmio.write32(base + PLANE_CTL_OFFSET, control);
        self.mmio.write32(base + PLANE_SURF_OFFSET, prog.plane_surf);
        compiler_fence(Ordering::SeqCst);
    }

    // ── DP link training ─────────────────────────────────────

    // ── Gen9 DP training source ─────────────────────────────
    //
    // The SKL training source for the internal panel (Gen9
    // Lane 5): the whole `DDI_BUF_TRANS` table programmed once
    // at pre-enable (`hsw_prepare_dp_ddi_buffers`), then
    // per-iteration `hsw_set_signal_levels` — `skl_ddi_set_iboost`
    // at the sink's level plus `DDI_BUF_TRANS_SELECT(level)`
    // into `DDI_BUF_CTL` bits 27:24 — with a port-based
    // `DP_TP_CTL` (DDI base + 0x40, the same offset Gen11
    // uses). The level is lane 0's, exactly as Linux takes it
    // (`intel_ddi_level(encoder, crtc_state, 0)`); the
    // training core caps swing at 3 per lane, and the sink
    // model requests one level for all lanes. A pattern-1
    // write after a dirty Configure opens a retry attempt at a
    // lower rate, so the DPLL is reprogrammed for the new link
    // clock and the table + `DP_TP_CTL` PAT1 re-prepared
    // before the pattern field is rewritten — the mid-training
    // retune, mirroring `ComboPhy::training_update`.

    /// The Gen9 DP table inputs for this run, or
    /// `UnsupportedGeneration` when the run has no Gen9
    /// platform / SKU family to select with.
    fn gen9_dp_inputs(
        &self,
    ) -> Result<
        (
            crate::intel_gpu_gt::Gen9Platform,
            crate::intel_gpu_gen9_ddi::SkuFamily,
            bool,
        ),
        ModesetError,
    > {
        let platform = self
            .gen9_platform
            .ok_or(ModesetError::UnsupportedGeneration)?;
        let sku = self
            .gen9_sku_family
            .ok_or(ModesetError::UnsupportedGeneration)?;
        Ok((platform, sku, self.ddi == Ddi::A))
    }

    /// Program the (0, 0) levels for training at `rate`:
    /// the whole BUF_TRANS table (`hsw_prepare_dp_ddi_buffers`,
    /// capped by `dp_entry_count`), the level-0 I_boost
    /// (`skl_ddi_set_iboost`, VBT boost 0 — the VBT boost
    /// levels are caller inputs, not plumbed yet, so the
    /// table entry's `i_boost` rules), then `DP_TP_CTL`
    /// with pattern 1 (ENABLE | ENHANCED_FRAME |
    /// SCRAMBLE_DISABLE, pattern field 0 = PAT1).
    fn gen9_prepare_dp(&self, _rate: LinkRate, lanes: u8) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_ddi::Output;
        use crate::intel_gpu_gen9_ddi::{
            dp_entry_count, program_dp_buffers, select_table, set_iboost_for_level,
        };
        let (platform, sku, is_edp) = self.gen9_dp_inputs()?;
        let output = if is_edp { Output::Edp } else { Output::Dp };
        let table = select_table(platform, sku, output, self.edp_low_vswing);
        let count = dp_entry_count(self.ddi, table.len());
        // No VBT DP boost plumbed yet (Lane 4 remainder):
        // the balance-leg-enable bit stays clear.
        program_dp_buffers(self.mmio, self.ddi, table, count, false);
        // Port A with 4 lanes mirrors the boost to port E
        // (`skl_ddi_set_iboost`'s `PORT_A && max_lanes == 4`).
        let also_port_e = self.ddi == Ddi::A && lanes == 4;
        set_iboost_for_level(self.mmio, self.ddi, table, 0, 0, also_port_e);
        let tp = self.ddi.base() + GEN9_DP_TP_CTL_OFFSET;
        let cur = self.mmio.read32(tp);
        self.mmio.write32(
            tp,
            (cur & !(GEN9_DP_TP_CTL_LINK_TRAIN_MASK | GEN9_DP_TP_CTL_SCRAMBLE_DISABLE))
                | GEN9_DP_TP_CTL_ENABLE
                | GEN9_DP_TP_CTL_ENHANCED_FRAME_ENABLE
                | GEN9_DP_TP_CTL_SCRAMBLE_DISABLE,
        );
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Apply the sink's requested levels for `state.rate`:
    /// `skl_ddi_set_iboost` at lane 0's level, then
    /// `DDI_BUF_TRANS_SELECT(level)` into `DDI_BUF_CTL`.
    /// (`rate` is part of the training-update shape — the
    /// level program itself is rate-independent.)
    fn gen9_set_levels(
        &self,
        _rate: LinkRate,
        levels: &[(u8, u8); 4],
        lanes: u8,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_ddi::Output;
        use crate::intel_gpu_gen9_ddi::{select_table, set_iboost_for_level};
        use crate::intel_gpu_xelpg::preset_index;
        let (platform, sku, is_edp) = self.gen9_dp_inputs()?;
        let output = if is_edp { Output::Edp } else { Output::Dp };
        let table = select_table(platform, sku, output, self.edp_low_vswing);
        let (swing, pre) = levels[0];
        let level = preset_index(swing, pre);
        let also_port_e = self.ddi == Ddi::A && lanes == 4;
        set_iboost_for_level(self.mmio, self.ddi, table, level, 0, also_port_e);
        let off = self.ddi.base() + crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio
            .write32(off, (cur & !GEN9_DDI_BUF_EMP_MASK) | ((level as u32) << 24));
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Reprogram this DDI's SKL DPLL for `rate` mid-training:
    /// the `train_link` fallback ladder's retry attempt at a
    /// lower rate. The DDI buffer is already off while
    /// training; the clear + idle wait is the same defensive
    /// step the combo-PHY retune takes. `pll_disable` is a
    /// no-op for DPLL0 (it drives CDCLK and is always on);
    /// `pll_enable` rewrites `DPLL_CTRL1` for the new link
    /// clock — the VCO stays 8100 across DP rates, so no VCO
    /// change is involved — and waits the 5 ms lock.
    fn gen9_retune_dpll(&self, rate: LinkRate) -> Result<(), ModesetError> {
        use crate::intel_gpu_ddi::{
            DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS, DDI_BUF_CTL_OFFSET,
        };
        use crate::intel_gpu_gen9_dpll::{dp_state, dpll_pool, pll_disable, pll_enable, SklDpllId};
        let off = self.ddi.base() + DDI_BUF_CTL_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur & !DDI_BUF_CTL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(self.mmio, off, DDI_BUF_CTL_IDLE_STATUS, true, 10_000_000) {
            return Err(ModesetError::PllLockTimeout);
        }
        let tp = self.ddi.base() + GEN9_DP_TP_CTL_OFFSET;
        let tp_cur = self.mmio.read32(tp);
        self.mmio.write32(tp, tp_cur & !GEN9_DP_TP_CTL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let is_edp = self.ddi == Ddi::A;
        let id = dpll_pool(is_edp)
            .first()
            .copied()
            .unwrap_or(SklDpllId::Dpll0);
        let port_clock = crate::intel_gpu_gen12_combo_phy::port_clock_khz(rate)
            .ok_or(ModesetError::PllLockTimeout)?;
        let state = dp_state(port_clock).ok_or(ModesetError::PllLockTimeout)?;
        pll_disable(self.mmio, id).map_err(|_| ModesetError::PllLockTimeout)?;
        pll_enable(self.mmio, id, &state).map_err(|_| ModesetError::PllLockTimeout)
    }

    /// `ComboPhy::training_update` shape for the Gen9 source:
    /// Configure → nothing; Levels (clean) → reprogram the
    /// table select + I_boost at the state's rate; Levels
    /// (dirty) → nothing (the sink is about to rewrite the
    /// levels); Pattern → retune the DPLL and re-prepare on a
    /// dirty pattern-1, then rewrite the `DP_TP_CTL` pattern
    /// field. The pattern-0 write at the end of training is
    /// what returns `DP_TP_CTL` to NORMAL
    /// (`LINK_TRAIN_NORMAL` = 3), so there is no separate
    /// finish step — mirroring the combo-PHY path.
    fn gen9_training_update(
        &self,
        state: &training::State,
        change: training::Change,
    ) -> Result<(), ModesetError> {
        use training::Change;
        match change {
            Change::Configure => Ok(()),
            Change::Levels if !state.dirty => {
                self.gen9_set_levels(state.rate, &state.levels, state.lanes)
            }
            Change::Levels => Ok(()),
            Change::Pattern => {
                if state.pattern == 1 && state.dirty {
                    self.gen9_retune_dpll(state.rate)?;
                    self.gen9_prepare_dp(state.rate, state.lanes)?;
                }
                let tp = self.ddi.base() + GEN9_DP_TP_CTL_OFFSET;
                let bits = state
                    .pattern_bits()
                    .map_err(|_| ModesetError::PhyBusFailure)?;
                let cur = self.mmio.read32(tp);
                self.mmio.write32(
                    tp,
                    (cur & !(GEN9_DP_TP_CTL_LINK_TRAIN_MASK | GEN9_DP_TP_CTL_SCRAMBLE_DISABLE))
                        | bits,
                );
                compiler_fence(Ordering::SeqCst);
                Ok(())
            }
        }
    }

    /// Run the DP link-training state machine over our AUX
    /// channel. Wraps [`dp_link_training::train_link`] with our
    /// IntelAux transport. Picks rate + lane count from the mode
    /// the orchestrator computed during DPLL programming; today
    /// that's the same `link_rate_for_pixel_clock` decision.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/
    /// intel_dp_link_training.c (`intel_dp_link_training`).
    fn train_dp_link(
        &mut self,
        plan: Option<LinkPlan>,
    ) -> Result<(LinkRate, Option<crate::dp_link_training::TrainedLink>), ModesetError> {
        use crate::dp_link_training::{train_link, LinkError};
        let aux = IntelAux::new(self.mmio, self.ddi);
        // A run without a plan starts at HBR2/4-lane (the clock
        // step 4 programmed) and falls back via `train_link`'s
        // policy — the broadest envelope a modern eDP panel will
        // accept. The plan path starts at the negotiated
        // configuration (#1092).
        let (initial_rate, lanes) = match plan {
            Some(p) => (p.rate, p.lanes),
            None => (UNPLANNED_START_RATE, self.tc_width),
        };
        let result = if self.gen11_platform.is_some() && self.is_tc_port() {
            // Gen11 Type-C: the MG PHY is the training source
            // — same `TrainingAux` callback shape as the Dekel
            // branch, with the MG levels + display-11 transcoder
            // clock + port-based DP_TP_CTL. The training state
            // machine itself (`intel_dp_link_training.c`) is
            // generation-shared; only `set_signal_levels`
            // dispatches by PHY.
            let platform = self
                .gen11_platform
                .ok_or(ModesetError::UnsupportedGeneration)?;
            let port = crate::intel_gpu_gen11_mg_phy::MgPort::new(self.ddi, platform)?;
            port.start_training(
                self.mmio,
                self.transcoder(),
                to_pll_rate(initial_rate),
                lanes,
                false,
            )?;
            let mut failure = None;
            let mut aux = training::TrainingAux::new(
                aux,
                training::State::new(to_pll_rate(initial_rate), lanes),
                |state: &training::State, change| {
                    port.training_update(self.mmio, self.transcoder(), state, change)
                        .map_err(|error| {
                            failure = Some(error);
                            AuxError::Nacked
                        })
                },
            );
            let result = train_link(&mut aux, initial_rate, lanes, |us| {
                let _ = narf_scheduler::responsive_spin_until(
                    || false,
                    narf_time::Deadline::after_ns(u64::from(us) * 1000),
                );
            });
            if let Some(error) = failure {
                return Err(error);
            }
            result
        } else if self.gen9_platform.is_some() {
            // Gen9: the SKL training source — the whole
            // BUF_TRANS table at prepare, per-iteration
            // I_boost + TRANS_SELECT, port-based DP_TP_CTL.
            // The training state machine itself is
            // generation-shared; only the level program
            // dispatches by PHY.
            self.gen9_prepare_dp(to_pll_rate(initial_rate), lanes)?;
            let mut failure = None;
            let mut aux = training::TrainingAux::new(
                aux,
                training::State::new(to_pll_rate(initial_rate), lanes),
                |state: &training::State, change| {
                    self.gen9_training_update(state, change).map_err(|error| {
                        failure = Some(error);
                        AuxError::Nacked
                    })
                },
            );
            let result = train_link(&mut aux, initial_rate, lanes, |_us| core::hint::spin_loop());
            if let Some(error) = failure {
                return Err(error);
            }
            result
        } else if self.ddi as u8 >= Ddi::D as u8 && !self.is_gen11_combo_port_d() {
            let port = crate::intel_gpu_gen12_tc::DklPort::new(self.mmio, self.ddi)?;
            port.start_training(
                self.mmio,
                self.transcoder(),
                to_pll_rate(initial_rate),
                lanes,
                false,
            )?;
            let mut failure = None;
            let mut aux = training::TrainingAux::new(
                aux,
                training::State::new(to_pll_rate(initial_rate), lanes),
                |state: &training::State, change| {
                    port.training_update(self.mmio, self.transcoder(), state, change)
                        .map_err(|error| {
                            failure = Some(error);
                            AuxError::Nacked
                        })
                },
            );
            let result = train_link(&mut aux, initial_rate, lanes, |us| {
                let _ = narf_scheduler::responsive_spin_until(
                    || false,
                    narf_time::Deadline::after_ns(u64::from(us) * 1000),
                );
            });
            if let Some(error) = failure {
                return Err(error);
            }
            result
        } else {
            // Combo PHY (DDI A–C): program the (0, 0) levels and
            // enable DP_TP_CTL with pattern 1, then let the sink
            // drive per-iteration level updates through the same
            // `TrainingAux` callback shape the Type-C branch
            // uses. DDI A is the eDP panel port on Gen12
            // laptops, and the panel's VBT HOBL/low-vswing bits
            // ride on the modeset (set by
            // `modeset_display_family` from the probe-installed
            // facts) into the table selection. On Gen11 the same
            // programmer runs with the ICL tables and the
            // port-based DP_TP_CTL (`ComboPhy::new_gen11`); the
            // HOBL bit never reaches it (no HOBL table on ICL).
            let phy = match self.gen11_platform {
                Some(platform) => crate::intel_gpu_gen12_combo_phy::ComboPhy::new_gen11(
                    self.ddi,
                    platform,
                    self.ddi == Ddi::A,
                    self.edp_low_vswing,
                )?
                .with_gen11_dpll(self.gen11_dpll),
                None => crate::intel_gpu_gen12_combo_phy::ComboPhy::new(
                    self.ddi,
                    self.gen12_family,
                    self.tgl_uy,
                    self.ddi == Ddi::A,
                    self.edp_hobl,
                    self.edp_low_vswing,
                )?,
            };
            phy.prepare(
                self.mmio,
                self.transcoder(),
                to_pll_rate(initial_rate),
                lanes,
            )?;
            let mut failure = None;
            let mut aux = training::TrainingAux::new(
                aux,
                training::State::new(to_pll_rate(initial_rate), lanes),
                |state: &training::State, change| {
                    phy.training_update(self.mmio, self.transcoder(), state, change)
                        .map_err(|error| {
                            failure = Some(error);
                            AuxError::Nacked
                        })
                },
            );
            let result = train_link(&mut aux, initial_rate, lanes, |_us| core::hint::spin_loop());
            if let Some(error) = failure {
                return Err(error);
            }
            result
        };
        match result {
            Ok(trained) => {
                let pll = to_pll_rate(trained.rate);
                // Every path needs the achieved link: the plan
                // and Type-C paths already did (negotiated width
                // and SST payload capacity), and the legacy path
                // needs it so step 9b can reprogram M/N for the
                // settled link after a fallback (#2358). The
                // legacy callers that only use the PLL rate
                // (`modeset`, `modeset_fixed`) discard the link.
                Ok((pll, Some(trained)))
            }
            Err(LinkError::CrFailed(_)) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::EqFailed(_)) => Err(ModesetError::LinkTrainingEq),
            Err(LinkError::Aborted) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::AuxFailure(e)) => Err(ModesetError::AuxFailure(e)),
        }
    }

    // ── Lane-1 display correctness core ─────────────────────

    /// Program DPCLKA_CFGCR0 routing: this DDI's DPLL
    /// (`dpll_index_for`) → this DDI, clock on, in the PRM's two
    /// writes (select with the clock off, then clear the off
    /// bit). For DDI A / DPLL 0 this is byte-identical to the
    /// pre-multi-pipe programming.
    fn program_dpclka_routing(&mut self) -> Result<(), ModesetError> {
        if self.gen11_platform.is_some() && self.is_tc_port() {
            let platform = self
                .gen11_platform
                .ok_or(ModesetError::UnsupportedGeneration)?;
            return crate::intel_gpu_gen11_mg_phy::MgPort::new(self.ddi, platform)?
                .route_clock(self.mmio);
        }
        // Gen9: SKL has no DPCLKA (`DPCLKA_CFGCR0` is
        // Gen12/ICL). Clock routing is `DPLL_CTRL2`
        // (`skl_ddi_enable_clock`) — but the port's DDI IO well
        // comes first (`intel_ddi_pre_enable_dp` takes the IO
        // well before any DDI buffer programming).
        if self.gen9_platform.is_some() {
            self.enable_ddi_io_well(self.ddi)?;
            let id = crate::intel_gpu_gen9_dpll::dpll_pool(self.ddi == Ddi::A)
                .first()
                .copied()
                .unwrap_or(crate::intel_gpu_gen9_dpll::SklDpllId::Dpll0);
            crate::intel_gpu_gen9_dpll::enable_clock(self.mmio, self.ddi, id);
            return Ok(());
        }
        if self.ddi as u8 >= Ddi::D as u8 && !self.is_gen11_combo_port_d() {
            return crate::intel_gpu_gen12_tc::DklPort::new(self.mmio, self.ddi)?
                .route_clock(self.mmio);
        }
        use crate::intel_gpu_pll::{
            dpclka_clk_off, dpclka_clk_sel, dpclka_clk_sel_mask, DPCLKA_CFGCR0,
        };
        // EHL/JSL PORT_D clocks PHY A from the PLL it arbitrated
        // (`icl_ddi_combo_enable_clock` keys the field by PHY).
        let (phy, select) = if self.is_gen11_combo_port_d() {
            let id = self
                .gen11_dpll
                .ok_or(ModesetError::DisplayResourceUnavailable)?;
            (Ddi::A as u32, id.clock_select())
        } else {
            (self.ddi as u32, dpll_index_for(self.ddi))
        };
        let cur = self.mmio.read32(DPCLKA_CFGCR0);
        let selected = (cur & !dpclka_clk_sel_mask(phy) & !dpclka_clk_off(phy))
            | dpclka_clk_sel(select, phy)
            | dpclka_clk_off(phy);
        self.mmio.write32(DPCLKA_CFGCR0, selected);
        compiler_fence(Ordering::SeqCst);
        self.mmio
            .write32(DPCLKA_CFGCR0, selected & !dpclka_clk_off(phy));
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Raise CDCLK to the floor for `mode`'s pixel clock
    /// (PRM rule `pixel_clock <= 2 * CDCLK`, floor =
    /// `pixel_clock / 2`), via the TGL CDCLK model
    /// (`intel_gpu_gen12_cdclk`: `icl_cdclk_table` rung by the
    /// DSSM reference strap, DE PLL ratio + CD2X divider, pcode
    /// frequency-request notifies). Only raises; a faster
    /// firmware CDCLK is left alone, and a floor past the table
    /// leaves the firmware clock alone too. A refused pcode
    /// pre-notify degrades the same way (leave the firmware
    /// clock; the modeset proceeds — the standing contract in
    /// this file is that pcode failure degrades, it does not
    /// fail the modeset). A PLL lock timeout, lost access or
    /// readback mismatch fails the modeset.
    fn program_cdclk_floor(&mut self, mode: &Mode) -> Result<(), ModesetError> {
        // Gen9: the SKL CDCLK model (VCO-aware ladders,
        // `skl_set_cdclk`), not the TGL frequency-request
        // model below.
        if let Some(platform) = self.gen9_platform {
            return self.program_cdclk_floor_gen9(mode, platform);
        }
        // Gen11: the ICL CDCLK model (pcode command 0x7,
        // per-platform voltage levels), not the TGL
        // frequency-request model below.
        if let Some(platform) = self.gen11_platform {
            return self.program_cdclk_floor_gen11(mode, platform);
        }
        use crate::intel_gpu_gen12_cdclk as cdclk;
        let table = cdclk::table_for(self.gen12_family);
        let current =
            cdclk::Current::read(self.mmio, table).map_err(|_| ModesetError::CdclkUnavailable)?;
        let floor_khz = mode.pixel_clock_khz.div_ceil(2);
        if let Some(known) = current.known {
            if known.cdclk_khz >= floor_khz {
                return Ok(());
            }
        }
        self.refuse_shared_cdclk(current.known.map(|k| k.cdclk_khz), mode)?;
        let target = match cdclk::calc_cdclk(table, current.refclk_khz, floor_khz) {
            Some(r) => r,
            None => return Ok(()), // beyond the table; leave firmware CDCLK
        };
        match cdclk::program(self.mmio, &current, target) {
            Ok(()) => Ok(()),
            Err(cdclk::CdclkError::Pcode(_)) => Ok(()),
            Err(_) => Err(ModesetError::CdclkUnavailable),
        }
    }

    /// Gen9 CDCLK floor: the same shape as the Gen11 floor
    /// above, through the SKL model (`intel_gpu_gen9_cdclk`:
    /// the VCO-aware ladders, the Wa Display #1183
    /// `CDCLK_CTL` dance, pcode CDCLK-control notifies with
    /// the ready-bit check, and the platform VCO rule). The
    /// VCO is 8100 — `select_vco(platform, None)`, no eDP
    /// CRTC enabled when the floor runs — so the Wa #1183
    /// VCO-8640 refusal on Skylake is unreachable here; it
    /// maps to `CdclkUnavailable` anyway. A refused pcode
    /// pre-notify — or a reply without the ready bit —
    /// degrades the same way as on Gen11/Gen12 (leave the
    /// firmware clock; the modeset proceeds). A PLL lock
    /// timeout, lost access or readback mismatch fails the
    /// modeset. `calc_cdclk` always returns a rung (it clamps
    /// to the top), so a floor past the table leaves the
    /// firmware clock alone instead of programming a rung
    /// below the floor.
    fn program_cdclk_floor_gen9(
        &mut self,
        mode: &Mode,
        platform: crate::intel_gpu_gt::Gen9Platform,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen9_cdclk as cdclk;
        let current =
            cdclk::Current::read(self.mmio).map_err(|_| ModesetError::CdclkUnavailable)?;
        let floor_khz = mode.pixel_clock_khz.div_ceil(2);
        if current.cdclk_khz >= floor_khz {
            return Ok(());
        }
        self.refuse_shared_cdclk(Some(current.cdclk_khz), mode)?;
        let vco = cdclk::select_vco(platform, None);
        let target = cdclk::calc_cdclk(floor_khz, vco);
        if target < floor_khz {
            return Ok(()); // beyond the table; leave firmware CDCLK
        }
        match cdclk::program(self.mmio, &current, target, vco, platform) {
            Ok(()) => Ok(()),
            Err(cdclk::CdclkError::Pcode(_) | cdclk::CdclkError::PcodeNotReady) => Ok(()),
            Err(_) => Err(ModesetError::CdclkUnavailable),
        }
    }

    /// Gen11 CDCLK floor: the same shape as the Gen12 floor
    /// above, through the ICL model (`intel_gpu_gen11_cdclk`:
    /// the 18-rung table, DE PLL ratio + CD2X divider, pcode
    /// CDCLK-control notifies with the ready-bit check, and the
    /// platform voltage level). A refused pcode pre-notify —
    /// or a reply without the ready bit — degrades the same
    /// way as on Gen12 (leave the firmware clock; the modeset
    /// proceeds). A PLL lock timeout, lost access or readback
    /// mismatch fails the modeset.
    fn program_cdclk_floor_gen11(
        &mut self,
        mode: &Mode,
        platform: crate::intel_gpu_gt::Gen11Platform,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_gen11_cdclk as cdclk;
        let current =
            cdclk::Current::read(self.mmio).map_err(|_| ModesetError::CdclkUnavailable)?;
        let floor_khz = mode.pixel_clock_khz.div_ceil(2);
        if let Some(known) = current.known {
            if known.cdclk_khz >= floor_khz {
                return Ok(());
            }
        }
        self.refuse_shared_cdclk(current.known.map(|k| k.cdclk_khz), mode)?;
        let target = match cdclk::calc_cdclk(current.refclk_khz, floor_khz) {
            Some(r) => r,
            None => return Ok(()), // beyond the table; leave firmware CDCLK
        };
        match cdclk::program(self.mmio, &current, target, platform) {
            Ok(()) => Ok(()),
            Err(cdclk::CdclkError::Pcode(_) | cdclk::CdclkError::PcodeNotReady) => Ok(()),
            Err(_) => Err(ModesetError::CdclkUnavailable),
        }
    }

    /// Program the DP data/link M/N registers for this run's
    /// transcoder.
    fn program_mn(&mut self, mode: &Mode) {
        let rate = link_rate_for_pixel_clock(mode.pixel_clock_khz);
        let ls_khz = rate.megabits_per_sec() * 100;
        self.program_mn_values(mode, ls_khz, 4);
    }

    /// Program M/N for an explicit trained/negotiated link:
    /// `rate` is the training-core rate (its symbol clock is
    /// `rate_kbps / 10` in kHz), `lanes` the lane count.
    fn program_mn_link(&mut self, mode: &Mode, rate: crate::dp_link_training::LinkRate, lanes: u8) {
        self.program_mn_values(mode, rate.rate_kbps() / 10, lanes);
    }

    fn program_mn_values(&mut self, mode: &Mode, ls_khz: u32, lanes: u8) {
        use crate::intel_gpu_pipes::{
            dp_mn, PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET,
            PIPE_LINK_N1_OFFSET,
        };
        let (dm, dn, lm, ln) = dp_mn(mode.pixel_clock_khz, ls_khz, lanes as u32, 3);
        let base = self.transcoder().base();
        self.mmio.write32(base + PIPE_DATA_M1_OFFSET, dm);
        self.mmio.write32(base + PIPE_DATA_N1_OFFSET, dn);
        self.mmio.write32(base + PIPE_LINK_M1_OFFSET, lm);
        // LINK_N last: it triggers the hardware update.
        self.mmio.write32(base + PIPE_LINK_N1_OFFSET, ln);
        compiler_fence(Ordering::SeqCst);
    }

    /// Bind this run's transcoder to this DDI with an explicit
    /// DDI mode field (`TRANS_DDI_MODE_*`): DP-SST for SST
    /// runs (8 bpc, `lanes` lanes — 4 on the legacy path, the
    /// negotiated count on the plan path), DP-MST for MST
    /// stream runs (#1017).
    fn program_trans_ddi_func_ctl_mode(&mut self, lanes: u8, mode: u32) {
        use crate::intel_gpu_pipes::{build_trans_ddi_func_ctl, TRANS_DDI_FUNC_CTL_OFFSET};
        let val = self.trans_ddi_port(build_trans_ddi_func_ctl(self.ddi as u8, mode, lanes));
        self.mmio
            .write32(self.transcoder().base() + TRANS_DDI_FUNC_CTL_OFFSET, val);
        compiler_fence(Ordering::SeqCst);
    }

    /// Power both DBUF slices via `DBUF_CTL` POWER_REQUEST →
    /// POWER_STATE sequencing (Q6, #1024). Runs before any
    /// watermark programming: the DDB blocks the watermarks
    /// reference live in the slices' SRAM.
    fn enable_dbuf_slices(&mut self) -> Result<(), ModesetError> {
        // Gen9 DBUF slices live at the same offsets with the
        // same power sequencing (single slice S1 at 0x45008);
        // the Gen9-scoped module owns the call so the register
        // facts stay per-generation.
        if self.gen9_platform.is_some() {
            return crate::intel_gpu_gen9_wm::request_dbuf_slices(self.mmio)
                .map_err(|_| ModesetError::DbufPowerTimeout);
        }
        // Gen11 DBUF slices live at the same offsets with the
        // same power sequencing; the Gen11-scoped module owns
        // the call so the register facts stay per-generation.
        if self.gen11_platform.is_some() {
            return crate::intel_gpu_gen11_wm::request_dbuf_slices(self.mmio)
                .map_err(|_| ModesetError::DbufPowerTimeout);
        }
        crate::intel_gpu_wm::request_dbuf_slices(self.mmio)
            .map_err(|_| ModesetError::DbufPowerTimeout)
    }

    /// Latency-based watermarks + DBUF allocation (Q6,
    /// #1024): read the memory latencies and SAGV block time
    /// from the pcode mailbox, run the Gen12 algorithm in
    /// `intel_gpu_wm`, validate against this driver's DDB
    /// allocation (the whole DBUF to Pipe A's primary plane),
    /// and program PLANE_WM levels 0..5, the SAGV and
    /// transition watermarks, and PLANE_BUF_CFG.
    ///
    /// Multi-pipe (#1017): when the coordinator set an explicit
    /// DBUF share for this pipe, the PRM basic programming
    /// carries the share's block range instead (level-0
    /// watermark = the share size at 2 lines, PLANE_BUF_CFG =
    /// the share's (start, end)); the latency algorithm here
    /// models a single consumer owning the whole DDB. A single
    /// active pipe never gets a share.
    ///
    /// Fallback: if the pcode latency read fails, or the
    /// computed set has no usable level 0, program lane 1's
    /// PRM pre-OS-boot basics instead — a conservative fixed
    /// programming the PRM scopes to exactly this driver's
    /// shape — rather than leaving firmware watermarks of
    /// unknown provenance in place.
    fn program_watermarks(&mut self, mode: &Mode, fb: &Framebuffer) {
        // Gen9: the 8-level SKL algorithm (no SAGV watermark,
        // no transition watermark), through the Gen9-scoped
        // module.
        if self.gen9_platform.is_some() {
            self.program_watermarks_gen9(mode, fb);
            return;
        }
        // Gen11: the 8-level ICL algorithm (no SAGV watermark),
        // through the Gen11-scoped module.
        if self.gen11_platform.is_some() {
            self.program_watermarks_gen11(mode, fb);
            return;
        }
        use crate::intel_gpu_wm::{
            adjust_latencies, compute_plane_watermarks, encode_plane_buf_cfg, encode_wm_level,
            validate_watermarks, WmParams, PRIMARY_DDB_END, PRIMARY_DDB_START,
        };
        if let Some((start, end)) = self.dbuf_share {
            write_wm_block(
                self.mmio,
                self.pipe,
                plane_wm0_for_blocks(end - start + 1),
                dbuf_buf_cfg(start, end),
            );
            return;
        }
        let mmio = self.mmio;
        let computed = (|| {
            let raw = crate::intel_gpu_pcode::read_mem_latencies(mmio).ok()?;
            let latencies = adjust_latencies(&raw);
            // A failed SAGV read disables the SAGV watermarks
            // (block time 0) but not the latency levels — the
            // same degradation the reference driver takes.
            let block_time = crate::intel_gpu_pcode::read_sagv_block_time_us(mmio).unwrap_or(0);
            let params = WmParams {
                pixel_rate_khz: mode.pixel_clock_khz,
                htotal: mode.h_total as u32,
                width_px: mode.h_active as u32,
                cpp: fb.format.bits_per_pixel() / 8,
            };
            let mut wm = compute_plane_watermarks(&params, &latencies, block_time);
            if !wm.levels[0].enable {
                return None;
            }
            validate_watermarks(&mut wm, PRIMARY_DDB_END - PRIMARY_DDB_START);
            if !wm.levels[0].enable {
                return None;
            }
            Some(wm)
        })();
        let wm = match computed {
            Some(wm) => wm,
            None => {
                self.program_watermarks_preboot();
                return;
            }
        };
        let wm_base = self.pipe.base() + PLANE_WM_BASE_OFFSET;
        for (level, wm_level) in wm.levels.iter().enumerate() {
            self.mmio
                .write32(wm_base + level as u64 * 4, encode_wm_level(wm_level));
        }
        self.mmio
            .write32(wm_base + PLANE_WM_SAGV_OFFSET, encode_wm_level(&wm.sagv));
        self.mmio.write32(
            wm_base + PLANE_WM_SAGV_TRANS_OFFSET,
            encode_wm_level(&wm.sagv_trans),
        );
        self.mmio
            .write32(wm_base + PLANE_WM_TRANS_OFFSET, encode_wm_level(&wm.trans));
        self.mmio.write32(
            self.pipe.base() + PLANE_BUF_CFG_OFFSET,
            encode_plane_buf_cfg(PRIMARY_DDB_START, PRIMARY_DDB_END),
        );
        compiler_fence(Ordering::SeqCst);
    }

    /// Latency-based watermarks + DBUF allocation on Gen11
    /// (Lane 5): the 8-level ICL algorithm in
    /// `intel_gpu_gen11_wm` — read the memory latencies from
    /// the pcode mailbox, compute the 8 levels + transition
    /// watermark, validate against the whole-DBUF allocation,
    /// and program PLANE_WM levels 0..7, the transition
    /// watermark, and PLANE_BUF_CFG. Gen11 has no SAGV
    /// watermark (`HAS_SAGV_WM` is DISPLAY_VER >= 12), so the
    /// SAGV offsets are never written. The multi-pipe share
    /// shape mirrors the Gen12 path (level-0 = the share size
    /// at 2 lines, PLANE_BUF_CFG = the share's range).
    ///
    /// Fallback: if the pcode latency read fails, or the
    /// computed set has no usable level 0, program the
    /// pre-boot basics instead — the same 160-block level-0
    /// shape as the Gen12 fallback (same DBUF geometry and
    /// encoding; the ICL PRM pre-boot table itself was not
    /// independently verified, so this is the shared shape).
    fn program_watermarks_gen11(&mut self, mode: &Mode, fb: &Framebuffer) {
        use crate::intel_gpu_gen11_wm::{
            adjust_latencies, compute_plane_watermarks, encode_plane_buf_cfg, encode_wm_level,
            validate_watermarks, WmParams, PRIMARY_DDB_END, PRIMARY_DDB_START,
        };
        if let Some((start, end)) = self.dbuf_share {
            write_wm_block_skl(
                self.mmio,
                self.pipe,
                plane_wm0_for_blocks(end - start + 1),
                dbuf_buf_cfg(start, end),
            );
            return;
        }
        let mmio = self.mmio;
        let computed = (|| {
            let raw = crate::intel_gpu_pcode::read_mem_latencies(mmio).ok()?;
            // No 16 Gb-DIMM latency adjustment input: the driver
            // does not model DIMMs, so the adjustment is off.
            let latencies = adjust_latencies(&raw, false);
            let params = WmParams {
                pixel_rate_khz: mode.pixel_clock_khz,
                htotal: mode.h_total as u32,
                width_px: mode.h_active as u32,
                cpp: fb.format.bits_per_pixel() / 8,
            };
            let mut wm = compute_plane_watermarks(&params, &latencies);
            if !wm.levels[0].enable {
                return None;
            }
            validate_watermarks(&mut wm, PRIMARY_DDB_END - PRIMARY_DDB_START);
            if !wm.levels[0].enable {
                return None;
            }
            Some(wm)
        })();
        let wm = match computed {
            Some(wm) => wm,
            None => {
                self.program_watermarks_preboot_gen11();
                return;
            }
        };
        let wm_base = self.pipe.base() + PLANE_WM_BASE_OFFSET;
        for (level, wm_level) in wm.levels.iter().enumerate() {
            self.mmio
                .write32(wm_base + level as u64 * 4, encode_wm_level(wm_level));
        }
        self.mmio
            .write32(wm_base + PLANE_WM_TRANS_OFFSET, encode_wm_level(&wm.trans));
        self.mmio.write32(
            self.pipe.base() + PLANE_BUF_CFG_OFFSET,
            encode_plane_buf_cfg(PRIMARY_DDB_START, PRIMARY_DDB_END),
        );
        compiler_fence(Ordering::SeqCst);
    }

    /// Gen9 pre-boot watermark basics: the same 160-block
    /// level-0 shape as the Gen12 fallback (the 892-block
    /// DBUF holds it; same encoding — see
    /// `program_watermarks_gen9`).
    fn program_watermarks_preboot_gen9(&mut self) {
        write_wm_block_skl(
            self.mmio,
            self.pipe,
            PLANE_WM0_PREBOOT,
            PLANE_BUF_CFG_PREBOOT_A,
        );
    }

    /// Gen9 watermarks: the 8-level SKL algorithm (no SAGV
    /// watermark, no transition watermark —
    /// `WaDisableTWM`), through the Gen9-scoped module. The
    /// shape mirrors `program_watermarks_gen11`: the latency
    /// algorithm with the 16 Gb-DIMM adjustment off (the
    /// driver does not model DIMMs), the whole 892-block DBUF
    /// to Pipe A's primary plane, and the pre-boot fallback
    /// when the pcode latency read fails or level 0 is unusable.
    fn program_watermarks_gen9(&mut self, mode: &Mode, fb: &Framebuffer) {
        use crate::intel_gpu_gen9_wm::{
            adjust_latencies, compute_plane_watermarks, encode_plane_buf_cfg, encode_wm_level,
            validate_watermarks, WmParams, PRIMARY_DDB_END, PRIMARY_DDB_START,
        };
        if let Some((start, end)) = self.dbuf_share {
            write_wm_block_skl(
                self.mmio,
                self.pipe,
                plane_wm0_for_blocks(end - start + 1),
                dbuf_buf_cfg(start, end),
            );
            return;
        }
        let mmio = self.mmio;
        let computed = (|| {
            let raw = crate::intel_gpu_pcode::read_mem_latencies(mmio).ok()?;
            // No 16 Gb-DIMM latency adjustment input: the driver
            // does not model DIMMs, so the adjustment is off.
            let latencies = adjust_latencies(&raw, false);
            let params = WmParams {
                pixel_rate_khz: mode.pixel_clock_khz,
                htotal: mode.h_total as u32,
                width_px: mode.h_active as u32,
                cpp: fb.format.bits_per_pixel() / 8,
            };
            let mut wm = compute_plane_watermarks(&params, &latencies);
            if !wm.levels[0].enable {
                return None;
            }
            validate_watermarks(&mut wm, PRIMARY_DDB_END - PRIMARY_DDB_START);
            if !wm.levels[0].enable {
                return None;
            }
            Some(wm)
        })();
        let wm = match computed {
            Some(wm) => wm,
            None => {
                self.program_watermarks_preboot_gen9();
                return;
            }
        };
        let wm_base = self.pipe.base() + PLANE_WM_BASE_OFFSET;
        for (level, wm_level) in wm.levels.iter().enumerate() {
            self.mmio
                .write32(wm_base + level as u64 * 4, encode_wm_level(wm_level));
        }
        // No transition watermark on Gen9 (`WaDisableTWM`):
        // the TRANS register stays disabled, and there is no
        // SAGV watermark — the 0x18/0x1C offsets are WM levels
        // 6/7, written by the loop above.
        self.mmio.write32(wm_base + PLANE_WM_TRANS_OFFSET, 0);
        self.mmio.write32(
            self.pipe.base() + PLANE_BUF_CFG_OFFSET,
            encode_plane_buf_cfg(PRIMARY_DDB_START, PRIMARY_DDB_END),
        );
        compiler_fence(Ordering::SeqCst);
    }

    /// Gen11 pre-boot watermark basics: the same 160-block
    /// level-0 shape as the Gen12 fallback (same DBUF geometry
    /// and encoding — see `program_watermarks_gen11`).
    fn program_watermarks_preboot_gen11(&mut self) {
        write_wm_block_skl(
            self.mmio,
            self.pipe,
            PLANE_WM0_PREBOOT,
            PLANE_BUF_CFG_PREBOOT_A,
        );
    }

    /// Lane 1's basic programming, kept as the fallback when
    /// the latency-based algorithm cannot run: the PRM's
    /// "Display Buffer Allocation and Watermark Programming
    /// Prior to OS Boot" values (TGL PRM Vol. 12) — 160 DBUF
    /// blocks for this pipe's primary plane (PLANE_BUF_CFG =
    /// END 159 / START 0), level-0 watermark 160 blocks /
    /// 2 lines (0x800080A0), all higher levels, SAGV and
    /// transition watermarks disabled. The PRM scopes this
    /// programming to any resolution, linear surfaces,
    /// <=32 bpp, one universal plane per pipe.
    fn program_watermarks_preboot(&mut self) {
        if self.gen9_platform.is_some() {
            self.program_watermarks_preboot_gen9();
            return;
        }
        if self.gen11_platform.is_some() {
            self.program_watermarks_preboot_gen11();
            return;
        }
        write_wm_block(
            self.mmio,
            self.pipe,
            PLANE_WM0_PREBOOT,
            PLANE_BUF_CFG_PREBOOT_A,
        );
    }

    // ── DDI buffer enable ────────────────────────────────────

    /// Drive the physical output buffer enable. PRM Vol. 12
    /// §"DDI_BUF_CTL" — set the ENABLE bit and the lane-count
    /// field, then poll the (inverse-logic) IDLE_STATUS bit to
    /// see the buffer come alive.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_ddi.c
    /// (`intel_ddi_pre_enable_dp` + `intel_ddi_buf_enable`).
    fn enable_ddi_buffer(&mut self, lanes: u8) {
        use crate::intel_gpu_ddi::{
            build_ddi_buf_ctl, LaneCount, DDI_BUF_CTL_IDLE_STATUS, DDI_BUF_CTL_OFFSET,
        };
        let lane_count = match lanes {
            1 => LaneCount::X1,
            2 => LaneCount::X2,
            _ => LaneCount::X4,
        };
        let off = self.ddi.base() + DDI_BUF_CTL_OFFSET;
        let cur = self.mmio.read32(off);
        let val = cur | build_ddi_buf_ctl(lane_count);
        self.mmio.write32(off, val);
        compiler_fence(Ordering::SeqCst);
        // Wait for IDLE_STATUS to clear — buffer is now driving.
        // PRM allows 600 µs; we give 1 ms.
        let _ = wait_bit(self.mmio, off, DDI_BUF_CTL_IDLE_STATUS, false, 1_000_000);
    }

    // ── Final enables (PRM-mandated order) ───────────────────

    /// Enable this run's transcoder. TRANS_CONF.ENABLE +
    /// state-active poll per PRM Vol. 14 §"Transcoder Enable".
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_enable_transcoder`).
    fn enable_transcoder(&mut self) {
        use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE};
        let off = self.transcoder().conf_base() + PIPECONF_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur | PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        // Poll state-active. 100 ms cap matches i915's
        // `intel_wait_for_pipe_off` budget.
        let _ = wait_bit(self.mmio, off, PIPECONF_STATE, true, 100_000_000);
    }

    /// Program this run's VRR timings for the mode being committed
    /// (`intel_vrr_set_transcoder_timings`, called from transcoder
    /// configuration in Linux's `hsw_configure_cpu_transcoder`).
    ///
    /// Recomputes from the mode this run commits and the sink range
    /// discovery published — the stored timings are from the previous
    /// modeset (or install) and describe the previous mode, so they
    /// are never programmed as-is. A missing range (or an uncappable
    /// mode) clears the stored timings and leaves fixed refresh; the
    /// range itself is a sink property that only changes on sink
    /// change, and the DP paths' post-modeset recompute refreshes it
    /// from discovery, so a stale range can lag by at most one modeset.
    /// Programs the limits only when VRR is requested for this CRTC.
    fn program_vrr_for_modeset(&mut self, mode: &Mode) -> Result<(), ModesetError> {
        let crtc = self.crtc_id();
        let ip = self.vrr_ip();
        // CMRR auto-enable is eDP-only: the orchestrator knows the port,
        // not the connector type, so DDI A (the built-in panel) maps to
        // EmbeddedDisplayPort and every other port conservatively maps to
        // Other (no auto-enable). The DP/HDMI activate paths call the
        // recompute with their own kind; this must agree with the
        // post-modeset recompute in `modeset_display_family` for the
        // same CRTC, or the auto-enable state would flap between the two.
        let kind = match self.ddi {
            Ddi::A => crate::intel_gpu_vrr::VrrConnectorKind::EmbeddedDisplayPort,
            _ => crate::intel_gpu_vrr::VrrConnectorKind::Other,
        };
        let timings = crate::intel_gpu_vrr::recompute_timings_for_modeset(
            crtc,
            mode,
            crate::intel_gpu_vrr::VRR_STATE.range(crtc),
            ip,
            crate::intel_gpu_vrr::VrrComputeOpts::default(),
            kind,
        );
        if crate::intel_gpu_vrr::VRR_STATE.is_enabled(crtc) {
            if let Some(timings) = timings {
                let trans = crate::intel_gpu_vrr::VrrTranscoder::for_crtc(crtc);
                crate::intel_gpu_vrr::program_vrr_timings(self.mmio, trans, ip, &timings)
                    .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
            }
        }
        Ok(())
    }

    /// Enable VRR after the transcoder is live (`intel_vrr_enable`
    /// runs after `intel_enable_transcoder` in Linux's
    /// `intel_crtc_enable`). Only when VRR is requested and timings
    /// were programmed for this run; a missing-timing run stays at
    /// fixed refresh.
    fn enable_vrr_for_modeset(&mut self) -> Result<(), ModesetError> {
        let crtc = self.crtc_id();
        if crate::intel_gpu_vrr::VRR_STATE.is_enabled(crtc) {
            if let Some(timings) = crate::intel_gpu_vrr::VRR_STATE.timings(crtc) {
                let ip = self.vrr_ip();
                let trans = crate::intel_gpu_vrr::VrrTranscoder::for_crtc(crtc);
                crate::intel_gpu_vrr::vrr_enable(self.mmio, trans, ip, timings.guardband)
                    .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
            }
        }
        Ok(())
    }

    /// Disable VRR before the transcoder stops (`intel_vrr_disable`
    /// runs before the transcoder disable in Linux's
    /// `intel_crtc_disable`). Best effort: the pipeline is being torn
    /// down regardless, so a `NoDevice`/timeout here must not fail
    /// the disable — the failure surfaces through
    /// `request_vrr_enabled`'s return value on the direct toggle path.
    fn disable_vrr_for_modeset(&mut self) {
        let crtc = self.crtc_id();
        let trans = crate::intel_gpu_vrr::VrrTranscoder::for_crtc(crtc);
        let _ = crate::intel_gpu_vrr::vrr_disable(self.mmio, trans, self.vrr_ip());
    }

    /// Enable this run's pipe. Same register block as the
    /// transcoder on Gen12 (PIPE_CONF / TRANS_CONF are aliased
    /// at the per-pipe block); writing the same ENABLE bit at
    /// the pipe's base turns on the per-pipe raster engine.
    ///
    /// Reference: Linux drivers/gpu/drm/i915/display/intel_pipe.c
    /// (`intel_enable_pipe`).
    fn enable_pipe(&mut self) {
        use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE};
        let off = self.pipe.base() + PIPECONF_OFFSET;
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
        let budget = narf_time::wall::ns_to_cycles(20_000_000);
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

// ── Watermark / DBUF allocation registers (plane 1, pipe A) ────
// Absolute bases: PLANE_WM_1_A_0 = 0x70240, PLANE_WM_SAGV_1_A =
// 0x70258, PLANE_WM_SAGV_TRANS_1_A = 0x7025C, PLANE_WM_TRANS_1_A
// = 0x70268, PLANE_BUF_CFG_1_A = 0x7027C — expressed here as
// offsets from Pipe::A.base() (0x70000).

pub(crate) const PLANE_WM_BASE_OFFSET: u64 = 0x0240;
const PLANE_WM_SAGV_OFFSET: u64 = 0x0018;
const PLANE_WM_SAGV_TRANS_OFFSET: u64 = 0x001C;
const PLANE_WM_TRANS_OFFSET: u64 = 0x0028;
pub(crate) const PLANE_BUF_CFG_OFFSET: u64 = 0x027C;
/// PRM pre-OS-boot level-0 watermark: enable | 2 lines | 160 blocks.
const PLANE_WM0_PREBOOT: u32 = 0x8000_80A0;
/// PRM pre-OS-boot DBUF allocation for Pipe A: END 159, START 0.
const PLANE_BUF_CFG_PREBOOT_A: u32 = 0x009F_0000;

/// `PLANE_WM` level-0 value for a plane allocated `blocks` DBUF
/// blocks, in the PRM's basic programming shape: WM enable,
/// 2 lines, `blocks` in the blocks field (bits [13:0]).
/// `plane_wm0_for_blocks(160)` is exactly
/// [`PLANE_WM0_PREBOOT`] — the pre-boot programming is this
/// shape at 160 blocks (pinned by a fixture).
pub const fn plane_wm0_for_blocks(blocks: u16) -> u32 {
    (1 << 31) | (2 << 14) | (blocks as u32 & 0x3FFF)
}

/// `PLANE_BUF_CFG` value for the DBUF block range
/// `start..=end`: END in bits [26:16], START in bits [10:0].
/// `dbuf_buf_cfg(0, 159)` is exactly [`PLANE_BUF_CFG_PREBOOT_A`].
pub const fn dbuf_buf_cfg(start: u16, end: u16) -> u32 {
    ((end as u32 & 0x7FF) << 16) | (start as u32 & 0x7FF)
}

/// Write one pipe's watermark block + DBUF allocation: level-0
/// watermark `wm0`, levels 1–5 / SAGV / transition disabled,
/// PLANE_BUF_CFG `buf_cfg`. The PLANE_SURF write of a later
/// modeset (or the plane's next vblank latch) applies them.
fn write_wm_block<M: MmioWindow + ?Sized>(mmio: &M, pipe: Pipe, wm0: u32, buf_cfg: u32) {
    let wm_base = pipe.base() + PLANE_WM_BASE_OFFSET;
    mmio.write32(wm_base, wm0);
    for level in 1..6u64 {
        mmio.write32(wm_base + level * 4, 0);
    }
    mmio.write32(wm_base + PLANE_WM_SAGV_OFFSET, 0);
    mmio.write32(wm_base + PLANE_WM_SAGV_TRANS_OFFSET, 0);
    mmio.write32(wm_base + PLANE_WM_TRANS_OFFSET, 0);
    mmio.write32(pipe.base() + PLANE_BUF_CFG_OFFSET, buf_cfg);
    compiler_fence(Ordering::SeqCst);
}

/// The SKL form of `write_wm_block`: level-0 watermark
/// `wm0`, levels 1–7 and the transition watermark disabled,
/// PLANE_BUF_CFG `buf_cfg`. Gen11 and Gen9 share the SKL
/// universal-plane layout (8 latency levels, no SAGV
/// watermark — the offsets 0x18/0x1C are WM levels 6/7
/// here, so the Gen12 writer (which writes SAGV zeros there)
/// must never run on a Gen11 or Gen9 pipe.
fn write_wm_block_skl<M: MmioWindow + ?Sized>(mmio: &M, pipe: Pipe, wm0: u32, buf_cfg: u32) {
    let wm_base = pipe.base() + PLANE_WM_BASE_OFFSET;
    mmio.write32(wm_base, wm0);
    for level in 1..8u64 {
        mmio.write32(wm_base + level * 4, 0);
    }
    mmio.write32(wm_base + PLANE_WM_TRANS_OFFSET, 0);
    mmio.write32(pipe.base() + PLANE_BUF_CFG_OFFSET, buf_cfg);
    compiler_fence(Ordering::SeqCst);
}

/// Reprogram an already-live pipe's DBUF share (#1017): when
/// the set of active pipes changes, the multi-pipe coordinator
/// rewrites every surviving pipe's watermark block and
/// PLANE_BUF_CFG with its new share of the DBUF pool, exactly
/// as i915 recomputes DBUF allocations on every atomic commit
/// that changes the active-pipe set.
pub fn program_pipe_dbuf_share<M: MmioWindow + ?Sized>(
    mmio: &M,
    pipe: Pipe,
    start_block: u16,
    end_block: u16,
) {
    write_wm_block(
        mmio,
        pipe,
        plane_wm0_for_blocks(end_block - start_block + 1),
        dbuf_buf_cfg(start_block, end_block),
    );
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
    let budget = narf_time::wall::ns_to_cycles(timeout_ns);
    let start = narf_time::now_cycles();
    loop {
        // read_poll_timeout: sample expiry before the read, so the read
        // that ends a timed-out wait follows the deadline.
        let expired = narf_time::now_cycles().wrapping_sub(start) > budget;
        let v = mmio.read32(off);
        if v == u32::MAX {
            return false;
        }
        let asserted = v & mask != 0;
        if asserted == want_set {
            return true;
        }
        if expired {
            return false;
        }
        core::hint::spin_loop();
    }
}

fn validate_framebuffer(fb: &Framebuffer) -> Result<(), ModesetError> {
    // Gen12 linear-surface stride must be multiple of 64.
    if fb.stride_bytes == 0 || fb.stride_bytes % 64 != 0 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    // PLANE_SURF carries a page-aligned, 32-bit GGTT offset.
    if fb.phys_addr & 0xFFF != 0 || fb.phys_addr > u64::from(u32::MAX) {
        // Page alignment for GGTT mapping.
        return Err(ModesetError::InvalidFramebuffer);
    }
    Ok(())
}

/// Validate the plane before either orchestrator disables a live pipeline.
pub(crate) fn validate_framebuffer_sized(
    fb: &Framebuffer,
    w: u16,
    h: u16,
) -> Result<(), ModesetError> {
    validate_framebuffer(fb)?;
    if fb.stride_bytes < u32::from(w) * 4 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    let end = fb.phys_addr + u64::from(fb.stride_bytes) * u64::from(h);
    if end > 1u64 << 32 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    crate::intel_gpu_pipes::build_primary_plane(
        w,
        h,
        fb.stride_bytes,
        fb.phys_addr as u32,
        crate::intel_gpu_pipes::PixelFormat::Argb8888,
    )
    .map_err(|_| ModesetError::InvalidFramebuffer)?;
    Ok(())
}

pub(crate) fn validate_framebuffer_mode(fb: &Framebuffer, mode: &Mode) -> Result<(), ModesetError> {
    validate_framebuffer_sized(fb, mode.h_active, mode.v_active)
}

/// Internal-panel modeset dispatch shared by takeover and resume.
/// `Some(mode)` restores exactly that timing; `None` discovers it over AUX.
pub(crate) fn modeset_display<M: MmioWindow + ?Sized>(
    mmio: &M,
    generation: crate::intel_gpu::Generation,
    fb: &Framebuffer,
    mode: Option<&Mode>,
) -> Result<Mode, ModesetError> {
    // No chip: the Gen11 platform is unknown, so the IceLake
    // arm fails closed (see `modeset_display_family`); the
    // Gen9 platform and SKU family are unknown too, so the
    // Skylake arm fails closed the same way.
    modeset_display_family(mmio, generation, None, false, None, None, None, fb, mode)
}

/// The pipe side of a YCbCr 4:2:0 HDMI stream on display 11+, with the pipe
/// off: a 1:1 pipe scaler (the 4:2:0 downsampler; `skl_update_scaler_crtc`
/// requires one for `INTEL_OUTPUT_FORMAT_YCBCR420`), then the BT.709
/// limited-range RGB-to-YCbCr output CSC (`ilk_csc_matrix_rgb_to_ycbcr`,
/// `icl_update_output_csc`: pre-offsets, coefficients, post-offsets) and
/// `ICL_OUTPUT_CSC_ENABLE`. The `PIPE_MISC` YUV bits are the caller's
/// (`bdw_set_pipe_misc`).
pub(crate) fn program_ycbcr420_pipe<M: MmioWindow + ?Sized>(io: &M, pipe: Pipe, mode: &Mode) {
    for (reg, val) in ycbcr420_scaler(mode).enable_writes(pipe) {
        io.write32(reg, val);
    }
    let base = PIPE_CSC_OUTPUT_COEFF_RY_GY + pipe as u64 * PIPE_COLOR_STRIDE;
    const COEFF: [u32; 9] = [
        0x1e08, 0x9cc0, 0xb528, 0x2ba8, 0x09d8, 0x37e8, 0xbce8, 0x9ad8, 0x1e08,
    ];
    const POSTOFF: [u32; 3] = [0x0800, 0x0100, 0x0800];
    for reg in [0x18u64, 0x1c, 0x20] {
        io.write32(base + reg, 0);
    }
    for (row, reg) in [0x00u64, 0x08, 0x10].into_iter().enumerate() {
        io.write32(base + reg, COEFF[row * 3] << 16 | COEFF[row * 3 + 1]);
        io.write32(base + reg + 4, COEFF[row * 3 + 2] << 16);
    }
    for (i, reg) in [0x24u64, 0x28, 0x2c].into_iter().enumerate() {
        io.write32(base + reg, POSTOFF[i]);
    }
    let csc_mode = PIPE_CSC_MODE + pipe as u64 * PIPE_COLOR_STRIDE;
    let cur = io.read32(csc_mode);
    io.write32(csc_mode, cur | ICL_OUTPUT_CSC_ENABLE);
    compiler_fence(Ordering::SeqCst);
}

/// The 1:1 pipe scaler a 4:2:0 stream runs through (`skl_pfit_enable`:
/// scaler 0, normal mode, the medium filter, the full active window).
pub(crate) fn ycbcr420_scaler(mode: &Mode) -> crate::intel_gpu_xelpg_scaler::PipeScaler {
    use crate::intel_gpu_xelpg_scaler::{Filter, PipeScaler, Window};
    PipeScaler {
        id: 0,
        window: Window {
            x: 0,
            y: 0,
            width: u32::from(mode.h_active),
            height: u32::from(mode.v_active),
        },
        hscale: 0x10000,
        vscale: 0x10000,
        filter: Filter::Default,
        mode: 0,
    }
}

/// Undo [`program_ycbcr420_pipe`] once the pipe is down: detach the pipe's
/// scalers (`skl_scaler_disable`), drop the output CSC enable and the
/// `PIPE_MISC` YUV encoding.
pub(crate) fn clear_ycbcr420_pipe<M: MmioWindow + ?Sized>(io: &M, pipe: Pipe) {
    for (reg, val) in crate::intel_gpu_xelpg_scaler::disable_writes(pipe) {
        io.write32(reg, val);
    }
    let csc_mode = PIPE_CSC_MODE + pipe as u64 * PIPE_COLOR_STRIDE;
    let cur = io.read32(csc_mode);
    io.write32(csc_mode, cur & !ICL_OUTPUT_CSC_ENABLE);
    let misc = pipe.base() + 0x30;
    let cur = io.read32(misc);
    io.write32(misc, cur & !PIPE_MISC_YUV_MASK);
    compiler_fence(Ordering::SeqCst);
}

/// `PIPE_MISC`'s YCbCr 4:2:0 encoding (`bdw_set_pipe_misc`): YUV420 enable,
/// full-blend mode and the YUV output colorspace.
pub(crate) const PIPE_MISC_YCBCR420: u32 =
    PIPE_MISC_YUV420_ENABLE | PIPE_MISC_YUV420_MODE_FULL_BLEND | PIPE_MISC_OUTPUT_COLORSPACE_YUV;

/// Exact known PCI family; no P/S/N inference from the broad generation.
pub(crate) fn gen12_family_for_chip(
    chip: crate::intel_gpu::ChipInfo,
) -> Option<crate::intel_gpu_gt::Gen12Platform> {
    use crate::intel_gpu::Generation;
    match crate::intel_gpu_gt::GtPlatform::from_pci(chip.vid, chip.did) {
        Some(crate::intel_gpu_gt::GtPlatform::Gen12(family))
            if (chip.generation == Generation::TigerLake
                && family == crate::intel_gpu_gt::Gen12Platform::TigerLake)
                || (chip.generation == Generation::RocketLake
                    && family == crate::intel_gpu_gt::Gen12Platform::RocketLake)
                || (chip.generation == Generation::AlderLake
                    && matches!(
                        family,
                        crate::intel_gpu_gt::Gen12Platform::AlderLakeS
                            | crate::intel_gpu_gt::Gen12Platform::AlderLakeP
                            | crate::intel_gpu_gt::Gen12Platform::AlderLakeN
                    )) =>
        {
            Some(family)
        }
        _ => None,
    }
}

/// The Gen11 mirror of `gen12_family_for_chip`: the exact
/// Ice Lake / Elkhart Lake / Jasper Lake product for a chip
/// whose generation is IceLake, from the PCI device ID.
pub(crate) fn gen11_family_for_chip(
    chip: crate::intel_gpu::ChipInfo,
) -> Option<crate::intel_gpu_gt::Gen11Platform> {
    use crate::intel_gpu::Generation;
    match crate::intel_gpu_gt::GtPlatform::from_pci(chip.vid, chip.did) {
        Some(crate::intel_gpu_gt::GtPlatform::Gen11(platform))
            if chip.generation == Generation::IceLake =>
        {
            Some(platform)
        }
        _ => None,
    }
}

/// The Gen9 mirror of `gen12_family_for_chip`: the exact
/// Skylake / Kaby Lake / Comet Lake product for a chip whose
/// generation is Skylake, from the PCI device ID.
pub(crate) fn gen9_family_for_chip(
    chip: crate::intel_gpu::ChipInfo,
) -> Option<crate::intel_gpu_gt::Gen9Platform> {
    use crate::intel_gpu::Generation;
    match crate::intel_gpu_gt::GtPlatform::from_pci(chip.vid, chip.did) {
        Some(crate::intel_gpu_gt::GtPlatform::Gen9(platform))
            if chip.generation == Generation::Skylake =>
        {
            Some(platform)
        }
        _ => None,
    }
}

pub(crate) fn modeset_display_for_chip<M: MmioWindow + ?Sized>(
    mmio: &M,
    chip: crate::intel_gpu::ChipInfo,
    fb: &Framebuffer,
    mode: Option<&Mode>,
) -> Result<Mode, ModesetError> {
    let family = gen12_family_for_chip(chip);
    if matches!(
        chip.generation,
        crate::intel_gpu::Generation::TigerLake
            | crate::intel_gpu::Generation::RocketLake
            | crate::intel_gpu::Generation::AlderLake
    ) && family.is_none()
    {
        return Err(ModesetError::UnsupportedGeneration);
    }
    // Gen11: the platform is required — without the exact
    // product the CDCLK voltage levels and DDI table selection
    // cannot be resolved, so an unmapped IceLake chip fails
    // closed here rather than modesetting as a wrong product.
    let gen11 = if chip.generation == crate::intel_gpu::Generation::IceLake {
        Some(match gen11_family_for_chip(chip) {
            Some(platform) => platform,
            None => return Err(ModesetError::UnsupportedGeneration),
        })
    } else {
        None
    };
    // Gen9: the platform is required for the same reason —
    // the SKL CDCLK VCO rule and DDI table selection need the
    // exact product — and so is the SKU family, which picks
    // the U/Y DDI tables from the PCI device ID.
    let (gen9, gen9_sku) = if chip.generation == crate::intel_gpu::Generation::Skylake {
        let platform = match gen9_family_for_chip(chip) {
            Some(platform) => platform,
            None => return Err(ModesetError::UnsupportedGeneration),
        };
        (
            Some(platform),
            Some(crate::intel_gpu_gen9_ddi::sku_family_for_did(chip.did)),
        )
    } else {
        (None, None)
    };
    modeset_display_family(
        mmio,
        chip.generation,
        family,
        crate::intel_gpu_gen12_combo_phy::is_tgl_uy(chip.did),
        gen11,
        gen9,
        gen9_sku,
        fb,
        mode,
    )
}

/// The per-generation panel entry point: one parameter per
/// generation's platform option. The arity is the dispatch
/// surface, not a smell to bundle away.
#[allow(clippy::too_many_arguments)]
fn modeset_display_family<M: MmioWindow + ?Sized>(
    mmio: &M,
    generation: crate::intel_gpu::Generation,
    family: Option<crate::intel_gpu_gt::Gen12Platform>,
    tgl_uy: bool,
    gen11: Option<crate::intel_gpu_gt::Gen11Platform>,
    gen9: Option<crate::intel_gpu_gt::Gen9Platform>,
    gen9_sku: Option<crate::intel_gpu_gen9_ddi::SkuFamily>,
    fb: &Framebuffer,
    mode: Option<&Mode>,
) -> Result<Mode, ModesetError> {
    use crate::intel_gpu::Generation;
    // This function is the built-in panel (DDI A / Port A, i.e. eDP)
    // modeset: takeover, resume re-light, and the Xe_LPG takeover all
    // route through it. External DP never comes here — it has its own
    // activate path (`intel_gpu_dp`) that calls the recompute with
    // `DisplayPort`.
    let result = match generation {
        Generation::TigerLake | Generation::AlderLake => {
            let mut ms = Modeset::new(mmio, Ddi::A);
            if let Some(family) = family {
                ms.set_gen12_family(family);
            }
            ms.set_tgl_uy(tgl_uy);
            // The built-in panel's VBT HOBL / low-vswing bits,
            // installed by probe (`intel_gpu_vbt::install_for_probe`);
            // without a VBT both stay clear and the DP tables are
            // selected.
            let edp_signal = crate::intel_gpu_gen12_combo_phy::installed_edp_signal();
            ms.set_edp_hobl(edp_signal.hobl());
            ms.set_edp_low_vswing(edp_signal.low_vswing());
            match mode {
                Some(mode) => ms.modeset_fixed(fb, mode),
                None => ms.modeset(fb, None),
            }
        }
        Generation::IceLake => {
            // Gen11 internal-panel modeset (Lane 5): the ICL
            // CDCLK / DPLL / watermark / DDI-table path in the
            // Linux ICL order, fixture-validated, silicon
            // untested. The platform must be known (the
            // no-chip `modeset_display` passes None and fails
            // closed below). Only the low-vswing VBT bit rides
            // into the table selection — there is no HOBL table
            // on ICL, so `edp_hobl` stays clear.
            let Some(platform) = gen11 else {
                return Err(ModesetError::UnsupportedGeneration);
            };
            let mut ms = Modeset::new(mmio, Ddi::A);
            ms.set_gen11_platform(platform);
            let edp_signal = crate::intel_gpu_gen12_combo_phy::installed_edp_signal();
            ms.set_edp_low_vswing(edp_signal.low_vswing());
            match mode {
                Some(mode) => ms.modeset_fixed(fb, mode),
                None => ms.modeset(fb, None),
            }
        }
        Generation::Skylake => {
            // Gen9 internal-panel modeset (Lane 5): the SKL
            // CDCLK / DPLL / watermark / DDI-table path in the
            // Linux SKL order, fixture-validated, silicon
            // untested. The platform and SKU family must be
            // known (the no-chip `modeset_display` passes None
            // and fails closed below). Only the low-vswing VBT
            // bit rides into the table selection — there is no
            // HOBL table on SKL, so `edp_hobl` stays clear.
            // DMC is REQUIRED on Gen9 (the Q5 default,
            // mirroring Gen12): without a loaded SKL/KBL DMC
            // program the modeset refuses here, before any
            // register is written.
            let Some(platform) = gen9 else {
                return Err(ModesetError::UnsupportedGeneration);
            };
            if !crate::intel_gpu_gen9_dmc::gen9_dmc_loaded() {
                return Err(ModesetError::DmcUnavailable);
            }
            let sku = gen9_sku.ok_or(ModesetError::UnsupportedGeneration)?;
            let mut ms = Modeset::new(mmio, Ddi::A);
            ms.set_gen9_platform(platform);
            ms.set_gen9_sku_family(sku);
            let edp_signal = crate::intel_gpu_gen12_combo_phy::installed_edp_signal();
            ms.set_edp_low_vswing(edp_signal.low_vswing());
            match mode {
                Some(mode) => ms.modeset_fixed(fb, mode),
                None => ms.modeset(fb, None),
            }
        }
        Generation::MeteorLake => {
            let mut ms = crate::intel_gpu_modeset_xelpg::XeLpgModeset::new(
                mmio,
                crate::intel_gpu_xelpg::XeLpgPort::A,
            );
            match mode {
                Some(mode) => ms.modeset_fixed(fb, mode),
                None => ms.modeset(fb, None),
            }
        }
        // Rocket Lake / Lunar Lake / Panther Lake have no
        // panel modeset in this module (owned routes elsewhere
        // or not modeled).
        Generation::RocketLake | Generation::LunarLake | Generation::PantherLake => {
            Err(ModesetError::UnsupportedGeneration)
        }
    };
    if let Ok(committed) = &result {
        // Per-modeset VRR/CMRR compute for the panel (#1771): a
        // fractional-refresh eDP mode auto-enables CMRR from the
        // committed mode. The range is whatever discovery has
        // published for CRTC 1 (`None` until eDP discovery publishes
        // the panel range); the CMRR auto-enable does not require a
        // range — see `recompute_timings_for_modeset`.
        let ip = crate::intel_gpu_vrr::DisplayVrrIp::from_generation(generation);
        let range = crate::intel_gpu_vrr::VRR_STATE.range(1);
        crate::intel_gpu_vrr::recompute_timings_for_modeset(
            1,
            committed,
            range,
            ip,
            crate::intel_gpu_vrr::VrrComputeOpts::default(),
            crate::intel_gpu_vrr::VrrConnectorKind::EmbeddedDisplayPort,
        );
    }
    result
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

    impl Default for FakeMmio {
        fn default() -> Self {
            Self::new()
        }
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
            // Model the actual common RGB bypass writes; canned power/PLL
            // state observations below retain their independent behavior.
            if matches!(off, 0x70034 | 0x4a480 | 0x49028 | 0x701c8 | 0x701cc) {
                if let Some((_, value)) = self.writes.borrow().iter().rev().find(|(r, _)| *r == off)
                {
                    return *value;
                }
            }
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

    fn smoke_takeover_requires_enabled_firmware_pipe() -> TestResult {
        for generation in [
            crate::intel_gpu::Generation::TigerLake,
            crate::intel_gpu::Generation::AlderLake,
            crate::intel_gpu::Generation::MeteorLake,
            crate::intel_gpu::Generation::PantherLake,
        ] {
            let mmio = FakeMmio::new();
            if takeover_display_with(&mmio, generation).is_some() {
                return TestResult::Fail("disabled firmware pipe must not produce a mode");
            }
            if !mmio.writes.borrow().is_empty() {
                return TestResult::Fail("disabled firmware pipe must not be programmed");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_takeover_requires_enabled_firmware_pipe
    );

    fn smoke_display_dispatch_rejects_unmodelled_generation() -> TestResult {
        struct NoMmio;
        impl MmioWindow for NoMmio {
            fn read32(&self, _: u64) -> u32 {
                panic!("unsupported generation touched MMIO")
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("unsupported generation touched MMIO")
            }
        }
        if modeset_display(
            &NoMmio,
            crate::intel_gpu::Generation::PantherLake,
            &fb_1080p(),
            Some(&Mode::VESA_1024X768_60),
        ) != Err(ModesetError::UnsupportedGeneration)
        {
            return TestResult::Fail("Panther Lake must refuse display programming");
        }
        if takeover_display_with(&NoMmio, crate::intel_gpu::Generation::PantherLake).is_some() {
            return TestResult::Fail("Panther Lake must refuse takeover");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_display_dispatch_rejects_unmodelled_generation
    );

    fn smoke_fixed_modeset_rejects_invalid_surface_before_mmio() -> TestResult {
        let valid = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 4096,
            format: PixelFormat::Xrgb8888,
        };
        let mode = Mode::VESA_1024X768_60;
        // Zero/short/misaligned pitch, misaligned or truncated GGTT address,
        // and a valid base whose pitched surface crosses the 32-bit window.
        for fb in [
            Framebuffer {
                stride_bytes: 0,
                ..valid
            },
            Framebuffer {
                stride_bytes: 4032,
                ..valid
            },
            Framebuffer {
                stride_bytes: 4097,
                ..valid
            },
            Framebuffer {
                phys_addr: 0x100_0001,
                ..valid
            },
            Framebuffer {
                phys_addr: 0x1_0000_0000,
                ..valid
            },
            Framebuffer {
                phys_addr: 0xffff_f000,
                ..valid
            },
        ] {
            for generation in [
                crate::intel_gpu::Generation::TigerLake,
                crate::intel_gpu::Generation::AlderLake,
                crate::intel_gpu::Generation::MeteorLake,
            ] {
                let mmio = FakeMmio::new();
                if modeset_display(&mmio, generation, &fb, Some(&mode))
                    != Err(ModesetError::InvalidFramebuffer)
                    || !mmio.writes.borrow().is_empty()
                {
                    return TestResult::Fail("invalid surface must fail before display writes");
                }
            }
        }
        for mode in [
            Mode {
                h_active: 0,
                ..mode
            },
            Mode {
                v_active: 0,
                ..mode
            },
            Mode {
                v_active: 8193,
                ..mode
            },
        ] {
            let mmio = FakeMmio::new();
            if modeset_display(
                &mmio,
                crate::intel_gpu::Generation::TigerLake,
                &valid,
                Some(&mode),
            ) != Err(ModesetError::InvalidFramebuffer)
                || !mmio.writes.borrow().is_empty()
            {
                return TestResult::Fail("unencodable plane geometry must fail before writes");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_fixed_modeset_rejects_invalid_surface_before_mmio
    );

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

    fn smoke_enable_pg3_for_pipe_b() -> TestResult {
        // Multi-pipe (#1017): Pipe B lives under PG3. With the
        // PG3 STATE bit granted, the enable must succeed and
        // the REQUEST write must carry the PG3 request bit.
        let mut mmio = FakeMmio::new();
        mmio.state_offset = super::PWR_WELL_CTL2;
        mmio.state_value = super::pwr_well_state(super::PowerWell::Pg3 as u32);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::B);
        match ms.enable_pipe_power_well(Pipe::B) {
            Ok(()) => {}
            Err(e) => {
                let _ = e;
                return TestResult::Fail("PG3 enable returned error with state asserted");
            }
        }
        let req = super::pwr_well_req(super::PowerWell::Pg3 as u32);
        let writes = mmio.writes_to(super::PWR_WELL_CTL2);
        if writes.iter().all(|w| (w & req) == 0) {
            return TestResult::Fail("PG3 REQUEST bit never set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_modeset", smoke_enable_pg3_for_pipe_b);

    /// Rocket Lake has no PW_2 (`rkl_power_wells`): Pipe A requests no
    /// per-pipe well, Pipe B requests PW_3 and Pipe C PW_4, and no run
    /// ever requests PW_2.
    fn smoke_rkl_pipe_power_wells_skip_pw2() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        let pg2 = super::pwr_well_req(super::PowerWell::Pg2 as u32);
        for (pipe, well) in [
            (Pipe::A, None),
            (Pipe::B, Some(super::PowerWell::Pg3)),
            (Pipe::C, Some(super::PowerWell::Pg4)),
        ] {
            let mut mmio = FakeMmio::new();
            mmio.state_offset = super::PWR_WELL_CTL2;
            mmio.state_value = well.map_or(0, |w| super::pwr_well_state(w as u32));
            let mut ms = Modeset::for_pipe(&mmio, Ddi::B, pipe);
            ms.set_gen12_family(Gen12Platform::RocketLake);
            if ms.enable_pipe_power_well(pipe).is_err() {
                return TestResult::Fail("RKL per-pipe well must enable");
            }
            let writes = mmio.writes_to(super::PWR_WELL_CTL2);
            match well {
                None if !writes.is_empty() => {
                    return TestResult::Fail("RKL Pipe A must request no per-pipe well");
                }
                Some(w)
                    if writes
                        .iter()
                        .all(|v| v & super::pwr_well_req(w as u32) == 0) =>
                {
                    return TestResult::Fail("RKL Pipe B/C must request PW_3/PW_4");
                }
                _ => {}
            }
            if writes.iter().any(|v| v & pg2 != 0) {
                return TestResult::Fail("RKL must never request PW_2");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_rkl_pipe_power_wells_skip_pw2
    );

    fn smoke_enable_pg4_for_pipe_c() -> TestResult {
        // Pipe C lives under PG4 (#1017).
        let mut mmio = FakeMmio::new();
        mmio.state_offset = super::PWR_WELL_CTL2;
        mmio.state_value = super::pwr_well_state(super::PowerWell::Pg4 as u32);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::C, Pipe::C);
        match ms.enable_pipe_power_well(Pipe::C) {
            Ok(()) => {}
            Err(e) => {
                let _ = e;
                return TestResult::Fail("PG4 enable returned error with state asserted");
            }
        }
        let req = super::pwr_well_req(super::PowerWell::Pg4 as u32);
        let writes = mmio.writes_to(super::PWR_WELL_CTL2);
        if writes.iter().all(|w| (w & req) == 0) {
            return TestResult::Fail("PG4 REQUEST bit never set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_modeset", smoke_enable_pg4_for_pipe_c);

    fn smoke_enable_pg_rejects_pipe_d() -> TestResult {
        // Pipe D is outside this driver's arbitration set: the
        // refusal is immediate and names no well — no CTL2
        // write may happen at all.
        let mmio = FakeMmio::new();
        let mut ms = Modeset::for_pipe(&mmio, Ddi::A, Pipe::D);
        match ms.enable_pipe_power_well(Pipe::D) {
            Err(ModesetError::PowerWellTimeout) => {}
            other => {
                let _ = other;
                return TestResult::Fail("Pipe D must be refused");
            }
        }
        if !mmio.writes_to(super::PWR_WELL_CTL2).is_empty() {
            return TestResult::Fail("Pipe D refusal must not touch PWR_WELL_CTL2");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_enable_pg_rejects_pipe_d
    );

    fn smoke_dbuf_share_encodings_match_preboot() -> TestResult {
        // The share encodings must reproduce the PRM pre-boot
        // constants at the pre-boot allocation: 160 blocks at
        // (0, 159). If either drifts, single-pipe programming
        // silently changes shape.
        if super::plane_wm0_for_blocks(160) != super::PLANE_WM0_PREBOOT {
            return TestResult::Fail("WM0(160 blocks) != PLANE_WM0_PREBOOT");
        }
        if super::dbuf_buf_cfg(0, 159) != super::PLANE_BUF_CFG_PREBOOT_A {
            return TestResult::Fail("BUF_CFG(0,159) != PLANE_BUF_CFG_PREBOOT_A");
        }
        // program_pipe_dbuf_share writes the pipe's own block:
        // Pipe B share (512, 1023) → BUF_CFG at 0x7127C.
        let mmio = FakeMmio::new();
        super::program_pipe_dbuf_share(&mmio, Pipe::B, 512, 1023);
        let buf_cfg_off = Pipe::B.base() + super::PLANE_BUF_CFG_OFFSET;
        if mmio.writes_to(buf_cfg_off) != alloc::vec![super::dbuf_buf_cfg(512, 1023)] {
            return TestResult::Fail("Pipe B PLANE_BUF_CFG share not written");
        }
        let wm_off = Pipe::B.base() + super::PLANE_WM_BASE_OFFSET;
        if mmio.writes_to(wm_off) != alloc::vec![super::plane_wm0_for_blocks(512)] {
            return TestResult::Fail("Pipe B PLANE_WM0 share not written");
        }
        // And nothing lands in Pipe A's block.
        if !mmio
            .writes_to(Pipe::A.base() + super::PLANE_BUF_CFG_OFFSET)
            .is_empty()
        {
            return TestResult::Fail("share reprogram leaked into Pipe A");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_dbuf_share_encodings_match_preboot
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
        match ms.program_dpll_with_rate(&mode, LinkRate::DpRbr) {
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

    fn smoke_program_transcoder_vblank_start_follows_display_version() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        use crate::intel_gpu_pipes::{Transcoder, TRANS_VBLANK_OFFSET, TRANS_VTOTAL_OFFSET};
        // intel_set_transcoder_timings for 1024x768 (vtotal 806): display 12
        // (TGL, ADL-S) writes VBLANK_START vactive - 1 = 767 with
        // VBLANK_END 805; display 13 (ADL-P, ADL-N) writes VBLANK_END only.
        let reg = Transcoder::A.base() + TRANS_VBLANK_OFFSET;
        for (family, expected) in [
            (None, (805 << 16) | 767),
            (Some(Gen12Platform::TigerLake), (805 << 16) | 767),
            (Some(Gen12Platform::AlderLakeS), (805 << 16) | 767),
            (Some(Gen12Platform::AlderLakeP), 805 << 16),
            (Some(Gen12Platform::AlderLakeN), 805 << 16),
        ] {
            let mmio = FakeMmio::new();
            let mut ms = Modeset::new(&mmio, Ddi::A);
            if let Some(family) = family {
                ms.set_gen12_family(family);
            }
            ms.program_transcoder(&Mode::VESA_1024X768_60);
            if mmio.writes_to(reg) != alloc::vec![expected] {
                return TestResult::Fail("TRANS_VBLANK must follow the display version");
            }
            if mmio.writes_to(Transcoder::A.base() + TRANS_VTOTAL_OFFSET)
                != alloc::vec![(805 << 16) | 767]
            {
                return TestResult::Fail("TRANS_VTOTAL keeps its active field");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_transcoder_vblank_start_follows_display_version
    );

    fn smoke_program_pipe_writes_srcsz() -> TestResult {
        use crate::intel_gpu_pipes::{Pipe as PipeIdx, PIPE_SRCSZ_OFFSET};
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.program_pipe(&Mode::VESA_1024X768_60);
        let writes = mmio.writes_to(PipeIdx::A.trans_base() + PIPE_SRCSZ_OFFSET);
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

    /// Gen9 panel fitting: a 1024x768 source on a 1920x1080 panel takes
    /// PIPE_SRCSZ and the plane size from the source, binds scaler 0 in HQ
    /// mode (`skl_pfit_enable`) and pillarboxes it; without a fit the pipe
    /// detaches its scalers. Other generations refuse the fit.
    fn smoke_gen9_panel_fit_programs_the_pipe_scaler() -> TestResult {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PIPE_SRCSZ_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET,
        };
        use crate::intel_gpu_xelpg_scaler::{
            ps_ctrl, ps_win_pos, ps_win_sz, ScalerRefusal, ScalingMode, PS_SCALER_EN,
            SKL_PS_SCALER_MODE_HQ,
        };
        let panel = Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            ..Mode::VESA_1024X768_60
        };
        let fb = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 4096,
            format: PixelFormat::Xrgb8888,
        };
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        if ms.set_gen9_panel_fit(&panel, 1024, 768, ScalingMode::Aspect)
            != Err(ScalerRefusal::NoScaler)
        {
            return TestResult::Fail("a non-Gen9 run must refuse the Gen9 panel fitter");
        }
        ms.set_gen9_platform(crate::intel_gpu_gt::Gen9Platform::KabyLake);
        if ms.set_gen9_panel_fit(&panel, 1024, 768, ScalingMode::Aspect) != Ok(()) {
            return TestResult::Fail("a 1024x768 upscale must fit a 1080p panel");
        }
        ms.program_pipe(&panel);
        ms.program_plane(&fb, &panel);
        let a = PipeIdx::A;
        if mmio.writes_to(a.trans_base() + PIPE_SRCSZ_OFFSET) != alloc::vec![(1023 << 16) | 767] {
            return TestResult::Fail("PIPE_SRCSZ must carry the fitted source");
        }
        if mmio.writes_to(a.base() + PLANE_PRIMARY_OFFSET + PLANE_SIZE_OFFSET)
            != alloc::vec![(767 << 16) | 1023]
        {
            return TestResult::Fail("the primary plane must scan out the source size");
        }
        if mmio.writes_to(ps_ctrl(a, 0)) != alloc::vec![PS_SCALER_EN | SKL_PS_SCALER_MODE_HQ] {
            return TestResult::Fail("scaler 0 must bind the pipe in HQ mode");
        }
        // Aspect 4:3 on 16:9: 1440x1080 pillarboxed at x = 240.
        if mmio.writes_to(ps_win_pos(a, 0)) != alloc::vec![240 << 16]
            || mmio.writes_to(ps_win_sz(a, 0)) != alloc::vec![(1440 << 16) | 1080]
        {
            return TestResult::Fail("the pillarbox window is wrong");
        }
        // A native source clears the fit; the pipe then detaches both
        // scalers and scans out the mode size.
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.set_gen9_platform(crate::intel_gpu_gt::Gen9Platform::KabyLake);
        if ms.set_gen9_panel_fit(&panel, 1920, 1080, ScalingMode::Aspect) != Ok(()) {
            return TestResult::Fail("a native source must clear the fit");
        }
        ms.program_pipe(&panel);
        if mmio.writes_to(a.trans_base() + PIPE_SRCSZ_OFFSET) != alloc::vec![(1919 << 16) | 1079]
            || mmio.writes_to(ps_ctrl(a, 0)) != alloc::vec![0]
            || mmio.writes_to(ps_ctrl(a, 1)) != alloc::vec![0]
        {
            return TestResult::Fail("a native Gen9 pipe must detach its scalers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_panel_fit_programs_the_pipe_scaler
    );

    /// A DVI sink's transcoder selects DVI mode and never scrambles.
    fn smoke_hdmi_dvi_sink_selects_dvi_mode() -> TestResult {
        use crate::intel_gpu_pipes::{
            Transcoder, TRANS_DDI_FUNC_CTL_OFFSET, TRANS_DDI_HDMI_SCRAMBLING, TRANS_DDI_MODE_DVI,
            TRANS_DDI_MODE_HDMI,
        };
        let reg = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        let mode_bits = 7 << 24;
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::B);
        ms.program_trans_ddi_func_ctl_hdmi(false, false);
        ms.set_hdmi_dvi(true);
        ms.program_trans_ddi_func_ctl_hdmi(true, true);
        let writes = mmio.writes_to(reg);
        if writes.len() != 2
            || writes[0] & mode_bits != TRANS_DDI_MODE_HDMI
            || writes[1] & mode_bits != TRANS_DDI_MODE_DVI
            || writes[1] & TRANS_DDI_HDMI_SCRAMBLING != 0
        {
            return TestResult::Fail("a DVI sink must take TRANS_DDI_MODE_SELECT_DVI unscrambled");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_hdmi_dvi_sink_selects_dvi_mode
    );

    /// Deep colour: TRANS_DDI_BPC_10/_12, PIPE_MISC_BPC_10, and 12 bpc in
    /// PIPE_MISC only on display 13.
    fn smoke_hdmi_deep_colour_bpc_fields() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        use crate::intel_gpu_pipes::{Transcoder, TRANS_DDI_FUNC_CTL_OFFSET};
        let func = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        let misc = 0x70030;
        for (family, bpc, trans_bpc, misc_bpc) in [
            (Gen12Platform::TigerLake, 10, 1, Some(1)),
            (Gen12Platform::TigerLake, 12, 3, Some(0)),
            (Gen12Platform::AlderLakeP, 12, 3, Some(4)),
            (Gen12Platform::TigerLake, 8, 0, None),
        ] {
            let mmio = FakeMmio::new();
            let mut ms = Modeset::new(&mmio, Ddi::B);
            ms.set_gen12_family(family);
            ms.set_hdmi_bpc(bpc);
            ms.program_trans_ddi_func_ctl_hdmi(false, false);
            ms.program_pipe_misc_bpc();
            let f = mmio.writes_to(func);
            if f.len() != 1 || (f[0] >> 20) & 7 != trans_bpc {
                return TestResult::Fail("TRANS_DDI_FUNC_CTL BPC must follow the HDMI depth");
            }
            let m = mmio.writes_to(misc);
            match misc_bpc {
                Some(v) if m.len() == 1 && (m[0] >> 5) & 7 == v => {}
                None if m.is_empty() => {}
                _ => return TestResult::Fail("PIPE_MISC BPC must follow bdw_set_pipe_misc"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_hdmi_deep_colour_bpc_fields
    );

    fn smoke_gen12_internal_rgb_bypass_precedes_primary_and_refuses_live_pipe() -> TestResult {
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.initialize_internal_color().unwrap();
        assert_eq!(
            &*mmio.writes.borrow(),
            &[
                (0x70034, 0),
                (0x4a480, 0),
                (0x49028, 0),
                (0x701c8, 0),
                (0x701cc, 1 << 13)
            ]
        );
        ms.program_plane(
            &Framebuffer {
                phys_addr: 0x1000000,
                stride_bytes: 4096,
                format: PixelFormat::Xrgb8888,
            },
            &Mode::VESA_1024X768_60,
        );
        assert_eq!(mmio.writes.borrow().last().unwrap().0, 0x7019c);
        for (r, value) in [(0x70008, 1 << 31), (0x70180, 1 << 31)] {
            let mmio = FakeMmio::new();
            mmio.set_read(r, value);
            let mut ms = Modeset::new(&mmio, Ddi::A);
            assert_eq!(
                ms.initialize_internal_color(),
                Err(ModesetError::ColorPipelineUnavailable)
            );
            assert!(mmio.writes.borrow().is_empty());
        }
        let mmio = FakeMmio::new();
        Modeset::for_pipe(&mmio, Ddi::B, Pipe::B)
            .initialize_internal_color()
            .unwrap();
        assert!(mmio.writes.borrow().is_empty());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen12_internal_rgb_bypass_precedes_primary_and_refuses_live_pipe
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
        mmio.state_offset = Transcoder::A.conf_base() + PIPECONF_OFFSET;
        mmio.state_value = crate::intel_gpu_pipes::PIPECONF_STATE;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.enable_transcoder();
        let writes = mmio.writes_to(Transcoder::A.conf_base() + PIPECONF_OFFSET);
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
        ms.enable_ddi_buffer(4);
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

    fn smoke_program_mn_writes_link_n_last() -> TestResult {
        use crate::intel_gpu_pipes::Transcoder;
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.program_mn(&Mode::VESA_1024X768_60);
        let base = Transcoder::A.base();
        for off in [0x30u64, 0x34, 0x40, 0x44] {
            if mmio.writes_to(base + off).is_empty() {
                return TestResult::Fail("M/N register not written");
            }
        }
        // LINK_N (base+0x44) must be the last of the four writes.
        let log = mmio.writes.borrow();
        let mut last_mn_idx = 0usize;
        let mut link_n_idx = 0usize;
        for (i, (o, _)) in log.iter().enumerate() {
            if *o >= base + 0x30 && *o <= base + 0x44 {
                last_mn_idx = i;
            }
            if *o == base + 0x44 {
                link_n_idx = i;
            }
        }
        if link_n_idx != last_mn_idx {
            return TestResult::Fail("LINK_N must be written last");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_mn_writes_link_n_last
    );

    fn smoke_program_routing_and_watermarks() -> TestResult {
        use crate::intel_gpu_pipes::{Pipe as PipeIdx, Transcoder, TRANS_DDI_FUNC_CTL_OFFSET};
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.program_trans_ddi_func_ctl_mode(4, crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST);
        let want = (1u32 << 31) | (1 << 27) | (2 << 24) | (3 << 1);
        let writes = mmio.writes_to(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET);
        if writes != alloc::vec![want] {
            return TestResult::Fail("TRANS_DDI_FUNC_CTL value wrong");
        }
        // FakeMmio answers every pcode read with 0: latencies
        // all zero → WaWmMemoryReadLatency raises level 0 to
        // 3 µs, the rest stay disabled. For 1024×768@65 MHz the
        // algorithm yields level 0 = 9 blocks / 1 line and a
        // transition watermark of 9 + 14 = 23 blocks, with the
        // full-DBUF allocation — not the pre-boot values.
        let fb = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1024 * 4,
            format: PixelFormat::Xrgb8888,
        };
        ms.program_watermarks(&Mode::VESA_1024X768_60, &fb);
        let wm_base = PipeIdx::A.base() + super::PLANE_WM_BASE_OFFSET;
        if mmio.writes_to(wm_base) != alloc::vec![0x8000_4009] {
            return TestResult::Fail("PLANE_WM level 0 must be the computed 9-block value");
        }
        if mmio.writes_to(wm_base + 4) != alloc::vec![0] {
            return TestResult::Fail("PLANE_WM level 1 must be disabled");
        }
        if mmio.writes_to(wm_base + super::PLANE_WM_TRANS_OFFSET) != alloc::vec![0x8000_0017] {
            return TestResult::Fail("transition watermark must be wm0 blocks + 14");
        }
        if mmio.writes_to(PipeIdx::A.base() + super::PLANE_BUF_CFG_OFFSET)
            != alloc::vec![0x07FF_0000]
        {
            return TestResult::Fail("PLANE_BUF_CFG must be the full-DBUF allocation");
        }
        // DPCLKA routing: two writes, first with clock-off set
        // (select phase), second with it clear (clock on).
        let mut ms2 = Modeset::new(&mmio, Ddi::A);
        ms2.program_dpclka_routing().unwrap();
        let dpclka = mmio.writes_to(crate::intel_gpu_pll::DPCLKA_CFGCR0);
        if dpclka.len() != 2 {
            return TestResult::Fail("DPCLKA routing must be two writes");
        }
        if dpclka[0] & (1 << 10) == 0 || dpclka[1] & (1 << 10) != 0 {
            return TestResult::Fail("DPCLKA clock-off sequencing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_program_routing_and_watermarks
    );

    /// Display 9–11 select the port at bits[30:28] = index
    /// (`TRANS_DDI_SELECT_PORT`); display 12 at bits[30:27] =
    /// index + 1. Only DDI B encodes the same in both.
    fn smoke_pre_tgl_trans_ddi_port_select() -> TestResult {
        use crate::intel_gpu_gt::{Gen11Platform, Gen9Platform};
        use crate::intel_gpu_pipes::{
            Transcoder, TRANS_DDI_FUNC_CTL_OFFSET, TRANS_DDI_MODE_DP_SST,
        };
        let sst = (1u32 << 31) | (2 << 24) | (3 << 1);
        for (ddi, gen, want) in [
            (Ddi::A, Some(11), sst),
            (Ddi::B, Some(11), sst | (1 << 28)),
            (Ddi::C, Some(11), sst | (2 << 28)),
            (Ddi::E, Some(9), sst | (4 << 28)),
            (Ddi::A, Some(9), sst),
            (Ddi::C, None, sst | (3 << 27)),
        ] {
            let mmio = FakeMmio::new();
            let mut ms = Modeset::new(&mmio, ddi);
            match gen {
                Some(11) => ms.set_gen11_platform(Gen11Platform::IceLake),
                Some(9) => ms.set_gen9_platform(Gen9Platform::KabyLake),
                _ => {}
            }
            ms.program_trans_ddi_func_ctl_mode(4, TRANS_DDI_MODE_DP_SST);
            let base = ms.transcoder().base();
            if mmio.writes_to(base + TRANS_DDI_FUNC_CTL_OFFSET) != alloc::vec![want] {
                return TestResult::Fail(
                    "TRANS_DDI_FUNC_CTL port select must follow the display version",
                );
            }
        }
        // HDMI on Gen11 DDI C: HDMI mode, port 2 at bits[30:28].
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::C);
        ms.set_gen11_platform(Gen11Platform::IceLake);
        ms.program_trans_ddi_func_ctl_hdmi(false, false);
        let func = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        if mmio.writes_to(func) != alloc::vec![(1u32 << 31) | (2 << 28) | (3 << 1)] {
            return TestResult::Fail("Gen11 HDMI must select DDI C as port 2");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_pre_tgl_trans_ddi_port_select
    );

    /// A run beside a live pipe takes the CDCLK it finds: a floor above it
    /// (or an unknown clock) refuses; a lone run may raise it.
    fn smoke_shared_cdclk_refuses_a_raise() -> TestResult {
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::B);
        let mut p2160 = mode_1080p60();
        p2160.pixel_clock_khz = 594_000;
        if ms.refuse_shared_cdclk(Some(300_000), &p2160).is_err() {
            return TestResult::Fail("a lone run may raise CDCLK");
        }
        ms.set_shared_cdclk(true);
        if ms.refuse_shared_cdclk(Some(296_999), &p2160) != Err(ModesetError::CdclkUnavailable)
            || ms.refuse_shared_cdclk(None, &p2160) != Err(ModesetError::CdclkUnavailable)
            || ms.refuse_shared_cdclk(Some(307_200), &p2160).is_err()
        {
            return TestResult::Fail("a shared run must refuse a CDCLK raise");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_shared_cdclk_refuses_a_raise
    );

    fn smoke_gen12_tc_sst_refuses_insufficient_payload_before_writes() -> TestResult {
        let mmio = FakeMmio::new();
        let mut ms = Modeset::for_pipe(&mmio, Ddi::D, Pipe::B);
        let mut mode = Mode::VESA_1024X768_60;
        // One RBR lane carries RGB8 at up to 54 MHz.
        let plan = LinkPlan {
            rate: crate::dp_link_training::LinkRate::Rbr,
            lanes: 1,
        };
        mode.pixel_clock_khz = 54_000;
        if plan.check_rgb8_capacity(&mode).is_err() {
            return TestResult::Fail("exact RGB8 link capacity should be admitted");
        }
        mode.pixel_clock_khz += 1;
        if ms.modeset_with_plan(&fb_1080p(), &mode, plan)
            != Err(ModesetError::LinkBandwidthInsufficient)
            || !mmio.writes.borrow().is_empty()
        {
            return TestResult::Fail("an undersized Type-C plan must refuse before MMIO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen12_tc_sst_refuses_insufficient_payload_before_writes
    );

    fn smoke_modeset_power_well_timeout() -> TestResult {
        // No state bits ever assert: PG1 grant times out.
        let mmio = FakeMmio::new();
        let mut ms = Modeset::new(&mmio, Ddi::A);
        let fb = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1024 * 4,
            format: PixelFormat::Xrgb8888,
        };
        match ms.modeset(&fb, Some(&Mode::VESA_1024X768_60)) {
            Err(ModesetError::PowerWellTimeout) => TestResult::Pass,
            _ => TestResult::Fail("missing PG1 grant must surface as PowerWellTimeout"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_power_well_timeout
    );

    fn smoke_modeset_pll_lock_timeout() -> TestResult {
        // Power wells grant; the PLL powers but never locks.
        let mut mmio = FakeMmio::new();
        mmio.set_read(
            super::PWR_WELL_CTL2,
            super::pwr_well_state(0) | super::pwr_well_state(1),
        );
        mmio.state_offset = super::DPLL0_ENABLE;
        mmio.state_value = super::PLL_POWER_STATE;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        let fb = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1024 * 4,
            format: PixelFormat::Xrgb8888,
        };
        match ms.modeset(&fb, Some(&Mode::VESA_1024X768_60)) {
            Err(ModesetError::PllLockTimeout) => TestResult::Pass,
            _ => TestResult::Fail("missing PLL lock must surface as PllLockTimeout"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_pll_lock_timeout
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
        let trans_writes = mmio.writes_to(Transcoder::A.conf_base() + PIPECONF_OFFSET);
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

    // ── Scripted sink model (Q6, #1024 item 4) ───────────────
    //
    // Unlike FakeMmio's canned reads, this model *computes*
    // its answers from state the modeset itself establishes:
    // power-well STATE follows REQUEST, PLL LOCK follows
    // ENABLE, DBUF STATE follows REQUEST, the pcode endpoint
    // answers latency queries from its scripted table keyed by
    // the DATA0 set selector, and the DP sink runs a real
    // training state machine — CR only locks after the source
    // applies the swing the sink's ADJUST_REQUEST asks for, EQ
    // only completes under TPS3. A modeset step that programs
    // the wrong thing gets a wrong answer and fails, which is
    // what makes the full-run fixture below a test of the
    // modeset rather than of the fake. Q4's branch (#1114)
    // grows a sibling sink model for the DP-codec layer
    // (`DpSink`); when both are on main the two should be
    // unified into one shared sink model.

    /// The scripted panel's EDID: VESA DMT 1920×1080@60
    /// (148.5 MHz; h 1920/2200, sync +88/+44; v 1080/1125,
    /// sync +4/+5; both syncs positive), valid header and
    /// checksum, detailed timing in the first descriptor slot.
    fn edid_1080p60() -> [u8; 128] {
        let mut e = [0u8; 128];
        e[..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        e[18] = 1; // EDID 1.4
        e[19] = 4;
        e[20] = 0x80; // digital input
        e[21] = 53; // 53 cm wide
        e[22] = 30; // 30 cm high
        let d = 0x36; // first detailed-timing descriptor
        e[d] = 0x02; // pixel clock 14850 (0x3A02) × 10 kHz, LE
        e[d + 1] = 0x3A;
        e[d + 2] = 0x80; // h active low (1920)
        e[d + 3] = 0x18; // h blanking low (280)
        e[d + 4] = 0x71; // h active/blanking high nibbles
        e[d + 5] = 0x38; // v active low (1080)
        e[d + 6] = 0x2D; // v blanking low (45)
        e[d + 7] = 0x40; // v active/blanking high nibbles
        e[d + 8] = 88; // h sync offset
        e[d + 9] = 44; // h sync width
        e[d + 10] = 0x45; // v sync offset (high nibble) / width
        e[d + 11] = 0; // all sync high bits zero
        e[d + 17] = 0x1E; // digital separate, +VSync, +HSync
        let sum: u8 = e[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        e[127] = 0u8.wrapping_sub(sum);
        e
    }

    #[derive(Debug, Default)]
    struct SinkState {
        power: u8,
        pattern: u8,
        pattern_history: Vec<u8>,
        tunes: [u8; 4],
        /// TPS1 entries so far (one per training attempt).
        cr_attempts: u32,
        /// Test knob: fail clock recovery for the first this
        /// many TPS1 entries, then let CR lock — drives the
        /// fallback ladder from a fixture. 0 (default) never
        /// fails.
        fail_cr_attempts: u8,
    }

    impl SinkState {
        fn lane_swing(&self, lane: usize) -> u8 {
            self.tunes[lane] & 0x3
        }
        /// Per-lane status nibble, computed from the training
        /// state the source has actually established.
        fn lane_nibble(&self, lane: usize) -> u8 {
            match self.pattern {
                // TPS1 (CR): locks once the sink's requested
                // swing (1) has been applied — unless the
                // fixture is failing this CR attempt.
                1 => {
                    if self.cr_attempts <= u32::from(self.fail_cr_attempts) {
                        0
                    } else if self.lane_swing(lane) >= 1 {
                        0x1 // CR_DONE
                    } else {
                        0
                    }
                }
                // TPS2 (EQ at RBR/HBR) and TPS3 (EQ at HBR2+):
                // CR held + EQ done + symbol locked once CR's
                // swing is in place.
                2 | 3 => {
                    if self.lane_swing(lane) >= 1 {
                        0x7
                    } else {
                        0
                    }
                }
                _ => 0,
            }
        }
        fn status_byte(&self, pair: usize) -> u8 {
            self.lane_nibble(pair * 2) | (self.lane_nibble(pair * 2 + 1) << 4)
        }
        fn adjust_byte(&self, pair: usize) -> u8 {
            // Under TPS1, ask for swing 1 on any lane still at
            // swing 0; pre-emphasis stays 0.
            let req = |lane: usize| -> u8 {
                if self.pattern == 1 && self.lane_swing(lane) == 0 {
                    1
                } else {
                    0
                }
            };
            req(pair * 2) | (req(pair * 2 + 1) << 4)
        }
        fn align_byte(&self) -> u8 {
            if matches!(self.pattern, 2 | 3) && (0..4).all(|l| self.lane_swing(l) >= 1) {
                1 // INTERLANE_ALIGN_DONE
            } else {
                0
            }
        }
        fn write(&mut self, addr: u32, data: &[u8]) {
            for (i, &b) in data.iter().enumerate() {
                match addr + i as u32 {
                    0x600 => self.power = b & 0x3,
                    0x102 => {
                        self.pattern = b;
                        self.pattern_history.push(b);
                        if b == 1 {
                            self.cr_attempts += 1;
                        }
                    }
                    a @ 0x103..=0x106 => self.tunes[(a - 0x103) as usize] = b,
                    _ => {}
                }
            }
        }
        fn read(&self, addr: u32) -> u8 {
            match addr {
                0x202 => self.status_byte(0),
                0x203 => self.status_byte(1),
                0x204 => self.align_byte(),
                0x206 => self.adjust_byte(0),
                0x207 => self.adjust_byte(1),
                _ => 0,
            }
        }
    }

    /// Full scripted machine: display register file with
    /// computed status bits, pcode endpoint, and the AUX
    /// engine + DP sink above.
    #[derive(Debug)]
    pub struct ScriptedSinkMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        regs: RefCell<Vec<(u64, u32)>>,
        /// Raw DSSM value served on reads (reference strap).
        pub dssm: u32,
        /// Tiger Lake UY (GT2) part: when true the window
        /// reports `tgl_uy`, so a `Modeset` built over it
        /// selects the UY HBR2 table. Default false (the
        /// standard TGL table).
        pub tgl_uy: bool,
        /// Latency table the pcode endpoint serves.
        pub latencies: [u16; 8],
        /// SAGV block time the pcode endpoint serves.
        pub sagv_block_time: u32,
        /// When nonzero, every pcode command completes with
        /// this status (the modeset must fall back).
        pub pcode_status: u8,
        /// When false, DBUF slices never grant power.
        pub dbuf_grant: bool,
        pcode_data: RefCell<[u32; 2]>,
        pcode_mailbox: RefCell<u32>,
        sink: RefCell<SinkState>,
        edid_ptr: RefCell<usize>,
    }

    impl ScriptedSinkMmio {
        pub fn new(dssm: u32) -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                regs: RefCell::new(Vec::new()),
                dssm,
                tgl_uy: false,
                latencies: [6, 9, 13, 18, 24, 31, 40, 52],
                sagv_block_time: 20,
                pcode_status: 0,
                dbuf_grant: true,
                pcode_data: RefCell::new([0; 2]),
                pcode_mailbox: RefCell::new(0),
                sink: RefCell::new(SinkState::default()),
                edid_ptr: RefCell::new(0),
            }
        }
        fn get(&self, off: u64) -> u32 {
            let mut v = 0;
            for (o, val) in self.regs.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            v
        }
        fn set(&self, off: u64, val: u32) {
            self.regs.borrow_mut().push((off, val));
        }
        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn pcode_execute(&self, cmd_word: u32) {
            use crate::intel_gpu_pcode::{
                PCODE_CMD_READ_MEM_LATENCY, PCODE_CMD_READ_SAGV_BLOCK_TIME_US,
            };
            if self.pcode_status != 0 {
                *self.pcode_mailbox.borrow_mut() = self.pcode_status as u32;
                return;
            }
            match cmd_word & 0xFF {
                PCODE_CMD_READ_MEM_LATENCY => {
                    let set = (self.pcode_data.borrow()[0] & 1) as usize;
                    let mut packed = 0u32;
                    for level in 0..4usize {
                        packed |= (self.latencies[set * 4 + level] as u32) << (8 * level);
                    }
                    self.pcode_data.borrow_mut()[0] = packed;
                    *self.pcode_mailbox.borrow_mut() = 0;
                }
                PCODE_CMD_READ_SAGV_BLOCK_TIME_US => {
                    self.pcode_data.borrow_mut()[0] = self.sagv_block_time;
                    *self.pcode_mailbox.borrow_mut() = 0;
                }
                crate::intel_gpu_pcode::PCODE_CMD_DE_WRITE_FREQ_REQ => {
                    // The frequency request is accepted; the punit
                    // answers with no data dwords.
                    *self.pcode_mailbox.borrow_mut() = 0;
                }
                crate::intel_gpu_pcode::PCODE_CMD_CDCLK_CONTROL => {
                    // The ICL CDCLK-control notifies: pre-notify
                    // (DATA0 = PREPARE_FOR_CHANGE) replies with
                    // the ready bit; post-notify (DATA0 = voltage
                    // level) just completes.
                    use crate::intel_gpu_pcode::{
                        SKL_CDCLK_PREPARE_FOR_CHANGE, SKL_CDCLK_READY_FOR_CHANGE,
                    };
                    if self.pcode_data.borrow()[0] == SKL_CDCLK_PREPARE_FOR_CHANGE {
                        self.pcode_data.borrow_mut()[0] = SKL_CDCLK_READY_FOR_CHANGE;
                    } else {
                        self.pcode_data.borrow_mut()[0] = 0;
                    }
                    *self.pcode_mailbox.borrow_mut() = 0;
                }
                _ => *self.pcode_mailbox.borrow_mut() = 0x1, // ILLEGAL_CMD
            }
        }

        /// Run one AUX transaction against the sink model:
        /// unpack the wire frame from the AUX DATA registers,
        /// dispatch it, and leave the reply in the DATA
        /// registers. `base` is the DDI's AUX DATA base
        /// (derived from the CTL write that triggered the
        /// transaction, so any DDI's sink works); `msgsize` is
        /// the request length from AUX_CTL. Returns the reply
        /// length in bytes.
        fn aux_engine(&self, base: u64, msgsize: usize) -> usize {
            use crate::intel_gpu_aux::{DDI_AUX_DATA_DWORDS, DDI_AUX_DATA_OFFSET};
            let _ = DDI_AUX_DATA_OFFSET;
            let mut wire = [0u8; 20];
            for i in 0..DDI_AUX_DATA_DWORDS {
                wire[i * 4..i * 4 + 4]
                    .copy_from_slice(&self.get(base + (i as u64) * 4).to_be_bytes());
            }
            let cmd = wire[0] >> 4;
            let addr = (((wire[0] & 0xF) as u32) << 16) | ((wire[1] as u32) << 8) | wire[2] as u32;
            let len = (wire[3] as usize) + 1;
            let mut reply = [0u8; 17]; // status byte + payload
            let reply_len = match cmd {
                // I²C address-only (the bare 3-byte header): a
                // start or, MOT clear, the STOP. Ack, no data.
                _ if msgsize == 3 => 1,
                0x8 => {
                    // Native write.
                    self.sink.borrow_mut().write(addr, &wire[4..4 + len]);
                    1
                }
                0x9 => {
                    // Native read.
                    for i in 0..len {
                        reply[1 + i] = self.sink.borrow().read(addr + i as u32);
                    }
                    1 + len
                }
                0x0 | 0x4 => {
                    // I2C write: the EDID EEPROM latches its
                    // byte pointer from the payload.
                    if addr == 0x50 {
                        *self.edid_ptr.borrow_mut() = wire[4] as usize;
                    }
                    1
                }
                0x1 | 0x5 => {
                    // I2C read: stream from the EEPROM pointer.
                    let edid = edid_1080p60();
                    let ptr = *self.edid_ptr.borrow();
                    reply[1..1 + len].copy_from_slice(&edid[ptr..ptr + len]);
                    *self.edid_ptr.borrow_mut() = ptr + len;
                    1 + len
                }
                _ => 1,
            };
            for i in 0..DDI_AUX_DATA_DWORDS {
                let mut v = 0u32;
                for b in 0..4 {
                    let idx = i * 4 + b;
                    if idx < reply_len {
                        v |= (reply[idx] as u32) << (24 - 8 * b);
                    }
                }
                self.set(base + (i as u64) * 4, v);
            }
            reply_len
        }
    }

    impl MmioWindow for ScriptedSinkMmio {
        fn tgl_uy(&self) -> bool {
            self.tgl_uy
        }
        fn read32(&self, off: u64) -> u32 {
            use crate::intel_gpu_aux::{DDI_AUX_CTL_OFFSET, DDI_AUX_DATA_OFFSET};
            use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
            use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_DATA1, PCODE_MAILBOX};
            use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE};
            use crate::intel_gpu_wm::{
                DBUF_CTL_S1, DBUF_CTL_S2, DBUF_POWER_REQUEST, DBUF_POWER_STATE,
            };
            match off {
                o if o == DSSM => self.dssm,
                o if o == PCODE_MAILBOX => *self.pcode_mailbox.borrow(),
                o if o == PCODE_DATA0 => self.pcode_data.borrow()[0],
                o if o == PCODE_DATA1 => self.pcode_data.borrow()[1],
                o if o == super::PWR_WELL_CTL2 => {
                    // STATE follows REQUEST per well index.
                    // Indices 0..15 cover the ICL PG wells and
                    // the SKL map (PW_2 at 15, DDI_IO_* at 1–4).
                    let stored = self.get(off);
                    let mut v = stored;
                    for idx in 0..16u32 {
                        if stored & super::pwr_well_req(idx) != 0 {
                            v |= super::pwr_well_state(idx);
                        } else {
                            v &= !super::pwr_well_state(idx);
                        }
                    }
                    v
                }
                o if o == crate::intel_gpu_gen9_dpll::DPLL_STATUS => {
                    // SKL DPLL lock follows CTL ENABLE per DPLL
                    // id (`skl_ddi_pll_enable`'s 5 ms lock wait
                    // polls this register, not the CTL).
                    use crate::intel_gpu_gen9_dpll::{
                        ctl_reg, dpll_lock_bit, SklDpllId, PLL_ENABLE,
                    };
                    let mut v = 0u32;
                    for id in [
                        SklDpllId::Dpll0,
                        SklDpllId::Dpll1,
                        SklDpllId::Dpll2,
                        SklDpllId::Dpll3,
                    ] {
                        if self.get(ctl_reg(id)) & PLL_ENABLE != 0 {
                            v |= dpll_lock_bit(id);
                        }
                    }
                    v
                }
                0x46010 | 0x46014 | 0x46020 | 0x46030 | 0x46034 | 0x46038 | 0x4603C => {
                    // Any ICL PLL enable register (combo DPLL0/1,
                    // TBT, MG TC1–TC4): POWER_STATE follows
                    // POWER_ENABLE, LOCK follows ENABLE.
                    let stored = self.get(off);
                    let mut v = stored;
                    if stored & super::PLL_POWER_ENABLE != 0 {
                        v |= super::PLL_POWER_STATE;
                    }
                    if stored & super::PLL_ENABLE != 0 {
                        v |= super::PLL_LOCK;
                    }
                    v
                }
                o if o == crate::intel_gpu_gen12_cdclk::DE_PLL_ENABLE => {
                    // CDCLK PLL LOCK follows ENABLE (same shape as
                    // the DPLL arm above).
                    use crate::intel_gpu_gen12_cdclk::{PLL_ENABLE, PLL_LOCK};
                    let stored = self.get(off);
                    if stored & PLL_ENABLE != 0 {
                        stored | PLL_LOCK
                    } else {
                        stored & !PLL_LOCK
                    }
                }
                o if o == Pipe::A.base() + PIPECONF_OFFSET
                    || o == crate::intel_gpu_pipes::Transcoder::Edp.conf_base()
                        + PIPECONF_OFFSET =>
                {
                    // PIPECONF STATE follows ENABLE — Pipe A and
                    // the Gen9 EDP transcoder (whose CONF lives
                    // at 0x7F008, not aliased to the pipe block).
                    let stored = self.get(off);
                    if stored & PIPECONF_ENABLE != 0 {
                        stored | PIPECONF_STATE
                    } else {
                        stored & !PIPECONF_STATE
                    }
                }
                o if (0x64000..0x64900).contains(&o) && o & 0xFF == DDI_BUF_CTL_OFFSET => {
                    use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS};
                    let stored = self.get(off);
                    if stored & DDI_BUF_CTL_ENABLE != 0 {
                        stored & !DDI_BUF_CTL_IDLE_STATUS
                    } else {
                        stored | DDI_BUF_CTL_IDLE_STATUS
                    }
                }
                o if o == DBUF_CTL_S1 || o == DBUF_CTL_S2 => {
                    let stored = self.get(off);
                    if self.dbuf_grant && stored & DBUF_POWER_REQUEST != 0 {
                        stored | DBUF_POWER_STATE
                    } else {
                        stored & !DBUF_POWER_STATE
                    }
                }
                o if o == Ddi::A.base() + DDI_AUX_CTL_OFFSET => self.get(off),
                o if (Ddi::A.base() + DDI_AUX_DATA_OFFSET
                    ..Ddi::A.base() + DDI_AUX_DATA_OFFSET + 20)
                    .contains(&o) =>
                {
                    self.get(off)
                }
                _ => self.get(off),
            }
        }
        fn write32(&self, off: u64, val: u32) {
            use crate::intel_gpu_aux::{
                AUX_CTL_MSGSIZE_MASK, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY, DDI_AUX_CTL_OFFSET,
            };
            use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_DATA1, PCODE_MAILBOX, PCODE_READY};
            self.writes.borrow_mut().push((off, val));
            match off {
                o if o == PCODE_DATA0 => self.pcode_data.borrow_mut()[0] = val,
                o if o == PCODE_DATA1 => self.pcode_data.borrow_mut()[1] = val,
                o if o == PCODE_MAILBOX => {
                    if val & PCODE_READY != 0 {
                        self.pcode_execute(val);
                    } else {
                        *self.pcode_mailbox.borrow_mut() = val;
                    }
                }
                o if (0x64000..0x64900).contains(&o) && o & 0xFF == DDI_AUX_CTL_OFFSET => {
                    if val & AUX_CTL_SEND_BUSY != 0 {
                        let msgsize =
                            ((val & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
                        // The AUX DATA base for this DDI: the CTL
                        // write offset minus the CTL offset plus
                        // the DATA offset within the DDI block.
                        use crate::intel_gpu_aux::DDI_AUX_DATA_OFFSET;
                        let reply_len =
                            self.aux_engine(o - DDI_AUX_CTL_OFFSET + DDI_AUX_DATA_OFFSET, msgsize);
                        // Sending clears the W1C error bits. A successful
                        // completion publishes DONE and the new reply length.
                        let ctl = crate::intel_gpu_aux::AUX_CTL_DONE
                            | ((reply_len as u32) << AUX_CTL_MSGSIZE_SHIFT);
                        self.set(off, ctl);
                    } else {
                        self.set(off, val);
                    }
                }
                _ => {
                    self.set(off, val);
                    // Group aperture: a GRP write lands on all
                    // four lanes, so a later LN0 read sees it —
                    // the hardware behavior Linux's
                    // read-LN0/write-GRP sequence relies on (the
                    // combo-PHY step-6 training-enable set must
                    // not clobber step 5's scaling program). The
                    // writes log still records exactly what the
                    // driver wrote.
                    for base in [0x162000u64, 0x6C000, 0x160000, 0x161000, 0x16B000] {
                        for (grp, ln) in
                            [(base + 0x604, base + 0x804), (base + 0x694, base + 0x894)]
                        {
                            if off == grp {
                                for lane in 0..4u64 {
                                    self.set(ln + lane * 0x100, val);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn fb_1080p() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        }
    }

    /// The sink's EDID preferred mode as a literal (same
    /// numbers `smoke_gen11_modeset_full_run_scripted_sink`
    /// pins from the EDID parse): 1920x1080@60, 148.5 MHz.
    fn mode_1080p60() -> Mode {
        Mode {
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
        }
    }

    fn smoke_gen12_restore_keeps_allocated_mode() -> TestResult {
        for generation in [
            crate::intel_gpu::Generation::TigerLake,
            crate::intel_gpu::Generation::AlderLake,
        ] {
            // The sink advertises 1920x1080, but resume owns a 1024x768
            // allocation. EDID must not silently enlarge that scanout.
            let mmio = ScriptedSinkMmio::new(1 << 29);
            let fb = Framebuffer {
                stride_bytes: 4096,
                ..fb_1080p()
            };
            let mode = Mode::VESA_1024X768_60;
            if modeset_display(&mmio, generation, &fb, Some(&mode)) != Ok(mode) {
                return TestResult::Fail("resume must retain the allocation's exact mode");
            }
            if mmio.writes_to(0x70190).last() != Some(&0x02ff_03ff) {
                return TestResult::Fail("restored plane must be 1024x768");
            }
            if mmio
                .writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0)
                .is_empty()
            {
                return TestResult::Fail("Gen12 resume must program the combo DPLL");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen12_restore_keeps_allocated_mode
    );

    fn smoke_modeset_full_run_scripted_sink() -> TestResult {
        // DSSM strap: 19.2 MHz (field 1).
        let mmio = ScriptedSinkMmio::new(1 << 29);
        let mut ms = Modeset::new(&mmio, Ddi::A);
        let mode = match ms.modeset(&fb_1080p(), None) {
            Ok(m) => m,
            Err(_) => return TestResult::Fail("full modeset over scripted sink must succeed"),
        };
        // The mode came from the sink's EDID, not a fallback.
        if mode.pixel_clock_khz != 148_500
            || mode.h_active != 1920
            || mode.h_total != 2200
            || mode.h_sync_start != 2008
            || mode.h_sync_end != 2052
            || mode.v_active != 1080
            || mode.v_total != 1125
            || mode.v_sync_start != 1084
            || mode.v_sync_end != 1089
            || !mode.h_sync_positive
            || !mode.v_sync_positive
        {
            return TestResult::Fail("modeset must return the EDID preferred mode");
        }
        // DPLL: the HBR2 row of the 19.2 MHz family — the rate
        // training starts at. CFGCR0 is the one DCO word every DP
        // row of the family shares; CFGCR1 (KDIV_1 | PDIV_3 |
        // CFREQ = 0x4B) is the rate witness.
        let cfgcr0 = mmio.writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0);
        if cfgcr0 != alloc::vec![0x01C0_01A5] {
            return TestResult::Fail("CFGCR0 must be the 19.2-family DP DCO word");
        }
        let cfgcr1 = crate::intel_gpu_pll::dpll_cfgcr1(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0);
        if mmio.writes_to(cfgcr1) != alloc::vec![0x4B] {
            return TestResult::Fail("CFGCR1 must be the HBR2 row training starts at");
        }
        // CDCLK: 148.5 MHz pixel clock, floor 74.25 MHz, 19.2 MHz
        // strap -> the 172.8 MHz icl rung (ratio 18, DIV_SEL_1,
        // decimal 344), with pcode pre + post notifies (0x17).
        use crate::intel_gpu_gen12_cdclk::{CDCLK_CTL, DE_PLL_ENABLE};
        if mmio.writes_to(DE_PLL_ENABLE) != alloc::vec![0, 18, 0x8000_0012] {
            return TestResult::Fail("CDCLK PLL must disable, then enable at ratio 18");
        }
        if mmio.writes_to(CDCLK_CTL) != alloc::vec![(7 << 19) | 344] {
            return TestResult::Fail("CDCLK_CTL must be pipe-none + decimal 344");
        }
        let freq_req = mmio
            .writes_to(crate::intel_gpu_pcode::PCODE_MAILBOX)
            .into_iter()
            .filter(|w| *w == 0x8000_0017)
            .count();
        if freq_req != 2 {
            return TestResult::Fail("CDCLK change must send pre + post frequency requests");
        }
        // Watermarks: the values hand-computed from the
        // algorithm for this mode + the sink's latency table.
        let wm_base = Pipe::A.base() + super::PLANE_WM_BASE_OFFSET;
        let want = [
            0x8000_4010u32,
            0x8000_4010,
            0x8000_8012,
            0x8000_8021,
            0x8000_8021,
            0x8000_C031,
        ];
        for (level, w) in want.iter().enumerate() {
            if mmio.writes_to(wm_base + level as u64 * 4) != alloc::vec![*w] {
                return TestResult::Fail("PLANE_WM level value mismatch in full run");
            }
        }
        if mmio.writes_to(wm_base + super::PLANE_WM_SAGV_OFFSET) != alloc::vec![0x8000_8021] {
            return TestResult::Fail("SAGV watermark mismatch in full run");
        }
        if mmio.writes_to(wm_base + super::PLANE_WM_TRANS_OFFSET) != alloc::vec![0x8000_001E] {
            return TestResult::Fail("transition watermark mismatch in full run");
        }
        if mmio.writes_to(Pipe::A.base() + super::PLANE_BUF_CFG_OFFSET) != alloc::vec![0x07FF_0000]
        {
            return TestResult::Fail("BUF_CFG must be the full-DBUF allocation");
        }
        // DBUF slices were power-requested.
        use crate::intel_gpu_wm::{DBUF_CTL_S1, DBUF_CTL_S2, DBUF_POWER_REQUEST};
        for off in [DBUF_CTL_S1, DBUF_CTL_S2] {
            if !mmio
                .writes_to(off)
                .iter()
                .any(|v| v & DBUF_POWER_REQUEST != 0)
            {
                return TestResult::Fail("DBUF slice never power-requested");
            }
        }
        // Training really happened: SET_POWER D0, TPS1 → TPS3
        // → off, and the sink's requested swing was applied.
        let sink = mmio.sink.borrow();
        if sink.power != 1 {
            return TestResult::Fail("sink never powered to D0");
        }
        if sink.pattern_history != alloc::vec![1u8, 3, 0] {
            return TestResult::Fail("training pattern sequence must be TPS1, TPS3, off");
        }
        if sink.pattern != 0 {
            return TestResult::Fail("training must end with pattern off");
        }
        if sink.tunes.iter().any(|t| t & 0x3 != 1) {
            return TestResult::Fail("sink-requested swing 1 must be applied on all lanes");
        }
        // Combo-PHY signal levels (PHY_A, 0x162000): the sink
        // trained at HBR2 and asked for swing 1, so the final
        // program is preset 4 of the TGL HBR2 table
        // {0xA, 0x47, 0x3F, 0x00, 0x00}.
        let phy = 0x162000u64;
        if mmio.writes_to(phy + 0x604).last() != Some(&0x0400_0000) {
            return TestResult::Fail("PCS_DW1 must end with COMMON_KEEPER_EN set");
        }
        if mmio.writes_to(phy + 0x14).last() != Some(&0x3) {
            return TestResult::Fail("CL_DW5 must carry SUS_CLOCK_CONFIG");
        }
        let cl_dw10 = mmio.writes_to(phy + 0x28);
        if cl_dw10.is_empty() || cl_dw10.iter().any(|w| *w != 0) {
            return TestResult::Fail("eDP must clear the CL_DW10 HOBL override");
        }
        if mmio.writes_to(phy + 0x694).last() != Some(&0xA008_0030) {
            return TestResult::Fail("DW5 must end with scaling programmed + training enable");
        }
        if mmio.writes_to(phy + 0x888).last() != Some(&0x9098) {
            return TestResult::Fail("DW2 LN0 must carry the preset-4 swing");
        }
        if mmio.writes_to(phy + 0x890).last() != Some(&0x3F)
            || mmio.writes_to(phy + 0x990).last() != Some(&0x8000_003F)
        {
            return TestResult::Fail("DW4 must carry the preset-4 cursor + loadgen");
        }
        if mmio.writes_to(phy + 0x89C).last() != Some(&0x4700_0000) {
            return TestResult::Fail("DW7 LN0 must carry the preset-4 N-scalar");
        }
        // DP_TP_CTL returns to NORMAL once training ends with
        // pattern off (ENABLE + ENHANCED_FRAME stay set).
        let tp = crate::intel_gpu_pipes::Transcoder::A.base() + 0x540;
        if mmio.writes_to(tp).last() != Some(&0x8004_0300) {
            return TestResult::Fail("DP_TP_CTL must end at NORMAL");
        }
        // Gen12 never writes DDI_BUF_TRANS: the combo-PHY model
        // programs signal levels through PORT_TX_DW2/DW4/DW5/DW7,
        // and Linux selects DDI_BUF_TRANS only for DISPLAY_VER
        // < 10 (`has_buf_trans_select` in intel_ddi.c). The
        // register file is at 0x64E00 for DDI A — 10 LO/HI
        // entries, `DDI_BUF_TRANS_LO/HI(port, i)` in
        // intel_display_regs.h — NOT 0x64010, which is the DP AUX
        // channel block (`_DPA_AUX_CH_CTL`), written legitimately
        // on every AUX transaction during link training.
        if mmio
            .writes
            .borrow()
            .iter()
            .any(|(o, _)| (0x64E00..0x64E50).contains(o))
        {
            return TestResult::Fail("DDI_BUF_TRANS must not be written on Gen12");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_full_run_scripted_sink
    );

    // ── Gen11 modeset (Lane 5) ───────────────────────────────────

    fn smoke_gen11_family_for_chip_uses_exact_pci_ids() -> TestResult {
        use crate::intel_gpu::{ChipInfo, Generation};
        use crate::intel_gpu_gt::Gen11Platform;
        for (did, platform) in [
            (0x8A51, Gen11Platform::IceLake),
            (0x4571, Gen11Platform::ElkhartLake),
            (0x4E51, Gen11Platform::JasperLake),
        ] {
            let chip = ChipInfo {
                vid: 0x8086,
                did,
                generation: Generation::IceLake,
                asic: "literal native fixture",
            };
            if gen11_family_for_chip(chip) != Some(platform) {
                return TestResult::Fail("Gen11 PCI ID must map to its exact product");
            }
            // A generation alias must not promote a chip into a
            // Gen11 platform it is not.
            if gen11_family_for_chip(ChipInfo {
                generation: Generation::TigerLake,
                ..chip
            })
            .is_some()
            {
                return TestResult::Fail("Gen11 mapping must require the IceLake generation");
            }
        }
        // An unmapped IceLake chip fails closed at the dispatch,
        // without touching MMIO.
        struct NoIo;
        impl MmioWindow for NoIo {
            fn read32(&self, _: u64) -> u32 {
                panic!("unknown Gen11 chip read MMIO")
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("unknown Gen11 chip wrote MMIO")
            }
        }
        if modeset_display_for_chip(
            &NoIo,
            ChipInfo {
                vid: 0x8086,
                did: 0x8AFF,
                generation: Generation::IceLake,
                asic: "unknown",
            },
            &fb_1080p(),
            Some(&Mode::VESA_1024X768_60),
        ) != Err(ModesetError::UnsupportedGeneration)
        {
            return TestResult::Fail("unmapped IceLake chip must fail closed");
        }
        // The no-chip entry point has no platform to select
        // with, so IceLake fails closed there too.
        if modeset_display(
            &NoIo,
            Generation::IceLake,
            &fb_1080p(),
            Some(&Mode::VESA_1024X768_60),
        ) != Err(ModesetError::UnsupportedGeneration)
        {
            return TestResult::Fail("no-chip IceLake modeset must fail closed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen11_family_for_chip_uses_exact_pci_ids
    );

    fn smoke_gen11_scanout_admission() -> TestResult {
        use crate::intel_gpu_gt::Gen11Platform;
        if crate::intel_gpu_scanout::skl_alignment() != 256 * 1024
            || crate::intel_gpu_scanout::skl_max_stride() != 32 * 1024
        {
            return TestResult::Fail("Gen11 alignment/stride must be the SKL rules");
        }
        let io = FakeMmio::new();
        let mut ms = Modeset::new(&io, Ddi::A);
        ms.set_gen11_platform(Gen11Platform::IceLake);
        // Stride past the 32 KiB SKL cap.
        let over_stride = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 32 * 1024 + 64,
            format: PixelFormat::Xrgb8888,
        };
        if ms.validate_framebuffer_skl(&over_stride).is_ok() {
            return TestResult::Fail("Gen11 must refuse a stride past 32 KiB");
        }
        // 4K-aligned but not 256 KiB aligned surface.
        let misaligned = Framebuffer {
            phys_addr: 0x100_1000,
            stride_bytes: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        };
        if ms.validate_framebuffer_skl(&misaligned).is_ok() {
            return TestResult::Fail("Gen11 must refuse a surface past 256 KiB alignment");
        }
        // The probe's owned allocation (16 MiB, 256 KiB aligned)
        // and the 1080p stride pass.
        if ms.validate_framebuffer_skl(&fb_1080p()).is_err() {
            return TestResult::Fail("Gen11 must admit the owned 1080p surface");
        }
        // The cap is exact: 32 KiB strides pass.
        let at_cap = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 32 * 1024,
            format: PixelFormat::Xrgb8888,
        };
        if ms.validate_framebuffer_skl(&at_cap).is_err() {
            return TestResult::Fail("Gen11 must admit a 32 KiB stride");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen11_scanout_admission
    );

    fn smoke_gen11_modeset_full_run_scripted_sink() -> TestResult {
        use crate::intel_gpu::{ChipInfo, Generation};
        // DSSM strap: 19.2 MHz (field 1).
        let mmio = ScriptedSinkMmio::new(1 << 29);
        let chip = ChipInfo {
            vid: 0x8086,
            did: 0x8A51,
            generation: Generation::IceLake,
            asic: "icelake",
        };
        let mode = match modeset_display_for_chip(&mmio, chip, &fb_1080p(), None) {
            Ok(m) => m,
            Err(_) => {
                return TestResult::Fail("Gen11 full modeset over scripted sink must succeed")
            }
        };
        // The mode came from the sink's EDID, not a fallback.
        if mode.pixel_clock_khz != 148_500
            || mode.h_active != 1920
            || mode.h_total != 2200
            || mode.v_active != 1080
            || mode.v_total != 1125
        {
            return TestResult::Fail("Gen11 modeset must return the EDID preferred mode");
        }
        // DPLL: the HBR2 row of the 19.2 MHz family (the rate
        // training starts at), written to the ICL CFGCR0/1
        // (0x164000/0x164004) — never the TGL CFGCR0
        // (0x164284). CFGCR1 = KDIV_1 | PDIV_3 | CFREQ.
        if mmio.writes_to(0x164000) != alloc::vec![0x01C0_01A5] {
            return TestResult::Fail(
                "Gen11 CFGCR0 must be the 19.2-family DP DCO word at 0x164000",
            );
        }
        if mmio.writes_to(0x164004) != alloc::vec![0x4B] {
            return TestResult::Fail("Gen11 CFGCR1 must be the HBR2 row at 0x164004");
        }
        if !mmio.writes_to(0x164284).is_empty() {
            return TestResult::Fail("Gen11 must never write the TGL CFGCR0");
        }
        // CDCLK: 148.5 MHz pixel clock, floor 74.25 MHz, 19.2 MHz
        // strap -> the 172.8 MHz ICL rung (ratio 18, DIV_SEL 2,
        // decimal 344), with pcode CDCLK-control pre + post
        // notifies (0x07).
        use crate::intel_gpu_gen11_cdclk::{CDCLK_CTL, DE_PLL_ENABLE};
        if mmio.writes_to(DE_PLL_ENABLE) != alloc::vec![0, 18, 0x8000_0012] {
            return TestResult::Fail("Gen11 CDCLK PLL must disable, then enable at ratio 18");
        }
        if mmio.writes_to(CDCLK_CTL) != alloc::vec![(7 << 19) | 344] {
            return TestResult::Fail("Gen11 CDCLK_CTL must be pipe-none + decimal 344");
        }
        let cdclk_notify = mmio
            .writes_to(crate::intel_gpu_pcode::PCODE_MAILBOX)
            .into_iter()
            .filter(|w| *w == 0x8000_0007)
            .count();
        if cdclk_notify != 2 {
            return TestResult::Fail("Gen11 CDCLK change must send pre + post control notifies");
        }
        // Linux order: the CDCLK program precedes the DPLL
        // program in the write log.
        let writes = mmio.writes.borrow();
        let cdclk_at = writes
            .iter()
            .position(|(o, _)| *o == CDCLK_CTL)
            .unwrap_or(usize::MAX);
        let dpll_at = writes
            .iter()
            .position(|(o, _)| *o == 0x164000)
            .unwrap_or(usize::MAX);
        if cdclk_at >= dpll_at {
            return TestResult::Fail("Gen11 CDCLK must precede DPLL in the write log");
        }
        // DPCLKA: DDI A selects DPLL 0, clock on, in the PRM's
        // two writes.
        if mmio.writes_to(0x164280) != alloc::vec![0x400, 0x0] {
            return TestResult::Fail("Gen11 DPCLKA must select DPLL0 for DDI A, clock on");
        }
        // Watermarks: the 8 ICL levels hand-computed from the
        // algorithm for this mode + the sink's latency table
        // ([6, 9, 13, 18, 24, 31, 40, 52] µs), the transition
        // watermark (level-0 blocks + 14), and the full-DBUF
        // allocation. No SAGV watermark exists on Gen11: the
        // 0x18/0x1C offsets are WM levels 6/7 and must carry
        // their levels, never SAGV zeros.
        let wm_base = Pipe::A.base() + super::PLANE_WM_BASE_OFFSET;
        let want = [
            0x8000_4010u32,
            0x8000_4010,
            0x8000_8012,
            0x8000_8021,
            0x8000_8021,
            0x8000_C031,
            0x8000_C031,
            0x8001_0041,
        ];
        for (level, w) in want.iter().enumerate() {
            if mmio.writes_to(wm_base + level as u64 * 4) != alloc::vec![*w] {
                return TestResult::Fail("Gen11 PLANE_WM level value mismatch in full run");
            }
        }
        if mmio.writes_to(wm_base + super::PLANE_WM_TRANS_OFFSET) != alloc::vec![0x8000_001E] {
            return TestResult::Fail("Gen11 transition watermark mismatch in full run");
        }
        if mmio.writes_to(Pipe::A.base() + super::PLANE_BUF_CFG_OFFSET) != alloc::vec![0x07FF_0000]
        {
            return TestResult::Fail("Gen11 BUF_CFG must be the full-DBUF allocation");
        }
        // DBUF slices were power-requested.
        use crate::intel_gpu_gen11_wm::{DBUF_CTL_S1, DBUF_CTL_S2, DBUF_POWER_REQUEST};
        for off in [DBUF_CTL_S1, DBUF_CTL_S2] {
            if !mmio
                .writes_to(off)
                .iter()
                .any(|v| v & DBUF_POWER_REQUEST != 0)
            {
                return TestResult::Fail("Gen11 DBUF slice never power-requested");
            }
        }
        // Training really happened: SET_POWER D0, TPS1 → TPS3
        // → off, and the sink's requested swing was applied.
        let sink = mmio.sink.borrow();
        if sink.power != 1 {
            return TestResult::Fail("sink never powered to D0");
        }
        if sink.pattern_history != alloc::vec![1u8, 3, 0] {
            return TestResult::Fail("training pattern sequence must be TPS1, TPS3, off");
        }
        if sink.pattern != 0 {
            return TestResult::Fail("training must end with pattern off");
        }
        if sink.tunes.iter().any(|t| t & 0x3 != 1) {
            return TestResult::Fail("sink-requested swing 1 must be applied on all lanes");
        }
        // Combo-PHY signal levels (PHY_A, 0x162000): the sink
        // trained at HBR2 and asked for swing 1, so the final
        // program is preset 4 of the ICL DP HBR2 / eDP HBR3
        // table {0xA, 0x4C, 0x3F, 0x00, 0x00} — the N-scalar
        // 0x4C distinguishes it from the TGL table's 0x47.
        let phy = 0x162000u64;
        if mmio.writes_to(phy + 0x604).last() != Some(&0x0400_0000) {
            return TestResult::Fail("PCS_DW1 must end with COMMON_KEEPER_EN set");
        }
        if mmio.writes_to(phy + 0x14).last() != Some(&0x3) {
            return TestResult::Fail("CL_DW5 must carry SUS_CLOCK_CONFIG");
        }
        let cl_dw10 = mmio.writes_to(phy + 0x28);
        if cl_dw10.is_empty() || cl_dw10.iter().any(|w| *w != 0) {
            return TestResult::Fail("Gen11 eDP must clear the CL_DW10 HOBL override");
        }
        if mmio.writes_to(phy + 0x694).last() != Some(&0xA008_0030) {
            return TestResult::Fail("DW5 must end with scaling programmed + training enable");
        }
        if mmio.writes_to(phy + 0x888).last() != Some(&0x9098) {
            return TestResult::Fail("DW2 LN0 must carry the preset-4 swing");
        }
        if mmio.writes_to(phy + 0x89C).last() != Some(&0x4C00_0000) {
            return TestResult::Fail("DW7 LN0 must carry the ICL preset-4 N-scalar");
        }
        // DP_TP_CTL is port-based on Gen11: DDI A base + 0x40
        // (0x64040) returns to NORMAL once training ends with
        // pattern off (ENABLE + ENHANCED_FRAME stay set), and
        // the TGL transcoder-based register (0x60540) is never
        // written.
        if mmio.writes_to(0x64040).last() != Some(&0x8004_0300) {
            return TestResult::Fail("Gen11 DP_TP_CTL must end at NORMAL");
        }
        if !mmio.writes_to(0x60540).is_empty() {
            return TestResult::Fail("Gen11 must never write the TGL transcoder DP_TP_CTL");
        }
        // Gen11 never writes DDI_BUF_TRANS either: Linux selects
        // it only for DISPLAY_VER < 10.
        if mmio
            .writes
            .borrow()
            .iter()
            .any(|(o, _)| (0x64E00..0x64E50).contains(o))
        {
            return TestResult::Fail("DDI_BUF_TRANS must not be written on Gen11");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen11_modeset_full_run_scripted_sink
    );

    // ── Gen9 (Lane 5) ────────────────────────────────────────────

    /// Gen9: the PCI census maps each Gen9 DID to exactly one
    /// Gen9 platform (Skylake → Skylake, KabyLake → KabyLake,
    /// CometLake → CometLake); a TigerLake generation must not
    /// promote a Skylake DID into a Gen9 family; an unmapped
    /// Skylake chip and a no-chip Skylake modeset both fail
    /// closed with `UnsupportedGeneration` — and neither touches
    /// MMIO.
    fn smoke_gen9_family_for_chip_uses_exact_pci_ids() -> TestResult {
        use crate::intel_gpu::{ChipInfo, Generation};
        for (did, want, asic) in [
            (
                0x1912,
                crate::intel_gpu_gt::Gen9Platform::Skylake,
                "skylake",
            ),
            (
                0x5912,
                crate::intel_gpu_gt::Gen9Platform::KabyLake,
                "kabylake",
            ),
            (
                0x9B41,
                crate::intel_gpu_gt::Gen9Platform::CometLake,
                "cometlake",
            ),
        ] {
            let chip = ChipInfo {
                vid: 0x8086,
                did,
                generation: Generation::Skylake,
                asic,
            };
            if gen9_family_for_chip(chip) != Some(want) {
                return TestResult::Fail("gen9_family_for_chip mapped a DID to the wrong platform");
            }
        }
        // Generation alias must not promote: a TigerLake
        // generation with a Skylake DID is not a Gen9 chip.
        let alias = ChipInfo {
            vid: 0x8086,
            did: 0x1912,
            generation: Generation::TigerLake,
            asic: "skylake",
        };
        if gen9_family_for_chip(alias).is_some() {
            return TestResult::Fail(
                "gen9_family_for_chip promoted a TigerLake-generation chip with a Skylake DID",
            );
        }
        // Unmapped Skylake chip: fails closed without touching MMIO.
        let unmapped = ChipInfo {
            vid: 0x8086,
            did: 0x19FF,
            generation: Generation::Skylake,
            asic: "skylake",
        };
        if gen9_family_for_chip(unmapped).is_some() {
            return TestResult::Fail("gen9_family_for_chip mapped unlisted Skylake DID 0x19ff");
        }
        let io = FakeMmio::new();
        let out = modeset_display_for_chip(&io, unmapped, &fb_1080p(), None);
        if out != Err(ModesetError::UnsupportedGeneration) {
            return TestResult::Fail(
                "unmapped Skylake modeset did not refuse UnsupportedGeneration",
            );
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("unmapped Skylake modeset wrote registers before refusing");
        }
        // No-chip Skylake modeset: the Gen9 arm has no platform
        // and refuses with UnsupportedGeneration (not DmcUnavailable).
        let out = modeset_display(&io, Generation::Skylake, &fb_1080p(), None);
        if out != Err(ModesetError::UnsupportedGeneration) {
            return TestResult::Fail(
                "no-chip Skylake modeset did not refuse UnsupportedGeneration",
            );
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_family_for_chip_uses_exact_pci_ids
    );

    /// Gen9: plane admission reuses the SKL rule (256 KiB
    /// surface alignment, 32 KiB stride cap) — the same rule
    /// Gen11 uses via the renamed `skl_*` helpers.
    fn smoke_gen9_scanout_admission() -> TestResult {
        if crate::intel_gpu_scanout::skl_alignment() != 256 * 1024
            || crate::intel_gpu_scanout::skl_max_stride() != 32 * 1024
        {
            return TestResult::Fail("Gen9 alignment/stride must be the SKL rules");
        }
        let io = FakeMmio::new();
        let mut ms = Modeset::new(&io, Ddi::A);
        ms.set_gen9_platform(crate::intel_gpu_gt::Gen9Platform::Skylake);
        ms.set_gen9_sku_family(crate::intel_gpu_gen9_ddi::SkuFamily::Desktop);
        // Stride past the 32 KiB SKL cap.
        let over_stride = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 32 * 1024 + 64,
            format: PixelFormat::Xrgb8888,
        };
        if ms.validate_framebuffer_skl(&over_stride).is_ok() {
            return TestResult::Fail("Gen9 must refuse a stride past 32 KiB");
        }
        // 4K-aligned but not 256 KiB aligned surface.
        let misaligned = Framebuffer {
            phys_addr: 0x100_1000,
            stride_bytes: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        };
        if ms.validate_framebuffer_skl(&misaligned).is_ok() {
            return TestResult::Fail("Gen9 must refuse a surface past 256 KiB alignment");
        }
        // The probe's owned allocation (16 MiB, 256 KiB aligned)
        // and the 1080p stride pass.
        if ms.validate_framebuffer_skl(&fb_1080p()).is_err() {
            return TestResult::Fail("Gen9 must admit the owned 1080p surface");
        }
        // The cap is exact: 32 KiB strides pass.
        let at_cap = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 32 * 1024,
            format: PixelFormat::Xrgb8888,
        };
        if ms.validate_framebuffer_skl(&at_cap).is_err() {
            return TestResult::Fail("Gen9 must admit a 32 KiB stride");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_scanout_admission
    );

    /// Gen9: with the DMC installed flag cleared, a mapped
    /// Skylake chip refuses with `DmcUnavailable` and writes
    /// nothing — the required-DMC gate fires before any
    /// register is touched.
    fn smoke_gen9_modeset_refuses_without_dmc() -> TestResult {
        use crate::intel_gpu::{ChipInfo, Generation};
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
        let io = FakeMmio::new();
        let chip = ChipInfo {
            vid: 0x8086,
            did: 0x1912,
            generation: Generation::Skylake,
            asic: "skylake",
        };
        let out = modeset_display_for_chip(&io, chip, &fb_1080p(), None);
        if out != Err(ModesetError::DmcUnavailable) {
            return TestResult::Fail("modeset without DMC did not refuse DmcUnavailable");
        }
        if !io.writes.borrow().is_empty() {
            return TestResult::Fail("modeset without DMC wrote registers before refusing");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_modeset_refuses_without_dmc
    );

    /// Gen9: the full first-light run over the scripted sink —
    /// 1080p60 on the internal eDP panel of a Skylake chip, DMC
    /// installed. Hand-computed expectations, not the module's
    /// own helpers: CDCLK 337.5 MHz via the PCODE handshake
    /// (floor 74.25 MHz from the 148.5 MHz mode), DPLL0 at HBR2,
    /// DDI A routed to DPLL0, the DDI IO well requested, the
    /// 8-level SKL watermarks from the sink's [6, 9, 13, 18, 24,
    /// 31, 40, 52] µs latencies over the full 892-block DBUF,
    /// the 9-entry SKL DP buffer table, and a clean TPS1→TPS3→
    /// off training run at swing level 1 (preset 4).
    fn smoke_gen9_modeset_full_run_scripted_sink() -> TestResult {
        use crate::intel_gpu::{ChipInfo, Generation};
        use crate::intel_gpu_gen11_dpll::DPLL_CTRL1;
        use crate::intel_gpu_gen9_cdclk::CDCLK_CTL;
        use crate::intel_gpu_gen9_ddi::{ddi_buf_trans_hi, ddi_buf_trans_lo, DISPIO_CR_TX_BMU_CR0};
        use crate::intel_gpu_gen9_dpll::DPLL_CTRL2;
        use crate::intel_gpu_gen9_wm::{DBUF_CTL_S1, DBUF_POWER_REQUEST};
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
        // DSSM strap: 19.2 MHz (field 1) — irrelevant to the
        // Gen9 CDCLK (fixed 24 MHz reference), kept for parity
        // with the Gen11 sink.
        let chip = ChipInfo {
            vid: 0x8086,
            did: 0x1912,
            generation: Generation::Skylake,
            asic: "skylake",
        };
        let sink = ScriptedSinkMmio::new(1 << 29);
        let out = modeset_display_for_chip(&sink, chip, &fb_1080p(), None);
        let mode = match out {
            Ok(mode) => mode,
            Err(_) => return TestResult::Fail("gen9 full run failed"),
        };
        // The EDID preferred mode is the 1080p60 panel mode.
        if mode.pixel_clock_khz != 148_500
            || mode.h_active != 1920
            || mode.h_total != 2200
            || mode.v_active != 1080
            || mode.v_total != 1125
        {
            return TestResult::Fail("gen9 full run did not commit the EDID preferred mode");
        }
        // CDCLK: 337.5 MHz (freq_sel 2, decimal 673) with the
        // override dance; the final value is 0x080002A1 and the
        // pre/post pcode notifies (cmd 0x7) both happened.
        let cdclk = sink.writes_to(CDCLK_CTL);
        if cdclk
            != [
                0x0800_02A1,
                0x0808_02A1,
                0x0008_0000,
                0x0808_02A1,
                0x0800_02A1,
            ]
        {
            return TestResult::Fail(
                "CDCLK_CTL writes are not [0x080002A1, 0x080802A1, 0x00080000, 0x080002A1, 0x080002A1]",
            );
        }
        if sink
            .writes_to(crate::intel_gpu_pcode::PCODE_MAILBOX)
            .iter()
            .filter(|w| **w == 0x8000_0007)
            .count()
            != 2
        {
            return TestResult::Fail("CDCLK program did not issue both pcode voltage notifies");
        }
        // CDCLK precedes the DP DPLL program (DPLL_CTRL1 = 1,
        // the HBR2 state) in the write log.
        let writes = sink.writes.borrow();
        let cdclk_at = writes
            .iter()
            .position(|(o, v)| *o == CDCLK_CTL && *v == 0x0800_02A1)
            .unwrap_or(usize::MAX);
        let dpll_at = writes
            .iter()
            .position(|(o, v)| *o == DPLL_CTRL1 && *v == 0x1)
            .unwrap_or(usize::MAX);
        if cdclk_at >= dpll_at {
            return TestResult::Fail("CDCLK was not programmed before the DP DPLL");
        }
        // DPLL_CTRL1: the CDCLK VCO program (5, OVERRIDE +
        // LINK_RATE_810) then the HBR2 link state (1).
        if sink.writes_to(DPLL_CTRL1) != [0x5, 0x1] {
            return TestResult::Fail("DPLL_CTRL1 writes are not [0x5, 0x1]");
        }
        // DPLL_CTRL2 routes DDI A to DPLL0 with override:
        // sel 0, override bit 0 → 0x1.
        if sink.writes_to(DPLL_CTRL2) != [0x1] {
            return TestResult::Fail("DPLL_CTRL2 writes are not [0x1]");
        }
        // The DDI IO well (idx 1) was requested — no PW_1/PW_2
        // writes for the always-on Pipe A.
        if sink.writes_to(PWR_WELL_CTL2) != [0x8] {
            return TestResult::Fail("PWR_WELL_CTL2 writes are not [0x8] (DDI IO A only)");
        }
        // DBUF slice S1 power-requested.
        if sink
            .writes_to(DBUF_CTL_S1)
            .iter()
            .all(|w| w & DBUF_POWER_REQUEST == 0)
        {
            return TestResult::Fail("DBUF_CTL_S1 was never power-requested");
        }
        // Watermarks: the 8 levels for the sink's latencies
        // (blocks/lines hand-computed: 8/0, 17/1, 18/1, 23/2,
        // 30/2, 38/3, 49/3, 63/4), TRANS 0, and the full
        // 892-block DBUF in BUF_CFG.
        let wm_base = Pipe::A.base() + PLANE_WM_BASE_OFFSET;
        let want_wm: [u32; 8] = [
            0x8000_0008,
            0x8000_4011,
            0x8000_4012,
            0x8000_8017,
            0x8000_801E,
            0x8000_C026,
            0x8000_C031,
            0x8001_003F,
        ];
        for (level, want) in want_wm.iter().enumerate() {
            // PLANE_WM levels are 4 bytes apart
            // (`program_watermarks_gen9` writes `wm_base +
            // level * 4`); the Gen11 full-run test pins the
            // same stride.
            let got = sink.writes_to(wm_base + (level as u64) * 4);
            if got.last() != Some(want) {
                return TestResult::Fail("a PLANE_WM level is not the hand-computed value");
            }
        }
        if sink.writes_to(wm_base + PLANE_WM_TRANS_OFFSET) != [0x0] {
            return TestResult::Fail("PLANE_WM_TRANS is not 0");
        }
        if sink.writes_to(Pipe::A.base() + PLANE_BUF_CFG_OFFSET) != [0x037B_0000] {
            return TestResult::Fail("PLANE_BUF_CFG is not the full 892-block DBUF");
        }
        // The 9-entry SKL DP buffer table was programmed at
        // DDI_BUF_TRANS_A; no 10th entry exists for port A DP.
        if sink.writes_to(ddi_buf_trans_lo(Ddi::A, 0)) != [0x0000_2016]
            || sink.writes_to(ddi_buf_trans_hi(Ddi::A, 0)) != [0x0000_00A0]
        {
            return TestResult::Fail("DDI_BUF_TRANS entry 0 is not the SKL DP table entry 0");
        }
        if sink.writes_to(ddi_buf_trans_lo(Ddi::A, 8)) != [0x8000_5012]
            || sink.writes_to(ddi_buf_trans_hi(Ddi::A, 8)) != [0x0000_00C0]
        {
            return TestResult::Fail("DDI_BUF_TRANS entry 8 is not the SKL DP table entry 8");
        }
        if !sink.writes_to(ddi_buf_trans_lo(Ddi::A, 9)).is_empty() {
            return TestResult::Fail("DDI_BUF_TRANS entry 9 was written — port A DP caps at 9");
        }
        // I_boost: the level-4 table entry's boost is 0, so
        // prepare writes the BALANCE_LEG_DISABLE words for
        // ports A then E; the final value keeps both.
        let iboost = sink.writes_to(DISPIO_CR_TX_BMU_CR0);
        if iboost.len() < 2 || iboost[0] != 0x0080_0000 || iboost[1] != 0x0880_0000 {
            return TestResult::Fail(
                "DISPIO_CR_TX_BMU_CR0 does not start [0x00800000, 0x08800000]",
            );
        }
        if iboost.last() != Some(&0x0880_0000) {
            return TestResult::Fail("DISPIO_CR_TX_BMU_CR0 last write is not 0x08800000");
        }
        // DDI_BUF_CTL ends enabled, 4 lanes, TRANS_SELECT 4
        // (swing 1, pre-emphasis 0 on lane 0). DDI A BUF_CTL
        // is 0x64000. The low byte keeps the IDLE bit (0x80)
        // the fixture serves on readback while ENABLE is
        // clear — `enable_ddi_buffer` RMWs it in, so the
        // final value is 0x84000086, not 0x84000006.
        let buf_ctl = sink.writes_to(0x64000);
        if buf_ctl.last() != Some(&0x8400_0086) {
            return TestResult::Fail("DDI_BUF_CTL last write is not 0x84000086");
        }
        // Training ended with DP_TP_CTL NORMAL (0x80040300)
        // and the Gen12 transcoder DP_TP_CTL was never touched.
        if sink.writes_to(0x64040).last() != Some(&0x8004_0300) {
            return TestResult::Fail("DP_TP_CTL last write is not 0x80040300");
        }
        if !sink.writes_to(0x60540).is_empty() {
            return TestResult::Fail(
                "Gen12 transcoder DP_TP_CTL 0x60540 was written on a Gen9 run",
            );
        }
        // The EDP transcoder — not the pipe-A block — carries
        // the timing registers.
        if sink.writes_to(0x6F400).is_empty() {
            return TestResult::Fail(
                "TRANS_DDI_FUNC_CTL at the EDP base (0x6F400) was never written",
            );
        }
        if !sink.writes_to(0x60400).is_empty() {
            return TestResult::Fail(
                "TRANS_DDI_FUNC_CTL at the Transcoder A base (0x60400) was written on a Gen9 run",
            );
        }
        // No Tiger Lake DPLL/CFGCR registers on this run:
        // TGL CFGCR0 is 0x164284, DPCLKA is 0x164280.
        for off in [0x164284_u64, 0x164280_u64] {
            if !sink.writes_to(off).is_empty() {
                return TestResult::Fail("a Tiger Lake register was written on a Gen9 run");
            }
        }
        // Training ran clean: the sink is powered, the pattern
        // history is TPS1 → TPS3 → off, and every tune is
        // swing 1.
        let sink_state = sink.sink.borrow();
        if sink_state.power != 1 || sink_state.pattern != 0 {
            return TestResult::Fail("sink is not powered in pattern 0 after training");
        }
        if sink_state.pattern_history != alloc::vec![1u8, 3, 0] {
            return TestResult::Fail("sink pattern history is not [1, 3, 0]");
        }
        if sink_state.tunes.iter().any(|t| t & 0x3 != 1) {
            return TestResult::Fail("sink tunes are not all swing 1");
        }
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_modeset_full_run_scripted_sink
    );

    /// Gen9: the external-DP plan path on DDI B (Lane 8) —
    /// the Lane 5 backstop is gone. DDI B / Pipe A / HBR2
    /// x4 / 1080p60, asserting the full register image
    /// against the panel run (same mode, same sink): the
    /// DPLL1 program, the DDI-IO-B power well, the SKL DP
    /// table at the port-B BUF_TRANS block, and the training
    /// sequence on DDI B's AUX channel.
    fn smoke_gen9_external_dp_ddi_b_full_run() -> TestResult {
        use crate::intel_gpu_gen11_dpll::DPLL_CTRL1;
        use crate::intel_gpu_gen9_cdclk::CDCLK_CTL;
        use crate::intel_gpu_gen9_ddi::{ddi_buf_trans_hi, ddi_buf_trans_lo, DISPIO_CR_TX_BMU_CR0};
        use crate::intel_gpu_gen9_dpll::DPLL_CTRL2;
        use crate::intel_gpu_gen9_wm::{DBUF_CTL_S1, DBUF_POWER_REQUEST};
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
        // DSSM strap: 19.2 MHz (field 1) — irrelevant to the
        // Gen9 CDCLK (fixed 24 MHz reference), kept for parity
        // with the panel run.
        let mmio = ScriptedSinkMmio::new(1 << 29);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::A);
        ms.set_gen9_platform(crate::intel_gpu_gt::Gen9Platform::Skylake);
        ms.set_gen9_sku_family(crate::intel_gpu_gen9_ddi::SkuFamily::Desktop);
        let plan = LinkPlan {
            rate: crate::dp_link_training::LinkRate::Hbr2,
            lanes: 4,
        };
        let (mode, trained) = match ms.modeset_with_plan(&fb_1080p(), &mode_1080p60(), plan) {
            Ok((m, t)) => (m, t),
            Err(_) => return TestResult::Fail("Gen9 external DP on DDI B must succeed"),
        };
        if mode.pixel_clock_khz != 148_500
            || trained.rate != crate::dp_link_training::LinkRate::Hbr2
            || trained.lanes != 4
        {
            return TestResult::Fail("external DP must train at HBR2 x4 for 1080p60");
        }
        // CDCLK: the same 337.5 MHz rung as the panel run,
        // programmed before the DP DPLL.
        if mmio.writes_to(CDCLK_CTL)
            != [
                0x0800_02A1,
                0x0808_02A1,
                0x0008_0000,
                0x0808_02A1,
                0x0800_02A1,
            ]
        {
            return TestResult::Fail("CDCLK_CTL writes are not the panel run's sequence");
        }
        let writes = mmio.writes.borrow();
        let cdclk_at = writes
            .iter()
            .position(|(o, v)| *o == CDCLK_CTL && *v == 0x0800_02A1)
            .unwrap_or(usize::MAX);
        let dpll_at = writes
            .iter()
            .position(|(o, v)| *o == DPLL_CTRL1 && *v == 0x45)
            .unwrap_or(usize::MAX);
        drop(writes);
        if cdclk_at >= dpll_at {
            return TestResult::Fail("CDCLK was not programmed before the DP DPLL");
        }
        // DPLL_CTRL1: the CDCLK VCO program (0x5) then the
        // DPLL1 HBR2 link state (0x1 << 6 = 0x40, RMW'd over
        // the VCO field: 0x45).
        if mmio.writes_to(DPLL_CTRL1) != [0x5, 0x45] {
            return TestResult::Fail("DPLL_CTRL1 writes are not [0x5, 0x45]");
        }
        // DPLL_CTRL2 routes DDI B to DPLL1 with override:
        // sel 1 << 4 | override 1 << 3 = 0x18.
        if mmio.writes_to(DPLL_CTRL2) != [0x18] {
            return TestResult::Fail("DPLL_CTRL2 writes are not [0x18]");
        }
        // The DDI IO well for port B (idx 2) was requested —
        // no PW_1/PW_2 writes for the always-on Pipe A.
        if mmio.writes_to(PWR_WELL_CTL2) != [0x20] {
            return TestResult::Fail("PWR_WELL_CTL2 writes are not [0x20] (DDI IO B only)");
        }
        // DBUF slice S1 power-requested.
        if mmio
            .writes_to(DBUF_CTL_S1)
            .iter()
            .all(|w| w & DBUF_POWER_REQUEST == 0)
        {
            return TestResult::Fail("DBUF_CTL_S1 was never power-requested");
        }
        // Watermarks: the same 8 levels as the panel run
        // (same mode, pipe, latencies), TRANS 0, and the full
        // 892-block DBUF in BUF_CFG.
        let wm_base = Pipe::A.base() + PLANE_WM_BASE_OFFSET;
        let want_wm: [u32; 8] = [
            0x8000_0008,
            0x8000_4011,
            0x8000_4012,
            0x8000_8017,
            0x8000_801E,
            0x8000_C026,
            0x8000_C031,
            0x8001_003F,
        ];
        for (level, want) in want_wm.iter().enumerate() {
            let got = mmio.writes_to(wm_base + (level as u64) * 4);
            if got.last() != Some(want) {
                return TestResult::Fail("a PLANE_WM level is not the panel run's value");
            }
        }
        if mmio.writes_to(wm_base + PLANE_WM_TRANS_OFFSET) != [0x0] {
            return TestResult::Fail("PLANE_WM_TRANS is not 0");
        }
        if mmio.writes_to(Pipe::A.base() + PLANE_BUF_CFG_OFFSET) != [0x037B_0000] {
            return TestResult::Fail("PLANE_BUF_CFG is not the full 892-block DBUF");
        }
        // The 9-entry SKL DP buffer table was programmed at
        // DDI_BUF_TRANS_B (0x64E60); no 10th entry exists.
        if mmio.writes_to(ddi_buf_trans_lo(Ddi::B, 0)) != [0x0000_2016]
            || mmio.writes_to(ddi_buf_trans_hi(Ddi::B, 0)) != [0x0000_00A0]
        {
            return TestResult::Fail("DDI_BUF_TRANS entry 0 is not the SKL DP table entry 0");
        }
        if mmio.writes_to(ddi_buf_trans_lo(Ddi::B, 8)) != [0x8000_5012]
            || mmio.writes_to(ddi_buf_trans_hi(Ddi::B, 8)) != [0x0000_00C0]
        {
            return TestResult::Fail("DDI_BUF_TRANS entry 8 is not the SKL DP table entry 8");
        }
        if !mmio.writes_to(ddi_buf_trans_lo(Ddi::B, 9)).is_empty() {
            return TestResult::Fail("DDI_BUF_TRANS entry 9 was written — port B DP caps at 9");
        }
        // I_boost: the level-4 table entry's boost is 0, so
        // the prepare + set-levels writes both disable port
        // B's balance leg (1 << 24).
        let iboost = mmio.writes_to(DISPIO_CR_TX_BMU_CR0);
        if iboost.len() < 2 || iboost.iter().any(|w| *w != 0x0100_0000) {
            return TestResult::Fail(
                "DISPIO_CR_TX_BMU_CR0 must be all 0x01000000 (port B disable)",
            );
        }
        // DDI_BUF_CTL for DDI B (0x64100): the disable-first
        // write (readback 0x80); the level-0 select the training
        // core's first TRAINING_LANE_SET (0, 0) asks for
        // (TRANS_SELECT 0, so the same 0x80 — Linux's
        // `hsw_set_signal_levels` writes DDI_BUF_CTL on every
        // level change); the sink's swing-1 request at CR and
        // again at EQ (level 4, 0x04000080); then the enable
        // (0x84000086 — IDLE bit RMW'd in, as on the panel
        // run). DDI A is never enabled.
        if mmio.writes_to(0x64100) != [0x80, 0x80, 0x0400_0080, 0x0400_0080, 0x8400_0086] {
            return TestResult::Fail(
                "DDI_BUF_CTL B must be [0x80, 0x80, 0x04000080, 0x04000080, 0x84000086]",
            );
        }
        if !mmio.writes_to(0x64000).is_empty() {
            return TestResult::Fail("Gen9 DDI B run must not touch DDI A");
        }
        // Training ended with DP_TP_CTL NORMAL (0x80040300)
        // and the Gen12 transcoder DP_TP_CTL was never touched.
        if mmio.writes_to(0x64140).last() != Some(&0x8004_0300) {
            return TestResult::Fail("DP_TP_CTL last write is not 0x80040300");
        }
        if !mmio.writes_to(0x60540).is_empty() {
            return TestResult::Fail(
                "Gen12 transcoder DP_TP_CTL 0x60540 was written on a Gen9 run",
            );
        }
        // TRANS_DDI_FUNC_CTL at the Transcoder A base
        // (0x60400): DP-SST, 8 bpc, 4 lanes, DDI B selected
        // (0x92000006); the EDP transcoder is untouched.
        if mmio.writes_to(0x60400).last() != Some(&0x9200_0006) {
            return TestResult::Fail(
                "TRANS_DDI_FUNC_CTL must bind transcoder A to DDI B in DP-SST",
            );
        }
        if !mmio.writes_to(0x6F400).is_empty() {
            return TestResult::Fail(
                "EDP transcoder FUNC_CTL 0x6F400 was written on an external run",
            );
        }
        // No Tiger Lake DPLL/CFGCR registers on this run:
        // TGL CFGCR0 is 0x164284, DPCLKA is 0x164280.
        for off in [0x164284_u64, 0x164280_u64] {
            if !mmio.writes_to(off).is_empty() {
                return TestResult::Fail("a Tiger Lake register was written on a Gen9 run");
            }
        }
        // Training ran clean on DDI B's AUX channel: the sink
        // is powered, the pattern history is TPS1 → TPS3 →
        // off, and every tune is swing 1.
        let sink = mmio.sink.borrow();
        if sink.power != 1 || sink.pattern != 0 {
            return TestResult::Fail("sink is not powered in pattern 0 after training");
        }
        if sink.pattern_history != alloc::vec![1u8, 3, 0] {
            return TestResult::Fail("sink pattern history is not [1, 3, 0]");
        }
        if sink.tunes.iter().any(|t| t & 0x3 != 1) {
            return TestResult::Fail("sink tunes are not all swing 1");
        }
        drop(sink);
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_external_dp_ddi_b_full_run
    );

    /// Gen9: the HDMI path on DDI B (Lane 8) — the SKL WRPLL
    /// row, the SKL HDMI table entry, and the Wa #1143 pulse.
    /// The DMC gate is exercised first (refusal, no writes),
    /// then the full run.
    fn smoke_gen9_hdmi_ddi_b_full_run() -> TestResult {
        use crate::intel_gpu_gen11_dpll::DPLL_CTRL1;
        use crate::intel_gpu_gen9_cdclk::CDCLK_CTL;
        use crate::intel_gpu_gen9_ddi::{
            chicken_trans_for_port, ddi_buf_trans_hi, ddi_buf_trans_lo, DISPIO_CR_TX_BMU_CR0,
        };
        use crate::intel_gpu_gen9_dpll::DPLL_CTRL2;
        // DSSM strap: 24 MHz (field 0).
        let mmio = ScriptedSinkMmio::new(0);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::A);
        ms.set_gen9_platform(crate::intel_gpu_gt::Gen9Platform::Skylake);
        ms.set_gen9_sku_family(crate::intel_gpu_gen9_ddi::SkuFamily::Desktop);
        // DMC gate: the HDMI entry refuses without DMC and
        // writes nothing. The flag is global: a failed earlier
        // Gen9 run can leave it set, so the precondition is set
        // here.
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
        let refused = ms.modeset_hdmi(&fb_1080p(), &mode_1080p60(), false, false);
        if refused != Err(ModesetError::DmcUnavailable) {
            return TestResult::Fail("Gen9 HDMI must refuse without DMC");
        }
        if !mmio.writes.borrow().is_empty() {
            return TestResult::Fail("Gen9 HDMI refusal wrote registers");
        }
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
        let mode = match ms.modeset_hdmi(&fb_1080p(), &mode_1080p60(), false, false) {
            Ok(m) => m,
            Err(_) => return TestResult::Fail("Gen9 HDMI on DDI B must succeed"),
        };
        if mode.pixel_clock_khz != 148_500 {
            return TestResult::Fail("HDMI must commit the 1080p60 mode");
        }
        // WRPLL row for 148.5 MHz at the fixed 24 MHz ref
        // (divider 12, DCO 371 + 0x2000, Q/3 K/2 P/2):
        // CFGCR1 0x80400173, CFGCR2 0x3A5 at the DPLL1 pair
        // (0x6C040/0x6C044). DPLL0 has no CFGCRs.
        if mmio.writes_to(0x6C040) != [0x8040_0173] {
            return TestResult::Fail("Gen9 HDMI CFGCR1 must be the WRPLL row at 0x6C040");
        }
        if mmio.writes_to(0x6C044) != [0x3A5] {
            return TestResult::Fail("Gen9 HDMI CFGCR2 must be Q/3 K/2 P/2 at 0x6C044");
        }
        // DPLL_CTRL1: the HDMI DPLL1 program (OVERRIDE |
        // HDMI_MODE << 6 = 0x840), then the CDCLK VCO program
        // RMW'd over the DPLL0 field (0x845).
        if mmio.writes_to(DPLL_CTRL1) != [0x840, 0x845] {
            return TestResult::Fail("DPLL_CTRL1 writes are not [0x840, 0x845]");
        }
        // DPLL1 CTL enabled (LCPLL2_CTL 0x46014).
        if mmio.writes_to(0x46014) != [0x8000_0000] {
            return TestResult::Fail("DPLL1 CTL must enable at 0x46014");
        }
        // DPLL_CTRL2 routes DDI B to DPLL1 with override.
        if mmio.writes_to(DPLL_CTRL2) != [0x18] {
            return TestResult::Fail("DPLL_CTRL2 writes are not [0x18]");
        }
        // The DDI IO well for port B (idx 2).
        if mmio.writes_to(PWR_WELL_CTL2) != [0x20] {
            return TestResult::Fail("PWR_WELL_CTL2 writes are not [0x20] (DDI IO B only)");
        }
        // CDCLK: the same 337.5 MHz rung as the panel run.
        if mmio.writes_to(CDCLK_CTL)
            != [
                0x0800_02A1,
                0x0808_02A1,
                0x0008_0000,
                0x0808_02A1,
                0x0800_02A1,
            ]
        {
            return TestResult::Fail("CDCLK_CTL writes are not the panel run's sequence");
        }
        // TRANS_DDI_FUNC_CTL (transcoder A + 0x400): HDMI
        // mode, 8 bpc, 4 lanes, DDI B selected — no scrambling
        // at 148.5 MHz.
        if mmio.writes_to(0x60400).last() != Some(&0x9000_0006) {
            return TestResult::Fail("Gen9 HDMI must bind transcoder A to DDI B in HDMI mode");
        }
        // Watermarks: the same 8 levels as the panel run
        // (same mode, pipe, latencies), TRANS 0, and the full
        // 892-block DBUF in BUF_CFG.
        let wm_base = Pipe::A.base() + PLANE_WM_BASE_OFFSET;
        let want_wm: [u32; 8] = [
            0x8000_0008,
            0x8000_4011,
            0x8000_4012,
            0x8000_8017,
            0x8000_801E,
            0x8000_C026,
            0x8000_C031,
            0x8001_003F,
        ];
        for (level, want) in want_wm.iter().enumerate() {
            let got = mmio.writes_to(wm_base + (level as u64) * 4);
            if got.last() != Some(want) {
                return TestResult::Fail("a PLANE_WM level is not the panel run's value");
            }
        }
        if mmio.writes_to(wm_base + PLANE_WM_TRANS_OFFSET) != [0x0] {
            return TestResult::Fail("PLANE_WM_TRANS is not 0");
        }
        if mmio.writes_to(Pipe::A.base() + PLANE_BUF_CFG_OFFSET) != [0x037B_0000] {
            return TestResult::Fail("PLANE_BUF_CFG is not the full 892-block DBUF");
        }
        // HDMI signal levels: the SKL HDMI default entry
        // (index 8) at BUF_TRANS index 9, I_boost 1 on port
        // B, and the Wa #1143 pulse on CHICKEN_TRANS_A.
        if mmio.writes_to(ddi_buf_trans_lo(Ddi::B, 9)) != [0x8000_3015]
            || mmio.writes_to(ddi_buf_trans_hi(Ddi::B, 9)) != [0x0000_00CD]
        {
            return TestResult::Fail("DDI_BUF_TRANS index 9 is not the SKL HDMI default entry");
        }
        if mmio.writes_to(DISPIO_CR_TX_BMU_CR0) != [0x800] {
            return TestResult::Fail("DISPIO_CR_TX_BMU_CR0 must be 0x800 (port B I_boost 1)");
        }
        if mmio.writes_to(chicken_trans_for_port(Ddi::B).unwrap()) != [0xC0000, 0x0] {
            return TestResult::Fail("Wa #1143 pulse must set then clear bits 19|18");
        }
        // DDI_BUF_CTL for DDI B: disable-first (0x80) then
        // enable (0x80000086); no training writes on HDMI.
        if mmio.writes_to(0x64100) != [0x80, 0x8000_0086] {
            return TestResult::Fail("Gen9 HDMI DDI B buffer must enable at 4 lanes");
        }
        // No DP training on a TMDS link: DP_TP_CTL B untouched.
        if !mmio.writes_to(0x64140).is_empty() {
            return TestResult::Fail("Gen9 HDMI must not touch DP_TP_CTL");
        }
        // No Tiger Lake registers, no DDI A, no EDP transcoder.
        for off in [0x164284_u64, 0x164280_u64] {
            if !mmio.writes_to(off).is_empty() {
                return TestResult::Fail("a Tiger Lake register was written on a Gen9 run");
            }
        }
        if !mmio.writes_to(0x64000).is_empty() {
            return TestResult::Fail("Gen9 HDMI run must not touch DDI A");
        }
        if !mmio.writes_to(0x6F400).is_empty() {
            return TestResult::Fail("EDP transcoder FUNC_CTL 0x6F400 was written on an HDMI run");
        }
        crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen9_hdmi_ddi_b_full_run
    );

    fn smoke_gen11_external_dp_ddi_b_full_run() -> TestResult {
        use crate::intel_gpu_gt::Gen11Platform;
        // DSSM strap: 19.2 MHz (field 1).
        let mmio = ScriptedSinkMmio::new(1 << 29);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::A);
        ms.set_gen11_platform(Gen11Platform::IceLake);
        let plan = LinkPlan {
            rate: crate::dp_link_training::LinkRate::Hbr2,
            lanes: 4,
        };
        let (mode, trained) = match ms.modeset_with_plan(&fb_1080p(), &mode_1080p60(), plan) {
            Ok((m, t)) => (m, t),
            Err(_) => return TestResult::Fail("Gen11 external DP on DDI B must succeed"),
        };
        if mode.pixel_clock_khz != 148_500
            || trained.rate != crate::dp_link_training::LinkRate::Hbr2
            || trained.lanes != 4
        {
            return TestResult::Fail("external DP must train at HBR2 x4 for 1080p60");
        }
        // DPLL1 (0x164080): the HBR2 row of the 19.2 MHz family;
        // DPLL0 is never programmed on this run.
        if mmio.writes_to(0x164080) != alloc::vec![0x01C0_01A5] {
            return TestResult::Fail("Gen11 DDI B CFGCR0 must be the HBR2 row at 0x164080");
        }
        if !mmio.writes_to(0x164000).is_empty() {
            return TestResult::Fail("Gen11 DDI B run must not program DPLL0");
        }
        // DPCLKA: DDI B selects DPLL1 (0x4), clock on, in the
        // PRM's two writes.
        if mmio.writes_to(0x164280) != alloc::vec![0x804, 0x4] {
            return TestResult::Fail("Gen11 DPCLKA must select DPLL1 for DDI B, clock on");
        }
        // Training really happened on DDI B's AUX channel:
        // TPS1 → TPS3 → off, swing 1 applied on all lanes.
        let sink = mmio.sink.borrow();
        if sink.pattern_history != alloc::vec![1u8, 3, 0] {
            return TestResult::Fail("DDI B training pattern sequence must be TPS1, TPS3, off");
        }
        if sink.tunes.iter().any(|t| t & 0x3 != 1) {
            return TestResult::Fail("sink-requested swing 1 must be applied on all lanes");
        }
        drop(sink);
        // Combo-PHY signal levels (PHY_B, 0x06C000): the same
        // preset-4 ICL DP values as the DDI A run, at the PHY_B
        // block.
        let phy = 0x06C000u64;
        if mmio.writes_to(phy + 0x888).last() != Some(&0x9098) {
            return TestResult::Fail("DW2 LN0 must carry the preset-4 swing on PHY_B");
        }
        if mmio.writes_to(phy + 0x89C).last() != Some(&0x4C00_0000) {
            return TestResult::Fail("DW7 LN0 must carry the ICL preset-4 N-scalar on PHY_B");
        }
        // DP_TP_CTL is port-based: DDI B base + 0x40 (0x64140)
        // ends at NORMAL; the TGL transcoder register is never
        // written.
        if mmio.writes_to(0x64140).last() != Some(&0x8004_0300) {
            return TestResult::Fail("Gen11 DDI B DP_TP_CTL must end at NORMAL");
        }
        if !mmio.writes_to(0x60540).is_empty() {
            return TestResult::Fail("Gen11 must never write the TGL transcoder DP_TP_CTL");
        }
        // DDI_BUF_CTL for DDI B (0x64100): step 3's disable-first
        // writes the readback (IDLE set, ENABLE clear: 0x80),
        // then the enable writes ENABLE | (4-1)<<1 plus the
        // IDLE bit the fixture serves pre-enable (0x8000_0086);
        // DDI A is never enabled.
        if mmio.writes_to(0x64100) != alloc::vec![0x80, 0x8000_0086] {
            return TestResult::Fail("Gen11 DDI B buffer must enable at 4 lanes");
        }
        if !mmio.writes_to(0x64000).is_empty() {
            return TestResult::Fail("Gen11 DDI B run must not touch DDI A");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen11_external_dp_ddi_b_full_run
    );

    /// Rocket Lake external DP on combo DDI B / Pipe A at HBR2 x4,
    /// 1080p60, 19.2 MHz strap. Hand-computed RKL deltas from the TGL run:
    /// CDCLK from `rkl_cdclk_table` (floor 74.25 MHz -> 172.8 MHz at ratio
    /// 36, VCO / 4: DE_PLL_ENABLE [0, 36, 0x80000024], CDCLK_CTL DIV_SEL 2
    /// | pipe none | decimal 344 = 0x00B80158) and no PW_2 request. DDI B's
    /// PLL and clock routing are Tiger Lake's on RKL: DPLL1 at
    /// `RKL_DPLL_CFGCR0/1(1)` = 0x16428C / 0x164290 (the HBR2 row), and
    /// DPCLKA phy B select 1 at bits 3:2 with CLK_OFF bit 11.
    fn smoke_rkl_external_dp_ddi_b_full_run() -> TestResult {
        use crate::intel_gpu_gen12_cdclk::{CDCLK_CTL, DE_PLL_ENABLE};
        use crate::intel_gpu_gt::Gen12Platform;
        let mmio = ScriptedSinkMmio::new(1 << 29);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::A);
        ms.set_gen12_family(Gen12Platform::RocketLake);
        let plan = LinkPlan {
            rate: crate::dp_link_training::LinkRate::Hbr2,
            lanes: 4,
        };
        let trained = match ms.modeset_with_plan(&fb_1080p(), &mode_1080p60(), plan) {
            Ok((_, t)) => t,
            Err(_) => return TestResult::Fail("RKL external DP on DDI B must succeed"),
        };
        if trained.rate != crate::dp_link_training::LinkRate::Hbr2 || trained.lanes != 4 {
            return TestResult::Fail("RKL DDI B must train at HBR2 x4");
        }
        if mmio.writes_to(DE_PLL_ENABLE) != alloc::vec![0, 36, 0x8000_0024] {
            return TestResult::Fail("RKL CDCLK PLL must relock at the rkl_cdclk_table ratio 36");
        }
        if mmio.writes_to(CDCLK_CTL) != alloc::vec![0x00B8_0158] {
            return TestResult::Fail("RKL CDCLK_CTL must divide the 691.2 MHz VCO by 4");
        }
        let pg2 = super::pwr_well_req(super::PowerWell::Pg2 as u32);
        if mmio.writes_to(PWR_WELL_CTL2).iter().any(|v| v & pg2 != 0) {
            return TestResult::Fail("RKL must never request PW_2");
        }
        if mmio.writes_to(0x16428C) != alloc::vec![0x01C0_01A5]
            || mmio.writes_to(0x164290) != alloc::vec![0x4B]
        {
            return TestResult::Fail("RKL DDI B must program DPLL1 at the HBR2 row");
        }
        if mmio.writes_to(0x164280) != alloc::vec![0x804, 0x4] {
            return TestResult::Fail("RKL DPCLKA must select DPLL1 for PHY B, clock on");
        }
        let tp = crate::intel_gpu_pipes::Transcoder::A.base() + 0x540;
        if mmio.writes_to(tp).last() != Some(&0x8004_0300) {
            return TestResult::Fail("RKL DP_TP_CTL is transcoder-based and must end at NORMAL");
        }
        if mmio.sink.borrow().pattern_history != alloc::vec![1u8, 3, 0] {
            return TestResult::Fail("RKL DDI B training must run TPS1, TPS3, off");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_rkl_external_dp_ddi_b_full_run
    );

    fn smoke_gen11_hdmi_ddi_b_full_run() -> TestResult {
        use crate::intel_gpu_gt::Gen11Platform;
        // DSSM strap: 24 MHz (field 0) — the WRPLL row for
        // 148.5 MHz at 24 MHz is the pinned DCO 371 + 0x2000.
        let mmio = ScriptedSinkMmio::new(0);
        let mut ms = Modeset::for_pipe(&mmio, Ddi::B, Pipe::A);
        ms.set_gen11_platform(Gen11Platform::IceLake);
        let mode = match ms.modeset_hdmi(&fb_1080p(), &mode_1080p60(), false, false) {
            Ok(m) => m,
            Err(_) => return TestResult::Fail("Gen11 HDMI on DDI B must succeed"),
        };
        if mode.pixel_clock_khz != 148_500 {
            return TestResult::Fail("HDMI must commit the 1080p60 mode");
        }
        // WRPLL coefficients for 148.5 MHz at 24 MHz (DCO 371 +
        // 0x2000, Q/3 K/2 P/2), written to the ICL CFGCR pair
        // for DPLL1 (0x164080/0x164084); DPLL0 untouched.
        if mmio.writes_to(0x164080) != alloc::vec![0x0080_0173] {
            return TestResult::Fail("Gen11 HDMI CFGCR0 must be the WRPLL row at 0x164080");
        }
        if mmio.writes_to(0x164084) != alloc::vec![0xE87] {
            return TestResult::Fail("Gen11 HDMI CFGCR1 must be Q/3 K/2 P/2 CFREQ");
        }
        if !mmio.writes_to(0x164000).is_empty() {
            return TestResult::Fail("Gen11 HDMI run must not program DPLL0");
        }
        // DPCLKA: DDI B selects DPLL1, clock on.
        if mmio.writes_to(0x164280) != alloc::vec![0x804, 0x4] {
            return TestResult::Fail("Gen11 HDMI DPCLKA must select DPLL1 for DDI B");
        }
        // TRANS_DDI_FUNC_CTL (transcoder A + 0x400): HDMI mode,
        // 8 bpc, 4 lanes, DDI B selected — no scrambling at
        // 148.5 MHz.
        if mmio.writes_to(0x60400).last() != Some(&0x9000_0006) {
            return TestResult::Fail("Gen11 HDMI must bind transcoder A to DDI B in HDMI mode");
        }
        // Combo-PHY HDMI default levels (ICL HDMI table entry 6
        // {0x6, 0x7F, 0x35, 0x00, 0x0A}) at the PHY_B block:
        // DW2 = swing 0x6 + RCOMP 0x98, DW7 = N-scalar 0x7F,
        // common keeper cleared.
        let phy = 0x06C000u64;
        if mmio.writes_to(phy + 0x888).last() != Some(&0x3098) {
            return TestResult::Fail("HDMI DW2 LN0 must carry the default-entry swing on PHY_B");
        }
        if mmio.writes_to(phy + 0x89C).last() != Some(&0x7F00_0000) {
            return TestResult::Fail("HDMI DW7 LN0 must carry the default-entry N-scalar");
        }
        if mmio.writes_to(phy + 0x604).last() != Some(&0) {
            return TestResult::Fail("HDMI must clear the common keeper");
        }
        // DDI_BUF_CTL for DDI B enabled at 4 lanes: the
        // disable-first stop write (readback 0x80, IDLE set,
        // ENABLE clear) precedes the enable (0x8000_0086),
        // same as the external-DP run.
        if mmio.writes_to(0x64100) != alloc::vec![0x80, 0x8000_0086] {
            return TestResult::Fail("Gen11 HDMI DDI B buffer must enable at 4 lanes");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen11_hdmi_ddi_b_full_run
    );

    fn smoke_gen11_tc_dp_ddi_c_full_run() -> TestResult {
        use crate::intel_gpu_gt::Gen11Platform;
        // DSSM strap: 19.2 MHz (field 1).
        let mmio = ScriptedSinkMmio::new(1 << 29);
        // Fail clock recovery on the first attempt (HBR2) so the
        // ladder falls back to HBR — this exercises the MG
        // retune (disable + re-enable + re-route) mid-training.
        mmio.sink.borrow_mut().fail_cr_attempts = 1;
        let mut ms = Modeset::for_pipe(&mmio, Ddi::C, Pipe::A);
        ms.set_gen11_platform(Gen11Platform::IceLake);
        let plan = LinkPlan {
            rate: crate::dp_link_training::LinkRate::Hbr2,
            lanes: 4,
        };
        let (mode, trained) = match ms.modeset_with_plan(&fb_1080p(), &mode_1080p60(), plan) {
            Ok((m, t)) => (m, t),
            Err(_) => return TestResult::Fail("Gen11 TC DP on DDI C must succeed"),
        };
        if mode.pixel_clock_khz != 148_500
            || trained.rate != crate::dp_link_training::LinkRate::Hbr
            || trained.lanes != 4
        {
            return TestResult::Fail("TC DP must fall back to HBR x4 for 1080p60");
        }
        // Two attempts: TPS1, off (CR failed), TPS1, TPS2
        // (HBR EQ), off.
        if mmio.sink.borrow().pattern_history != alloc::vec![1u8, 0, 1, 2, 0] {
            return TestResult::Fail("TC fallback must retry training at the lower rate");
        }
        // MG PLL (TC1, 0x46030): power + enable, then the retune
        // cycles it (disable: enable off, power off) and brings
        // it back up.
        if mmio.writes_to(0x46030)
            != alloc::vec![
                0x0800_0000,
                0x8800_0000,
                0x0800_0000,
                0x0,
                0x0800_0000,
                0x8800_0000
            ]
        {
            return TestResult::Fail("MG PLL must cycle power + enable across the retune");
        }
        // MG DIV0 (0x168A00) carries the HBR2 state (DCO 8.1 GHz
        // at 19.2 MHz — the same DCO the HBR retune reuses).
        if mmio.writes_to(0x168A00) != alloc::vec![0x7C00_00D2, 0x7C00_00D2] {
            return TestResult::Fail("MG DIV0 must carry the HBR2/HBR state at both enables");
        }
        // The retune re-selected the clock-top dividers for HBR
        // (div1=3, div2=2): hsclk 0x9200, not the HBR2 0x1100.
        if mmio.writes_to(0x1688D4).last() != Some(&0x9200) {
            return TestResult::Fail("MG retune must reprogram the HBR clock-top dividers");
        }
        // DDI clock routing: MG select, then the retune clears
        // it and re-routes; DPCLKA TC_CLK_OFF (bit 12) clears,
        // sets on disable, clears again.
        if mmio.writes_to(0x46108) != alloc::vec![0x8000_0000, 0x0, 0x8000_0000] {
            return TestResult::Fail("TC clock routing must cycle MG select across the retune");
        }
        if mmio.writes_to(0x164280) != alloc::vec![0x0, 0x1000, 0x0] {
            return TestResult::Fail("DPCLKA TC_CLK_OFF must cycle across the retune");
        }
        // Display-11 transcoder clock: (port + 1) << 29 at
        // TRANS_CLK_SEL(A) — DDI C is port index 2.
        if mmio.writes_to(0x46140).last() != Some(&0x6000_0000) {
            return TestResult::Fail("TC transcoder clock must be the ICL (port+1)<<29 value");
        }
        // MG signal levels: the fallback settled at HBR, so the
        // final program is the RBR/HBR table entry 4
        // {0x21, 0x00, 0x00} — DRVCTRL 0x21 << 24 | override
        // enable — not the HBR2 table's 0x26.
        if mmio.writes_to(0x168144).last() != Some(&0x2140_0000) {
            return TestResult::Fail(
                "MG DRVCTRL must carry the RBR/HBR table entry after fallback",
            );
        }
        // DP_TP_CTL is port-based: DDI C base + 0x40 (0x64240)
        // ends at NORMAL; the TGL transcoder register and the
        // Dekel HIP bank are never written.
        if mmio.writes_to(0x64240).last() != Some(&0x8004_0300) {
            return TestResult::Fail("Gen11 DDI C DP_TP_CTL must end at NORMAL");
        }
        if !mmio.writes_to(0x60540).is_empty() || !mmio.writes_to(0x1010A0).is_empty() {
            return TestResult::Fail("Gen11 TC must never write the TGL DP_TP_CTL or the HIP bank");
        }
        // DDI_BUF_CTL for DDI C (0x64200) enabled at 4 lanes
        // after the retune's stop + re-enable.
        let buf = mmio.writes_to(0x64200);
        if buf.last() != Some(&0x8000_0086) || !buf.contains(&0x6) {
            return TestResult::Fail("Gen11 DDI C buffer must stop and re-enable at 4 lanes");
        }
        // No combo DPLL was programmed on this run.
        if !mmio.writes_to(0x164000).is_empty() || !mmio.writes_to(0x164080).is_empty() {
            return TestResult::Fail("Gen11 TC run must not program a combo DPLL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_gen11_tc_dp_ddi_c_full_run
    );

    fn smoke_modeset_fallback_retunes_combo_dpll() -> TestResult {
        // DSSM strap: 19.2 MHz (field 1), EDID 1080p60 mode.
        let mmio = ScriptedSinkMmio::new(1 << 29);
        // Fail clock recovery on the first attempt (HBR2) so
        // the ladder falls back to HBR; the second attempt
        // trains.
        mmio.sink.borrow_mut().fail_cr_attempts = 1;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        if ms.modeset(&fb_1080p(), None).is_err() {
            return TestResult::Fail(
                "modeset with a first-attempt CR failure must fall back and succeed",
            );
        }
        // Two attempts: TPS1, off (CR failed), TPS1, TPS2
        // (HBR EQ), off.
        if mmio.sink.borrow().pattern_history != alloc::vec![1u8, 0, 1, 2, 0] {
            return TestResult::Fail("fallback must retry training at the lower rate");
        }
        // DPLL: programmed at the HBR2 row the first attempt
        // trains at (CFGCR1 KDIV_1 | PDIV_3 | CFREQ = 0x4B), then
        // retuned mid-training to HBR (KDIV_2 | PDIV_3 |
        // CFREQ = 0x8B) when the fallback retry opened. CFGCR0
        // is the same DCO row at both rates, so CFGCR1 is the
        // rate witness.
        let cfgcr1 = crate::intel_gpu_pll::dpll_cfgcr1(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0);
        if mmio.writes_to(cfgcr1) != alloc::vec![0x4B, 0x8B] {
            return TestResult::Fail(
                "fallback must reprogram CFGCR1 from the HBR2 row to the HBR row",
            );
        }
        // DPLL enable cycled by the retune: step-4 power +
        // enable, then disable (enable off, power off) +
        // bring-up.
        if mmio.writes_to(super::DPLL0_ENABLE)
            != alloc::vec![
                0x0800_0000,
                0x8C00_0000,
                0x0800_0000,
                0,
                0x0800_0000,
                0x8800_0000
            ]
        {
            return TestResult::Fail("fallback must disable then re-enable the DPLL");
        }
        // M/N carries the settled link: HBR symbol clock
        // (2_700_000 / 10 = 270_000 kHz) over 4 lanes.
        use crate::intel_gpu_pipes::{dp_mn, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET};
        let (_, _, lm, ln) = dp_mn(148_500, 270_000, 4, 3);
        let trans_base = crate::intel_gpu_pipes::Transcoder::A.base();
        if mmio.writes_to(trans_base + PIPE_LINK_M1_OFFSET).last() != Some(&lm)
            || mmio.writes_to(trans_base + PIPE_LINK_N1_OFFSET).last() != Some(&ln)
        {
            return TestResult::Fail("fallback must reprogram M/N for the settled HBR link");
        }
        // DP_TP_CTL returns to NORMAL once training ends.
        let tp = crate::intel_gpu_pipes::Transcoder::A.base() + 0x540;
        if mmio.writes_to(tp).last() != Some(&0x8004_0300) {
            return TestResult::Fail("DP_TP_CTL must end at NORMAL after fallback training");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_fallback_retunes_combo_dpll
    );

    fn smoke_modeset_uy_window_selects_uy_hbr2_table() -> TestResult {
        // Same scripted-sink run as
        // `smoke_modeset_full_run_scripted_sink`, but over a
        // Tiger Lake UY window: the sink trains at HBR2 and
        // asks for swing 1, so the final program is preset 4 —
        // and preset 4 is where the UY HBR2 table differs from
        // the standard one (swing select 0xC vs 0xA; the
        // N-scalar 0x47 and cursor 0x3F agree). The UY window
        // is the whole wiring under test: `Modeset::for_pipe`
        // derives `tgl_uy` from it, and the shared
        // `train_dp_link` combo branch programs the PHY from
        // that flag — the same branch external DP and the MST
        // primary stream run through.
        let mut mmio = ScriptedSinkMmio::new(1 << 29);
        mmio.tgl_uy = true;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        if ms.modeset(&fb_1080p(), None).is_err() {
            return TestResult::Fail("full modeset over a UY window must succeed");
        }
        let phy = 0x162000u64;
        if mmio.writes_to(phy + 0x888).last() != Some(&0xA098) {
            return TestResult::Fail("DW2 LN0 must carry the UY preset-4 swing (0xC)");
        }
        if mmio.writes_to(phy + 0x89C).last() != Some(&0x4700_0000) {
            return TestResult::Fail("DW7 LN0 must carry the preset-4 N-scalar");
        }
        if mmio.writes_to(phy + 0x890).last() != Some(&0x3F) {
            return TestResult::Fail("DW4 must carry the preset-4 cursor");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_uy_window_selects_uy_hbr2_table
    );

    fn smoke_modeset_full_run_ref24_pll_row() -> TestResult {
        // Same run on a 24 MHz-strapped part: only the DPLL
        // row changes.
        let mmio = ScriptedSinkMmio::new(0);
        let mut ms = Modeset::new(&mmio, Ddi::A);
        if ms.modeset(&fb_1080p(), None).is_err() {
            return TestResult::Fail("full modeset must succeed on the 24 MHz strap");
        }
        let cfgcr0 = mmio.writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0);
        if cfgcr0 != alloc::vec![0x0100_0151] {
            return TestResult::Fail("CFGCR0 must be the 24-family DP DCO word");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_full_run_ref24_pll_row
    );

    fn smoke_modeset_dbuf_power_timeout() -> TestResult {
        let mut mmio = ScriptedSinkMmio::new(1 << 29);
        mmio.dbuf_grant = false;
        let mut ms = Modeset::new(&mmio, Ddi::A);
        match ms.modeset(&fb_1080p(), None) {
            Err(ModesetError::DbufPowerTimeout) => TestResult::Pass,
            _ => TestResult::Fail("ungranted DBUF slices must surface DbufPowerTimeout"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_dbuf_power_timeout
    );

    fn smoke_modeset_pcode_failure_falls_back_to_preboot() -> TestResult {
        let mut mmio = ScriptedSinkMmio::new(1 << 29);
        mmio.pcode_status = 0x1; // ILLEGAL_CMD on every command
        let mut ms = Modeset::new(&mmio, Ddi::A);
        if ms.modeset(&fb_1080p(), None).is_err() {
            return TestResult::Fail("pcode failure must degrade, not fail the modeset");
        }
        let wm_base = Pipe::A.base() + super::PLANE_WM_BASE_OFFSET;
        if mmio.writes_to(wm_base) != alloc::vec![super::PLANE_WM0_PREBOOT] {
            return TestResult::Fail("fallback must program the pre-boot level 0");
        }
        if mmio.writes_to(Pipe::A.base() + super::PLANE_BUF_CFG_OFFSET)
            != alloc::vec![super::PLANE_BUF_CFG_PREBOOT_A]
        {
            return TestResult::Fail("fallback must program the pre-boot BUF_CFG");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_pcode_failure_falls_back_to_preboot
    );
    fn smoke_modeset_gen12_xrgb_arb_slots_are_exact_source_family_literals() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        for (family, expected) in [
            (Gen12Platform::TigerLake, 0x84000000),
            (Gen12Platform::RocketLake, 0x84000000),
            (Gen12Platform::AlderLakeS, 0x84000000),
            (Gen12Platform::AlderLakeP, 0x94000000),
            (Gen12Platform::AlderLakeN, 0x94000000),
        ] {
            let mmio = FakeMmio::new();
            let mut ms = Modeset::new(&mmio, Ddi::A);
            ms.set_gen12_family(family);
            // Isolated stopped-plane bank: exercise the actual modeset
            // formatter and final CTL-before-SURF MMIO ordering.
            ms.program_plane(
                &fb_1080p(),
                &Mode {
                    h_active: 1920,
                    v_active: 1080,
                    ..Mode::VESA_1024X768_60
                },
            );
            assert_eq!(mmio.writes_to(0x70180), alloc::vec![expected]);
            let writes = mmio.writes.borrow();
            let ctl = writes.iter().position(|&(r, _)| r == 0x70180).unwrap();
            let surf = writes.iter().position(|&(r, _)| r == 0x7019c).unwrap();
            assert!(ctl < surf);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_modeset_gen12_xrgb_arb_slots_are_exact_source_family_literals
    );
    fn smoke_external_display_family_uses_exact_pci_ids_and_rejects_generation_aliases(
    ) -> TestResult {
        use crate::intel_gpu::{ChipInfo, Generation};
        use crate::intel_gpu_gt::Gen12Platform;
        for (did, generation, family) in [
            (0x9a49, Generation::TigerLake, Gen12Platform::TigerLake),
            (0x4c80, Generation::RocketLake, Gen12Platform::RocketLake),
            (0x4680, Generation::AlderLake, Gen12Platform::AlderLakeS),
            (0x46a6, Generation::AlderLake, Gen12Platform::AlderLakeP),
            (0x46d0, Generation::AlderLake, Gen12Platform::AlderLakeN),
        ] {
            let chip = ChipInfo {
                vid: 0x8086,
                did,
                generation,
                asic: "literal native fixture",
            };
            assert_eq!(gen12_family_for_chip(chip), Some(family));
            assert_eq!(
                gen12_family_for_chip(ChipInfo {
                    generation: Generation::MeteorLake,
                    ..chip
                }),
                None
            );
            assert_eq!(
                gen12_family_for_chip(ChipInfo {
                    vid: 0x1002,
                    ..chip
                }),
                None
            );
        }
        for (did, generation) in [
            (0x46ff, Generation::AlderLake),
            (0x7d55, Generation::MeteorLake),
        ] {
            assert_eq!(
                gen12_family_for_chip(ChipInfo {
                    vid: 0x8086,
                    did,
                    generation,
                    asic: "unsupported"
                }),
                None
            );
        }
        struct NoIo;
        impl MmioWindow for NoIo {
            fn read32(&self, _: u64) -> u32 {
                panic!("unknown exact PCI family read MMIO")
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("unknown exact PCI family wrote MMIO")
            }
        }
        assert_eq!(
            modeset_display_for_chip(
                &NoIo,
                ChipInfo {
                    vid: 0x8086,
                    did: 0x46ff,
                    generation: Generation::AlderLake,
                    asic: "unknown"
                },
                &fb_1080p(),
                Some(&Mode::VESA_1024X768_60)
            ),
            Err(ModesetError::UnsupportedGeneration)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_external_display_family_uses_exact_pci_ids_and_rejects_generation_aliases
    );

    // ── VRR modeset sequencing (#1769) ───────────────────────────────────
    //
    // The full-run fixture drives the real `modeset()` over the scripted
    // sink with VRR requested and asserts the Linux order in the write
    // log: timings programmed during transcoder configuration, TG
    // enabled after the transcoder. The disable fixture drives
    // `disable_pipeline()` with VRR live and asserts the disable lands
    // between the pipe stop and the transcoder stop.

    fn smoke_vrr_modeset_full_run_sequences_timings_then_enable() -> TestResult {
        use crate::intel_gpu_pipes::{Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET};
        use crate::intel_gpu_vrr::{
            DisplayVrrIp, VrrComputeOpts, VrrRange, VrrTimings, TRANS_VRR_CTL_OFFSET,
            TRANS_VRR_VMAX_OFFSET, TRANS_VRR_VMIN_OFFSET, VRR_CTL_VRR_ENABLE, VRR_STATE,
        };
        let range = VrrRange::new(48, 144).unwrap();
        VRR_STATE.set_range(1, Some(range));
        VRR_STATE.set_enabled(1, true);

        // DSSM strap: 19.2 MHz (field 1), as in the non-VRR full run.
        let mmio = ScriptedSinkMmio::new(1 << 29);
        let mut ms = Modeset::new(&mmio, Ddi::A);
        let mode = match ms.modeset(&fb_1080p(), None) {
            Ok(m) => m,
            Err(_) => {
                VRR_STATE.set_enabled(1, false);
                VRR_STATE.set_range(1, None);
                return TestResult::Fail("VRR full modeset over scripted sink must succeed");
            }
        };
        // The request is retained state, not a one-shot: clear it now so
        // later fixtures in this harness process start from fixed refresh.
        VRR_STATE.set_enabled(1, false);
        VRR_STATE.set_range(1, None);
        VRR_STATE.set_timings(1, None);
        VRR_STATE.set_mode(1, None);

        // The timings programmed are the ones computed for the mode this
        // run committed (Gen12 writes them directly, no −1).
        let expected = VrrTimings::compute_config(
            &mode,
            range,
            DisplayVrrIp::Gen12,
            VrrComputeOpts::default(),
        )
        .expect("1080p60 against 48..144 computes on Gen12");
        let base = Transcoder::A.base();
        if mmio.writes_to(base + TRANS_VRR_VMIN_OFFSET) != alloc::vec![expected.vmin] {
            return TestResult::Fail("VRR VMIN must be the computed vmin");
        }
        if mmio.writes_to(base + TRANS_VRR_VMAX_OFFSET) != alloc::vec![expected.vmax] {
            return TestResult::Fail("VRR VMAX must be the computed vmax");
        }

        // Order in the full write log: timings programmed before the TG
        // is enabled, and the TG is enabled after the transcoder.
        let writes = mmio.writes.borrow();
        let pos = |off: u64, pred: &dyn Fn(u32) -> bool| {
            writes.iter().position(|(o, v)| *o == off && pred(*v))
        };
        let vmin_pos = pos(base + TRANS_VRR_VMIN_OFFSET, &|_| true);
        let pipeconf_enable_pos = pos(Pipe::A.base() + PIPECONF_OFFSET, &|v| {
            v & PIPECONF_ENABLE != 0
        });
        let ctl_enable_pos = pos(base + TRANS_VRR_CTL_OFFSET, &|v| {
            v & VRR_CTL_VRR_ENABLE != 0
        });
        match (vmin_pos, pipeconf_enable_pos, ctl_enable_pos) {
            (Some(vmin), Some(tg), Some(ctl)) if vmin < ctl && tg < ctl => TestResult::Pass,
            _ => TestResult::Fail("VRR order must be timings, then transcoder, then TG enable"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_vrr_modeset_full_run_sequences_timings_then_enable
    );

    fn smoke_vrr_disable_precedes_transcoder_stop() -> TestResult {
        use crate::intel_gpu_pipes::{Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET};
        use crate::intel_gpu_vrr::{
            TRANS_PUSH_OFFSET, TRANS_VRR_CTL_OFFSET, VRR_CTL_FLIP_LINE_EN, VRR_CTL_VRR_ENABLE,
        };
        let mut mmio = FakeMmio::new();
        mmio.state_offset = 0;
        mmio.state_value = 0;
        // VRR live on transcoder A before the disable.
        let base = Transcoder::A.base();
        mmio.set_read(
            base + TRANS_VRR_CTL_OFFSET,
            VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN,
        );
        let mut ms = Modeset::new(&mmio, Ddi::A);
        ms.disable_pipeline();

        // VRR CTL must be cleared (ENABLE off, flip-line kept).
        let ctl_writes = mmio.writes_to(base + TRANS_VRR_CTL_OFFSET);
        if ctl_writes != alloc::vec![VRR_CTL_FLIP_LINE_EN] {
            return TestResult::Fail("VRR CTL must clear ENABLE on disable");
        }
        // PUSH reset to 0.
        if mmio.writes_to(base + TRANS_PUSH_OFFSET) != alloc::vec![0] {
            return TestResult::Fail("TRANS_PUSH must reset to 0 on disable");
        }
        // Order: pipe stop, then VRR off, then transcoder stop. The pipe
        // and transcoder CONF writes share one offset on Gen12, so the
        // two clears to that offset bracket the VRR CTL clear.
        let writes = mmio.writes.borrow();
        let pipeconf_clears: alloc::vec::Vec<usize> = writes
            .iter()
            .enumerate()
            .filter(|(_, (o, v))| {
                *o == Pipe::A.base() + PIPECONF_OFFSET && v & PIPECONF_ENABLE == 0
            })
            .map(|(i, _)| i)
            .collect();
        let vrr_pos = writes
            .iter()
            .position(|(o, _)| *o == base + TRANS_VRR_CTL_OFFSET);
        match (pipeconf_clears.as_slice(), vrr_pos) {
            ([first, second], Some(vrr)) if *first < vrr && vrr < *second => TestResult::Pass,
            _ => TestResult::Fail("VRR disable must land between pipe and transcoder stop"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset",
        smoke_vrr_disable_precedes_transcoder_stop
    );
}

/// Attempt to take over the display from UEFI GOP without disrupting
/// the existing framebuffer mapping.
pub fn takeover_display(gpu: &crate::intel_gpu::IntelGpu) -> Option<Mode> {
    let window = gpu.mode_window();
    takeover_display_with_chip(&window, gpu.chip.generation, Some(gpu.chip))
}

/// Take over only an enabled firmware pipe, using its current surface.
pub(crate) fn takeover_display_with<M: MmioWindow + ?Sized>(
    mmio: &M,
    generation: crate::intel_gpu::Generation,
) -> Option<Mode> {
    takeover_display_with_chip(mmio, generation, None)
}
fn takeover_display_with_chip<M: MmioWindow + ?Sized>(
    mmio: &M,
    generation: crate::intel_gpu::Generation,
    chip: Option<crate::intel_gpu::ChipInfo>,
) -> Option<Mode> {
    use crate::intel_gpu_pipes::{
        Pipe, PIPECONF_ENABLE, PIPECONF_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_STRIDE_OFFSET,
        PLANE_SURF_OFFSET,
    };
    if !generation.display_supported() {
        return None;
    }
    let pipe_base = Pipe::A.base();
    if mmio.read32(pipe_base + PIPECONF_OFFSET) & PIPECONF_ENABLE == 0 {
        return None;
    }
    let plane_base = pipe_base + PLANE_PRIMARY_OFFSET;
    let surf = mmio.read32(plane_base + PLANE_SURF_OFFSET);
    let stride = mmio.read32(plane_base + PLANE_STRIDE_OFFSET);
    let fb = Framebuffer {
        phys_addr: u64::from(surf & !0xFFF),
        stride_bytes: stride.checked_mul(64)?,
        format: PixelFormat::Xrgb8888,
    };
    match chip {
        Some(chip) => modeset_display_for_chip(mmio, chip, &fb, None).ok(),
        None => modeset_display(mmio, generation, &fb, None).ok(),
    }
}
