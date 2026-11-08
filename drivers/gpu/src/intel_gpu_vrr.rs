//! Variable Refresh Rate (VRR / Adaptive Sync) engine for Intel graphics.
//!
//! Controls transcoder VRR timing registers (`TRANS_VRR_CTL`, `TRANS_VRR_VMIN`,
//! `TRANS_VRR_VMAX`, `TRANS_VRR_FLIPLINE`, `TRANS_VRR_VSYNC`, `TRANS_PUSH`)
//! across Intel display generations:
//! - Gen12 (TigerLake, RocketLake, DG1): display 12; direct `vtotal` values,
//!   `TRANS_VRR_CTL` enable/flip-line flags.
//! - Display 13 (AlderLake, RaptorLake, DG2): `vtotal - 1` offsets,
//!   `VRR_CTL_IGN_MAX_STRETCH`.
//! - Display 14 (MeteorLake / Xe_LPG): `TRANS_VRR_VSYNC`, `guardband` packed in
//!   `TRANS_VRR_CTL`.
//! - Display 20 (LunarLake / Xe2_LPD): `EMP_AS_SDP_TL` Adaptive Sync SDP timing.
//! - Display 30 (PantherLake / Xe3_LPD): VRR timing generator architecture.
//!
//! Corresponds to Linux `drivers/gpu/drm/i915/display/intel_vrr.c` and
//! `intel_vrr_regs.h`.

use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{intel_gpu::Generation, intel_gpu_aux::MmioWindow, intel_gpu_modeset::Mode};

// ── Transcoder Register Offsets (relative to Transcoder base) ────────────────

pub const TRANS_VRR_CTL_OFFSET: u64 = 0x420;
pub const TRANS_VRR_VMAX_OFFSET: u64 = 0x424;
pub const TRANS_VRR_STATUS_OFFSET: u64 = 0x42c;
pub const TRANS_VRR_VMIN_OFFSET: u64 = 0x434;
pub const TRANS_VRR_FLIPLINE_OFFSET: u64 = 0x438;
pub const TRANS_VRR_VSYNC_OFFSET: u64 = 0x078;
pub const EMP_AS_SDP_TL_OFFSET: u64 = 0x204;
pub const TRANS_PUSH_OFFSET: u64 = 0xa70;
pub const TRANS_CMRR_M_LO_OFFSET: u64 = 0x4f0;
pub const TRANS_CMRR_M_HI_OFFSET: u64 = 0x4f4;
pub const TRANS_CMRR_N_LO_OFFSET: u64 = 0x4f8;
pub const TRANS_CMRR_N_HI_OFFSET: u64 = 0x4fc;
/// `TRANS_SET_CONTEXT_LATENCY`, relative to the transcoder base
/// (transcoder A: 0x6007c). Same value as the private offset in
/// `intel_gpu_xelpg_pipes` (kept separate so this module does not
/// depend on the pipe-enable module for one constant).
pub const TRANS_SET_CONTEXT_LATENCY_OFFSET: u64 = 0x7c;

// ── Transcoder Base Addresses ────────────────────────────────────────────────

pub const TRANSCODER_A_BASE: u64 = 0x60000;
pub const TRANSCODER_B_BASE: u64 = 0x61000;
pub const TRANSCODER_C_BASE: u64 = 0x62000;
pub const TRANSCODER_D_BASE: u64 = 0x63000;
pub const TRANSCODER_EDP_BASE: u64 = 0x6f000;

// ── Register Bit Definitions ─────────────────────────────────────────────────

pub const VRR_CTL_VRR_ENABLE: u32 = 1 << 31;
pub const VRR_CTL_IGN_MAX_STRETCH: u32 = 1 << 30;
pub const VRR_CTL_FLIP_LINE_EN: u32 = 1 << 29;
pub const VRR_CTL_CMRR_ENABLE: u32 = 1 << 27;
pub const VRR_CTL_GUARDBAND_MASK: u32 = 0xffff;

pub const VRR_STATUS_CMRR_EN_LIVE: u32 = 1 << 28;
pub const VRR_STATUS_VRR_EN_LIVE: u32 = 1 << 27;
pub const VRR_STATUS_FLIP_BEING_PUSHED: u32 = 1 << 26;

pub const TRANS_PUSH_EN: u32 = 1 << 31;
pub const TRANS_PUSH_SEND: u32 = 1 << 30;

/// `TRANS_VRR_VMIN` field mask (`i915_reg.h` `VRR_VMIN_MASK`, GENMASK(15, 0)).
pub const VRR_VMIN_MASK: u32 = 0xffff;
/// `TRANS_VRR_VMAX` field mask (`i915_reg.h` `VRR_VMAX_MASK`, GENMASK(19, 0)).
pub const VRR_VMAX_MASK: u32 = 0x000f_ffff;
/// `TRANS_VRR_FLIPLINE` field mask (`i915_reg.h` `VRR_FLIPLINE_MASK`, GENMASK(19, 0)).
pub const VRR_FLIPLINE_MASK: u32 = 0x000f_ffff;
/// `TRANS_VRR_CTL` pipeline-full field mask, Gen12/display 13
/// (`i915_reg.h` `VRR_CTL_PIPELINE_FULL_MASK`, GENMASK(10, 3)).
pub const VRR_CTL_PIPELINE_FULL_MASK: u32 = 0x7f8;
/// Shift of the `TRANS_VRR_CTL` pipeline-full field.
pub const VRR_CTL_PIPELINE_FULL_SHIFT: u32 = 3;

/// Max hardware vertical total supported by the VRR registers (13 bits).
pub const VRR_MAX_VTOTAL_HW: u32 = 0x1fff;

// ── Transcoders ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VrrTranscoder {
    A,
    B,
    C,
    D,
    Edp,
}

impl VrrTranscoder {
    pub const fn base(self) -> u64 {
        match self {
            Self::A => TRANSCODER_A_BASE,
            Self::B => TRANSCODER_B_BASE,
            Self::C => TRANSCODER_C_BASE,
            Self::D => TRANSCODER_D_BASE,
            Self::Edp => TRANSCODER_EDP_BASE,
        }
    }

    pub const fn for_crtc(crtc_id: u32) -> Self {
        match crtc_id {
            1 => Self::A,
            2 => Self::B,
            3 => Self::C,
            4 => Self::D,
            _ => Self::A,
        }
    }
}

// ── Display Hardware Generation for VRR ──────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DisplayVrrIp {
    Gen12,
    Display13,
    Display14,
    Display20,
    Display30,
}

impl DisplayVrrIp {
    pub const fn from_generation(gen: Generation) -> Self {
        match gen {
            Generation::TigerLake => Self::Gen12,
            Generation::AlderLake => Self::Display13,
            Generation::MeteorLake => Self::Display14,
            Generation::LunarLake => Self::Display20,
            Generation::PantherLake => Self::Display30,
        }
    }

    /// The display IP for a Gen12 platform family (the DP discovery
    /// path knows the family, not the `Generation`).
    pub const fn from_gen12_platform(family: crate::intel_gpu_gt::Gen12Platform) -> Self {
        match family {
            crate::intel_gpu_gt::Gen12Platform::TigerLake => Self::Gen12,
            crate::intel_gpu_gt::Gen12Platform::AlderLakeP
            | crate::intel_gpu_gt::Gen12Platform::AlderLakeS
            | crate::intel_gpu_gt::Gen12Platform::AlderLakeN => Self::Display13,
        }
    }

    /// Whether VMIN, VMAX, and FLIPLINE write `val - 1` (display 13+) or `val` (Gen12).
    pub const fn uses_vtotal_minus_one(self) -> bool {
        matches!(
            self,
            Self::Display13 | Self::Display14 | Self::Display20 | Self::Display30
        )
    }

    /// Whether `TRANS_VRR_VSYNC` (`base + 0x078`) is supported (display 14+).
    pub const fn has_vrr_vsync(self) -> bool {
        matches!(self, Self::Display14 | Self::Display20 | Self::Display30)
    }

    /// Whether `EMP_AS_SDP_TL` (`base + 0x204`) is supported (display 20+).
    pub const fn has_emp_as_sdp(self) -> bool {
        matches!(self, Self::Display20 | Self::Display30)
    }

    /// Whether the guardband field is packed into `TRANS_VRR_CTL[15:0]` (display 14+).
    pub const fn uses_guardband_in_ctl(self) -> bool {
        matches!(self, Self::Display14 | Self::Display20 | Self::Display30)
    }

    /// Whether `VRR_CTL_IGN_MAX_STRETCH` is supported (display 13).
    pub const fn uses_ign_max_stretch(self) -> bool {
        matches!(self, Self::Display13)
    }

    /// Whether Content-Matched Refresh Rate (CMRR) is supported (display 14+).
    pub const fn supports_cmrr(self) -> bool {
        matches!(self, Self::Display14 | Self::Display20 | Self::Display30)
    }
}

// ── VRR Refresh Range ────────────────────────────────────────────────────────

/// A sink's supported variable refresh rate range in Hz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrRange {
    pub min_hz: u16,
    pub max_hz: u16,
}

impl VrrRange {
    /// Linux requires the EDID range spread to be **> 10 Hz**
    /// (`intel_vrr_is_capable`: `max_vfreq - min_vfreq > 10`); a
    /// 10 Hz spread is not enough for a reasonable Adaptive-Sync
    /// experience.
    pub const fn new(min_hz: u16, max_hz: u16) -> Option<Self> {
        if min_hz != 0 && max_hz > min_hz && (max_hz - min_hz) > 10 {
            Some(Self { min_hz, max_hz })
        } else {
            None
        }
    }

    pub const fn supports_refresh(&self, hz: u32) -> bool {
        hz >= self.min_hz as u32 && hz <= self.max_hz as u32
    }

    /// Parse VRR range from an EDID byte slice (monitor range descriptor or DisplayID).
    pub fn from_edid(edid: &[u8]) -> Option<Self> {
        let r = crate::amdgpu_freesync::monitor_range(edid)
            .filter(|r| r.min_vfreq != 0 && r.max_vfreq != 0)
            .or_else(|| crate::amdgpu_freesync::displayid_range(edid))?;
        Self::new(r.min_vfreq, r.max_vfreq)
    }

    /// Parse VRR range from an EDID and optional DPCD block.
    pub fn from_edid_and_dpcd(edid: &[u8], dpcd: Option<&[u8; 16]>) -> Option<Self> {
        if let Some(dpcd) = dpcd {
            if dpcd[7] & crate::amdgpu_freesync::DPCD_MSA_TIMING_PAR_IGNORED == 0 {
                return None;
            }
        }
        Self::from_edid(edid)
    }

    /// Parse VRR range from an EDID and decoded DPCD receiver
    /// capabilities — the [`DpcdCaps`] form of
    /// [`Self::from_edid_and_dpcd`], for the discovery path, which
    /// holds the decoded caps rather than the raw 16-byte block.
    pub fn from_edid_and_dpcd_caps(
        edid: &[u8],
        caps: &crate::dp_link_training::DpcdCaps,
    ) -> Option<Self> {
        if !caps.msa_timing_par_ignored {
            return None;
        }
        Self::from_edid(edid)
    }
}

/// The connector kind a VRR capability decision is made for.
///
/// Linux `intel_vrr_is_capable` gates on it: eDP additionally
/// requires the VBT `vrr` flag; HDMI and anything else is never
/// VRR-capable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VrrConnectorKind {
    /// External DisplayPort.
    DisplayPort,
    /// Embedded DisplayPort (laptop panel).
    EmbeddedDisplayPort,
    /// HDMI (including via a DP-HDMI protocol converter).
    Hdmi,
    /// Anything else (VGA, DVI, ...).
    Other,
}

/// Linux `intel_vrr_is_capable`
/// (`drivers/gpu/drm/i915/display/intel_vrr.c`): `HAS_VRR` and an
/// EDID range spread > 10 Hz; DP/eDP require the DPCD Ignore-MSA
/// bit; eDP additionally requires the VBT `vrr` flag
/// ([`installed_vrr`], BDB_LFP_POWER `vrr_feature_enabled`, BDB
/// 233+); HDMI/other → false.
///
/// Returns the sink's VRR range when capable, `None` otherwise.
/// The eDP branch reads the installed VBT projection; the DP branch
/// needs none.
pub fn sink_vrr_range(
    edid: &[u8],
    dpcd: Option<&crate::dp_link_training::DpcdCaps>,
    kind: VrrConnectorKind,
    has_vrr: bool,
) -> Option<VrrRange> {
    if !has_vrr {
        return None;
    }
    match kind {
        VrrConnectorKind::EmbeddedDisplayPort => {
            if !matches!(installed_vrr(), VbtVrr::Present(true)) {
                return None;
            }
        }
        VrrConnectorKind::DisplayPort => {}
        VrrConnectorKind::Hdmi | VrrConnectorKind::Other => return None,
    }
    let caps = dpcd?;
    VrrRange::from_edid_and_dpcd_caps(edid, caps)
}

// ── Modeline Refresh Helper ──────────────────────────────────────────────────

/// Calculate the rounded vertical refresh rate in Hz for a display mode.
pub fn mode_vrefresh(mode: &Mode) -> u32 {
    let total = u64::from(mode.h_total) * u64::from(mode.v_total);
    if total == 0 {
        return 0;
    }
    let num = u64::from(mode.pixel_clock_khz) * 1000;
    u32::try_from((num + total / 2) / total).unwrap_or(0)
}

// ── VRR Timings ──────────────────────────────────────────────────────────────

/// Transcoder VRR timing registers for one mode + sink range.
///
/// Stored semantics follow current Linux (`intel_vrr_compute_config`
/// after the 2025-09 Ville series, "Hide the ICL/TGL
/// `intel_vrr_flipline_offset()` mangling better" and "Move the TGL
/// SCL mangling of vmin/vmax/flipline deeper"): `vmin` and `flipline`
/// are **equal** and match the minimum vtotal; the ICL/TGL −1
/// adjustment lives in the low-level programming path, not in the
/// stored state. (The older Linux formula stored `vmin = V − 1`,
/// `flipline = V`; the two agree on the values actually programmed
/// on display 13+, where the register write subtracts one — see
/// [`program_vrr_timings`].)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrTimings {
    /// Minimum vtotal (lines).
    pub vmin: u32,
    /// Maximum vtotal (lines).
    pub vmax: u32,
    /// Flip line (lines); equals `vmin`.
    pub flipline: u32,
    /// Late-phase guardband (lines); stored for every IP, packed
    /// into `TRANS_VRR_CTL` only on display 14+.
    pub guardband: u16,
    /// Gen12 delayed-vblank scanline value derived from the
    /// guardband (0 on display 13+, which uses the guardband
    /// register instead). See [`VrrTimings::compute_config_late`].
    pub pipeline_full: u16,
    /// VSYNC start/end (lines from the end of the frame); only
    /// meaningful when [`VrrTimings::as_sdp`] is set.
    pub vsync_start: u32,
    pub vsync_end: u32,
    /// The sink supports Adaptive-Sync SDP: only then are
    /// `TRANS_VRR_VSYNC` / `EMP_AS_SDP_TL` programmed.
    pub as_sdp: bool,
}

/// Options for [`VrrTimings::compute_config`] beyond mode/range/IP:
/// the facts Linux's `intel_vrr_compute_config` takes from the
/// connector/pipe state rather than the mode itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VrrComputeOpts {
    /// Interlaced mode: Linux bails on interlaced modes outright.
    /// (NARF modes are progressive today; the flag exists so the
    /// bail is fixture-testable and the day an interlaced mode
    /// arrives it is refused rather than silently programmed.)
    pub interlaced: bool,
    /// Bigjoiner pipe: Linux bails on joiner pipes. The Pipe-A
    /// modeset path never joins; the flag is the bail's input.
    pub joiner: bool,
    /// The sink supports Adaptive-Sync SDP: only then does Linux
    /// program `TRANS_VRR_VSYNC` / `EMP_AS_SDP_TL`. Which DPCD
    /// bit reports this is UNVERIFIED (no Bspec access in this
    /// lane); discovery callers pass `false` until it is resolved,
    /// and the PR body records it.
    pub as_sdp: bool,
    /// The set-context-latency the guardband is computed against
    /// (Linux "drm/i915/vrr: Use SCL for computing guardband",
    /// 2025-09-25): the guardband is the vblank length minus the
    /// SCL, so the late phase subtracts it. 0 is the pre-SCL
    /// behaviour; the modeset path passes
    /// [`set_context_latency_for_crtc`].
    pub scl: u32,
}

/// Late-phase guardband shared by VRR and CMRR.
///
/// Linux `intel_vrr_compute_config_late` / "drm/i915/vrr: Use SCL
/// for computing guardband" (2025-09-25): "guardband is equal to the
/// vblank length so ideally it should be computed as difference
/// between the vmin vtotal and vactive", minus the set-context
/// latency (the lines before the double-buffering point the
/// register programming needs). The pre-existing NARF clamps are
/// kept: at least 8 lines, at most the blanking length
/// `vtotal − v_active`.
fn late_guardband(vmin: u32, mode: &Mode, scl: u32) -> u16 {
    let guard = u64::from(vmin.saturating_sub(u32::from(mode.v_active)))
        .saturating_sub(u64::from(scl))
        .max(8);
    let max_guard = u64::from(mode.v_total.saturating_sub(mode.v_active)).min(0xffff);
    u16::try_from(guard.min(max_guard)).unwrap_or(8)
}

impl VrrTimings {
    /// Compute transcoder VRR timing registers for a given mode, sink VRR range, and display IP.
    ///
    /// Legacy single-call shape: AS SDP is unknown, so VSYNC follows
    /// the display IP as #1590 did (display 14+). The modeset path
    /// uses [`Self::compute_config`] with the real sink value.
    pub fn compute(mode: &Mode, range: VrrRange, ip: DisplayVrrIp) -> Option<Self> {
        Self::compute_config(
            mode,
            range,
            ip,
            VrrComputeOpts {
                as_sdp: ip.has_vrr_vsync(),
                ..Default::default()
            },
        )
    }

    /// Linux `intel_vrr_compute_config` equivalent: recompute the
    /// timings from the mode actually committed by a modeset and the
    /// sink's range, on every modeset.
    ///
    /// - `vmin = max(vtotal, ceil(clock / (htotal · max_vfreq)))`,
    ///   `vmax = max(vtotal, clock / (htotal · min_vfreq))`
    ///   (HW-clamped); bails when `vmin >= vmax` — there is no room
    ///   to vary, so no degenerate range is programmed (the old code
    ///   clamped `vmax` up to `vmin` instead).
    /// - Bails on interlaced modes and joiner pipes.
    /// - `flipline = vmin` (stored semantics per the 2025-09 Linux
    ///   refactor; see the struct docs).
    /// - VSYNC start/end are computed only when AS SDP is supported.
    /// - The late phase ([`Self::compute_config_late`]) fills the
    ///   guardband (and the Gen12 `pipeline_full` value).
    pub fn compute_config(
        mode: &Mode,
        range: VrrRange,
        ip: DisplayVrrIp,
        opts: VrrComputeOpts,
    ) -> Option<Self> {
        if mode.h_total == 0 || mode.v_total == 0 || mode.pixel_clock_khz == 0 {
            return None;
        }
        if mode.v_total <= mode.v_active || mode.v_sync_start > mode.v_total {
            return None;
        }
        if opts.interlaced || opts.joiner {
            return None;
        }
        let hz = mode_vrefresh(mode);
        if !range.supports_refresh(hz) {
            return None;
        }

        let num = u64::from(mode.pixel_clock_khz) * 1000;
        let denom_max = u64::from(mode.h_total) * u64::from(range.max_hz);
        if denom_max == 0 {
            return None;
        }
        let vmin_from_max = u32::try_from(num.div_ceil(denom_max)).ok()?;
        let vmin = u32::from(mode.v_total).max(vmin_from_max);
        let denom_min = u64::from(mode.h_total) * u64::from(range.min_hz);
        if denom_min == 0 {
            return None;
        }
        let raw_vmax = u32::try_from(num / denom_min).ok()?;
        let vmax = raw_vmax.min(VRR_MAX_VTOTAL_HW).max(u32::from(mode.v_total));
        if vmin >= vmax {
            return None;
        }

        let (vsync_start, vsync_end) = if opts.as_sdp {
            (
                u32::from(mode.v_total.saturating_sub(mode.v_sync_start)),
                u32::from(mode.v_total.saturating_sub(mode.v_sync_end)),
            )
        } else {
            (0, 0)
        };

        let mut timings = Self {
            vmin,
            vmax,
            flipline: vmin,
            guardband: 0,
            pipeline_full: 0,
            vsync_start,
            vsync_end,
            as_sdp: opts.as_sdp,
        };
        timings.compute_config_late(mode, ip, opts.scl);
        Some(timings)
    }

    /// Linux `intel_vrr_compute_config_late` equivalent: the
    /// guardband phase, run once the final mode is known.
    ///
    /// The guardband is the vblank length at the minimum vtotal
    /// ([`late_guardband`]); Linux 2025-09 ("Store guardband in
    /// crtc state even for icl/tgl") stores it in the state even for
    /// ICL/TGL, which has no guardband register — the hardware
    /// instead consumes the derived `pipeline_full` value.
    ///
    /// `pipeline_full` conversion: UNVERIFIED. What the fetched
    /// Linux sources establish is that the guardband is converted
    /// into the `pipeline_full` representation the ICL/TGL hardware
    /// consumes, and that the value is capped at 255 scanlines
    /// ("we don't currently handle the maximum limit of 255
    /// scanlines for the pipeline_full in a very nice way"). NARF
    /// uses the identity-with-clamp (`min(guardband, 255)`) as the
    /// conservative placeholder and records it as UNVERIFIED in the
    /// PR body; the exact conversion is a follow-up once the
    /// formula is readable.
    pub fn compute_config_late(&mut self, mode: &Mode, ip: DisplayVrrIp, scl: u32) {
        self.guardband = late_guardband(self.vmin, mode, scl);
        self.pipeline_full = if ip == DisplayVrrIp::Gen12 {
            self.guardband.min(255)
        } else {
            0
        };
    }
}

// ── CMRR (Content-Matched Refresh Rate) ──────────────────────────────────────

/// Target content frame rate for Content-Matched Refresh Rate (CMRR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmrrRate {
    /// 23.976 Hz (24000/1001) - Standard NTSC film rate.
    Fps23_976,
    /// 24.000 Hz - Cinema standard film rate.
    Fps24,
    /// 25.000 Hz - PAL standard video rate.
    Fps25,
    /// 29.970 Hz (30000/1001) - Standard NTSC video rate.
    Fps29_970,
    /// 30.000 Hz - Standard progressive rate.
    Fps30,
    /// 48.000 Hz - High frame rate cinema.
    Fps48,
    /// 50.000 Hz - PAL progressive rate.
    Fps50,
    /// 59.940 Hz (60000/1001) - Standard NTSC high rate.
    Fps59_940,
    /// 60.000 Hz - Standard display refresh rate.
    Fps60,
    /// Custom rational frame rate: `num / den` in Hz.
    Custom { num: u32, den: u32 },
}

impl CmrrRate {
    /// Returns the exact rational representation (numerator, denominator) of the frame rate.
    pub const fn fraction(self) -> (u64, u64) {
        match self {
            Self::Fps23_976 => (24_000, 1001),
            Self::Fps24 => (24, 1),
            Self::Fps25 => (25, 1),
            Self::Fps29_970 => (30_000, 1001),
            Self::Fps30 => (30, 1),
            Self::Fps48 => (48, 1),
            Self::Fps50 => (50, 1),
            Self::Fps59_940 => (60_000, 1001),
            Self::Fps60 => (60, 1),
            Self::Custom { num, den } => (num as u64, den as u64),
        }
    }

    /// String representation of the standard rate in Hz (e.g. "59.940").
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fps23_976 => "23.976",
            Self::Fps24 => "24",
            Self::Fps25 => "25",
            Self::Fps29_970 => "29.970",
            Self::Fps30 => "30",
            Self::Fps48 => "48",
            Self::Fps50 => "50",
            Self::Fps59_940 => "59.940",
            Self::Fps60 => "60",
            Self::Custom { .. } => "custom",
        }
    }

    /// Parse a refresh rate string into a `CmrrRate`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

impl core::str::FromStr for CmrrRate {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .trim()
            .trim_end_matches("Hz")
            .trim_end_matches("hz")
            .trim_end_matches("fps")
            .trim();
        match s {
            "23.976" | "23.98" => Ok(Self::Fps23_976),
            "24" | "24.0" => Ok(Self::Fps24),
            "25" | "25.0" => Ok(Self::Fps25),
            "29.970" | "29.97" => Ok(Self::Fps29_970),
            "30" | "30.0" => Ok(Self::Fps30),
            "48" | "48.0" => Ok(Self::Fps48),
            "50" | "50.0" => Ok(Self::Fps50),
            "59.940" | "59.94" => Ok(Self::Fps59_940),
            "60" | "60.0" => Ok(Self::Fps60),
            _ => Err(()),
        }
    }
}

/// Content-Matched Refresh Rate timing parameters programmed into the transcoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmrrTimings {
    pub cmrr_m: u64,
    pub cmrr_n: u64,
    pub vmin: u32,
    pub vmax: u32,
    pub flipline: u32,
    pub guardband: u16,
    pub vsync_start: u32,
    pub vsync_end: u32,
}

impl CmrrTimings {
    /// Compute transcoder CMRR M and N dividers and timing registers for a given mode and content frame rate.
    pub fn compute(mode: &Mode, rate: CmrrRate, ip: DisplayVrrIp) -> Option<Self> {
        if !ip.supports_cmrr() {
            return None;
        }
        if mode.h_total == 0 || mode.v_total == 0 || mode.pixel_clock_khz == 0 {
            return None;
        }
        if mode.v_total <= mode.v_active || mode.v_sync_start > mode.v_total {
            return None;
        }
        let (fps_num, fps_den) = rate.fraction();
        if fps_num == 0 || fps_den == 0 {
            return None;
        }

        let pixel_clock_hz = u64::from(mode.pixel_clock_khz) * 1000;
        let htotal = u64::from(mode.h_total);
        let vtotal = u64::from(mode.v_total);

        // Fixed precision multiplier (1_000_000_000)
        let cmrr_n = 1_000_000_000u64;
        let num =
            u128::from(htotal) * u128::from(vtotal) * u128::from(fps_num) * u128::from(cmrr_n);
        let den = u128::from(pixel_clock_hz) * u128::from(fps_den);
        if den == 0 {
            return None;
        }
        let cmrr_m = u64::try_from(num / den).ok()?;

        let vmin = u32::from(mode.v_total);
        let vmax = vmin;
        let flipline = vmin;

        let vsync_start = u32::from(mode.v_total.saturating_sub(mode.v_sync_start));
        let vsync_end = u32::from(mode.v_total.saturating_sub(mode.v_sync_end));

        let guardband = if ip.uses_guardband_in_ctl() {
            // The CMRR TG runs, so the set-context-latency floor is
            // 1 (wa_14015401596: PSR/PR with VRR needs SCL >= 1;
            // PSR may qualify under the fixed-RR CMRR TG).
            late_guardband(vmin, mode, 1)
        } else {
            0
        };

        Some(Self {
            cmrr_m,
            cmrr_n,
            vmin,
            vmax,
            flipline,
            guardband,
            vsync_start,
            vsync_end,
        })
    }
}

// ── Hardware Register Programming ────────────────────────────────────────────

/// Program the transcoder VRR timing limit registers (`TRANS_VRR_VMIN`, `TRANS_VRR_VMAX`,
/// `TRANS_VRR_FLIPLINE`, and `TRANS_VRR_VSYNC` / `EMP_AS_SDP_TL` where supported).
///
/// Register values: display 13+ writes `val - 1`, Gen12 writes the
/// stored value directly (#1590). Whether Gen12 should instead apply
/// a −1 to VMIN when programming is UNVERIFIED: fetched Linux
/// (2025-09, "Hide the ICL/TGL `intel_vrr_flipline_offset()` mangling
/// better") hides a vmin−1 / flipline+1 adjustment in the low-level
/// ICL/TGL programming path so the stored `vmin`/`flipline` stay
/// equal to the minimum vtotal, and notes "the actual register value
/// will no longer match crtc_state->vrr.vmin on ICL/TGL". No Bspec
/// was readable in this lane to resolve which side is right, so the
/// #1590 register values are kept as-is and the discrepancy is
/// recorded in the PR body rather than guessed at.
///
/// `TRANS_VRR_VSYNC` / `EMP_AS_SDP_TL` are programmed only when the
/// timings carry AS SDP support (`timings.as_sdp`): Linux programs
/// `EMP_AS_SDP_TL` for the DP Adaptive-Sync SDP case, and VSYNC is
/// likewise AS-SDP-gated rather than written unconditionally on
/// display 14+.
pub fn program_vrr_timings(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    timings: &VrrTimings,
) -> Result<(), FsError> {
    let base = trans.base();
    if ip.uses_vtotal_minus_one() {
        io.write32(base + TRANS_VRR_VMIN_OFFSET, timings.vmin.saturating_sub(1));
        io.write32(base + TRANS_VRR_VMAX_OFFSET, timings.vmax.saturating_sub(1));
        io.write32(
            base + TRANS_VRR_FLIPLINE_OFFSET,
            timings.flipline.saturating_sub(1),
        );
    } else {
        io.write32(base + TRANS_VRR_VMIN_OFFSET, timings.vmin);
        io.write32(base + TRANS_VRR_VMAX_OFFSET, timings.vmax);
        io.write32(base + TRANS_VRR_FLIPLINE_OFFSET, timings.flipline);
    }

    if ip.has_vrr_vsync() && timings.as_sdp {
        let vsync_val = ((timings.vsync_end & 0x1fff) << 16) | (timings.vsync_start & 0x1fff);
        io.write32(base + TRANS_VRR_VSYNC_OFFSET, vsync_val);
    }

    if ip.has_emp_as_sdp() && timings.as_sdp {
        io.write32(base + EMP_AS_SDP_TL_OFFSET, timings.vsync_start & 0x1fff);
    }

    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Enable VRR on the specified transcoder: arms `TRANS_PUSH` and writes `TRANS_VRR_CTL`.
pub fn vrr_enable(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    guardband: u16,
) -> Result<(), FsError> {
    let base = trans.base();
    io.write32(base + TRANS_PUSH_OFFSET, TRANS_PUSH_EN);

    let mut ctl = VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN;
    if ip.uses_ign_max_stretch() {
        ctl |= VRR_CTL_IGN_MAX_STRETCH;
    }
    if ip.uses_guardband_in_ctl() {
        ctl |= u32::from(guardband) & VRR_CTL_GUARDBAND_MASK;
    }

    io.write32(base + TRANS_VRR_CTL_OFFSET, ctl);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Disable VRR on the specified transcoder: clears `VRR_CTL_VRR_ENABLE`, waits for
/// `VRR_STATUS_VRR_EN_LIVE` to clear, then resets `TRANS_PUSH`.
pub fn vrr_disable(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    _ip: DisplayVrrIp,
) -> Result<(), FsError> {
    let base = trans.base();
    let ctl = io.read32(base + TRANS_VRR_CTL_OFFSET);
    if ctl == u32::MAX || !io.display_access_ok() {
        return Err(FsError::NoDevice);
    }
    if ctl & VRR_CTL_VRR_ENABLE == 0 {
        return Ok(());
    }

    // Keep flip line enable and guardband, clear VRR enable
    let new_ctl = (ctl & !VRR_CTL_VRR_ENABLE) | VRR_CTL_FLIP_LINE_EN;
    io.write32(base + TRANS_VRR_CTL_OFFSET, new_ctl);

    // Wait for hardware to exit VRR live state (bounded to 10,000 polls)
    for _ in 0..10_000 {
        let status = io.read32(base + TRANS_VRR_STATUS_OFFSET);
        if status == u32::MAX || !io.display_access_ok() {
            return Err(FsError::NoDevice);
        }
        if status & VRR_STATUS_VRR_EN_LIVE == 0 {
            break;
        }
    }

    io.write32(base + TRANS_PUSH_OFFSET, 0);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Send a push event on `TRANS_PUSH` to terminate vblank early on an armed page flip.
pub fn vrr_send_push(io: &(impl MmioWindow + ?Sized), trans: VrrTranscoder) -> Result<(), FsError> {
    io.write32(trans.base() + TRANS_PUSH_OFFSET, TRANS_PUSH_EN);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Query whether VRR is currently active in hardware on the transcoder.
pub fn is_vrr_active(io: &(impl MmioWindow + ?Sized), trans: VrrTranscoder) -> bool {
    let ctl = io.read32(trans.base() + TRANS_VRR_CTL_OFFSET);
    ctl != u32::MAX && (ctl & VRR_CTL_VRR_ENABLE != 0)
}

/// Program the transcoder CMRR M and N registers (`TRANS_CMRR_M_LO/HI`, `TRANS_CMRR_N_LO/HI`)
/// and the associated VRR timing limits.
pub fn program_cmrr_timings(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    timings: &CmrrTimings,
) -> Result<(), FsError> {
    let base = trans.base();
    let vrr_timings = VrrTimings {
        vmin: timings.vmin,
        vmax: timings.vmax,
        flipline: timings.flipline,
        guardband: timings.guardband,
        pipeline_full: 0,
        vsync_start: timings.vsync_start,
        vsync_end: timings.vsync_end,
        // CMRR keeps #1590's unconditional VSYNC programming on
        // display 14+ (its AS-SDP gating is the sequencing lane's
        // call); the VRR path gates on the sink instead.
        as_sdp: ip.has_vrr_vsync(),
    };
    program_vrr_timings(io, trans, ip, &vrr_timings)?;

    io.write32(base + TRANS_CMRR_M_LO_OFFSET, timings.cmrr_m as u32);
    io.write32(base + TRANS_CMRR_M_HI_OFFSET, (timings.cmrr_m >> 32) as u32);
    io.write32(base + TRANS_CMRR_N_LO_OFFSET, timings.cmrr_n as u32);
    io.write32(base + TRANS_CMRR_N_HI_OFFSET, (timings.cmrr_n >> 32) as u32);

    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Enable CMRR on the specified transcoder: arms `TRANS_PUSH` and writes `TRANS_VRR_CTL` with
/// `VRR_CTL_VRR_ENABLE` and `VRR_CTL_CMRR_ENABLE`.
pub fn cmrr_enable(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    guardband: u16,
) -> Result<(), FsError> {
    let base = trans.base();
    io.write32(base + TRANS_PUSH_OFFSET, TRANS_PUSH_EN);

    let mut ctl = VRR_CTL_VRR_ENABLE | VRR_CTL_CMRR_ENABLE | VRR_CTL_FLIP_LINE_EN;
    if ip.uses_guardband_in_ctl() {
        ctl |= u32::from(guardband) & VRR_CTL_GUARDBAND_MASK;
    }

    io.write32(base + TRANS_VRR_CTL_OFFSET, ctl);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Disable CMRR on the specified transcoder: clears `VRR_CTL_VRR_ENABLE` and `VRR_CTL_CMRR_ENABLE`,
/// waits for live status to clear, and resets `TRANS_PUSH`.
pub fn cmrr_disable(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    _ip: DisplayVrrIp,
) -> Result<(), FsError> {
    let base = trans.base();
    let ctl = io.read32(base + TRANS_VRR_CTL_OFFSET);
    if ctl == u32::MAX || !io.display_access_ok() {
        return Err(FsError::NoDevice);
    }
    if ctl & (VRR_CTL_VRR_ENABLE | VRR_CTL_CMRR_ENABLE) == 0 {
        return Ok(());
    }

    let new_ctl = (ctl & !(VRR_CTL_VRR_ENABLE | VRR_CTL_CMRR_ENABLE)) | VRR_CTL_FLIP_LINE_EN;
    io.write32(base + TRANS_VRR_CTL_OFFSET, new_ctl);

    for _ in 0..10_000 {
        let status = io.read32(base + TRANS_VRR_STATUS_OFFSET);
        if status == u32::MAX || !io.display_access_ok() {
            return Err(FsError::NoDevice);
        }
        if status & (VRR_STATUS_VRR_EN_LIVE | VRR_STATUS_CMRR_EN_LIVE) == 0 {
            break;
        }
    }

    io.write32(base + TRANS_PUSH_OFFSET, 0);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

/// Query whether CMRR is currently active in hardware on the transcoder.
pub fn is_cmrr_active(io: &(impl MmioWindow + ?Sized), trans: VrrTranscoder) -> bool {
    let ctl = io.read32(trans.base() + TRANS_VRR_CTL_OFFSET);
    ctl != u32::MAX
        && (ctl & (VRR_CTL_VRR_ENABLE | VRR_CTL_CMRR_ENABLE)
            == (VRR_CTL_VRR_ENABLE | VRR_CTL_CMRR_ENABLE))
}

/// Program fixed refresh rate timings using the VRR timing generator (Display 20/30 architecture).
pub fn program_fixed_rr_timings(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    mode: &Mode,
) -> Result<(), FsError> {
    let vtotal = u32::from(mode.v_total);
    if vtotal == 0 || mode.v_sync_start > mode.v_total || mode.v_sync_end > mode.v_total {
        return Err(FsError::InvalidData);
    }
    let base = trans.base();
    let val = if ip.uses_vtotal_minus_one() {
        vtotal.saturating_sub(1)
    } else {
        vtotal
    };
    io.write32(base + TRANS_VRR_VMIN_OFFSET, val);
    io.write32(base + TRANS_VRR_VMAX_OFFSET, val);
    io.write32(base + TRANS_VRR_FLIPLINE_OFFSET, val);

    if ip.has_vrr_vsync() {
        let vsync_start = u32::from(mode.v_total.saturating_sub(mode.v_sync_start));
        let vsync_end = u32::from(mode.v_total.saturating_sub(mode.v_sync_end));
        let vsync_val = ((vsync_end & 0x1fff) << 16) | (vsync_start & 0x1fff);
        io.write32(base + TRANS_VRR_VSYNC_OFFSET, vsync_val);
    }
    if ip.has_emp_as_sdp() {
        let vsync_start = u32::from(mode.v_total.saturating_sub(mode.v_sync_start));
        io.write32(base + EMP_AS_SDP_TL_OFFSET, vsync_start & 0x1fff);
    }
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}

// ── Global Driver VRR State ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct VrrState {
    enabled: [AtomicBool; 4],
    cmrr_enabled: [AtomicBool; 4],
    timings: [IrqSafeSpinLock<Option<VrrTimings>>; 4],
    cmrr_timings: [IrqSafeSpinLock<Option<CmrrTimings>>; 4],
    range: [IrqSafeSpinLock<Option<VrrRange>>; 4],
    cmrr_rate: [IrqSafeSpinLock<Option<CmrrRate>>; 4],
    mode: [IrqSafeSpinLock<Option<Mode>>; 4],
}

impl Default for VrrState {
    fn default() -> Self {
        Self::new()
    }
}

impl VrrState {
    pub const fn new() -> Self {
        Self {
            enabled: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
            cmrr_enabled: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
            timings: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
            cmrr_timings: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
            range: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
            cmrr_rate: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
            mode: [
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
                IrqSafeSpinLock::new(None),
            ],
        }
    }

    fn crtc_index(crtc_id: u32) -> Option<usize> {
        match crtc_id {
            1..=4 => Some((crtc_id - 1) as usize),
            _ => None,
        }
    }

    pub fn set_enabled(&self, crtc_id: u32, enabled: bool) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            self.enabled[idx].store(enabled, Ordering::SeqCst);
        }
    }

    pub fn is_enabled(&self, crtc_id: u32) -> bool {
        Self::crtc_index(crtc_id)
            .map(|idx| self.enabled[idx].load(Ordering::SeqCst))
            .unwrap_or(false)
    }

    pub fn set_cmrr_enabled(&self, crtc_id: u32, enabled: bool) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            self.cmrr_enabled[idx].store(enabled, Ordering::SeqCst);
        }
    }

    pub fn is_cmrr_enabled(&self, crtc_id: u32) -> bool {
        Self::crtc_index(crtc_id)
            .map(|idx| self.cmrr_enabled[idx].load(Ordering::SeqCst))
            .unwrap_or(false)
    }

    pub fn set_timings(&self, crtc_id: u32, timings: Option<VrrTimings>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.timings[idx].lock() = timings;
        }
    }

    pub fn timings(&self, crtc_id: u32) -> Option<VrrTimings> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.timings[idx].lock())
    }

    pub fn set_cmrr_timings(&self, crtc_id: u32, timings: Option<CmrrTimings>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.cmrr_timings[idx].lock() = timings;
        }
    }

    pub fn cmrr_timings(&self, crtc_id: u32) -> Option<CmrrTimings> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.cmrr_timings[idx].lock())
    }

    pub fn set_range(&self, crtc_id: u32, range: Option<VrrRange>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.range[idx].lock() = range;
        }
    }

    pub fn range(&self, crtc_id: u32) -> Option<VrrRange> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.range[idx].lock())
    }

    pub fn set_cmrr_rate(&self, crtc_id: u32, rate: Option<CmrrRate>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.cmrr_rate[idx].lock() = rate;
        }
    }

    pub fn cmrr_rate(&self, crtc_id: u32) -> Option<CmrrRate> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.cmrr_rate[idx].lock())
    }

    pub fn set_mode(&self, crtc_id: u32, mode: Option<Mode>) {
        if let Some(idx) = Self::crtc_index(crtc_id) {
            *self.mode[idx].lock() = mode;
        }
    }

    pub fn mode(&self, crtc_id: u32) -> Option<Mode> {
        Self::crtc_index(crtc_id).and_then(|idx| *self.mode[idx].lock())
    }
}

pub static VRR_STATE: VrrState = VrrState::new();

/// The VBT facts VRR consumes for the Pipe-A eDP panel: the
/// `vrr_feature_enabled` flag Linux's `intel_vrr_is_capable` gates
/// eDP on. Mirrors the `VbtPsr` install pattern
/// (`intel_gpu_psr::install_vbt`): the probe installs the
/// projection once, consumers read it via [`installed_vrr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VbtVrr {
    /// No VBT: eDP VRR is never capable (as in Linux, where
    /// `intel_bios_vrr` is false without a VBT).
    Missing,
    /// The VBT's `vrr_feature_enabled` value for the panel.
    Present(bool),
}

impl VbtVrr {
    /// `intel_bios_init` for the panel: the VBT's VRR feature flag.
    pub fn from_vbt(vbt: &crate::intel_gpu_vbt::Vbt) -> Self {
        Self::Present(vbt.vrr_feature_enabled())
    }
}

static VBT_VRR: IrqSafeSpinLock<VbtVrr> = IrqSafeSpinLock::new(VbtVrr::Missing);

/// Install the probe's VBT facts ([`VbtVrr::Missing`] without a VBT).
pub fn install_vbt(vbt: VbtVrr) {
    *VBT_VRR.lock() = vbt;
}

/// The installed VBT facts.
pub fn installed_vrr() -> VbtVrr {
    *VBT_VRR.lock()
}

/// Recompute a CRTC's VRR timings from the mode actually committed
/// by a modeset and the sink range discovery published for it.
///
/// This is the per-modeset compute (`intel_vrr_compute_config`
/// equivalent): the modeset path calls it with the real mode on
/// every modeset instead of reusing install-time timings. It stores
/// the mode + range in [`VRR_STATE`] and the fresh timings — or
/// clears them when there is no range or the compute bails (mode
/// outside the range, `vmin >= vmax`, interlace/joiner) — and
/// returns the timings. Pipe-A only by construction: callers pass
/// CRTC 1.
pub fn recompute_timings_for_modeset(
    crtc_id: u32,
    mode: &Mode,
    range: Option<VrrRange>,
    ip: DisplayVrrIp,
    opts: VrrComputeOpts,
) -> Option<VrrTimings> {
    VRR_STATE.set_mode(crtc_id, Some(*mode));
    VRR_STATE.set_range(crtc_id, range);
    // The guardband is computed against the set-context-latency
    // the TG will run with (Linux "Use SCL for computing
    // guardband"); the modeset path programs that SCL alongside
    // the timings.
    let mut opts = opts;
    opts.scl = set_context_latency_for_crtc(crtc_id);
    let timings = range.and_then(|r| VrrTimings::compute_config(mode, r, ip, opts));
    VRR_STATE.set_timings(crtc_id, timings);
    timings
}

/// Whether the VRR timing generator on `crtc_id` runs at a variable
/// refresh rate: VRR enabled and the TG not running at a fixed rate.
///
/// Linux `intel_psr_compute_config` and the DPCD MSA-ignore rule
/// both key off `vrr.enable && !vrr.fixed_rr`. Fixed-RR in NARF is
/// CMRR (`is_cmrr_enabled` — CMRR timings have `vmin == vmax` by
/// construction in `CmrrTimings::compute`); the standalone fixed-RR
/// TG programmer (`program_fixed_rr_timings`) has no production
/// caller yet, so CMRR is the only live fixed-RR mode.
pub fn vrr_is_variable(crtc_id: u32) -> bool {
    VRR_STATE.is_enabled(crtc_id) && !VRR_STATE.is_cmrr_enabled(crtc_id)
}

/// Whether VRR on `crtc_id` excludes PSR (Linux
/// `intel_psr_compute_config`: "Current PSR panels don't work
/// reliably with VRR enabled. So if VRR is enabled, do not enable
/// PSR", relaxed upstream to allow PSR with the fixed-RR VRR TG
/// only).
pub fn vrr_excludes_psr(crtc_id: u32) -> bool {
    vrr_is_variable(crtc_id)
}

/// Whether the sink on `crtc_id` wants DPCD MSA-timing-par-ignore
/// programmed: VRR runs at a variable rate and VRR timings are
/// programmed. Timings imply the sink advertised MSA-ignore — the
/// range gate in `sink_vrr_range` only publishes a range when the
/// sink's DPCD reports it — so no separate caps check is needed
/// here. Fixed-RR (CMRR) is skipped: the sink receives valid MSA
/// timing parameters at the fixed rate.
pub fn msa_timing_par_ignore_wanted(crtc_id: u32) -> bool {
    vrr_is_variable(crtc_id) && VRR_STATE.timings(crtc_id).is_some()
}

/// The `TRANS_SET_CONTEXT_LATENCY` value for `crtc_id`: 1 while the
/// VRR timing generator runs on the CRTC, 0 otherwise.
///
/// Wa_14015401596 (display 13/14): program set-context-latency to
/// at least 1 when PSR1/PSR2/Panel Replay is enabled with VRR
/// ("Panel Replay VSC SDP not getting sent when VRR is enabled and
/// W1 and W2 are 0"). The modeset/toggle paths cannot know whether
/// PSR will qualify — that happens after the first latch, in KMS
/// state unreachable from here — so the VRR-TG-running floor is
/// used: one line of programming window is harmless when PSR does
/// not engage, and PSR may qualify under the fixed-RR (CMRR) TG.
/// Linux computes SCL from `has_psr` and writes 0 without it; the
/// 1-line reservation is the safe side of the workaround.
pub fn set_context_latency_for_crtc(crtc_id: u32) -> u32 {
    if VRR_STATE.is_enabled(crtc_id) || VRR_STATE.is_cmrr_enabled(crtc_id) {
        1
    } else {
        0
    }
}

/// The display pipe driven by `crtc_id`, for resolving the live
/// connector (CRTC 1..=4 map to pipes A..=D; anything else has no
/// pipe). Mirrors `VrrTranscoder::for_crtc` but fallible: a CRTC
/// with no pipe has no sink to program.
fn pipe_for_crtc(crtc_id: u32) -> Option<crate::intel_gpu_pipes::Pipe> {
    use crate::intel_gpu_pipes::Pipe;
    match crtc_id {
        1 => Some(Pipe::A),
        2 => Some(Pipe::B),
        3 => Some(Pipe::C),
        4 => Some(Pipe::D),
        _ => None,
    }
}

/// Bring the sink's DPCD MSA-ignore bit in line with the current
/// VRR state for `crtc_id`, after a VRR/CMRR toggle.
///
/// The DPCD write is a slow AUX transaction: it runs off a
/// `DisplayInfo` snapshot (see its docs — slow AUX/modeset work
/// must not retain CONTROLLER while framebuffer pumps query it),
/// never under the controller lock. Best-effort: an unreachable
/// AUX leaves the sink's bit as it was; the DP modeset path
/// re-syncs it on the next modeset. A CRTC with no live pipe
/// owner has no sink to program and is skipped, never guessed.
fn sync_msa_timing_par_ignore(crtc_id: u32) {
    let _ = crate::intel_gpu::with_display_info(|display| {
        let io = display.mode_window();
        if let Some(pipe) = pipe_for_crtc(crtc_id) {
            if let Some(owner) = crate::intel_gpu_multipipe::pipe_owner(pipe) {
                let _ = crate::intel_gpu_dp::set_msa_timing_par_ignore(
                    &io,
                    owner.ddi,
                    msa_timing_par_ignore_wanted(crtc_id),
                );
            }
        }
    });
}

/// Retain and apply a CRTC's VRR request (from DRM `VRR_ENABLED`).
pub fn request_vrr_enabled(crtc_id: u32, enabled: bool) {
    VRR_STATE.set_enabled(crtc_id, enabled);

    // Apply to hardware if controller is initialized
    let trans = VrrTranscoder::for_crtc(crtc_id);
    crate::intel_gpu::with_controller(|dev| {
        let ip = DisplayVrrIp::from_generation(dev.chip.generation);
        let io = dev.mode_window();
        if enabled {
            if let Some(timings) = VRR_STATE.timings(crtc_id) {
                let _ = program_vrr_timings(&io, trans, ip, &timings);
                let _ = vrr_enable(&io, trans, ip, timings.guardband);
            }
        } else {
            let _ = vrr_disable(&io, trans, ip);
        }
        // The set-context-latency is a plain register write:
        // program it with the TG state (wa_14015401596 floor).
        io.write32(
            trans.base() + TRANS_SET_CONTEXT_LATENCY_OFFSET,
            set_context_latency_for_crtc(crtc_id),
        );
    });
    // The sink's MSA-ignore bit follows the toggle: set on enable,
    // cleared on disable, via the slow-AUX snapshot path.
    sync_msa_timing_par_ignore(crtc_id);
}

/// Retain and apply a CRTC's CMRR request.
pub fn request_cmrr_enabled(crtc_id: u32, enabled: bool) {
    VRR_STATE.set_cmrr_enabled(crtc_id, enabled);

    let trans = VrrTranscoder::for_crtc(crtc_id);
    crate::intel_gpu::with_controller(|dev| {
        let ip = DisplayVrrIp::from_generation(dev.chip.generation);
        let io = dev.mode_window();
        if enabled {
            if let Some(timings) = VRR_STATE.cmrr_timings(crtc_id) {
                let _ = program_cmrr_timings(&io, trans, ip, &timings);
                let _ = cmrr_enable(&io, trans, ip, timings.guardband);
            }
        } else {
            let _ = cmrr_disable(&io, trans, ip);
        }
        // CMRR runs the VRR TG, so the set-context-latency floor
        // applies here too (wa_14015401596).
        io.write32(
            trans.base() + TRANS_SET_CONTEXT_LATENCY_OFFSET,
            set_context_latency_for_crtc(crtc_id),
        );
    });
    // CMRR is the fixed-RR TG: enabling it clears the sink's
    // MSA-ignore bit, disabling it re-evaluates from the VRR state.
    sync_msa_timing_par_ignore(crtc_id);
}

/// Invoked on a completed/armed primary plane flip to trigger dynamic VRR/CMRR push.
pub fn on_plane_flip(crtc_id: u32, io: &(impl MmioWindow + ?Sized)) {
    if VRR_STATE.is_enabled(crtc_id) || VRR_STATE.is_cmrr_enabled(crtc_id) {
        let trans = VrrTranscoder::for_crtc(crtc_id);
        let _ = vrr_send_push(io, trans);
    }
}

/// Attempt to reconstruct active display `Mode` timings from hardware transcoder registers.
pub fn capture_mode_from_hw(io: &(impl MmioWindow + ?Sized), trans: VrrTranscoder) -> Option<Mode> {
    let base = trans.base();
    let htotal = io.read32(base);
    let hsync = io.read32(base + 0x008);
    let vtotal = io.read32(base + 0x00c);
    let vsync = io.read32(base + 0x014);

    if htotal == 0
        || htotal == u32::MAX
        || vtotal == 0
        || vtotal == u32::MAX
        || !io.display_access_ok()
    {
        return None;
    }

    let h_active = ((htotal & 0xffff) + 1) as u16;
    let h_tot = (((htotal >> 16) & 0xffff) + 1) as u16;
    let v_active = ((vtotal & 0xffff) + 1) as u16;
    let v_tot = (((vtotal >> 16) & 0xffff) + 1) as u16;

    let (h_sync_start, h_sync_end) = if hsync != 0 && hsync != u32::MAX {
        let start = ((hsync & 0xffff) + 1) as u16;
        let end = (((hsync >> 16) & 0xffff) + 1) as u16;
        if start <= h_tot && end <= h_tot && start >= h_active {
            (start, end)
        } else {
            (h_active + 16, h_active + 32)
        }
    } else {
        (h_active + 16, h_active + 32)
    };

    let (v_sync_start, v_sync_end) = if vsync != 0 && vsync != u32::MAX {
        let start = ((vsync & 0xffff) + 1) as u16;
        let end = (((vsync >> 16) & 0xffff) + 1) as u16;
        if start <= v_tot && end <= v_tot && start >= v_active {
            (start, end)
        } else {
            (v_active + 3, v_active + 6)
        }
    } else {
        (v_active + 3, v_active + 6)
    };

    let pixel_clock_khz = (u32::from(h_tot) * u32::from(v_tot) * 60) / 1000;

    Some(Mode {
        pixel_clock_khz,
        h_active,
        h_total: h_tot,
        h_sync_start,
        h_sync_end,
        v_active,
        v_total: v_tot,
        v_sync_start,
        v_sync_end,
        h_sync_positive: false,
        v_sync_positive: false,
    })
}

/// Decoded VRR register state read back from one transcoder.
///
/// Linux `intel_vrr_get_config` equivalent (the decode half):
/// `TRANS_VRR_CTL` (enable, CMRR, flip-line), `TRANS_VRR_VMIN` /
/// `TRANS_VRR_VMAX` / `TRANS_VRR_FLIPLINE` (register value + 1 when
/// `FLIP_LINE_EN` is set), `TRANS_VRR_VSYNC` (display 14+), CMRR
/// M/N, and the guardband (display 14+, `TRANS_VRR_CTL[15:0]`) or
/// pipeline-full (Gen12/display 13, `TRANS_VRR_CTL[10:3]`).
///
/// Field masks are grounded in `i915_reg.h` (`VRR_VMIN_MASK`,
/// `VRR_VMAX_MASK`, `VRR_FLIPLINE_MASK`, `VRR_CTL_PIPELINE_FULL_MASK`,
/// `XELPD_VRR_CTL_VRR_GUARDBAND_MASK`); the CMRR-enable bit and the
/// `TRANS_VRR_VSYNC` / CMRR M/N offsets are the V1 lane's constants
/// (no CMRR/VSYNC definitions in the `i915_reg.h` copy on file).
///
/// The `TRANS_VRR_STATUS` live bits are NOT used here: the copy of
/// `i915_reg.h` on file says bit 28 is `NO_FLIP_FRAME`, while the
/// V1 lane's `VRR_STATUS_CMRR_EN_LIVE` constant puts the CMRR live
/// bit at 28 — the two disagree, so readback trusts the CTL
/// enable/CMRR bits only. See the V1 notes in the spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrReadback {
    pub enabled: bool,
    pub cmrr_enabled: bool,
    pub flipline_en: bool,
    pub vmin: u32,
    pub vmax: u32,
    pub flipline: u32,
    pub guardband: u16,
    pub pipeline_full: u16,
    pub vsync_start: u32,
    pub vsync_end: u32,
    pub cmrr_m: u64,
    pub cmrr_n: u64,
}

/// Read back one transcoder's VRR registers into a [`VrrReadback`].
///
/// Returns `None` when the MMIO window is dead (the CTL register
/// reads all-ones, the same dead-window signal `vrr_disable` uses)
/// or `display_access_ok` reports the display registers as
/// inaccessible. `vmin`/`vmax`/`flipline` are the programmed values:
/// the register value + 1 when `FLIP_LINE_EN` is set (Linux
/// `intel_vrr_get_config`), the register value directly otherwise.
///
/// GEN12 ENCODE TENSION: NARF's Gen12 write path stores the value
/// directly while Linux's programming path applies vmin − 1 (the
/// V1 lane's open UNVERIFIED item); readback follows Linux's decode
/// and documents the discrepancy here rather than silently
/// re-encoding the write path's convention.
pub fn readback_vrr(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
) -> Option<VrrReadback> {
    let base = trans.base();
    let ctl = io.read32(base + TRANS_VRR_CTL_OFFSET);
    if ctl == u32::MAX || !io.display_access_ok() {
        return None;
    }
    let enabled = ctl & VRR_CTL_VRR_ENABLE != 0;
    let cmrr_enabled = ctl & VRR_CTL_CMRR_ENABLE != 0;
    let flipline_en = ctl & VRR_CTL_FLIP_LINE_EN != 0;
    // Register values are one less than the stored vtotal when the
    // flip line is enabled; without it the register holds the value
    // directly. The field mask applies before the +1.
    let plus_one = u32::from(flipline_en);
    let vmin = (io.read32(base + TRANS_VRR_VMIN_OFFSET) & VRR_VMIN_MASK) + plus_one;
    let vmax = (io.read32(base + TRANS_VRR_VMAX_OFFSET) & VRR_VMAX_MASK) + plus_one;
    let flipline = (io.read32(base + TRANS_VRR_FLIPLINE_OFFSET) & VRR_FLIPLINE_MASK) + plus_one;
    // Guardband (display 14+, low 16 bits of CTL) or pipeline-full
    // (Gen12/display 13, CTL[10:3]) — never both, per the IP.
    let (guardband, pipeline_full) = if ip.uses_guardband_in_ctl() {
        (u16::try_from(ctl & VRR_CTL_GUARDBAND_MASK).unwrap_or(0), 0)
    } else {
        (
            0,
            u16::try_from((ctl & VRR_CTL_PIPELINE_FULL_MASK) >> VRR_CTL_PIPELINE_FULL_SHIFT)
                .unwrap_or(0),
        )
    };
    let (vsync_start, vsync_end) = if ip.has_vrr_vsync() {
        let vsync = io.read32(base + TRANS_VRR_VSYNC_OFFSET);
        if vsync == u32::MAX {
            // Dead register on an otherwise live window: report
            // no VSYNC rather than a bogus 0x1fff/0x1fff range.
            (0, 0)
        } else {
            (vsync & 0x1fff, (vsync >> 16) & 0x1fff)
        }
    } else {
        (0, 0)
    };
    let (cmrr_m, cmrr_n) = if cmrr_enabled {
        let m_lo = io.read32(base + TRANS_CMRR_M_LO_OFFSET) as u64;
        let m_hi = io.read32(base + TRANS_CMRR_M_HI_OFFSET) as u64;
        let n_lo = io.read32(base + TRANS_CMRR_N_LO_OFFSET) as u64;
        let n_hi = io.read32(base + TRANS_CMRR_N_HI_OFFSET) as u64;
        ((m_hi << 32) | m_lo, (n_hi << 32) | n_lo)
    } else {
        (0, 0)
    };
    Some(VrrReadback {
        enabled,
        cmrr_enabled,
        flipline_en,
        vmin,
        vmax,
        flipline,
        guardband,
        pipeline_full,
        vsync_start,
        vsync_end,
        cmrr_m,
        cmrr_n,
    })
}

/// Outcome of [`reconcile_vrr_at_setup`]: the readback (if any),
/// whether a fixed-RR TG was disabled, and the enabled state
/// published to [`VRR_STATE`] (and, at install, to the atomic
/// `Card::vrr_enabled` slot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrReconcileOutcome {
    pub readback: Option<VrrReadback>,
    pub disabled_fixed_rr: bool,
    pub enabled: bool,
}

/// Publish a decoded readback into [`VRR_STATE`]. The CMRR timings
/// are only overwritten when CMRR is actually on in hardware: the
/// install seed stores default 59.94 Hz CMRR timings so CMRR can be
/// enabled later without a modeset, and clearing them on a VRR-off
/// readback would take that away.
fn publish_readback(crtc_id: u32, ip: DisplayVrrIp, rb: &VrrReadback) {
    VRR_STATE.set_enabled(crtc_id, rb.enabled);
    VRR_STATE.set_cmrr_enabled(crtc_id, rb.cmrr_enabled);
    if rb.enabled {
        VRR_STATE.set_timings(
            crtc_id,
            Some(VrrTimings {
                vmin: rb.vmin,
                vmax: rb.vmax,
                flipline: rb.flipline,
                guardband: rb.guardband,
                pipeline_full: rb.pipeline_full,
                vsync_start: rb.vsync_start,
                vsync_end: rb.vsync_end,
                as_sdp: ip.has_vrr_vsync() && (rb.vsync_start != 0 || rb.vsync_end != 0),
            }),
        );
    } else {
        VRR_STATE.set_timings(crtc_id, None);
    }
    if rb.cmrr_enabled {
        VRR_STATE.set_cmrr_timings(
            crtc_id,
            Some(CmrrTimings {
                cmrr_m: rb.cmrr_m,
                cmrr_n: rb.cmrr_n,
                vmin: rb.vmin,
                vmax: rb.vmax,
                flipline: rb.flipline,
                guardband: rb.guardband,
                vsync_start: rb.vsync_start,
                vsync_end: rb.vsync_end,
            }),
        );
    }
}

/// Read back one transcoder's VRR registers and reconcile the
/// GOP-left state at install/modeset setup (Linux
/// `intel_vrr_get_config` + the GOP-readback sanitize, #1772).
///
/// - No readable state (dead MMIO): `VRR_STATE` is left untouched.
/// - VRR off in hardware: publish disabled (enable off, timings
///   cleared) so later modesets start from a known-off TG.
/// - VRR on with fixed-RR timings (`vmin == vmax`) and CMRR off:
///   the TG is running a fixed rate, not variable refresh — disable
///   it ([`vrr_disable`]) and publish disabled. CMRR is exempt: it
///   programs `vmin == vmax == vtotal` by design (the rate varies
///   via M/N, not via the vtotal range).
/// - VRR on with a real variable range (`vmin < vmax`): publish the
///   readback timings + enable flags into `VRR_STATE`. The sink
///   range is NOT recovered from registers (only the programmed
///   vmin/vmax are visible); it stays whatever discovery published,
///   and the per-modeset recompute replaces the timings from the
///   committed mode + range anyway.
///
/// Returns the outcome; callers at install surface `enabled` to
/// the atomic path. The caller passes the transcoder matching the
/// CRTC (`VrrTranscoder::A` for CRTC 1 / Pipe A).
pub fn reconcile_vrr_at_setup(
    io: &(impl MmioWindow + ?Sized),
    trans: VrrTranscoder,
    ip: DisplayVrrIp,
    crtc_id: u32,
) -> VrrReconcileOutcome {
    let Some(rb) = readback_vrr(io, trans, ip) else {
        return VrrReconcileOutcome {
            readback: None,
            disabled_fixed_rr: false,
            enabled: VRR_STATE.is_enabled(crtc_id),
        };
    };
    // Fixed-RR TG, not CMRR: disable it in hardware, then publish off.
    if rb.enabled && !rb.cmrr_enabled && rb.vmin == rb.vmax && vrr_disable(io, trans, ip).is_ok() {
        VRR_STATE.set_enabled(crtc_id, false);
        VRR_STATE.set_cmrr_enabled(crtc_id, false);
        VRR_STATE.set_timings(crtc_id, None);
        return VrrReconcileOutcome {
            readback: Some(rb),
            disabled_fixed_rr: true,
            enabled: false,
        };
    }
    // Otherwise (not a fixed-RR TG, or the disable failed and the TG is
    // still on in hardware): publish the readback as-is rather than
    // claim it is off.
    publish_readback(crtc_id, ip, &rb);
    VrrReconcileOutcome {
        readback: Some(rb),
        disabled_fixed_rr: false,
        enabled: rb.enabled,
    }
}

/// Generate a multi-line formatted summary of the VRR and CMRR engine state across all pipes.
pub fn vrr_status_string() -> alloc::string::String {
    use alloc::format;
    let mut out = alloc::string::String::new();
    for crtc_id in 1..=4 {
        let name = match crtc_id {
            1 => "Pipe A",
            2 => "Pipe B",
            3 => "Pipe C",
            4 => "Pipe D",
            _ => "Unknown",
        };
        let enabled = VRR_STATE.is_enabled(crtc_id);
        let cmrr_en = VRR_STATE.is_cmrr_enabled(crtc_id);
        let rate_str = VRR_STATE
            .cmrr_rate(crtc_id)
            .map(|r| r.as_str())
            .unwrap_or("none");
        let timings = VRR_STATE.timings(crtc_id);
        let cmrr_t = VRR_STATE.cmrr_timings(crtc_id);
        out.push_str(&format!("{}:\n", name));
        out.push_str(&format!("  vrr_enabled: {}\n", if enabled { 1 } else { 0 }));
        out.push_str(&format!(
            "  cmrr_enabled: {}\n",
            if cmrr_en { 1 } else { 0 }
        ));
        out.push_str(&format!("  cmrr_rate: {}\n", rate_str));
        if let Some(t) = timings {
            out.push_str(&format!("  vmin: {}\n", t.vmin));
            out.push_str(&format!("  vmax: {}\n", t.vmax));
            out.push_str(&format!("  flipline: {}\n", t.flipline));
            out.push_str(&format!("  guardband: {}\n", t.guardband));
        } else {
            out.push_str("  timings: none\n");
        }
        if let Some(c) = cmrr_t {
            out.push_str(&format!("  cmrr_m: {}\n", c.cmrr_m));
            out.push_str(&format!("  cmrr_n: {}\n", c.cmrr_n));
            out.push_str(&format!("  cmrr_guardband: {}\n", c.guardband));
        } else {
            out.push_str("  cmrr_timings: none\n");
        }
    }
    out
}

/// Populate sysfs nodes for Intel VRR & CMRR under `/sys/class/drm/card<N>/vrr/`.
pub fn populate_card(_index: u32, node: &alloc::sync::Arc<narf_filesystem::sysfs::Kobject>) {
    use alloc::format;
    use narf_filesystem::sysfs::{
        get_or_create_child, kobject_add_attr, kobject_add_writable_attr,
    };

    let vrr_dir = get_or_create_child(node, "vrr");

    kobject_add_attr(&vrr_dir, "vrr_status", vrr_status_string);

    kobject_add_writable_attr(
        &vrr_dir,
        "pipeA_enabled",
        || format!("{}\n", if VRR_STATE.is_enabled(1) { 1 } else { 0 }),
        |data| {
            let s = core::str::from_utf8(data)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            match s {
                "1" | "true" | "on" => {
                    request_vrr_enabled(1, true);
                    Ok(())
                }
                "0" | "false" | "off" => {
                    request_vrr_enabled(1, false);
                    Ok(())
                }
                _ => Err(FsError::InvalidData),
            }
        },
    );

    kobject_add_writable_attr(
        &vrr_dir,
        "pipeA_cmrr_enabled",
        || format!("{}\n", if VRR_STATE.is_cmrr_enabled(1) { 1 } else { 0 }),
        |data| {
            let s = core::str::from_utf8(data)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            match s {
                "1" | "true" | "on" => {
                    request_cmrr_enabled(1, true);
                    Ok(())
                }
                "0" | "false" | "off" => {
                    request_cmrr_enabled(1, false);
                    Ok(())
                }
                _ => Err(FsError::InvalidData),
            }
        },
    );

    kobject_add_writable_attr(
        &vrr_dir,
        "pipeA_cmrr_rate",
        || {
            let r = VRR_STATE
                .cmrr_rate(1)
                .map(|rate| rate.as_str())
                .unwrap_or("none");
            format!("{}\n", r)
        },
        |data| {
            let s = core::str::from_utf8(data)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            if s == "none" || s == "off" {
                VRR_STATE.set_cmrr_rate(1, None);
                VRR_STATE.set_cmrr_timings(1, None);
                return Ok(());
            }
            let rate = CmrrRate::from_str(s).ok_or(FsError::InvalidData)?;
            VRR_STATE.set_cmrr_rate(1, Some(rate));
            let mode = VRR_STATE.mode(1).unwrap_or(Mode::VESA_1024X768_60);
            let ip = crate::intel_gpu::with_controller(|dev| {
                DisplayVrrIp::from_generation(dev.chip.generation)
            })
            .unwrap_or(DisplayVrrIp::Display30);
            if let Some(cmrr_t) = CmrrTimings::compute(&mode, rate, ip) {
                VRR_STATE.set_cmrr_timings(1, Some(cmrr_t));
                if VRR_STATE.is_cmrr_enabled(1) {
                    request_cmrr_enabled(1, true);
                }
            }
            Ok(())
        },
    );

    kobject_add_attr(&vrr_dir, "pipeA_vrr_live", || {
        let live = crate::intel_gpu::with_controller(|dev| {
            let io = dev.mode_window();
            is_vrr_active(&io, VrrTranscoder::A)
        })
        .unwrap_or(false);
        format!("{}\n", if live { 1 } else { 0 })
    });

    kobject_add_attr(&vrr_dir, "pipeA_cmrr_live", || {
        let live = crate::intel_gpu::with_controller(|dev| {
            let io = dev.mode_window();
            is_cmrr_active(&io, VrrTranscoder::A)
        })
        .unwrap_or(false);
        format!("{}\n", if live { 1 } else { 0 })
    });

    kobject_add_attr(&vrr_dir, "pipeA_vmin", || {
        let v = VRR_STATE.timings(1).map(|t| t.vmin).unwrap_or(0);
        format!("{}\n", v)
    });

    kobject_add_attr(&vrr_dir, "pipeA_vmax", || {
        let v = VRR_STATE.timings(1).map(|t| t.vmax).unwrap_or(0);
        format!("{}\n", v)
    });

    kobject_add_attr(&vrr_dir, "pipeA_flipline", || {
        let v = VRR_STATE.timings(1).map(|t| t.flipline).unwrap_or(0);
        format!("{}\n", v)
    });

    kobject_add_attr(&vrr_dir, "pipeA_guardband", || {
        let v = VRR_STATE.timings(1).map(|t| t.guardband).unwrap_or(0);
        format!("{}\n", v)
    });

    kobject_add_attr(&vrr_dir, "pipeA_cmrr_m", || {
        let v = VRR_STATE.cmrr_timings(1).map(|t| t.cmrr_m).unwrap_or(0);
        format!("{}\n", v)
    });

    kobject_add_attr(&vrr_dir, "pipeA_cmrr_n", || {
        let v = VRR_STATE.cmrr_timings(1).map(|t| t.cmrr_n).unwrap_or(0);
        format!("{}\n", v)
    });

    kobject_add_writable_attr(
        &vrr_dir,
        "pipeA_push",
        || "0\n".into(),
        |data| {
            let s = core::str::from_utf8(data)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            if s == "1" || s == "push" {
                crate::intel_gpu::with_controller(|dev| {
                    let io = dev.mode_window();
                    on_plane_flip(1, &io);
                });
            }
            Ok(())
        },
    );
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_vrr_tests.rs"]
mod tests;
