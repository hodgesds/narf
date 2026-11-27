//! Panel Replay (DP 2.0 / eDP 1.5) behind `narf.intel.panel_replay=1`.
//!
//! Pinned source: Linux 7.4-rc4 `i915/display/intel_psr.c`
//! (`_panel_replay_init_dpcd`, `_panel_replay_compute_su_granularity`,
//! `compute_pr_dsc_support`, `_panel_replay_compute_config`, the Panel
//! Replay branch of `intel_sel_update_config_valid`,
//! `psr2_granularity_check`, `psr2_su_region_et_valid`,
//! `_compute_psr2_sdp_prior_scanline_indication`,
//! `intel_psr_panel_replay_enable_sink`, `_panel_replay_enable_sink`,
//! `intel_psr_enable_locked`, `intel_psr_enable_source`,
//! `dg2_activate_panel_replay`, `intel_psr_exit`,
//! `intel_psr_wait_exit_locked`, `intel_psr_disable_locked`),
//! `intel_alpm.c` (`intel_alpm_compute_params`, `_lnl_compute_alpm_params`,
//! `_lnl_compute_aux_less_alpm_params`, `_lnl_compute_aux_less_wake_time`,
//! `lnl_alpm_configure`, `intel_alpm_port_configure`,
//! `intel_alpm_enable_sink`, `intel_alpm_disable`), `intel_dp.c`
//! (`intel_dp_needs_as_sdp`, `intel_dp_link_symbol_clock`), `intel_ddi.c`
//! (`intel_ddi_pre_enable_dp`: the sink's enable bit before link training),
//! `intel_psr_regs.h`, `intel_display_regs.h` (`TRANS_DP2_CTL`) and
//! `include/drm/display/drm_dp.h`.
//!
//! Source support follows `intel_psr_init`: external DP on display 14+
//! (`HAS_DP20`), eDP on display 20+. Display 35 is not qualified here
//! ([`Refusal::SourceUnsupported`]). The DP sink must answer
//! `DP_PANEL_REPLAY_CAP_SUPPORT`; an eDP sink must also report AUX-less
//! ALPM and early transport. Panel Replay never runs over MST, over a
//! 128b/132b eDP link, with HDCP on eDP, or with DSC a sink cannot decode in
//! replay.
//!
//! The replay stream's secondary data packets (Linux 7.4-rc4 `intel_dp.c`
//! `intel_dp_compute_vsc_sdp`, `intel_dp_compute_as_sdp`,
//! `intel_dp_as_sdp_pack`, `intel_dp_detect_sdp_caps`,
//! `intel_dp_sink_supports_as_sdp_v2`, `intel_dp_needs_as_sdp`,
//! `drm_dp_helper.c` `drm_dp_vsc_sdp_pack` / `drm_dp_as_sdp_supported`,
//! `intel_hdmi.c` `hsw_write_infoframe`, `intel_alpm.c`
//! `intel_alpm_configure_pr_as_sdp`): the VSC SDP header of DP 2.0 Table
//! 2-223 (revision 6) for every replay, and the Adaptive-Sync SDP (fixed
//! vtotal) when the sink takes AS SDP v2 and is no branch, which on eDP also
//! programs `PR_ALPM_CTL`. Linux writes both in the modeset before replay
//! enables; here they are written at the replay enable, on a transcoder the
//! modeset already gave its AS SDP timing (`TRANS_VRR_VSYNC`), and cleared
//! again at the disable.
//!
//! The sink's `PANEL_REPLAY_CONFIG` enable must be written before link
//! training ([`enable_before_training`]); a link trained without it is
//! refused ([`Refusal::NotEnabledAtTraining`]). Selective update over
//! Panel Replay runs with selective fetch (display 14+ have no PSR HW
//! tracking) at the sink's granularity, through the PSR owner's
//! selective-fetch programming ([`crate::intel_gpu_psr::Psr`]).
//!
//! The owned external DP SST routes run this owner behind their own option,
//! `narf.intel.ext_panel_replay=1`, with frontbuffer tracking for their
//! console scanout ([`crate::intel_gpu_xelpg_external::replay`]).

use crate::dp_aux::{AuxChannel, AuxError};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_psr::{read, usecs_to_scanlines, write};

/// The strict default-off option.
pub const BOOT_OPTION: &str = "narf.intel.panel_replay";

/// Whether the boot command line carries exactly `narf.intel.panel_replay=1`.
pub fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), BOOT_OPTION)
}

// ── DPCD (drm_dp.h) ──────────────────────────────────────────────

/// `DP_PANEL_REPLAY_CAP_SUPPORT`, the first of `DP_PANEL_REPLAY_CAP_SIZE`.
pub const DP_PANEL_REPLAY_CAP_SUPPORT: u32 = 0x0b0;
/// `DP_PANEL_REPLAY_CAP_SIZE`.
pub const DP_PANEL_REPLAY_CAP_SIZE: usize = 7;
/// `DP_PANEL_REPLAY_SUPPORT`.
pub const DP_PANEL_REPLAY_SUPPORT: u8 = 1 << 0;
/// `DP_PANEL_REPLAY_SU_SUPPORT`.
pub const DP_PANEL_REPLAY_SU_SUPPORT: u8 = 1 << 1;
/// `DP_PANEL_REPLAY_EARLY_TRANSPORT_SUPPORT` (eDP 1.5).
pub const DP_PANEL_REPLAY_EARLY_TRANSPORT_SUPPORT: u8 = 1 << 2;
/// `DP_PANEL_REPLAY_DSC_DECODE_CAPABILITY_IN_PR_MASK` (in `_CAP_CAPABILITY`).
const DSC_DECODE_MASK: u8 = 3 << 1;
/// `DP_PANEL_REPLAY_ASYNC_VIDEO_TIMING_NOT_SUPPORTED_IN_PR`.
pub const DP_PANEL_REPLAY_ASYNC_VIDEO_TIMING_NOT_SUPPORTED_IN_PR: u8 = 1 << 3;
/// `DP_PANEL_REPLAY_SU_GRANULARITY_REQUIRED`.
pub const DP_PANEL_REPLAY_SU_GRANULARITY_REQUIRED: u8 = 1 << 5;
/// `DP_PANEL_REPLAY_FULL_LINE_GRANULARITY`.
pub const DP_PANEL_REPLAY_FULL_LINE_GRANULARITY: u16 = 0xffff;
/// `DP_RECEIVER_ALPM_CAP` and `DP_ALPM_AUX_LESS_CAP`.
pub const DP_RECEIVER_ALPM_CAP: u32 = 0x02e;
pub const DP_ALPM_AUX_LESS_CAP: u8 = 1 << 2;
/// `DP_RECEIVER_ALPM_CONFIG`: `DP_ALPM_ENABLE`,
/// `DP_ALPM_LOCK_ERROR_IRQ_HPD_ENABLE`, `DP_ALPM_MODE_AUX_LESS`.
pub const DP_RECEIVER_ALPM_CONFIG: u32 = 0x116;
pub const SINK_ALPM_AUX_LESS: u8 = (1 << 0) | (1 << 1) | (1 << 2);
/// `PANEL_REPLAY_CONFIG` and its bits.
pub const PANEL_REPLAY_CONFIG: u32 = 0x1b0;
pub const DP_PANEL_REPLAY_ENABLE: u8 = 1 << 0;
pub const DP_PANEL_REPLAY_VSC_SDP_CRC_EN: u8 = 1 << 1;
pub const DP_PANEL_REPLAY_UNRECOVERABLE_ERROR_EN: u8 = 1 << 3;
pub const DP_PANEL_REPLAY_RFB_STORAGE_ERROR_EN: u8 = 1 << 4;
pub const DP_PANEL_REPLAY_ACTIVE_FRAME_CRC_ERROR_EN: u8 = 1 << 5;
pub const DP_PANEL_REPLAY_SU_ENABLE: u8 = 1 << 6;
pub const DP_PANEL_REPLAY_ENABLE_SU_REGION_ET: u8 = 1 << 7;
/// `PANEL_REPLAY_CONFIG2` (eDP 1.5) bits `_panel_replay_enable_sink` sets.
pub const PANEL_REPLAY_CONFIG2: u32 = 0x1b1;
pub const DP_PANEL_REPLAY_CRC_VERIFICATION: u8 = 1 << 1;
pub const DP_PANEL_REPLAY_SU_REGION_SCANLINE_CAPTURE: u8 = 1 << 7;
/// `PANEL_REPLAY_CONFIG3` (DP 2.1) and `DP_PR_AS_SDP_SETUP_TIME_T1`
/// (`intel_dp_as_sdp_transmission_time`).
pub const PANEL_REPLAY_CONFIG3: u32 = 0x11a;
pub const DP_PR_AS_SDP_SETUP_TIME_T1: u8 = 0;
/// `DP_SET_POWER` / `DP_SET_POWER_D0`.
const DP_SET_POWER: u32 = 0x600;
const DP_SET_POWER_D0: u8 = 1;
/// `DP_EDP_14b`: `_compute_psr2_sdp_prior_scanline_indication`'s floor.
const DP_EDP_14B: u8 = 0x05;
/// `DP_PANEL_REPLAY_LINK_OFF_SUPPORTED_IN_PR_AFTER_ADAPTIVE_SYNC_SDP`.
pub const DP_PANEL_REPLAY_LINK_OFF_SUPPORTED_IN_PR_AFTER_ADAPTIVE_SYNC_SDP: u8 = 1 << 7;
/// `DP_DPRX_FEATURE_ENUMERATION_LIST_CONT_1` and its
/// `DP_ADAPTIVE_SYNC_SDP_SUPPORTED` / `DP_AS_SDP_FAVT_PAYLOAD_FIELDS_PARSING_SUPPORTED`.
pub const DP_DPRX_FEATURE_ENUMERATION_LIST_CONT_1: u32 = 0x2214;
pub const DP_ADAPTIVE_SYNC_SDP_SUPPORTED: u8 = 1 << 0;
pub const DP_AS_SDP_FAVT_PAYLOAD_FIELDS_PARSING_SUPPORTED: u8 = 1 << 2;
/// `DP_DOWNSTREAMPORT_PRESENT` / `DP_DWN_STRM_PORT_PRESENT` (`drm_dp_is_branch`).
pub const DP_DOWNSTREAMPORT_PRESENT: u32 = 0x005;
pub const DP_DWN_STRM_PORT_PRESENT: u8 = 1 << 0;
/// `DP_DPCD_REV_13`, `drm_dp_as_sdp_supported`'s floor.
pub const DP_DPCD_REV_13: u8 = 0x13;
/// `DP_SDP_VSC` / `DP_SDP_ADAPTIVE_SYNC` (secondary-data packet types).
pub const DP_SDP_VSC: u8 = 0x07;
pub const DP_SDP_ADAPTIVE_SYNC: u8 = 0x22;
/// `DP_AS_SDP_AVT_FIXED_VTOTAL` (`enum operation_mode`).
pub const DP_AS_SDP_AVT_FIXED_VTOTAL: u8 = 0x01;
/// `sizeof(struct dp_sdp)`: `VIDEO_DIP_VSC_DATA_SIZE` and
/// `VIDEO_DIP_ASYNC_DATA_SIZE`.
pub const DP_SDP_BYTES: usize = 36;

// ── Source registers ─────────────────────────────────────────────

/// `TRANS_DP2_CTL(trans)`.
pub const fn trans_dp2_ctl(trans: u8) -> u64 {
    0x600a0 + 0x1000 * trans as u64
}
/// `TRANS_DP2_PANEL_REPLAY_ENABLE`.
pub const TRANS_DP2_PANEL_REPLAY_ENABLE: u32 = 1 << 30;
/// `TRANS_DP2_PR_TUNNELING_ENABLE` (only display 35 sets it).
pub const TRANS_DP2_PR_TUNNELING_ENABLE: u32 = 1 << 26;
/// `HSW_TVIDEO_DIP_CTL(trans)` and the enables `hsw_write_infoframe` sets
/// for the VSC (`VIDEO_DIP_ENABLE_VSC_HSW`, with `VSC_DIP_HW_DATA_SW_HEA`)
/// and AS (`VIDEO_DIP_ENABLE_AS_ADL`) SDPs.
pub const fn video_dip_ctl(trans: u8) -> u64 {
    0x60200 + 0x1000 * trans as u64
}
pub const VIDEO_DIP_ENABLE_VSC_HSW: u32 = 1 << 20;
pub const VSC_DIP_HW_DATA_SW_HEA: u32 = 2 << 25;
pub const VIDEO_DIP_ENABLE_AS_ADL: u32 = 1 << 23;
/// `HSW_TVIDEO_DIP_VSC_DATA(trans, i)` / `ADL_TVIDEO_DIP_AS_SDP_DATA(trans, i)`.
pub const fn video_dip_vsc_data(trans: u8, i: usize) -> u64 {
    0x60320 + 0x1000 * trans as u64 + 4 * i as u64
}
pub const fn video_dip_as_sdp_data(trans: u8, i: usize) -> u64 {
    0x60484 + 0x1000 * trans as u64 + 4 * i as u64
}
/// `TRANS_VRR_VSYNC(trans)`: the AS SDP's vsync window.
pub const fn trans_vrr_vsync(trans: u8) -> u64 {
    0x60078 + 0x1000 * trans as u64
}
/// `PR_ALPM_CTL(trans)` and the fields `intel_alpm_configure_pr_as_sdp`
/// sets below display 35 (no skip frames, no DC3CO idle protocol).
pub const fn pr_alpm_ctl(trans: u8) -> u64 {
    0x60948 + 0x1000 * trans as u64
}
pub const PR_ALPM_CTL_ALLOW_LINK_OFF_BETWEEN_AS_SDP_AND_SU: u32 = 1 << 6;
pub const PR_ALPM_CTL_AS_SDP_TRANSMISSION_IN_ACTIVE_DISABLE: u32 = 1 << 4;
pub const PR_ALPM_CTL_ADAPTIVE_SYNC_SDP_POSITION_T1: u32 = 1;
/// The transcoder's `EDP_PSR_STATUS`, `EDP_PSR_IMR`, `EDP_PSR_DEBUG`,
/// `EDP_PSR2_CTL`, `EDP_PSR2_STATUS`, `PSR2_MAN_TRK_CTL` and `ALPM_CTL`.
pub const fn psr_status(trans: u8) -> u64 {
    0x60840 + 0x1000 * trans as u64
}
pub const fn psr_imr(trans: u8) -> u64 {
    0x60814 + 0x1000 * trans as u64
}
pub const fn psr_debug(trans: u8) -> u64 {
    0x60860 + 0x1000 * trans as u64
}
pub const fn psr2_ctl(trans: u8) -> u64 {
    0x60900 + 0x1000 * trans as u64
}
pub const fn psr2_status(trans: u8) -> u64 {
    0x60940 + 0x1000 * trans as u64
}
pub const fn psr2_man_trk_ctl(trans: u8) -> u64 {
    0x60910 + 0x1000 * trans as u64
}
pub const fn alpm_ctl(trans: u8) -> u64 {
    0x60950 + 0x1000 * trans as u64
}
/// `PORT_ALPM_CTL(port)` / `PORT_ALPM_LFPS_CTL(port)` (`_MMIO_PORT`).
pub const fn port_alpm_ctl(port: u8) -> u64 {
    0x16fa2c + 0x200 * port as u64
}
pub const fn port_alpm_lfps_ctl(port: u8) -> u64 {
    0x16fa30 + 0x200 * port as u64
}
/// `LNL_EDP_PSR2_SU_REGION_ET_ENABLE` and `EDP_PSR2_SU_SDP_SCANLINE`.
pub const LNL_EDP_PSR2_SU_REGION_ET_ENABLE: u32 = 1 << 27;
pub const EDP_PSR2_SU_SDP_SCANLINE: u32 = 1 << 25;
/// `ADLP_PSR2_MAN_TRK_CTL_SF_CONTINUOS_FULL_FRAME`.
pub const MAN_TRK_SF_CONTINUOUS_FULL_FRAME: u32 = 1 << 13;
/// `ALPM_CTL` fields `lnl_alpm_configure` writes.
pub const ALPM_CTL_ALPM_ENABLE: u32 = 1 << 31;
pub const ALPM_CTL_ALPM_AUX_LESS_ENABLE: u32 = 1 << 30;
pub const ALPM_CTL_LOBF_ENABLE: u32 = 1 << 29;
pub const ALPM_CTL_AUX_LESS_SLEEP_HOLD_TIME_50_SYMBOLS: u32 = 0;
pub const fn alpm_ctl_entry_check(lines: u32) -> u32 {
    (lines & 0xf) << 16
}
const ALPM_CTL_AUX_LESS_WAKE_TIME_MASK: u32 = 0x3f;
/// `PORT_ALPM_CTL` fields `intel_alpm_port_configure` writes.
pub const PORT_ALPM_CTL_ALPM_AUX_LESS_ENABLE: u32 = 1 << 31;
pub const fn port_alpm_ctl_max_phy_swing_setup(v: u32) -> u32 {
    (v & 0x3f) << 20
}
const PORT_ALPM_CTL_SILENCE_PERIOD_MASK: u32 = 0xff;
/// `PORT_ALPM_LFPS_CTL` fields (`LFPS_CYCLE_COUNT` biased by its minimum 7).
pub const fn port_alpm_lfps_value(cycles: u32, half_cycle: u32) -> u32 {
    ((cycles - 7) & 0xf) << 24
        | (half_cycle & 0x1f) << 16
        | (half_cycle & 0x1f) << 8
        | (half_cycle & 0x1f)
}
const LFPS_HALF_CYCLE_MASK: u32 = 0x1f;
/// `TGL_PSR_MASK` / `TGL_PSR_ERROR` (`psr_irq_control`).
const TGL_PSR_MASK: u32 = 7;
const TGL_PSR_ERROR: u32 = 1 << 2;
/// `EDP_PSR_DEBUG_MASK_HPD`, `_MEMUP`, `_LPSP`.
const PSR_DEBUG_MASK_HPD: u32 = 1 << 25;
const PSR_DEBUG_MASK_MEMUP: u32 = 1 << 26;
const PSR_DEBUG_MASK_LPSP: u32 = 1 << 27;
/// `EDP_PSR_STATUS_STATE_MASK`, `EDP_PSR2_STATUS_STATE_MASK`.
const PSR_STATUS_STATE_MASK: u32 = 7 << 29;
const PSR2_STATUS_STATE_MASK: u32 = 0xf << 28;
/// `GEN8_CHICKEN_DCPR_1` and `LATENCY_REPORTING_REMOVED(pipe)`.
const CHICKEN_DCPR_1: u64 = 0x46430;
const fn latency_reporting_removed(pipe: u8) -> u32 {
    match pipe {
        0 => 1 << 23,
        1 => 1 << 24,
        2 => 1 << 31,
        _ => 1 << 30,
    }
}
/// `SILENCE_PERIOD_TIME` (ns) and `LFPS_CYCLE_COUNT` (`intel_alpm.c`).
const SILENCE_PERIOD_TIME_NS: u32 = 80 + (180 - 80) / 2;
const LFPS_CYCLE_COUNT: u32 = 10;

// ── Refusals ─────────────────────────────────────────────────────

/// Why Panel Replay is not (or no longer) running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `narf.intel.panel_replay=1` is absent.
    Disabled,
    /// `psr_global_enabled`: the VBT does not enable PSR for the eDP panel
    /// (Linux computes Panel Replay only past this gate).
    VbtDisabled,
    /// No fixed timing, or an interlaced one.
    NoTiming,
    /// `intel_psr_init`: eDP below display 20, DP below display 14, or a
    /// display IP this module does not qualify (35).
    SourceUnsupported,
    /// `_panel_replay_init_dpcd`: an MST link.
    Mst,
    /// `DP_PANEL_REPLAY_SUPPORT` is clear.
    NoSinkSupport,
    /// eDP without AUX-less ALPM.
    NoAuxLessAlpm,
    /// eDP without early transport.
    NoEarlyTransport,
    /// A sink AUX transaction failed.
    Aux(AuxError),
    /// DSC on the link and the sink decodes no DSC in replay.
    Dsc,
    /// eDP Panel Replay on a pipe other than A or B.
    Pipe,
    /// eDP Panel Replay over 128b/132b.
    Uhbr,
    /// eDP Panel Replay with HDCP.
    Hdcp,
    /// `alpm_config_valid`: the eDP wake or ALPM parameters do not fit.
    Alpm,
    /// `intel_dp_needs_as_sdp`: the stream needs the AS SDP, but the lit
    /// transcoder has no AS SDP timing (`TRANS_VRR_VSYNC`, which
    /// `intel_vrr_set_transcoder_timings` programs in the modeset).
    AsSdpTiming,
    /// The link was trained without the sink's `PANEL_REPLAY_CONFIG`
    /// enable (`intel_ddi_pre_enable_dp` writes it before training).
    NotEnabledAtTraining,
    /// The source already had Panel Replay or PSR enabled.
    Inherited,
    /// A source register read all-ones.
    Unavailable,
    /// The replay state machine did not return to idle within the bound.
    ExitTimeout,
    /// Wa_14015648006's `wm_level_disabled` is not known (display 14).
    WmLevelUnknown,
    /// `_intel_psr_min_set_context_latency`: the lit transcoder's
    /// `TRANS_SET_CONTEXT_LATENCY` is below what replay needs (DP on display
    /// 20 reads `SRD_STATUS`, which needs the delayed vblank a line after
    /// the undelayed one; Wa_14015401596 on display 13/14). Linux sets it in
    /// the modeset that computes replay; an external route lit before
    /// replay qualifies is refused instead.
    SetContextLatency,
}

// ── Sink capability ──────────────────────────────────────────────

/// `enum intel_panel_replay_dsc_support`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DscSupport {
    NotSupported,
    FullFrameOnly,
    SelectiveUpdate,
}

/// `connector->dp.panel_replay_caps` after `_panel_replay_init_dpcd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// The raw `DP_PANEL_REPLAY_CAP_SUPPORT..` bytes.
    pub dpcd: [u8; DP_PANEL_REPLAY_CAP_SIZE],
    /// `su_support`.
    pub su: bool,
    /// `su_w_granularity` / `su_y_granularity`.
    pub su_w_granularity: u16,
    pub su_y_granularity: u8,
    /// `dsc_support`.
    pub dsc: DscSupport,
    /// The sink is eDP.
    pub edp: bool,
}

impl Caps {
    /// `_panel_replay_init_dpcd` (and the AUX-less ALPM test of an eDP
    /// sink, `intel_alpm_aux_less_wake_supported`).
    pub fn read<A: AuxChannel + ?Sized>(
        aux: &mut A,
        edp: bool,
        mst: bool,
    ) -> Result<Self, Refusal> {
        if mst {
            return Err(Refusal::Mst);
        }
        let mut dpcd = [0u8; DP_PANEL_REPLAY_CAP_SIZE];
        read(aux, DP_PANEL_REPLAY_CAP_SUPPORT, &mut dpcd).map_err(Refusal::Aux)?;
        if dpcd[0] & DP_PANEL_REPLAY_SUPPORT == 0 {
            return Err(Refusal::NoSinkSupport);
        }
        if edp {
            let mut alpm = [0u8];
            read(aux, DP_RECEIVER_ALPM_CAP, &mut alpm).map_err(Refusal::Aux)?;
            if alpm[0] & DP_ALPM_AUX_LESS_CAP == 0 {
                return Err(Refusal::NoAuxLessAlpm);
            }
            if dpcd[0] & DP_PANEL_REPLAY_EARLY_TRANSPORT_SUPPORT == 0 {
                return Err(Refusal::NoEarlyTransport);
            }
        }
        Ok(Self::parse(dpcd, edp))
    }

    /// The decoded capability of `dpcd` (support already established).
    pub fn parse(dpcd: [u8; DP_PANEL_REPLAY_CAP_SIZE], edp: bool) -> Self {
        let su = dpcd[0] & DP_PANEL_REPLAY_SU_SUPPORT != 0;
        // _panel_replay_compute_su_granularity: 4x4 unless required;
        // a zero required value takes the default (4, 1).
        let (w, y) = if !su {
            (0, 0)
        } else if dpcd[1] & DP_PANEL_REPLAY_SU_GRANULARITY_REQUIRED == 0 {
            (4, 4)
        } else {
            let w = u16::from_le_bytes([dpcd[2], dpcd[3]]);
            (
                if w == 0 { 4 } else { w },
                if dpcd[4] == 0 { 1 } else { dpcd[4] },
            )
        };
        // compute_pr_dsc_support.
        let dsc = match (dpcd[1] & DSC_DECODE_MASK) >> 1 {
            0 => DscSupport::SelectiveUpdate,
            1 => DscSupport::FullFrameOnly,
            _ => DscSupport::NotSupported,
        };
        Self {
            dpcd,
            su,
            su_w_granularity: w,
            su_y_granularity: y,
            dsc,
            edp,
        }
    }

    /// `intel_psr_pr_async_video_timing_supported`.
    pub fn async_video_timing(&self) -> bool {
        self.dpcd[1] & DP_PANEL_REPLAY_ASYNC_VIDEO_TIMING_NOT_SUPPORTED_IN_PR == 0
    }
}

/// `intel_psr_panel_replay_enable_sink` from `intel_ddi_pre_enable_dp`:
/// before link training, when the option is on, the source supports Panel
/// Replay on this output and the sink can replay, set
/// `PANEL_REPLAY_CONFIG` to `DP_PANEL_REPLAY_ENABLE`. Returns whether it
/// was written; nothing is written otherwise.
pub fn enable_before_training<A: AuxChannel + ?Sized>(
    aux: &mut A,
    display_ver: u16,
    edp: bool,
    mst: bool,
    opted_in: bool,
) -> bool {
    if !opted_in || source_supported(display_ver, edp).is_err() {
        return false;
    }
    if Caps::read(aux, edp, mst).is_err() {
        return false;
    }
    write(aux, PANEL_REPLAY_CONFIG, DP_PANEL_REPLAY_ENABLE).is_ok()
}

/// Whether the sink's `PANEL_REPLAY_CONFIG` enable is set, as
/// [`enable_before_training`] leaves it for the link it preceded.
pub fn enabled_at_training<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<bool, Refusal> {
    let mut config = [0u8];
    read(aux, PANEL_REPLAY_CONFIG, &mut config).map_err(Refusal::Aux)?;
    Ok(config[0] & DP_PANEL_REPLAY_ENABLE != 0)
}

/// `_intel_psr_min_set_context_latency` (Linux 7.4-rc4) for a stream with
/// PSR or replay: the delayed-vblank lines the transcoder's set context
/// latency must reach. `vrr_possible` is `intel_vrr_possible` (every
/// progressive DP stream on display 11+ in 7.4-rc4, whose fixed refresh
/// rate sets a flipline), `edp` the output type.
pub const fn min_set_context_latency(
    display_ver: u16,
    edp: bool,
    panel_replay: bool,
    sel_update: bool,
    vrr_possible: bool,
) -> u32 {
    // Wa_14015401596.
    if vrr_possible && (display_ver == 13 || display_ver == 14) {
        return 1;
    }
    if display_ver < 20 || sel_update || (display_ver < 30 && edp) {
        return 0;
    }
    if display_ver >= 30 && panel_replay {
        return 0;
    }
    1
}

/// `intel_psr_init`'s `source_panel_replay_support`, narrowed to the
/// display IPs this module qualifies.
pub const fn source_supported(display_ver: u16, edp: bool) -> Result<(), Refusal> {
    match (edp, display_ver) {
        (false, 14..=30) | (true, 20..=30) => Ok(()),
        _ => Err(Refusal::SourceUnsupported),
    }
}

// ── Configuration ────────────────────────────────────────────────

/// The stream Panel Replay is computed for (`crtc_state`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Stream {
    /// `DISPLAY_VER` (14, 20 or 30).
    pub display_ver: u16,
    /// The pipe and its CPU transcoder (same index).
    pub pipe: u8,
    /// The DDI's `enum port` (eDP: A or B), for `PORT_ALPM_*`.
    pub port: u8,
    /// `port_clock` in kHz (10 kbit/s units).
    pub port_clock: u32,
    /// `lane_count`.
    pub lanes: u32,
    /// The fixed timing.
    pub timing: crate::intel_gpu_dsb::Timing,
    /// DSC compresses the link.
    pub dsc: bool,
    /// 128b/132b link.
    pub uhbr: bool,
    /// HDCP is desired or enabled.
    pub hdcp: bool,
    /// `intel_dp_needs_as_sdp`: an AS SDP v2 sink that is no branch device
    /// (every progressive stream is `intel_vrr_possible` in 7.4-rc4), see
    /// [`as_sdp_needed`].
    pub as_sdp_v2: bool,
    /// The eDP DPCD revision (`intel_dp->edp_dpcd[0]`), 0 for DP.
    pub edp_rev: u8,
    /// `QUIRK_FW_SYNC_LEN` (`intel_dp_aux_fw_sync_len` + 2).
    pub fw_sync_quirk: bool,
    /// Selective fetch may be used (the plane path can program it).
    pub sel_fetch: bool,
}

/// The eDP ALPM state (`crtc_state->alpm_state`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Alpm {
    pub io_wake_lines: u8,
    pub fast_wake_lines: u8,
    pub check_entry_lines: u8,
    pub aux_less_wake_lines: u8,
    pub silence_period_sym_clocks: u8,
    pub lfps_half_cycle_num_of_syms: u8,
}

/// A qualified Panel Replay configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// eDP (ALPM, `DP_SET_POWER`, the eDP `PSR_DEBUG` mask).
    pub edp: bool,
    pub display_ver: u16,
    pub pipe: u8,
    pub port: u8,
    /// `has_sel_update` over Panel Replay.
    pub su: bool,
    /// `su_y_granularity` the selective fetch aligns to.
    pub su_y_granularity: u16,
    /// `enable_psr2_su_region_et`.
    pub su_region_et: bool,
    /// `req_psr2_sdp_prior_scanline`.
    pub sdp_prior_scanline: bool,
    /// eDP's AUX-less ALPM state.
    pub alpm: Option<Alpm>,
    /// Wa_14015648006 input (`IS_DISPLAY_VER(11, 14)` only).
    pub wm_level_disabled: bool,
    /// The Adaptive-Sync SDP the stream sends (`intel_dp_needs_as_sdp`).
    pub as_sdp: Option<AsSdp>,
    /// eDP with an AS SDP sink: `PR_ALPM_CTL` (`lnl_alpm_configure`).
    pub pr_alpm_ctl: Option<u32>,
}

/// `struct drm_dp_as_sdp` as `intel_dp_compute_as_sdp` fills it (type
/// `DP_SDP_ADAPTIVE_SYNC`, revision 2, length 9, no duration increment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsSdp {
    /// `enum operation_mode`.
    pub mode: u8,
    /// `intel_vrr_vmin_vtotal`.
    pub vtotal: u16,
    pub target_rr: u16,
    pub target_rr_divider: bool,
    /// `crtc_state->vrr.vmax` when the sink keeps async video timing in PR.
    pub coasting_vtotal: u16,
}

/// `intel_dp_compute_as_sdp` at a fixed refresh rate (no CMRR, VRR off;
/// replay is refused at a variable rate): `DP_AS_SDP_AVT_FIXED_VTOTAL` at
/// vmin = vmax = `crtc_vtotal`, the coasting vtotal only for a sink with
/// async video timing in PR.
pub const fn as_sdp_fixed(vtotal: u16, async_video_timing: bool) -> AsSdp {
    AsSdp {
        mode: DP_AS_SDP_AVT_FIXED_VTOTAL,
        vtotal,
        target_rr: 0,
        target_rr_divider: false,
        coasting_vtotal: if async_video_timing { vtotal } else { 0 },
    }
}

/// `intel_dp_as_sdp_pack`.
pub fn pack_as_sdp(sdp: &AsSdp) -> [u8; DP_SDP_BYTES] {
    let mut b = [0u8; DP_SDP_BYTES];
    b[1] = DP_SDP_ADAPTIVE_SYNC;
    b[2] = 0x2;
    b[3] = 0x9;
    let db = &mut b[4..];
    db[0] = sdp.mode;
    db[1] = sdp.vtotal as u8;
    db[2] = (sdp.vtotal >> 8) as u8;
    db[3] = sdp.target_rr as u8;
    db[4] = ((sdp.target_rr >> 8) & 0x3) as u8;
    if sdp.target_rr_divider {
        db[4] |= 0x20;
    }
    db[7] = sdp.coasting_vtotal as u8;
    db[8] = (sdp.coasting_vtotal >> 8) as u8;
    b
}

/// `drm_dp_vsc_sdp_pack` of `intel_dp_compute_vsc_sdp`'s replay header
/// without colorimetry: revision 0x6, length 0x10 (DP 2.0 Table 2-223),
/// DB0 and DB3 set.
pub fn pack_replay_vsc_sdp() -> [u8; DP_SDP_BYTES] {
    let mut b = [0u8; DP_SDP_BYTES];
    b[1] = DP_SDP_VSC;
    b[2] = 0x6;
    b[3] = 0x10;
    b[4] = 1;
    b[7] = 1;
    b
}

/// `intel_alpm_configure_pr_as_sdp` below display 35: the AS SDP at T1
/// (`intel_dp_as_sdp_transmission_time`), link off between the AS SDP and
/// SU when the sink allows it, and no AS SDP in PR active when the sink
/// keeps async video timing (`disable_as_sdp_when_pr_active`).
pub const fn pr_alpm_ctl_value(caps: &Caps) -> u32 {
    let mut value = PR_ALPM_CTL_ADAPTIVE_SYNC_SDP_POSITION_T1;
    if caps.dpcd[1] & DP_PANEL_REPLAY_LINK_OFF_SUPPORTED_IN_PR_AFTER_ADAPTIVE_SYNC_SDP != 0 {
        value |= PR_ALPM_CTL_ALLOW_LINK_OFF_BETWEEN_AS_SDP_AND_SU;
    }
    if caps.dpcd[1] & DP_PANEL_REPLAY_ASYNC_VIDEO_TIMING_NOT_SUPPORTED_IN_PR == 0 {
        value |= PR_ALPM_CTL_AS_SDP_TRANSMISSION_IN_ACTIVE_DISABLE;
    }
    value
}

/// `intel_dp_detect_sdp_caps` and `intel_dp_needs_as_sdp` for a replay
/// sink (`HAS_AS_SDP`: display 13+): DPCD 1.3+ with
/// `DP_ADAPTIVE_SYNC_SDP_SUPPORTED`; eDP always takes v2, DP when it parses
/// FAVT payloads or keeps no async video timing in PR
/// (`intel_dp_sink_supports_as_sdp_v2`); a branch never gets it. A failed
/// read is "not supported", as `drm_dp_as_sdp_supported` answers.
pub fn as_sdp_needed<A: AuxChannel + ?Sized>(aux: &mut A, dpcd_rev: u8, caps: &Caps) -> bool {
    if dpcd_rev < DP_DPCD_REV_13 {
        return false;
    }
    let mut rx = [0u8];
    if read(aux, DP_DPRX_FEATURE_ENUMERATION_LIST_CONT_1, &mut rx).is_err()
        || rx[0] & DP_ADAPTIVE_SYNC_SDP_SUPPORTED == 0
    {
        return false;
    }
    let v2 = caps.edp
        || rx[0] & DP_AS_SDP_FAVT_PAYLOAD_FIELDS_PARSING_SUPPORTED != 0
        || !caps.async_video_timing();
    if !v2 {
        return false;
    }
    if caps.edp {
        return true;
    }
    let mut ports = [0u8];
    read(aux, DP_DOWNSTREAMPORT_PRESENT, &mut ports).is_ok()
        && ports[0] & DP_DWN_STRM_PORT_PRESENT == 0
}

/// `hsw_write_infoframe` for a 36-byte SDP on `trans`: the type's enable
/// (`hsw_infoframe_enable`) cleared, the nine data dwords (`dp_sdp` bytes,
/// little-endian) at `data(i)`, then `set` (the enable, and for the VSC SDP
/// `VSC_DIP_HW_DATA_SW_HEA`) ORed in.
pub fn write_sdp<M: MmioWindow + ?Sized>(
    regs: &M,
    trans: u8,
    data: fn(u8, usize) -> u64,
    enable: u32,
    set: u32,
    sdp: &[u8; DP_SDP_BYTES],
) {
    let ctl = video_dip_ctl(trans);
    let val = regs.read32(ctl) & !enable;
    regs.write32(ctl, val);
    for (i, word) in sdp.chunks_exact(4).enumerate() {
        regs.write32(
            data(trans, i),
            u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
        );
    }
    regs.write32(ctl, val | set);
}

/// `_lnl_compute_aux_less_wake_time` in µs (port clock in 10 kbit/s).
pub fn aux_less_wake_time_us(port_clock: u32) -> u32 {
    let tps4 = 252u32;
    let tml_phy_lock = 1000 * 1000 * tps4 / port_clock.max(1);
    let num_ml_phy_lock = 7 + 6500u32.div_ceil(tml_phy_lock.max(1)) + 1;
    let tcds = num_ml_phy_lock * tml_phy_lock;
    (12 * 1000 + lfps_cycle_time_ns(port_clock) + SILENCE_PERIOD_TIME_NS + 50 * 1000 + tcds)
        .div_ceil(1000)
}

/// `get_lfps_cycle_time`.
fn lfps_cycle_time_ns(port_clock: u32) -> u32 {
    let (min, max) = if port_clock < 540_000 {
        (65 * LFPS_CYCLE_COUNT, 75 * LFPS_CYCLE_COUNT)
    } else {
        (140, 800)
    };
    min + (max - min) / 2
}

/// `get_silence_period_symbols` (8b/10b: the symbol clock is the rate).
pub fn silence_period_symbols(port_clock: u32) -> u32 {
    (u64::from(SILENCE_PERIOD_TIME_NS) * u64::from(port_clock) / 1000 / 1000) as u32
}

/// `get_lfps_half_cycle_clocks`.
pub fn lfps_half_cycle_clocks(port_clock: u32) -> u32 {
    (u64::from(lfps_cycle_time_ns(port_clock)) * u64::from(port_clock)
        / 1000
        / 1000
        / u64::from(2 * LFPS_CYCLE_COUNT)) as u32
}

/// `intel_alpm_compute_params` with `_lnl_compute_alpm_params` (display
/// 20+, AUX-less), then `wake_lines_fit_into_vblank` with the AUX-less
/// wake lines.
pub(crate) fn alpm_params(stream: &Stream, sdp_prior_scanline: bool) -> Result<Alpm, Refusal> {
    let timing = &stream.timing;
    let precharge = 10 + if stream.fw_sync_quirk { 2 } else { 0 };
    let io_time = precharge.max(10) + 8 + 4 + 20;
    let fast_time = precharge + 8 + 4 + 20;
    let io = usecs_to_scanlines(timing, io_time);
    let fast = usecs_to_scanlines(timing, fast_time);
    let max_wake_lines = if stream.display_ver >= 20 { 68 } else { 12 };
    if io > max_wake_lines || fast > max_wake_lines {
        return Err(Refusal::Alpm);
    }
    let check_entry_lines = 2 + usecs_to_scanlines(timing, 5);
    if check_entry_lines > 15 {
        return Err(Refusal::Alpm);
    }
    let aux_less = usecs_to_scanlines(timing, aux_less_wake_time_us(stream.port_clock));
    let silence = silence_period_symbols(stream.port_clock);
    let lfps = lfps_half_cycle_clocks(stream.port_clock);
    if aux_less > ALPM_CTL_AUX_LESS_WAKE_TIME_MASK
        || silence > PORT_ALPM_CTL_SILENCE_PERIOD_MASK
        || lfps > LFPS_HALF_CYCLE_MASK
    {
        return Err(Refusal::Alpm);
    }
    // wake_lines_fit_into_vblank: vblank less the set context latency
    // (`_intel_psr_min_set_context_latency`: 0 for eDP below display 30,
    // 0 for Panel Replay on display 30) and the SDP line.
    let mut vblank = u32::from(timing.vtotal).saturating_sub(u32::from(timing.height));
    if sdp_prior_scanline {
        vblank = vblank.saturating_sub(1);
    }
    if vblank < aux_less {
        return Err(Refusal::Alpm);
    }
    Ok(Alpm {
        io_wake_lines: io.max(7) as u8,
        fast_wake_lines: fast.max(7) as u8,
        check_entry_lines: check_entry_lines as u8,
        aux_less_wake_lines: aux_less as u8,
        silence_period_sym_clocks: silence as u8,
        lfps_half_cycle_num_of_syms: lfps as u8,
    })
}

/// `_compute_psr2_sdp_prior_scanline_indication`: `Ok(false)` when the
/// hblank carries the SDP, `Ok(true)` when an eDP 1.4b+ sink takes it a
/// line early, `Err(())` otherwise (Linux's u32 arithmetic).
fn sdp_prior_scanline(stream: &Stream) -> Result<bool, ()> {
    let t = &stream.timing;
    if stream.lanes == 0 || stream.port_clock < 1000 || t.clock == 0 {
        return Err(());
    }
    let hblank_total = u64::from(t.htotal.saturating_sub(t.width));
    let hblank_ns = (1_000_000 * hblank_total / u64::from(t.clock)) as u32;
    let req_ns = ((60 / stream.lanes) + 11) * 1000 / (stream.port_clock / 1000);
    if hblank_ns.wrapping_sub(req_ns) > 100 {
        Ok(false)
    } else if stream.display_ver <= 13 || stream.edp_rev < DP_EDP_14B {
        Err(())
    } else {
        Ok(true)
    }
}

/// `intel_psr_compute_config`'s Panel Replay half: `_panel_replay_compute_config`,
/// then `intel_sel_update_config_valid` for Panel Replay (a refusal there
/// keeps full-frame replay).
pub(crate) fn compute(
    caps: &Caps,
    stream: &Stream,
    wm_level_disabled: Option<bool>,
) -> Result<Config, Refusal> {
    source_supported(stream.display_ver, caps.edp)?;
    if stream.dsc && caps.dsc == DscSupport::NotSupported {
        return Err(Refusal::Dsc);
    }
    if caps.edp {
        if stream.pipe > 1 {
            return Err(Refusal::Pipe);
        }
        if stream.uhbr {
            return Err(Refusal::Uhbr);
        }
        if stream.hdcp {
            return Err(Refusal::Hdcp);
        }
    }
    // intel_dp_compute_as_sdp, and on eDP (AUX-less ALPM with an AS SDP
    // sink) lnl_alpm_configure's PR_ALPM_CTL.
    let as_sdp = if stream.as_sdp_v2 {
        Some(as_sdp_fixed(stream.timing.vtotal, caps.async_video_timing()))
    } else {
        None
    };
    let pr_alpm = if caps.edp && stream.as_sdp_v2 {
        Some(pr_alpm_ctl_value(caps))
    } else {
        None
    };
    // Wa_14015648006 is IS_DISPLAY_VER(11, 14); later IPs clear the bit.
    let wm_level_disabled = if stream.display_ver <= 14 {
        wm_level_disabled.ok_or(Refusal::WmLevelUnknown)?
    } else {
        false
    };
    // intel_sel_update_config_valid for Panel Replay.
    let sdp = sdp_prior_scanline(stream);
    let su = stream.sel_fetch
        && caps.su
        && sdp.is_ok()
        && !(stream.dsc && caps.dsc != DscSupport::SelectiveUpdate)
        && granularity_ok(caps, stream);
    let sdp_prior = su && sdp == Ok(true);
    let alpm = if caps.edp {
        Some(alpm_params(stream, sdp_prior)?)
    } else {
        None
    };
    Ok(Config {
        edp: caps.edp,
        display_ver: stream.display_ver,
        pipe: stream.pipe,
        port: stream.port,
        su,
        su_y_granularity: u16::from(caps.su_y_granularity),
        // psr2_su_region_et_valid would allow early transport on display
        // 20+ eDP; the selective-fetch area code here has no early
        // transport adjustments, so it stays off, as Linux's
        // I915_PSR_DEBUG_SU_REGION_ET_DISABLE leaves it.
        su_region_et: false,
        sdp_prior_scanline: sdp_prior,
        alpm,
        wm_level_disabled,
        as_sdp,
        pr_alpm_ctl: pr_alpm,
    })
}

/// `psr2_granularity_check` for Panel Replay with selective fetch: a
/// full-line X granularity is the width; display 14+ fetch at one-line
/// granularity, so the sink's Y granularity holds as is.
fn granularity_ok(caps: &Caps, stream: &Stream) -> bool {
    let w = if caps.su_w_granularity == DP_PANEL_REPLAY_FULL_LINE_GRANULARITY {
        stream.timing.width
    } else {
        caps.su_w_granularity
    };
    let y = u16::from(caps.su_y_granularity);
    w != 0 && y != 0 && stream.timing.width % w == 0 && stream.timing.height % y == 0
}

/// `_panel_replay_enable_sink`'s `PANEL_REPLAY_CONFIG` and
/// `PANEL_REPLAY_CONFIG2` bytes.
pub fn sink_config(config: &Config) -> [u8; 2] {
    let mut first = DP_PANEL_REPLAY_ENABLE
        | DP_PANEL_REPLAY_VSC_SDP_CRC_EN
        | DP_PANEL_REPLAY_UNRECOVERABLE_ERROR_EN
        | DP_PANEL_REPLAY_RFB_STORAGE_ERROR_EN
        | DP_PANEL_REPLAY_ACTIVE_FRAME_CRC_ERROR_EN;
    let mut second = DP_PANEL_REPLAY_CRC_VERIFICATION;
    if config.su {
        first |= DP_PANEL_REPLAY_SU_ENABLE;
    }
    if config.su_region_et {
        first |= DP_PANEL_REPLAY_ENABLE_SU_REGION_ET;
    }
    if config.sdp_prior_scanline {
        second |= DP_PANEL_REPLAY_SU_REGION_SCANLINE_CAPTURE;
    }
    [first, second]
}

/// `intel_psr_enable_source`'s `PSR_DEBUG` mask for Panel Replay: below
/// display 20 or on eDP `MASK_HPD`; eDP adds `MEMUP` and `LPSP` (display
/// 20+ has no `MAX_SLEEP`). DP on display 20+ masks nothing.
pub const fn debug_mask(config: &Config) -> u32 {
    let mut mask = 0;
    if config.display_ver < 20 || config.edp {
        mask = PSR_DEBUG_MASK_HPD;
    }
    if config.edp {
        mask |= PSR_DEBUG_MASK_MEMUP | PSR_DEBUG_MASK_LPSP;
    }
    mask
}

/// `lnl_alpm_configure` for eDP Panel Replay (AUX-less, no AS SDP).
pub fn alpm_ctl_value(alpm: &Alpm) -> u32 {
    ALPM_CTL_ALPM_ENABLE
        | ALPM_CTL_ALPM_AUX_LESS_ENABLE
        | ALPM_CTL_AUX_LESS_SLEEP_HOLD_TIME_50_SYMBOLS
        | (u32::from(alpm.aux_less_wake_lines) & ALPM_CTL_AUX_LESS_WAKE_TIME_MASK)
        | alpm_ctl_entry_check(u32::from(alpm.check_entry_lines))
}

/// `intel_alpm_port_configure` for AUX-less ALPM: `PORT_ALPM_CTL` and
/// `PORT_ALPM_LFPS_CTL`.
pub fn port_alpm_values(alpm: &Alpm) -> (u32, u32) {
    let half = u32::from(alpm.lfps_half_cycle_num_of_syms);
    (
        PORT_ALPM_CTL_ALPM_AUX_LESS_ENABLE
            | port_alpm_ctl_max_phy_swing_setup(15)
            | (u32::from(alpm.silence_period_sym_clocks) & PORT_ALPM_CTL_SILENCE_PERIOD_MASK),
        port_alpm_lfps_value(LFPS_CYCLE_COUNT, half),
    )
}

// ── Owner ────────────────────────────────────────────────────────

fn readable<M: MmioWindow + ?Sized>(regs: &M, register: u64) -> Result<u32, Refusal> {
    let value = regs.read32(register);
    if value == u32::MAX || !regs.display_access_ok() {
        Err(Refusal::Unavailable)
    } else {
        Ok(value)
    }
}

/// A running Panel Replay on one transcoder: what it enabled, and whether
/// it is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanelReplay {
    config: Config,
    active: bool,
}

impl PanelReplay {
    /// `intel_psr_enable_locked` for Panel Replay up to (not including)
    /// `intel_psr_activate`: no PSR error check (`psr_interrupt_error_check`
    /// skips replay), the sink (`intel_alpm_enable_sink` on eDP,
    /// `_panel_replay_enable_sink`, `PANEL_REPLAY_CONFIG3`, eDP's
    /// `DP_SET_POWER` D0), then the source (`PSR_DEBUG`, `psr_irq_control`,
    /// `wm_optimization_wa`, and on eDP the port and transcoder ALPM).
    /// Every check precedes the first write; a failed sink conversation
    /// leaves the source untouched. The caller activates with
    /// [`Self::resume`] once its frame change latched.
    pub fn enable<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
        regs: &M,
        aux: &mut A,
        config: Config,
    ) -> Result<Self, Refusal> {
        let t = config.pipe;
        if readable(regs, trans_dp2_ctl(t))? & TRANS_DP2_PANEL_REPLAY_ENABLE != 0
            || readable(regs, psr2_ctl(t))? & (1 << 31) != 0
            || readable(regs, 0x60800 + 0x1000 * u64::from(t))? & (1 << 31) != 0
        {
            return Err(Refusal::Inherited);
        }
        if !enabled_at_training(aux)? {
            return Err(Refusal::NotEnabledAtTraining);
        }
        let dcpr = readable(regs, CHICKEN_DCPR_1)?;
        let imr = readable(regs, psr_imr(t))?;
        readable(regs, video_dip_ctl(t))?;
        if config.as_sdp.is_some() && readable(regs, trans_vrr_vsync(t))? == 0 {
            return Err(Refusal::AsSdpTiming);
        }
        let [first, second] = sink_config(&config);
        let alpm = if config.edp {
            write(aux, DP_RECEIVER_ALPM_CONFIG, SINK_ALPM_AUX_LESS)
        } else {
            Ok(())
        };
        let sink = alpm
            .and_then(|()| write(aux, PANEL_REPLAY_CONFIG, first))
            .and_then(|()| write(aux, PANEL_REPLAY_CONFIG2, second))
            .and_then(|()| write(aux, PANEL_REPLAY_CONFIG3, DP_PR_AS_SDP_SETUP_TIME_T1))
            .and_then(|()| {
                if config.edp {
                    write(aux, DP_SET_POWER, DP_SET_POWER_D0)
                } else {
                    Ok(())
                }
            });
        if let Err(error) = sink {
            // Back to the pre-training enable alone.
            let _ = write(aux, PANEL_REPLAY_CONFIG, DP_PANEL_REPLAY_ENABLE);
            if config.edp {
                let _ = write(aux, DP_RECEIVER_ALPM_CONFIG, 0);
            }
            return Err(Refusal::Aux(error));
        }
        // intel_dp_set_infoframes' SDPs of a replay stream: the VSC SDP
        // (has_psr), then the AS SDP.
        write_sdp(
            regs,
            t,
            video_dip_vsc_data,
            VIDEO_DIP_ENABLE_VSC_HSW,
            VIDEO_DIP_ENABLE_VSC_HSW | VSC_DIP_HW_DATA_SW_HEA,
            &pack_replay_vsc_sdp(),
        );
        if let Some(as_sdp) = config.as_sdp {
            write_sdp(
                regs,
                t,
                video_dip_as_sdp_data,
                VIDEO_DIP_ENABLE_AS_ADL,
                VIDEO_DIP_ENABLE_AS_ADL,
                &pack_as_sdp(&as_sdp),
            );
        }
        // intel_psr_enable_source.
        regs.write32(psr_debug(t), debug_mask(&config));
        regs.write32(psr_imr(t), (imr & !TGL_PSR_MASK) | !TGL_PSR_ERROR);
        let removed = latency_reporting_removed(config.pipe);
        regs.write32(
            CHICKEN_DCPR_1,
            if config.wm_level_disabled {
                dcpr | removed
            } else {
                dcpr & !removed
            },
        );
        if let Some(alpm) = config.alpm {
            let (port_ctl, lfps) = port_alpm_values(&alpm);
            regs.write32(port_alpm_ctl(config.port), port_ctl);
            regs.write32(port_alpm_lfps_ctl(config.port), lfps);
            if let Some(pr_alpm) = config.pr_alpm_ctl {
                regs.write32(pr_alpm_ctl(t), pr_alpm);
            }
            regs.write32(alpm_ctl(t), alpm_ctl_value(&alpm));
        }
        Ok(Self {
            config,
            active: false,
        })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn active(&self) -> bool {
        self.active
    }

    /// `dg2_activate_panel_replay`: eDP selective update writes
    /// `EDP_PSR2_CTL` (region ET, SDP scanline; no `EDP_PSR2_ENABLE`),
    /// `PSR2_MAN_TRK_CTL` gets continuous full frame, then
    /// `TRANS_DP2_CTL` the replay enable (tunneling cleared below
    /// display 35).
    pub fn activate<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        let t = self.config.pipe;
        let dp2 = readable(regs, trans_dp2_ctl(t))?;
        let man = readable(regs, psr2_man_trk_ctl(t))?;
        if self.config.edp && self.config.su {
            let mut val = 0;
            if self.config.su_region_et {
                val |= LNL_EDP_PSR2_SU_REGION_ET_ENABLE;
            }
            if self.config.sdp_prior_scanline {
                val |= EDP_PSR2_SU_SDP_SCANLINE;
            }
            regs.write32(psr2_ctl(t), val);
        }
        regs.write32(psr2_man_trk_ctl(t), man | MAN_TRK_SF_CONTINUOUS_FULL_FRAME);
        regs.write32(
            trans_dp2_ctl(t),
            (dp2 & !TRANS_DP2_PR_TUNNELING_ENABLE) | TRANS_DP2_PANEL_REPLAY_ENABLE,
        );
        self.active = true;
        Ok(())
    }

    /// `intel_psr_exit` for Panel Replay: clear the replay enable.
    pub fn exit<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        if !self.active {
            return Ok(());
        }
        let t = self.config.pipe;
        let dp2 = readable(regs, trans_dp2_ctl(t))?;
        regs.write32(trans_dp2_ctl(t), dp2 & !TRANS_DP2_PANEL_REPLAY_ENABLE);
        self.active = false;
        Ok(())
    }

    /// `intel_psr_wait_exit_locked`'s status: `EDP_PSR2_STATUS` on eDP,
    /// `EDP_PSR_STATUS` (SRD_STATUS) on DP.
    pub fn status(&self) -> (u64, u32) {
        if self.config.edp {
            (psr2_status(self.config.pipe), PSR2_STATUS_STATE_MASK)
        } else {
            (psr_status(self.config.pipe), PSR_STATUS_STATE_MASK)
        }
    }

    /// The replay state machine is idle.
    pub fn idle<M: MmioWindow + ?Sized>(&self, regs: &M) -> Result<bool, Refusal> {
        let (register, mask) = self.status();
        Ok(readable(regs, register)? & mask == 0)
    }

    /// Bounded `intel_psr_wait_exit_locked`.
    pub fn wait_idle<M: MmioWindow + ?Sized>(
        &self,
        regs: &M,
        timeout_ms: u64,
    ) -> Result<(), Refusal> {
        let (register, mask) = self.status();
        let mut lost = false;
        let ok = narf_scheduler::responsive_spin_until(
            || {
                let v = regs.read32(register);
                lost = v == u32::MAX || !regs.display_access_ok();
                lost || v & mask == 0
            },
            narf_time::Deadline::after_ms(timeout_ms),
        );
        if lost {
            Err(Refusal::Unavailable)
        } else if ok {
            Ok(())
        } else {
            Err(Refusal::ExitTimeout)
        }
    }

    /// The selective-fetch configuration of selective update over Panel
    /// Replay for [`crate::intel_gpu_psr::sel_fetch_update`]: the sink's Y
    /// granularity over the full-width pipe source (no display-14 A0..A3
    /// workaround: Linux skips it for Panel Replay).
    pub fn psr2(&self, width: u16, height: u16) -> Option<crate::intel_gpu_psr::Psr2> {
        if !self.config.su {
            return None;
        }
        let (io, fast) = self
            .config
            .alpm
            .map_or((7, 7), |a| (a.io_wake_lines, a.fast_wake_lines));
        Some(crate::intel_gpu_psr::Psr2 {
            io_wake_lines: io,
            fast_wake_lines: fast,
            req_sdp_prior_scanline: self.config.sdp_prior_scanline,
            su_y_granularity: self.config.su_y_granularity,
            frames_before_su: 0,
            tp2_wakeup_us: 0,
            a0_to_b0: false,
            width,
            height,
        })
    }

    /// One commit's selective update over Panel Replay for the pipe's
    /// full-screen primary: the noarm `SEL_FETCH_PLANE_POS`, `_OFFSET`,
    /// `_SIZE`, then `PSR2_MAN_TRK_CTL` and `SEL_FETCH_PLANE_CTL`
    /// (`icl_plane_update_sel_fetch_noarm` / `_arm`,
    /// `intel_psr2_program_trans_man_trk_ctl`).
    pub fn program_sel_fetch<M: MmioWindow + ?Sized>(
        &self,
        regs: &M,
        width: u16,
        sf: &crate::intel_gpu_psr::SelFetch,
    ) {
        let pipe = 0x1000 * u64::from(self.config.pipe);
        let (y1, y2) = sf.primary.unwrap_or((-1, -1));
        regs.write32(
            crate::intel_gpu_psr::SEL_FETCH_PLANE_POS + pipe,
            (y1 as u32) << 16,
        );
        regs.write32(
            crate::intel_gpu_psr::SEL_FETCH_PLANE_OFFSET + pipe,
            (y1 as u32) << 16,
        );
        regs.write32(
            crate::intel_gpu_psr::SEL_FETCH_PLANE_SIZE + pipe,
            ((y2.wrapping_sub(y1).wrapping_sub(1) as u32) << 16) | u32::from(width).wrapping_sub(1),
        );
        regs.write32(psr2_man_trk_ctl(self.config.pipe), sf.man_trk_ctl);
        regs.write32(
            crate::intel_gpu_psr::SEL_FETCH_PLANE_CTL + pipe,
            if y2 > y1 {
                crate::intel_gpu_psr::SEL_FETCH_PLANE_CTL_ENABLE
            } else {
                0
            },
        );
    }

    /// `intel_psr_resume` after a frame change latched: re-activate from
    /// idle only.
    pub fn resume<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<bool, Refusal> {
        if self.active {
            return Ok(true);
        }
        if !self.idle(regs)? {
            return Ok(false);
        }
        self.activate(regs)?;
        Ok(true)
    }

    /// `intel_psr_disable_locked` for Panel Replay: exit, wait idle, clear
    /// `LATENCY_REPORTING_REMOVED`, then on eDP `intel_alpm_disable`. The
    /// sink keeps its replay configuration (Linux clears only PSR's
    /// `DP_PSR_EN_CFG`). The VSC and AS SDP enables the enable set are
    /// cleared last (Linux clears them when the crtc goes off,
    /// `intel_dp_set_infoframes(false)`, which no route stop here runs).
    /// Every step runs; the first failure is returned.
    pub fn disable<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        timeout_ms: u64,
    ) -> Result<(), Refusal> {
        let mut first = self.exit(regs).err();
        if let Err(refusal) = self.wait_idle(regs, timeout_ms) {
            first.get_or_insert(refusal);
        }
        let dcpr = regs.read32(CHICKEN_DCPR_1);
        if dcpr != u32::MAX {
            regs.write32(
                CHICKEN_DCPR_1,
                dcpr & !latency_reporting_removed(self.config.pipe),
            );
        }
        if self.config.edp {
            let t = self.config.pipe;
            let ctl = regs.read32(alpm_ctl(t));
            if ctl != u32::MAX {
                regs.write32(
                    alpm_ctl(t),
                    ctl & !(ALPM_CTL_ALPM_ENABLE | ALPM_CTL_LOBF_ENABLE),
                );
            }
        }
        let t = self.config.pipe;
        let dip = regs.read32(video_dip_ctl(t));
        if dip != u32::MAX {
            let mut enables = VIDEO_DIP_ENABLE_VSC_HSW;
            if self.config.as_sdp.is_some() {
                enables |= VIDEO_DIP_ENABLE_AS_ADL;
            }
            regs.write32(video_dip_ctl(t), dip & !enables);
        }
        self.active = false;
        first.map_or(Ok(()), Err)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_panel_replay_tests.rs"]
mod tests;
