//! Display-14 Panel Self Refresh (PSR1) on the KMS-owned Pipe-A eDP.
//!
//! Pinned source: Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! `i915/display/intel_psr.c`, `intel_psr_regs.h`, `intel_alpm.c`,
//! `intel_fbc.c`, `intel_dp.c`, `intel_crtc.c`, `intel_bios.c`,
//! `intel_display_params.h`, `skl_watermark.c`, `i915_reg.h`,
//! `drm/display/drm_dp_helper.c` and `include/drm/display/drm_dp.h`.
//!
//! What is modelled, for display 14 (Meteor Lake / Arrow Lake), eDP on
//! transcoder A:
//!
//! - Sink capability (`intel_dp_get_dpcd`'s eDP DPCD read,
//!   `intel_alpm_init`, `_psr_init_dpcd`, `_psr_compute_su_granularity`,
//!   `intel_dp_get_sink_sync_latency`, the `DP_DPCD_QUIRK_NO_PSR` sink-OUI
//!   entry of `dpcd_quirk_list`).
//! - Qualification (`intel_psr_compute_config` → `_psr_compute_config` →
//!   `intel_psr_entry_setup_frames`): first `psr_global_enabled` (eDP
//!   with the default debug mode: the VBT's `psr.enable` for the panel),
//!   then no interlace, a valid setup time that
//!   fits `vtotal - vdisplay - 1` lines (display < 20 has no entry setup
//!   frames). Panel Replay and selective update are not offered here.
//! - Enable (`intel_psr_enable_locked`): `psr_interrupt_error_check`, then
//!   `intel_psr_enable_sink` (PSR1 needs no ALPM: `intel_psr_needs_alpm`),
//!   then `intel_psr_enable_source` (PSR_MASK, `psr_irq_control`,
//!   Wa_14015648006 through `wm_optimization_wa`; display 14 has no PSR2 HW
//!   tracking chicken, no DC3CO exit line and no ALPM programming), then
//!   `hsw_activate_psr1` with the VBT training-pattern wake times
//!   (`intel_psr1_get_tp_time`) and idle frames (`psr_compute_idle_frames`).
//! - Watermark changes while enabled (`intel_psr_pre_plane_update` /
//!   `intel_psr_post_plane_update`): `wm_optimization_wa` sets
//!   `LATENCY_REPORTING_REMOVED` before a state whose `wm_level_disabled`
//!   is true, and clears it after one whose value is false
//!   ([`Psr::wm_optimization_wa`]).
//! - Exit / re-arm (`intel_psr_exit`, `intel_psr_wait_exit_locked`,
//!   `intel_psr_pause`, `intel_psr_resume`, `intel_psr_work`'s
//!   `__psr_wait_for_idle_locked` gate) and disable
//!   (`intel_psr_disable_locked`).
//! - Errors: Linux takes `TGL_PSR_ERROR` as an interrupt and then
//!   `intel_psr_handle_irq` disables PSR, marks the sink unreliable and
//!   wakes the sink. This driver has no display interrupt handler, so the
//!   same bit is polled in `TRANS_PSR_IIR` at every pause and re-arm, with
//!   the same consequence; enable refuses while `GEN8_DE_MISC_IER` could
//!   deliver `GEN8_DE_EDP_PSR` to the CPU.
//!
//! The VBT ([`VbtPsr`], installed at probe): `psr_global_enabled` takes
//! eDP PSR from the panel's `psr.enable`. Without a VBT Linux never sets
//! it (`init_vbt_missing_defaults` and `parse_power_conservation_features`
//! leave it false), so PSR is refused (`VbtDisabled`) exactly as Linux's
//! "PSR disabled by flag". `psr_safest_params` defaults to false, so the
//! TP1 and TP2/TP3 wake times come from the VBT's PSR table (zero when the
//! VBT has no PSR block, as Linux's zeroed panel data gives), and the idle
//! frames are `max(6, vbt idle_frames, sync_latency + 1)`. `link_standby`
//! keeps its display >= 12 default (false: link off; `full_link` is only
//! read below display 12). The panel is `get_panel_type`'s VBT index for
//! the port-A child (`panel_type2` for an LFP2 handle), falling back to 0
//! as Linux does; a VBT that selects its panel by EDID PnP ID (0xFF) is
//! refused (`VbtPanelByPnpId`) because this driver does not match PnP IDs.
//! A sink that reports a PSR error is never re-enabled.
//!
//! Wa_14015648006 needs `wm_level_disabled` from `skl_wm_check_vblank`.
//! The display-14 watermark code registers its Pipe-A provider
//! ([`register_wm_level_disabled`]); with no provider, or while the
//! programmed watermarks are not proved, PSR is refused (`WmLevelUnknown`)
//! rather than guessed.

use narf_lib::sync::IrqSafeSpinLock;

use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxStatus};
use crate::intel_gpu_aux::MmioWindow;

// ── Source registers (transcoder A; intel_psr_regs.h, i915_reg.h) ──

/// `EDP_PSR_CTL(TRANSCODER_A)`.
pub const PSR_CTL: u64 = 0x60800;
/// `TRANS_PSR_IMR(TRANSCODER_A)`.
pub const PSR_IMR: u64 = 0x60814;
/// `TRANS_PSR_IIR(TRANSCODER_A)`.
pub const PSR_IIR: u64 = 0x60818;
/// `EDP_PSR_STATUS(TRANSCODER_A)`.
pub const PSR_STATUS: u64 = 0x60840;
/// `EDP_PSR_DEBUG(TRANSCODER_A)` (PSR_MASK on SKL+).
pub const PSR_DEBUG: u64 = 0x60860;
/// `EDP_PSR2_CTL(TRANSCODER_A)`.
pub const PSR2_CTL: u64 = 0x60900;
/// `EDP_PSR2_STATUS(TRANSCODER_A)`.
pub const PSR2_STATUS: u64 = 0x60940;
/// `GEN8_CHICKEN_DCPR_1`.
pub const CHICKEN_DCPR_1: u64 = 0x46430;
/// `GEN8_DE_MISC_IMR`.
pub const DE_MISC_IMR: u64 = 0x44464;
/// `GEN8_DE_MISC_IER`.
pub const DE_MISC_IER: u64 = 0x4446c;

/// `EDP_PSR_ENABLE`.
pub const EDP_PSR_ENABLE: u32 = 1 << 31;
/// `EDP_PSR_RESTORE_PSR_ACTIVE_CTX_MASK` (software must not modify).
pub const EDP_PSR_RESTORE_PSR_ACTIVE_CTX: u32 = 1 << 29;
/// `EDP_PSR_MAX_SLEEP_TIME(0x1f)` (`hsw_activate_psr1`, display < 20).
pub const EDP_PSR_MAX_SLEEP_TIME_MAX: u32 = 0x1f << 20;
/// `EDP_PSR_TP_TP1_TP3`.
pub const EDP_PSR_TP_TP1_TP3: u32 = 1 << 11;
/// `EDP_PSR_CRC_ENABLE`.
pub const EDP_PSR_CRC_ENABLE: u32 = 1 << 10;
/// `EDP_PSR_TP2_TP3_TIME_500us`.
pub const EDP_PSR_TP2_TP3_TIME_500US: u32 = 0;
/// `EDP_PSR_TP2_TP3_TIME_100us`.
pub const EDP_PSR_TP2_TP3_TIME_100US: u32 = 1 << 8;
/// `EDP_PSR_TP2_TP3_TIME_2500us`.
pub const EDP_PSR_TP2_TP3_TIME_2500US: u32 = 2 << 8;
/// `EDP_PSR_TP2_TP3_TIME_0us`.
pub const EDP_PSR_TP2_TP3_TIME_0US: u32 = 3 << 8;
/// `EDP_PSR_TP4_TIME_0us` (ICL+).
pub const EDP_PSR_TP4_TIME_0US: u32 = 3 << 6;
/// `EDP_PSR_TP1_TIME_500us`.
pub const EDP_PSR_TP1_TIME_500US: u32 = 0;
/// `EDP_PSR_TP1_TIME_100us`.
pub const EDP_PSR_TP1_TIME_100US: u32 = 1 << 4;
/// `EDP_PSR_TP1_TIME_2500us`.
pub const EDP_PSR_TP1_TIME_2500US: u32 = 2 << 4;
/// `EDP_PSR_TP1_TIME_0us`.
pub const EDP_PSR_TP1_TIME_0US: u32 = 3 << 4;
/// `EDP_PSR_IDLE_FRAMES_MASK`.
pub const EDP_PSR_IDLE_FRAMES_MASK: u32 = 0xf;
/// `EDP_PSR_STATUS_STATE_MASK`.
pub const EDP_PSR_STATUS_STATE_MASK: u32 = 7 << 29;
/// `EDP_PSR2_ENABLE`.
pub const EDP_PSR2_ENABLE: u32 = 1 << 31;
/// `EDP_PSR2_STATUS_STATE_MASK`.
pub const EDP_PSR2_STATUS_STATE_MASK: u32 = 0xf << 28;
/// `TGL_PSR_MASK`.
pub const TGL_PSR_MASK: u32 = 7;
/// `TGL_PSR_ERROR`.
pub const TGL_PSR_ERROR: u32 = 1 << 2;
/// `EDP_PSR_DEBUG_MASK_MAX_SLEEP`.
pub const EDP_PSR_DEBUG_MASK_MAX_SLEEP: u32 = 1 << 28;
/// `EDP_PSR_DEBUG_MASK_LPSP`.
pub const EDP_PSR_DEBUG_MASK_LPSP: u32 = 1 << 27;
/// `EDP_PSR_DEBUG_MASK_MEMUP`.
pub const EDP_PSR_DEBUG_MASK_MEMUP: u32 = 1 << 26;
/// `EDP_PSR_DEBUG_MASK_HPD`.
pub const EDP_PSR_DEBUG_MASK_HPD: u32 = 1 << 25;
/// `LATENCY_REPORTING_REMOVED(PIPE_A)`.
pub const LATENCY_REPORTING_REMOVED_PIPE_A: u32 = 1 << 23;
/// `GEN8_DE_EDP_PSR`.
pub const GEN8_DE_EDP_PSR: u32 = 1 << 19;

/// `intel_psr_enable_source`'s PSR_MASK for display 14 eDP: HPD, MEMUP,
/// LPSP (display >= 8) and MAX_SLEEP (display < 20).
pub const PSR_DEBUG_MASK: u32 = EDP_PSR_DEBUG_MASK_HPD
    | EDP_PSR_DEBUG_MASK_MEMUP
    | EDP_PSR_DEBUG_MASK_LPSP
    | EDP_PSR_DEBUG_MASK_MAX_SLEEP;

/// `intel_psr_wait_exit_locked`'s bound.
pub const PSR_EXIT_TIMEOUT_MS: u64 = 2000;
/// `PSR_IDLE_TIMEOUT_MS` (pipe update / re-enable idle wait).
pub const PSR_IDLE_TIMEOUT_MS: u64 = 50;

// ── Sink DPCD (drm_dp.h) ──────────────────────────────────────────

/// `DP_DPCD_REV`.
pub const DP_DPCD_REV: u32 = 0x000;
/// `DP_MAX_LANE_COUNT`.
pub const DP_MAX_LANE_COUNT: u32 = 0x002;
/// `DP_TPS3_SUPPORTED`.
pub const DP_TPS3_SUPPORTED: u8 = 1 << 6;
/// `DP_RECEIVER_ALPM_CAP`.
pub const DP_RECEIVER_ALPM_CAP: u32 = 0x02e;
/// `DP_ALPM_CAP`.
pub const DP_ALPM_CAP: u8 = 1 << 0;
/// `DP_PSR_SUPPORT`.
pub const DP_PSR_SUPPORT: u32 = 0x070;
/// `DP_PSR2_WITH_Y_COORD_IS_SUPPORTED`.
pub const DP_PSR2_WITH_Y_COORD_IS_SUPPORTED: u8 = 3;
/// `DP_PSR_SETUP_TIME_MASK`.
pub const DP_PSR_SETUP_TIME_MASK: u8 = 7 << 1;
/// `DP_PSR2_SU_Y_COORDINATE_REQUIRED`.
pub const DP_PSR2_SU_Y_COORDINATE_REQUIRED: u8 = 1 << 4;
/// `DP_PSR2_SU_GRANULARITY_REQUIRED`.
pub const DP_PSR2_SU_GRANULARITY_REQUIRED: u8 = 1 << 5;
/// `DP_PSR2_SU_X_GRANULARITY`.
pub const DP_PSR2_SU_X_GRANULARITY: u32 = 0x072;
/// `DP_PSR2_SU_Y_GRANULARITY`.
pub const DP_PSR2_SU_Y_GRANULARITY: u32 = 0x074;
/// `DP_PSR_EN_CFG`.
pub const DP_PSR_EN_CFG: u32 = 0x170;
/// `DP_PSR_ENABLE`.
pub const DP_PSR_ENABLE: u8 = 1 << 0;
/// `DP_PSR_MAIN_LINK_ACTIVE`.
pub const DP_PSR_MAIN_LINK_ACTIVE: u8 = 1 << 1;
/// `DP_PSR_CRC_VERIFICATION`.
pub const DP_PSR_CRC_VERIFICATION: u8 = 1 << 2;
/// `DP_SINK_OUI`.
pub const DP_SINK_OUI: u32 = 0x400;
/// `DP_SET_POWER`.
pub const DP_SET_POWER: u32 = 0x600;
/// `DP_SET_POWER_D0`.
pub const DP_SET_POWER_D0: u8 = 1;
/// `DP_EDP_DPCD_REV` (`EDP_DISPLAY_CTL_CAP_SIZE` bytes follow).
pub const DP_EDP_DPCD_REV: u32 = 0x700;
/// `DP_EDP_SET_POWER_CAP` in `DP_EDP_GENERAL_CAP_1`.
pub const DP_EDP_SET_POWER_CAP: u8 = 1 << 7;
/// `DP_SYNCHRONIZATION_LATENCY_IN_SINK`.
pub const DP_SYNCHRONIZATION_LATENCY_IN_SINK: u32 = 0x2009;
/// `DP_MAX_RESYNC_FRAME_COUNT_MASK`.
pub const DP_MAX_RESYNC_FRAME_COUNT_MASK: u8 = 0xf;
/// The `DP_DPCD_QUIRK_NO_PSR` sink OUI in `dpcd_quirk_list` (Apple).
pub const NO_PSR_SINK_OUI: [u8; 3] = [0x00, 0x10, 0xfa];
/// `DRM_MODE_FLAG_INTERLACE`.
pub const DRM_MODE_FLAG_INTERLACE: u32 = 1 << 4;

/// `drm_dp_psr_setup_time`'s table, in µs, by `DP_PSR_SETUP_TIME` code.
const PSR_SETUP_TIME_US: [u32; 7] = [330, 275, 220, 165, 110, 55, 0];

/// Why PSR is not (or no longer) running. `latched()` refusals are kept
/// for the card's lifetime; the rest are re-evaluated at the next latch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No fixed Pipe-A panel timing (not display 14, or no mode).
    NoTiming,
    /// `psr_global_enabled` is false: the VBT's `psr.enable` for the
    /// panel is clear, or there is no VBT ("PSR disabled by flag").
    VbtDisabled,
    /// The VBT selects the panel by EDID PnP ID, which is not matched.
    VbtPanelByPnpId,
    /// A sink AUX transaction failed.
    Aux(AuxError),
    /// `DP_PSR_SUPPORT` is zero.
    NoSinkPsr,
    /// `DP_DPCD_QUIRK_NO_PSR` (sink OUI 00:10:fa).
    SinkQuirk,
    /// `DP_EDP_SET_POWER_CAP` clear: "Panel lacks power state control".
    NoSetPowerCap,
    /// `DRM_MODE_FLAG_INTERLACE`.
    Interlaced,
    /// `drm_dp_psr_setup_time` returned `-EINVAL`.
    InvalidSetupTime,
    /// The setup time does not fit `vtotal - vdisplay - 1` lines.
    SetupTimeTooLong,
    /// Wa_14015648006's `wm_level_disabled` is not provided.
    WmLevelUnknown,
    /// `GEN8_DE_MISC_IER` could deliver `GEN8_DE_EDP_PSR`, and there is no
    /// display interrupt handler.
    InterruptDelivery,
    /// `TGL_PSR_ERROR` latched (`psr_interrupt_error_check` /
    /// `intel_psr_handle_irq`): `sink_not_reliable`.
    SinkNotReliable,
    /// PSR1 or PSR2 was found enabled by somebody else.
    Inherited,
    /// A source register read all-ones.
    Unavailable,
    /// PSR did not return to idle within the bound.
    ExitTimeout,
}

impl Refusal {
    /// Whether this refusal holds until the card goes away.
    pub fn latched(self) -> bool {
        matches!(
            self,
            Refusal::NoSinkPsr
                | Refusal::SinkQuirk
                | Refusal::NoSetPowerCap
                | Refusal::Interlaced
                | Refusal::InvalidSetupTime
                | Refusal::SetupTimeTooLong
                | Refusal::SinkNotReliable
                | Refusal::ExitTimeout
        )
    }
}

fn read<A: AuxChannel + ?Sized>(aux: &mut A, address: u32, buf: &mut [u8]) -> Result<(), AuxError> {
    let request = AuxRequest {
        cmd: AuxCommand::NativeRead,
        address,
        data: &*buf,
    };
    let mut reply = [0u8; 17];
    let len = buf.len();
    let response = aux.transact(&request, &mut reply[..1 + len])?;
    if response.status != AuxStatus::Ack {
        return Err(AuxError::Nacked);
    }
    if response.data.len() != len {
        return Err(AuxError::ShortReply);
    }
    buf.copy_from_slice(response.data);
    Ok(())
}

fn write<A: AuxChannel + ?Sized>(aux: &mut A, address: u32, value: u8) -> Result<(), AuxError> {
    let data = [value];
    let request = AuxRequest {
        cmd: AuxCommand::NativeWrite,
        address,
        data: &data,
    };
    let mut reply = [0u8; 1];
    let response = aux.transact(&request, &mut reply)?;
    if response.status != AuxStatus::Ack {
        return Err(AuxError::Nacked);
    }
    Ok(())
}

// ── Sink capability ───────────────────────────────────────────────

/// The PSR-relevant sink DPCD, read once per card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sink {
    /// `DP_PSR_SUPPORT`, `DP_PSR_CAPS` (`EDP_PSR_RECEIVER_CAP_SIZE`).
    pub psr: [u8; 2],
    /// `DP_DPCD_REV`.
    pub dpcd_rev: u8,
    /// `DP_MAX_LANE_COUNT`.
    pub max_lane_count: u8,
    /// `DP_EDP_DPCD_REV..` (`EDP_DISPLAY_CTL_CAP_SIZE`); zero when the
    /// read fails, as `intel_dp->edp_dpcd` stays.
    pub edp: [u8; 5],
    /// `DP_RECEIVER_ALPM_CAP` (`intel_dp->alpm_dpcd`); zero on failure.
    pub alpm: u8,
    /// `DP_SINK_OUI`; zero on failure (no quirk).
    pub oui: [u8; 3],
    /// `intel_dp_get_sink_sync_latency` (8 when unreadable).
    pub sync_latency: u8,
    /// `su_w_granularity` (`_psr_compute_su_granularity`).
    pub su_w_granularity: u16,
    /// `su_y_granularity`.
    pub su_y_granularity: u8,
}

impl Sink {
    /// Read the sink fields `intel_dp_get_dpcd`, `intel_alpm_init`,
    /// `drm_dp_read_desc` and `_psr_init_dpcd` consult. The receiver
    /// capability and PSR capability reads are required; the others fall
    /// back to the values Linux keeps when they fail.
    pub fn read<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<Sink, Refusal> {
        let mut receiver = [0u8; 3];
        read(aux, DP_DPCD_REV, &mut receiver).map_err(Refusal::Aux)?;
        let mut psr = [0u8; 2];
        read(aux, DP_PSR_SUPPORT, &mut psr).map_err(Refusal::Aux)?;
        let mut edp = [0u8; 5];
        if read(aux, DP_EDP_DPCD_REV, &mut edp).is_err() {
            edp = [0; 5];
        }
        let mut alpm = [0u8; 1];
        if read(aux, DP_RECEIVER_ALPM_CAP, &mut alpm).is_err() {
            alpm = [0];
        }
        let mut oui = [0u8; 3];
        if read(aux, DP_SINK_OUI, &mut oui).is_err() {
            oui = [0; 3];
        }
        let mut sink = Sink {
            psr,
            dpcd_rev: receiver[0],
            max_lane_count: receiver[2],
            edp,
            alpm: alpm[0],
            oui,
            sync_latency: 8,
            su_w_granularity: 4,
            su_y_granularity: 4,
        };
        if sink.psr[0] == 0 || sink.oui == NO_PSR_SINK_OUI || !sink.set_power_cap() {
            return Ok(sink);
        }
        let mut latency = [0u8; 1];
        if read(aux, DP_SYNCHRONIZATION_LATENCY_IN_SINK, &mut latency).is_ok() {
            sink.sync_latency = latency[0] & DP_MAX_RESYNC_FRAME_COUNT_MASK;
        }
        if sink.su_support() && sink.psr[1] & DP_PSR2_SU_GRANULARITY_REQUIRED != 0 {
            let mut w = [0u8; 2];
            sink.su_w_granularity = match read(aux, DP_PSR2_SU_X_GRANULARITY, &mut w) {
                Ok(()) if u16::from_le_bytes(w) != 0 => u16::from_le_bytes(w),
                _ => 4,
            };
            let mut y = [0u8; 1];
            sink.su_y_granularity = match read(aux, DP_PSR2_SU_Y_GRANULARITY, &mut y) {
                Ok(()) if y[0] == 0 => 1,
                Ok(()) => y[0],
                Err(_) => 4,
            };
        }
        Ok(sink)
    }

    /// `intel_dp->edp_dpcd[1] & DP_EDP_SET_POWER_CAP`.
    pub fn set_power_cap(&self) -> bool {
        self.edp[1] & DP_EDP_SET_POWER_CAP != 0
    }

    /// `_psr_init_dpcd`'s `psr_caps.support`.
    pub fn psr_support(&self) -> Result<(), Refusal> {
        if self.psr[0] == 0 {
            return Err(Refusal::NoSinkPsr);
        }
        if self.oui == NO_PSR_SINK_OUI {
            return Err(Refusal::SinkQuirk);
        }
        if !self.set_power_cap() {
            return Err(Refusal::NoSetPowerCap);
        }
        Ok(())
    }

    /// `_psr_init_dpcd`'s `su_support` for display >= 9: PSR version 3+
    /// with the Y-coordinate requirement and AUX-wake ALPM.
    pub fn su_support(&self) -> bool {
        self.psr[0] >= DP_PSR2_WITH_Y_COORD_IS_SUPPORTED
            && self.psr[1] & DP_PSR2_SU_Y_COORDINATE_REQUIRED != 0
            && self.alpm & DP_ALPM_CAP != 0
    }

    /// `intel_dp_source_supports_tps3` (display >= 10) and
    /// `drm_dp_tps3_supported`.
    pub fn tps3(&self) -> bool {
        self.dpcd_rev >= 0x12 && self.max_lane_count & DP_TPS3_SUPPORTED != 0
    }

    /// `drm_dp_psr_setup_time`.
    pub fn setup_time_us(&self) -> Option<u32> {
        PSR_SETUP_TIME_US
            .get(usize::from((self.psr[1] & DP_PSR_SETUP_TIME_MASK) >> 1))
            .copied()
    }
}

// ── Qualification ─────────────────────────────────────────────────

/// `intel_usecs_to_scanlines`.
pub(crate) fn usecs_to_scanlines(timing: &crate::intel_gpu_dsb::Timing, usecs: u32) -> u32 {
    if timing.htotal == 0 {
        return 1;
    }
    (u64::from(usecs) * u64::from(timing.clock)).div_ceil(1000 * u64::from(timing.htotal)) as u32
}

// ── VBT ───────────────────────────────────────────────────────────

/// `DEVICE_HANDLE_LFP2`.
const DEVICE_HANDLE_LFP2: u16 = 0x0080;

/// The VBT facts eDP PSR consumes for the Pipe-A panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VbtPsr {
    /// No VBT: `panel->vbt.psr.enable` is never set.
    Missing,
    /// `panel_type` 0xFF: Linux picks the panel by EDID PnP ID
    /// (`pnpid_get_panel_type`), which this driver does not implement.
    PanelByPnpId,
    /// `parse_psr` and the PSR enable for the selected panel.
    Panel(crate::intel_gpu_vbt::PsrPanel),
}

impl VbtPsr {
    /// `intel_bios_init_panel` for the port-A eDP of a display-14 VBT:
    /// `get_panel_type` (OpRegion panel type only applies to a DMI quirk
    /// list; LFP2 when the port's child has that handle; the VBT index,
    /// else `fallback_get_panel_type`'s 0), then `parse_psr` and the PSR
    /// enable for that panel.
    pub fn from_vbt(vbt: &crate::intel_gpu_vbt::Vbt) -> Self {
        use crate::intel_gpu_vbt::{port, PanelType, VbtPlatform};
        let second = vbt
            .encoder(VbtPlatform::MeteorLake, port::A)
            .and_then(|encoder| vbt.children().get(encoder.child))
            .is_some_and(|child| child.handle() == DEVICE_HANDLE_LFP2);
        match vbt.panel_type(second) {
            PanelType::PnpId => VbtPsr::PanelByPnpId,
            panel => VbtPsr::Panel(vbt.psr_panel(panel.index_or_fallback())),
        }
    }

    /// `psr_global_enabled` for eDP under `I915_PSR_DEBUG_DEFAULT` (and
    /// `enable_psr`'s default -1): the panel's facts when PSR may run.
    pub fn enabled(&self) -> Result<crate::intel_gpu_vbt::PsrPanel, Refusal> {
        match self {
            VbtPsr::Panel(panel) if panel.enable => Ok(*panel),
            VbtPsr::PanelByPnpId => Err(Refusal::VbtPanelByPnpId),
            _ => Err(Refusal::VbtDisabled),
        }
    }
}

static VBT: IrqSafeSpinLock<VbtPsr> = IrqSafeSpinLock::new(VbtPsr::Missing);

/// Install the probe's VBT facts ([`VbtPsr::Missing`] without a VBT).
pub fn install_vbt(vbt: VbtPsr) {
    *VBT.lock() = vbt;
}

/// The installed VBT facts.
pub fn installed_vbt() -> VbtPsr {
    *VBT.lock()
}

/// A qualified PSR1 configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psr1 {
    /// `psr_compute_idle_frames`.
    pub idle_frames: u32,
    /// TP1/TP3 training-pattern select.
    pub tps3: bool,
    /// Wa_14015648006's input.
    pub wm_level_disabled: bool,
    /// The VBT's `psr.tp1_wakeup_time_us`.
    pub tp1_wakeup_us: u32,
    /// The VBT's `psr.tp2_tp3_wakeup_time_us`.
    pub tp2_tp3_wakeup_us: u32,
}

/// `intel_psr_compute_config` for PSR1 on display 14.
pub(crate) fn compute_psr1(
    sink: &Sink,
    timing: &crate::intel_gpu_dsb::Timing,
    vbt: &VbtPsr,
    wm_level_disabled: Option<bool>,
) -> Result<Psr1, Refusal> {
    let panel = vbt.enabled()?;
    if timing.flags & DRM_MODE_FLAG_INTERLACE != 0 {
        return Err(Refusal::Interlaced);
    }
    sink.psr_support()?;
    // intel_psr_entry_setup_frames: display < 20 has no setup frames.
    let setup = sink.setup_time_us().ok_or(Refusal::InvalidSetupTime)?;
    let blank = u32::from(timing.vtotal).saturating_sub(u32::from(timing.height));
    if blank == 0 || usecs_to_scanlines(timing, setup) > blank - 1 {
        return Err(Refusal::SetupTimeTooLong);
    }
    let wm_level_disabled = wm_level_disabled.ok_or(Refusal::WmLevelUnknown)?;
    // The VBT's psr_table is zero when the VBT has no PSR block.
    let table = panel.table;
    Ok(Psr1 {
        idle_frames: 6u32
            .max(table.map_or(0, |t| u32::from(t.idle_frames)))
            .max(u32::from(sink.sync_latency) + 1)
            .min(EDP_PSR_IDLE_FRAMES_MASK),
        tps3: sink.tps3(),
        wm_level_disabled,
        tp1_wakeup_us: table.map_or(0, |t| t.tp1_wakeup_time_us),
        tp2_tp3_wakeup_us: table.map_or(0, |t| t.tp2_tp3_wakeup_time_us),
    })
}

/// `intel_psr1_get_tp_time` for display 14 (`psr_safest_params` false).
pub fn psr1_tp_time(config: &Psr1) -> u32 {
    let mut value = EDP_PSR_TP4_TIME_0US;
    value |= match config.tp1_wakeup_us {
        0 => EDP_PSR_TP1_TIME_0US,
        1..=100 => EDP_PSR_TP1_TIME_100US,
        101..=500 => EDP_PSR_TP1_TIME_500US,
        _ => EDP_PSR_TP1_TIME_2500US,
    };
    value |= match config.tp2_tp3_wakeup_us {
        0 => EDP_PSR_TP2_TP3_TIME_0US,
        1..=100 => EDP_PSR_TP2_TP3_TIME_100US,
        101..=500 => EDP_PSR_TP2_TP3_TIME_500US,
        _ => EDP_PSR_TP2_TP3_TIME_2500US,
    };
    if config.tps3 {
        value |= EDP_PSR_TP_TP1_TP3;
    }
    value
}

/// `hsw_activate_psr1`'s value for display 14 (`link_standby` false).
pub fn psr1_ctl(config: &Psr1) -> u32 {
    let mut value = EDP_PSR_ENABLE;
    value |= config.idle_frames & EDP_PSR_IDLE_FRAMES_MASK;
    value |= EDP_PSR_MAX_SLEEP_TIME_MAX;
    value |= psr1_tp_time(config);
    value | EDP_PSR_CRC_ENABLE
}

/// `_psr_enable_sink`'s PSR1 `DP_PSR_EN_CFG` byte before `DP_PSR_ENABLE`:
/// CRC verification only (no link standby, no entry setup frames).
pub fn sink_cfg_psr1() -> u8 {
    DP_PSR_CRC_VERIFICATION
}

// ── The owner ─────────────────────────────────────────────────────

fn readable<M: MmioWindow + ?Sized>(regs: &M, register: u64) -> Result<u32, Refusal> {
    match regs.read32(register) {
        u32::MAX => Err(Refusal::Unavailable),
        value => Ok(value),
    }
}

/// `EDP_PSR_STATUS` state is idle (PSR1).
pub fn idle<M: MmioWindow + ?Sized>(regs: &M) -> Result<bool, Refusal> {
    Ok(readable(regs, PSR_STATUS)? & EDP_PSR_STATUS_STATE_MASK == 0)
}

/// `intel_de_wait_for_clear_ms(EDP_PSR_STATUS, STATE_MASK, timeout_ms)`.
pub fn wait_idle<M: MmioWindow + ?Sized>(regs: &M, timeout_ms: u64) -> Result<(), Refusal> {
    let mut error = None;
    let done = narf_scheduler::responsive_spin_until(
        || match idle(regs) {
            Ok(idle) => idle,
            Err(refusal) => {
                error = Some(refusal);
                true
            }
        },
        narf_time::Deadline::after_ms(timeout_ms),
    );
    match error {
        Some(refusal) => Err(refusal),
        None if done => Ok(()),
        None => Err(Refusal::ExitTimeout),
    }
}

/// The PSR1 owner on the KMS-owned Pipe-A eDP. It only ever programs what
/// it enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psr {
    config: Psr1,
    active: bool,
}

impl Psr {
    /// `intel_psr_enable_locked` for PSR1 up to (not including)
    /// `intel_psr_activate`: error check, sink, source. Activation is the
    /// caller's [`Psr::resume`] once its frame changes have latched. Every
    /// check precedes the first write; a sink conversation failure leaves
    /// the source untouched.
    pub fn enable<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
        regs: &M,
        aux: &mut A,
        config: Psr1,
    ) -> Result<Psr, Refusal> {
        if (readable(regs, PSR_CTL)? & EDP_PSR_ENABLE)
            | (readable(regs, PSR2_CTL)? & EDP_PSR2_ENABLE)
            != 0
        {
            return Err(Refusal::Inherited);
        }
        let ier = readable(regs, DE_MISC_IER)?;
        let imr = regs.read32(DE_MISC_IMR); // all-masked is a valid value
        if ier & !imr & GEN8_DE_EDP_PSR != 0 {
            return Err(Refusal::InterruptDelivery);
        }
        if readable(regs, PSR_IIR)? & TGL_PSR_ERROR != 0 {
            return Err(Refusal::SinkNotReliable);
        }
        let dcpr = readable(regs, CHICKEN_DCPR_1)?;
        // intel_psr_enable_sink → _psr_enable_sink, then DP_SET_POWER D0.
        let cfg = sink_cfg_psr1();
        let sink = write(aux, DP_PSR_EN_CFG, cfg)
            .and_then(|()| write(aux, DP_PSR_EN_CFG, cfg | DP_PSR_ENABLE))
            .and_then(|()| write(aux, DP_SET_POWER, DP_SET_POWER_D0));
        if let Err(error) = sink {
            let _ = write(aux, DP_PSR_EN_CFG, 0);
            return Err(Refusal::Aux(error));
        }
        // intel_psr_enable_source.
        regs.write32(PSR_DEBUG, PSR_DEBUG_MASK);
        let imr = regs.read32(PSR_IMR);
        regs.write32(PSR_IMR, (imr & !TGL_PSR_MASK) | !TGL_PSR_ERROR);
        // Wa_14015648006 (wm_optimization_wa).
        regs.write32(
            CHICKEN_DCPR_1,
            if config.wm_level_disabled {
                dcpr | LATENCY_REPORTING_REMOVED_PIPE_A
            } else {
                dcpr & !LATENCY_REPORTING_REMOVED_PIPE_A
            },
        );
        Ok(Psr {
            config,
            active: false,
        })
    }

    pub fn config(&self) -> Psr1 {
        self.config
    }

    /// `wm_optimization_wa` for a new `wm_level_disabled` while PSR is
    /// enabled: `intel_psr_pre_plane_update` calls it (setting
    /// `LATENCY_REPORTING_REMOVED`) before a state whose value is true,
    /// `intel_psr_post_plane_update` (clearing it) after one whose value
    /// is false. Only bit 23 changes.
    pub fn wm_optimization_wa<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        wm_level_disabled: bool,
    ) -> Result<(), Refusal> {
        let dcpr = readable(regs, CHICKEN_DCPR_1)?;
        regs.write32(
            CHICKEN_DCPR_1,
            if wm_level_disabled {
                dcpr | LATENCY_REPORTING_REMOVED_PIPE_A
            } else {
                dcpr & !LATENCY_REPORTING_REMOVED_PIPE_A
            },
        );
        self.config.wm_level_disabled = wm_level_disabled;
        Ok(())
    }
    /// `intel_dp->psr.active`.
    pub fn active(&self) -> bool {
        self.active
    }

    /// `hsw_activate_psr1`: RMW keeping only the context-restore bit.
    fn activate<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        let ctl = readable(regs, PSR_CTL)?;
        regs.write32(
            PSR_CTL,
            (ctl & EDP_PSR_RESTORE_PSR_ACTIVE_CTX) | psr1_ctl(&self.config),
        );
        self.active = true;
        Ok(())
    }

    /// `intel_psr_exit` for PSR1.
    fn exit<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        if !self.active {
            return Ok(());
        }
        let ctl = readable(regs, PSR_CTL)?;
        regs.write32(PSR_CTL, ctl & !EDP_PSR_ENABLE);
        self.active = false;
        Ok(())
    }

    /// `TRANS_PSR_IIR & TGL_PSR_ERROR`, polled.
    fn error<M: MmioWindow + ?Sized>(regs: &M) -> Result<(), Refusal> {
        if readable(regs, PSR_IIR)? & TGL_PSR_ERROR != 0 {
            Err(Refusal::SinkNotReliable)
        } else {
            Ok(())
        }
    }

    /// `intel_psr_pause`'s exit (frontbuffer invalidate before any frame
    /// change). The caller then waits for [`idle`] within
    /// [`PSR_EXIT_TIMEOUT_MS`] (`intel_psr_wait_exit_locked`). A latched
    /// error is returned before any write; the caller then disables.
    pub fn pause<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        Self::error(regs)?;
        self.exit(regs)
    }

    /// `intel_psr_resume` / `intel_psr_work` after the frame change
    /// latched: re-activate only from idle. `Ok(false)` leaves PSR
    /// inactive until the next re-arm (Linux keeps it disabled until the
    /// next cycle when idle is not reached).
    pub fn resume<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<bool, Refusal> {
        if self.active {
            return Ok(true);
        }
        Self::error(regs)?;
        if !idle(regs)? {
            return Ok(false);
        }
        self.activate(regs)?;
        Ok(true)
    }

    /// `intel_psr_disable_locked` for PSR1: exit, wait, undo
    /// Wa_14015648006, then clear the sink. Every step runs; the first
    /// failure is returned. `wake` adds `intel_psr_handle_irq`'s
    /// `DP_SET_POWER_D0`.
    pub fn disable<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
        &mut self,
        regs: &M,
        aux: &mut A,
        timeout_ms: u64,
        wake: bool,
    ) -> Result<(), Refusal> {
        let mut first = self.exit(regs).err();
        if let Err(refusal) = wait_idle(regs, timeout_ms) {
            first.get_or_insert(refusal);
        }
        let dcpr = regs.read32(CHICKEN_DCPR_1);
        if dcpr != u32::MAX {
            regs.write32(CHICKEN_DCPR_1, dcpr & !LATENCY_REPORTING_REMOVED_PIPE_A);
        }
        if let Err(error) = write(aux, DP_PSR_EN_CFG, 0) {
            first.get_or_insert(Refusal::Aux(error));
        }
        if wake {
            let _ = write(aux, DP_SET_POWER, DP_SET_POWER_D0);
        }
        self.active = false;
        first.map_or(Ok(()), Err)
    }
}

// ── Watermark-lane input ──────────────────────────────────────────

/// A Wa_14015648006 input provider: Pipe-A `wm_level_disabled`, or `None`
/// while the watermark lane cannot answer. Production registers
/// [`crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled`] at display-14
/// KMS install.
pub type WmLevelProvider = fn() -> Option<bool>;

static WM_LEVEL_DISABLED: IrqSafeSpinLock<Option<WmLevelProvider>> = IrqSafeSpinLock::new(None);

/// Register (or clear) the Wa_14015648006 input: the Pipe-A
/// `wm_level_disabled` that `skl_wm_check_vblank` computes. Returns the
/// previous provider. The provider must not touch registers or block.
pub fn register_wm_level_disabled(provider: Option<WmLevelProvider>) -> Option<WmLevelProvider> {
    core::mem::replace(&mut *WM_LEVEL_DISABLED.lock(), provider)
}

/// The registered `wm_level_disabled`; `None` when no provider exists.
pub fn wm_level_disabled() -> Option<bool> {
    let provider = *WM_LEVEL_DISABLED.lock();
    provider.and_then(|provider| provider())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_psr_tests.rs"]
mod tests;
