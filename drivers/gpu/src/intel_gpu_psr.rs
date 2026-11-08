//! Display-14 Panel Self Refresh (PSR1, and PSR2 with selective fetch) on
//! the KMS-owned Pipe-A eDP.
//!
//! Pinned source: Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! `i915/display/intel_psr.c`, `intel_psr_regs.h`, `intel_alpm.c`,
//! `intel_fbc.c`, `intel_dp.c`, `intel_dp_aux.c`, `intel_quirks.c`,
//! `intel_crtc.c`, `intel_display.c`, `intel_bios.c`,
//! `intel_display_params.h`, `intel_display_device.c`, `intel_vdsc_regs.h`,
//! `skl_universal_plane.c` / `_regs.h`, `intel_cursor.c` / `_regs.h`,
//! `skl_watermark.c`, `i915_reg.h`, `drm/drm_damage_helper.c`,
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
//!   frames). Then selective update ([`compute_psr2`], from
//!   `intel_sel_update_config_valid`): the sink's SU support, the display
//!   12–14 bpp limit, `intel_alpm_compute_params` (with `QUIRK_FW_SYNC_LEN`),
//!   the vblank fit, the SDP prior-scanline indication, SU granularity and
//!   `intel_psr_compute_config_late`. A refusal ([`Psr2Refusal`]) falls back
//!   to PSR1. Panel Replay is not offered (`PANEL_REPLAY_CAP` is never read).
//! - PSR2 (`intel_alpm_enable_sink`, `_psr_enable_sink`,
//!   `intel_psr_enable_source` with Wa_16014451276 and Wa_16012604467 on
//!   display 14.00 A0..A3, `hsw_activate_psr2`) and selective fetch per
//!   commit ([`sel_fetch_update`] from `intel_psr2_sel_fetch_update` and
//!   `psr2_man_trk_ctl_calc`; `PSR2_MAN_TRK_CTL`, `SEL_FETCH_PLANE_*` for the
//!   primary and `SEL_FETCH_CUR_CTL`). Display 14 has no PSR2 HW tracking,
//!   no early transport and no DC3CO (its exit line is disabled in Linux).
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

// ── PSR2 / selective fetch (display 14, transcoder A, pipe A) ─────

/// `EDP_PSR2_STATUS_STATE_DEEP_SLEEP` (`_psr2_ready_for_pipe_update_locked`
/// waits for this bit pattern to clear).
pub const EDP_PSR2_STATUS_STATE_DEEP_SLEEP: u32 = 8 << 28;
/// `PSR2_MAN_TRK_CTL(TRANSCODER_A)`.
pub const PSR2_MAN_TRK_CTL: u64 = 0x60910;
/// `ADLP_PSR2_MAN_TRK_CTL_SF_PARTIAL_FRAME_UPDATE` (display 14 has no
/// separate `PSR2_MAN_TRK_CTL_ENABLE`: `man_trk_ctl_enable_bit_get` is 0).
pub const MAN_TRK_SF_PARTIAL_FRAME_UPDATE: u32 = 1 << 31;
/// `ADLP_PSR2_MAN_TRK_CTL_SF_SINGLE_FULL_FRAME`.
pub const MAN_TRK_SF_SINGLE_FULL_FRAME: u32 = 1 << 14;
/// `ADLP_PSR2_MAN_TRK_CTL_SF_CONTINUOS_FULL_FRAME`.
pub const MAN_TRK_SF_CONTINUOUS_FULL_FRAME: u32 = 1 << 13;
/// `ADLP_PSR2_MAN_TRK_CTL_SU_REGION_START_ADDR_MASK` (28:16) and
/// `..._END_ADDR_MASK` (12:0) are both 13 bits wide.
const MAN_TRK_SU_REGION_ADDR_MASK: u32 = 0x1fff;
/// `TGL_EDP_PSR2_BLOCK_COUNT_NUM_3` (`..._NUM_2` is 0).
pub const EDP_PSR2_BLOCK_COUNT_NUM_3: u32 = 1 << 28;
/// `EDP_PSR2_SU_SDP_SCANLINE` (display 13+).
pub const EDP_PSR2_SU_SDP_SCANLINE: u32 = 1 << 25;
/// `TGL_EDP_PSR2_IO_BUFFER_WAKE_MIN_LINES` / `TGL_EDP_PSR2_FAST_WAKE_MIN_LINES`.
const TGL_EDP_PSR2_WAKE_MIN_LINES: u32 = 5;
/// `EDP_PSR2_TP2_TIME_500us`.
pub const EDP_PSR2_TP2_TIME_500US: u32 = 0;
/// `EDP_PSR2_TP2_TIME_100us`.
pub const EDP_PSR2_TP2_TIME_100US: u32 = 1 << 8;
/// `EDP_PSR2_TP2_TIME_2500us`.
pub const EDP_PSR2_TP2_TIME_2500US: u32 = 2 << 8;
/// `EDP_PSR2_TP2_TIME_50us`.
pub const EDP_PSR2_TP2_TIME_50US: u32 = 3 << 8;
/// `SEL_FETCH_PLANE_CTL(PIPE_A, PLANE_1)`.
pub const SEL_FETCH_PLANE_CTL: u64 = 0x70890;
/// `SEL_FETCH_PLANE_POS(PIPE_A, PLANE_1)`.
pub const SEL_FETCH_PLANE_POS: u64 = 0x70894;
/// `SEL_FETCH_PLANE_SIZE(PIPE_A, PLANE_1)`.
pub const SEL_FETCH_PLANE_SIZE: u64 = 0x70898;
/// `SEL_FETCH_PLANE_OFFSET(PIPE_A, PLANE_1)`.
pub const SEL_FETCH_PLANE_OFFSET: u64 = 0x7089c;
/// `SEL_FETCH_PLANE_CTL_ENABLE`.
pub const SEL_FETCH_PLANE_CTL_ENABLE: u32 = 1 << 31;
/// `SEL_FETCH_CUR_CTL(PIPE_A)`.
pub const SEL_FETCH_CUR_CTL: u64 = 0x70880;
/// `CURCNTR(PIPE_A)`.
pub const CURCNTR: u64 = 0x70080;
/// `CURBASE(PIPE_A)`.
pub const CURBASE: u64 = 0x70084;
/// `CURPOS(PIPE_A)`.
pub const CURPOS: u64 = 0x70088;
/// `CURSURFLIVE(PIPE_A)`: a write is the PSR "Frame Change" event
/// (`intel_psr_trigger_frame_change_event`, Display WA #0884).
pub const CURSURFLIVE: u64 = 0x700ac;
/// `MCURSOR_MODE_MASK`.
pub const MCURSOR_MODE_MASK: u32 = 0x27;
/// `MCURSOR_MODE_64_ARGB_AX`.
pub const MCURSOR_MODE_64_ARGB_AX: u32 = 0x27;
/// `CHICKEN_TRANS(TRANSCODER_A)` on display 14 (`_MTL_CHICKEN_TRANS_A`).
pub const MTL_CHICKEN_TRANS_A: u64 = 0x604e0;
/// `ADLP_1_BASED_X_GRANULARITY`.
pub const ADLP_1_BASED_X_GRANULARITY: u32 = 1 << 18;
/// `MTL_CLKGATE_DIS_TRANS(TRANSCODER_A)`.
pub const MTL_CLKGATE_DIS_TRANS_A: u64 = 0x604e8;
/// `MTL_CLKGATE_DIS_TRANS_DMASC_GATING_DIS`.
pub const MTL_CLKGATE_DIS_TRANS_DMASC_GATING_DIS: u32 = 1 << 7;
/// `GMD_ID_DISPLAY`: architecture 31:22, release 21:14, step 5:0.
pub const GMD_ID_DISPLAY: u64 = 0x510a0;
/// `PIPE_MISC(PIPE_A)`; `PIPE_MISC_BPC_MASK` is 7:5.
pub const PIPE_MISC_A: u64 = 0x70030;
/// `TRANS_DDI_FUNC_CTL(TRANSCODER_A)`; `DDI_PORT_WIDTH_MASK` is 3:1.
pub const TRANS_DDI_FUNC_CTL_A: u64 = 0x60400;
/// `TRANS_SET_CONTEXT_LATENCY(TRANSCODER_A)` (15:0).
pub const TRANS_SET_CONTEXT_LATENCY_A: u64 = 0x6007c;
/// `ICL_PIPE_DSS_CTL1(PIPE_A)`.
pub const PIPE_DSS_CTL1_A: u64 = 0x78000;
/// `ICL_PIPE_DSS_CTL2(PIPE_A)`.
pub const PIPE_DSS_CTL2_A: u64 = 0x78004;
/// `SPLITTER_ENABLE | JOINER_ENABLE | BIG_JOINER_ENABLE |
/// ULTRA_JOINER_ENABLE | UNCOMPRESSED_JOINER_PRIMARY | _SECONDARY`.
const DSS_CTL1_SPLIT: u32 = (1 << 31) | (1 << 30) | (1 << 29) | (1 << 23) | (1 << 21) | (1 << 20);
/// `VDSC0_ENABLE | VDSC2_ENABLE | VDSC1_ENABLE`.
const DSS_CTL2_VDSC: u32 = (1 << 31) | (1 << 30) | (1 << 15);
/// `SKL_PS_CTRL(PIPE_A, 0)` and `(PIPE_A, 1)`.
pub const PS_CTRL_A: [u64; 2] = [0x68180, 0x68280];
/// `PS_SCALER_EN`.
pub const PS_SCALER_EN: u32 = 1 << 31;
/// `DP_SUPPORTED_LINK_RATES` (eDP 1.4, eight LE16 entries in 200 kHz).
pub const DP_SUPPORTED_LINK_RATES: u32 = 0x010;
/// `DP_LINK_BW_SET`.
pub const DP_LINK_BW_SET: u32 = 0x100;
/// `DP_LINK_RATE_SET` (eDP 1.4); `DP_LINK_RATE_SET_MASK` is 2:0.
pub const DP_LINK_RATE_SET: u32 = 0x115;
/// `DP_RECEIVER_ALPM_CONFIG`.
pub const DP_RECEIVER_ALPM_CONFIG: u32 = 0x116;
/// `DP_ALPM_ENABLE`.
pub const DP_ALPM_ENABLE: u8 = 1 << 0;
/// `DP_ALPM_LOCK_ERROR_IRQ_HPD_ENABLE`.
pub const DP_ALPM_LOCK_ERROR_IRQ_HPD_ENABLE: u8 = 1 << 1;
/// `DP_PSR_SU_REGION_SCANLINE_CAPTURE`.
pub const DP_PSR_SU_REGION_SCANLINE_CAPTURE: u8 = 1 << 4;
/// `DP_PSR_IRQ_HPD_WITH_CRC_ERRORS`.
pub const DP_PSR_IRQ_HPD_WITH_CRC_ERRORS: u8 = 1 << 5;
/// `DP_PSR_ENABLE_PSR2`.
pub const DP_PSR_ENABLE_PSR2: u8 = 1 << 6;
/// `DP_EDP_14b`.
pub const DP_EDP_14B: u8 = 0x05;
/// `intel_dpcd_quirks[]`'s `QUIRK_FW_SYNC_LEN` (Dell Precision 5490):
/// PCI device, subsystem vendor and device, and sink OUI.
pub const FW_SYNC_QUIRK: (u16, u16, u16, [u8; 3]) = (0x7d55, 0x1028, 0x0cc7, [0x38, 0xec, 0x11]);

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
    /// VRR is enabled on the CRTC and the timing generator runs at
    /// a variable rate (Linux `intel_psr_compute_config`: "Current
    /// PSR panels don't work reliably with VRR enabled. So if VRR
    /// is enabled, do not enable PSR", relaxed upstream to allow
    /// PSR with the fixed-RR VRR TG only). Deliberately NOT
    /// latched: VRR can toggle off, and the next latch must
    /// re-evaluate and re-qualify PSR — see `psr_after_latch`.
    VrrEnabled,
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

// ── PSR2 qualification (intel_sel_update_config_valid) ────────────

/// Why selective update (PSR2) is not offered; PSR1 runs instead. Like
/// Linux's `has_sel_update` it is decided per enable, so every refusal is
/// retried at the next qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Psr2Refusal {
    /// VRR is enabled on the CRTC and the timing generator runs at
    /// a variable rate (Linux `intel_psr_compute_config`, fixed-RR
    /// TG relaxation): PSR2 is refused before any sink fact is
    /// consulted. Set by the caller from `VRR_STATE` via
    /// [`Psr2Source::vrr_excludes_psr`].
    VrrEnabled,
    /// `psr_caps.su_support` is false (`_psr_init_dpcd`): PSR version 3,
    /// the Y-coordinate requirement and AUX-wake ALPM are not all present.
    NoSinkSu,
    /// A source or link fact could not be read: a register read all-ones,
    /// the display IP is not 14.00, the PCI identity behind
    /// `QUIRK_FW_SYNC_LEN` is unknown, or the sink's link setting is.
    Unknown,
    /// DSC, a joiner or the MSO splitter is engaged on Pipe A. Linux
    /// aligns the SU area to the DSC slice height and applies
    /// Wa_14014971492 under the splitter; this driver models neither.
    StreamSplit,
    /// `pipe_bpp` above 30, the display 12–14 limit.
    PipeBpp,
    /// `intel_alpm_compute_params`: an IO or fast wake time above 12 lines.
    WakeTime,
    /// The PSR2 block-count lines do not fit the vblank
    /// (`wake_lines_fit_into_vblank`, `intel_psr_compute_config_late`).
    Vblank,
    /// `_compute_psr2_sdp_prior_scanline_indication`: the SDP does not fit
    /// hblank and the sink is older than eDP 1.4b.
    SdpPriorScanline,
    /// `psr2_granularity_check`.
    Granularity,
}

/// The source and link facts PSR2 qualification reads from the live Pipe A
/// (Linux takes them from the computed crtc state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psr2Source {
    /// The display 14.00 stepping (`GMD_ID_DISPLAY` 5:0; 0..3 is A0..A3,
    /// 4 is B0, as `STEP_A0 + gmd_id.step`).
    pub step: u8,
    /// `pipe_bpp` (`PIPE_MISC` BPC × 3).
    pub pipe_bpp: u32,
    /// `lane_count` (`TRANS_DDI_FUNC_CTL` port width + 1).
    pub lane_count: u32,
    /// `port_clock`: the link rate in 10 kbit/s (270000 for HBR).
    pub port_clock: u32,
    /// The live `TRANS_SET_CONTEXT_LATENCY`.
    pub set_context_latency: u32,
    /// DSC, a joiner or the splitter is engaged ([`Psr2Refusal::StreamSplit`]).
    pub stream_split: bool,
    /// `QUIRK_FW_SYNC_LEN` applies (`intel_dp_aux_fw_sync_len` + 2).
    pub fw_sync_quirk: bool,
    /// VRR is enabled on the CRTC and the timing generator runs at
    /// a variable rate, so PSR is excluded (Linux
    /// `intel_psr_compute_config` + the fixed-RR TG relaxation).
    /// Read from `VRR_STATE` by the caller — this struct stays
    /// platform-neutral — and refused as
    /// [`Psr2Refusal::VrrEnabled`] by [`compute_psr2`].
    pub vrr_excludes_psr: bool,
}

/// A qualified PSR2 configuration with selective fetch (display 14 has no
/// PSR2 HW tracking, so `enable_psr2_sel_fetch` is the only SU mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psr2 {
    /// `alpm_state.io_wake_lines`.
    pub io_wake_lines: u8,
    /// `alpm_state.fast_wake_lines`.
    pub fast_wake_lines: u8,
    /// `req_psr2_sdp_prior_scanline`.
    pub req_sdp_prior_scanline: bool,
    /// `su_y_granularity` (display 14 takes the sink's).
    pub su_y_granularity: u16,
    /// `frames_before_su_entry` (no entry setup frames below display 20).
    pub frames_before_su: u8,
    /// The VBT's `psr.psr2_tp2_tp3_wakeup_time_us`.
    pub tp2_wakeup_us: u32,
    /// Display 14.00 A0..A3 (`IS_DISPLAY_VERx100_STEP(1400, A0, B0)`):
    /// Wa_16014451276 and Wa_16012604467.
    pub a0_to_b0: bool,
    /// The pipe source width (`pipe_src`).
    pub width: u16,
    /// The pipe source height.
    pub height: u16,
}

/// `psr2_block_count_lines`.
pub fn psr2_block_count_lines(io_wake_lines: u8, fast_wake_lines: u8) -> u32 {
    if io_wake_lines < 9 && fast_wake_lines < 9 {
        8
    } else {
        12
    }
}

/// `intel_sel_update_config_valid` for display 14 eDP PSR, after
/// [`compute_psr1`] succeeded: `intel_psr2_config_valid` (sink SU, the
/// display 12–14 bpp limit, `alpm_config_valid`), then
/// `_compute_psr2_sdp_prior_scanline_indication` and
/// `psr2_granularity_check`, then `intel_psr_compute_config_late`'s
/// vblank check. Defaults hold: `enable_psr` -1 and
/// `enable_psr2_sel_fetch` true, `psr_safest_params` false, no pipe CRC,
/// no early transport below display 20, and no DC3CO (its exit line is
/// disabled). VRR is refused up front (`source.vrr_excludes_psr`):
/// with VRR the set-context-latency the late check subtracts is the
/// VRR-TG value (at least 1, wa_14015401596), not the no-VRR 0 the
/// old doc assumed.
pub(crate) fn compute_psr2(
    sink: &Sink,
    timing: &crate::intel_gpu_dsb::Timing,
    panel: &crate::intel_gpu_vbt::PsrPanel,
    source: &Psr2Source,
) -> Result<Psr2, Psr2Refusal> {
    // Linux `intel_psr_compute_config` (fixed-RR TG relaxation):
    // PSR panels don't work reliably with VRR enabled, so refuse
    // before any sink fact is consulted.
    if source.vrr_excludes_psr {
        return Err(Psr2Refusal::VrrEnabled);
    }
    if !sink.su_support() {
        return Err(Psr2Refusal::NoSinkSu);
    }
    // transcoder_has_psr2: transcoder A on display 14. DSC is allowed with
    // PSR2 on display 14, but its slice alignment is not modelled.
    if source.stream_split {
        return Err(Psr2Refusal::StreamSplit);
    }
    if source.pipe_bpp > 30 {
        return Err(Psr2Refusal::PipeBpp);
    }
    // intel_alpm_compute_params: tfw_exit_latency 20, phy_wake 4, preamble
    // 8, precharge intel_dp_aux_fw_sync_len() - preamble, and the TGL+
    // 10 µs IO buffer wake.
    let precharge = 10 + if source.fw_sync_quirk { 2 } else { 0 };
    let io_time = precharge.max(10) + 8 + 4 + 20;
    let fast_time = precharge + 8 + 4 + 20;
    let io = usecs_to_scanlines(timing, io_time);
    let fast = usecs_to_scanlines(timing, fast_time);
    if io > 12 || fast > 12 {
        return Err(Psr2Refusal::WakeTime);
    }
    // According to Bspec the lower limit is 7 lines.
    let io_wake_lines = io.max(7) as u8;
    let fast_wake_lines = fast.max(7) as u8;
    let wake = psr2_block_count_lines(io_wake_lines, fast_wake_lines);
    // wake_lines_fit_into_vblank before req_psr2_sdp_prior_scanline is
    // known: crtc_vblank_end - crtc_vblank_start, less the 0 SCL.
    let vblank = u32::from(timing.vtotal).saturating_sub(u32::from(timing.height));
    if vblank < wake {
        return Err(Psr2Refusal::Vblank);
    }
    // _compute_psr2_sdp_prior_scanline_indication, in Linux's u32
    // arithmetic (a hblank shorter than the request wraps and passes).
    if source.lane_count == 0 || source.port_clock < 1000 || timing.clock == 0 {
        return Err(Psr2Refusal::Unknown);
    }
    let hblank_total = u64::from(timing.htotal.saturating_sub(timing.width));
    let hblank_ns = (1_000_000 * hblank_total / u64::from(timing.clock)) as u32;
    let req_ns = ((60 / source.lane_count) + 11) * 1000 / (source.port_clock / 1000);
    let req_sdp_prior_scanline = if hblank_ns.wrapping_sub(req_ns) > 100 {
        false
    } else if sink.edp[0] < DP_EDP_14B {
        return Err(Psr2Refusal::SdpPriorScanline);
    } else {
        true
    };
    // psr2_granularity_check: PSR2 HW sends full lines; selective fetch on
    // display 14 has 1-line granularity, so the sink's Y granularity holds.
    let (hdisplay, vdisplay) = (u32::from(timing.width), u32::from(timing.height));
    let y = u32::from(sink.su_y_granularity);
    if u32::from(sink.su_w_granularity) == 0
        || hdisplay % u32::from(sink.su_w_granularity) != 0
        || y == 0
        || vdisplay % y != 0
    {
        return Err(Psr2Refusal::Granularity);
    }
    // intel_psr_compute_config_late: intel_crtc_vblank_length is
    // crtc_vtotal - crtc_vblank_start, the start moved by the set context
    // latency (Linux computes 0; the live value is taken here).
    let mut late = vblank.saturating_sub(source.set_context_latency);
    if req_sdp_prior_scanline {
        late = late.saturating_sub(1);
    }
    if late < wake {
        return Err(Psr2Refusal::Vblank);
    }
    Ok(Psr2 {
        io_wake_lines,
        fast_wake_lines,
        req_sdp_prior_scanline,
        su_y_granularity: y as u16,
        frames_before_su: (sink.sync_latency + 1).max(2),
        tp2_wakeup_us: panel.table.map_or(0, |t| t.psr2_tp2_tp3_wakeup_time_us),
        a0_to_b0: source.step < 4,
        width: timing.width,
        height: timing.height,
    })
}

/// `intel_psr2_get_tp_time` (`psr_safest_params` false).
pub fn psr2_tp_time(tp2_wakeup_us: u32) -> u32 {
    match tp2_wakeup_us {
        0..=50 => EDP_PSR2_TP2_TIME_50US,
        51..=100 => EDP_PSR2_TP2_TIME_100US,
        101..=500 => EDP_PSR2_TP2_TIME_500US,
        _ => EDP_PSR2_TP2_TIME_2500US,
    }
}

/// `hsw_activate_psr2`'s `EDP_PSR2_CTL` for display 14: enable, idle
/// frames (`psr_compute_idle_frames`), frames before SU, the PSR2 TP2
/// time, the TGL block count, IO buffer and fast wake lines, and the SU
/// SDP scanline indication. Display 14 sets neither `EDP_SU_TRACK_ENABLE`
/// nor `EDP_Y_COORDINATE_ENABLE`.
pub fn psr2_ctl(config: &Psr1, su: &Psr2) -> u32 {
    let mut value = EDP_PSR2_ENABLE;
    value |= config.idle_frames & 0xf;
    value |= (u32::from(su.frames_before_su) & 0xf) << 4;
    value |= psr2_tp_time(su.tp2_wakeup_us);
    if psr2_block_count_lines(su.io_wake_lines, su.fast_wake_lines) / 4 > 2 {
        value |= EDP_PSR2_BLOCK_COUNT_NUM_3;
    }
    value |= ((u32::from(su.io_wake_lines) - TGL_EDP_PSR2_WAKE_MIN_LINES) & 7) << 13;
    value |= ((u32::from(su.fast_wake_lines) - TGL_EDP_PSR2_WAKE_MIN_LINES) & 7) << 10;
    if su.req_sdp_prior_scanline {
        value |= EDP_PSR2_SU_SDP_SCANLINE;
    }
    value
}

/// `_psr_enable_sink`'s PSR2 `DP_PSR_EN_CFG` byte before `DP_PSR_ENABLE`.
pub fn sink_cfg_psr2(su: &Psr2) -> u8 {
    DP_PSR_ENABLE_PSR2
        | DP_PSR_IRQ_HPD_WITH_CRC_ERRORS
        | if su.req_sdp_prior_scanline {
            DP_PSR_SU_REGION_SCANLINE_CAPTURE
        } else {
            0
        }
}

/// `intel_alpm_enable_sink` for PSR2 on eDP (AUX-wake ALPM).
pub const SINK_ALPM_PSR2: u8 = DP_ALPM_ENABLE | DP_ALPM_LOCK_ERROR_IRQ_HPD_ENABLE;

/// The link rate the sink was trained at, in `port_clock` units: a
/// `DP_LINK_BW_SET` code times 27000, or (eDP 1.4 rate select) the
/// `DP_SUPPORTED_LINK_RATES` entry `DP_LINK_RATE_SET` names, times 20
/// (`intel_edp_init_dpcd`'s `(val * 200) / 10`). `None` when unreadable or
/// unset.
pub fn sink_link_rate<A: AuxChannel + ?Sized>(aux: &mut A) -> Option<u32> {
    let mut bw = [0u8; 1];
    read(aux, DP_LINK_BW_SET, &mut bw).ok()?;
    if bw[0] != 0 {
        return Some(u32::from(bw[0]) * 27000);
    }
    let mut index = [0u8; 1];
    read(aux, DP_LINK_RATE_SET, &mut index).ok()?;
    let mut rate = [0u8; 2];
    read(
        aux,
        DP_SUPPORTED_LINK_RATES + 2 * u32::from(index[0] & 7),
        &mut rate,
    )
    .ok()?;
    match u32::from(u16::from_le_bytes(rate)) * 20 {
        0 => None,
        rate => Some(rate),
    }
}

/// Read the live Pipe-A facts [`compute_psr2`] needs. `pci` is the device
/// and subsystem identity behind `QUIRK_FW_SYNC_LEN`.
/// `vrr_excludes_psr` is the caller's VRR fact (read from
/// `VRR_STATE`): the register/aux reads below cannot know it, and
/// [`compute_psr2`] refuses on it before any of them is used.
pub fn psr2_source<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
    regs: &M,
    aux: &mut A,
    sink: &Sink,
    pci: Option<(u16, u16, u16)>,
    vrr_excludes_psr: bool,
) -> Result<Psr2Source, Psr2Refusal> {
    let get = |register| match regs.read32(register) {
        u32::MAX => Err(Psr2Refusal::Unknown),
        value => Ok(value),
    };
    let gmd = get(GMD_ID_DISPLAY)?;
    if gmd >> 22 != 14 || (gmd >> 14) & 0xff != 0 {
        return Err(Psr2Refusal::Unknown);
    }
    // bdw_get_pipe_misc_bpp for display 13+.
    let pipe_bpp = match (get(PIPE_MISC_A)? >> 5) & 7 {
        0 => 24,
        1 => 30,
        2 => 18,
        4 => 36,
        _ => return Err(Psr2Refusal::Unknown),
    };
    let lane_count = ((get(TRANS_DDI_FUNC_CTL_A)? >> 1) & 7) + 1;
    let set_context_latency = get(TRANS_SET_CONTEXT_LATENCY_A)? & 0xffff;
    let stream_split =
        get(PIPE_DSS_CTL1_A)? & DSS_CTL1_SPLIT != 0 || get(PIPE_DSS_CTL2_A)? & DSS_CTL2_VDSC != 0;
    let (device, vendor, subsystem) = pci.ok_or(Psr2Refusal::Unknown)?;
    let (q_device, q_vendor, q_subsystem, q_oui) = FW_SYNC_QUIRK;
    let fw_sync_quirk =
        (device, vendor, subsystem) == (q_device, q_vendor, q_subsystem) && sink.oui == q_oui;
    let port_clock = sink_link_rate(aux).ok_or(Psr2Refusal::Unknown)?;
    Ok(Psr2Source {
        step: (gmd & 0x3f) as u8,
        pipe_bpp,
        lane_count,
        port_clock,
        set_context_latency,
        stream_split,
        fw_sync_quirk,
        vrr_excludes_psr,
    })
}

// ── Selective fetch (intel_psr2_sel_fetch_update) ─────────────────

pub use crate::drm::fb_cmd::{Damage, Rect};

/// A plane's `psr2_sel_fetch_area` as plane-relative rows `y1..y2`;
/// `None` is Linux's `{-1, -1}`.
pub type Area = Option<(i32, i32)>;

fn area_height(area: Area) -> i32 {
    area.map_or(0, |(y1, y2)| y2 - y1)
}

/// The cursor plane on Pipe A as selective fetch sees it: visible, with
/// its unclipped `uapi.dst` and `CURCNTR` (`plane_state->ctl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorPlane {
    pub dst: Rect,
    pub ctl: u32,
}

impl CursorPlane {
    /// The visible Pipe-A cursor from `CURCNTR` and `CURPOS`
    /// (`intel_cursor_position`'s sign-magnitude encoding). The KMS cursor
    /// is 64x64 ARGB; any other enabled mode gets an empty destination,
    /// for which selective fetch takes a full update.
    pub fn read<M: MmioWindow + ?Sized>(regs: &M) -> Result<Option<Self>, Refusal> {
        let ctl = readable(regs, CURCNTR)?;
        if ctl & MCURSOR_MODE_MASK == 0 {
            return Ok(None);
        }
        let pos = readable(regs, CURPOS)?;
        let coord = |magnitude: u32, negative: bool| {
            if negative {
                -(magnitude as i32)
            } else {
                magnitude as i32
            }
        };
        let x = coord(pos & 0x7fff, pos & (1 << 15) != 0);
        let y = coord((pos >> 16) & 0x7fff, pos & (1 << 31) != 0);
        let size = if ctl & MCURSOR_MODE_MASK == MCURSOR_MODE_64_ARGB_AX {
            64
        } else {
            0
        };
        Ok(Some(Self {
            dst: Rect::new(x, y, x + size, y + size),
            ctl,
        }))
    }
    /// `psr2_sel_fetch_plane_state_supported`: no negative position (a
    /// cursor has no scaler and no rotation here).
    fn supported(&self) -> bool {
        self.dst.x1 >= 0 && self.dst.y1 >= 0
    }
}

/// One commit's selective-fetch input for the fixed full-screen primary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuCommit<'a> {
    /// The primary's FB_DAMAGE_CLIPS (or DIRTYFB clips).
    pub damage: &'a Damage,
    /// The primary's previous framebuffer source.
    pub old_src: Rect,
    /// The primary's new framebuffer source.
    pub src: Rect,
    /// `psr2_sel_fetch_pipe_state_supported`: no pipe or plane scaler is
    /// engaged (there are no async flips here).
    pub pipe_supported: bool,
    /// The visible cursor on the pipe, if any.
    pub cursor: Option<CursorPlane>,
}

/// What one commit programs (`intel_psr2_sel_fetch_update`,
/// `psr2_man_trk_ctl_calc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelFetch {
    /// The SU area could not be used: continuous full frame.
    pub full_update: bool,
    /// `psr2_su_area` rows after alignment (`-1, -1` when unset).
    pub su: (i32, i32),
    /// `psr2_man_track_ctl`.
    pub man_trk_ctl: u32,
    /// The primary's `psr2_sel_fetch_area`. The primary is always in the
    /// commit; a full update keeps its previous area.
    pub primary: Area,
    /// The cursor's new area and `CURCNTR` when the cursor joined the
    /// commit's `update_planes`.
    pub cursor: Option<(Area, u32)>,
}

/// `psr2_man_trk_ctl_calc` for display 14 (ADL-P layout, no enable bit;
/// SF partial frame update is set even for a full update).
pub fn man_trk_ctl(full_update: bool, su: (i32, i32)) -> u32 {
    let value = MAN_TRK_SF_PARTIAL_FRAME_UPDATE;
    if full_update {
        return value | MAN_TRK_SF_CONTINUOUS_FULL_FRAME;
    }
    value
        | ((su.0 as u32 & MAN_TRK_SU_REGION_ADDR_MASK) << 16)
        | ((su.1 - 1) as u32 & MAN_TRK_SU_REGION_ADDR_MASK)
}

/// `intel_psr_configure_full_frame_update` below display 20: single and
/// continuous full frame, written before `intel_psr_force_update` by a
/// frontbuffer flush. Every frame change here is a commit, so the driver
/// has no frontbuffer origin and never writes it; it is the reference
/// value for that path.
pub fn man_trk_ctl_full_frame_update() -> u32 {
    MAN_TRK_SF_PARTIAL_FRAME_UPDATE
        | MAN_TRK_SF_SINGLE_FULL_FRAME
        | MAN_TRK_SF_CONTINUOUS_FULL_FRAME
}

/// `clip_area_update`.
fn clip_area_update(su: &mut Option<(i32, i32)>, damage: &Rect, pipe_src: &Rect) {
    let mut damage = *damage;
    if !damage.intersect(pipe_src) {
        return;
    }
    *su = Some(match *su {
        None => (damage.y1, damage.y2),
        Some((y1, y2)) => (y1.min(damage.y1), y2.max(damage.y2)),
    });
}

/// `intel_psr2_sel_fetch_update` for the fixed full-screen primary
/// (`dst` = `pipe_src` = `0, 0, width, height`, always visible, alpha and
/// position unchanged) on a PSR2 with `su`, given the planes' previous
/// areas `(primary, cursor)`. No early transport (display < 20), no DSC,
/// and Wa_14014971492 needs the splitter, which qualification refuses.
pub fn sel_fetch_update(su: &Psr2, commit: &SuCommit<'_>, previous: (Area, Area)) -> SelFetch {
    let pipe_src = Rect::new(0, 0, i32::from(su.width), i32::from(su.height));
    let dst = pipe_src;
    let mut result = SelFetch {
        full_update: true,
        su: (-1, -1),
        man_trk_ctl: 0,
        primary: previous.0,
        cursor: None,
    };
    let mut area = None;
    if commit.pipe_supported {
        // The first loop sees only the planes in the commit: the primary,
        // through drm_atomic_helper_damage_merged.
        if let Some(mut damaged) = commit.damage.merged(&commit.old_src, &commit.src) {
            damaged.translate(dst.x1 - commit.src.x1, dst.y1 - commit.src.y1);
            clip_area_update(&mut area, &damaged, &pipe_src);
        }
    }
    // "Selective fetch area calculation failed" (or an unsupported pipe):
    // a full update that skips the plane loop.
    if let Some((mut y1, mut y2)) = area {
        result.full_update = false;
        // intel_psr2_sel_fetch_pipe_alignment without DSC.
        let g = i32::from(su.su_y_granularity);
        y1 -= y1 % g;
        if y2 % g != 0 {
            y2 = (y2 / g + 1) * g;
        }
        result.su = (y1, y2);
        let su_rect = Rect::new(0, y1, pipe_src.x2, y2);
        // drm_atomic_add_affected_planes brought in the cursor; every
        // visible plane that intersects the SU area fetches its rows.
        let mut inter = su_rect;
        result.primary = inter
            .intersect(&dst)
            .then_some((inter.y1 - dst.y1, inter.y2 - dst.y1));
        if let Some(cursor) = commit.cursor {
            let mut inter = su_rect;
            if !cursor.dst.visible() {
                // A cursor mode this driver does not size has no exact
                // fetch area (NARF policy).
                result.full_update = true;
            } else if !inter.intersect(&cursor.dst) {
                // A previously enabled cursor fetch is disabled.
                if area_height(previous.1) > 0 {
                    result.cursor = Some((None, cursor.ctl));
                }
            } else if !cursor.supported() {
                result.full_update = true;
            } else {
                result.cursor = Some((
                    Some((inter.y1 - cursor.dst.y1, inter.y2 - cursor.dst.y1)),
                    cursor.ctl,
                ));
            }
        }
    }
    result.man_trk_ctl = man_trk_ctl(result.full_update, result.su);
    result
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
    wait_clear(regs, PSR_STATUS, EDP_PSR_STATUS_STATE_MASK, timeout_ms)
}

/// `intel_de_wait_for_clear_ms(register, mask, timeout_ms)`; a timeout is
/// [`Refusal::ExitTimeout`].
fn wait_clear<M: MmioWindow + ?Sized>(
    regs: &M,
    register: u64,
    mask: u32,
    timeout_ms: u64,
) -> Result<(), Refusal> {
    let mut error = None;
    let done = narf_scheduler::responsive_spin_until(
        || match readable(regs, register) {
            Ok(value) => value & mask == 0,
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

/// Whether a pipe or plane scaler is engaged on Pipe A (`SKL_PS_CTRL`):
/// `psr2_sel_fetch_pipe_state_supported` then forces a full update.
pub fn pipe_scaled<M: MmioWindow + ?Sized>(regs: &M) -> Result<bool, Refusal> {
    let mut scaled = false;
    for register in PS_CTRL_A {
        scaled |= readable(regs, register)? & PS_SCALER_EN != 0;
    }
    Ok(scaled)
}

/// `intel_psr_trigger_frame_change_event`: a `CURSURFLIVE` write raises the
/// PSR "Frame Change" event, which takes PSR2 out of deep sleep. Linux
/// display 14 gets the same exit from enabling the vblank interrupt in
/// `intel_pipe_update_start`; this driver has no display interrupt.
pub fn frame_change_event<M: MmioWindow + ?Sized>(regs: &M) {
    regs.write32(CURSURFLIVE, 0);
}

/// A running selective update: its configuration and the planes'
/// persisted `psr2_sel_fetch_area` (primary, cursor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Su {
    config: Psr2,
    primary: Area,
    cursor: Area,
}

/// The PSR owner on the KMS-owned Pipe-A eDP: PSR1, or PSR2 with selective
/// fetch. It only ever programs what it enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psr {
    config: Psr1,
    su: Option<Su>,
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
        Self::enable_with(regs, aux, config, None)
    }

    /// [`Psr::enable`] for PSR2 with selective fetch. The sink gets ALPM
    /// and the PSR2 configuration; then the selective fetch of the commit
    /// that qualified PSR2 is programmed (`commit`, normally the whole
    /// plane: `intel_psr2_program_trans_man_trk_ctl` and the plane updates
    /// run in that commit before `intel_psr_post_plane_update` enables
    /// PSR); then the source, with Wa_16014451276 and Wa_16012604467 on
    /// display 14.00 A0..A3.
    pub fn enable_su<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
        regs: &M,
        aux: &mut A,
        config: Psr1,
        su: Psr2,
        commit: &SuCommit<'_>,
    ) -> Result<Psr, Refusal> {
        Self::enable_with(regs, aux, config, Some((su, commit)))
    }

    fn enable_with<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
        regs: &M,
        aux: &mut A,
        config: Psr1,
        su: Option<(Psr2, &SuCommit<'_>)>,
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
        let chickens = match su {
            Some((su, _)) if su.a0_to_b0 => Some((
                readable(regs, MTL_CHICKEN_TRANS_A)?,
                readable(regs, MTL_CLKGATE_DIS_TRANS_A)?,
            )),
            _ => None,
        };
        // intel_psr_enable_sink: intel_alpm_enable_sink (PSR2 only), then
        // _psr_enable_sink, then DP_SET_POWER D0.
        let cfg = su.map_or_else(sink_cfg_psr1, |(su, _)| sink_cfg_psr2(&su));
        let alpm = match su {
            Some(_) => write(aux, DP_RECEIVER_ALPM_CONFIG, SINK_ALPM_PSR2),
            None => Ok(()),
        };
        let sink = alpm
            .and_then(|()| write(aux, DP_PSR_EN_CFG, cfg))
            .and_then(|()| write(aux, DP_PSR_EN_CFG, cfg | DP_PSR_ENABLE))
            .and_then(|()| write(aux, DP_SET_POWER, DP_SET_POWER_D0));
        if let Err(error) = sink {
            let _ = write(aux, DP_PSR_EN_CFG, 0);
            if su.is_some() {
                let _ = write(aux, DP_RECEIVER_ALPM_CONFIG, 0);
            }
            return Err(Refusal::Aux(error));
        }
        let mut psr = Psr {
            config,
            su: su.map(|(config, _)| Su {
                config,
                primary: None,
                cursor: None,
            }),
            active: false,
        };
        if let Some((su, commit)) = su {
            let first = sel_fetch_update(&su, commit, (None, None));
            psr.program_sel_fetch_noarm(regs, &first);
            psr.program_sel_fetch_arm(regs, &first);
            psr.program_sel_fetch_cursor(regs, &first);
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
        // Wa_16014451276 and Wa_16012604467 (mtl[a0,b0], not Panel Replay).
        if let Some((chicken, clkgate)) = chickens {
            regs.write32(MTL_CHICKEN_TRANS_A, chicken | ADLP_1_BASED_X_GRANULARITY);
            regs.write32(
                MTL_CLKGATE_DIS_TRANS_A,
                clkgate | MTL_CLKGATE_DIS_TRANS_DMASC_GATING_DIS,
            );
        }
        Ok(psr)
    }

    pub fn config(&self) -> Psr1 {
        self.config
    }

    /// The PSR2 configuration when selective update runs.
    pub fn psr2(&self) -> Option<Psr2> {
        self.su.map(|su| su.config)
    }

    /// Whether this is PSR2 with selective fetch (`sel_update_enabled`).
    pub fn selective(&self) -> bool {
        self.su.is_some()
    }

    /// The persisted `psr2_sel_fetch_area` of the primary and the cursor.
    pub fn areas(&self) -> (Area, Area) {
        self.su.map_or((None, None), |su| (su.primary, su.cursor))
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

    /// `hsw_activate_psr1` (RMW keeping only the context-restore bit) or
    /// `hsw_activate_psr2`: `EDP_PSR_CTL` written 0 (BSpec: keep
    /// `EDP_PSR_TP1_TP3_SEL` unset while PSR2 is enabled), then
    /// `EDP_PSR2_CTL`.
    fn activate<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        match self.su {
            Some(su) => {
                readable(regs, PSR2_CTL)?;
                regs.write32(PSR_CTL, 0);
                regs.write32(PSR2_CTL, psr2_ctl(&self.config, &su.config));
            }
            None => {
                let ctl = readable(regs, PSR_CTL)?;
                regs.write32(
                    PSR_CTL,
                    (ctl & EDP_PSR_RESTORE_PSR_ACTIVE_CTX) | psr1_ctl(&self.config),
                );
            }
        }
        self.active = true;
        Ok(())
    }

    /// `intel_psr_exit`: clear `EDP_PSR_ENABLE` (PSR1) or
    /// `EDP_PSR2_ENABLE` (PSR2; DC3CO is never allowed here).
    fn exit<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Refusal> {
        if !self.active {
            return Ok(());
        }
        let (register, enable) = if self.su.is_some() {
            (PSR2_CTL, EDP_PSR2_ENABLE)
        } else {
            (PSR_CTL, EDP_PSR_ENABLE)
        };
        let ctl = readable(regs, register)?;
        regs.write32(register, ctl & !enable);
        self.active = false;
        Ok(())
    }

    /// `intel_psr_wait_exit_locked`'s status: `EDP_PSR2_STATUS` for
    /// selective update, else `EDP_PSR_STATUS`.
    fn status(&self) -> (u64, u32) {
        if self.su.is_some() {
            (PSR2_STATUS, EDP_PSR2_STATUS_STATE_MASK)
        } else {
            (PSR_STATUS, EDP_PSR_STATUS_STATE_MASK)
        }
    }

    /// The PSR state machine of this mode is idle.
    pub fn idle<M: MmioWindow + ?Sized>(&self, regs: &M) -> Result<bool, Refusal> {
        let (register, mask) = self.status();
        Ok(readable(regs, register)? & mask == 0)
    }

    /// `intel_psr_wait_exit_locked` for this mode, bounded at `timeout_ms`.
    pub fn wait_idle<M: MmioWindow + ?Sized>(
        &self,
        regs: &M,
        timeout_ms: u64,
    ) -> Result<(), Refusal> {
        let (register, mask) = self.status();
        wait_clear(regs, register, mask, timeout_ms)
    }

    /// `TRANS_PSR_IIR & TGL_PSR_ERROR`, polled.
    pub fn error<M: MmioWindow + ?Sized>(regs: &M) -> Result<(), Refusal> {
        if readable(regs, PSR_IIR)? & TGL_PSR_ERROR != 0 {
            Err(Refusal::SinkNotReliable)
        } else {
            Ok(())
        }
    }

    /// `intel_psr_pause`'s exit (frontbuffer invalidate before any frame
    /// change). The caller then waits for [`Psr::idle`] within
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
        if !self.idle(regs)? {
            return Ok(false);
        }
        self.activate(regs)?;
        Ok(true)
    }

    /// `_psr2_ready_for_pipe_update_locked`: PSR2 is out of deep sleep, so
    /// a pipe update may run while it stays enabled.
    pub fn ready_for_update<M: MmioWindow + ?Sized>(&self, regs: &M) -> Result<bool, Refusal> {
        Ok(readable(regs, PSR2_STATUS)? & EDP_PSR2_STATUS_STATE_DEEP_SLEEP == 0)
    }

    /// `intel_psr2_sel_fetch_update` against this owner's persisted areas;
    /// `None` without selective update.
    pub fn sel_fetch(&self, commit: &SuCommit<'_>) -> Option<SelFetch> {
        self.su
            .map(|su| sel_fetch_update(&su.config, commit, (su.primary, su.cursor)))
    }

    /// `icl_plane_update_sel_fetch_noarm` for the full-screen primary
    /// (destination and source origin 0): `SEL_FETCH_PLANE_POS`, `_OFFSET`
    /// and `_SIZE` from its area. Written before the update waits for PSR.
    pub fn program_sel_fetch_noarm<M: MmioWindow + ?Sized>(&self, regs: &M, sf: &SelFetch) {
        let Some(su) = self.su else {
            return;
        };
        let (y1, y2) = sf.primary.unwrap_or((-1, -1));
        regs.write32(SEL_FETCH_PLANE_POS, (y1 as u32) << 16);
        regs.write32(SEL_FETCH_PLANE_OFFSET, (y1 as u32) << 16);
        regs.write32(
            SEL_FETCH_PLANE_SIZE,
            ((y2.wrapping_sub(y1).wrapping_sub(1) as u32) << 16)
                | u32::from(su.config.width).wrapping_sub(1),
        );
    }

    /// The commit's arm half for the primary: `PSR2_MAN_TRK_CTL`
    /// (`commit_pipe_pre_planes`), then `icl_plane_update_sel_fetch_arm`'s
    /// `SEL_FETCH_PLANE_CTL`, ahead of the plane's surface write.
    pub fn program_sel_fetch_arm<M: MmioWindow + ?Sized>(&mut self, regs: &M, sf: &SelFetch) {
        let Some(su) = self.su.as_mut() else {
            return;
        };
        regs.write32(PSR2_MAN_TRK_CTL, sf.man_trk_ctl);
        regs.write32(
            SEL_FETCH_PLANE_CTL,
            if area_height(sf.primary) > 0 {
                SEL_FETCH_PLANE_CTL_ENABLE
            } else {
                0
            },
        );
        su.primary = sf.primary;
    }

    /// `i9xx_cursor_update_sel_fetch_arm` when the cursor joined the
    /// commit: `SEL_FETCH_CUR_CTL` (its `CURCNTR` while it fetches, else
    /// 0), then `CURBASE` rewritten unchanged, the write that arms every
    /// cursor register (`i9xx_cursor_update_arm` always writes it).
    pub fn program_sel_fetch_cursor<M: MmioWindow + ?Sized>(&mut self, regs: &M, sf: &SelFetch) {
        let (Some(su), Some((area, ctl))) = (self.su.as_mut(), sf.cursor) else {
            return;
        };
        regs.write32(
            SEL_FETCH_CUR_CTL,
            if area_height(area) > 0 { ctl } else { 0 },
        );
        let base = regs.read32(CURBASE);
        if base != u32::MAX {
            regs.write32(CURBASE, base);
        }
        su.cursor = area;
    }

    /// `intel_psr_disable_locked`: exit, wait, undo Wa_14015648006 (and,
    /// for PSR2 on A0..A3, Wa_16012604467), then clear the sink
    /// (`DP_PSR_EN_CFG`, and `DP_RECEIVER_ALPM_CONFIG` after PSR2). Every
    /// step runs; the first failure is returned. `wake` adds
    /// `intel_psr_handle_irq`'s `DP_SET_POWER_D0`.
    pub fn disable<M: MmioWindow + ?Sized, A: AuxChannel + ?Sized>(
        &mut self,
        regs: &M,
        aux: &mut A,
        timeout_ms: u64,
        wake: bool,
    ) -> Result<(), Refusal> {
        let mut first = self.exit(regs).err();
        if let Err(refusal) = self.wait_idle(regs, timeout_ms) {
            first.get_or_insert(refusal);
        }
        let dcpr = regs.read32(CHICKEN_DCPR_1);
        if dcpr != u32::MAX {
            regs.write32(CHICKEN_DCPR_1, dcpr & !LATENCY_REPORTING_REMOVED_PIPE_A);
        }
        if self.su.is_some_and(|su| su.config.a0_to_b0) {
            let clkgate = regs.read32(MTL_CLKGATE_DIS_TRANS_A);
            if clkgate != u32::MAX {
                regs.write32(
                    MTL_CLKGATE_DIS_TRANS_A,
                    clkgate & !MTL_CLKGATE_DIS_TRANS_DMASC_GATING_DIS,
                );
            }
        }
        if let Err(error) = write(aux, DP_PSR_EN_CFG, 0) {
            first.get_or_insert(Refusal::Aux(error));
        }
        if self.su.is_some() {
            if let Err(error) = write(aux, DP_RECEIVER_ALPM_CONFIG, 0) {
                first.get_or_insert(Refusal::Aux(error));
            }
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
