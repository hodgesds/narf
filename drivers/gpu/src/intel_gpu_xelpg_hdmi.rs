//! Intel Xe-LPDP (Meteor Lake / Arrow Lake), Xe2_LPD (Lunar Lake) and
//! Xe3_LPD (Panther Lake) HDMI TMDS output.
//!
//! The HDMI counterpart of [`crate::intel_gpu_xelpg_external`]: one
//! owned TMDS stream on a Pipe B–D and its transcoder over DDI B (C10, or
//! C20 on Panther Lake) or a Type-C port in legacy mode (C20), next to the
//! lit internal panel. Display 20 and 30 take the DP route's deltas: the
//! D2D link in `DDI_BUF_CTL` (kept set by the full DDI write,
//! `intel_ddi_enable_hdmi`'s `XE2LPD_DDI_BUF_D2D_LINK_ENABLE`), the IP's
//! pipe resources and Type-C profile, and on display 30 the fixed-refresh
//! VRR timing generator. Nova Lake-S display 35 runs the same route on LT
//! port B and legacy TC1/TC2 with the LT PHY's TMDS PLL
//! (`xe3plpd_lt_hdmi_tables` or its computed image) and the DP 1.4 table's
//! HDMI level. Wildcat Lake's 30.02 profile has no HDMI route. The
//! pipe side (power wells, resource transaction, pipe DMC, timings, plane
//! arm, release) is the shared Pipe B–D owner
//! ([`crate::intel_gpu_xelpg_pipes`]) through the DP route's helpers.
//!
//! ## Sources (Linux b90c984d)
//!
//! - `intel_cx0_phy.c`: `mtl_c10_hdmi_tables[]` and the TMDS entries of
//!   `mtl_c20_hdmi_tables[]` (generated verbatim into
//!   `intel_gpu_xelpg_hdmi_tables.rs`), `intel_c10pll_update_pll` (no
//!   HDMI SSC: PLL bytes 4..8 zeroed), `intel_c20_calc_vdr_params`
//!   (TMDS: width 0, no serdes bits, HDMI rate 0),
//!   `intel_program_port_clock_ctl` (maxPCLK, no SSC), the C10
//!   Wa_13013502646 powerdown toggle and `intel_cx0_phy_set_signal_levels`
//!   with the HDMI TX levels — all in [`crate::intel_gpu_xelpg`].
//! - `intel_ddi.c`: `intel_ddi_pre_enable_hdmi` (PLL, transcoder clock,
//!   infoframes), `intel_ddi_enable` (transcoder function, then the
//!   transcoder), `intel_ddi_enable_hdmi` (D2D, signal levels,
//!   PORT_BUF_CTL1 width, DDI_CTL_DE with the lane width — display 14
//!   fills it for TMDS), `intel_ddi_post_disable_hdmi` (infoframes off,
//!   `intel_ddi_buf_disable`, transcoder clock off, PLL off).
//! - `intel_hdmi.c` (`intel_hdmi_compute_config` scrambling,
//!   `intel_hdmi_handle_sink_scrambling`, `intel_hdmi_default_ddc_pin`),
//!   `intel_ddi.c::intel_ddi_disable_hdmi`, `drm_scdc_helper.c`
//!   (`drm_scdc_set_high_tmds_clock_ratio`, `drm_scdc_set_scrambling`)
//!   and `drm_edid.c::drm_parse_hdmi_forum_scds`; `intel_gmbus.c`
//!   `gmbus_pins_mtp`: DDI B's DDC is GMBUS pin 2 ("dpb").
//! - `drm_edid.c::drm_do_probe_ddc_edid` over `intel_gmbus.c::gmbus_xfer`:
//!   each EDID block is an offset write + read at slave 0x50, an
//!   INDEX-cycle transfer on the shared GMBUS transport
//!   ([`crate::intel_gpu_gmbus::GmbusBus`]), with the E-DDC segment
//!   pointer chained ahead of blocks 2 and 3; see [`read_edid_ddc`].
//!
//! [`probe_hdmi`] owns a legacy Type-C PHY in legacy mode before its DDC
//! is used (rolled back on any failure), and the hotplug service
//! ([`crate::intel_gpu_xelpg_external::MtlExternalService`]) selects this
//! route per its port policy.
//!
//! ## Qualified profile and refusals
//!
//! TMDS clocks from the source tables, 8 bpc RGB, AVI infoframe. Above
//! 340 MHz (C10 497.75/592/593.407/594 MHz, C20 594 MHz) HDMI 2.0
//! scrambling runs as `intel_hdmi_compute_config` decides it from the
//! sink's HF-VSDB/HF-SCDB (`drm_parse_hdmi_forum_scds`, [`parse_sink_scdc`],
//! [`tmds_link`]): `TRANS_DDI_HDMI_SCRAMBLING` +
//! `TRANS_DDI_HIGH_TMDS_CHAR_RATE` in the function control, and the sink's
//! SCDC TMDS_CONFIG (1/40 ratio, 1 ms, then scrambling;
//! `intel_hdmi_handle_sink_scrambling`) after the transcoder and before
//! the DDI buffer, reset before the transcoder stops. A sink with
//! LTE_340Mcsc_Scramble is scrambled at lower clocks too; any
//! scrambling-capable sink gets its SCDC written (cleared) on every
//! enable, as in Linux. Refused with typed errors: a clock above 340 MHz
//! the sink declares no scrambling for or above its declared maximum,
//! FRL and the FRL-ambiguous TMDS clocks 300/600 MHz (`intel_hdmi_is_frl`
//! would select FRL clocking), clocks above the 600 MHz source maximum
//! (a clock without a source table computes: SNPS C10 always, C20 when the
//! mapping reports its MTL-U / ARL-S `tx_misc` fact), Type-C DP-alt (HDMI
//! needs a legacy port), an
//! active DDI, no free Pipe B–D, a lit Pipe A that is not the owned panel
//! profile, and the Pipe B–D owner's resource refusals (all before the
//! first write). PM demand runs at the TMDS clock (Linux's
//! `crtc_state->port_clock` for HDMI). Linux only logs an SCDC failure; here a
//! stream that needs the sink scrambling fails activation instead (and
//! is locally stopped). YCbCr 4:2:0 follows `intel_hdmi_compute_output_format`
//! at 8 bpc on display 14 and 20 (a Y420VDB VIC, or a Y420CMDB VIC whose RGB
//! link is invalid): half the TMDS clock, the 1:1 pipe scaler in the
//! resource transaction's prefill, the BT.709 output CSC, `PIPE_MISC` YUV
//! and the Y420 AVI infoframe; display 30 keeps RGB. Under
//! `narf.intel.hdmi14_ext=1` the route also takes Linux's deep colour (10
//! and 12 bpc with the GCP, [`crate::intel_gpu_xelpg_external::color`]) and
//! HDMI audio ([`crate::intel_gpu_xelpg_external::audio`]). Linux never
//! drives YCbCr 4:4:4 over HDMI, and HDMI 2.1 FRL stays refused: Linux 7.4
//! has no source FRL link training (its FRL facts are below).
//!
//! DDC pins come from the corrected GMBUS numbering
//! ([`crate::intel_gpu_gmbus::PinPair`], `gmbus_pins_mtp`): DDI B is pin 2
//! ("dpb"), a declared legacy TCn is pin 8 + n ("tc1".."tc4"); see
//! [`ddc_pin`].

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gmbus::PinPair;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_pipes::Pipe;
use crate::intel_gpu_xe2lpd::{disable_d2d, enable_d2d, DisplayIp};
use crate::intel_gpu_xelpg::{
    disable_port_pll_complete, enable_port_pll_state, port_width, set_signal_levels_hdmi,
    wait_port_buf_active, wait_port_buf_idle, C10PllState, C20PllState, C20Vdr, Cx0Error, Cx0Phy,
    Cx0PllState, PhyKind, PllRequest, XeLpgPort, PORT_BUF_PHY_IDLE, PORT_WIDTH_MASK,
};
use crate::intel_gpu_xelpg_external::{
    ddi_enable_value, external_pipe, preflight_ip, request_pipe_wells, reserve_pipe, trans_clk_sel,
    trans_clk_sel_port, trans_ddi_func_ctl, ExternalDisplayProfile, ExternalError, MtlDisplay,
    PipeRefusal, RoutePipe,
};
use crate::intel_gpu_xelpg_pipes::{PipeEnableError, Pipes};
use crate::intel_gpu_xelpg_tc::{
    connect_for as tc_connect_for, connection_intact, disconnect as tc_disconnect, TcConnection,
    TcMode,
};

include!("intel_gpu_xelpg_hdmi_tables.rs");

/// Highest TMDS character clock driven without the 1/40 clock ratio
/// (HDMI 2.0 scrambling threshold, `intel_hdmi_compute_config`).
pub const MAX_TMDS_KHZ_UNSCRAMBLED: u32 = 340_000;
/// Lowest HDMI TMDS clock (`intel_c20_get_hdmi_rate` range floor).
pub const MIN_TMDS_KHZ: u32 = 25_000;
/// `intel_hdmi_is_frl` clocks: 3, 6, 8, 10 and 12 Gbps per lane.
const FRL_CLOCKS_KHZ: [u32; 5] = [300_000, 600_000, 800_000, 1_000_000, 1_200_000];

/// `intel_hdmi_is_frl`: `clock_khz` is an FRL rate within
/// `intel_dpll_clock_matches`' 1 kHz.
pub const fn is_frl(clock_khz: u32) -> bool {
    let mut i = 0;
    while i < FRL_CLOCKS_KHZ.len() {
        if clock_khz.abs_diff(FRL_CLOCKS_KHZ[i]) <= 1 {
            return true;
        }
        i += 1;
    }
    false
}

/// `PIPE_FRMCOUNT_G4X`, primary `PLANE_SURF` / `PLANE_SURFLIVE`, relative
/// to [`Pipe::base`].
const FRMCOUNT: u64 = 0x040;
const PLANE_SURF_1: u64 = 0x19C;
const PLANE_SURFLIVE_1: u64 = 0x1AC;
const TRANS_DDI_FUNC_ENABLE: u32 = 1 << 31;
const TRANS_DDI_PORT_AND_MODE: u32 = (0xF << 27) | (0x7 << 24);
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
/// HDMI TMDS always drives four lanes.
const HDMI_LANES: u8 = 4;

/// Typed HDMI refusal or failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdmiError {
    /// The clock has no source table on this PHY (or is below the TMDS
    /// floor).
    UnsupportedClock(u32),
    /// The clock is an FRL rate or FRL-ambiguous.
    FrlClock(u32),
    /// The mode's TMDS clock is above the 600 MHz source maximum and the
    /// sink declares HDMI 2.1 FRL. Linux 7.4 has no native FRL link
    /// training for the source (`intel_hdmi_mode_valid` prunes these
    /// modes; its FRL path is a DP PCON's), so the stream is refused.
    FrlUnsupported {
        /// The mode's TMDS clock in kHz.
        clock_khz: u32,
        /// `intel_hdmi_sink_max_frl_rate` in Gbps.
        sink_max_frl_gbps: u32,
    },
    /// The clock is above 340 MHz and the sink declares no scrambling
    /// (no SCDC or no Max_TMDS_Character_Rate in its HF-VSDB/HF-SCDB).
    ScramblingRequired(u32),
    /// The clock is above the sink's declared `max_tmds_clock`.
    SinkClockLimit {
        /// The mode's TMDS clock in kHz.
        clock_khz: u32,
        /// The sink's limit in kHz (0: none declared above 340 MHz).
        max_khz: u32,
    },
    /// An SCDC transfer the stream depends on failed.
    Scdc(crate::intel_gpu_hdmi::DdcError),
    /// The port's DDC is not reachable through the shared GMBUS encoder.
    DdcUnavailable,
    /// DDC transfer failed.
    Ddc(crate::intel_gpu_hdmi::DdcError),
    /// EDID did not parse to a preferred mode.
    Edid,
    /// A Type-C port not in legacy mode cannot carry native HDMI.
    NotLegacy,
    /// Route-level refusal or failure (shared with DP).
    Route(ExternalError),
}

impl From<ExternalError> for HdmiError {
    fn from(e: ExternalError) -> Self {
        HdmiError::Route(e)
    }
}

impl From<crate::intel_gpu_xelpg_tc::TcError> for HdmiError {
    fn from(e: crate::intel_gpu_xelpg_tc::TcError) -> Self {
        HdmiError::Route(e.into())
    }
}

fn d2d_err(_: crate::intel_gpu_xe2lpd::IpError) -> HdmiError {
    // The same failed 100-us state observation the display-14 helper
    // reports as a PHY timeout.
    phy_err(Cx0Error::Timeout)
}

fn phy_err(e: Cx0Error) -> HdmiError {
    HdmiError::Route(ExternalError::Modeset(match e {
        Cx0Error::PhyError | Cx0Error::ProtocolMismatch => ModesetError::PhyBusFailure,
        Cx0Error::Timeout | Cx0Error::UnsupportedRate => ModesetError::PllLockTimeout,
    }))
}

// ── Sink scrambling capability (HF-VSDB / HF-SCDB) ───────────────────

/// `intel_hdmi_source_max_tmds_clock` for display 13 and later (no VBT
/// `max_tmds_clock` cap without a VBT).
pub const SOURCE_MAX_TMDS_KHZ: u32 = 600_000;
/// `HDMI_FORUM_IEEE_OUI` 0xc45dd8 as stored in a vendor block (LSB first).
const HDMI_FORUM_OUI: [u8; 3] = [0xD8, 0x5D, 0xC4];
/// `CEA_EXT`.
const CEA_EXT: u8 = 0x02;
/// `CTA_DB_VENDOR` and `CTA_DB_EXTENDED_TAG`.
const CTA_DB_VENDOR: u8 = 3;
const CTA_DB_EXTENDED_TAG: u8 = 7;
/// `CTA_EXT_DB_HF_SCDB`.
const CTA_EXT_DB_HF_SCDB: u8 = 0x79;

/// The sink's SCDC and scrambling capability as
/// `drm_edid.c::drm_parse_hdmi_forum_scds` records it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SinkScdc {
    /// `hdmi.scdc.supported` (SCDC_Present, flags bit 7).
    pub scdc: bool,
    /// `hdmi.scdc.scrambling.supported`: SCDC present and a non-zero
    /// Max_TMDS_Character_Rate.
    pub scrambling: bool,
    /// `hdmi.scdc.scrambling.low_rates` (LTE_340Mcsc_Scramble, bit 3).
    pub low_rates: bool,
    /// `display_info.max_tmds_clock` when the block raised it above
    /// 340 MHz (rate byte × 5000 kHz), else 0.
    pub max_tmds_clock_khz: u32,
}

/// Parse the HDMI Forum blocks of `edid`'s CTA extensions. A block is the
/// HF-VSDB (`cea_db_is_hdmi_forum_vsdb`: vendor tag, HDMI Forum OUI) or
/// the HF-SCDB (`cea_db_is_hdmi_forum_scdb`: extended tag 0x79), each
/// with a payload of at least 7 bytes; both share the `hf_scds` layout
/// (byte 5 the rate, byte 6 the flags). Only revision 3+ CTA extensions
/// with a valid checksum are walked, over the data block collection
/// `cea_db_collection_size` bounds (bytes 4..d, d in 4..=127).
pub fn parse_sink_scdc(edid: &[u8]) -> SinkScdc {
    let mut out = SinkScdc::default();
    for_each_forum_block(edid, |hf| {
        if hf[6] & 0x80 != 0 {
            out.scdc = true;
        }
        if hf[5] != 0 {
            let max = u32::from(hf[5]) * 5_000;
            if max > MAX_TMDS_KHZ_UNSCRAMBLED {
                out.max_tmds_clock_khz = max;
            }
            if out.scdc {
                out.scrambling = true;
                if hf[6] & 0x08 != 0 {
                    out.low_rates = true;
                }
            }
        }
    });
    out
}

/// Run `f` on every HDMI Forum block (header byte first, at least eight
/// bytes) of `edid`'s valid revision 3+ CTA extensions.
fn for_each_forum_block(edid: &[u8], mut f: impl FnMut(&[u8])) {
    for ext in edid.chunks_exact(128).skip(1) {
        let sum = ext.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        if ext[0] != CEA_EXT || ext[1] < 3 || sum != 0 {
            continue;
        }
        let end = ext[2] as usize;
        if !(4..=127).contains(&end) {
            continue;
        }
        let mut index = 4usize;
        while index < end {
            let tag = ext[index] >> 5;
            let len = (ext[index] & 0x1F) as usize;
            if index + 1 + len > end {
                break;
            }
            let hf = &ext[index..index + 1 + len];
            let forum = len >= 7
                && ((tag == CTA_DB_VENDOR && hf[1..4] == HDMI_FORUM_OUI)
                    || (tag == CTA_DB_EXTENDED_TAG && hf[1] == CTA_EXT_DB_HF_SCDB));
            if forum {
                f(hf);
            }
            index += 1 + len;
        }
    }
}

/// The TMDS link state the source drives: `crtc_state->hdmi_scrambling`
/// and `hdmi_high_tmds_clock_ratio`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TmdsLink {
    /// `TRANS_DDI_HDMI_SCRAMBLING` and SCDC scrambling enable.
    pub scrambling: bool,
    /// `TRANS_DDI_HIGH_TMDS_CHAR_RATE` and the SCDC 1/40 clock ratio.
    pub high_tmds_clock_ratio: bool,
}

/// `intel_hdmi_compute_config`'s scrambling decision for `clock_khz`
/// against `sink` (`source_supports_scrambling` holds: the source maximum
/// is 600 MHz): scramble when the sink supports it and either it accepts
/// low-rate scrambling or the clock is above 340 MHz, and use the 1/40
/// ratio above 340 MHz. A clock above 340 MHz is refused when the sink
/// declares no scrambling or a lower `max_tmds_clock`
/// (`hdmi_port_clock_limit` with downstream limits).
pub fn tmds_link(clock_khz: u32, sink: &SinkScdc) -> Result<TmdsLink, HdmiError> {
    let high = clock_khz > MAX_TMDS_KHZ_UNSCRAMBLED;
    if high && !sink.scrambling {
        return Err(HdmiError::ScramblingRequired(clock_khz));
    }
    if high && clock_khz > sink.max_tmds_clock_khz {
        return Err(HdmiError::SinkClockLimit {
            clock_khz,
            max_khz: sink.max_tmds_clock_khz,
        });
    }
    Ok(TmdsLink {
        scrambling: sink.scrambling && (sink.low_rates || high),
        high_tmds_clock_ratio: sink.scrambling && high,
    })
}

// ── HDMI 2.1 FRL facts ───────────────────────────────────────────────
//
// Linux 7.4 has no native HDMI FRL link training for the source: the SCDC
// FRL registers (`SCDC_CONFIG_1`, `SCDC_FLT_READY`, `SCDC_STATUS_FLAGS_1`)
// are only read by `drm_scdc_read_state` for debugfs, i915 never writes
// them, and `intel_hdmi_mode_valid` prunes every mode above 600 MHz
// ("Current platforms do not support FRL"). What it has is the rate
// detection (`intel_hdmi_is_frl`, `intel_hdmi_sink_max_frl_rate`,
// `intel_hdmi_sink_dsc_max_frl_rate`, used by the DP PCON path) and the
// PHY half: the FRL entries of `mtl_c20_hdmi_tables[]`, the FRL VDR
// parameters ([`crate::intel_gpu_xelpg::C20Vdr::hdmi`]), the DIV18CLK
// clock select ([`crate::intel_gpu_xelpg::ddi_clock_select`]) and the
// FRL link symbol clock
// ([`crate::intel_gpu_xelpg::hdmi_link_symbol_clock_khz`]). Those are
// carried here; an FRL stream stays a typed refusal
// ([`HdmiError::FrlUnsupported`], [`HdmiError::FrlClock`]).

/// The sink's FRL capability as `drm_parse_hdmi_forum_scds` records it
/// (`drm_get_max_frl_rate` of `hf_scds[7]` bits 7:4, and of `hf_scds[12]`
/// when `hf_scds[11]` declares DSC).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SinkFrl {
    /// `hdmi.max_lanes`.
    pub max_lanes: u8,
    /// `hdmi.max_frl_rate_per_lane` (Gbps).
    pub max_frl_rate_per_lane: u8,
    /// `hdmi.dsc_cap.max_lanes`.
    pub dsc_max_lanes: u8,
    /// `hdmi.dsc_cap.max_frl_rate_per_lane` (Gbps).
    pub dsc_max_frl_rate_per_lane: u8,
}

impl SinkFrl {
    /// `intel_hdmi_sink_max_frl_rate`: lanes × rate per lane (Gbps).
    pub const fn max_frl_rate(&self) -> u32 {
        self.max_lanes as u32 * self.max_frl_rate_per_lane as u32
    }

    /// `intel_hdmi_sink_dsc_max_frl_rate`: 0 unless both DSC fields are set.
    pub const fn dsc_max_frl_rate(&self) -> u32 {
        if self.dsc_max_lanes == 0 || self.dsc_max_frl_rate_per_lane == 0 {
            0
        } else {
            self.dsc_max_lanes as u32 * self.dsc_max_frl_rate_per_lane as u32
        }
    }
}

/// `drm_get_max_frl_rate`: (lanes, Gbps per lane) of a `Max_FRL_Rate` code.
pub const fn max_frl_rate(code: u8) -> (u8, u8) {
    match code {
        1 => (3, 3),
        2 => (3, 6),
        3 => (4, 6),
        4 => (4, 8),
        5 => (4, 10),
        6 => (4, 12),
        7 => (4, 16),
        8 => (4, 20),
        9 => (4, 24),
        _ => (0, 0),
    }
}

/// Parse the FRL fields of `edid`'s HDMI Forum blocks (the HF-VSDB or
/// HF-SCDB [`parse_sink_scdc`] walks).
pub fn parse_sink_frl(edid: &[u8]) -> SinkFrl {
    let mut out = SinkFrl::default();
    for_each_forum_block(edid, |hf| {
        if hf[7] != 0 {
            (out.max_lanes, out.max_frl_rate_per_lane) = max_frl_rate(hf[7] >> 4);
        }
        // cea_db_payload_len(hf_scds) >= 11 && hf_scds[11]: drm_parse_dsc_info,
        // whose max FRL rate needs a payload of 12 and a nonzero hf_scds[12].
        if hf.len() > 11 && hf[11] != 0 && hf.len() > 12 && hf[12] != 0 {
            (out.dsc_max_lanes, out.dsc_max_frl_rate_per_lane) = max_frl_rate(hf[12] >> 4);
        }
    });
    out
}

/// The FRL entries of Linux 7.4 `mtl_c20_hdmi_tables[]` (`mtl_c20_hdmi_300`
/// .. `mtl_c20_hdmi_1200`), hand-transcribed: (port clock kHz, PLL state).
/// No route programs them.
pub const C20_HDMI_FRL_TABLES: [(u32, C20PllState); 5] = [
    (
        300_000,
        C20PllState {
            tx: [0xBE98, 0x8800, 0x0000],
            cmn: [0x0500, 0x0005, 0x0000, 0x0000],
            mpllb: [
                0x309C, 0x2110, 0xCA06, 0xBE40, 0x0000, 0x0000, 0x2200, 0x0001, 0x2000, 0x0000,
                0x0004,
            ],
        },
    ),
    (
        600_000,
        C20PllState {
            tx: [0xBE98, 0x8800, 0x0000],
            cmn: [0x0500, 0x0005, 0x0000, 0x0000],
            mpllb: [
                0x109C, 0x2108, 0xCA06, 0xBE40, 0x0000, 0x0000, 0x2200, 0x0001, 0x2000, 0x0000,
                0x0004,
            ],
        },
    ),
    (
        800_000,
        C20PllState {
            tx: [0xBE98, 0x8800, 0x0000],
            cmn: [0x0500, 0x0005, 0x0000, 0x0000],
            mpllb: [
                0x10D0, 0x2108, 0x4A06, 0xBE40, 0x0000, 0x0000, 0x2200, 0x0003, 0x2AAA, 0x0002,
                0x0004,
            ],
        },
    ),
    (
        1_000_000,
        C20PllState {
            tx: [0xBE98, 0x8800, 0x0000],
            cmn: [0x0500, 0x0005, 0x0000, 0x0000],
            mpllb: [
                0x1104, 0x2108, 0x0A06, 0xBE40, 0x0000, 0x0000, 0x2200, 0x0003, 0x3555, 0x0001,
                0x0004,
            ],
        },
    ),
    (
        1_200_000,
        C20PllState {
            tx: [0xBE98, 0x8800, 0x0000],
            cmn: [0x0500, 0x0005, 0x0000, 0x0000],
            mpllb: [
                0x1138, 0x2108, 0x5486, 0xFE40, 0x0000, 0x0000, 0x2200, 0x0001, 0x4000, 0x0000,
                0x0004,
            ],
        },
    ),
];

/// The C20 FRL PLL state and VDR parameters for an FRL port clock (the
/// table entry and `intel_c20_calc_vdr_params`); `None` for any other
/// clock.
pub fn c20_hdmi_frl_state(port_clock_khz: u32) -> Option<(C20PllState, C20Vdr)> {
    let (_, state) = C20_HDMI_FRL_TABLES
        .iter()
        .find(|(clock, _)| *clock == port_clock_khz)?;
    Some((*state, C20Vdr::hdmi(port_clock_khz)?))
}

// ── SCDC (drm_scdc_helper.c over the GMBUS transport) ─────────────────

/// `SCDC_I2C_SLAVE_ADDRESS`.
pub const SCDC_I2C_SLAVE_ADDRESS: u8 = 0x54;
/// `SCDC_TMDS_CONFIG`.
pub const SCDC_TMDS_CONFIG: u8 = 0x20;
/// `SCDC_TMDS_BIT_CLOCK_RATIO_BY_40`.
pub const SCDC_TMDS_BIT_CLOCK_RATIO_BY_40: u8 = 1 << 1;
/// `SCDC_SCRAMBLING_ENABLE`.
pub const SCDC_SCRAMBLING_ENABLE: u8 = 1 << 0;

/// `intel_hdmi_handle_sink_scrambling` for a sink whose scrambling is
/// supported: `drm_scdc_set_high_tmds_clock_ratio` (read-modify-write of
/// TMDS_CONFIG bit 1, then at least 1 ms before the sink is relied on),
/// then `drm_scdc_set_scrambling` (read-modify-write of bit 0). The
/// sequence is shared with Gen12
/// ([`crate::intel_gpu_hdmi::handle_sink_scrambling`]).
pub fn sink_scrambling<M: MmioWindow + ?Sized>(
    io: &M,
    pin: PinPair,
    high_tmds_clock_ratio: bool,
    scrambling: bool,
) -> Result<(), HdmiError> {
    crate::intel_gpu_hdmi::handle_sink_scrambling(io, pin, high_tmds_clock_ratio, scrambling)
        .map_err(HdmiError::Scdc)
}

/// `intel_c20_hdmi_tmds_tx_cgf_1`: the C20 HDMI `tx[1]` word for a
/// platform's `tx_misc` and termination control (DCC calibration range 8,
/// DCC bypass). Linux takes `tx_misc` 5 with termination 4 on display 20+,
/// 0 on Battlemage, 3 on Meteor Lake-U (`INTEL_MTL_U_IDS`) and on an Arrow
/// Lake-S host bridge, and 7 otherwise, all with termination 2 below
/// display 20.
pub const fn c20_hdmi_tx_cfg1(tx_misc: u16, term_ctl: u16) -> u16 {
    (tx_misc & 0xFF) | (8 << 8) | (1 << 12) | ((term_ctl & 7) << 13)
}

/// `intel_c20_compute_hdmi_tmds_pll`: the C20 MPLLB state for an HDMI TMDS
/// `port_clock_khz` without an ideal table, against the 38.4 MHz
/// reference, with the platform's `tx[1]` word ([`c20_hdmi_tx_cfg1`]).
/// `None` outside 25.175-600 MHz.
pub fn compute_c20_hdmi_tmds(port_clock_khz: u32, tx_cfg1: u16) -> Option<C20PllState> {
    if !(25_175..=600_000).contains(&port_clock_khz) {
        return None;
    }
    const REFCLK: u64 = 38_400_000;
    const CLOCK_4999MHZ: u64 = 4_999_999_999;
    const CLOCK_9999MHZ: u64 = 9_999_999_999;
    let datarate = u64::from(port_clock_khz) * 1000 * 10;
    let tx_clk_div = (CLOCK_9999MHZ / datarate).ilog2() as u16;
    let vco_freq_shift = (CLOCK_4999MHZ * 256 / datarate).ilog2();
    let vco_freq = (datarate << vco_freq_shift) >> 8;
    let multiplier = (vco_freq << 28) / (REFCLK >> 4);
    let mpll_multiplier = (2 * (multiplier >> 32)) as u16;
    let fracn_quot = ((multiplier >> 16) & 0xFFFF) as u16;
    let fracn_rem = (multiplier & 0xFFFF) as u16;
    let div_multiplier = ((vco_freq * 16 + (datarate >> 1)) / datarate).min(255) as u16;
    let ana_freq_vco: u16 = match vco_freq {
        f if f <= 3_000_000_000 => 3,
        f if f <= 3_500_000_000 => 2,
        f if f <= 4_000_000_000 => 1,
        _ => 0,
    };
    Some(C20PllState {
        tx: [0xBE88, tx_cfg1, 0x0000],
        cmn: [0x0500, 0x0005, 0x0000, 0x0000],
        mpllb: [
            // MPLL_TX_CLK_DIV (15:13) | MPLL_MULTIPLIER (11:0)
            (tx_clk_div << 13) | (mpll_multiplier & 0xFFF),
            // CAL_DAC_CODE(31) (14:10) | WORD_CLK_DIV | MPLL_DIV_MULTIPLIER
            (31 << 10) | (1 << 8) | div_multiplier,
            // MPLLB_ANA_FREQ_VCO (15:14) | CP_PROP(20) (13:7) | CP_INT(6)
            (ana_freq_vco << 14) | (20 << 7) | 6,
            // V2I(2) (15:14) | CP_PROP_GS(30) (13:7) | CP_INT_GS(28)
            (2 << 14) | (30 << 7) | 28,
            0x0000,
            0x0000,
            // C20_MPLLB_FRACEN | SSC_UP_SPREAD
            (1 << 13) | (1 << 9),
            // MPLL_FRACN_DEN
            0xFFFF,
            fracn_quot,
            fracn_rem,
            // HDMI_DIV(1)
            1,
        ],
    })
}

/// The kernel's 64-bit helpers, as `intel_snps_hdmi_pll.c` sees them:
/// `do_div` (and so `DIV_ROUND_DOWN_ULL` / `DIV_ROUND_UP_ULL`) truncates
/// its divisor to 32 bits, the `DIV64_U64_*` forms keep 64, and all of it
/// wraps like C. A divisor that is zero after truncation ends the
/// computation (the C would trap).
mod snps {
    pub(super) fn div_down(ll: u64, d: u64) -> Option<u64> {
        ll.checked_div(u64::from(d as u32))
    }
    pub(super) fn div_up_ull(ll: u64, d: u64) -> Option<u64> {
        div_down(ll.wrapping_add(d).wrapping_sub(1), d)
    }
    pub(super) fn div64_up(ll: u64, d: u64) -> Option<u64> {
        ll.wrapping_add(d).wrapping_sub(1).checked_div(d)
    }
    pub(super) fn div64_closest(n: u64, d: u64) -> Option<u64> {
        n.wrapping_add(d / 2).checked_div(d)
    }
    /// `int_sqrt`: the floor square root.
    pub(super) fn int_sqrt(x: u64) -> u64 {
        if x <= 1 {
            return x;
        }
        let (mut x, mut y) = (x, 0u64);
        let mut m = 1u64 << ((63 - x.leading_zeros()) & !1);
        while m != 0 {
            let b = y + m;
            y >>= 1;
            if x >= b {
                x -= b;
                y += m;
            }
            m >>= 2;
        }
        y
    }
    /// `interp`: its `s64` operands go through `DIV64_U64_ROUND_UP` as
    /// `u64`, so a falling curve segment wraps exactly as in C.
    pub(super) fn interp(x: u64, x1: u64, x2: u64, y1: u64, y2: u64) -> Option<u64> {
        let dydx = div64_up(
            y2.wrapping_sub(y1).wrapping_mul(100_000),
            x2.wrapping_sub(x1),
        )?;
        Some(y1.wrapping_add(div64_up(dydx.wrapping_mul(x.wrapping_sub(x1)), 100_000)?))
    }
}

/// `intel_snps_hdmi_pll_compute_c10pll` (`intel_snps_hdmi_pll.c`): the C10
/// PLL state for an HDMI TMDS `port_clock_khz` without a precomputed
/// table, before `intel_c10pll_update_pll` clears the SSC bytes. Ported
/// operation for operation, including that `do_div(vco_clk, ...)` leaves
/// the quotient in `vco_clk`, so the VCO segment and the charge-pump
/// interpolation see that quotient; the output matches Linux's compiled
/// function byte for byte.
pub fn compute_c10_hdmi_tmds(port_clock_khz: u32) -> Option<C10PllState> {
    use snps::{div64_closest, div64_up, div_down, div_up_ull, int_sqrt, interp};
    const HZ_4999: u64 = 4_999_999_900;
    const HZ_9999: u64 = 2 * HZ_4999;
    const HZ_16G: u64 = 16_000_000_000;
    const FREQ: [[u64; 8]; 2] = [
        [
            2_500_000_000,
            3_000_000_000,
            3_000_000_000,
            3_500_000_000,
            3_500_000_000,
            4_000_000_000,
            4_000_000_000,
            5_000_000_000,
        ],
        [
            4_000_000_000,
            4_600_000_000,
            4_601_000_000,
            5_400_000_000,
            5_401_000_000,
            6_600_000_000,
            6_601_000_000,
            8_001_000_000,
        ],
    ];
    const CURVE_0: [[u64; 8]; 2] = [
        [
            41174500, 48605500, 42973700, 49433100, 42408600, 47681900, 40297400, 49131400,
        ],
        [
            82056800, 94420700, 82323400, 96370600, 81273300, 98630100, 81728700, 99105700,
        ],
    ];
    const CURVE_1: [[u64; 8]; 2] = [
        [
            73_300_000_000_000,
            66_000_000_000_000,
            83_100_000_000_000,
            75_300_000_000_000,
            99_700_000_000_000,
            92_300_000_000_000,
            125_000_000_000_000,
            110_000_000_000_000,
        ],
        [
            53_700_000_000_000,
            47_700_000_000_000,
            62_200_000_000_000,
            54_400_000_000_000,
            75_100_000_000_000,
            63_400_000_000_000,
            90_600_000_000_000,
            76_300_000_000_000,
        ],
    ];
    const CURVE_2: [[u64; 8]; 2] = [
        [
            2_415_790_000,
            3_136_460_000,
            2_581_990_000,
            3_222_670_000,
            2_529_330_000,
            3_042_020_000,
            2_336_970_000,
            3_191_460_000,
        ],
        [
            4_808_390_000,
            5_994_250_000,
            4_832_730_000,
            6_193_730_000,
            4_737_700_000,
            6_428_750_000,
            4_779_200_000,
            6_479_340_000,
        ],
    ];
    const CURVE0_MULTIPLIER: u64 = 1_000_000_000;
    const CURVE1_MULTIPLIER: u64 = 100;
    const CURVE2_MULTIPLIER: u64 = 1_000_000_000_000;
    const REFCLK: u64 = 38_400_000; // prescaler_divider 0
    const CP_INT_GS: u8 = 30;
    const CP_PROP_GS: u8 = 28;

    // compute_hdmi_tmds_pll
    let datarate = u64::from(port_clock_khz).wrapping_mul(10_000);
    if datarate == 0 {
        return None;
    }
    let (v2i, tx_clk_div) = if datarate <= HZ_9999 {
        (2u64, (HZ_9999 / datarate).checked_ilog2()?)
    } else {
        (3, (HZ_16G / datarate).checked_ilog2()?)
    };
    let mut vco_clk = datarate.wrapping_shl(tx_clk_div) >> 1;
    let integer = div_down(vco_clk, REFCLK)? as u32;
    let rem = vco_clk % REFCLK;
    vco_clk /= REFCLK; // do_div leaves the quotient here
    let fracn = div_down(rem << 32, REFCLK)? as u32;
    let fracn_quot = fracn >> 16;
    let mut fracn_rem = fracn & 0xFFFF;
    fracn_rem -= fracn_rem >> 15;
    let fracn_den: u32 = 0xFFFF;
    let fracn_en = u8::from(fracn_quot != 0 || fracn_rem != 0);
    let multiplier = integer.wrapping_sub(16).wrapping_mul(2);
    let c = (v2i - 2) as usize;
    let (mut a, mut ana_freq_vco) = (0usize, 0u8);
    for i in (0..8).step_by(2) {
        if vco_clk <= FREQ[c][i + 1] {
            a = i;
            ana_freq_vco = 3 - (a >> 1) as u8;
            break;
        }
    }

    // get_ana_cp_int_prop
    let vco_div_refclk = vco_clk.wrapping_mul(div_down(1_000_000_000_000, REFCLK)?);
    let (x1, x2) = (FREQ[c][a], FREQ[c][a + 1]);
    let c0 = interp(vco_clk, x1, x2, CURVE_0[c][a], CURVE_0[c][a + 1])?;
    let c2 = interp(vco_clk, x1, x2, CURVE_2[c][a], CURVE_2[c][a + 1])?;
    let c1 = interp(vco_clk, x1, x2, CURVE_1[c][a], CURVE_1[c][a + 1])?;
    let c1 = div_down(c1, CURVE1_MULTIPLIER)?;
    let temp = c2.wrapping_mul(4 - v2i);
    let c2_scaled1 = div_down(temp, 16_000)?;
    let c2_scaled2 = div_down(temp, 160)?;
    let scaled1 = 112_008_301u64.wrapping_mul(div_down(vco_div_refclk, 100_000)?);
    let adjusted1 = CURVE2_MULTIPLIER.wrapping_mul(div_down(
        scaled1,
        c0.wrapping_mul(div_down(c1, CURVE0_MULTIPLIER)?),
    )?);
    let cp_int = div64_closest(div_down(adjusted1, c2_scaled1)?, CURVE2_MULTIPLIER)?.clamp(1, 127);
    let c2_scaled_int = c2_scaled1.wrapping_mul(cp_int);
    let product = c1.wrapping_mul(c2_scaled_int.wrapping_mul(div_down(c0, CURVE0_MULTIPLIER)?));
    let sqrt =
        int_sqrt(div64_up(product, vco_div_refclk)?.wrapping_mul(div_down(1_000_000_000_000, 55)?));
    let scaled2 = div_up_ull(vco_div_refclk, 1_000_000)?;
    let adjusted2 = 1_460_281u64.wrapping_mul(div64_up(sqrt.wrapping_mul(scaled2), c1)?);
    // `*ana_cp_prop` is a u32: the quotient truncates before the clamp.
    let cp_prop = u64::from((div64_up(adjusted2, c2_scaled2)? as u32).clamp(1, 127));
    let (cp_int, cp_prop, v2i) = (cp_int as u8, cp_prop as u8, v2i as u8);

    let mut pll = [0u8; 20];
    // C10_PLL0: DIV5CLK_EN (mpll_div5_en 1), FRACEN, PMIX_EN (= fracn_en),
    // ANA_FREQ_VCO.
    pll[0] = (1 << 2) | (fracn_en << 4) | (fracn_en << 5) | ((ana_freq_vco & 3) << 6);
    pll[2] = multiplier as u8;
    pll[3] = ((multiplier >> 8) & 0xF) as u8;
    pll[8] = 1 << 5; // SSC_UP_SPREAD
    pll[9] = fracn_den as u8;
    pll[10] = (fracn_den >> 8) as u8;
    pll[11] = fracn_quot as u8;
    pll[12] = (fracn_quot >> 8) as u8;
    pll[13] = fracn_rem as u8;
    pll[14] = (fracn_rem >> 8) as u8;
    // TXCLKDIV (2:0) | HDMIDIV(1) (5:3)
    pll[15] = (tx_clk_div as u8 & 7) | (1 << 3);
    // REG_FIELD_PREP masks each field, as the C does.
    pll[16] = (cp_int & 0x7F) | ((CP_INT_GS << 7) & 0x80);
    pll[17] = ((CP_INT_GS >> 1) & 0x3F) | ((cp_prop << 6) & 0xC0);
    pll[18] = ((cp_prop >> 2) & 0x1F) | ((CP_PROP_GS << 5) & 0xE0);
    pll[19] = ((CP_PROP_GS >> 3) & 0xF) | ((v2i << 4) & 0x30);
    Some(C10PllState {
        tx: 0x10,
        cmn: 0x01,
        pll,
    })
}

/// Resolve the HDMI TMDS PLL request for `port` at `clock_khz`
/// (`intel_c10pll_calc_state` / `intel_c20pll_calc_state`, table path).
pub fn hdmi_pll_request(
    port: XeLpgPort,
    clock_khz: u32,
    legacy: bool,
) -> Result<PllRequest, HdmiError> {
    hdmi_pll_request_computed(port, clock_khz, legacy, None)
}

/// [`hdmi_pll_request`] with Linux's C20 fallback: a C20 clock with no
/// ideal table is computed (`intel_c20pll_calc_state` tries the tables
/// first, "since the calculated values, although correct, may not be
/// optimal") when the platform's `tx[1]` word is known. C10 always falls
/// back to the SNPS algorithm (`compute_c10_hdmi_tmds`).
pub fn hdmi_pll_request_computed(
    port: XeLpgPort,
    clock_khz: u32,
    legacy: bool,
    c20_tx_cfg1: Option<u16>,
) -> Result<PllRequest, HdmiError> {
    hdmi_pll_request_kind(port.phy(), clock_khz, legacy, c20_tx_cfg1)
}

/// [`hdmi_pll_request_computed`] for the PHY `kind` behind the port
/// ([`crate::intel_gpu_xelpg::phy_kind`]: Panther Lake's DDI B is a C20).
pub fn hdmi_pll_request_kind(
    kind: PhyKind,
    clock_khz: u32,
    legacy: bool,
    c20_tx_cfg1: Option<u16>,
) -> Result<PllRequest, HdmiError> {
    if is_frl(clock_khz) {
        return Err(HdmiError::FrlClock(clock_khz));
    }
    if clock_khz < MIN_TMDS_KHZ {
        return Err(HdmiError::UnsupportedClock(clock_khz));
    }
    if clock_khz > SOURCE_MAX_TMDS_KHZ {
        return Err(HdmiError::UnsupportedClock(clock_khz));
    }
    let state = match kind {
        PhyKind::C10 => {
            // intel_c10pll_calc_state: the tables, then for HDMI the SNPS
            // algorithm.
            let mut state = C10_HDMI_TABLES
                .iter()
                .find(|(clock, _)| *clock == clock_khz)
                .map(|(_, state)| *state)
                .or_else(|| compute_c10_hdmi_tmds(clock_khz))
                .ok_or(HdmiError::UnsupportedClock(clock_khz))?;
            // intel_c10pll_update_pll: HDMI has no SSC.
            for byte in &mut state.pll[4..9] {
                *byte = 0;
            }
            Cx0PllState::C10(state)
        }
        PhyKind::C20 => {
            let state = C20_HDMI_TMDS_TABLES
                .iter()
                .find(|(clock, _)| *clock == clock_khz)
                .map(|(_, state)| *state)
                .or_else(|| c20_tx_cfg1.and_then(|cfg| compute_c20_hdmi_tmds(clock_khz, cfg)))
                .ok_or(HdmiError::UnsupportedClock(clock_khz))?;
            Cx0PllState::C20(state, C20Vdr::hdmi_tmds())
        }
    };
    Ok(PllRequest {
        lanes: crate::intel_gpu_xelpg::PhyLaneConfig::NATIVE,
        state,
        port_clock_khz: clock_khz,
        lane_count: HDMI_LANES,
        dp_alt: false,
        ssc: false,
        hdmi: true,
        protocol_switch: legacy && kind == PhyKind::C20,
    })
}

/// The LT-PHY TMDS request at `clock_khz` (display 35): the source
/// envelope and the shared request fields of [`hdmi_pll_request_kind`],
/// admitted only when `intel_lt_phy_pll_calc_state` has an image for the
/// clock (`xe3plpd_lt_hdmi_tables`, then `intel_lt_phy_calculate_hdmi_state`).
/// The request's Cx0 state is never programmed: the route enables the LT PLL
/// from its port clock ([`crate::intel_gpu_lt_phy::LtPhy::enable_hdmi_tmds`]).
fn lt_hdmi_request(clock_khz: u32) -> Result<PllRequest, HdmiError> {
    let request = hdmi_pll_request_kind(PhyKind::C10, clock_khz, false, None)?;
    crate::intel_gpu_lt_phy::hdmi_pll_state(clock_khz)
        .ok_or(HdmiError::UnsupportedClock(clock_khz))?;
    Ok(request)
}

/// The LT PHY behind `port` for a TMDS route on display 35; `None` on a
/// Cx0 view. HDMI drives all four transmitters, natively (legacy Type-C
/// included), with the VBT's board reversal.
fn hdmi_lt_phy<'a, M: MmioWindow + ?Sized>(
    io: &'a M,
    port: XeLpgPort,
    pll: &PllRequest,
) -> Result<Option<crate::intel_gpu_lt_phy::LtPhy<'a, M>>, HdmiError> {
    crate::intel_gpu_xelpg_external::lt_phy(io, port, false, HDMI_LANES, pll.lanes.reversed())
        .map_err(HdmiError::Route)
}

/// The DDC pin of an HDMI-capable MTL port, valid in `gmbus_pins_mtp`.
/// DDI B is `intel_hdmi_default_ddc_pin`'s `dg1_encoder_to_ddc_pin`
/// (`PCH_MTL >= PCH_DG1`: PHY B + 1 = `GMBUS_PIN_2_BXT`, "dpb"). That
/// formula gives Type-C (PHY F..I) pins 6..9, which the MTP table does
/// not wire to TC1..TC4, so Linux takes a Type-C port's DDC only from its
/// VBT child (`intel_bios_hdmi_ddc_pin`, mapped by `map_ddc_pin` with
/// `adlp_ddc_pin_map`: `ADLP_DDC_BUS_PORT_TCn` = `GMBUS_PIN_9_TC1_ICP +
/// n - 1`, "tc1".."tc4"). A hand-declared legacy port carries that VBT
/// fact here: TCn's DDC is the MTP "tcn" pin. DDI A (internal) has none.
/// A policy derived from a parsed VBT carries `intel_hdmi_ddc_pin`'s
/// own result instead (`MtlPortDecl::ddc_pin`).
pub const fn ddc_pin(port: XeLpgPort) -> Option<PinPair> {
    match port {
        XeLpgPort::A => None,
        XeLpgPort::B => Some(PinPair::Pin2Bxt),
        XeLpgPort::Tc1 => Some(PinPair::Pin9Tc1),
        XeLpgPort::Tc2 => Some(PinPair::Pin10Tc2),
        XeLpgPort::Tc3 => Some(PinPair::Pin11Tc3),
        XeLpgPort::Tc4 => Some(PinPair::Pin12Tc4),
    }
}

/// Probe result owning the (legacy) Type-C connection.
#[derive(Clone, Debug)]
pub struct MtlHdmiProbe {
    /// The port.
    pub port: XeLpgPort,
    /// The display IP the route runs on (its D2D register, `DDI_BUF_CTL`
    /// value, pipe resources and display-30 VRR timing generator).
    pub(crate) display_ip: DisplayIp,
    /// Legacy Type-C ownership (TC ports only).
    pub tc: Option<TcConnection>,
    /// Preferred mode.
    pub mode: Mode,
    /// The resolved PLL request for the mode's TMDS clock.
    pub pll: PllRequest,
    /// The sink's SCDC/scrambling capability.
    pub sink: SinkScdc,
    /// The scrambling state the source drives for the mode.
    pub link: TmdsLink,
    /// The DDC pin EDID and SCDC traffic use (the port policy's
    /// `intel_hdmi_ddc_pin` result).
    pub ddc: PinPair,
    /// The output format (`intel_hdmi_compute_output_format`).
    pub format: crate::intel_gpu_hdmi::SinkFormat,
    /// The pipe's bpc (`intel_hdmi_compute_bpc`): 8, or 10 or 12 under
    /// `narf.intel.hdmi14_ext=1` ([`crate::intel_gpu_xelpg_external::color`]).
    pub bpc: u8,
    /// The probe ran under `narf.intel.hdmi14_ext=1`: the route sends the
    /// General Control Packet to an HDMI sink
    /// (`intel_hdmi_compute_gcp_infoframe`).
    pub ext: bool,
    /// The sink's ELD (`drm_edid_to_eld`) when the route enables audio
    /// (`narf.intel.hdmi14_ext=1`, `intel_hdmi_has_audio`: an HDMI sink
    /// that declares basic audio or audio descriptors).
    pub audio: Option<alloc::boxed::Box<[u8; crate::intel_gpu_xelpg_external::audio::MAX_ELD_BYTES]>>,
    /// EDID bytes (`edid_len` valid).
    pub edid: alloc::boxed::Box<[u8; crate::intel_gpu_hdmi::EDID_CAPACITY]>,
    /// Valid EDID length.
    pub edid_len: usize,
}

/// Read the sink's EDID over DDC the way `drm_do_probe_ddc_edid` does:
/// each 128-byte block is an offset write followed by a read at slave
/// 0x50, which `intel_gmbus.c::do_gmbus_xfer` runs as one INDEX-cycle
/// transfer; blocks 2 and 3 chain the E-DDC segment pointer ahead of it
/// with a repeated START ([`crate::intel_gpu_gmbus::read_edid_eddc`]).
pub fn read_edid_ddc<M: MmioWindow + ?Sized>(
    io: &M,
    pin: PinPair,
) -> Result<([u8; crate::intel_gpu_hdmi::EDID_CAPACITY], usize), HdmiError> {
    crate::intel_gpu_hdmi::read_edid(io, pin).map_err(HdmiError::Ddc)
}

/// Probe an HDMI sink: Type-C legacy connect (TC only), DDC EDID,
/// preferred mode and its TMDS PLL request. `ddc` is the port's DDC pin
/// from the board policy (`None`: the port has no usable DDC pin, as
/// `intel_hdmi_init_connector` refuses). Refusals precede MMIO where
/// possible; a Type-C connection is rolled back on failure.
pub fn probe_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
    ddc: Option<PinPair>,
) -> Result<MtlHdmiProbe, HdmiError> {
    let profile = ExternalDisplayProfile::for_generation(generation)
        .ok_or(HdmiError::Route(ExternalError::UnsupportedGeneration))?;
    probe_hdmi_profile(io, profile, port, legacy_port, ddc)
}

/// [`probe_hdmi`] for an exact source profile. Meteor, Lunar and Panther
/// Lake drive HDMI on their admitted ports; Wildcat Lake's 30.02 profile
/// has no qualified HDMI route. Deep colour follows
/// `narf.intel.hdmi14_ext`.
pub(crate) fn probe_hdmi_profile<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    port: XeLpgPort,
    legacy_port: bool,
    ddc: Option<PinPair>,
) -> Result<MtlHdmiProbe, HdmiError> {
    probe_hdmi_profile_ext(
        io,
        profile,
        port,
        legacy_port,
        ddc,
        crate::intel_gpu_xelpg_external::color::opted_in(),
    )
}

/// [`probe_hdmi_profile`] with an explicit `narf.intel.hdmi14_ext` decision.
pub(crate) fn probe_hdmi_profile_ext<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    port: XeLpgPort,
    legacy_port: bool,
    ddc: Option<PinPair>,
    ext: bool,
) -> Result<MtlHdmiProbe, HdmiError> {
    let display_ip = profile.display_ip();
    if display_ip == DisplayIp::WildcatLake {
        return Err(ExternalError::UnsupportedGeneration.into());
    }
    if port == XeLpgPort::A || !profile.admits_port(port) {
        return Err(ExternalError::UnsupportedPort.into());
    }
    if !profile.admits_view(io) {
        return Err(ExternalError::UnsupportedGeneration.into());
    }
    let type_c = port.tc_index().is_some();
    if type_c && !legacy_port {
        return Err(HdmiError::NotLegacy);
    }
    let pin = ddc.ok_or(HdmiError::DdcUnavailable)?;
    // A legacy Type-C port is owned in legacy mode before its DDC is used,
    // as the DP probe owns the PHY before AUX.
    let tc = if type_c {
        let conn = tc_connect_for(io, port, true, HDMI_LANES, profile.tc_profile())?;
        if conn.mode != TcMode::Legacy {
            let _ = tc_disconnect(io, &conn);
            return Err(HdmiError::NotLegacy);
        }
        Some(conn)
    } else {
        None
    };
    let rollback = |e: HdmiError| {
        if let Some(conn) = tc {
            let _ = tc_disconnect(io, &conn);
        }
        e
    };
    let (edid, edid_len) = read_edid_ddc(io, pin).map_err(rollback)?;
    let mode = crate::intel_gpu_dp::mode_from_edid(&edid[..edid_len])
        .map_err(|_| rollback(HdmiError::Edid))?;
    let sink = parse_sink_scdc(&edid[..edid_len]);
    let (format, bpc, pll, link) = output_for(
        io,
        display_ip,
        port,
        type_c,
        &mode,
        &edid[..edid_len],
        &sink,
        ext,
    )
    .map_err(rollback)?;
    if !io.display_access_ok() {
        return Err(rollback(ExternalError::AccessLost.into()));
    }
    Ok(MtlHdmiProbe {
        port,
        display_ip,
        tc,
        mode,
        pll,
        sink,
        link,
        ddc: pin,
        format,
        bpc,
        ext,
        audio: hdmi_audio(&edid[..edid_len], ext).map(alloc::boxed::Box::new),
        edid: alloc::boxed::Box::new(edid),
        edid_len,
    })
}

/// `intel_hdmi_has_audio` under `narf.intel.hdmi14_ext=1`: an HDMI sink
/// whose `display_info.has_audio` holds (basic audio or an audio data
/// block) gets audio with Linux's connector ELD (`drm_edid_to_eld`), SADs
/// or none.
fn hdmi_audio(
    edid: &[u8],
    ext: bool,
) -> Option<[u8; crate::intel_gpu_xelpg_external::audio::MAX_ELD_BYTES]> {
    use crate::intel_gpu_xelpg_external::audio;
    if !ext || !crate::intel_gpu_hdmi::is_hdmi_sink(edid) || !audio::edid_has_audio(edid) {
        return None;
    }
    Some(audio::eld_from_edid(edid, false))
}

/// The output an HDMI probe resolves: format, pipe bpc, PLL request and
/// TMDS link.
type HdmiOutput = (crate::intel_gpu_hdmi::SinkFormat, u8, PllRequest, TmdsLink);

/// `intel_hdmi_compute_output_format` for `mode` on `port`: a 4:2:0-only
/// VIC (Y420VDB) goes out as YCbCr 4:2:0 on an HDMI sink, any other mode as
/// RGB, falling back to 4:2:0 when RGB has no valid TMDS link and the VIC is
/// 4:2:0-also (Y420CMDB). 4:2:0 halves the TMDS clock
/// (`intel_hdmi_tmds_clock`) and needs the pipe scaler, which takes at most
/// 8192 active pixels (`skl_scaler_mode_valid` compares `hdisplay` with
/// the display-14 maximum source height). Display 30 is not qualified for
/// it: its VRR timing-generator guardband carries no scaler prefill here.
///
/// Each format runs at 8 bpc, or with `ext` (`narf.intel.hdmi14_ext=1`) at
/// `intel_hdmi_compute_bpc`'s depth: from the pipe maximum
/// ([`crate::intel_gpu_xelpg_external::color::max_pipe_bpp`]) down in steps
/// of 2 bpc, the first above 8 that `hdmi_bpc_possible` and
/// `hdmi_port_clock_valid` admit at its TMDS clock and whose PLL and TMDS
/// link resolve; 8 bpc when none does. A depth whose PLL this driver cannot
/// build (a C20 clock without a table or the platform's `tx[1]` fact)
/// steps down where Linux would compute it.
#[allow(clippy::too_many_arguments)]
fn output_for<M: MmioWindow + ?Sized>(
    io: &M,
    ip: DisplayIp,
    port: XeLpgPort,
    type_c: bool,
    mode: &Mode,
    edid: &[u8],
    sink: &SinkScdc,
    ext: bool,
) -> Result<HdmiOutput, HdmiError> {
    use crate::intel_gpu_hdmi::{
        parse_hdmi_vsdb, parse_ycbcr420, tmds_clock_for, vic_for_mode, SinkFormat,
    };
    use crate::intel_gpu_xelpg_external::color;
    let kind = crate::intel_gpu_xelpg::phy_kind(io, port);
    let lt = io.has_lt_phy();
    let link_for = |format, bpc| -> Result<HdmiOutput, HdmiError> {
        let clock = tmds_clock_for(mode.pixel_clock_khz, bpc, format);
        let pll = if lt {
            lt_hdmi_request(clock)?
        } else {
            hdmi_pll_request_kind(kind, clock, type_c, io.c20_hdmi_tx_cfg1())?
        };
        Ok((format, bpc, pll, tmds_link(clock, sink)?))
    };
    let y420 = parse_ycbcr420(edid);
    let vsdb = parse_hdmi_vsdb(edid);
    let start = if ext {
        (color::max_pipe_bpp(color::sink_display_bpc(edid)) / 3).max(8) as u8
    } else {
        8
    };
    let limit = color::hdmi_port_clock_limit(edid);
    let with_depth = |format| -> Result<HdmiOutput, HdmiError> {
        let mut bpc = start;
        while bpc > 8 {
            let tmds = tmds_clock_for(mode.pixel_clock_khz, bpc, format);
            if color::sink_bpc_possible(bpc, vsdb, &y420, format)
                && color::hdmi_port_clock_valid(tmds, limit, type_c)
            {
                if let Ok(output) = link_for(format, bpc) {
                    return Ok(output);
                }
            }
            bpc -= 2;
        }
        link_for(format, 8)
    };
    let vic = vic_for_mode(mode);
    let allowed = vsdb.is_some() && !ip.is_display30() && mode.h_active <= 8192;
    let result = if allowed && y420.only(vic) {
        with_depth(SinkFormat::Ycbcr420)
    } else {
        match with_depth(SinkFormat::Rgb) {
            Err(e) if allowed && y420.also(vic) => {
                with_depth(SinkFormat::Ycbcr420).map_err(|_| e)
            }
            result => result,
        }
    };
    result.map_err(|e| frl_refusal(e, edid))
}

/// A clock above the 600 MHz source maximum on a sink that declares FRL
/// (`intel_hdmi_sink_max_frl_rate` nonzero) is [`HdmiError::FrlUnsupported`]:
/// only FRL could carry it, and Linux has no native FRL training.
fn frl_refusal(e: HdmiError, edid: &[u8]) -> HdmiError {
    match e {
        HdmiError::UnsupportedClock(clock_khz) | HdmiError::FrlClock(clock_khz)
            if clock_khz > SOURCE_MAX_TMDS_KHZ =>
        {
            match parse_sink_frl(edid).max_frl_rate() {
                0 => e,
                sink_max_frl_gbps => HdmiError::FrlUnsupported {
                    clock_khz,
                    sink_max_frl_gbps,
                },
            }
        }
        e => e,
    }
}

/// Release a probe's Type-C ownership (DDI B owns nothing).
pub fn release_hdmi_probe<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlHdmiProbe,
) -> Result<(), HdmiError> {
    match probe.tc {
        Some(conn) => tc_disconnect(io, &conn).map_err(HdmiError::from),
        None => Ok(()),
    }
}

/// Lifecycle of an HDMI route (same meaning as the DP route's).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdmiRouteState {
    /// Scanning out.
    Live,
    /// Locally stopped and observed.
    Stopped,
    /// A stop step was not observed; leases retained.
    Quarantined,
}

/// One owned HDMI route on a Pipe B–D.
#[derive(Clone, Debug)]
pub struct MtlHdmiRoute {
    /// The probe.
    pub probe: MtlHdmiProbe,
    /// The scanned-out framebuffer.
    pub fb: Framebuffer,
    state: HdmiRouteState,
    /// The Pipe B–D (and transcoder) the route was activated on.
    pipe: Pipe,
    /// The pipe's reservation until its post-plane release is proven.
    reservation: Option<RoutePipe>,
    /// The Pipe B–D owner as the proven release left it, until a sibling
    /// route adopts it.
    retired: Option<Pipes>,
    /// The audio stream `intel_audio_codec_enable` started, until its
    /// disable.
    audio: Option<crate::intel_gpu_xelpg_external::audio::AudioStream>,
}

fn wr<M: MmioWindow + ?Sized>(io: &M, off: u64, value: u32) -> Result<(), HdmiError> {
    io.write32(off, value);
    compiler_fence(Ordering::SeqCst);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(ExternalError::AccessLost.into())
    }
}

fn rd<M: MmioWindow + ?Sized>(io: &M, off: u64) -> Result<u32, HdmiError> {
    let v = io.read32(off);
    if v == u32::MAX || !io.display_access_ok() {
        Err(ExternalError::AccessLost.into())
    } else {
        Ok(v)
    }
}

impl From<PipeEnableError> for HdmiError {
    fn from(e: PipeEnableError) -> Self {
        HdmiError::Route(e.into())
    }
}

/// Program and light the HDMI route on a free Pipe B–D next to what Pipe A
/// runs (`display`), in `intel_atomic_commit_tail` (pre-plane resources)
/// → `hsw_crtc_enable` (pipe DMC, `intel_ddi_pre_enable_hdmi`, pipe and
/// transcoder) → `intel_ddi_enable` → `intel_ddi_enable_hdmi` →
/// `intel_update_crtc` order. Every refusal precedes the first write and
/// returns the probe; programming failures return a `Stopped` or
/// `Quarantined` route.
// Refusal hands the owned probe/route back inline: it must not allocate.
#[allow(clippy::result_large_err)]
pub fn activate_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlHdmiProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
) -> Result<MtlHdmiRoute, (Result<MtlHdmiRoute, MtlHdmiProbe>, HdmiError)> {
    activate_hdmi_beside(io, probe, fb, display, None)
}

/// [`activate_hdmi`] beside a live sibling route whose Pipe B–D owner is
/// `beside` (`narf.intel.ext_routes=2`): the new pipe joins that layout.
#[allow(clippy::result_large_err)]
pub(crate) fn activate_hdmi_beside<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlHdmiProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
    beside: Option<Pipes>,
) -> Result<MtlHdmiRoute, (Result<MtlHdmiRoute, MtlHdmiProbe>, HdmiError)> {
    if let Err(e) = crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &probe.mode) {
        return Err((Err(probe), ExternalError::Modeset(e).into()));
    }
    let choice = match preflight_ip(io, probe.port, display, probe.display_ip, beside) {
        Ok(choice) => choice,
        Err(e) => return Err((Err(probe), e.into())),
    };
    if let Some(conn) = probe.tc {
        if connection_intact(io, &conn) != Ok(true) {
            return Err((Err(probe), HdmiError::NotLegacy));
        }
    }
    // crtc_state->port_clock is the TMDS clock for HDMI.
    let mut ext = match external_pipe(
        &choice,
        probe.port,
        &probe.mode,
        &fb,
        probe.pll.port_clock_khz,
        None,
        u32::from(probe.bpc) * 3,
    ) {
        Ok(ext) => ext,
        Err(e) => return Err((Err(probe), e.into())),
    };
    // A 4:2:0 stream's 1:1 scaler joins the pipe's prefill term.
    if probe.format == crate::intel_gpu_hdmi::SinkFormat::Ycbcr420 {
        ext.scaler = Some(crate::intel_gpu_modeset::ycbcr420_scaler(&probe.mode));
    }
    ext.audio = probe.audio.is_some();
    if let Err(e) = choice.pipes.admit(io, &ext) {
        return Err((Err(probe), e.into()));
    }
    let mut route = MtlHdmiRoute {
        probe,
        fb,
        state: HdmiRouteState::Stopped,
        pipe: choice.pipe,
        reservation: None,
        retired: None,
        audio: None,
    };
    let dmc = display.pipe_dmc;
    let result = request_pipe_wells(io, ext.pipe)
        .and_then(|()| reserve_audio_pipe(io, choice, &ext, dmc))
        .map_err(HdmiError::from)
        .and_then(|rp| {
            route.reservation = Some(rp);
            program_hdmi(io, &mut route)
        });
    match result {
        Ok(()) => {
            route.state = HdmiRouteState::Live;
            Ok(route)
        }
        Err(e) => {
            route.state = match stop_hdmi_local(io, &mut route) {
                Ok(()) => HdmiRouteState::Stopped,
                Err(_) => HdmiRouteState::Quarantined,
            };
            Err((Ok(route), e))
        }
    }
}

/// [`reserve_pipe`] bracketed, for a pipe with audio, by
/// `intel_audio_cdclk_change_pre` / `_post` (the transaction may move
/// CDCLK, and `AUD_TS_CDCLK_M/N` follow it).
pub(crate) fn reserve_audio_pipe<M: MmioWindow + ?Sized>(
    io: &M,
    choice: crate::intel_gpu_xelpg_external::PipeChoice,
    ext: &crate::intel_gpu_xelpg_pipes::ExternalPipe,
    dmc: &'static (dyn crate::intel_gpu_dc_states::PipeDmc + Sync),
) -> Result<RoutePipe, ExternalError> {
    use crate::intel_gpu_xelpg_external::audio;
    if ext.audio {
        audio::cdclk_change_pre(io).map_err(|_| ExternalError::AccessLost)?;
    }
    let result = reserve_pipe(io, choice, ext, dmc);
    if ext.audio {
        let _ = audio::cdclk_change_post(io);
    }
    result
}

fn reservation(route: &mut MtlHdmiRoute) -> Result<&mut RoutePipe, HdmiError> {
    route
        .reservation
        .as_mut()
        .ok_or(HdmiError::Route(ExternalError::Pipe(PipeRefusal::Sequence)))
}

fn program_hdmi<M: MmioWindow + ?Sized>(io: &M, route: &mut MtlHdmiRoute) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    let link = route.probe.link;
    let (scrambling, ddc, pll, ip, format) = (
        route.probe.sink.scrambling,
        route.probe.ddc,
        route.probe.pll,
        route.probe.display_ip,
        route.probe.format,
    );
    let bpc = route.probe.bpc;
    // intel_hdmi_compute_gcp_infoframe (narf.intel.hdmi14_ext=1): every
    // HDMI sink with infoframes gets the General Control Packet.
    let gcp = route.probe.ext
        && crate::intel_gpu_hdmi::is_hdmi_sink(&route.probe.edid[..route.probe.edid_len]);
    let rp = reservation(route)?;
    let (pipe, trans) = (rp.pipe, rp.transcoder());
    // intel_ddi_pre_enable_hdmi: PLL (intel_lt_phy_pll_enable on display
    // 35), transcoder clock, infoframes.
    match hdmi_lt_phy(io, port, &pll)? {
        Some(lt) => lt
            .enable_hdmi_tmds(crate::intel_gpu_lt_phy::LtHdmiEnable {
                clock_khz: pll.port_clock_khz,
                lane_count: HDMI_LANES,
            })
            .map_err(phy_err)?,
        None => enable_port_pll_state(io, port, &pll).map_err(phy_err)?,
    }
    wr(io, trans_clk_sel(trans), trans_clk_sel_port(port))?;
    crate::intel_gpu_hdmi::write_avi_infoframe(
        io,
        trans,
        &crate::intel_gpu_hdmi::pack_avi_infoframe_for(&mode, format),
    );
    if gcp {
        crate::intel_gpu_hdmi::write_gcp(io, trans, bpc, &mode);
    }
    // hsw_crtc_enable: source size, timings, RGB bypass (pipe off).
    rp.pipes.program_timings(io, pipe)?;
    // A 4:2:0 stream: bdw_set_pipe_misc's YUV encoding, skl_pfit_enable's
    // 1:1 downsampler and the RGB-to-YCbCr output CSC, still pipe off.
    if format == crate::intel_gpu_hdmi::SinkFormat::Ycbcr420 {
        let misc = pipe.base() + crate::intel_gpu_xelpg_dsc::PIPE_MISC_OFFSET;
        let cur = rd(io, misc)?;
        wr(io, misc, cur | crate::intel_gpu_modeset::PIPE_MISC_YCBCR420)?;
        crate::intel_gpu_modeset::program_ycbcr420_pipe(io, pipe, &mode);
    }
    // intel_ddi_enable: transcoder function, then the transcoder.
    // TRANS_DDI_BPC_10 / _12 for a deep-colour pipe (BPC_8 is 0).
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(
        port.func_ctl_index(),
        link.scrambling,
        link.high_tmds_clock_ratio,
    ) | crate::intel_gpu_xelpg_dsc::trans_ddi_bpc(u32::from(bpc) * 3);
    wr(io, trans_ddi_func_ctl(trans), func)?;
    // Display 30 always scans out through the VRR timing generator,
    // programmed and enabled after TRANS_DDI_FUNC_CTL and before TRANSCONF
    // (a no-op on display 14 and 20).
    rp.pipes.enable_fixed_tg(io, pipe)?;
    let start = rd(io, pipe.base() + FRMCOUNT)?;
    rp.pipes.enable(io, pipe)?;
    // intel_ddi_enable_hdmi (display 14+): sink scrambling/ratio over
    // SCDC (only for a scrambling-capable sink), D2D, levels,
    // PORT_BUF_CTL1 width, DDI_CTL_DE with the TMDS lane width, buffer
    // active. Linux only logs an SCDC failure; a stream that needs the
    // sink scrambling cannot work without it, so that failure stops here.
    if scrambling {
        let scdc = sink_scrambling(io, ddc, link.high_tmds_clock_ratio, link.scrambling);
        if scdc.is_err() && (link.scrambling || link.high_tmds_clock_ratio) {
            return scdc;
        }
    }
    // D2D lives in PORT_BUF_CTL1 on display 14 and in DDI_BUF_CTL on
    // display 20+, where the DDI_BUF_CTL write keeps it set
    // (XE2LPD_DDI_BUF_D2D_LINK_ENABLE in intel_ddi_enable_hdmi's buf_ctl).
    enable_d2d(io, ip, port).map_err(d2d_err)?;
    match hdmi_lt_phy(io, port, &pll)? {
        // intel_lt_phy_set_signal_levels: the DP 1.4 table at
        // intel_ddi_hdmi_level on every transmitter (no VBT level here).
        Some(lt) => {
            let (level, _) = crate::intel_gpu_lt_phy::hdmi_signal_level(None);
            lt.program_signal_levels(
                crate::intel_gpu_lt_phy::LtSignalProtocol::Hdmi,
                &[level; HDMI_LANES as usize],
            )
            .map_err(phy_err)?
        }
        None => {
            set_signal_levels_hdmi(&Cx0Phy::with_lanes(io, port, pll.lanes)).map_err(phy_err)?
        }
    }
    let buf = rd(io, port.buf_ctl1())?;
    wr(
        io,
        port.buf_ctl1(),
        (buf & !PORT_WIDTH_MASK) | port_width(HDMI_LANES),
    )?;
    wr(io, port.ddi_buf_ctl(), ddi_enable_value(ip, HDMI_LANES))?;
    wait_port_buf_active(io, port).map_err(phy_err)?;
    // intel_update_crtc: the primary, armed under vblank evasion.
    rp.pipes.arm_primary(io, pipe)?;
    observe_hdmi(io, route, func, start)?;
    // intel_post_plane_update: intel_encoders_audio_enable.
    let Some(connector_eld) = route.probe.audio.clone() else {
        return Ok(());
    };
    use crate::intel_gpu_xelpg_external::audio;
    let stream = audio::AudioStream {
        trans,
        pipe,
        port: port.port_enum() as i32,
        dp: false,
        uhbr: false,
        crtc_clock_khz: mode.pixel_clock_khz,
        port_clock_khz: pll.port_clock_khz,
        pipe_bpp: u32::from(bpc) * 3,
        lane_count: HDMI_LANES,
        h_active: mode.h_active,
        h_total: mode.h_total,
        v_active: mode.v_active,
        dsc_bpp_x16: None,
        ycbcr420: format == crate::intel_gpu_hdmi::SinkFormat::Ycbcr420,
        wa_14020863754: audio::needs_wa_14020863754(ip),
    };
    let edid = &route.probe.edid[..route.probe.edid_len];
    let eld = audio::compute_eld(&connector_eld, edid, &stream);
    // The shared sink takes the builder's publication (none without SADs).
    let publication = narf_drivers_sound::display_audio::build_eld(
        edid,
        narf_drivers_sound::display_audio::DisplayConnector::Hdmi,
        0,
    );
    // The stream is the route's to disable from here on, even if a step
    // of the enable failed.
    route.audio = Some(stream);
    audio::audio_codec_enable(io, &stream, &eld, publication)
        .map_err(|_| ExternalError::AccessLost.into())
}

fn observe_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlHdmiRoute,
    func: u32,
    start: u32,
) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    let (base, trans) = (route.pipe.base(), route.pipe.transcoder());
    let plane = crate::intel_gpu_pipes::build_primary_plane(
        mode.h_active,
        mode.v_active,
        route.fb.stride_bytes,
        route.fb.phys_addr as u32,
        crate::intel_gpu_pipes::PixelFormat::Argb8888,
    )
    .map_err(|_| ExternalError::Modeset(ModesetError::InvalidFramebuffer))?;
    let dip = trans.base() + crate::intel_gpu_hdmi::VIDEO_DIP_CTL_OFFSET;
    let mut refused = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let frame = io.read32(base + FRMCOUNT);
            let surf = io.read32(base + PLANE_SURF_1);
            let live = io.read32(base + PLANE_SURFLIVE_1);
            let route_now = io.read32(trans_ddi_func_ctl(trans));
            let clock = io.read32(trans_clk_sel(trans));
            let infoframes = io.read32(dip);
            let buf = io.read32(port.buf_ctl1());
            let ddi = io.read32(port.ddi_buf_ctl());
            refused = !io.display_access_ok() || frame == u32::MAX || ddi == u32::MAX;
            refused
                || (frame != start
                    && surf == plane.plane_surf
                    && live == surf
                    && route_now == func
                    && clock == trans_clk_sel_port(port)
                    && infoframes & crate::intel_gpu_hdmi::VIDEO_DIP_ENABLE_AVI != 0
                    && buf & PORT_BUF_PHY_IDLE == 0
                    && ddi & DDI_BUF_CTL_ENABLE != 0)
        },
        narf_time::Deadline::after_ns(100_000_000),
    );
    if !done || refused {
        return Err(ExternalError::Modeset(ModesetError::PipelineEnableUnavailable).into());
    }
    Ok(())
}

/// Local stop in `hsw_crtc_disable` order: plane off
/// (`intel_crtc_disable_planes`), sink scrambling reset
/// (`intel_ddi_disable_hdmi`), transcoder off, function deselect, then
/// `intel_ddi_post_disable_hdmi` (infoframes off, DDI_CTL_DE off + PHY
/// idle, D2D off, transcoder clock off, `intel_cx0pll_disable`), the pipe
/// DMC disable and the post-plane repartition without the pipe. A route
/// that failed before its reservation has nothing to stop: its port is
/// programmed only after it.
fn stop_hdmi_local<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlHdmiRoute,
) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let (scrambling, ddc, ip, format) = (
        route.probe.sink.scrambling,
        route.probe.ddc,
        route.probe.display_ip,
        route.probe.format,
    );
    let stop_failed: HdmiError =
        ExternalError::Modeset(ModesetError::PipelineStopUnavailable).into();
    // intel_pre_plane_update: intel_encoders_audio_disable, before the
    // planes go (best effort: the stop proof is the pipe's).
    let had_audio = route.probe.audio.is_some();
    if let Some(stream) = route.audio.take() {
        let _ = crate::intel_gpu_xelpg_external::audio::audio_codec_disable(io, &stream);
    }
    let Some(rp) = route.reservation.as_mut() else {
        return Ok(());
    };
    let (pipe, trans) = (rp.pipe, rp.transcoder());
    rp.pipes.disable_primary(io, pipe)?;
    // intel_ddi_disable_hdmi (encoder disable, before the transcoder):
    // reset sink scrambling and the 1/10 ratio, best effort as in Linux
    // (an SCDC NACK never replaces the local stop proof).
    if scrambling {
        let _ = sink_scrambling(io, ddc, false, false);
    }
    rp.pipes.disable(io, pipe).map_err(|e| match e {
        PipeEnableError::Timeout => stop_failed,
        e => e.into(),
    })?;
    // skl_scaler_disable and the color/PIPE_MISC state of a 4:2:0 stream.
    if format == crate::intel_gpu_hdmi::SinkFormat::Ycbcr420 {
        crate::intel_gpu_modeset::clear_ycbcr420_pipe(io, pipe);
    }
    let func = rd(io, trans_ddi_func_ctl(trans))?;
    wr(
        io,
        trans_ddi_func_ctl(trans),
        func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE),
    )?;
    crate::intel_gpu_hdmi::disable_infoframes(io, trans);
    let ddi = rd(io, port.ddi_buf_ctl())?;
    wr(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
    wait_port_buf_idle(io, port).map_err(|_| stop_failed)?;
    disable_d2d(io, ip, port).map_err(|_| stop_failed)?;
    wr(io, trans_clk_sel(trans), 0)?;
    match hdmi_lt_phy(io, port, &route.probe.pll).map_err(|_| stop_failed)? {
        Some(lt) => lt.disable().map_err(|_| stop_failed)?,
        None => disable_port_pll_complete(io, port).map_err(|_| stop_failed)?,
    }
    let ddi = rd(io, port.ddi_buf_ctl())?;
    let buf = rd(io, port.buf_ctl1())?;
    let clock = rd(io, port.port_clock_ctl())?;
    if ddi & DDI_BUF_CTL_ENABLE != 0 || buf & PORT_BUF_PHY_IDLE == 0 || clock & 0xCC00_0000 != 0 {
        return Err(stop_failed);
    }
    crate::intel_gpu_xelpg_external::release_audio_pipe(io, rp, had_audio)?;
    route.retired = route.reservation.take().map(|rp| rp.pipes);
    Ok(())
}

impl MtlHdmiRoute {
    /// Lifecycle state.
    pub fn state(&self) -> HdmiRouteState {
        self.state
    }

    /// The external port.
    pub fn port(&self) -> XeLpgPort {
        self.probe.port
    }

    /// The Pipe B–D (and same-index transcoder) the route was activated on.
    pub fn pipe(&self) -> Pipe {
        self.pipe
    }

    /// Whether the pipe's display resources are still reserved.
    pub fn reserved(&self) -> bool {
        self.reservation.is_some()
    }

    /// The Pipe B–D owner this route's reservation holds.
    pub(crate) fn shared_pipes(&self) -> Option<&Pipes> {
        self.reservation.as_ref().map(|rp| &rp.pipes)
    }

    /// Adopt a sibling route's newer Pipe B–D owner (same layout, plus or
    /// minus the sibling's pipe); a route without a reservation keeps none.
    pub(crate) fn adopt_shared_pipes(&mut self, pipes: &Pipes) {
        if let Some(rp) = self.reservation.as_mut() {
            rp.pipes = pipes.clone();
        }
    }

    /// The owner a sibling adopts after this route changed it: the
    /// reservation's, or once the post-release owner the proven stop left.
    pub(crate) fn take_shared_pipes(&mut self) -> Option<Pipes> {
        match self.reservation.as_ref() {
            Some(rp) => Some(rp.pipes.clone()),
            None => self.retired.take(),
        }
    }

    /// Locally stop; a failed stop quarantines the route.
    pub fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), HdmiError> {
        match self.state {
            HdmiRouteState::Stopped => Ok(()),
            HdmiRouteState::Quarantined => Err(ExternalError::Quarantined.into()),
            HdmiRouteState::Live => match stop_hdmi_local(io, self) {
                Ok(()) => {
                    self.state = HdmiRouteState::Stopped;
                    Ok(())
                }
                Err(e) => {
                    self.state = HdmiRouteState::Quarantined;
                    Err(e)
                }
            },
        }
    }

    /// Release the Type-C connection of a stopped route.
    // The retained route returns inline on refusal: it must not allocate.
    #[allow(clippy::result_large_err)]
    pub fn release<M: MmioWindow + ?Sized>(self, io: &M) -> Result<(), (MtlHdmiRoute, HdmiError)> {
        if self.state != HdmiRouteState::Stopped {
            return Err((self, ExternalError::Quarantined.into()));
        }
        match self.probe.tc {
            Some(conn) => tc_disconnect(io, &conn).map_err(|e| (self, e.into())),
            None => Ok(()),
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_hdmi_tests.rs"]
pub mod tests;
