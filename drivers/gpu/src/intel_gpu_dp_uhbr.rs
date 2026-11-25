//! DisplayPort 2.0 UHBR (128b/132b channel coding) for the display-14+
//! external DP route ([`crate::intel_gpu_xelpg_external`]), behind the
//! strict boot option `narf.intel.uhbr=1` ([`BOOT_OPTION`], default off).
//! Without it the route never reads a 128b/132b register and stays 8b/10b.
//!
//! What this module owns, each grounded in Linux 7.4:
//!
//! - **Rates** ([`UhbrRate`]): `DP_LINK_BW_10/13_5/20`, the sink's
//!   `DP_128B132B_SUPPORTED_LINK_RATES` behind `DP_CAP_ANSI_128B132B`
//!   (`intel_dp_set_dpcd_sink_rates`), the LTTPR masking it applies, and the
//!   source set ([`source_rates`]): `mtl_rates` ends 810000, 1000000,
//!   2000000 and `mtl_max_source_rate` caps C10 PHYs and Wildcat Lake at
//!   HBR3, so UHBR10 and UHBR20 exist on the display-14/20/30 C20 ports and
//!   the display-35 LT ports; UHBR13.5 (Battlemage's `bmg_rates`) never.
//! - **Bandwidth** ([`wide_link`], [`mtp_tu`]): `intel_dp_compute_link_config_wide`
//!   over the combined ascending rate list (8b/10b, then UHBR) with
//!   `drm_dp_max_dprx_data_rate`'s 96.71% 128b/132b efficiency and
//!   `drm_dp_bw_overhead`'s 32-bit symbols, then the SST MTP time-slot count
//!   (`intel_dp_mtp_tu_compute_config`) with the link M/N of
//!   `intel_link_compute_m_n` at the 32-bit link symbol clock.
//! - **Training** ([`train`]): `intel_dp_128b132b_link_train`: the intra-hop
//!   AUX check, the LANEx_EQ_DONE sequence with the sink's TX FFE presets
//!   (`intel_dp_128b132b_lane_eq`), the interlane alignment, the
//!   LANEx_CDS_DONE sequence (`intel_dp_128b132b_lane_cds`), then
//!   [`stop_train`] (`intel_dp_stop_link_train`).
//! - **Payload** ([`write_payload`], [`poll_act_handled`]): the 128b/132b SST
//!   VC payload (VCPID 1, slot 0, `tu` slots) of `mtl_ddi_pre_enable_dp` /
//!   `intel_ddi_enable` and its clear in `intel_ddi_post_disable_hdmi_or_sst`.
//!
//! - **Thunderbolt alt mode** (display 30+): the DP tunnel's BW allocation
//!   ([`super::tunnel`]) supplies the tunnelled DPRX's 128b/132b rates
//!   ([`read_sink_rates`]) and caps every configuration
//!   ([`wide_link_capped`]); the port clock is the fabric's UHBR select
//!   (`crate::intel_gpu_xelpg::enable_tbt_clock_khz`).
//!
//! - **LTTPRs** ([`init_lttpr_and_dprx_caps`], [`wake_timeout_setup`]): the
//!   LTTPR common capabilities cap the link (`drm_dp_lttpr_max_link_rate`,
//!   `drm_dp_lttpr_max_lane_count`) and mask the UHBR rates; the 128b/132b
//!   route switches the repeaters to non-transparent mode
//!   (`intel_dp_init_lttpr_and_dprx_caps`, `drm_dp_lttpr_init`), grants their
//!   extended wake timeout and trains with the repeater count (the CDS
//!   budget). 128b/132b training has no per-hop phase: Linux trains the
//!   whole path from the DPRX's status. The 8b/10b route keeps the repeaters
//!   transparent (the per-hop `intel_dp_link_train_all_phys` is not
//!   implemented), so a 128b/132b route hands them back to transparent mode
//!   when it stops.
//!
//! Not implemented, refused typed ([`UhbrRefusal`]) instead of running a
//! link Linux would not: 128b/132b MST, DSC on a link whose common rates
//! include UHBR, Thunderbolt-alt UHBR on display 14/20 (no TBT UHBR clock
//! select), and the reduced-parameter retry after a failed 128b/132b
//! training.

use crate::dp_aux::{AuxChannel, AuxError};
use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_xe2lpd::DisplayIp;
use crate::intel_gpu_xelpg_dsc as dsc;

/// The strict boot option.
pub const BOOT_OPTION: &str = "narf.intel.uhbr";

/// `narf.intel.uhbr=1` is on the command line.
pub fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), BOOT_OPTION)
}

// ── DPCD (drm_dp.h) ──────────────────────────────────────────────

/// `DP_MAIN_LINK_CHANNEL_CODING` (in the receiver capability field).
const DP_MAIN_LINK_CHANNEL_CODING: usize = 0x006;
/// `DP_CAP_ANSI_128B132B`.
const DP_CAP_ANSI_128B132B: u8 = 1 << 1;
/// `DP_MAX_LANE_COUNT` and its `DP_POST_LT_ADJ_REQ_SUPPORTED` bit.
const DP_MAX_LANE_COUNT: usize = 0x002;
const DP_POST_LT_ADJ_REQ_SUPPORTED: u8 = 1 << 5;
/// `DP_LINK_BW_SET` / `DP_LANE_COUNT_SET` (written as one pair).
const DP_LINK_BW_SET: u32 = 0x100;
/// `DP_POST_LT_ADJ_REQ_GRANTED` in `DP_LANE_COUNT_SET`.
const DP_POST_LT_ADJ_REQ_GRANTED: u8 = 1 << 5;
/// `DP_TRAINING_PATTERN_SET`; `DP_TRAINING_LANE0_SET` follows it.
pub const DP_TRAINING_PATTERN_SET: u32 = 0x102;
/// `DP_TRAINING_LANE0_SET`.
pub const DP_TRAINING_LANE0_SET: u32 = 0x103;
/// `DP_TRAINING_PATTERN_1` / `_2` / `_2_CDS` (128b/132b TPS1, TPS2 and the
/// CDS phase's TPS2) and `DP_TRAINING_PATTERN_DISABLE`.
pub const DP_TRAINING_PATTERN_DISABLE: u8 = 0;
pub const DP_TRAINING_PATTERN_1: u8 = 1;
pub const DP_TRAINING_PATTERN_2: u8 = 2;
pub const DP_TRAINING_PATTERN_2_CDS: u8 = 3;
/// `DP_DOWNSPREAD_CTRL`; `DP_MAIN_LINK_CHANNEL_CODING_SET` follows it.
pub const DP_DOWNSPREAD_CTRL: u32 = 0x107;
/// `DP_MAIN_LINK_CHANNEL_CODING_SET` and its two codes.
pub const DP_MAIN_LINK_CHANNEL_CODING_SET: u32 = 0x108;
pub const DP_SET_ANSI_8B10B: u8 = 1 << 0;
pub const DP_SET_ANSI_128B132B: u8 = 1 << 1;
/// `DP_SDP_ERROR_DETECTION_CONFIGURATION` / `DP_SDP_CRC16_128B132B_EN`.
pub const DP_SDP_ERROR_DETECTION_CONFIGURATION: u32 = 0x121;
pub const DP_SDP_CRC16_128B132B_EN: u8 = 1 << 0;
/// `DP_PAYLOAD_ALLOCATE_SET` (VCPID, start slot, slot count).
pub const DP_PAYLOAD_ALLOCATE_SET: u32 = 0x1c0;
/// `DP_LANE0_1_STATUS`: the six-byte link status starts here.
pub const DP_LANE0_1_STATUS: u32 = 0x202;
/// `DP_SINK_STATUS` and `DP_INTRA_HOP_AUX_REPLY_INDICATION`.
pub const DP_SINK_STATUS: u32 = 0x205;
pub const DP_INTRA_HOP_AUX_REPLY_INDICATION: u8 = 1 << 3;
/// `DP_LANE_ALIGN_STATUS_UPDATED` bits (byte 2 of the link status).
pub const DP_INTERLANE_ALIGN_DONE: u8 = 1 << 0;
pub const DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE: u8 = 1 << 2;
pub const DP_128B132B_DPRX_CDS_INTERLANE_ALIGN_DONE: u8 = 1 << 3;
pub const DP_128B132B_LT_FAILED: u8 = 1 << 4;
/// Per-lane status nibble bits.
pub const DP_LANE_CHANNEL_EQ_DONE: u8 = 1 << 1;
pub const DP_LANE_SYMBOL_LOCKED: u8 = 1 << 2;
/// `DP_PAYLOAD_TABLE_UPDATE_STATUS` and its bits.
pub const DP_PAYLOAD_TABLE_UPDATE_STATUS: u32 = 0x2c0;
pub const DP_PAYLOAD_TABLE_UPDATED: u8 = 1 << 0;
pub const DP_PAYLOAD_ACT_HANDLED: u8 = 1 << 1;
/// `DP_128B132B_SUPPORTED_LINK_RATES` and its rate bits.
pub const DP_128B132B_SUPPORTED_LINK_RATES: u32 = 0x2215;
pub const DP_UHBR10: u8 = 1 << 0;
pub const DP_UHBR20: u8 = 1 << 1;
pub const DP_UHBR13_5: u8 = 1 << 2;
/// `DP_128B132B_TRAINING_AUX_RD_INTERVAL`.
pub const DP_128B132B_TRAINING_AUX_RD_INTERVAL: u32 = 0x2216;
const DP_128B132B_TRAINING_AUX_RD_INTERVAL_1MS_UNIT: u8 = 1 << 7;
const DP_128B132B_TRAINING_AUX_RD_INTERVAL_MASK: u8 = 0x7f;
/// `DP_LT_TUNABLE_PHY_REPEATER_FIELD_DATA_STRUCTURE_REV`: the eight-byte
/// LTTPR common capabilities (`DP_LTTPR_COMMON_CAP_SIZE`).
pub const DP_LTTPR_COMMON_CAPS: u32 = 0xf0000;
const DP_MAX_LINK_RATE_PHY_REPEATER: usize = 1;
const DP_PHY_REPEATER_CNT: usize = 2;
/// `DP_PHY_REPEATER_MODE` (0xf0003) within the common capabilities.
const DP_PHY_REPEATER_MODE_INDEX: usize = 3;
const DP_MAX_LANE_COUNT_PHY_REPEATER: usize = 4;
const DP_MAIN_LINK_CHANNEL_CODING_PHY_REPEATER: usize = 6;
const DP_PHY_REPEATER_128B132B_SUPPORTED: u8 = 1 << 0;
const DP_PHY_REPEATER_128B132B_RATES: usize = 7;
/// `DP_PHY_REPEATER_MODE` and its two values.
pub const DP_PHY_REPEATER_MODE: u32 = 0xf_0003;
pub const DP_PHY_REPEATER_MODE_TRANSPARENT: u8 = 0x55;
pub const DP_PHY_REPEATER_MODE_NON_TRANSPARENT: u8 = 0xaa;
/// `DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT` and its request mask / grant.
pub const DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT: u32 = 0xf_0005;
const DP_EXTENDED_WAKE_TIMEOUT_REQUEST_MASK: u8 = 0x7f;
pub const DP_EXTENDED_WAKE_TIMEOUT_GRANT: u8 = 1 << 7;
/// `DP_EXTENDED_DPRX_SLEEP_WAKE_TIMEOUT_REQUEST` / `_GRANT` and
/// `DP_DPRX_SLEEP_WAKE_TIMEOUT_PERIOD_GRANTED`.
pub const DP_EXTENDED_DPRX_SLEEP_WAKE_TIMEOUT_REQUEST: u32 = 0x2211;
pub const DP_EXTENDED_DPRX_SLEEP_WAKE_TIMEOUT_GRANT: u32 = 0x119;
pub const DP_DPRX_SLEEP_WAKE_TIMEOUT_PERIOD_GRANTED: u8 = 1 << 0;
/// `DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1`, the first of the three
/// `DP_LTTPR_PHY_CAP_SIZE` bytes, and the LTTPR register stride
/// (`__DP_LTTPR2_BASE - __DP_LTTPR1_BASE`).
pub const DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1: u32 = 0xf_0020;
pub const DP_LTTPR_STRIDE: u32 = 0x50;
const DP_LTTPR_PHY_CAP_SIZE: usize = 3;

/// `DP_LINK_STATUS_SIZE`.
pub const LINK_STATUS_SIZE: usize = 6;

// ── Rates ────────────────────────────────────────────────────────

/// A DP 2.0 UHBR link rate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UhbrRate {
    /// 10 Gbps per lane.
    Uhbr10,
    /// 13.5 Gbps per lane.
    Uhbr13_5,
    /// 20 Gbps per lane.
    Uhbr20,
}

impl UhbrRate {
    /// Ascending, as `intel_dp->sink_rates` lists them.
    pub const ALL: [Self; 3] = [Self::Uhbr10, Self::Uhbr13_5, Self::Uhbr20];

    /// Linux link-rate units (10 kbps per lane): `crtc_state->port_clock`.
    pub const fn link_rate(self) -> u32 {
        match self {
            Self::Uhbr10 => 1_000_000,
            Self::Uhbr13_5 => 1_350_000,
            Self::Uhbr20 => 2_000_000,
        }
    }

    /// The rate for a Linux link rate.
    pub const fn from_link_rate(link_rate: u32) -> Option<Self> {
        match link_rate {
            1_000_000 => Some(Self::Uhbr10),
            1_350_000 => Some(Self::Uhbr13_5),
            2_000_000 => Some(Self::Uhbr20),
            _ => None,
        }
    }

    /// `drm_dp_link_rate_to_bw_code`: `DP_LINK_BW_10` 0x01,
    /// `DP_LINK_BW_13_5` 0x04, `DP_LINK_BW_20` 0x02.
    pub const fn link_bw(self) -> u8 {
        match self {
            Self::Uhbr10 => 0x01,
            Self::Uhbr13_5 => 0x04,
            Self::Uhbr20 => 0x02,
        }
    }

    /// The rate's bit in `DP_128B132B_SUPPORTED_LINK_RATES`.
    pub const fn rate_bit(self) -> u8 {
        match self {
            Self::Uhbr10 => DP_UHBR10,
            Self::Uhbr13_5 => DP_UHBR13_5,
            Self::Uhbr20 => DP_UHBR20,
        }
    }

    /// `intel_dp_link_symbol_clock`: the 32-bit symbol clock in kHz,
    /// what `DDI_CLK_VALFREQ` and the link N carry.
    pub const fn symbol_clock_khz(self) -> u32 {
        crate::intel_gpu_xelpg::dp_link_symbol_clock_khz(self.link_rate())
    }
}

/// The source's UHBR rates (`DP_UHBR*` bits) on a display-14+ port:
/// `intel_dp_set_source_rates` takes `mtl_rates` (whose UHBR entries are
/// 1000000 and 2000000) up to `mtl_max_source_rate`, which is 810000 for a
/// C10 PHY (`intel_encoder_is_c10phy`) and for Wildcat Lake
/// (`pantherlake_wildcatlake`) and 2000000 otherwise. Display 14.01
/// (Battlemage's `bmg_rates`) is not a profile of this route.
pub const fn source_rates(ip: DisplayIp, c10_phy: bool) -> u8 {
    if c10_phy {
        return 0;
    }
    match ip {
        DisplayIp::WildcatLake => 0,
        DisplayIp::Xelpdp | DisplayIp::Xe2Lpd | DisplayIp::Xe3Lpd | DisplayIp::NovaLakeS => {
            DP_UHBR10 | DP_UHBR20
        }
    }
}

/// What the sink side of `intel_dp_set_dpcd_sink_rates` reports for 128b/132b.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UhbrSink {
    /// The sink's UHBR rate bits, zero unless `DP_CAP_ANSI_128B132B`; an
    /// LTTPR that supports 128b/132b masks them with its own
    /// `DP_PHY_REPEATER_128B132B_RATES`, one that does not clears them.
    pub rates: u8,
    /// `drm_dp_lttpr_count` found one to eight repeaters (a malformed count
    /// is none: Linux's LTTPR init resets it before the sink rates).
    pub lttpr: bool,
    /// The LTTPR common capabilities ([`read_lttpr_caps`]).
    pub lttpr_caps: [u8; 8],
    /// `drm_dp_post_lt_adj_req_supported`.
    pub post_lt_adj_req: bool,
}

/// `drm_dp_lttpr_count`: 0 without a repeater, 1..8, or `None` for a
/// malformed count byte (more than one bit set).
pub const fn lttpr_count(caps: &[u8; 8]) -> Option<u8> {
    let count = caps[DP_PHY_REPEATER_CNT];
    match count.count_ones() {
        0 => Some(0),
        1 => Some(8 - count.trailing_zeros() as u8),
        _ => None,
    }
}

/// Read the sink's 128b/132b capabilities after the receiver capability
/// field `raw` ([`crate::dp_link_training::read_receiver_caps`]):
/// `DP_128B132B_SUPPORTED_LINK_RATES` when `DP_CAP_ANSI_128B132B` is set,
/// and the LTTPR common capabilities (`drm_dp_read_lttpr_common_caps`; a
/// failed read is Linux's zeroed caps, no repeater).
pub fn read_sink<A: AuxChannel + ?Sized>(
    aux: &mut A,
    raw: &[u8; 16],
) -> Result<UhbrSink, AuxError> {
    read_sink_rates(aux, raw, None)
}

/// [`read_sink`] behind a DP tunnel with BW allocation enabled
/// ([`super::tunnel`]): `dprx_supports_128b132b` and
/// `dprx_128b132b_link_rates` take the tunnel's 128b/132b rates
/// (`drm_dp_tunnel_128b132b_dprx_rates`, zero without 128b/132b support)
/// instead of `DP_CAP_ANSI_128B132B` and `DP_128B132B_SUPPORTED_LINK_RATES`
/// (which a tunnelled DPRX reports empty, DP 2.1 5.14.3); the LTTPR masking
/// is unchanged. `None` is [`read_sink`].
pub fn read_sink_rates<A: AuxChannel + ?Sized>(
    aux: &mut A,
    raw: &[u8; 16],
    tunnel_rates: Option<u8>,
) -> Result<UhbrSink, AuxError> {
    let post_lt_adj_req = raw[DP_MAX_LANE_COUNT] & DP_POST_LT_ADJ_REQ_SUPPORTED != 0;
    let supported = match tunnel_rates {
        Some(rates) => rates != 0,
        None => raw[DP_MAIN_LINK_CHANNEL_CODING] & DP_CAP_ANSI_128B132B != 0,
    };
    if !supported {
        return Ok(UhbrSink {
            post_lt_adj_req,
            ..UhbrSink::default()
        });
    }
    let rates = match tunnel_rates {
        Some(rates) => rates,
        None => {
            let mut rates = [0u8];
            aux.dpcd_read(DP_128B132B_SUPPORTED_LINK_RATES, &mut rates)?;
            rates[0]
        }
    };
    let lttpr = read_lttpr_caps(aux, raw[0]);
    let mut rates = rates & (DP_UHBR10 | DP_UHBR13_5 | DP_UHBR20);
    // intel_dp_init_lttpr_phys resets a malformed count before the sink
    // rates are set: no repeater then.
    let present = lttpr_count(&lttpr).is_some_and(|n| n > 0);
    if present {
        if lttpr[0] >= 0x20
            && lttpr[DP_MAIN_LINK_CHANNEL_CODING_PHY_REPEATER] & DP_PHY_REPEATER_128B132B_SUPPORTED
                != 0
        {
            rates &= lttpr[DP_PHY_REPEATER_128B132B_RATES];
        } else {
            rates = 0;
        }
    }
    Ok(UhbrSink {
        rates,
        lttpr: present,
        lttpr_caps: lttpr,
        post_lt_adj_req,
    })
}

// ── LTTPRs ───────────────────────────────────────────────────────

/// `drm_dp_read_lttpr_common_caps` and `intel_dp_read_lttpr_common_caps`:
/// the eight bytes at 0xf0000, one byte per AUX read below DPCD 1.4
/// (`drm_dp_read_lttpr_regs`: "the DELL P2715Q ... returns corrupted
/// values"); a failed read or a revision below 1.4 is Linux's zeroed caps.
pub fn read_lttpr_caps<A: AuxChannel + ?Sized>(aux: &mut A, dpcd_rev: u8) -> [u8; 8] {
    let mut caps = [0u8; 8];
    let ok = if dpcd_rev < 0x14 {
        (0..caps.len()).all(|i| {
            aux.dpcd_read(DP_LTTPR_COMMON_CAPS + i as u32, &mut caps[i..i + 1])
                .is_ok()
        })
    } else {
        aux.dpcd_read(DP_LTTPR_COMMON_CAPS, &mut caps).is_ok()
    };
    if !ok || caps[0] < 0x14 {
        return [0; 8];
    }
    caps
}

/// `drm_dp_lttpr_max_link_rate` (`drm_dp_bw_code_to_link_rate` of
/// `DP_MAX_LINK_RATE_PHY_REPEATER`; 0 for zeroed caps).
pub const fn lttpr_max_link_rate(caps: &[u8; 8]) -> u32 {
    caps[DP_MAX_LINK_RATE_PHY_REPEATER] as u32 * 27_000
}

/// `drm_dp_lttpr_max_lane_count`.
pub const fn lttpr_max_lanes(caps: &[u8; 8]) -> u8 {
    caps[DP_MAX_LANE_COUNT_PHY_REPEATER] & 0x1f
}

/// The LTTPR state of `intel_dp_init_lttpr_and_dprx_caps`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LttprInit {
    /// The repeaters in non-transparent mode (0: none, or transparent).
    pub count: u8,
    /// `intel_dp->lttpr_common_caps` afterwards: its `DP_PHY_REPEATER_MODE`
    /// byte holds the mode Linux set (`intel_dp_set_lttpr_transparent_mode`).
    pub caps: [u8; 8],
}

impl LttprInit {
    /// `intel_dp_lttpr_transparent_mode_enabled`.
    pub fn transparent(&self) -> bool {
        self.caps[DP_PHY_REPEATER_MODE_INDEX] == DP_PHY_REPEATER_MODE_TRANSPARENT
    }
}

/// `intel_dp_init_lttpr_and_dprx_caps` on a link that is not active
/// (non-eDP, display 10+): `intel_dp_read_dprx_caps` (the
/// `drm_dp_dpcd_probe` of 0xf0000 and the receiver capabilities), then
/// `intel_dp_init_lttpr`: the common caps, `drm_dp_lttpr_count` and
/// `drm_dp_lttpr_init` — `DP_PHY_REPEATER_MODE` transparent, then
/// non-transparent (DP 2.0 3.6.6.1), back to transparent when that fails;
/// a malformed count stops after the transparent write — and each
/// repeater's `drm_dp_read_lttpr_phy_caps`; then the receiver capabilities
/// again ("The DPTX shall read the DPRX caps after LTTPR detection"). A
/// failed DPRX read is Linux's `-EIO`, which `intel_dp_start_link_train`
/// takes as no repeater.
pub fn init_lttpr_and_dprx_caps<A: AuxChannel + ?Sized>(aux: &mut A) -> LttprInit {
    let mut probe = [0u8];
    let mut dpcd = [0u8; 16];
    if aux.dpcd_read(DP_LTTPR_COMMON_CAPS, &mut probe).is_err()
        || aux.dpcd_read(0x000, &mut dpcd).is_err()
    {
        return LttprInit::default();
    }
    let mut caps = read_lttpr_caps(aux, dpcd[0]);
    let mut count = 0;
    let found = lttpr_count(&caps);
    if found != Some(0) {
        // intel_dp_init_lttpr_phys with LTTPRs (or a malformed count).
        let transparent = aux
            .dpcd_write(DP_PHY_REPEATER_MODE, &[DP_PHY_REPEATER_MODE_TRANSPARENT])
            .is_ok();
        let non_transparent = match found {
            Some(_) if transparent => {
                if aux
                    .dpcd_write(DP_PHY_REPEATER_MODE, &[DP_PHY_REPEATER_MODE_NON_TRANSPARENT])
                    .is_ok()
                {
                    true
                } else {
                    let _ = aux
                        .dpcd_write(DP_PHY_REPEATER_MODE, &[DP_PHY_REPEATER_MODE_TRANSPARENT]);
                    false
                }
            }
            _ => false,
        };
        if non_transparent {
            caps[DP_PHY_REPEATER_MODE_INDEX] = DP_PHY_REPEATER_MODE_NON_TRANSPARENT;
            count = found.unwrap_or(0);
            for i in 0..u32::from(count) {
                let base = DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1 + i * DP_LTTPR_STRIDE;
                let mut phy = [0u8; DP_LTTPR_PHY_CAP_SIZE];
                if dpcd[0] < 0x14 {
                    for (j, b) in phy.iter_mut().enumerate() {
                        if aux
                            .dpcd_read(base + j as u32, core::slice::from_mut(b))
                            .is_err()
                        {
                            break;
                        }
                    }
                } else {
                    let _ = aux.dpcd_read(base, &mut phy);
                }
            }
        } else {
            // intel_dp_set_lttpr_transparent_mode(true) and
            // intel_dp_reset_lttpr_count.
            caps[DP_PHY_REPEATER_MODE_INDEX] = DP_PHY_REPEATER_MODE_TRANSPARENT;
            caps[DP_PHY_REPEATER_CNT] = 0;
        }
    }
    if aux.dpcd_read(0x000, &mut dpcd).is_err() {
        return LttprInit::default();
    }
    LttprInit { count, caps }
}

/// `drm_dp_lttpr_wake_timeout_setup`: in transparent mode the DPRX's
/// `DP_EXTENDED_DPRX_SLEEP_WAKE_TIMEOUT_REQUEST` (1, 20, 40, 60, 80 or 100 ms;
/// anything else is 1) is granted when above 1 ms; in non-transparent mode
/// any `DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT` request (units of 10 ms) is
/// granted. A failed read grants nothing.
pub fn wake_timeout_setup<A: AuxChannel + ?Sized>(aux: &mut A, transparent: bool) {
    let mut value = [0u8];
    if transparent {
        const MAPPING: [u8; 6] = [1, 20, 40, 60, 80, 100];
        if aux
            .dpcd_read(DP_EXTENDED_DPRX_SLEEP_WAKE_TIMEOUT_REQUEST, &mut value)
            .is_err()
        {
            return;
        }
        let ms = MAPPING.get(usize::from(value[0])).copied().unwrap_or(1);
        if ms > 1 {
            let _ = aux.dpcd_write(
                DP_EXTENDED_DPRX_SLEEP_WAKE_TIMEOUT_GRANT,
                &[DP_DPRX_SLEEP_WAKE_TIMEOUT_PERIOD_GRANTED],
            );
        }
    } else {
        if aux
            .dpcd_read(DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT, &mut value)
            .is_err()
        {
            return;
        }
        if value[0] & DP_EXTENDED_WAKE_TIMEOUT_REQUEST_MASK != 0 {
            let _ = aux.dpcd_write(
                DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT,
                &[DP_EXTENDED_WAKE_TIMEOUT_GRANT],
            );
        }
    }
}

// ── Bandwidth ────────────────────────────────────────────────────

/// `drm_dp_max_dprx_data_rate` on 128b/132b, kBps: the link rate times the
/// 96.71% channel coding efficiency (`drm_dp_bw_channel_coding_efficiency`).
pub fn max_link_data_rate(rate: UhbrRate, lanes: u32) -> u64 {
    u64::from(rate.link_rate()) * 10 * u64::from(lanes) * 967_100 / (1_000_000 * 8)
}

/// `drm_dp_bw_overhead` for an uncompressed 128b/132b stream (32-bit
/// symbols; MST alignment of the symbol cycles to `4 / lanes` when `mst`,
/// as `intel_dp_mtp_tu_compute_config` asks), at least 100%. ppm.
fn bw_overhead(lanes: u32, hactive: u32, bpp_x16: u32, mst: bool) -> u64 {
    if lanes == 0 || hactive == 0 || bpp_x16 == 0 {
        return 0;
    }
    let cycles = (u64::from(hactive) * u64::from(bpp_x16)).div_ceil(16 * 32 * u64::from(lanes));
    let align = if mst { u64::from(4 / lanes) } else { 1 };
    let cycles = cycles.div_ceil(align) * align;
    let overhead = (cycles * 32 * u64::from(lanes) * 1_000_000 * 16)
        .div_ceil(u64::from(hactive) * u64::from(bpp_x16));
    overhead.max(1_000_000)
}

/// `intel_dp_effective_data_rate`, kBps.
fn effective_data_rate(pixel_clock: u32, bpp_x16: u32, overhead: u64) -> u64 {
    (u64::from(pixel_clock) * u64::from(bpp_x16) * overhead).div_ceil(1_000_000 * 16 * 8)
}

/// `intel_dp_link_required` on 128b/132b SST (the flags
/// `intel_dp_link_bw_overhead` adds for a UHBR rate), kBps.
pub fn link_required(lanes: u32, mode_clock: u32, hdisplay: u32, bpp_x16: u32) -> u64 {
    effective_data_rate(
        mode_clock,
        bpp_x16,
        bw_overhead(lanes, hdisplay, bpp_x16, false),
    )
}

/// An uncompressed 128b/132b SST link.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UhbrLink {
    /// The link rate.
    pub rate: UhbrRate,
    /// 1, 2 or 4.
    pub lanes: u8,
    /// `crtc_state->pipe_bpp`: 24, or 18 (6 bpc).
    pub pipe_bpp: u32,
}

/// What `intel_dp_compute_link_config_wide` picks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WideLink {
    /// An 8b/10b configuration carries the stream at the highest bpp that
    /// fits anywhere: the route's 8b/10b negotiation is unchanged.
    EightTenB,
    /// Only a UHBR configuration carries that bpp.
    Uhbr(UhbrLink),
    /// No uncompressed configuration fits (Linux then tries DSC).
    None,
}

/// `intel_dp_compute_link_config_wide` with the SST order
/// (`INTEL_DP_LINK_CAPS_ORDER_KEY_RATE_LANE`, ascending): for each pipe bpp
/// from `max_bpp` down in steps of 6 to 18, every common rate from the
/// lowest (the 8b/10b rates of `limits`, then the UHBR rates in
/// `uhbr_rates`) and every lane count from 1 to `limits.max_lanes`; the
/// first that carries the mode wins.
#[cfg(any(test, feature = "kernel-test"))]
pub fn wide_link(limits: &dsc::LinkLimits, uhbr_rates: u8, mode: &Mode, max_bpp: u32) -> WideLink {
    wide_link_capped(limits, uhbr_rates, mode, max_bpp, None, 0)
}

/// [`wide_link`] with `intel_dp_max_link_data_rate`'s DP tunnel cap
/// (`cap`, kBps: the tunnel's available bandwidth while BW allocation is
/// enabled) on every configuration, and the UHBR lane counts the tunnel's
/// `intel_dp_tunnel_uhbr_lanes_wa_apply` disabled (`uhbr_lane_mask`, bit
/// `ilog2(lanes)`).
pub fn wide_link_capped(
    limits: &dsc::LinkLimits,
    uhbr_rates: u8,
    mode: &Mode,
    max_bpp: u32,
    cap: Option<u64>,
    uhbr_lane_mask: u8,
) -> WideLink {
    let capped = |rate: u64| cap.map_or(rate, |cap| rate.min(cap));
    let max_bpp = max_bpp.min(dsc::PIPE_BPP);
    let lanes = [1u8, 2, 4].into_iter().filter(|&l| l <= limits.max_lanes);
    let (clock, hdisplay) = (mode.pixel_clock_khz, u32::from(mode.h_active));
    let mut bpp = max_bpp - max_bpp % 6;
    while bpp >= dsc::MIN_PIPE_BPP {
        let bpp_x16 = bpp * 16;
        for rate in limits.rates.iter().copied().take_while(|&r| r != 0) {
            for l in lanes.clone() {
                let l = u32::from(l);
                if dsc::link_required(l, clock, hdisplay, bpp_x16, false)
                    <= capped(dsc::max_link_data_rate(rate, l))
                {
                    return WideLink::EightTenB;
                }
            }
        }
        for rate in UhbrRate::ALL
            .into_iter()
            .filter(|r| uhbr_rates & r.rate_bit() != 0)
        {
            for l in lanes
                .clone()
                .filter(|l| uhbr_lane_mask & (1 << l.trailing_zeros()) == 0)
            {
                if link_required(u32::from(l), clock, hdisplay, bpp_x16)
                    <= capped(max_link_data_rate(rate, u32::from(l)))
                {
                    return WideLink::Uhbr(UhbrLink {
                        rate,
                        lanes: l,
                        pipe_bpp: bpp,
                    });
                }
            }
        }
        bpp -= 6;
    }
    WideLink::None
}

/// `compute_m_n` with a constant N, then `intel_reduce_m_n_ratio`.
fn compute_m_n(m: u64, n: u64, constant_n: u64) -> (u32, u32) {
    if n == 0 {
        return (0, 0);
    }
    let mut ret_n = constant_n;
    let mut ret_m = m * ret_n / n;
    while ret_m > 0xff_ffff || ret_n > 0xff_ffff {
        ret_m >>= 1;
        ret_n >>= 1;
    }
    (ret_m as u32, ret_n as u32)
}

/// The 128b/132b SST stream's MTP allocation and M/N.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UhbrStream {
    /// `crtc_state->dp_m_n.tu`: the time slots of the 64-slot MTP (also
    /// the payload's slot count).
    pub tu: u8,
    /// `PIPE_DATA_M1` (with `TU_SIZE(tu)`), `PIPE_DATA_N1`, `PIPE_LINK_M1`,
    /// `PIPE_LINK_N1`.
    pub m_n: [u32; 4],
}

/// `intel_dp_mtp_tu_compute_config` for an uncompressed 128b/132b SST
/// stream: the MST BW overhead (`intel_dp_mst_bw_overhead` without SSC or
/// FEC, symbol cycles aligned to `4 / lanes`), `intel_link_compute_m_n` at
/// the 32-bit link symbol clock, `tu = DIV_ROUND_UP(data_m * 64, data_n)`
/// aligned to `4 / lanes`; `None` when it exceeds the 64 slots (Linux then
/// needs DSC).
pub fn mtp_tu(link: &UhbrLink, mode: &Mode) -> Option<UhbrStream> {
    let lanes = u32::from(link.lanes);
    if !matches!(lanes, 1 | 2 | 4) {
        return None;
    }
    let bpp_x16 = link.pipe_bpp * 16;
    let clock = mode.pixel_clock_khz;
    let overhead = bw_overhead(lanes, u32::from(mode.h_active), bpp_x16, true);
    let data_m = effective_data_rate(clock, bpp_x16, overhead);
    let data_n = max_link_data_rate(link.rate, lanes);
    if data_n == 0 {
        return None;
    }
    let align = u64::from(4 / lanes);
    let tu = (data_m * 64).div_ceil(data_n).div_ceil(align) * align;
    if tu == 0 || tu > 64 {
        return None;
    }
    let (dm, dn) = compute_m_n(data_m, data_n, 0x800_0000);
    let (lm, ln) = compute_m_n(
        u64::from(clock),
        u64::from(link.rate.symbol_clock_khz()),
        0x8_0000,
    );
    Some(UhbrStream {
        tu: tu as u8,
        m_n: [((tu as u32 - 1) << 25) | dm, dn, lm, ln],
    })
}

/// `intel_dp_compute_min_hblank` for an uncompressed 128b/132b SST stream
/// on display 30 (`DP_MIN_HBLANK_CTL`): the blanking symbol cycles at the
/// fixed four-lane count, at least the 3 of BS/VBID/BE, minus 2 for the
/// framing, at most the 3 the spec recommends.
pub fn min_hblank(mode: &Mode, pipe_bpp: u32) -> u32 {
    let (hactive, htotal) = (u64::from(mode.h_active), u64::from(mode.h_total));
    if hactive == 0 {
        return 0;
    }
    let active = (hactive * u64::from(pipe_bpp * 16)).div_ceil(16 * 32 * 4);
    let total = htotal * active / hactive;
    let blank = total.saturating_sub(active).max(3) - 2;
    blank.min(3) as u32
}

// ── 128b/132b link training ──────────────────────────────────────

/// The source's `DP_TP_CTL` link-training state
/// (`intel_dp_program_link_training_pattern`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourcePattern {
    /// 128b/132b TPS1 (`DP_TP_CTL_LINK_TRAIN_PAT1`).
    Tps1,
    /// 128b/132b TPS2 (`DP_TP_CTL_LINK_TRAIN_PAT2`).
    Tps2,
    /// `DP_TRAINING_PATTERN_DISABLE`: `DP_TP_CTL_LINK_TRAIN_NORMAL`.
    Normal,
}

/// What the source does between the DPCD writes of a 128b/132b training.
pub trait UhbrSource {
    /// The source's own failure.
    type Error;
    /// `intel_dp_program_link_training_pattern`.
    fn pattern(&mut self, pattern: SourcePattern) -> Result<(), Self::Error>;
    /// `encoder->set_signal_levels` with these per-lane TX FFE presets
    /// (`intel_dp->train_set`, four entries).
    fn presets(&mut self, presets: &[u8; 4]) -> Result<(), Self::Error>;
}

/// The training's time base: microseconds and sleeps.
pub trait Clock {
    /// A monotonic microsecond count.
    fn now_us(&mut self) -> u64;
    /// `fsleep` / `usleep_range`.
    fn sleep_us(&mut self, us: u64);
}

/// The system clock (`narf_time`).
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_us(&mut self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000
    }
    fn sleep_us(&mut self, us: u64) {
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(us));
    }
}

/// Why a 128b/132b training failed (each a Linux `lt_err`/`lt_dbg` exit).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrainFailure {
    /// The lane count is not 1, 2 or 4 (nothing was written).
    LaneCount,
    /// `DP_INTRA_HOP_AUX_REPLY_INDICATION` did not clear within 500 ms.
    IntraHop,
    /// A DPCD access the sequence needs failed.
    Aux(AuxError),
    /// The DPRX reported `DP_128B132B_LT_FAILED`.
    LtFailed,
    /// LANEx_EQ_DONE missed its 450 ms budget.
    EqTimeout,
    /// LANEx_EQ_DONE took all 20 tries.
    EqMaxTries,
    /// `DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE` missed the EQ budget.
    AlignTimeout,
    /// LANEx_CDS_DONE missed its `(lttpr_count + 1) * 20` ms budget.
    CdsTimeout,
}

/// A failed training: the sink's sequence, or the source.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrainError<E> {
    /// The 128b/132b sequence failed.
    Link(TrainFailure),
    /// The source failed to program a pattern or level.
    Source(E),
}

impl<E> From<AuxError> for TrainError<E> {
    fn from(e: AuxError) -> Self {
        Self::Link(TrainFailure::Aux(e))
    }
}

/// `intel_dp_prepare_link_train`'s sink half on a UHBR link:
/// `intel_dp_link_training_set_mode` (`DP_DOWNSPREAD_CTRL` 0 — no VRR, no
/// panel replay — and `DP_MAIN_LINK_CHANNEL_CODING_SET` =
/// `DP_SET_ANSI_128B132B`, before the rate per DP 2.1 3.5.2.16), then
/// `intel_dp_link_training_set_bw` (`DP_LINK_BW_SET` / `DP_LANE_COUNT_SET`
/// with no enhanced framing on 128b/132b and `DP_POST_LT_ADJ_REQ_GRANTED`
/// when the sink supports it: `intel_dp_use_post_lt_adj_req` holds for
/// TPS2).
pub fn prepare<A: AuxChannel + ?Sized>(
    aux: &mut A,
    rate: UhbrRate,
    lanes: u8,
    post_lt_adj_req: bool,
) -> Result<(), AuxError> {
    aux.dpcd_write(DP_DOWNSPREAD_CTRL, &[0, DP_SET_ANSI_128B132B])?;
    let lane_count = lanes
        | if post_lt_adj_req {
            DP_POST_LT_ADJ_REQ_GRANTED
        } else {
            0
        };
    aux.dpcd_write(DP_LINK_BW_SET, &[rate.link_bw(), lane_count])
}

/// `drm_dp_128b132b_read_aux_rd_interval`: `(value + 1)` units of 2 ms (1
/// ms with `_1MS_UNIT`); a failed read is the maximum.
fn aux_rd_interval_us<A: AuxChannel + ?Sized>(aux: &mut A) -> u64 {
    let mut value = [0u8];
    if aux
        .dpcd_read(DP_128B132B_TRAINING_AUX_RD_INTERVAL, &mut value)
        .is_err()
    {
        value[0] = DP_128B132B_TRAINING_AUX_RD_INTERVAL_MASK;
    }
    let unit = if value[0] & DP_128B132B_TRAINING_AUX_RD_INTERVAL_1MS_UNIT != 0 {
        1
    } else {
        2
    };
    (u64::from(value[0] & DP_128B132B_TRAINING_AUX_RD_INTERVAL_MASK) + 1) * unit * 1_000
}

/// `drm_dp_dpcd_read_link_status`: DPCD 0x202..=0x207.
fn read_link_status<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<[u8; 6], AuxError> {
    let mut status = [0u8; LINK_STATUS_SIZE];
    aux.dpcd_read(DP_LANE0_1_STATUS, &mut status)?;
    Ok(status)
}

fn lane_status(status: &[u8; 6], lane: usize) -> u8 {
    (status[lane / 2] >> ((lane & 1) * 4)) & 0xf
}

/// `drm_dp_128b132b_lane_channel_eq_done`: `DP_INTERLANE_ALIGN_DONE` and
/// every lane's `DP_LANE_CHANNEL_EQ_DONE`.
pub fn lane_channel_eq_done(status: &[u8; 6], lanes: u8) -> bool {
    status[2] & DP_INTERLANE_ALIGN_DONE != 0
        && (0..usize::from(lanes)).all(|l| lane_status(status, l) & DP_LANE_CHANNEL_EQ_DONE != 0)
}

fn lane_symbol_locked(status: &[u8; 6], lanes: u8) -> bool {
    (0..usize::from(lanes)).all(|l| lane_status(status, l) & DP_LANE_SYMBOL_LOCKED != 0)
}

/// `intel_dp_get_lane_adjust_tx_ffe_preset` for every `train_set` entry with
/// per-lane signal levels (display 10+): lane `n` takes the preset the sink
/// requests for `min(n, lanes - 1)` (`drm_dp_get_adjust_tx_ffe_preset`).
pub fn adjust_presets(status: &[u8; 6], lanes: u8) -> [u8; 4] {
    let mut presets = [0u8; 4];
    for (lane, preset) in presets.iter_mut().enumerate() {
        let l = lane.min(usize::from(lanes.max(1)) - 1);
        *preset = (status[4 + l / 2] >> ((l & 1) * 4)) & 0xf;
    }
    presets
}

/// `intel_dp_128b132b_intra_hop`: `Some(true)` while the DPRX still
/// replies for an intra-hop AUX, `None` on a failed read.
fn intra_hop<A: AuxChannel + ?Sized>(aux: &mut A) -> Option<bool> {
    let mut status = [0u8];
    aux.dpcd_read(DP_SINK_STATUS, &mut status).ok()?;
    Some(status[0] & DP_INTRA_HOP_AUX_REPLY_INDICATION != 0)
}

/// `poll_timeout_us(intel_dp_128b132b_intra_hop(), ret == 0, 500,
/// 500 * 1000, false)`: expiry is sampled before each read, so the read
/// after the deadline still decides; reads are 500 us apart.
fn wait_intra_hop_clear<A: AuxChannel + ?Sized, C: Clock>(aux: &mut A, clock: &mut C) -> bool {
    let deadline = clock.now_us() + 500_000;
    loop {
        let expired = clock.now_us() > deadline;
        if intra_hop(aux) == Some(false) {
            return true;
        }
        if expired {
            return false;
        }
        clock.sleep_us(500);
    }
}

/// `intel_dp_set_link_train`: the source pattern, then
/// `DP_TRAINING_PATTERN_SET` with the lanes' `DP_TRAINING_LANEx_SET`.
fn set_link_train<A: AuxChannel + ?Sized, S: UhbrSource>(
    aux: &mut A,
    source: &mut S,
    source_pattern: SourcePattern,
    dpcd_pattern: u8,
    train_set: &[u8; 4],
    lanes: u8,
) -> Result<(), TrainError<S::Error>> {
    source.pattern(source_pattern).map_err(TrainError::Source)?;
    let mut buf = [0u8; 5];
    buf[0] = dpcd_pattern;
    buf[1..5].copy_from_slice(train_set);
    aux.dpcd_write(DP_TRAINING_PATTERN_SET, &buf[..1 + usize::from(lanes)])?;
    Ok(())
}

/// `intel_dp_update_link_train`: the source levels, then
/// `DP_TRAINING_LANEx_SET`.
fn update_link_train<A: AuxChannel + ?Sized, S: UhbrSource>(
    aux: &mut A,
    source: &mut S,
    train_set: &[u8; 4],
    lanes: u8,
) -> Result<(), TrainError<S::Error>> {
    source.presets(train_set).map_err(TrainError::Source)?;
    aux.dpcd_write(DP_TRAINING_LANE0_SET, &train_set[..usize::from(lanes)])?;
    Ok(())
}

/// 128b/132b DP LANEx_EQ_DONE Sequence (`intel_dp_128b132b_lane_eq`).
fn lane_eq<A: AuxChannel + ?Sized, S: UhbrSource, C: Clock>(
    aux: &mut A,
    source: &mut S,
    clock: &mut C,
    lanes: u8,
    train_set: &mut [u8; 4],
) -> Result<(), TrainError<S::Error>> {
    // Reset the levels and start 128b/132b TPS1: the DPRX and any LTTPR
    // enter intra-hop AUX mode (intel_dp_reset_link_train).
    *train_set = [0; 4];
    source.presets(train_set).map_err(TrainError::Source)?;
    set_link_train(
        aux,
        source,
        SourcePattern::Tps1,
        DP_TRAINING_PATTERN_1,
        train_set,
        lanes,
    )?;
    let mut delay = aux_rd_interval_us(aux);
    // The initial TX FFE settings the sink asks for.
    let status = read_link_status(aux)?;
    *train_set = adjust_presets(&status, lanes);
    update_link_train(aux, source, train_set, lanes)?;
    set_link_train(
        aux,
        source,
        SourcePattern::Tps2,
        DP_TRAINING_PATTERN_2,
        train_set,
        lanes,
    )?;
    let deadline = clock.now_us() + 450_000;
    let mut timeout = false;
    let mut done = false;
    for _ in 0..20 {
        clock.sleep_us(delay);
        let status = read_link_status(aux)?;
        if status[2] & DP_128B132B_LT_FAILED != 0 {
            return Err(TrainError::Link(TrainFailure::LtFailed));
        }
        if lane_channel_eq_done(&status, lanes) {
            done = true;
            break;
        }
        if timeout {
            return Err(TrainError::Link(TrainFailure::EqTimeout));
        }
        if clock.now_us() > deadline {
            timeout = true;
        }
        // During LT the source reads AUX_RD_INTERVAL just before writing
        // the new FFE presets.
        delay = aux_rd_interval_us(aux);
        *train_set = adjust_presets(&status, lanes);
        update_link_train(aux, source, train_set, lanes)?;
    }
    if !done {
        return Err(TrainError::Link(TrainFailure::EqMaxTries));
    }
    loop {
        if clock.now_us() > deadline {
            timeout = true;
        }
        let status = read_link_status(aux)?;
        if status[2] & DP_128B132B_LT_FAILED != 0 {
            return Err(TrainError::Link(TrainFailure::LtFailed));
        }
        if status[2] & DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE != 0 {
            return Ok(());
        }
        if timeout {
            return Err(TrainError::Link(TrainFailure::AlignTimeout));
        }
        clock.sleep_us(2_000);
    }
}

/// 128b/132b DP LANEx_CDS_DONE Sequence (`intel_dp_128b132b_lane_cds`).
fn lane_cds<A: AuxChannel + ?Sized, C: Clock, E>(
    aux: &mut A,
    clock: &mut C,
    lanes: u8,
    lttpr_count: u8,
) -> Result<(), TrainError<E>> {
    aux.dpcd_write(DP_TRAINING_PATTERN_SET, &[DP_TRAINING_PATTERN_2_CDS])?;
    let deadline = clock.now_us() + (u64::from(lttpr_count) + 1) * 20_000;
    loop {
        let timeout = clock.now_us() > deadline;
        clock.sleep_us(2_000);
        let status = read_link_status(aux)?;
        if status[2] & DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE != 0
            && status[2] & DP_128B132B_DPRX_CDS_INTERLANE_ALIGN_DONE != 0
            && lane_symbol_locked(&status, lanes)
        {
            return Ok(());
        }
        if status[2] & DP_128B132B_LT_FAILED != 0 {
            return Err(TrainError::Link(TrainFailure::LtFailed));
        }
        if timeout {
            return Err(TrainError::Link(TrainFailure::CdsTimeout));
        }
    }
}

/// `intel_dp_128b132b_link_train` after [`prepare`] and the source's
/// `mtl_ddi_prepare_link_retrain`: the intra-hop check, LANEx_EQ_DONE and
/// LANEx_CDS_DONE. However it ends, the source is left at TPS2 (a failed
/// training sets it: leaving TPS1 would stick the transcoder) and
/// `DP_TRAINING_PATTERN_SET` is disabled. Returns the trained TX FFE
/// presets (`intel_dp->train_set`).
pub fn train<A: AuxChannel + ?Sized, S: UhbrSource, C: Clock>(
    aux: &mut A,
    source: &mut S,
    clock: &mut C,
    lanes: u8,
    lttpr_count: u8,
) -> Result<[u8; 4], TrainError<S::Error>> {
    if !matches!(lanes, 1 | 2 | 4) {
        return Err(TrainError::Link(TrainFailure::LaneCount));
    }
    let mut train_set = [0u8; 4];
    let result = if wait_intra_hop_clear(aux, clock) {
        lane_eq(aux, source, clock, lanes, &mut train_set)
            .and_then(|()| lane_cds(aux, clock, lanes, lttpr_count))
    } else {
        Err(TrainError::Link(TrainFailure::IntraHop))
    };
    if result.is_err() {
        if let Err(e) = source.pattern(SourcePattern::Tps2) {
            let _ = aux.dpcd_write(DP_TRAINING_PATTERN_SET, &[DP_TRAINING_PATTERN_DISABLE]);
            return Err(TrainError::Source(e));
        }
    }
    let _ = aux.dpcd_write(DP_TRAINING_PATTERN_SET, &[DP_TRAINING_PATTERN_DISABLE]);
    result.map(|()| train_set)
}

/// `intel_dp_stop_link_train` on a UHBR link: the source's normal pattern,
/// then the intra-hop indication must clear within 500 ms (Linux only logs
/// when it does not; so does this: `false`).
pub fn stop_train<A: AuxChannel + ?Sized, S: UhbrSource, C: Clock>(
    aux: &mut A,
    source: &mut S,
    clock: &mut C,
) -> Result<bool, S::Error> {
    source.pattern(SourcePattern::Normal)?;
    Ok(wait_intra_hop_clear(aux, clock))
}

// ── 128b/132b SST payload ────────────────────────────────────────

/// `drm_dp_dpcd_write_payload`: clear `DP_PAYLOAD_TABLE_UPDATED`, write
/// (VCPID, start slot, slot count) to `DP_PAYLOAD_ALLOCATE_SET`, then poll
/// for the update: 20 reads, 10 ms apart. `false` on failure.
pub fn write_payload<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    vcpid: u8,
    start_slot: u8,
    slots: u8,
) -> bool {
    let _ = aux.dpcd_write(DP_PAYLOAD_TABLE_UPDATE_STATUS, &[DP_PAYLOAD_TABLE_UPDATED]);
    if aux
        .dpcd_write(DP_PAYLOAD_ALLOCATE_SET, &[vcpid, start_slot, slots])
        .is_err()
    {
        return false;
    }
    for retry in 0..20 {
        let mut status = [0u8];
        if aux
            .dpcd_read(DP_PAYLOAD_TABLE_UPDATE_STATUS, &mut status)
            .is_err()
        {
            return false;
        }
        if status[0] & DP_PAYLOAD_TABLE_UPDATED != 0 {
            return true;
        }
        if retry < 19 {
            clock.sleep_us(10_000);
        }
    }
    false
}

/// `drm_dp_dpcd_poll_act_handled(aux, 0)`: `DP_PAYLOAD_ACT_HANDLED` within
/// the default 3000 ms (`readx_poll_timeout`, 200 us apart, expiry sampled
/// before each read); a failed read ends the wait.
pub fn poll_act_handled<A: AuxChannel + ?Sized, C: Clock>(aux: &mut A, clock: &mut C) -> bool {
    let deadline = clock.now_us() + 3_000_000;
    loop {
        let expired = clock.now_us() > deadline;
        let mut status = [0u8];
        if aux
            .dpcd_read(DP_PAYLOAD_TABLE_UPDATE_STATUS, &mut status)
            .is_err()
        {
            return false;
        }
        if status[0] & DP_PAYLOAD_ACT_HANDLED != 0 {
            return true;
        }
        if expired {
            return false;
        }
        clock.sleep_us(200);
    }
}

// ── Typed refusals ───────────────────────────────────────────────

/// Why a route that `narf.intel.uhbr=1` would run at a UHBR rate is refused
/// (nothing was programmed unless noted).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UhbrRefusal {
    /// The link is MST and its hub supports a common UHBR rate: Linux runs
    /// 128b/132b MST (`intel_dp_mst_compute_link_config` takes the
    /// highest-bandwidth link), which is not implemented.
    Mst,
    /// The stream needs DSC and the common rates include UHBR: Linux's DSC
    /// search would consider them; DSC over 128b/132b is not implemented.
    Dsc,
    /// The stream needs UHBR over Thunderbolt alt mode on display 14 or 20:
    /// `intel_mtl_tbt_clock_select` has no UHBR10/20 select below display
    /// 30 (Linux WARNs and programs the 162 MHz one).
    Tbt,
    /// The DP tunnel's bandwidth request for the 128b/132b stream failed
    /// (`drm_dp_tunnel_alloc_bw`; nothing past the tunnel was programmed).
    Tunnel(super::tunnel::TunnelError),
    /// No 64-slot MTP carries the stream (Linux then needs DSC).
    Slots,
    /// The 128b/132b training failed; Linux's reduced-parameter retry is not
    /// run (the route was stopped).
    Training(TrainFailure),
    /// The sink's payload table or ACT did not acknowledge the 128b/132b
    /// SST payload (the route was stopped).
    Payload,
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_dp_uhbr_tests.rs"]
mod tests;
