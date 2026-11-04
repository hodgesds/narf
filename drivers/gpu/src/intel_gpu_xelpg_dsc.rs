//! Display-14 (Meteor Lake) VESA Display Stream Compression: the sink's
//! DSC capabilities, Linux's compression decision, the per-pipe VDSC
//! engine image, the PPS secondary data packet and DP FEC.
//!
//! Sources (Linux b90c984d):
//! - `drm_dp_helper.c` / `drm_dp_helper.h`: the DSC DPCD accessors
//!   (`drm_dp_dsc_sink_*`, `drm_edp_dsc_sink_output_bpp`,
//!   `drm_dp_bw_overhead`, `drm_dp_max_dprx_data_rate`);
//! - `intel_dp.c`: `intel_dp_compute_link_config`,
//!   `intel_dp_compute_link_config_wide`, `intel_dp_compute_config_limits`
//!   (`intel_dp_dsc_compute_pipe_bpp_limits`,
//!   `intel_dp_compute_config_link_bpp_limits`),
//!   `compute_min_compressed_bpp_x16`, `compute_max_compressed_bpp_x16`,
//!   `dsc_compute_compressed_bpp`, `dsc_compute_link_config`,
//!   `intel_dp_dsc_get_slice_count`, `intel_dp_dsc_compute_config`,
//!   `intel_dp_dsc_compute_params`, `intel_dp_get_slice_height`,
//!   `intel_dp_link_required`, `intel_dp_needs_8b10b_fec`,
//!   `intel_edp_set_sink_rates`, `intel_dp_get_dsc_sink_cap`,
//!   `intel_edp_get_dsc_sink_cap`, `intel_dp_sink_set_dsc_decompression`;
//! - `intel_vdsc.c`: `intel_dsc_compute_params`, `calculate_rc_params`,
//!   `intel_dsc_pps_configure`, `intel_dsc_enable`, `intel_dsc_disable`,
//!   `intel_dsc_dp_pps_write`, `intel_vdsc_min_cdclk`,
//!   `intel_vdsc_prefill_lines`, `intel_dsc_get_config`; registers from
//!   `intel_vdsc_regs.h` (`is_pipe_dsc` is true on display 12+, so every
//!   pipe, Pipe A included, uses its own `ICL_DSC0/1` engines and
//!   `ICL_PIPE_DSS_CTL1/2`; the power domain is the pipe's own well);
//! - `intel_qp_tables.c` (`rc_range_{min,max}qp444_8bpc`);
//! - `intel_display.c`: `intel_link_compute_m_n`, `intel_set_m_n`;
//! - `intel_hdmi.c::hsw_write_infoframe` for `DP_SDP_PPS`;
//! - `intel_ddi.c`: `intel_dp_sink_set_fec_ready`,
//!   `intel_ddi_enable_fec`, `intel_ddi_disable_fec`,
//!   `intel_ddi_wait_for_fec_status`.
//!
//! The generic VESA helpers (`drm_dsc_config`, the rate-control parameter
//! derivation and PPS packing) are the shared [`crate::drm_dsc`].
//!
//! Qualified profile: one pipe, no joiner (big, ultra or uncompressed),
//! RGB with NARF's 8 bpc pipe (`pipe_bpp` 24: Linux's selection with
//! `max bpc` 8), 8b/10b SST (UHBR refused upstream), at most four slices
//! per line (two VDSC engines), no branch device. Everything else is a
//! typed [`DscRefusal`].

use crate::dp_aux::{AuxChannel, AuxError};
use crate::drm_dsc::{self, Pps};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_pipes::{Pipe, Transcoder};

// ── DPCD ─────────────────────────────────────────────────────────

/// `DP_MAX_LINK_RATE`.
const DP_MAX_LINK_RATE: usize = 0x001;
/// `DP_MAX_LANE_COUNT`.
const DP_MAX_LANE_COUNT: usize = 0x002;
/// `DP_DOWNSTREAMPORT_PRESENT`.
const DP_DOWNSTREAMPORT_PRESENT: usize = 0x005;
/// `DP_DWN_STRM_PORT_PRESENT`.
const DP_DWN_STRM_PORT_PRESENT: u8 = 1;
/// `DP_SUPPORTED_LINK_RATES` (eDP 1.4).
pub const DP_SUPPORTED_LINK_RATES: u32 = 0x010;
/// `DP_DSC_SUPPORT`, the first of the 16 DSC capability bytes.
pub const DP_DSC_SUPPORT: u32 = 0x060;
/// `DP_FEC_CAPABILITY`.
pub const DP_FEC_CAPABILITY: u32 = 0x090;
/// `DP_FEC_CAPABLE`.
pub const DP_FEC_CAPABLE: u8 = 1;
/// `DP_FEC_CONFIGURATION`.
pub const DP_FEC_CONFIGURATION: u32 = 0x120;
/// `DP_FEC_READY`.
pub const DP_FEC_READY: u8 = 1;
/// `DP_DSC_ENABLE`.
pub const DP_DSC_ENABLE: u32 = 0x160;
/// `DP_DECOMPRESSION_EN`.
pub const DP_DECOMPRESSION_EN: u8 = 1;
/// `DP_FEC_STATUS`.
pub const DP_FEC_STATUS: u32 = 0x280;
/// `DP_FEC_DECODE_EN_DETECTED`.
pub const DP_FEC_DECODE_EN_DETECTED: u8 = 1 << 0;
/// `DP_FEC_DECODE_DIS_DETECTED`.
pub const DP_FEC_DECODE_DIS_DETECTED: u8 = 1 << 1;
/// `DP_SET_POWER`.
pub const DP_SET_POWER: u32 = 0x600;
/// `DP_SET_POWER_D0`.
pub const DP_SET_POWER_D0: u8 = 1;
/// `DP_EDP_DPCD_REV`.
pub const DP_EDP_DPCD_REV: u32 = 0x700;
/// `DP_EDP_14`.
pub const DP_EDP_14: u8 = 0x03;
/// `DP_DPCD_REV_14`.
pub const DP_DPCD_REV_14: u8 = 0x14;

/// `dsc_dpcd`: the sink's DSC capabilities, DPCD 0x060..=0x06F.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DscDpcd(pub [u8; 16]);

impl DscDpcd {
    fn reg(&self, dpcd: u32) -> u8 {
        self.0[(dpcd - DP_DSC_SUPPORT) as usize]
    }

    /// `drm_dp_sink_supports_dsc`.
    pub fn supports_dsc(&self) -> bool {
        self.reg(0x060) & 1 != 0
    }

    /// `DP_DSC_REV` major.
    pub fn version_major(&self) -> u8 {
        self.reg(0x061) & 0xf
    }

    /// `intel_dp_sink_dsc_version_minor`.
    pub fn version_minor(&self) -> u8 {
        (self.reg(0x061) >> 4) & 0xf
    }

    /// `drm_dp_dsc_sink_slice_count_mask`: bit n set for n + 1 slices.
    pub fn slice_count_mask(&self, is_edp: bool) -> u32 {
        let cap1 = self.reg(0x064);
        let mut mask = 0u32;
        if !is_edp {
            let cap2 = self.reg(0x06d);
            for (bit, slices) in [(2, 24), (1, 20), (0, 16)] {
                if cap2 & (1 << bit) != 0 {
                    mask |= 1 << (slices - 1);
                }
            }
        }
        for (bit, slices) in [(7, 12), (6, 10), (5, 8), (4, 6), (3, 4), (1, 2), (0, 1)] {
            if cap1 & (1 << bit) != 0 {
                mask |= 1 << (slices - 1);
            }
        }
        mask
    }

    /// `drm_dp_dsc_sink_max_slice_count`: `fls` of the mask.
    pub fn max_slice_count(&self, is_edp: bool) -> u8 {
        (32 - self.slice_count_mask(is_edp).leading_zeros()) as u8
    }

    /// `drm_dp_dsc_sink_line_buf_depth` (0 for an invalid code).
    pub fn line_buf_depth(&self) -> u8 {
        match self.reg(0x065) & 0xf {
            0 => 9,
            1 => 10,
            2 => 11,
            3 => 12,
            4 => 13,
            5 => 14,
            6 => 15,
            7 => 16,
            8 => 8,
            _ => 0,
        }
    }

    /// `DP_DSC_BLK_PREDICTION_IS_SUPPORTED`.
    pub fn block_prediction(&self) -> bool {
        self.reg(0x066) & 1 != 0
    }

    /// `drm_edp_dsc_sink_output_bpp`: the sink's maximum bpp (x16), 0 when
    /// not declared.
    pub fn output_bpp_x16(&self) -> u16 {
        u16::from(self.reg(0x067)) | (u16::from(self.reg(0x068) & 3) << 8)
    }

    /// `drm_dp_dsc_sink_supports_format(DP_DSC_RGB)`.
    pub fn supports_rgb(&self) -> bool {
        self.reg(0x069) & 1 != 0
    }

    /// `drm_dp_dsc_sink_supported_input_bpcs`, highest first.
    pub fn input_bpcs(&self) -> ([u8; 3], usize) {
        let mut bpc = [0u8; 3];
        if !self.supports_dsc() {
            return (bpc, 0);
        }
        let depth = self.reg(0x06a);
        let mut n = 0;
        if depth & (1 << 3) != 0 {
            bpc[n] = 12;
            n += 1;
        }
        if depth & (1 << 2) != 0 {
            bpc[n] = 10;
            n += 1;
        }
        bpc[n] = 8;
        (bpc, n + 1)
    }

    /// `drm_dp_dsc_sink_max_slice_throughput` (kPixels/s).
    pub fn max_slice_throughput(&self, peak_pixel_rate: u32, rgb_yuv444: bool) -> u32 {
        let raw = self.reg(0x06b);
        let (code, delta) = if rgb_yuv444 {
            (raw & 0xf, u32::from((self.reg(0x062) >> 3) & 0x1f) * 2000)
        } else {
            (raw >> 4, 0)
        };
        let base = match code {
            0 => {
                // dsc_sink_min_slice_throughput (no delta).
                return if peak_pixel_rate >= 4_800_000 {
                    600_000
                } else if peak_pixel_rate >= 2_700_000 {
                    400_000
                } else {
                    340_000
                };
            }
            1 => 340_000,
            15 => 170_000,
            c => 400_000 + 50_000 * (u32::from(c) - 2),
        };
        base + delta
    }

    /// `drm_dp_dsc_sink_max_slice_width`.
    pub fn max_slice_width(&self) -> u32 {
        u32::from(self.reg(0x06c)) * 320
    }

    /// `drm_dp_dsc_sink_bpp_incr` (0 for a reserved code).
    pub fn bpp_incr(&self) -> u8 {
        match self.reg(0x06f) & 7 {
            0 => 16,
            1 => 8,
            2 => 4,
            3 => 2,
            4 => 1,
            _ => 0,
        }
    }
}

/// Typed refusals: every configuration Linux would not compress, or that
/// this driver does not qualify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DscRefusal {
    /// The sink does not decompress (`DP_DSC_SUPPORT`, or an eDP below 1.4).
    SinkUnsupported,
    /// The VBT's eDP block disables DSC (`edp.dsc_disable`).
    VbtDisabled,
    /// The VBT picks the panel by EDID PnP ID, which is not implemented.
    VbtPanelUnknown,
    /// DP DSC needs FEC and the sink is not FEC capable.
    FecUnsupported,
    /// The sink cannot decompress RGB.
    FormatUnsupported,
    /// No compressed bpp range (`intel_dp_compute_config_limits` false).
    NoBppRange,
    /// No compressed bpp fits a link configuration.
    NoLinkConfig,
    /// No slice count the sink and source share.
    NoSliceCount,
    /// More than four slices per line: two VDSC engines, no joiner.
    SliceCountUnqualified,
    /// `intel_dsc_slice_dimensions_valid`.
    SliceDimensions,
    /// The sink's line buffer depth code is invalid.
    LineBufDepth,
    /// `drm_dsc_compute_rc_parameters` -ERANGE.
    RcParameters,
    /// Linux carries the stream uncompressed at 6 bpc; the pipe is 8 bpc.
    SixBpcUnqualified,
    /// The link's maximum rate is not RBR, HBR, HBR2 or HBR3.
    LinkRateUnqualified,
    /// The compressed stream exceeds the eDP link Linux trains (this
    /// driver's guard; Linux's eDP path does not check).
    OverBudget,
    /// The DP sink is a branch device.
    BranchDevice,
    /// Training ended below the link the configuration was computed for.
    TrainingFallback,
}

// ── Source (display 14) ──────────────────────────────────────────

/// NARF's pipe: 8 bpc (`PIPE_MISC` BPC_8); Linux's `crtc_state->pipe_bpp`
/// with `max bpc` 8.
pub const PIPE_BPP: u32 = 24;
/// `intel_display_min_pipe_bpp`.
const MIN_PIPE_BPP: u32 = 18;
/// `intel_dp_dsc_min_src_input_bpc` / `_max_src_input_bpc` (display 12+).
const SRC_MIN_INPUT_BPC: u32 = 8;
const SRC_MAX_INPUT_BPC: u32 = 12;
/// `intel_dp_dsc_min_src_compressed_bpp`.
const SRC_MIN_COMPRESSED_BPP: u32 = 8;
/// `dsc_src_max_compressed_bpp` (display 13+, no forcing).
const SRC_MAX_COMPRESSED_BPP: u32 = 27;
/// `intel_dp_dsc_sink_min_compressed_bpp` (RGB).
const SINK_MIN_COMPRESSED_BPP: u32 = 8;
/// `small_joiner_ram_size_bits` (display 13+).
const SMALL_JOINER_RAM_BITS: u32 = 17280 * 8;
/// `INTEL_DP_DSC_MAX_LINE_BUF_DEPTH`.
const MAX_LINE_BUF_DEPTH: u8 = 13;
/// `intel_dp_source_dsc_version_minor` (display 14).
const SOURCE_VERSION_MINOR: u8 = 2;
/// `display->cdclk.max_cdclk_freq` at MTL's 38.4 MHz reference.
pub const MAX_CDCLK_KHZ: u32 = 652_800;
/// `DP_DSC_FEC_OVERHEAD_FACTOR` (ppm).
const FEC_OVERHEAD_FACTOR: u64 = 1_028_530;
/// The 8b/10b DP rates this driver programs (Linux link-rate units).
pub const DP_RATES: [u32; 4] = [162_000, 270_000, 540_000, 810_000];
/// `mtl_rates` up to the C10 PHY's 810000 (`mtl_max_source_rate`).
const MTL_C10_RATES: [u32; 9] = [
    162_000, 216_000, 243_000, 270_000, 324_000, 432_000, 540_000, 675_000, 810_000,
];

// ── Link bandwidth (8b/10b SST) ──────────────────────────────────

/// `drm_dp_max_dprx_data_rate` for an 8b/10b link, in kBps.
pub fn max_link_data_rate(link_rate: u32, lanes: u32) -> u64 {
    u64::from(link_rate) * 10 * u64::from(lanes) * 800_000 / (1_000_000 * 8)
}

/// `intel_dp_link_bw_overhead` for SST 8b/10b without DSC slices (what
/// `intel_dp_link_required` passes): `drm_dp_bw_overhead`, at least the
/// FEC factor. ppm, 100% = 1000000.
fn link_bw_overhead(lanes: u32, hactive: u32, bpp_x16: u32, fec: bool) -> u64 {
    if lanes == 0 || hactive == 0 || bpp_x16 == 0 {
        return 0;
    }
    let overhead = 1_000_000u64 + if fec { 24_016 } else { 0 };
    // drm_dp_link_data_symbol_cycles, symbol size 8, SST alignment 1.
    let cycles = (u64::from(hactive) * u64::from(bpp_x16)).div_ceil(16 * 8 * u64::from(lanes));
    let bw = (cycles * 8 * u64::from(lanes) * overhead * 16)
        .div_ceil(u64::from(hactive) * u64::from(bpp_x16));
    bw.max(if fec { FEC_OVERHEAD_FACTOR } else { 1_000_000 })
}

/// `intel_dp_effective_data_rate` (kBps).
fn effective_data_rate(pixel_clock: u32, bpp_x16: u32, overhead: u64) -> u64 {
    (u64::from(pixel_clock) * u64::from(bpp_x16) * overhead).div_ceil(1_000_000 * 16 * 8)
}

/// `intel_dp_link_required` (SST 8b/10b), kBps.
pub fn link_required(lanes: u32, mode_clock: u32, hdisplay: u32, bpp_x16: u32, fec: bool) -> u64 {
    effective_data_rate(
        mode_clock,
        bpp_x16,
        link_bw_overhead(lanes, hdisplay, bpp_x16, fec),
    )
}

/// The link Linux picks from: the common rates (ascending, in Linux link
/// units) and the lane count range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkLimits {
    /// Common rates (`intel_dp->common_rates`), ascending; 0 terminates.
    pub rates: [u32; 9],
    /// `limits->max_lane_count` (1, 2 or 4).
    pub max_lanes: u8,
}

impl LinkLimits {
    /// The standard DP rates up to `max_rate`, `max_lanes` lanes.
    pub fn standard(max_rate: u32, max_lanes: u8) -> Self {
        let mut rates = [0u32; 9];
        for (dst, &r) in rates
            .iter_mut()
            .zip(DP_RATES.iter().filter(|&&r| r <= max_rate))
        {
            *dst = r;
        }
        Self {
            rates,
            max_lanes: lane_floor(max_lanes),
        }
    }

    fn rates(&self) -> impl Iterator<Item = u32> + '_ {
        self.rates.iter().copied().take_while(|&r| r != 0)
    }

    /// `limits->max_rate`.
    pub fn max_rate(&self) -> u32 {
        self.rates().last().unwrap_or(0)
    }

    fn lanes(&self) -> impl Iterator<Item = u32> {
        let max = u32::from(self.max_lanes);
        [1u32, 2, 4].into_iter().filter(move |&l| l <= max)
    }
}

/// The largest of 4, 2, 1 not above `lanes` (1 for 0).
fn lane_floor(lanes: u8) -> u8 {
    match lanes {
        4.. => 4,
        2 | 3 => 2,
        _ => 1,
    }
}

/// `intel_dp_compute_link_config_wide` for NARF's pipe: the highest
/// uncompressed bpp in 24..=18 (steps of 6), then the lowest rate, then
/// the fewest lanes, that carries the mode. `None` when DSC is needed.
pub fn uncompressed_link(limits: &LinkLimits, mode: &Mode) -> Option<(u32, u32, u8)> {
    let mut bpp = PIPE_BPP;
    while bpp >= MIN_PIPE_BPP {
        for rate in limits.rates() {
            for lanes in limits.lanes() {
                let need = link_required(
                    lanes,
                    mode.pixel_clock_khz,
                    u32::from(mode.h_active),
                    bpp * 16,
                    false,
                );
                if need <= max_link_data_rate(rate, lanes) {
                    return Some((bpp, rate, lanes as u8));
                }
            }
        }
        bpp -= 6;
    }
    None
}

// ── eDP sink ─────────────────────────────────────────────────────

/// The eDP panel's link and DSC capabilities as `intel_edp_init_dpcd`
/// reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdpCaps {
    /// DPCD 0x000..=0x00F.
    pub receiver: [u8; 16],
    /// `DP_EDP_DPCD_REV`.
    pub edp_rev: u8,
    /// `DP_SUPPORTED_LINK_RATES` (eDP 1.4+), raw little-endian entries.
    pub link_rates: [u16; 8],
    /// DSC capabilities (eDP 1.4+, else zero).
    pub dsc: DscDpcd,
}

impl EdpCaps {
    /// Read the receiver capabilities, the eDP revision and, for eDP 1.4+,
    /// the link-rate table and the DSC capabilities (`intel_edp_init_dpcd`,
    /// `intel_edp_set_sink_rates`, `intel_edp_get_dsc_sink_cap`).
    pub fn read<A: AuxChannel>(aux: &mut A) -> Result<Self, AuxError> {
        let mut receiver = [0u8; 16];
        aux.dpcd_read(0, &mut receiver)?;
        let mut rev = [0u8; 1];
        aux.dpcd_read(DP_EDP_DPCD_REV, &mut rev)?;
        let mut link_rates = [0u16; 8];
        let mut dsc = DscDpcd::default();
        if rev[0] >= DP_EDP_14 {
            let mut raw = [0u8; 16];
            aux.dpcd_read(DP_SUPPORTED_LINK_RATES, &mut raw)?;
            for (i, rate) in link_rates.iter_mut().enumerate() {
                *rate = u16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]);
            }
            aux.dpcd_read(DP_DSC_SUPPORT, &mut dsc.0)?;
        }
        Ok(Self {
            receiver,
            edp_rev: rev[0],
            link_rates,
            dsc,
        })
    }

    /// `intel_dp_has_dsc` without the VBT: an eDP 1.4+ sink that
    /// decompresses.
    pub fn dsc_capable(&self) -> bool {
        self.edp_rev >= DP_EDP_14 && self.dsc.supports_dsc()
    }

    /// The common rates of this panel and the C10 PHY, capped by the VBT's
    /// eDP maximum (`vbt_max_link_rate`; 0 for none), and the panel's lane
    /// count: `intel_dp_common_rates` / `intel_dp_max_common_lane_count`.
    pub fn limits(&self, vbt_max_rate: u32) -> LinkLimits {
        let src_max = if vbt_max_rate != 0 {
            vbt_max_rate.min(810_000)
        } else {
            810_000
        };
        let mut rates = [0u32; 9];
        let mut n = 0;
        let table: usize = self.link_rates.iter().take_while(|&&r| r != 0).count();
        if table != 0 {
            // intel_edp_set_sink_rates: rate = val * 200 / 10; then the
            // intersection with the source rates (both ascending).
            let mut sink = [0u32; 8];
            for (dst, &v) in sink.iter_mut().zip(self.link_rates.iter().take(table)) {
                *dst = u32::from(v) * 200 / 10;
            }
            for &r in MTL_C10_RATES.iter().filter(|&&r| r <= src_max) {
                if sink[..table].contains(&r) && n < rates.len() {
                    rates[n] = r;
                    n += 1;
                }
            }
        } else {
            // intel_dp_set_dpcd_sink_rates: the standard rates up to
            // DP_MAX_LINK_RATE (drm_dp_bw_code_to_link_rate).
            let max = u32::from(self.receiver[DP_MAX_LINK_RATE]) * 27_000;
            for &r in DP_RATES.iter().filter(|&&r| r <= max && r <= src_max) {
                rates[n] = r;
                n += 1;
            }
        }
        LinkLimits {
            rates,
            max_lanes: lane_floor((self.receiver[DP_MAX_LANE_COUNT] & 0x1f).min(4)),
        }
    }
}

/// The VBT facts the eDP DSC decision reads (`panel->vbt.edp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdpVbt {
    /// No VBT: DSC allowed, no rate cap.
    Missing,
    /// The panel is chosen by PnP ID (not implemented).
    PanelByPnpId,
    /// The selected panel's `dsc_disable` and `max_link_rate` (0: none).
    Panel {
        /// `edp.dsc_disable`.
        dsc_disable: bool,
        /// `edp.max_link_rate` in link units, 0 when absent.
        max_link_rate: u32,
    },
}

impl EdpVbt {
    /// `intel_bios_init_panel`'s eDP facts for the port-A panel of a
    /// display-14 VBT, with the panel selection `VbtPsr::from_vbt` uses.
    pub fn from_vbt(vbt: &crate::intel_gpu_vbt::Vbt) -> Self {
        use crate::intel_gpu_vbt::{port, PanelType, VbtPlatform};
        let second = vbt
            .encoder(VbtPlatform::MeteorLake, port::A)
            .and_then(|encoder| vbt.children().get(encoder.child))
            .is_some_and(|child| child.handle() == 0x0080);
        match vbt.panel_type(second) {
            PanelType::PnpId => EdpVbt::PanelByPnpId,
            panel => match vbt.edp_panel(panel.index_or_fallback()) {
                Some(edp) => EdpVbt::Panel {
                    dsc_disable: edp.dsc_disable.unwrap_or(false),
                    max_link_rate: edp.max_link_rate_khz.unwrap_or(0),
                },
                None => EdpVbt::Panel {
                    dsc_disable: false,
                    max_link_rate: 0,
                },
            },
        }
    }

    /// `vbt.edp.max_link_rate` (0 for none).
    pub fn max_link_rate(&self) -> u32 {
        match *self {
            EdpVbt::Panel { max_link_rate, .. } => max_link_rate,
            _ => 0,
        }
    }

    /// `intel_dp_has_dsc`'s VBT term.
    pub fn allows_dsc(&self) -> Result<(), DscRefusal> {
        match *self {
            EdpVbt::Missing => Ok(()),
            EdpVbt::PanelByPnpId => Err(DscRefusal::VbtPanelUnknown),
            EdpVbt::Panel { dsc_disable, .. } => {
                if dsc_disable {
                    Err(DscRefusal::VbtDisabled)
                } else {
                    Ok(())
                }
            }
        }
    }
}

static EDP_VBT: narf_lib::sync::IrqSafeSpinLock<EdpVbt> =
    narf_lib::sync::IrqSafeSpinLock::new(EdpVbt::Missing);

/// Install the probe's eDP VBT facts ([`EdpVbt::Missing`] without a VBT).
pub fn install_edp_vbt(vbt: EdpVbt) {
    *EDP_VBT.lock() = vbt;
}

/// The installed eDP VBT facts.
pub fn installed_edp_vbt() -> EdpVbt {
    *EDP_VBT.lock()
}

/// What the Pipe-A eDP modeset does with a panel (`intel_dp_compute_link_config`
/// for NARF's 8 bpc pipe).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EdpDecision {
    /// The panel is not DSC capable: the uncompressed path, unchanged.
    NotCapable,
    /// 24 bpp fits the panel's link uncompressed.
    Uncompressed,
    /// Compress with this plan.
    Dsc(DscPlan),
}

/// `intel_dp_compute_link_config` for the eDP panel: uncompressed when
/// 24 bpp fits, a refusal when only 18 bpp fits, DSC otherwise.
pub fn decide_edp(caps: &EdpCaps, vbt: &EdpVbt, mode: &Mode) -> Result<EdpDecision, DscRefusal> {
    if !caps.dsc_capable() {
        return Ok(EdpDecision::NotCapable);
    }
    let limits = caps.limits(vbt.max_link_rate());
    match uncompressed_link(&limits, mode) {
        Some((PIPE_BPP, _, _)) => return Ok(EdpDecision::Uncompressed),
        Some(_) => return Err(DscRefusal::SixBpcUnqualified),
        None => {}
    }
    vbt.allows_dsc()?;
    if !DP_RATES.contains(&limits.max_rate()) {
        return Err(DscRefusal::LinkRateUnqualified);
    }
    let sink = DscSink {
        dpcd: caps.dsc,
        is_edp: true,
        fec_capable: false,
    };
    compute(&sink, &limits, mode).map(EdpDecision::Dsc)
}

// ── Compression decision ─────────────────────────────────────────

/// The sink as the decision reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscSink {
    /// DPCD 0x060..=0x06F.
    pub dpcd: DscDpcd,
    /// eDP: no FEC, the maximum link, the sink's maximum slice count.
    pub is_edp: bool,
    /// `DP_FEC_CAPABILITY & DP_FEC_CAPABLE` (DP).
    pub fec_capable: bool,
}

/// A computed DSC configuration (`crtc_state->dsc` and its link).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DscPlan {
    /// `port_clock` (Linux link units).
    pub link_rate: u32,
    /// `lane_count`.
    pub lanes: u8,
    /// `pipe_bpp`.
    pub pipe_bpp: u32,
    /// `dsc.compressed_bpp_x16`.
    pub compressed_bpp_x16: u16,
    /// `dsc.slice_count` (total slices per line).
    pub slice_count: u8,
    /// `dsc.num_streams` (VDSC engines on the pipe).
    pub num_streams: u8,
    /// `fec_enable`.
    pub fec: bool,
    /// `dsc.config`.
    pub config: Pps,
}

/// `intel_dp_dsc_bpp_step_x16` (display 14, SST).
fn bpp_step_x16(dpcd: &DscDpcd) -> u32 {
    match dpcd.bpp_incr() {
        0 => 16,
        incr => 16 / u32::from(incr),
    }
}

/// `round_down` / `round_up` for a power-of-two step.
fn round_down(x: u32, step: u32) -> u32 {
    x & !(step - 1)
}
fn round_up(x: u32, step: u32) -> u32 {
    ((x - 1) | (step - 1)) + 1
}

/// `intel_dp_dsc_compute_pipe_bpp_limits` from Linux's 18..=`PIPE_BPP`:
/// the source's 8..=12 bpc aligned to the sink's input depths.
fn pipe_bpp_limits(dpcd: &DscDpcd) -> Option<(u32, u32)> {
    let (bpcs, n) = dpcd.input_bpcs();
    let min = MIN_PIPE_BPP.max(SRC_MIN_INPUT_BPC * 3);
    let max = PIPE_BPP.min(SRC_MAX_INPUT_BPC * 3);
    // align_min_sink_dsc_input_bpp: lowest first; align_max: highest first.
    let min = bpcs[..n]
        .iter()
        .rev()
        .map(|&b| u32::from(b) * 3)
        .find(|&b| b >= min)?;
    let max = bpcs[..n]
        .iter()
        .map(|&b| u32::from(b) * 3)
        .find(|&b| b <= max)?;
    (min <= max).then_some((min, max))
}

/// `align_max_compressed_bpp_x16` (display 13+, RGB).
fn align_max_compressed_bpp_x16(step: u32, pipe_bpp: u32, max_bpp_x16: u32) -> u32 {
    round_down(max_bpp_x16.min(pipe_bpp * 16 - step), step)
}

/// `compute_min_compressed_bpp_x16` (RGB, display 13+).
fn min_compressed_bpp_x16(dpcd: &DscDpcd) -> u32 {
    round_up(
        SRC_MIN_COMPRESSED_BPP.max(SINK_MIN_COMPRESSED_BPP) * 16,
        bpp_step_x16(dpcd),
    )
}

/// `compute_max_compressed_bpp_x16` for one pipe, RGB, no throughput quirk.
fn max_compressed_bpp_x16(dpcd: &DscDpcd, hdisplay: u32, pipe_max_bpp: u32, link_max: u32) -> u32 {
    let joiner = SMALL_JOINER_RAM_BITS / hdisplay;
    // intel_dp_dsc_max_sink_compressed_bppx16 >> 4.
    let sink = match dpcd.output_bpp_x16() {
        0 => 3 * (pipe_max_bpp / 3),
        x16 => u32::from(x16) >> 4,
    };
    let dsc_max = sink.min(SRC_MAX_COMPRESSED_BPP).min(joiner);
    align_max_compressed_bpp_x16(bpp_step_x16(dpcd), pipe_max_bpp, link_max.min(dsc_max * 16))
}

/// `intel_dp_dsc_get_slice_count` for one pipe and a non-branch sink.
fn dp_slice_count(dpcd: &DscDpcd, mode_clock: u32, hdisplay: u32) -> u8 {
    let mask = dpcd.slice_count_mask(false);
    let tp = dpcd
        .max_slice_throughput(mode_clock, true)
        .min(dpcd.max_slice_throughput(mode_clock, false));
    let mut min = mode_clock.div_ceil(tp);
    if mode_clock >= MAX_CDCLK_KHZ * 85 / 100 {
        min = min.max(2);
    }
    let width = dpcd.max_slice_width();
    if width < 2560 {
        return 0;
    }
    min = min.max(hdisplay.div_ceil(width));
    // valid_dsc_slicecount {1, 2, 3, 4}; 3 needs three engines (no MTL).
    for n in [1u32, 2, 4] {
        if mask & (1 << (n - 1)) == 0 || hdisplay % n != 0 {
            continue;
        }
        if min <= n {
            return n as u8;
        }
    }
    0
}

/// `intel_dp_get_slice_height`.
pub fn slice_height(vactive: u32) -> u32 {
    let mut h = 108;
    while h <= vactive {
        if vactive % h == 0 {
            return h;
        }
        h += 2;
    }
    2
}

/// `intel_dp_dsc_compute_config` (SST, one pipe) after
/// `intel_dp_compute_config_limits(dsc = true)`.
pub fn compute(sink: &DscSink, limits: &LinkLimits, mode: &Mode) -> Result<DscPlan, DscRefusal> {
    let dpcd = &sink.dpcd;
    // intel_dp_supports_dsc: DSC, and FEC on DP.
    if !dpcd.supports_dsc() {
        return Err(DscRefusal::SinkUnsupported);
    }
    let fec = !sink.is_edp;
    if fec && !sink.fec_capable {
        return Err(DscRefusal::FecUnsupported);
    }
    let hdisplay = u32::from(mode.h_active);
    let clock = mode.pixel_clock_khz;
    if hdisplay == 0 || clock == 0 {
        return Err(DscRefusal::NoBppRange);
    }
    // intel_dp_compute_config_limits(dsc = true).
    let (_, pipe_max) = pipe_bpp_limits(dpcd).ok_or(DscRefusal::NoBppRange)?;
    let min_x16 = min_compressed_bpp_x16(dpcd);
    let max_x16 = max_compressed_bpp_x16(dpcd, hdisplay, pipe_max, pipe_max * 16);
    if min_x16 == 0 || min_x16 > max_x16 {
        return Err(DscRefusal::NoBppRange);
    }
    if !dpcd.supports_rgb() {
        return Err(DscRefusal::FormatUnsupported);
    }
    // intel_dp_dsc_compute_pipe_bpp / dsc_compute_compressed_bpp.
    let step = bpp_step_x16(dpcd);
    let max_x16 = align_max_compressed_bpp_x16(step, pipe_max, max_x16);
    let (link_rate, lanes, bpp_x16) = if sink.is_edp {
        (limits.max_rate(), limits.max_lanes, max_x16)
    } else {
        let mut found = None;
        let mut bpp = max_x16;
        'bpp: while bpp >= min_x16 {
            for rate in limits.rates() {
                for lanes in limits.lanes() {
                    if link_required(lanes, clock, hdisplay, bpp, fec)
                        <= max_link_data_rate(rate, lanes)
                    {
                        found = Some((rate, lanes as u8, bpp));
                        break 'bpp;
                    }
                }
            }
            bpp -= step;
        }
        found.ok_or(DscRefusal::NoLinkConfig)?
    };
    // Guard: the compressed stream must fit the link it trains (Linux's
    // eDP path takes the maximum link without this check).
    if link_required(u32::from(lanes), clock, hdisplay, bpp_x16, fec)
        > max_link_data_rate(link_rate, u32::from(lanes))
    {
        return Err(DscRefusal::OverBudget);
    }
    let slice_count = if sink.is_edp {
        dpcd.max_slice_count(true)
    } else {
        dp_slice_count(dpcd, clock, hdisplay)
    };
    if slice_count == 0 {
        return Err(DscRefusal::NoSliceCount);
    }
    if slice_count > 4 {
        return Err(DscRefusal::SliceCountUnqualified);
    }
    let num_streams = if slice_count > 1 { 2 } else { 1 };
    let config = compute_params(dpcd, mode, slice_count, pipe_max, bpp_x16 as u16)?;
    Ok(DscPlan {
        link_rate,
        lanes,
        pipe_bpp: pipe_max,
        compressed_bpp_x16: bpp_x16 as u16,
        slice_count,
        num_streams,
        fec,
        config,
    })
}

// ── Rate control (intel_vdsc.c) ──────────────────────────────────

/// `rc_range_minqp444_8bpc` (intel_qp_tables.c): [buffer range][bpp index], bpp 6..=24
/// in steps of 0.5.
const MIN_QP_444_8BPC: [[u8; 37]; 15] = [
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        3, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        3, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        5, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        5, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        5, 5, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        5, 5, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
        1, 1, 0, 0, 0, 0, 0,
    ],
    [
        5, 5, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
        1, 1, 1, 1, 0, 0, 0,
    ],
    [
        6, 5, 5, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 1, 1,
        1, 1, 1, 1, 0, 0, 0,
    ],
    [
        6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 1, 1,
        1, 1, 1, 1, 1, 1, 0,
    ],
    [
        6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 2, 2,
        2, 2, 1, 1, 1, 1, 0,
    ],
    [
        6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 3, 3, 2, 2,
        2, 2, 1, 1, 1, 1, 0,
    ],
    [
        9, 9, 9, 9, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 6, 6, 5, 5, 5, 5, 4, 4, 3, 3,
        3, 3, 2, 2, 1, 1, 1,
    ],
    [
        14, 14, 13, 13, 12, 12, 12, 12, 11, 11, 10, 10, 10, 10, 9, 9, 9, 8, 8, 8, 7, 7, 7, 7, 6, 6,
        5, 5, 5, 5, 4, 4, 4, 3, 3, 3, 3,
    ],
];
/// `rc_range_maxqp444_8bpc` (intel_qp_tables.c): [buffer range][bpp index], bpp 6..=24
/// in steps of 0.5.
const MAX_QP_444_8BPC: [[u8; 37]; 15] = [
    [
        4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ],
    [
        6, 6, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0, 0, 0, 0, 0,
    ],
    [
        8, 7, 7, 6, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0, 0, 0, 0, 0,
    ],
    [
        8, 8, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 4, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 0,
    ],
    [
        9, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 6, 6, 5, 4, 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
        1, 1, 1, 1, 1, 1, 0,
    ],
    [
        9, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 6, 6, 6, 5, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2,
        1, 1, 1, 1, 1, 1, 1,
    ],
    [
        9, 9, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 6, 6, 5, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2,
        1, 1, 1, 1, 1, 1, 1,
    ],
    [
        10, 10, 9, 9, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 7, 6, 5, 5, 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 2, 2,
        2, 2, 1, 1, 1, 1, 1,
    ],
    [
        11, 11, 10, 10, 9, 9, 9, 9, 9, 9, 8, 8, 8, 7, 7, 6, 6, 5, 5, 5, 5, 5, 4, 4, 4, 4, 3, 3, 2,
        2, 2, 2, 2, 2, 1, 1, 1,
    ],
    [
        12, 11, 11, 10, 10, 10, 9, 9, 9, 9, 9, 9, 9, 8, 8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 3, 3,
        2, 2, 2, 2, 2, 2, 1, 1, 1,
    ],
    [
        12, 12, 11, 11, 10, 10, 10, 10, 10, 10, 9, 9, 9, 8, 8, 7, 7, 6, 6, 6, 5, 5, 4, 4, 4, 4, 3,
        3, 2, 2, 2, 2, 2, 2, 2, 2, 1,
    ],
    [
        12, 12, 12, 11, 11, 11, 10, 10, 10, 10, 9, 9, 9, 9, 8, 8, 8, 7, 7, 7, 6, 6, 5, 5, 5, 5, 4,
        4, 3, 3, 3, 3, 2, 2, 2, 2, 1,
    ],
    [
        12, 12, 12, 12, 11, 11, 11, 11, 11, 10, 10, 9, 9, 9, 8, 8, 8, 7, 7, 7, 6, 6, 5, 5, 5, 5, 4,
        4, 3, 3, 3, 3, 2, 2, 2, 2, 1,
    ],
    [
        13, 13, 13, 13, 12, 12, 11, 11, 11, 11, 10, 10, 10, 10, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 6, 6,
        5, 5, 4, 4, 4, 4, 3, 3, 2, 2, 2,
    ],
    [
        15, 15, 14, 14, 13, 13, 13, 13, 12, 12, 11, 11, 11, 11, 10, 10, 10, 9, 9, 9, 8, 8, 8, 8, 7,
        7, 6, 6, 6, 6, 5, 5, 5, 4, 4, 4, 4,
    ],
];

/// `DIV_ROUND_UP` on C `int`s (truncating division, negative divisors
/// included).
fn div_round_up_i32(n: i32, d: i32) -> i32 {
    (n + d - 1) / d
}

/// `get_range_bpg_offset`.
fn range_bpg_offset(bpp_low: i32, ofs_low: i32, bpp_high: i32, ofs_high: i32, bpp: i32) -> i32 {
    ofs_low + div_round_up_i32((ofs_high - ofs_low) * (bpp - bpp_low), bpp_low - bpp_high)
}

/// `calculate_rc_params` for a non-4:2:0 stream.
fn calculate_rc_params(c: &mut Pps) {
    let bpp = i32::from(c.bits_per_pixel >> 4);
    let bpc = i32::from(c.bits_per_component);
    let qp_bpc_modifier = (bpc - 8) * 2;
    let slice_height = i32::from(c.slice_height);
    let first = if slice_height >= 8 {
        12 + (9 * 34.min(slice_height - 8)) / 100
    } else {
        2 * (slice_height - 1)
    };
    let uncompressed_bpg_rate = (3 * bpc + if c.convert_rgb { 0 } else { 2 }) * 3;
    c.first_line_bpg_offset = first.clamp(0, uncompressed_bpg_rate - 3 * bpp) as u8;
    c.initial_offset = if bpp >= 12 {
        2048
    } else if bpp >= 10 {
        (5632 - div_round_up_i32((bpp - 10) * 3584, 2)) as u16
    } else if bpp >= 8 {
        (6144 - div_round_up_i32((bpp - 8) * 512, 2)) as u16
    } else {
        6144
    };
    c.initial_xmit_delay =
        div_round_up_i32(i32::from(drm_dsc::RC_MODEL_SIZE_CONST), 2 * bpp) as u16;
    c.flatness_min_qp = (3 + qp_bpc_modifier) as u8;
    c.flatness_max_qp = (12 + qp_bpc_modifier) as u8;
    c.rc_quant_incr_limit0 = (11 + qp_bpc_modifier) as u8;
    c.rc_quant_incr_limit1 = (11 + qp_bpc_modifier) as u8;
    const OFS_UND6: [i32; 15] = [
        0, -2, -2, -4, -6, -6, -8, -8, -8, -10, -10, -12, -12, -12, -12,
    ];
    const OFS_UND8: [i32; 15] = [
        2, 0, 0, -2, -4, -6, -8, -8, -8, -10, -10, -10, -12, -12, -12,
    ];
    const OFS_UND12: [i32; 15] = [
        2, 0, 0, -2, -4, -6, -8, -8, -8, -10, -10, -10, -12, -12, -12,
    ];
    const OFS_UND15: [i32; 15] = [10, 8, 6, 4, 2, 0, -2, -4, -6, -8, -10, -10, -12, -12, -12];
    // fxp_q4_to_frac is in 1/16ths, never >= 5000: the index is bpp - 6.
    let bpp_i = (bpp - 6) as usize;
    for buf in 0..drm_dsc::NUM_BUF_RANGES {
        let ofs = if bpp <= 6 {
            OFS_UND6[buf]
        } else if bpp <= 8 {
            range_bpg_offset(6, OFS_UND6[buf], 8, OFS_UND8[buf], bpp)
        } else if bpp <= 12 {
            range_bpg_offset(8, OFS_UND8[buf], 12, OFS_UND12[buf], bpp)
        } else if bpp <= 15 {
            range_bpg_offset(12, OFS_UND12[buf], 15, OFS_UND15[buf], bpp)
        } else {
            OFS_UND15[buf]
        };
        c.rc_range_params[buf] = (
            MIN_QP_444_8BPC[buf][bpp_i],
            MAX_QP_444_8BPC[buf][bpp_i],
            (ofs as u8) & drm_dsc::RANGE_BPG_OFFSET_MASK,
        );
    }
}

/// `intel_dp_dsc_compute_params` with `intel_dsc_compute_params` (RGB,
/// display 14, not DSI).
fn compute_params(
    dpcd: &DscDpcd,
    mode: &Mode,
    slice_count: u8,
    pipe_bpp: u32,
    compressed_bpp_x16: u16,
) -> Result<Pps, DscRefusal> {
    let mut c = Pps {
        rc_model_size: drm_dsc::RC_MODEL_SIZE_CONST,
        pic_height: mode.v_active,
        slice_height: slice_height(u32::from(mode.v_active)) as u16,
        pic_width: mode.h_active,
        slice_width: mode.h_active.div_ceil(u16::from(slice_count)),
        ..Pps::default()
    };
    // intel_dsc_slice_dimensions_valid (RGB).
    if c.slice_height > 4095 || u32::from(c.slice_height) * u32::from(c.slice_width) < 15000 {
        return Err(DscRefusal::SliceDimensions);
    }
    c.convert_rgb = true;
    c.bits_per_pixel = compressed_bpp_x16;
    c.bits_per_component = (pipe_bpp / 3) as u8;
    if c.bits_per_component != 8 {
        // The QP tables carried here are the 8 bpc ones (NARF's pipe).
        return Err(DscRefusal::NoBppRange);
    }
    drm_dsc::set_rc_buf_thresh(&mut c);
    calculate_rc_params(&mut c);
    c.mux_word_size = if c.bits_per_component <= 10 {
        drm_dsc::MUX_WORD_SIZE_8_10_BPC
    } else {
        drm_dsc::MUX_WORD_SIZE_12_BPC
    };
    c.initial_scale_value =
        ((u32::from(c.rc_model_size) << 3) / u32::from(c.rc_model_size - c.initial_offset)) as u8;
    c.dsc_version_major = dpcd.version_major();
    c.dsc_version_minor = SOURCE_VERSION_MINOR.min(dpcd.version_minor());
    if c.convert_rgb {
        c.convert_rgb = dpcd.supports_rgb();
    }
    c.line_buf_depth = MAX_LINE_BUF_DEPTH.min(dpcd.line_buf_depth());
    if c.line_buf_depth == 0 {
        return Err(DscRefusal::LineBufDepth);
    }
    c.block_pred_enable = dpcd.block_prediction();
    drm_dsc::compute_rc_parameters(&mut c).ok_or(DscRefusal::RcParameters)?;
    Ok(c)
}

// ── Engine registers (intel_vdsc_regs.h) ─────────────────────────

/// `_MMIO_PIPE(pipe - PIPE_B, pb, pc)` with the 0x200 per-pipe stride
/// (Pipe A at `pb - 0x200`).
const fn pipe_reg(pipe: Pipe, pb: u64) -> u64 {
    pb + (pipe as u64) * 0x200 - 0x200
}

/// `ICL_PIPE_DSS_CTL1`.
pub const fn dss_ctl1(pipe: Pipe) -> u64 {
    pipe_reg(pipe, 0x7_8200)
}
/// `ICL_PIPE_DSS_CTL2`.
pub const fn dss_ctl2(pipe: Pipe) -> u64 {
    pipe_reg(pipe, 0x7_8204)
}
/// `ICL_DSC0_PPS` / `ICL_DSC1_PPS` (`engine` 0 or 1).
pub const fn pps_reg(pipe: Pipe, engine: u64, pps: u64) -> u64 {
    pipe_reg(pipe, 0x7_8270 + engine * 0x100) + pps * 4
}
/// `ICL_DSC{0,1}_RC_BUF_THRESH_{0,0_UDW,1,1_UDW}`.
const fn rc_buf_thresh_reg(pipe: Pipe, engine: u64, i: u64) -> u64 {
    pipe_reg(pipe, 0x7_8254 + engine * 0x100) + i * 4
}
/// `ICL_DSC{0,1}_RC_RANGE_PARAMETERS_{0..3}{,_UDW}`.
const fn rc_range_reg(pipe: Pipe, engine: u64, i: u64) -> u64 {
    pipe_reg(pipe, 0x7_8208 + engine * 0x100) + i * 4
}

/// `JOINER_ENABLE` (DSS_CTL1).
pub const JOINER_ENABLE: u32 = 1 << 30;
/// `VDSC0_ENABLE` (DSS_CTL2).
pub const VDSC0_ENABLE: u32 = 1 << 31;
/// `VDSC1_ENABLE` (DSS_CTL2).
pub const VDSC1_ENABLE: u32 = 1 << 15;
/// `VDIP_ENABLE_PPS` (`HSW_TVIDEO_DIP_CTL`).
pub const VDIP_ENABLE_PPS: u32 = 1 << 24;
/// `HSW_TVIDEO_DIP_CTL` offset from the transcoder base.
const VIDEO_DIP_CTL_OFFSET: u64 = 0x200;
/// `ICL_VIDEO_DIP_PPS_DATA` offset from the transcoder base.
const VIDEO_DIP_PPS_DATA_OFFSET: u64 = 0x350;
/// `VIDEO_DIP_PPS_DATA_SIZE` / 4.
pub const PPS_SDP_DWORDS: usize = 33;
/// `DP_TP_CTL_FEC_ENABLE`.
pub const DP_TP_CTL_FEC_ENABLE: u32 = 1 << 30;
/// `DP_TP_STATUS_FEC_ENABLE_LIVE` (`TGL_DP_TP_STATUS`).
pub const DP_TP_STATUS_FEC_ENABLE_LIVE: u32 = 1 << 28;
/// `TGL_DP_TP_CTL` / `TGL_DP_TP_STATUS` offsets from the transcoder base.
const DP_TP_CTL_OFFSET: u64 = 0x540;
const DP_TP_STATUS_OFFSET: u64 = 0x544;

impl DscPlan {
    /// `intel_dsc_get_num_vdsc_instances` (no joiner).
    pub fn vdsc_instances(&self) -> u32 {
        u32::from(self.num_streams)
    }

    /// `intel_dsc_enable`'s `DSS_CTL1` and `DSS_CTL2`.
    pub fn dss_ctl(&self) -> (u32, u32) {
        if self.num_streams > 1 {
            (JOINER_ENABLE, VDSC0_ENABLE | VDSC1_ENABLE)
        } else {
            (0, VDSC0_ENABLE)
        }
    }

    /// The `PPS 0..=10, 16, 17, 18` register values of
    /// `intel_dsc_pps_configure` (display 14), in write order.
    pub fn pps_values(&self) -> [(u64, u32); 14] {
        let c = &self.config;
        let inst = self.vdsc_instances();
        let mut pps0 = 1
            | (u32::from(c.dsc_version_minor) & 0xf) << 4
            | (u32::from(c.bits_per_component) & 0xf) << 8
            | (u32::from(c.line_buf_depth) & 0xf) << 12;
        if c.dsc_version_minor == 2 {
            pps0 |= 1 << 20;
            if c.native_420 {
                pps0 |= 1 << 22;
            }
            if c.native_422 {
                pps0 |= 1 << 23;
            }
        }
        if c.block_pred_enable {
            pps0 |= 1 << 16;
        }
        if c.convert_rgb {
            pps0 |= 1 << 17;
        }
        if c.simple_422 {
            pps0 |= 1 << 18;
        }
        if c.vbr_enable {
            pps0 |= 1 << 19;
        }
        let width = u32::from(c.pic_width) / inst;
        [
            (0, pps0),
            (1, u32::from(c.bits_per_pixel) & 0x3ff),
            (2, u32::from(c.pic_height) | width << 16),
            (
                3,
                u32::from(c.slice_height) | u32::from(c.slice_width) << 16,
            ),
            (
                4,
                (u32::from(c.initial_xmit_delay) & 0x3ff) | u32::from(c.initial_dec_delay) << 16,
            ),
            (
                5,
                u32::from(c.scale_increment_interval)
                    | (u32::from(c.scale_decrement_interval) & 0xfff) << 16,
            ),
            (
                6,
                (u32::from(c.initial_scale_value) & 0x3f)
                    | (u32::from(c.first_line_bpg_offset) & 0x1f) << 8
                    | (u32::from(c.flatness_min_qp) & 0x1f) << 16
                    | (u32::from(c.flatness_max_qp) & 0x1f) << 24,
            ),
            (
                7,
                u32::from(c.slice_bpg_offset) | u32::from(c.nfl_bpg_offset) << 16,
            ),
            (
                8,
                u32::from(c.final_offset) | u32::from(c.initial_offset) << 16,
            ),
            (
                9,
                u32::from(c.rc_model_size) | u32::from(drm_dsc::RC_EDGE_FACTOR_CONST) << 16,
            ),
            (
                10,
                (u32::from(c.rc_quant_incr_limit0) & 0x1f)
                    | (u32::from(c.rc_quant_incr_limit1) & 0x1f) << 8
                    | u32::from(drm_dsc::RC_TGT_OFFSET_HI_CONST) << 16
                    | u32::from(drm_dsc::RC_TGT_OFFSET_LO_CONST) << 20,
            ),
            (
                16,
                u32::from(c.slice_chunk_size)
                    | ((width / u32::from(c.slice_width)) & 7) << 16
                    | ((u32::from(c.pic_height) / u32::from(c.slice_height)) & 0xfff) << 20,
            ),
            (17, (u32::from(c.second_line_bpg_offset) & 0x1f) << 27),
            (
                18,
                u32::from(c.second_line_offset_adj) | u32::from(c.nsl_bpg_offset) << 16,
            ),
        ]
    }

    /// The four `RC_BUF_THRESH` dwords.
    pub fn rc_buf_thresh_dwords(&self) -> [u32; 4] {
        let mut dw = [0u32; 4];
        for (i, &th) in self.config.rc_buf_thresh.iter().enumerate() {
            dw[i / 4] |= u32::from(th as u8) << (8 * (i % 4));
        }
        dw
    }

    /// The eight `RC_RANGE_PARAMETERS` dwords.
    pub fn rc_range_dwords(&self) -> [u32; 8] {
        let mut dw = [0u32; 8];
        for (i, &(min, max, ofs)) in self.config.rc_range_params.iter().enumerate() {
            let v = u32::from(ofs) << 10 | u32::from(max) << 5 | u32::from(min);
            dw[i / 2] |= v << (16 * (i % 2));
        }
        dw
    }

    /// `intel_dsc_enable` for `pipe`, in Linux's write order: each PPS to
    /// DSC0 then DSC1, the thresholds and range parameters of DSC0 then
    /// DSC1, then `DSS_CTL1` and `DSS_CTL2`.
    pub fn engine_writes(&self, pipe: Pipe) -> alloc::vec::Vec<(u64, u32)> {
        let engines = u64::from(self.num_streams.min(2));
        let mut w = alloc::vec::Vec::with_capacity(64);
        for (pps, v) in self.pps_values() {
            for e in 0..engines {
                w.push((pps_reg(pipe, e, pps), v));
            }
        }
        let th = self.rc_buf_thresh_dwords();
        for e in 0..engines {
            for (i, &v) in th.iter().enumerate() {
                w.push((rc_buf_thresh_reg(pipe, e, i as u64), v));
            }
        }
        let rr = self.rc_range_dwords();
        for e in 0..engines {
            for (i, &v) in rr.iter().enumerate() {
                w.push((rc_range_reg(pipe, e, i as u64), v));
            }
        }
        let (c1, c2) = self.dss_ctl();
        w.push((dss_ctl1(pipe), c1));
        w.push((dss_ctl2(pipe), c2));
        w
    }

    /// `intel_dsc_dp_pps_write`'s SDP: the header and the
    /// `drm_dsc_pps_payload_pack` payload as `hsw_write_infoframe` writes
    /// them (little-endian dwords).
    pub fn pps_sdp(&self) -> [u32; PPS_SDP_DWORDS] {
        let mut bytes = [0u8; PPS_SDP_DWORDS * 4];
        bytes[..4].copy_from_slice(&drm_dsc::dp_pps_header());
        bytes[4..].copy_from_slice(&drm_dsc::pack_pps(&self.config));
        let mut dw = [0u32; PPS_SDP_DWORDS];
        for (i, d) in dw.iter_mut().enumerate() {
            *d = u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]);
        }
        dw
    }

    /// `intel_link_compute_m_n` with the compressed bpp and the FEC
    /// overhead, as `intel_set_m_n` writes them: `DATA_M1` (with
    /// `TU_SIZE(64)`), `DATA_N1`, `LINK_M1`, `LINK_N1`.
    pub fn m_n(&self, mode: &Mode) -> [u32; 4] {
        link_m_n(
            u32::from(self.compressed_bpp_x16),
            u32::from(self.lanes),
            mode.pixel_clock_khz,
            self.link_rate,
            self.fec,
        )
    }

    /// `intel_vdsc_min_cdclk` (no joiner).
    pub fn min_cdclk_khz(&self, mode: &Mode) -> u32 {
        vdsc_min_cdclk(
            mode.pixel_clock_khz,
            u32::from(mode.h_total),
            u32::from(self.slice_count),
            self.vdsc_instances(),
        )
    }

    /// The resource-transaction term of this plan.
    pub fn term(&self, mode: &Mode) -> DscTerm {
        DscTerm {
            min_cdclk_khz: self.min_cdclk_khz(mode),
        }
    }
}

/// `intel_link_compute_m_n` + `intel_set_m_n`'s register values.
pub fn link_m_n(
    bpp_x16: u32,
    lanes: u32,
    pixel_clock: u32,
    link_clock: u32,
    fec: bool,
) -> [u32; 4] {
    let overhead = if fec { FEC_OVERHEAD_FACTOR } else { 1_000_000 };
    let data_m = effective_data_rate(pixel_clock, bpp_x16, overhead);
    let data_n = max_link_data_rate(link_clock, lanes);
    let (dm, dn) = compute_m_n(data_m, data_n, 0x800_0000);
    // intel_dp_link_symbol_clock: 8b/10b symbols are 10 bits.
    let (lm, ln) = compute_m_n(u64::from(pixel_clock), u64::from(link_clock), 0x8_0000);
    // TU_SIZE(64): (64 - 1) << 25.
    [(63 << 25) | dm, dn, lm, ln]
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

/// `intel_vdsc_min_cdclk` without a joiner: the pixel rate with 14 bubble
/// pixels per slice, divided among the VDSC engines.
pub fn vdsc_min_cdclk(pixel_rate: u32, htotal: u32, slices: u32, instances: u32) -> u32 {
    if htotal == 0 || instances == 0 {
        return pixel_rate;
    }
    let rate =
        (u64::from(pixel_rate) * u64::from(htotal + 14 * slices)).div_ceil(u64::from(htotal));
    rate.div_ceil(u64::from(instances)).min(u64::from(u32::MAX)) as u32
}

/// `intel_vdsc_prefill_lines` for a compressing pipe: 1.5 lines (.16).
pub const PREFILL_LINES: u64 = 0x18000;

/// What a compressing pipe adds to its resource transaction:
/// `intel_vdsc_min_cdclk` and `intel_vdsc_prefill_lines`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscTerm {
    /// `intel_vdsc_min_cdclk`.
    pub min_cdclk_khz: u32,
}

// ── Programming ──────────────────────────────────────────────────

/// Access to the display was lost (an all-ones read or a revoked window).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessLost;

fn write<M: MmioWindow + ?Sized>(io: &M, r: u64, v: u32) -> Result<(), AccessLost> {
    io.write32(r, v);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(AccessLost)
    }
}

fn read<M: MmioWindow + ?Sized>(io: &M, r: u64) -> Result<u32, AccessLost> {
    let v = io.read32(r);
    if v == u32::MAX || !io.display_access_ok() {
        Err(AccessLost)
    } else {
        Ok(v)
    }
}

/// `intel_dsc_enable` on `pipe`; every value reads back.
pub fn enable_engines<M: MmioWindow + ?Sized>(
    io: &M,
    pipe: Pipe,
    plan: &DscPlan,
) -> Result<(), AccessLost> {
    let writes = plan.engine_writes(pipe);
    for &(r, v) in &writes {
        write(io, r, v)?;
    }
    for &(r, v) in &writes {
        if read(io, r)? != v {
            return Err(AccessLost);
        }
    }
    Ok(())
}

/// `intel_dsc_disable`: both `DSS_CTL` registers cleared when either is
/// set (the old state compressed or joined). Returns whether it wrote.
pub fn disable_engines<M: MmioWindow + ?Sized>(io: &M, pipe: Pipe) -> Result<bool, AccessLost> {
    if read(io, dss_ctl1(pipe))? == 0 && read(io, dss_ctl2(pipe))? == 0 {
        return Ok(false);
    }
    write(io, dss_ctl1(pipe), 0)?;
    write(io, dss_ctl2(pipe), 0)?;
    Ok(true)
}

/// Whether `pipe`'s VDSC is compressing (`intel_dsc_get_config`'s
/// `VDSC0_ENABLE`).
pub fn engines_enabled<M: MmioWindow + ?Sized>(io: &M, pipe: Pipe) -> Result<bool, AccessLost> {
    Ok(read(io, dss_ctl2(pipe))? & VDSC0_ENABLE != 0)
}

/// `intel_dsc_get_config` reduced to the resource term: the engines, the
/// slices (`PPS16` slices per line × engines) and `intel_vdsc_min_cdclk`
/// for `mode`. `None` when `pipe` does not compress.
pub fn read_term<M: MmioWindow + ?Sized>(
    io: &M,
    pipe: Pipe,
    mode: &Mode,
) -> Result<Option<DscTerm>, AccessLost> {
    let ctl2 = read(io, dss_ctl2(pipe))?;
    if ctl2 & VDSC0_ENABLE == 0 {
        return Ok(None);
    }
    let ctl1 = read(io, dss_ctl1(pipe))?;
    let streams = if ctl1 & JOINER_ENABLE != 0 && ctl2 & VDSC1_ENABLE != 0 {
        2
    } else {
        1
    };
    let per_line = (read(io, pps_reg(pipe, 0, 16))? >> 16) & 7;
    Ok(Some(DscTerm {
        min_cdclk_khz: vdsc_min_cdclk(
            mode.pixel_clock_khz,
            u32::from(mode.h_total),
            per_line * streams,
            streams,
        ),
    }))
}

/// `hsw_write_infoframe(DP_SDP_PPS)` on `trans`: the PPS enable cleared,
/// all 33 data dwords, then the enable set.
pub fn write_pps_sdp<M: MmioWindow + ?Sized>(
    io: &M,
    trans: Transcoder,
    plan: &DscPlan,
) -> Result<(), AccessLost> {
    let ctl_reg = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let ctl = read(io, ctl_reg)? & !VDIP_ENABLE_PPS;
    write(io, ctl_reg, ctl)?;
    for (i, &d) in plan.pps_sdp().iter().enumerate() {
        write(
            io,
            trans.base() + VIDEO_DIP_PPS_DATA_OFFSET + 4 * i as u64,
            d,
        )?;
    }
    write(io, ctl_reg, ctl | VDIP_ENABLE_PPS)?;
    if read(io, ctl_reg)? & VDIP_ENABLE_PPS == 0 {
        return Err(AccessLost);
    }
    Ok(())
}

/// `intel_dp_set_infoframes(false)`'s PPS term: `VDIP_ENABLE_PPS` cleared.
pub fn disable_pps_sdp<M: MmioWindow + ?Sized>(
    io: &M,
    trans: Transcoder,
) -> Result<(), AccessLost> {
    let ctl_reg = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let ctl = read(io, ctl_reg)?;
    if ctl & VDIP_ENABLE_PPS != 0 {
        write(io, ctl_reg, ctl & !VDIP_ENABLE_PPS)?;
    }
    Ok(())
}

/// `intel_set_m_n` for `trans` (`LINK_N1` last: it arms the update).
pub fn write_m_n<M: MmioWindow + ?Sized>(
    io: &M,
    trans: Transcoder,
    m_n: &[u32; 4],
) -> Result<(), AccessLost> {
    use crate::intel_gpu_pipes::{
        PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET,
    };
    let base = trans.base();
    write(io, base + PIPE_DATA_M1_OFFSET, m_n[0])?;
    write(io, base + PIPE_DATA_N1_OFFSET, m_n[1])?;
    write(io, base + PIPE_LINK_M1_OFFSET, m_n[2])?;
    write(io, base + PIPE_LINK_N1_OFFSET, m_n[3])
}

/// `intel_ddi_enable_fec` (display < 30: no status wait here).
pub fn enable_fec<M: MmioWindow + ?Sized>(io: &M, trans: Transcoder) -> Result<(), AccessLost> {
    let r = trans.base() + DP_TP_CTL_OFFSET;
    let v = read(io, r)?;
    write(io, r, v | DP_TP_CTL_FEC_ENABLE)
}

/// `intel_ddi_disable_fec` (with its posting read).
pub fn disable_fec<M: MmioWindow + ?Sized>(io: &M, trans: Transcoder) -> Result<(), AccessLost> {
    let r = trans.base() + DP_TP_CTL_OFFSET;
    let v = read(io, r)?;
    write(io, r, v & !DP_TP_CTL_FEC_ENABLE)?;
    read(io, r).map(|_| ())
}

/// The source half of `intel_ddi_wait_for_fec_status`:
/// `DP_TP_STATUS_FEC_ENABLE_LIVE` reaching `enabled` within 1 ms.
pub fn wait_fec_live<M: MmioWindow + ?Sized>(io: &M, trans: Transcoder, enabled: bool) -> bool {
    let r = trans.base() + DP_TP_STATUS_OFFSET;
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(r);
            lost = v == u32::MAX || !io.display_access_ok();
            lost || (v & DP_TP_STATUS_FEC_ENABLE_LIVE != 0) == enabled
        },
        narf_time::Deadline::after_ns(1_000_000),
    );
    done && !lost
}

// ── Sink side ────────────────────────────────────────────────────

/// `intel_dp_sink_set_dsc_decompression`: read-modify-write of
/// `DP_DECOMPRESSION_EN` in `DP_DSC_ENABLE`.
pub fn set_sink_decompression<A: AuxChannel>(aux: &mut A, enable: bool) -> Result<(), AuxError> {
    let mut v = [0u8; 1];
    aux.dpcd_read(DP_DSC_ENABLE, &mut v)?;
    let next = if enable {
        v[0] | DP_DECOMPRESSION_EN
    } else {
        v[0] & !DP_DECOMPRESSION_EN
    };
    aux.dpcd_write(DP_DSC_ENABLE, &[next])
}

/// `intel_dp_sink_set_fec_ready`: `DP_FEC_READY`, and on enable the
/// detected flags in `DP_FEC_STATUS` cleared.
pub fn set_sink_fec_ready<A: AuxChannel>(aux: &mut A, enable: bool) -> Result<(), AuxError> {
    aux.dpcd_write(
        DP_FEC_CONFIGURATION,
        &[if enable { DP_FEC_READY } else { 0 }],
    )?;
    if enable {
        aux.dpcd_write(
            DP_FEC_STATUS,
            &[DP_FEC_DECODE_EN_DETECTED | DP_FEC_DECODE_DIS_DETECTED],
        )?;
    }
    Ok(())
}

/// `wait_for_fec_detected(enabled)`: `DP_FEC_DECODE_EN_DETECTED` polled
/// every 10 ms for 200 ms.
pub fn wait_fec_detected<A: AuxChannel>(aux: &mut A, delay_us: impl Fn(u32)) -> bool {
    for _ in 0..=20 {
        let mut v = [0u8; 1];
        match aux.dpcd_read(DP_FEC_STATUS, &mut v) {
            Ok(()) if v[0] & DP_FEC_DECODE_EN_DETECTED != 0 => return true,
            Ok(()) => {}
            Err(_) => return false,
        }
        delay_us(10_000);
    }
    false
}

/// A DP sink's DSC inputs (`intel_dp_get_dsc_sink_cap`): DPCD 1.4+ reads
/// the DSC capabilities and `DP_FEC_CAPABILITY`; older sinks have none.
pub fn read_dp_sink<A: AuxChannel>(
    aux: &mut A,
    receiver: &[u8; 16],
) -> Result<DpDscSink, AuxError> {
    let mut sink = DpDscSink {
        dsc: DscSink {
            dpcd: DscDpcd::default(),
            is_edp: false,
            fec_capable: false,
        },
        branch: receiver[DP_DOWNSTREAMPORT_PRESENT] & DP_DWN_STRM_PORT_PRESENT != 0,
    };
    if receiver[0] < DP_DPCD_REV_14 {
        return Ok(sink);
    }
    aux.dpcd_read(DP_DSC_SUPPORT, &mut sink.dsc.dpcd.0)?;
    let mut fec = [0u8; 1];
    aux.dpcd_read(DP_FEC_CAPABILITY, &mut fec)?;
    sink.dsc.fec_capable = fec[0] & DP_FEC_CAPABLE != 0;
    Ok(sink)
}

/// A DP (not eDP) sink's DSC inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpDscSink {
    /// The decision inputs.
    pub dsc: DscSink,
    /// `drm_dp_is_branch`.
    pub branch: bool,
}

/// `intel_dp_compute_link_config` for an external DP sink with NARF's
/// 8 bpc pipe: `None` when 24 bpp fits uncompressed (the route's own
/// negotiation then runs), a plan when DSC (with FEC) carries it.
pub fn decide_dp(
    sink: &DpDscSink,
    limits: &LinkLimits,
    mode: &Mode,
) -> Result<Option<DscPlan>, DscRefusal> {
    match uncompressed_link(limits, mode) {
        Some((PIPE_BPP, _, _)) => return Ok(None),
        Some(_) => return Err(DscRefusal::SixBpcUnqualified),
        None => {}
    }
    if !sink.dsc.dpcd.supports_dsc() {
        return Err(DscRefusal::SinkUnsupported);
    }
    if sink.branch {
        return Err(DscRefusal::BranchDevice);
    }
    compute(&sink.dsc, limits, mode).map(Some)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_dsc_tests.rs"]
mod tests;
