//! Display 14+ external output colour (`narf.intel.hdmi14_ext=1`): deep
//! colour (10 and 12 bpc) on the HDMI and DP routes, and the YCbCr 4:4:4
//! pipe output Linux selects for a DP protocol converter.
//!
//! With the strict boot option ([`BOOT_OPTION`], default off) the
//! display-14+ routes follow Linux 7.4's pipe-bpp and output-format
//! choices instead of NARF's 8 bpc RGB ceiling:
//!
//! - The pipe's maximum is `compute_sink_pipe_bpp` with the connector's
//!   default `max_requested_bpc` of 12 (`intel_display_max_pipe_bpp` is
//!   36): `bpc_to_bpp` of the sink's `display_info.bpc`
//!   ([`sink_display_bpc`]), 8 bpc when it is undefined ([`max_pipe_bpp`]).
//! - HDMI: `intel_hdmi_compute_bpc` from that maximum down in steps of
//!   2 bpc, each depth admitted by `hdmi_bpc_possible` (the sink's HDMI
//!   VSDB DC_30/DC_36 flags, the HF-VSDB 4:2:0 flags for 4:2:0) and
//!   `hdmi_port_clock_valid` at `intel_hdmi_tmds_clock` (see
//!   [`crate::intel_gpu_xelpg_hdmi`]).
//! - DP: `intel_dp_compute_link_config_wide` from the maximum down in steps
//!   of 6 bpp ([`crate::intel_gpu_xelpg_dsc::uncompressed_link_upto`]).
//!
//! The pipe then carries the depth in `PIPE_MISC` (`BPC_10`,
//! `BPC_12_ADLP`), `TRANS_DDI_FUNC_CTL` (`TRANS_DDI_BPC_10` / `_12`) and, on
//! DP, `TRANS_MSA_MISC` (`intel_ddi_set_dp_msa`); an HDMI sink gets the
//! General Control Packet (`intel_hdmi_compute_gcp_infoframe`) with the
//! colour indication and default phase. Without the option nothing here is
//! consulted and the routes keep their 8 bpc (or 6 bpc DP) pipes.
//!
//! ## YCbCr 4:4:4
//!
//! Linux 7.4 never drives YCbCr 4:4:4 to a native HDMI or DP sink:
//! `intel_hdmi_output_format` is the sink format (RGB or 4:2:0), and
//! `intel_dp_output_format` yields 4:4:4 only for a DP branch whose HDMI DFP
//! converts 4:4:4 to 4:2:0 but not RGB to YCbCr, feeding a 4:2:0-only mode
//! (or under the `i915_dsc_output_format` debugfs force, not modelled).
//! That route is [`dp_output`]: the pipe runs the BT.709 limited-range
//! output CSC with `PIPE_MISC_OUTPUT_COLORSPACE_YUV`, the MSA carries
//! `DP_MSA_MISC_COLOR_YCBCR_444_BT709` ([`msa_misc`]), and the PCON is
//! configured for the conversion ([`configure_protocol_converter`]). A
//! 4:2:0 output on the DP link itself is refused
//! ([`ColorRefusal::Ycbcr420Output`]).

use crate::intel_gpu_hdmi::{parse_hdmi_vsdb, HdmiVsdb};

/// The strict boot option.
pub const BOOT_OPTION: &str = "narf.intel.hdmi14_ext";

/// `narf.intel.hdmi14_ext=1` is on the command line.
pub fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), BOOT_OPTION)
}

/// `DRM_EDID_HDMI_DC_30`, `_DC_36` and `_DC_48` in HDMI VSDB byte 6.
const HDMI_DC_30: u8 = 1 << 4;
const HDMI_DC_36: u8 = 1 << 5;
const HDMI_DC_48: u8 = 1 << 6;
/// `HDMI_IEEE_OUI` as stored in a vendor block (LSB first).
const HDMI_VSDB_OUI: [u8; 3] = [0x03, 0x0C, 0x00];

/// `drm_parse_hdmi_deep_color_info`'s `display_info.bpc`: 8 for a sink with
/// an HDMI VSDB, raised to 10, 12 or 16 by its DC_30, DC_36 and DC_48
/// flags (a payload shorter than 6 bytes carries none); 0 without a VSDB.
/// The CTA walk is [`crate::intel_gpu_hdmi::parse_hdmi_vsdb`]'s (the first
/// VSDB of the first CTA extension that has one).
pub fn hdmi_vsdb_bpc(edid: &[u8]) -> u8 {
    for block in edid.chunks_exact(128).skip(1) {
        if block[0] != 0x02 {
            continue;
        }
        let limit = match block[2] {
            0 => 127usize,
            n => (n as usize).min(127),
        };
        let mut pos = 4usize;
        while pos < limit {
            let header = block[pos];
            let (tag, len) = (header >> 5, (header & 0x1F) as usize);
            if pos + 1 + len > 128 {
                break;
            }
            let payload = &block[pos + 1..pos + 1 + len];
            if tag == 3 && len >= 3 && payload[..3] == HDMI_VSDB_OUI {
                let Some(&flags) = payload.get(5) else {
                    return 8;
                };
                let mut bpc = 8;
                if flags & HDMI_DC_30 != 0 {
                    bpc = 10;
                }
                if flags & HDMI_DC_36 != 0 {
                    bpc = 12;
                }
                if flags & HDMI_DC_48 != 0 {
                    bpc = 16;
                }
                return bpc;
            }
            pos += 1 + len;
        }
    }
    0
}

/// The sink's `display_info.bpc` (`update_display_info`): the HDMI VSDB's
/// deep colour for a digital EDID 1.3+ sink, the DFP 1.x default, EDID
/// 1.4's color bit depth field and the bpc quirks
/// ([`crate::intel_gpu_xelpg_dsc::edid_display_bpc_cta`]).
pub fn sink_display_bpc(edid: &[u8]) -> u8 {
    crate::intel_gpu_xelpg_dsc::edid_display_bpc_cta(edid, hdmi_vsdb_bpc(edid))
}

/// `bpc_to_bpp`: 6–7 bpc is 18 bpp, 8–9 is 24, 10–11 is 30, 12–16 is 36;
/// `None` elsewhere (Linux `MISSING_CASE`).
pub const fn bpc_to_bpp(bpc: u8) -> Option<u32> {
    match bpc {
        6..=7 => Some(18),
        8..=9 => Some(24),
        10..=11 => Some(30),
        12..=16 => Some(36),
        _ => None,
    }
}

/// `crtc_state->pipe_bpp` after `compute_baseline_pipe_bpp` for a sink
/// whose `display_info.bpc` is `display_bpc`: the connector state's
/// `max_bpc` is that bpc (8 when undefined) capped at the default
/// `max_requested_bpc` of 12, and the platform maximum is 36.
pub const fn max_pipe_bpp(display_bpc: u8) -> u32 {
    let bpc = match display_bpc {
        0 => 8,
        bpc if bpc > 12 => 12,
        bpc => bpc,
    };
    match bpc_to_bpp(bpc) {
        Some(bpp) => bpp,
        None => 24,
    }
}

/// `intel_hdmi_sink_bpc_possible` for an HDMI sink at `bpc`: DC_36 for 12,
/// DC_30 for 10 (the HDMI VSDB's for RGB, the HF-VSDB 4:2:0 flags for
/// 4:2:0), 8 always; a DVI sink (no VSDB) is 8 bpc only.
pub fn sink_bpc_possible(
    bpc: u8,
    vsdb: Option<HdmiVsdb>,
    y420: &crate::intel_gpu_hdmi::Ycbcr420Caps,
    format: crate::intel_gpu_hdmi::SinkFormat,
) -> bool {
    use crate::intel_gpu_hdmi::SinkFormat;
    let Some(vsdb) = vsdb else {
        return bpc == 8;
    };
    match (bpc, format) {
        (12, SinkFormat::Ycbcr420) => y420.dc_36,
        (12, SinkFormat::Rgb) => vsdb.dc_36,
        (10, SinkFormat::Ycbcr420) => y420.dc_30,
        (10, SinkFormat::Rgb) => vsdb.dc_30,
        (8, _) => true,
        _ => false,
    }
}

/// The sink's `display_info.max_tmds_clock` in kHz: the HF-VSDB's rate
/// when it raised it above 340 MHz (`drm_parse_hdmi_forum_scds`), else the
/// HDMI VSDB's (`drm_parse_hdmi_vsdb_video`); 0 when neither sets one.
pub fn display_max_tmds_clock(edid: &[u8]) -> u32 {
    match crate::intel_gpu_xelpg_hdmi::parse_sink_scdc(edid).max_tmds_clock_khz {
        0 => parse_hdmi_vsdb(edid).map_or(0, |v| v.max_tmds_khz),
        forum => forum,
    }
}

/// `hdmi_port_clock_limit` with downstream limits on display 14+: the
/// 600 MHz source maximum (no VBT cap), lowered to the sink's
/// `display_info.max_tmds_clock` (the HF-VSDB's above 340 MHz, else the
/// HDMI VSDB's), or to 165 MHz for a DVI sink without one.
pub fn hdmi_port_clock_limit(edid: &[u8]) -> u32 {
    let source = crate::intel_gpu_xelpg_hdmi::SOURCE_MAX_TMDS_KHZ;
    let vsdb = parse_hdmi_vsdb(edid);
    match (display_max_tmds_clock(edid), vsdb) {
        (0, None) => source.min(crate::intel_gpu_hdmi::DVI_MAX_TMDS_KHZ),
        (0, Some(_)) => source,
        (sink, _) => source.min(sink),
    }
}

/// `hdmi_port_clock_valid` with downstream limits on display 14+ for a
/// TMDS clock: at least 25 MHz, at most [`hdmi_port_clock_limit`], and
/// outside the Type-C PHY PLL's (500, 532.8) MHz hole on a Type-C port
/// (`intel_encoder_is_tc`; DDI B's C10/C20 is no combo PHY on display 14+).
pub fn hdmi_port_clock_valid(tmds_khz: u32, limit_khz: u32, type_c: bool) -> bool {
    tmds_khz >= 25_000
        && tmds_khz <= limit_khz
        && !(type_c && tmds_khz > 500_000 && tmds_khz < 532_800)
}

// ── DP ────────────────────────────────────────────────────────────────

/// `DP_DOWNSTREAMPORT_PRESENT` in the receiver capability field and its
/// `DP_DWN_STRM_PORT_PRESENT` bit.
pub const DP_DOWNSTREAMPORT_PRESENT: usize = 0x005;
const DP_DWN_STRM_PORT_PRESENT: u8 = 1 << 0;

/// `drm_dp_is_branch` over the receiver capability field.
pub fn dp_is_branch(dpcd: &[u8]) -> bool {
    dpcd.get(DP_DOWNSTREAMPORT_PRESENT)
        .is_some_and(|&b| b & DP_DWN_STRM_PORT_PRESENT != 0)
}

/// `DP_DPCD_REV` and `DP_DETAILED_CAP_INFO_AVAILABLE` (in
/// `DP_DOWNSTREAMPORT_PRESENT`).
const DP_DPCD_REV: usize = 0x000;
const DP_DETAILED_CAP_INFO_AVAILABLE: u8 = 1 << 4;
/// `DP_DOWNSTREAM_PORT_0`: downstream port 0's four capability bytes.
pub const DP_DOWNSTREAM_PORT_0: u32 = 0x080;
/// `DP_DS_PORT_TYPE_MASK`, `DP_DS_PORT_TYPE_DP` and `_HDMI`.
const DP_DS_PORT_TYPE_MASK: u8 = 7;
const DP_DS_PORT_TYPE_DP: u8 = 0;
const DP_DS_PORT_TYPE_HDMI: u8 = 3;
/// Port-cap byte 3: `DP_DS_HDMI_YCBCR420_PASS_THROUGH`,
/// `DP_DS_HDMI_YCBCR444_TO_420_CONV` and `DP_DS_HDMI_BT709_RGB_YCBCR_CONV`.
const DP_DS_HDMI_YCBCR420_PASS_THROUGH: u8 = 1 << 2;
const DP_DS_HDMI_YCBCR444_TO_420_CONV: u8 = 1 << 4;
const DP_DS_HDMI_BT709_RGB_YCBCR_CONV: u8 = 1 << 6;
/// `DP_PROTOCOL_CONVERTER_CONTROL_0` / `_1` / `_2` (DP 1.3) and their bits.
pub const DP_PROTOCOL_CONVERTER_CONTROL_0: u32 = 0x3050;
pub const DP_PROTOCOL_CONVERTER_CONTROL_1: u32 = 0x3051;
pub const DP_PROTOCOL_CONVERTER_CONTROL_2: u32 = 0x3052;
pub const DP_HDMI_DVI_OUTPUT_CONFIG: u8 = 1 << 0;
pub const DP_CONVERSION_TO_YCBCR420_ENABLE: u8 = 1 << 0;
const DP_CONVERSION_RGB_YCBCR_MASK: u8 = 7 << 4;
pub const DP_CONVERSION_BT709_RGB_YCBCR_ENABLE: u8 = 1 << 5;

/// `PIPE_MISC_OUTPUT_COLORSPACE_YUV` (`bdw_set_pipe_misc` for a YCbCr 4:2:0
/// or 4:4:4 output).
pub const PIPE_MISC_OUTPUT_COLORSPACE_YUV: u32 = 1 << 11;
/// `DP_MSA_MISC_COLOR_YCBCR_444_BT709`: `_DP_MSA_MISC_COLOR(0, 2, 1, 1)`.
pub const DP_MSA_MISC_COLOR_YCBCR_444_BT709: u32 = (1 << 4) | (1 << 3) | (2 << 1);

/// The DFP conversion facts `intel_dp_update_420` keeps (`intel_dp->dfp`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DfpCaps {
    /// `drm_dp_downstream_420_passthrough`.
    pub ycbcr420_passthrough: bool,
    /// `drm_dp_downstream_444_to_420_conversion` (no on-board LSPCON here).
    pub ycbcr_444_to_420: bool,
    /// `drm_dp_downstream_rgb_to_ycbcr_conversion` for BT.709.
    pub rgb_to_ycbcr: bool,
}

/// Decode the DFP conversion facts of downstream port 0 (`port_cap`, DPCD
/// 0x80..=0x83) for the receiver capability field `dpcd`, as the
/// `drm_dp_downstream_*` helpers do: none below DPCD 1.3 or without a
/// branch; a DP DFP passes 4:2:0 through; an HDMI DFP's byte 3 carries
/// each fact when the detailed capabilities are available.
pub fn dfp_caps(dpcd: &[u8], port_cap: &[u8; 4]) -> DfpCaps {
    if !dp_is_branch(dpcd) || dpcd.get(DP_DPCD_REV).is_none_or(|&rev| rev < 0x13) {
        return DfpCaps::default();
    }
    let detailed = dpcd[DP_DOWNSTREAMPORT_PRESENT] & DP_DETAILED_CAP_INFO_AVAILABLE != 0;
    match port_cap[0] & DP_DS_PORT_TYPE_MASK {
        DP_DS_PORT_TYPE_DP => DfpCaps {
            ycbcr420_passthrough: true,
            ..DfpCaps::default()
        },
        DP_DS_PORT_TYPE_HDMI if detailed => DfpCaps {
            ycbcr420_passthrough: port_cap[3] & DP_DS_HDMI_YCBCR420_PASS_THROUGH != 0,
            ycbcr_444_to_420: port_cap[3] & DP_DS_HDMI_YCBCR444_TO_420_CONV != 0,
            rgb_to_ycbcr: port_cap[3] & DP_DS_HDMI_BT709_RGB_YCBCR_CONV != 0,
        },
        _ => DfpCaps::default(),
    }
}

/// Read downstream port 0's capability bytes and decode them; a sink that
/// is not a DPCD 1.3+ branch reads nothing.
pub fn read_dfp_caps<A: crate::dp_aux::AuxChannel + ?Sized>(
    aux: &mut A,
    dpcd: &[u8],
) -> Result<DfpCaps, crate::dp_aux::AuxError> {
    if !dp_is_branch(dpcd) || dpcd.get(DP_DPCD_REV).is_none_or(|&rev| rev < 0x13) {
        return Ok(DfpCaps::default());
    }
    let mut port_cap = [0u8; 4];
    aux.dpcd_read(DP_DOWNSTREAM_PORT_0, &mut port_cap)?;
    Ok(dfp_caps(dpcd, &port_cap))
}

/// `drm_dp_read_downstream_info` for downstream port 0: the four capability
/// bytes of a branch above DPCD 1.0 (zeros otherwise, and nothing read).
pub fn read_dfp_port_cap<A: crate::dp_aux::AuxChannel + ?Sized>(
    aux: &mut A,
    dpcd: &[u8],
) -> Result<[u8; 4], crate::dp_aux::AuxError> {
    let mut port_cap = [0u8; 4];
    if dp_is_branch(dpcd) && dpcd.get(DP_DPCD_REV).is_some_and(|&rev| rev > 0x10) {
        aux.dpcd_read(DP_DOWNSTREAM_PORT_0, &mut port_cap)?;
    }
    Ok(port_cap)
}

/// `DP_DWN_STRM_PORT_TYPE_MASK` and its `_DP` / `_TMDS` values in
/// `DP_DOWNSTREAMPORT_PRESENT` (a DPCD 1.0 branch).
const DP_DWN_STRM_PORT_TYPE_MASK: u8 = 0x06;
const DP_DWN_STRM_PORT_TYPE_DP: u8 = 0;
const DP_DWN_STRM_PORT_TYPE_TMDS: u8 = 2 << 1;
/// `DP_DS_PORT_TYPE_VGA`, `_DVI` and `_DP_DUALMODE`.
const DP_DS_PORT_TYPE_VGA: u8 = 1;
const DP_DS_PORT_TYPE_DVI: u8 = 2;
const DP_DS_PORT_TYPE_DP_DUALMODE: u8 = 5;
/// `DP_DS_MAX_BPC_MASK` in port-cap byte 2.
const DP_DS_MAX_BPC_MASK: u8 = 3;

/// The DFP limits `intel_dp_update_sink_caps` keeps (`intel_dp->dfp`),
/// each 0 when the branch defines none.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DfpLimits {
    /// `drm_dp_downstream_max_bpc`.
    pub max_bpc: u8,
    /// `drm_dp_downstream_max_dotclock` (kHz).
    pub max_dotclock: u32,
    /// `drm_dp_downstream_min_tmds_clock` (kHz): set for an HDMI/DVI DFP.
    pub min_tmds_clock: u32,
    /// `drm_dp_downstream_max_tmds_clock` (kHz).
    pub max_tmds_clock: u32,
}

/// `is_edid_digital_input_dp`: an EDID 1.4 digital DisplayPort input.
fn edid_digital_input_dp(edid: &[u8]) -> bool {
    edid.get(19).is_some_and(|&rev| rev >= 4)
        && edid
            .get(20)
            .is_some_and(|&input| input & 0x80 != 0 && input & 7 == 5)
}

/// The `drm_dp_downstream_*` limits of downstream port 0 (`port_cap`) for
/// the receiver capability field `dpcd` and the sink's `edid`: none
/// without a branch; a DPCD 1.0 branch reports only its port type; a DP
/// DFP (or a dual-mode one in front of a DP sink) has no limits; an
/// HDMI/DVI DFP takes 25 MHz as its minimum TMDS clock and, without the
/// detailed capabilities, 8 bpc and 300 MHz (HDMI) or 165 MHz (DVI).
pub fn dfp_limits(dpcd: &[u8], port_cap: &[u8; 4], edid: &[u8]) -> DfpLimits {
    if !dp_is_branch(dpcd) {
        return DfpLimits::default();
    }
    let present = dpcd[DP_DOWNSTREAMPORT_PRESENT];
    if dpcd.get(DP_DPCD_REV).is_none_or(|&rev| rev < 0x11) {
        return match present & DP_DWN_STRM_PORT_TYPE_MASK {
            DP_DWN_STRM_PORT_TYPE_DP => DfpLimits::default(),
            DP_DWN_STRM_PORT_TYPE_TMDS => DfpLimits {
                max_bpc: 8,
                max_dotclock: 0,
                min_tmds_clock: 25_000,
                max_tmds_clock: 165_000,
            },
            _ => DfpLimits {
                max_bpc: 8,
                ..DfpLimits::default()
            },
        };
    }
    let detailed = present & DP_DETAILED_CAP_INFO_AVAILABLE != 0;
    let max_bpc = || {
        if !detailed {
            return 8;
        }
        match port_cap[2] & DP_DS_MAX_BPC_MASK {
            1 => 10,
            2 => 12,
            3 => 16,
            _ => 8,
        }
    };
    let ty = port_cap[0] & DP_DS_PORT_TYPE_MASK;
    match ty {
        DP_DS_PORT_TYPE_DP => DfpLimits::default(),
        DP_DS_PORT_TYPE_DP_DUALMODE if edid_digital_input_dp(edid) => DfpLimits::default(),
        DP_DS_PORT_TYPE_DP_DUALMODE | DP_DS_PORT_TYPE_HDMI | DP_DS_PORT_TYPE_DVI => {
            let max_tmds_clock = match (detailed, ty) {
                (false, DP_DS_PORT_TYPE_DVI) => 165_000,
                (false, _) => 300_000,
                (true, _) => u32::from(port_cap[1]) * 2_500,
            };
            DfpLimits {
                max_bpc: max_bpc(),
                max_dotclock: 0,
                min_tmds_clock: 25_000,
                max_tmds_clock,
            }
        }
        DP_DS_PORT_TYPE_VGA => DfpLimits {
            max_bpc: max_bpc(),
            max_dotclock: if detailed {
                u32::from(port_cap[1]) * 8_000
            } else {
                0
            },
            ..DfpLimits::default()
        },
        _ => DfpLimits {
            max_bpc: 8,
            ..DfpLimits::default()
        },
    }
}

/// What `intel_dp_configure_protocol_converter` writes to a DPCD 1.3+
/// branch: HDMI mode for an HDMI sink (`intel_dp_has_hdmi_sink`), the
/// 4:4:4-to-4:2:0 conversion and the BT.709 RGB-to-YCbCr conversion the
/// output format needs.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PconConfig {
    /// `DP_HDMI_DVI_OUTPUT_CONFIG` in `DP_PROTOCOL_CONVERTER_CONTROL_0`.
    pub hdmi_sink: bool,
    /// `DP_CONVERSION_TO_YCBCR420_ENABLE` in `_CONTROL_1`.
    pub ycbcr444_to_420: bool,
    /// `DP_CONVERSION_BT709_RGB_YCBCR_ENABLE` in `_CONTROL_2`.
    pub rgb_to_ycbcr: bool,
}

/// `DP_DPRX_FEATURE_ENUMERATION_LIST` (DP 1.3) and the two bits Linux keeps
/// from it (`intel_dp_get_sst_split_sdp_status`,
/// `intel_dp_get_colorimetry_status`).
pub const DP_DPRX_FEATURE_ENUMERATION_LIST: u32 = 0x2210;
pub const DP_SST_SPLIT_SDP_CAP: u8 = 1 << 1;
pub const DP_VSC_SDP_EXT_FOR_COLORIMETRY_SUPPORTED: u8 = 1 << 3;

/// `intel_dp_read_dprx_feature_enum`: the byte, or 0 when the read fails
/// (`drm_dp_dpcd_read_byte` leaves it cleared).
pub fn read_dprx_feature_enum<A: crate::dp_aux::AuxChannel + ?Sized>(aux: &mut A) -> u8 {
    let mut dprx = [0u8; 1];
    match aux.dpcd_read(DP_DPRX_FEATURE_ENUMERATION_LIST, &mut dprx) {
        Ok(()) => dprx[0],
        Err(_) => 0,
    }
}

/// The display-14+ DP route's output format and protocol-converter setup.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DpOutput {
    /// `crtc_state->output_format` is YCbCr 4:4:4 (RGB otherwise).
    pub ycbcr444: bool,
    /// `crtc_state->output_format` is YCbCr 4:2:0: the link carries 4:2:0
    /// (a native sink, or a DFP that passes it through).
    pub ycbcr420: bool,
    /// The sink's `DP_DPRX_FEATURE_ENUMERATION_LIST` (read under the option,
    /// 0 otherwise).
    pub dprx: u8,
    /// The protocol-converter configuration; `None` for a sink that is not
    /// a DPCD 1.3+ branch or a probe without the option.
    pub pcon: Option<PconConfig>,
}

impl DpOutput {
    /// `intel_dp_needs_vsc_colorimetry` with the default colorspace: a
    /// YCbCr 4:2:0 output to a sink that advertises VSC SDP colorimetry
    /// (`intel_dp->colorimetry_support`).
    pub const fn vsc_colorimetry(&self) -> bool {
        self.ycbcr420 && self.dprx & DP_VSC_SDP_EXT_FOR_COLORIMETRY_SUPPORTED != 0
    }

    /// `intel_dp->sst_split_sdp_support`.
    pub const fn sst_split_sdp(&self) -> bool {
        self.dprx & DP_SST_SPLIT_SDP_CAP != 0
    }

    /// `crtc_state->sink_format`: YCbCr 4:2:0 when the output is 4:2:0 or
    /// the protocol converter converts to it.
    pub fn sink_format(&self) -> crate::intel_gpu_hdmi::SinkFormat {
        if self.ycbcr420 || self.pcon.is_some_and(|p| p.ycbcr444_to_420) {
            crate::intel_gpu_hdmi::SinkFormat::Ycbcr420
        } else {
            crate::intel_gpu_hdmi::SinkFormat::Rgb
        }
    }

    /// `intel_dp_min_bpp`: 18 for RGB, 24 for a YCbCr output.
    pub const fn min_bpp(&self) -> u32 {
        if self.ycbcr444 || self.ycbcr420 {
            24
        } else {
            crate::intel_gpu_xelpg_dsc::MIN_PIPE_BPP
        }
    }

    /// `intel_dp_output_format_link_bpp_x16` in whole bits: a YCbCr 4:2:0
    /// pixel carries half the pipe's bits.
    pub const fn link_bpp(&self, pipe_bpp: u32) -> u32 {
        if self.ycbcr420 {
            pipe_bpp / 2
        } else {
            pipe_bpp
        }
    }
}

/// Typed refusals of the display-14+ DP output format.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColorRefusal {
    /// A YCbCr 4:2:0 output that no uncompressed 8b/10b link carries:
    /// Linux goes on to the 128b/132b rates or native 4:2:0 DSC, which this
    /// route does not plan for a 4:2:0 output.
    Ycbcr420Link,
    /// A YCbCr (4:4:4 or 4:2:0) output needs 24 bpp (`intel_dp_min_bpp`)
    /// and the sink's depth or the link does not carry it.
    Ycbcr444Bpp,
    /// The branch's HDMI/DVI DFP admits no depth for the mode
    /// (`intel_dp_hdmi_compute_bpc` fails, `intel_dp_max_bpp` is 0).
    DfpBpc,
}

/// `intel_dp_output_format` for `sink_420` (the sink format is YCbCr
/// 4:2:0; RGB otherwise): RGB when the DFP converts RGB to it
/// (`dfp_can_convert_from_rgb`), YCbCr 4:4:4 when it converts only 4:4:4
/// (`dfp_can_convert_from_ycbcr444`), YCbCr 4:2:0 on the link otherwise;
/// with the protocol-converter configuration of
/// `intel_dp_configure_protocol_converter`.
fn output_for(dpcd: &[u8], dfp: DfpCaps, edid: &[u8], sink_420: bool) -> DpOutput {
    let branch = dp_is_branch(dpcd);
    let from_rgb = branch && dfp.rgb_to_ycbcr && dfp.ycbcr_444_to_420;
    let from_444 = branch && dfp.ycbcr_444_to_420;
    let (ycbcr444, ycbcr420) = match (sink_420, from_rgb, from_444) {
        (false, _, _) | (true, true, _) => (false, false),
        (true, false, true) => (true, false),
        (true, false, false) => (false, true),
    };
    let pcon =
        (branch && dpcd.get(DP_DPCD_REV).is_some_and(|&rev| rev >= 0x13)).then(|| PconConfig {
            hdmi_sink: crate::intel_gpu_hdmi::is_hdmi_sink(edid),
            ycbcr444_to_420: sink_420 && !ycbcr420,
            rgb_to_ycbcr: sink_420 && !ycbcr420 && !ycbcr444,
        });
    DpOutput {
        ycbcr444,
        ycbcr420,
        dprx: 0,
        pcon,
    }
}

/// `intel_dp_sink_format_valid` for YCbCr 4:2:0: refused for a non-HDMI
/// sink behind an HDMI/DVI DFP (`dfp.min_tmds_clock`), without
/// `intel_dp_can_ycbcr420` (display 14 outputs 4:2:0, so a native sink, a
/// passthrough DFP or one that converts), or for a mode the sink does not
/// take in 4:2:0 (`drm_mode_is_420`).
fn ycbcr420_valid(
    dpcd: &[u8],
    dfp: DfpCaps,
    dfp_min_tmds_khz: u32,
    edid: &[u8],
    mode: &crate::intel_gpu_modeset::Mode,
) -> bool {
    use crate::intel_gpu_hdmi::{is_hdmi_sink, parse_ycbcr420, vic_for_mode};
    let branch = dp_is_branch(dpcd);
    let can_420 = !branch || dfp.ycbcr420_passthrough || dfp.ycbcr_444_to_420;
    let y420 = parse_ycbcr420(edid);
    let vic = vic_for_mode(mode);
    (dfp_min_tmds_khz == 0 || is_hdmi_sink(edid)) && can_420 && (y420.only(vic) || y420.also(vic))
}

/// `intel_dp_compute_formats` and `intel_dp_output_format` on display 14+
/// (`source_can_output` admits RGB, 4:4:4 and 4:2:0): a 4:2:0-only mode
/// (`drm_mode_is_420_only`) takes the 4:2:0 sink format when
/// `intel_dp_sink_format_valid` allows it, else (Linux's second pass) RGB;
/// any other mode RGB first ([`dp_output_420_also`] is the fallback when
/// no RGB link configuration fits). A 4:2:0 sink is fed RGB when the DFP
/// converts RGB to YCbCr and 4:4:4 to 4:2:0, YCbCr 4:4:4 when it converts
/// only 4:4:4 to 4:2:0, and YCbCr 4:2:0 otherwise (a native sink or a
/// passthrough DFP; the VSC SDP carries its colorimetry,
/// [`DpOutput::vsc_colorimetry`]). The protocol-converter configuration is
/// `intel_dp_configure_protocol_converter`'s. `dfp_min_tmds_khz` is
/// [`DfpLimits::min_tmds_clock`].
pub fn dp_output(
    dpcd: &[u8],
    dfp: DfpCaps,
    dfp_min_tmds_khz: u32,
    edid: &[u8],
    mode: &crate::intel_gpu_modeset::Mode,
) -> DpOutput {
    use crate::intel_gpu_hdmi::{parse_ycbcr420, vic_for_mode};
    let sink_420 = parse_ycbcr420(edid).only(vic_for_mode(mode))
        && ycbcr420_valid(dpcd, dfp, dfp_min_tmds_khz, edid, mode);
    output_for(dpcd, dfp, edid, sink_420)
}

/// `intel_dp_compute_formats`' second try for a mode that is not
/// 4:2:0-only: when no RGB link configuration fits a 4:2:0-also mode
/// (`drm_mode_is_420_also`), the 4:2:0 sink format, if
/// `intel_dp_sink_format_valid` allows it. `None` otherwise.
pub fn dp_output_420_also(
    dpcd: &[u8],
    dfp: DfpCaps,
    dfp_min_tmds_khz: u32,
    edid: &[u8],
    mode: &crate::intel_gpu_modeset::Mode,
) -> Option<DpOutput> {
    use crate::intel_gpu_hdmi::{parse_ycbcr420, vic_for_mode};
    let y420 = parse_ycbcr420(edid);
    let vic = vic_for_mode(mode);
    (!y420.only(vic) && ycbcr420_valid(dpcd, dfp, dfp_min_tmds_khz, edid, mode))
        .then(|| output_for(dpcd, dfp, edid, true))
}

/// `intel_dp_compute_link_config_wide` for `output` on the 8b/10b rates of
/// `limits`: from `rounddown(max_bpp, 6)` down to `intel_dp_min_bpp` in
/// steps of 6, each at its link bpp ([`DpOutput::link_bpp`]: half for
/// 4:2:0), the lowest rate then the fewest lanes that carries the mode.
pub fn output_link(
    limits: &crate::intel_gpu_xelpg_dsc::LinkLimits,
    mode: &crate::intel_gpu_modeset::Mode,
    max_bpp: u32,
    output: &DpOutput,
) -> Option<crate::intel_gpu_xelpg_dsc::UncompressedLink> {
    use crate::intel_gpu_xelpg_dsc::{link_required, max_link_data_rate, UncompressedLink};
    let max_bpp = max_bpp.min(36);
    let mut bpp = max_bpp - max_bpp % 6;
    while bpp >= output.min_bpp() {
        for rate in limits.rates() {
            for lanes in limits.lanes() {
                let need = link_required(
                    lanes,
                    mode.pixel_clock_khz,
                    u32::from(mode.h_active),
                    output.link_bpp(bpp) * 16,
                    false,
                );
                if need <= max_link_data_rate(rate, lanes) {
                    return Some(UncompressedLink {
                        pipe_bpp: bpp,
                        link_rate: rate,
                        lanes: lanes as u8,
                    });
                }
            }
        }
        bpp -= 6;
    }
    None
}

/// `intel_dp_max_tmds_clock`: the DFP's maximum, lowered to the sink's
/// `display_info.max_tmds_clock` when both are set.
fn dp_max_tmds_clock(dfp: &DfpLimits, edid: &[u8]) -> u32 {
    match (dfp.max_tmds_clock, display_max_tmds_clock(edid)) {
        (0, _) => 0,
        (dfp, 0) => dfp,
        (dfp, sink) => dfp.min(sink),
    }
}

/// `intel_dp_tmds_clock_valid` with downstream limits: the HDMI TMDS clock
/// of `clock_khz` at `bpc` within the DFP's minimum and maximum.
fn dp_tmds_clock_valid(
    dfp: &DfpLimits,
    edid: &[u8],
    clock_khz: u32,
    bpc: u8,
    format: crate::intel_gpu_hdmi::SinkFormat,
) -> bool {
    let tmds = crate::intel_gpu_hdmi::tmds_clock_for(clock_khz, bpc, format);
    let max = dp_max_tmds_clock(dfp, edid);
    !(dfp.min_tmds_clock != 0 && tmds < dfp.min_tmds_clock || max != 0 && tmds > max)
}

/// `intel_dp_hdmi_compute_bpc` with downstream limits: from `bpc` (at
/// least 8) down in steps of 2, the first depth the HDMI sink takes
/// (`intel_hdmi_bpc_possible`: 8 always, 10 and 12 by the sink's deep
/// colour flags for its format) at a valid TMDS clock.
fn dp_hdmi_compute_bpc(
    dfp: &DfpLimits,
    edid: &[u8],
    clock_khz: u32,
    bpc: u8,
    format: crate::intel_gpu_hdmi::SinkFormat,
) -> Option<u8> {
    let vsdb = parse_hdmi_vsdb(edid);
    let y420 = crate::intel_gpu_hdmi::parse_ycbcr420(edid);
    let mut bpc = bpc.max(8);
    while bpc >= 8 {
        if sink_bpc_possible(bpc, vsdb, &y420, format)
            && dp_tmds_clock_valid(dfp, edid, clock_khz, bpc, format)
        {
            return Some(bpc);
        }
        bpc -= 2;
    }
    None
}

/// `intel_dp_max_bpp` and the clamp of `intel_dp_compute_config_limits`
/// for an external DP sink whose `display_info.bpc` is `display_bpc`: the
/// bpc of `crtc_state->max_pipe_bpp` (`compute_sink_pipe_bpp`: the EDID's,
/// 8 when undefined, at most 36 bpp), lowered to the DFP's maximum bpc and,
/// behind an HDMI/DVI DFP, to [`dp_hdmi_compute_bpc`]'s at the mode's
/// clock and `format`; then no deeper than `crtc_state->pipe_bpp`
/// ([`max_pipe_bpp`]). Refused when the DFP admits no depth
/// ([`ColorRefusal::DfpBpc`]) or a YCbCr output's 24 bpp minimum is above
/// it ([`ColorRefusal::Ycbcr444Bpp`]: invalid limits).
pub fn dp_max_bpp(
    display_bpc: u8,
    dfp: &DfpLimits,
    edid: &[u8],
    clock_khz: u32,
    format: crate::intel_gpu_hdmi::SinkFormat,
    min_bpp: u32,
) -> Result<u32, ColorRefusal> {
    let edid_bpc = if display_bpc == 0 { 8 } else { display_bpc };
    let mut bpc = (bpc_to_bpp(edid_bpc).unwrap_or(24).min(36) / 3) as u8;
    if dfp.max_bpc != 0 {
        bpc = bpc.min(dfp.max_bpc);
    }
    if dfp.min_tmds_clock != 0 {
        let hdmi = dp_hdmi_compute_bpc(dfp, edid, clock_khz, bpc, format);
        bpc = bpc.min(hdmi.ok_or(ColorRefusal::DfpBpc)?);
    }
    let bpp = u32::from(bpc) * 3;
    if bpp < min_bpp {
        return Err(ColorRefusal::Ycbcr444Bpp);
    }
    Ok(max_pipe_bpp(display_bpc).clamp(min_bpp, bpp))
}

/// The pipe bpp ceiling of a DP MST stream: Linux 7.4's
/// `intel_dp_compute_config_limits` limits MST to 8 bpc
/// (`min(crtc_state->max_pipe_bpp, 24)`, "Until then we limit to <= 8bpc
/// since that's what was hardcoded for all MST streams previously"), so
/// deep colour stops at an MST stream, compressed or not.
pub const MST_MAX_PIPE_BPP: u32 = 24;

/// `intel_dp_configure_protocol_converter`: `_CONTROL_0` (HDMI mode),
/// `_CONTROL_1` (4:2:0 conversion), then `drm_dp_pcon_convert_rgb_to_ycbcr`'s
/// read-modify-write of `_CONTROL_2`. Linux only logs a failed transfer,
/// and so does this: each step is best effort.
pub fn configure_protocol_converter<A: crate::dp_aux::AuxChannel + ?Sized>(
    aux: &mut A,
    pcon: &PconConfig,
) {
    let control_0 = if pcon.hdmi_sink {
        DP_HDMI_DVI_OUTPUT_CONFIG
    } else {
        0
    };
    let _ = aux.dpcd_write(DP_PROTOCOL_CONVERTER_CONTROL_0, &[control_0]);
    let control_1 = if pcon.ycbcr444_to_420 {
        DP_CONVERSION_TO_YCBCR420_ENABLE
    } else {
        0
    };
    let _ = aux.dpcd_write(DP_PROTOCOL_CONVERTER_CONTROL_1, &[control_1]);
    let mut control_2 = [0u8; 1];
    if aux
        .dpcd_read(DP_PROTOCOL_CONVERTER_CONTROL_2, &mut control_2)
        .is_ok()
    {
        let next = if pcon.rgb_to_ycbcr {
            control_2[0] | DP_CONVERSION_BT709_RGB_YCBCR_ENABLE
        } else {
            control_2[0] & !DP_CONVERSION_RGB_YCBCR_MASK
        };
        let _ = aux.dpcd_write(DP_PROTOCOL_CONVERTER_CONTROL_2, &[next]);
    }
}

/// `intel_ddi_set_dp_msa` for `pipe_bpp`, with `DP_MSA_MISC_COLOR_YCBCR_444_BT709`
/// for a YCbCr 4:4:4 output (never limited range, no VSC SDP).
pub const fn msa_misc(pipe_bpp: u32, ycbcr444: bool) -> u32 {
    crate::intel_gpu_xelpg_dsc::msa_misc(pipe_bpp)
        | if ycbcr444 {
            DP_MSA_MISC_COLOR_YCBCR_444_BT709
        } else {
            0
        }
}

/// `DP_MSA_MISC_COLOR_VSC_SDP`: the VSC SDP carries the pixel encoding and
/// colorimetry (MISC1 bit 6).
pub const DP_MSA_MISC_COLOR_VSC_SDP: u32 = 1 << 14;

/// `intel_ddi_set_dp_msa` for `output` at `pipe_bpp`: the depth, the
/// YCbCr 4:4:4 colorimetry ([`msa_misc`]) and, for a YCbCr 4:2:0 output to
/// a sink with VSC SDP colorimetry, `DP_MSA_MISC_COLOR_VSC_SDP`.
pub const fn msa_misc_output(pipe_bpp: u32, output: &DpOutput) -> u32 {
    msa_misc(pipe_bpp, output.ycbcr444)
        | if output.vsc_colorimetry() {
            DP_MSA_MISC_COLOR_VSC_SDP
        } else {
            0
        }
}

// ── VSC SDP (intel_dp_compute_vsc_sdp, hsw_write_infoframe) ──────────

/// `DP_SDP_VSC`.
const DP_SDP_VSC: u8 = 0x07;
/// `DP_PIXELFORMAT_YUV420`, `DP_COLORIMETRY_BT709_YCC`.
const DP_PIXELFORMAT_YUV420: u8 = 0x3;
const DP_COLORIMETRY_BT709_YCC: u8 = 0x1;
/// `VIDEO_DIP_ENABLE_VSC_HSW` and `VSC_DIP_HW_DATA_SW_HEA` in
/// `HSW_TVIDEO_DIP_CTL`.
pub const VIDEO_DIP_ENABLE_VSC_HSW: u32 = 1 << 20;
pub const VSC_DIP_HW_DATA_SW_HEA: u32 = 2 << 25;
/// `HSW_TVIDEO_DIP_CTL` and `HSW_TVIDEO_DIP_VSC_DATA` relative to the
/// transcoder base (`_HSW_VIDEO_DIP_CTL_A` 0x60200,
/// `_HSW_VIDEO_DIP_VSC_DATA_A` 0x60320).
pub const VIDEO_DIP_CTL_OFFSET: u64 = 0x200;
pub const VIDEO_DIP_VSC_DATA_OFFSET: u64 = 0x320;
/// `VIDEO_DIP_VSC_DATA_SIZE`: the packed `struct dp_sdp`.
pub const VIDEO_DIP_VSC_DATA_SIZE: usize = 36;

/// `intel_dp_compute_vsc_colorimetry` and `drm_dp_vsc_sdp_pack` for a
/// YCbCr 4:2:0 output at `pipe_bpp` with the default colorspace and no
/// panel replay: header `HB1` = `DP_SDP_VSC`, revision 0x5, 0x13 valid
/// bytes; `DB16` = YUV420 << 4 | BT709_YCC (the RGB-to-YCbCr conversion
/// is BT.709); `DB17` = the bpc code (6: 0, 8: 1, 10: 2, 12: 3, 16: 4)
/// with `DP_DYNAMIC_RANGE_CTA` (YCbCr is always limited range); `DB18` =
/// `DP_CONTENT_TYPE_NOT_DEFINED`.
pub fn vsc_sdp_ycbcr420(pipe_bpp: u32) -> [u8; VIDEO_DIP_VSC_DATA_SIZE] {
    let mut sdp = [0u8; VIDEO_DIP_VSC_DATA_SIZE];
    sdp[1] = DP_SDP_VSC;
    sdp[2] = 0x5;
    sdp[3] = 0x13;
    let db = 4;
    sdp[db + 16] = (DP_PIXELFORMAT_YUV420 << 4) | DP_COLORIMETRY_BT709_YCC;
    let bpc_code = match pipe_bpp / 3 {
        8 => 1,
        10 => 2,
        12 => 3,
        16 => 4,
        _ => 0,
    };
    sdp[db + 17] = bpc_code | 0x80;
    sdp
}

/// `hsw_write_infoframe` for `DP_SDP_VSC` on `trans`: the VSC enable off,
/// the packed SDP and zeros over the whole `VIDEO_DIP_VSC_DATA_SIZE` (for
/// the ECC), then the enable with `VSC_DIP_HW_DATA_SW_HEA` and a posting
/// read. (Wa_14013475917 skips the enable only for a PSR route.)
pub fn write_vsc_sdp<M: crate::intel_gpu_aux::MmioWindow + ?Sized>(
    io: &M,
    trans: crate::intel_gpu_pipes::Transcoder,
    sdp: &[u8; VIDEO_DIP_VSC_DATA_SIZE],
) {
    let ctl = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let val = io.read32(ctl) & !VIDEO_DIP_ENABLE_VSC_HSW;
    io.write32(ctl, val);
    for (i, dword) in sdp.chunks_exact(4).enumerate() {
        io.write32(
            trans.base() + VIDEO_DIP_VSC_DATA_OFFSET + 4 * i as u64,
            u32::from_le_bytes([dword[0], dword[1], dword[2], dword[3]]),
        );
    }
    io.write32(ctl, val | VIDEO_DIP_ENABLE_VSC_HSW | VSC_DIP_HW_DATA_SW_HEA);
    let _ = io.read32(ctl);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// `intel_dp_set_infoframes(false)`'s VSC part: `VIDEO_DIP_ENABLE_VSC_HSW`
/// cleared, with a posting read.
pub fn disable_vsc_sdp<M: crate::intel_gpu_aux::MmioWindow + ?Sized>(
    io: &M,
    trans: crate::intel_gpu_pipes::Transcoder,
) {
    let ctl = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let val = io.read32(ctl);
    io.write32(ctl, val & !VIDEO_DIP_ENABLE_VSC_HSW);
    let _ = io.read32(ctl);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_color_tests.rs"]
pub mod tests;
