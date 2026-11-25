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

/// `hdmi_port_clock_limit` with downstream limits on display 14+: the
/// 600 MHz source maximum (no VBT cap), lowered to the sink's
/// `display_info.max_tmds_clock` (the HF-VSDB's above 340 MHz, else the
/// HDMI VSDB's), or to 165 MHz for a DVI sink without one.
pub fn hdmi_port_clock_limit(edid: &[u8]) -> u32 {
    let source = crate::intel_gpu_xelpg_hdmi::SOURCE_MAX_TMDS_KHZ;
    let forum = crate::intel_gpu_xelpg_hdmi::parse_sink_scdc(edid).max_tmds_clock_khz;
    let vsdb = parse_hdmi_vsdb(edid);
    let sink = if forum != 0 {
        forum
    } else {
        vsdb.map_or(0, |v| v.max_tmds_khz)
    };
    match (sink, vsdb) {
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

/// The display-14+ DP route's output format and protocol-converter setup.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DpOutput {
    /// `crtc_state->output_format` is YCbCr 4:4:4 (RGB otherwise).
    pub ycbcr444: bool,
    /// The protocol-converter configuration; `None` for a sink that is not
    /// a DPCD 1.3+ branch or a probe without the option.
    pub pcon: Option<PconConfig>,
}

/// Typed refusals of the display-14+ DP output format.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColorRefusal {
    /// The mode is 4:2:0-only and Linux would drive YCbCr 4:2:0 on the DP
    /// link (a native sink, or a DFP that passes it through): DP 4:2:0
    /// needs the VSC SDP colorimetry, which this route does not send.
    Ycbcr420Output,
    /// A YCbCr 4:4:4 output needs 24 bpp (`intel_dp_min_bpp`) and no link
    /// carries it.
    Ycbcr444Bpp,
}

/// `intel_dp_compute_formats` and `intel_dp_output_format` on display 14+
/// (`source_can_output` admits RGB, 4:4:4 and 4:2:0): a 4:2:0-only mode
/// (`drm_mode_is_420_only`) takes the 4:2:0 sink format when
/// `intel_dp_can_ycbcr420` allows it, else (Linux's second pass) RGB; any
/// other mode RGB. A 4:2:0 sink is fed RGB when the DFP converts RGB to
/// YCbCr and 4:4:4 to 4:2:0 (`dfp_can_convert_from_rgb`), YCbCr 4:4:4 when
/// it converts only 4:4:4 to 4:2:0 (`dfp_can_convert_from_ycbcr444`), and
/// YCbCr 4:2:0 otherwise, which is refused. A 4:2:0-also mode keeps RGB:
/// a converted output carries no fewer link bits, and the native 4:2:0
/// fallback is the refused one. The protocol-converter configuration is
/// `intel_dp_configure_protocol_converter`'s.
pub fn dp_output(
    dpcd: &[u8],
    dfp: DfpCaps,
    edid: &[u8],
    mode: &crate::intel_gpu_modeset::Mode,
) -> Result<DpOutput, ColorRefusal> {
    use crate::intel_gpu_hdmi::{is_hdmi_sink, parse_ycbcr420, vic_for_mode};
    let branch = dp_is_branch(dpcd);
    let from_rgb = branch && dfp.rgb_to_ycbcr && dfp.ycbcr_444_to_420;
    let from_444 = branch && dfp.ycbcr_444_to_420;
    let can_420 = !branch || dfp.ycbcr420_passthrough || from_rgb || from_444;
    let sink_420 = parse_ycbcr420(edid).only(vic_for_mode(mode)) && can_420;
    let ycbcr444 = if !sink_420 || from_rgb {
        false
    } else if from_444 {
        true
    } else {
        return Err(ColorRefusal::Ycbcr420Output);
    };
    let pcon = (branch && dpcd.get(DP_DPCD_REV).is_some_and(|&rev| rev >= 0x13)).then(|| {
        PconConfig {
            hdmi_sink: is_hdmi_sink(edid),
            ycbcr444_to_420: sink_420,
            rgb_to_ycbcr: sink_420 && !ycbcr444,
        }
    });
    Ok(DpOutput { ycbcr444, pcon })
}

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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_color_tests.rs"]
pub mod tests;
