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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_color_tests.rs"]
pub mod tests;
