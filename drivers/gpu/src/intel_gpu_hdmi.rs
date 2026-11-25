//! Intel external HDMI — full path (#1019).
//!
//! Everything an external HDMI sink needs that the DP path
//! does not have: EDID over DDC (GMBUS), TMDS modeset to HDMI
//! 2.0 rates with SCDC scrambling, AVI infoframe emission over
//! the transcoder DIP banks, and HDMI audio publication. The
//! register sequence runs through
//! [`Modeset::modeset_hdmi`](crate::intel_gpu_modeset::Modeset::modeset_hdmi) —
//! this module is the session layer around it, symmetric with
//! `intel_gpu_dp`.
//!
//! ## Seams consumed (built by other lanes — not re-implemented)
//!
//! - **GMBUS transport** (`intel_gpu_gmbus`): every DDC transfer runs
//!   through [`GmbusBus`] (`intel_gmbus.c::do_gmbus_xfer`): EDID blocks
//!   as `drm_do_probe_ddc_edid` sends them (offset write + read as one
//!   index transfer, the E-DDC segment pointer chained ahead of blocks 2
//!   and 3 by repeated START, [`crate::intel_gpu_gmbus::read_edid_eddc`]),
//!   SCDC as `drm_scdc_readb`/`drm_scdc_writeb`. This replaced an older
//!   engine that ran each program as a single STOP cycle and then waited
//!   for bus idle, wrote the byte index to GMBUS5 without
//!   `GMBUS_2BYTE_INDEX_EN`, and read SCDC SCRAMBLER_STATUS before any
//!   scrambled data flowed.
//! - **Shared display-audio sink**
//!   (`narf_drivers_sound::display_audio`, built by Q4 #1092):
//!   this lane is its second publisher, with
//!   [`DisplayConnector::Hdmi`]. The codec-side programming is
//!   the HDMI branch in [`crate::intel_gpu_audio`].
//! - **HPD** (`intel_gpu_dp::{HpdMonitor, hotplug_bit}`): the
//!   combo-DDI hotplug block is shared with DP; the production
//!   glue in `intel_gpu` routes a connect to whichever session
//!   answers (a DP sink answers AUX, an HDMI sink answers
//!   DDC).
//!
//! ## Protocol sources (fixtures are pinned against these)
//!
//! - HDMI 2.0 / CTA-861: infoframe packing + checksum
//!   (HDMI 1.4 §5.3.5 frame shape as implemented by Linux
//!   `drivers/video/hdmi.c`), AVI/audio infoframe data-byte
//!   layouts, CTA data-block iteration, HF-VSDB (OUI
//!   0xC45DD8) SCDC capability bits.
//! - HDMI SCDC: register map and semantics from the Linux
//!   `drm_scdc_helper` (`include/drm/display/
//!   drm_scdc_helper.h`): slave 0x54, TMDS_CONFIG 0x20
//!   (bit 0 scrambling enable, bit 1 clock ratio 1/40),
//!   SCRAMBLER_STATUS 0x21 bit 0; >340 Mcsc requires ratio
//!   1/40 + scrambling, <=340 Mcsc requires neither. The
//!   enable sequence is `intel_hdmi_handle_sink_scrambling`
//!   ([`handle_sink_scrambling`]); the scrambler status is only
//!   sampled once the stream runs ([`scrambler_status`]).
//! - Intel PRM Vol. 2c (TRANS_DDI_FUNC_CTL HDMI bits), Vol. 11
//!   (WRPLL — see `intel_gpu_pll::hdmi_wrpll_coeffs`), Vol. 12
//!   (VIDEO_DIP_* HSW bank map + the hsw_write_infoframe
//!   protocol in i915 `intel_hdmi.c`): the DIP buffer carries
//!   the infoframe with a 1-byte ECC hole at position 3 and is
//!   zero-padded to 32 bytes. There is no audio DIP bank — on
//!   this hardware the audio infoframe is synthesised by the
//!   HDA codec from the published ELD; the display side packs
//!   the frame ([`pack_audio_infoframe`]) and carries it on
//!   the connection for that consumer.
//!
//! ## Character-rate rule
//!
//! The TMDS character rate of an 8-bpc mode is its pixel
//! clock. Above 340 Mcsc the HDMI spec requires SCDC
//! scrambling + the 1/40 clock ratio, and the PRM requires
//! the TRANS_DDI_FUNC_CTL scrambling + high-char-rate bits;
//! at or below 340 Mcsc the sink must not be touched over
//! SCDC at all. A >340 Mcsc mode against a sink that does not
//! declare SCDC in its HF-VSDB is refused, not degraded.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_drivers_sound::display_audio::{
    build_eld, clear_display_audio, publish_display_audio, DisplayConnector,
};

use crate::intel_gpu_audio;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_dp::sink_id_for;
use crate::intel_gpu_gmbus::{GmbusBus, GmbusError, PinPair};
use crate::intel_gpu_modeset::{Framebuffer, Mode, Modeset, ModesetError};
use crate::intel_gpu_pipes::Transcoder;
use crate::intel_gpu_vbt::Gen12DdcOverrides;

// ── DDC over GMBUS ─────────────────────────────────────────────

/// Errors from the DDC transfers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DdcError {
    /// The GMBUS transport refused the transfer shape or pin.
    Gmbus(GmbusError),
    /// The addressed slave NACKed (no sink, or not that slave).
    SlaveNack,
    /// The controller did not reach the expected state in time.
    Timeout,
    /// The platform has no such DDI, so it has no DDC pin
    /// ([`crate::intel_gpu_gmbus::gen12_ddc_pin`]).
    NoPinPair,
}

impl From<GmbusError> for DdcError {
    fn from(e: GmbusError) -> Self {
        match e {
            GmbusError::SlaveNack => DdcError::SlaveNack,
            GmbusError::Timeout | GmbusError::HardwareTimeout => DdcError::Timeout,
            other => DdcError::Gmbus(other),
        }
    }
}

// ── EDID over DDC ──────────────────────────────────────────────

/// Largest EDID this session buffers: base + 3 extensions —
/// the same capacity as the DP session.
pub const EDID_CAPACITY: usize = crate::intel_gpu_gmbus::EDID_MAX_BYTES;

/// Read the sink's complete EDID over DDC as `drm_edid.c` does
/// ([`crate::intel_gpu_gmbus::read_edid_eddc`]): the base block and
/// every extension it announces up to [`EDID_CAPACITY`], blocks 2 and 3
/// through the E-DDC segment pointer in the same transfer as the read.
/// Returns the buffer and the valid byte count.
pub fn read_edid<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
) -> Result<([u8; EDID_CAPACITY], usize), DdcError> {
    let mut edid = [0u8; EDID_CAPACITY];
    let len = crate::intel_gpu_gmbus::read_edid_eddc(mmio, pin, &mut edid)?;
    Ok((edid, len))
}

// ── CTA HF-VSDB (SCDC capability discovery) ────────────────────

/// HDMI Forum Vendor-Specific Data Block OUI 0xC45DD8, on the
/// wire little-endian (D8 5D C4).
const HF_VSDB_OUI: [u8; 3] = [0xD8, 0x5D, 0xC4];

/// The SCDC-relevant capabilities a sink declares in its
/// CTA-861 HDMI Forum VSDB (payload layout: OUI[3], version,
/// max TMDS character rate in 5 MHz units, then the feature
/// byte: bit 7 SCDC_Present, bit 6 SCDC read-request capable,
/// bit 3 LTE_340Mcsc_scramble).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HfVsdb {
    /// An HF-VSDB was present at all.
    pub present: bool,
    /// The sink implements SCDC (required above 340 Mcsc).
    pub scdc_present: bool,
    /// The sink can raise SCDC read requests.
    pub scdc_read_request_capable: bool,
    /// The sink accepts scrambling at/below 340 Mcsc too.
    pub lte_340mcsc_scramble: bool,
    /// Max TMDS character rate in kHz (5 MHz units on the
    /// wire); 0 when the block carries no rate byte.
    pub max_tmds_char_rate_khz: u32,
    /// Max FRL rate in Gbps (`hf_scds[7]` bits 7:4 through
    /// `drm_get_max_frl_rate`); 0 for a sink without FRL.
    pub max_frl_gbps: u8,
    /// Max FRL rate for DSC transport (`hf_scds[12]` bits 7:4, when the
    /// block declares DSC 1.2); 0 otherwise.
    pub dsc_max_frl_gbps: u8,
}

/// Scan a complete EDID's CTA extensions for the HF-VSDB.
/// Data blocks are iterated per CTA-861: each extension's
/// block collection starts at byte 4 and ends at the DTD
/// offset (byte 2; 0 means the collection runs to the block
/// end). Other vendor blocks (including the HDMI Licensing
/// VSDB, OUI 0x000C03) are walked past, never matched.
/// The HDMI Licensing VSDB OUI, `00-0C-03` little-endian
/// (`HDMI_IEEE_OUI`).
const HDMI_VSDB_OUI: [u8; 3] = [0x03, 0x0C, 0x00];
/// DVI single-link ceiling (`hdmi_port_clock_valid`: a sink without an
/// HDMI VSDB is limited to 165 MHz).
pub const DVI_MAX_TMDS_KHZ: u32 = 165_000;

/// The HDMI Licensing VSDB (`drm_parse_hdmi_vsdb_video`): the deep-colour
/// flags (byte 6) and the max TMDS clock (byte 7, 5 MHz units).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HdmiVsdb {
    /// `DRM_EDID_HDMI_DC_30`: 10 bpc RGB 4:4:4.
    pub dc_30: bool,
    /// `DRM_EDID_HDMI_DC_36`: 12 bpc RGB 4:4:4.
    pub dc_36: bool,
    /// `max_tmds_clock` in kHz; 0 when the block has no rate byte.
    pub max_tmds_khz: u32,
}

/// The sink's HDMI VSDB, `None` for a DVI sink.
pub fn parse_hdmi_vsdb(edid: &[u8]) -> Option<HdmiVsdb> {
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
                let flags = payload.get(5).copied().unwrap_or(0);
                return Some(HdmiVsdb {
                    dc_30: flags & (1 << 4) != 0,
                    dc_36: flags & (1 << 5) != 0,
                    max_tmds_khz: payload.get(6).map_or(0, |&b| u32::from(b) * 5_000),
                });
            }
            pos += 1 + len;
        }
    }
    None
}

/// `drm_display_info.is_hdmi` (`drm_parse_hdmi_vsdb_video` via
/// `drm_parse_cea_ext`): a CTA extension carries the HDMI Licensing VSDB.
/// A sink without one is DVI (`intel_has_hdmi_sink`): no infoframes, no
/// audio, no SCDC, `TRANS_DDI_MODE_SELECT_DVI`.
pub fn is_hdmi_sink(edid: &[u8]) -> bool {
    parse_hdmi_vsdb(edid).is_some()
}

/// `intel_hdmi_source_max_tmds_clock` (no VBT cap): 600 MHz on display
/// 13 and ADL-S, 594 MHz on display 10-12, 300 MHz on display 9.
pub const fn source_max_tmds_khz(family: crate::intel_gpu_aux::SourceFamily) -> u32 {
    use crate::intel_gpu_aux::SourceFamily;
    use crate::intel_gpu_gt::Gen12Platform;
    match family {
        SourceFamily::Gen12(
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN | Gen12Platform::AlderLakeS,
        ) => 600_000,
        SourceFamily::Gen12(_) | SourceFamily::Gen11(_) => 594_000,
        // Display 10 (Gemini Lake) reaches 594 MHz; display 9 300 MHz.
        SourceFamily::Gen9 {
            platform: crate::intel_gpu_gt::Gen9Platform::GeminiLake,
            ..
        } => 594_000,
        SourceFamily::Gen9 { .. } => 300_000,
    }
}

/// `intel_hdmi_tmds_clock` for RGB: `DIV_ROUND_CLOSEST(clock * bpc, 8)`.
pub const fn tmds_clock_khz(pixel_clock_khz: u32, bpc: u8) -> u32 {
    (pixel_clock_khz * bpc as u32 + 4) / 8
}

/// `intel_hdmi_tmds_clock`: a YCbCr 4:2:0 link carries half the pixel
/// clock (integer halving, as Linux), then the bpc scaling.
pub const fn tmds_clock_for(pixel_clock_khz: u32, bpc: u8, format: SinkFormat) -> u32 {
    let clock = match format {
        SinkFormat::Ycbcr420 => pixel_clock_khz / 2,
        SinkFormat::Rgb => pixel_clock_khz,
    };
    tmds_clock_khz(clock, bpc)
}

/// The PLL holes `hdmi_port_clock_valid` refuses for `ddi` on `family`
/// (exclusive bounds): the ICL/TGL combo and Type-C PHY's (500, 533.2) and
/// (500, 532.8) MHz, and Gen9 LP's DPLL ranges (`MODE_CLOCK_RANGE`):
/// Broxton and Gemini Lake cannot generate (223.333, 240) MHz, Gemini Lake
/// not (446.666, 480) MHz either. Skylake has none.
fn pll_holes(
    family: crate::intel_gpu_aux::SourceFamily,
    ddi: Option<Ddi>,
) -> [Option<(u32, u32)>; 2] {
    use crate::intel_gpu_aux::SourceFamily;
    use crate::intel_gpu_gt::Gen9Platform;
    let tc = match family {
        SourceFamily::Gen9 {
            platform: Gen9Platform::GeminiLake,
            ..
        } => return [Some((223_333, 240_000)), Some((446_666, 480_000))],
        SourceFamily::Gen9 {
            platform: Gen9Platform::Broxton,
            ..
        } => return [Some((223_333, 240_000)), None],
        SourceFamily::Gen9 { .. } => return [None, None],
        _ if ddi.is_none() => return [None, None],
        SourceFamily::Gen11(platform) => ddi.is_some_and(|ddi| {
            matches!(
                crate::intel_gpu_gen11_ddi::phy_for_port(platform, ddi),
                Some(crate::intel_gpu_gen11_ddi::Gen11Phy::Mg { .. })
            )
        }),
        // Rocket Lake's and Alder Lake S's TC ports are combo PHYs
        // (`intel_phy_is_tc` false).
        SourceFamily::Gen12(
            crate::intel_gpu_gt::Gen12Platform::RocketLake
            | crate::intel_gpu_gt::Gen12Platform::AlderLakeS,
        ) => false,
        SourceFamily::Gen12(_) => ddi.is_some_and(|ddi| ddi as u8 >= Ddi::D as u8),
    };
    [Some((500_000, if tc { 532_800 } else { 533_200 })), None]
}

/// `hdmi_port_clock_valid` with downstream limits: at least 25 MHz, at
/// most the source maximum and the sink's `max_tmds_clock` (HF-VSDB above
/// 340 MHz, else the VSDB; 165 MHz for DVI), outside the PHY's PLL hole,
/// and — this driver's SCDC gate — above 340 MHz only on an SCDC sink.
fn port_clock_valid(
    family: crate::intel_gpu_aux::SourceFamily,
    ddi: Option<Ddi>,
    tmds: u32,
    vsdb: Option<HdmiVsdb>,
    hf: &HfVsdb,
) -> bool {
    let sink_max = match vsdb {
        None => DVI_MAX_TMDS_KHZ,
        Some(_) if hf.present && hf.max_tmds_char_rate_khz > SCRAMBLING_THRESHOLD_KHZ => {
            hf.max_tmds_char_rate_khz
        }
        Some(v) => v.max_tmds_khz,
    };
    tmds >= 25_000
        && tmds <= source_max_tmds_khz(family)
        && (sink_max == 0 || tmds <= sink_max)
        && (tmds <= SCRAMBLING_THRESHOLD_KHZ || hf.scdc_present)
        && !pll_holes(family, ddi)
            .iter()
            .flatten()
            .any(|&(lo, hi)| tmds > lo && tmds < hi)
}

/// `intel_hdmi_compute_clock` for `format`, from 12 bpc down (the max_bpc
/// property defaults to its 12 bpc maximum): `intel_hdmi_source_bpc_possible`
/// (10 bpc needs display 11+), the sink's deep-colour flags (the VSDB's for
/// RGB, the HF-VSDB's 4:2:0 flags for 4:2:0; DVI is 8 bpc only), and
/// [`port_clock_valid`] at the TMDS clock. `None` when not even 8 bpc fits.
/// Returns `(bpc, tmds_khz)`.
pub fn compute_clock(
    family: crate::intel_gpu_aux::SourceFamily,
    ddi: Option<Ddi>,
    pixel_clock_khz: u32,
    vsdb: Option<HdmiVsdb>,
    hf: &HfVsdb,
    y420: &Ycbcr420Caps,
    format: SinkFormat,
) -> Option<(u8, u32)> {
    let (dc_36, dc_30) = match (vsdb, format) {
        (None, _) => (false, false),
        (Some(_), SinkFormat::Ycbcr420) => (y420.dc_36, y420.dc_30),
        (Some(v), SinkFormat::Rgb) => (v.dc_36, v.dc_30),
    };
    let gen9 = matches!(family, crate::intel_gpu_aux::SourceFamily::Gen9 { .. });
    [(12u8, dc_36), (10, dc_30 && !gen9), (8, true)]
        .into_iter()
        .filter(|&(_, possible)| possible)
        .map(|(bpc, _)| (bpc, tmds_clock_for(pixel_clock_khz, bpc, format)))
        .find(|&(_, tmds)| port_clock_valid(family, ddi, tmds, vsdb, hf))
}

/// `intel_hdmi_compute_bpc` for an RGB 4:4:4 stream (see [`compute_clock`]),
/// with no PHY known: anything that fits nowhere is 8 bpc at the pixel
/// clock. Returns `(bpc, tmds_khz)`.
pub fn compute_bpc(
    family: crate::intel_gpu_aux::SourceFamily,
    pixel_clock_khz: u32,
    vsdb: Option<HdmiVsdb>,
    hf: &HfVsdb,
) -> (u8, u32) {
    compute_clock(
        family,
        None,
        pixel_clock_khz,
        vsdb,
        hf,
        &Ycbcr420Caps::default(),
        SinkFormat::Rgb,
    )
    .unwrap_or((8, pixel_clock_khz))
}

/// `connector->base.ycbcr_420_allowed`: display 10+ (`intel_hdmi_init_connector`).
pub const fn ycbcr420_allowed(family: crate::intel_gpu_aux::SourceFamily) -> bool {
    !matches!(family, crate::intel_gpu_aux::SourceFamily::Gen9 { .. })
}

/// `intel_hdmi_compute_output_format`: a 4:2:0-only VIC goes out as 4:2:0
/// on an HDMI sink the source allows it for; otherwise RGB, falling back
/// to 4:2:0 when RGB fits at no depth and the VIC is 4:2:0-also. When
/// nothing fits the RGB 8 bpc pixel clock is returned, and the modeset
/// refuses it. Returns `(format, bpc, tmds_khz)`.
pub fn compute_output(
    family: crate::intel_gpu_aux::SourceFamily,
    ddi: Ddi,
    mode: &Mode,
    vsdb: Option<HdmiVsdb>,
    hf: &HfVsdb,
    y420: &Ycbcr420Caps,
) -> (SinkFormat, u8, u32) {
    let vic = vic_for_mode(mode);
    let allowed = vsdb.is_some() && ycbcr420_allowed(family);
    let clock = |format| {
        compute_clock(
            family,
            Some(ddi),
            mode.pixel_clock_khz,
            vsdb,
            hf,
            y420,
            format,
        )
        .map(|(bpc, tmds)| (format, bpc, tmds))
    };
    let first = if allowed && y420.only(vic) {
        SinkFormat::Ycbcr420
    } else {
        SinkFormat::Rgb
    };
    clock(first)
        .or_else(|| {
            (first == SinkFormat::Rgb && allowed && y420.also(vic))
                .then(|| clock(SinkFormat::Ycbcr420))
                .flatten()
        })
        .unwrap_or((SinkFormat::Rgb, 8, mode.pixel_clock_khz))
}

/// `gcp_default_phase_possible`: deep colour packs pixels in groups (4 per
/// 5 clocks at 10 bpc, 2 per 3 at 12 bpc); the default phase holds when
/// every horizontal timing point lands on a group boundary.
pub fn gcp_default_phase_possible(bpc: u8, mode: &Mode) -> bool {
    let group = match bpc {
        10 => 4,
        12 => 2,
        _ => return false,
    };
    // hblank start/end are hdisplay/htotal: the modeset has no borders.
    [
        mode.h_active,
        mode.h_total,
        mode.h_sync_start,
        mode.h_sync_end,
    ]
    .iter()
    .all(|&v| v % group == 0)
}

pub fn parse_hf_vsdb(edid: &[u8]) -> HfVsdb {
    let mut out = HfVsdb::default();
    for block in edid.chunks_exact(128).skip(1) {
        if block[0] != 0x02 {
            continue; // not a CTA extension
        }
        let limit = match block[2] {
            0 => 127usize,
            n => (n as usize).min(127),
        };
        let mut pos = 4usize;
        while pos < limit {
            let header = block[pos];
            let tag = header >> 5;
            let len = (header & 0x1F) as usize;
            if pos + 1 + len > 128 {
                break;
            }
            let payload = &block[pos + 1..pos + 1 + len];
            if tag == 3 && len >= 5 && payload[..3] == HF_VSDB_OUI {
                out.present = true;
                out.max_tmds_char_rate_khz = (payload[4] as u32) * 5_000;
                if len >= 6 {
                    let features = payload[5];
                    out.scdc_present = features & 0x80 != 0;
                    out.scdc_read_request_capable = features & 0x40 != 0;
                    out.lte_340mcsc_scramble = features & 0x08 != 0;
                }
                // drm_parse_hdmi_forum_scds: hf_scds[7] (payload[6]) carries
                // the max FRL rate; hf_scds[11] bit 7 is DSC 1.2 and
                // hf_scds[12] its max FRL rate.
                if let Some(&frl) = payload.get(6) {
                    out.max_frl_gbps = crate::dp_pcon::frl_rate_gbps(frl >> 4);
                }
                if payload.get(10).is_some_and(|b| b & (1 << 7) != 0) {
                    if let Some(&dsc) = payload.get(11) {
                        out.dsc_max_frl_gbps = crate::dp_pcon::frl_rate_gbps(dsc >> 4);
                    }
                }
            }
            pos += 1 + len;
        }
    }
    out
}

// ── SCDC ───────────────────────────────────────────────────────

/// SCDC DDC slave address (HDMI spec; `drm_scdc_helper.h`).
pub const DDC_SLAVE_SCDC: u8 = 0x54;
/// SCDC sink version register.
pub const SCDC_SINK_VERSION: u8 = 0x01;
/// SCDC source version register (write 1 = SCDC revision 1).
pub const SCDC_SOURCE_VERSION: u8 = 0x02;
/// SCDC TMDS_CONFIG register.
pub const SCDC_TMDS_CONFIG: u8 = 0x20;
/// TMDS_CONFIG bit 0 — scrambling enable.
pub const TMDS_CONFIG_SCRAMBLING_ENABLE: u8 = 1 << 0;
/// TMDS_CONFIG bit 1 — TMDS bit clock ratio: set = 1/40,
/// clear = 1/10.
pub const TMDS_CONFIG_CLOCK_RATIO_1_40: u8 = 1 << 1;
/// SCDC SCRAMBLER_STATUS register; bit 0 = scrambling active.
pub const SCDC_SCRAMBLER_STATUS: u8 = 0x21;
/// `SCDC_SCRAMBLING_STATUS` (SCRAMBLER_STATUS bit 0).
pub const SCDC_SCRAMBLING_STATUS: u8 = 1 << 0;

/// The character rate above which the HDMI spec mandates
/// SCDC scrambling + the 1/40 clock ratio (340 Mcsc).
pub const SCRAMBLING_THRESHOLD_KHZ: u32 = 340_000;

/// `drm_scdc_readb`: one SCDC register, the offset write and the read
/// as one index transfer at slave 0x54.
pub fn scdc_read<M: MmioWindow + ?Sized>(mmio: &M, pin: PinPair, reg: u8) -> Result<u8, DdcError> {
    let mut byte = [0u8; 1];
    GmbusBus::new(mmio, pin).read_indexed(DDC_SLAVE_SCDC, reg, &mut byte)?;
    Ok(byte[0])
}

/// `drm_scdc_writeb`: one write message `[register, value]`.
pub fn scdc_write<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    reg: u8,
    value: u8,
) -> Result<(), DdcError> {
    GmbusBus::new(mmio, pin)
        .write(DDC_SLAVE_SCDC, &[reg, value])
        .map_err(DdcError::from)
}

/// `intel_hdmi_handle_sink_scrambling` for a scrambling-capable sink:
/// `drm_scdc_set_high_tmds_clock_ratio` (read-modify-write of
/// TMDS_CONFIG bit 1, then at least 1 ms — "a source should wait minimum
/// 1ms and maximum 100ms after writing the TMDS config for clock ratio")
/// and `drm_scdc_set_scrambling` (read-modify-write of bit 0). The
/// scrambler status is not read here: the sink can only report it once
/// scrambled data flows ([`scrambler_status`]).
pub fn handle_sink_scrambling<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    high_tmds_clock_ratio: bool,
    scrambling: bool,
) -> Result<(), DdcError> {
    let config = scdc_read(mmio, pin, SCDC_TMDS_CONFIG)?;
    let config = if high_tmds_clock_ratio {
        config | TMDS_CONFIG_CLOCK_RATIO_1_40
    } else {
        config & !TMDS_CONFIG_CLOCK_RATIO_1_40
    };
    scdc_write(mmio, pin, SCDC_TMDS_CONFIG, config)?;
    let _ =
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ns(1_000_000));
    let config = scdc_read(mmio, pin, SCDC_TMDS_CONFIG)?;
    let config = if scrambling {
        config | TMDS_CONFIG_SCRAMBLING_ENABLE
    } else {
        config & !TMDS_CONFIG_SCRAMBLING_ENABLE
    };
    scdc_write(mmio, pin, SCDC_TMDS_CONFIG, config)
}

/// `drm_scdc_get_scrambling_status`: SCRAMBLER_STATUS bit 0. Only
/// meaningful while the source transmits scrambled data.
pub fn scrambler_status<M: MmioWindow + ?Sized>(mmio: &M, pin: PinPair) -> Result<bool, DdcError> {
    Ok(scdc_read(mmio, pin, SCDC_SCRAMBLER_STATUS)? & SCDC_SCRAMBLING_STATUS != 0)
}

/// Configure SCDC for a >340 Mcsc stream: the sink must declare SCDC in
/// its HF-VSDB, then [`handle_sink_scrambling`] sets the 1/40 ratio and
/// scrambling. Callers driving <=340 Mcsc do not call this at all — SCDC
/// stays untouched there.
pub fn configure_scdc<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    hf_vsdb: &HfVsdb,
) -> Result<(), HdmiError> {
    if !hf_vsdb.scdc_present {
        return Err(HdmiError::ScramblingUnsupported);
    }
    handle_sink_scrambling(mmio, pin, true, true).map_err(HdmiError::Ddc)
}

// ── Infoframes ─────────────────────────────────────────────────

/// Infoframe checksum (HDMI 1.4 §5.3.5): the byte that makes
/// the whole frame — header included — sum to 0 mod 256.
fn infoframe_checksum(frame: &[u8], checksum_index: usize) -> u8 {
    let sum: u32 = frame
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != checksum_index)
        .map(|(_, b)| *b as u32)
        .sum();
    ((256 - (sum % 256)) % 256) as u8
}

/// The CTA-861 timings this driver matches modes against
/// (`edid_cea_modes_1`): VIC, horizontal active/sync start/sync
/// end/total, the vertical four, the nominal clock (kHz), the refresh
/// (Hz) and whether both syncs are positive.
struct CtaTiming {
    vic: u8,
    h: [u16; 4],
    v: [u16; 4],
    clock_khz: u32,
    refresh: u8,
    positive_sync: bool,
}

const CTA_TIMINGS: [CtaTiming; 22] = {
    const fn t(
        vic: u8,
        h: [u16; 4],
        v: [u16; 4],
        clock_khz: u32,
        refresh: u8,
        positive_sync: bool,
    ) -> CtaTiming {
        CtaTiming {
            vic,
            h,
            v,
            clock_khz,
            refresh,
            positive_sync,
        }
    }
    const V480: [u16; 4] = [480, 489, 495, 525];
    const V576: [u16; 4] = [576, 581, 586, 625];
    const V720: [u16; 4] = [720, 725, 730, 750];
    const V1080: [u16; 4] = [1080, 1084, 1089, 1125];
    const V2160: [u16; 4] = [2160, 2168, 2178, 2250];
    [
        t(
            1,
            [640, 656, 752, 800],
            [480, 490, 492, 525],
            25_175,
            60,
            false,
        ),
        t(2, [720, 736, 798, 858], V480, 27_000, 60, false),
        t(3, [720, 736, 798, 858], V480, 27_000, 60, false),
        t(4, [1280, 1390, 1430, 1650], V720, 74_250, 60, true),
        t(16, [1920, 2008, 2052, 2200], V1080, 148_500, 60, true),
        t(17, [720, 732, 796, 864], V576, 27_000, 50, false),
        t(18, [720, 732, 796, 864], V576, 27_000, 50, false),
        t(19, [1280, 1720, 1760, 1980], V720, 74_250, 50, true),
        t(31, [1920, 2448, 2492, 2640], V1080, 148_500, 50, true),
        t(32, [1920, 2558, 2602, 2750], V1080, 74_250, 24, true),
        t(33, [1920, 2448, 2492, 2640], V1080, 74_250, 25, true),
        t(34, [1920, 2008, 2052, 2200], V1080, 74_250, 30, true),
        t(93, [3840, 5116, 5204, 5500], V2160, 297_000, 24, true),
        t(94, [3840, 4896, 4984, 5280], V2160, 297_000, 25, true),
        t(95, [3840, 4016, 4104, 4400], V2160, 297_000, 30, true),
        t(96, [3840, 4896, 4984, 5280], V2160, 594_000, 50, true),
        t(97, [3840, 4016, 4104, 4400], V2160, 594_000, 60, true),
        t(98, [4096, 5116, 5204, 5500], V2160, 297_000, 24, true),
        t(99, [4096, 5064, 5152, 5280], V2160, 297_000, 25, true),
        t(100, [4096, 4184, 4272, 4400], V2160, 297_000, 30, true),
        t(101, [4096, 5064, 5152, 5280], V2160, 594_000, 50, true),
        t(102, [4096, 4184, 4272, 4400], V2160, 594_000, 60, true),
    ]
};

/// `cea_mode_alternate_clock`: the 59.94/29.97/23.976 Hz twin of a
/// 60/30/24 Hz timing (the table holds 59.94 Hz for the 480-line modes).
const fn cta_alternate_clock(t: &CtaTiming) -> u32 {
    if t.refresh % 6 != 0 {
        t.clock_khz
    } else if t.v[0] == 480 {
        (t.clock_khz * 1001 + 500) / 1000
    } else {
        (t.clock_khz * 1000 + 500) / 1001
    }
}

/// The CTA-861 VIC for a mode, `drm_match_cea_mode` over the timings this
/// driver pins: the clock's period (`KHZ2PICOS`) equals the VIC's or its
/// 1000/1001 twin's, and every timing point and the sync polarity match. 0
/// ("no VIC — timings govern") for anything else; sinks accept VIC 0 with
/// explicit timings. The first match wins, so the anamorphic 480p/576p
/// pairs take their 4:3 VIC.
pub fn vic_for_mode(mode: &Mode) -> u8 {
    const fn picos(khz: u32) -> u32 {
        1_000_000_000 / khz
    }
    if mode.pixel_clock_khz == 0 {
        return 0;
    }
    let period = picos(mode.pixel_clock_khz);
    CTA_TIMINGS
        .iter()
        .find(|t| {
            (period == picos(t.clock_khz) || period == picos(cta_alternate_clock(t)))
                && [
                    mode.h_active,
                    mode.h_sync_start,
                    mode.h_sync_end,
                    mode.h_total,
                ] == t.h
                && [
                    mode.v_active,
                    mode.v_sync_start,
                    mode.v_sync_end,
                    mode.v_total,
                ] == t.v
                && mode.h_sync_positive == t.positive_sync
                && mode.v_sync_positive == t.positive_sync
        })
        .map_or(0, |t| t.vic)
}

// ── YCbCr 4:2:0 ────────────────────────────────────────────────

/// The pixel encoding on the TMDS link (`crtc_state->sink_format`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SinkFormat {
    #[default]
    Rgb,
    Ycbcr420,
}

/// The sink's YCbCr 4:2:0 capabilities as `drm_parse_cea_ext` keeps them:
/// the VICs it takes only as 4:2:0 (Y420VDB, `y420_vdb_modes`), the VICs it
/// also takes as 4:2:0 (Y420CMDB over the VDB's SVDs, `y420_cmdb_modes`),
/// and the HF-VSDB's 4:2:0 deep-colour flags (`y420_dc_modes`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ycbcr420Caps {
    only: [u64; 4],
    also: [u64; 4],
    /// `DRM_EDID_YCBCR420_DC_30`.
    pub dc_30: bool,
    /// `DRM_EDID_YCBCR420_DC_36`.
    pub dc_36: bool,
}

impl Ycbcr420Caps {
    fn mark(bits: &mut [u64; 4], vic: u8) {
        bits[usize::from(vic / 64)] |= 1 << (vic % 64);
    }
    fn has(bits: &[u64; 4], vic: u8) -> bool {
        vic != 0 && bits[usize::from(vic / 64)] & (1 << (vic % 64)) != 0
    }
    /// `drm_mode_is_420_only` for a mode matching `vic`.
    pub fn only(&self, vic: u8) -> bool {
        Self::has(&self.only, vic)
    }
    /// `drm_mode_is_420_also` for a mode matching `vic`.
    pub fn also(&self, vic: u8) -> bool {
        Self::has(&self.also, vic)
    }
}

/// `svd_to_vic`: bit 7 is the native flag for VICs 1..=64.
const fn svd_to_vic(svd: u8) -> u8 {
    if matches!(svd, 1..=64 | 129..=192) {
        svd & 127
    } else {
        svd
    }
}

/// `drm_valid_cea_vic`: the VICs CTA-861 defines (1..=127, 193..=219).
const fn valid_cta_vic(vic: u8) -> bool {
    matches!(vic, 1..=127 | 193..=219)
}

/// Every CTA-861 data block of every CTA extension, as `(tag, payload)`.
fn for_each_cta_block(edid: &[u8], mut f: impl FnMut(u8, &[u8])) {
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
            f(tag, &block[pos + 1..pos + 1 + len]);
            pos += 1 + len;
        }
    }
}

/// `drm_parse_cea_ext`'s 4:2:0 parse: Y420VDB VICs (extended tag 14),
/// the Y420CMDB bitmap (extended tag 15, at most 8 bytes; an empty map
/// marks every SVD) applied to the first 64 SVDs across all video data
/// blocks (`update_cta_y420cmdb`), and the HF-VSDB's 4:2:0 deep colour.
pub fn parse_ycbcr420(edid: &[u8]) -> Ycbcr420Caps {
    let mut caps = Ycbcr420Caps::default();
    let mut vics = [0u8; 64];
    let mut vics_len = 0usize;
    let mut cmdb: u64 = 0;
    for_each_cta_block(edid, |tag, payload| match tag {
        2 => {
            for &svd in payload {
                let vic = svd_to_vic(svd);
                if vics_len < vics.len() {
                    vics[vics_len] = if valid_cta_vic(vic) { vic } else { 0 };
                }
                vics_len += 1;
            }
        }
        3 if payload.len() >= 7 && payload[..3] == HF_VSDB_OUI => {
            caps.dc_30 = payload[6] & 1 != 0;
            caps.dc_36 = payload[6] & 2 != 0;
        }
        7 if payload.first() == Some(&0x0E) => {
            for &svd in &payload[1..] {
                let vic = svd_to_vic(svd);
                if valid_cta_vic(vic) {
                    Ycbcr420Caps::mark(&mut caps.only, vic);
                }
            }
        }
        7 if payload.first() == Some(&0x0F) => {
            let map = &payload[1..];
            cmdb = if map.is_empty() {
                u64::MAX
            } else {
                map.iter()
                    .take(8)
                    .enumerate()
                    .fold(0, |m, (i, &b)| m | (u64::from(b) << (8 * i)))
            };
        }
        _ => {}
    });
    for (i, &vic) in vics.iter().take(vics_len.min(64)).enumerate() {
        if vic != 0 && cmdb & (1 << i) != 0 {
            Ycbcr420Caps::mark(&mut caps.also, vic);
        }
    }
    caps
}

/// Pack the AVI infoframe for `mode` (17 bytes: 4 header +
/// 13 data), per CTA-861 / HDMI 1.4 §5.3.5 as Linux
/// `drivers/video/hdmi.c::hdmi_avi_infoframe_pack` lays it
/// out: RGB colorspace, active-format aspect present and
/// "same as picture", colorimetry by mode class (ITU-709 for
/// HD VICs, ITU-601 for SD), full quantization range for RGB,
/// the mode's VIC, no bars.
pub fn pack_avi_infoframe(mode: &Mode) -> [u8; 17] {
    pack_avi_infoframe_for(mode, SinkFormat::Rgb)
}

/// [`pack_avi_infoframe`] for `format`, as `intel_hdmi_compute_avi_infoframe`
/// fills it: a YCbCr 4:2:0 stream carries colorspace Y420 (DB1 Y = 3), the
/// default RGB quantization field and limited YCC quantization (DB5 YQ = 0).
pub fn pack_avi_infoframe_for(mode: &Mode, format: SinkFormat) -> [u8; 17] {
    let vic = vic_for_mode(mode);
    let picture_aspect: u8 = if mode.v_active != 0 && mode.h_active * 9 == mode.v_active * 16 {
        2 // 16:9
    } else if mode.h_active * 3 == mode.v_active * 4 || (mode.h_active, mode.v_active) == (720, 480)
    {
        1 // 4:3
    } else {
        0
    };
    let colorimetry: u8 = if vic >= 16 || vic == 4 {
        2 // ITU-709 (HD formats)
    } else if vic != 0 {
        1 // ITU-601 (SD formats)
    } else {
        0
    };
    let mut frame = [0u8; 17];
    frame[0] = 0x82; // AVI infoframe type
    frame[1] = 2; // version
    frame[2] = 13; // length
                   // DB1: colorspace RGB (0) << 5 | active-aspect present.
    frame[4] = 1 << 4;
    // DB2: colorimetry << 6 | picture aspect << 4 | active
    // aspect (8 = same as picture aspect ratio).
    frame[5] = (colorimetry << 6) | (picture_aspect << 4) | 8;
    // DB3: quantization range full (2) << 2 for RGB.
    frame[6] = 2 << 2;
    // DB4: the VIC.
    frame[7] = vic & 0x7F;
    if format == SinkFormat::Ycbcr420 {
        // DB1: Y420 (3) << 5 | active-aspect present; DB3: quantization
        // default; DB5: YQ limited (0).
        frame[4] = (3 << 5) | (1 << 4);
        frame[6] = 0;
        frame[8] = 0;
    }
    frame[3] = infoframe_checksum(&frame, 3);
    frame
}

/// Pack the audio infoframe for a stream of `channels`
/// channels (14 bytes: 4 header + 10 data), per CTA-861 as
/// `hdmi_audio_infoframe_pack` lays it out: coding type and
/// sample frequency refer to the stream header (0) — they are
/// the HDA stream's facts, not the display's; the channel
/// count (channels - 1) and the channel allocation for the
/// standard 2.0 / 5.1 / 7.1 layouts are the display-side
/// facts the ELD established.
pub fn pack_audio_infoframe(channels: u8) -> [u8; 14] {
    let mut frame = [0u8; 14];
    frame[0] = 0x84; // audio infoframe type
    frame[1] = 1; // version
    frame[2] = 10; // length
                   // DB1: coding type 0 (stream header) << 4 | channel count.
    frame[4] = if channels >= 2 {
        (channels - 1) & 0x7
    } else {
        0
    };
    // DB4: channel allocation (CTA-861 speaker layouts).
    frame[7] = match channels {
        6 => 0x0B, // 5.1: FL FR LFE FC RL RR
        8 => 0x13, // 7.1: + RLC RRC
        _ => 0x00, // stereo / other: FL FR
    };
    frame[3] = infoframe_checksum(&frame, 3);
    frame
}

// ── DIP (Data Island Packet) banks ─────────────────────────────
//
// Per-transcoder banks at stride 0x1000 from the transcoder
// timing base (HSW map, i915 `intel_hdmi.c` / `i915_reg.h`):
// VIDEO_DIP_CTL +0x200, VIDEO_DIP_AVI_DATA +0x220. The write
// protocol is `hsw_write_infoframe`: clear the type's enable
// bit, write the data bank, set the enable bit. The DIP
// buffer is the frame with a 1-byte ECC hole at position 3
// (the checksum moves to position 4), zero-padded to the
// 32-byte VIDEO_DIP_DATA_SIZE so the hardware ECC covers the
// whole bank.

/// `VIDEO_DIP_CTL` offset from the transcoder timing base.
pub const VIDEO_DIP_CTL_OFFSET: u64 = 0x200;
/// `VIDEO_DIP_AVI_DATA` offset from the transcoder timing base.
pub const VIDEO_DIP_AVI_DATA_OFFSET: u64 = 0x220;
/// VIDEO_DIP_CTL AVI enable bit (HSW encoding).
pub const VIDEO_DIP_ENABLE_AVI: u32 = 1 << 12;
/// VIDEO_DIP_CTL GCP enable bit (HSW encoding).
pub const VIDEO_DIP_ENABLE_GCP: u32 = 1 << 16;
/// `HSW_TVIDEO_DIP_GCP` offset from the transcoder timing base.
pub const VIDEO_DIP_GCP_OFFSET: u64 = 0x210;
/// `GCP_COLOR_INDICATION` and `GCP_DEFAULT_PHASE_ENABLE`.
pub const GCP_COLOR_INDICATION: u32 = 1 << 2;
pub const GCP_DEFAULT_PHASE_ENABLE: u32 = 1 << 1;

/// The General Control Packet (`intel_hdmi_compute_gcp_infoframe` +
/// `hsw_set_infoframes`): every HDMI sink with infoframes gets it, with
/// the colour indication above 8 bpc and the default phase when the
/// timing is group-aligned.
pub fn write_gcp<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder, bpc: u8, mode: &Mode) {
    let mut gcp = 0;
    if bpc > 8 {
        gcp |= GCP_COLOR_INDICATION;
    }
    if gcp_default_phase_possible(bpc, mode) {
        gcp |= GCP_DEFAULT_PHASE_ENABLE;
    }
    mmio.write32(trans.base() + VIDEO_DIP_GCP_OFFSET, gcp);
    let ctl = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let cur = mmio.read32(ctl);
    mmio.write32(ctl, cur | VIDEO_DIP_ENABLE_GCP);
    compiler_fence(Ordering::SeqCst);
}

/// Total DIP data-bank size in bytes (8 dwords).
pub const VIDEO_DIP_DATA_SIZE: usize = 32;

/// Emit the AVI infoframe through the transcoder's DIP bank.
pub fn write_avi_infoframe<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder, frame: &[u8; 17]) {
    // DIP image: header bytes 0..2, ECC hole at 3, then the
    // frame from its checksum byte on.
    let mut image = [0u8; VIDEO_DIP_DATA_SIZE];
    image[0] = frame[0];
    image[1] = frame[1];
    image[2] = frame[2];
    image[4..4 + 14].copy_from_slice(&frame[3..17]);
    let ctl_off = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let data_off = trans.base() + VIDEO_DIP_AVI_DATA_OFFSET;
    let cur = mmio.read32(ctl_off);
    mmio.write32(ctl_off, cur & !VIDEO_DIP_ENABLE_AVI);
    compiler_fence(Ordering::SeqCst);
    for (i, chunk) in image.chunks_exact(4).enumerate() {
        mmio.write32(
            data_off + (i as u64) * 4,
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
        );
    }
    compiler_fence(Ordering::SeqCst);
    mmio.write32(ctl_off, cur | VIDEO_DIP_ENABLE_AVI);
    // Posting read: the enable write must land before the
    // stream's first data island.
    let _ = mmio.read32(ctl_off);
    compiler_fence(Ordering::SeqCst);
}

/// Disable the DIP infoframes this session emits (AVI + GCP)
/// ahead of teardown.
pub fn disable_infoframes<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder) {
    let ctl_off = trans.base() + VIDEO_DIP_CTL_OFFSET;
    let cur = mmio.read32(ctl_off);
    mmio.write32(
        ctl_off,
        cur & !(VIDEO_DIP_ENABLE_AVI | VIDEO_DIP_ENABLE_GCP),
    );
    compiler_fence(Ordering::SeqCst);
}

// ── Session ────────────────────────────────────────────────────

/// Errors the HDMI session can return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HdmiError {
    /// DDC transfer failed.
    Ddc(DdcError),
    /// EDID parse failed.
    Edid(narf_graphics::edid::EdidError),
    /// The modeset orchestrator failed.
    Modeset(ModesetError),
    /// A >340 Mcsc mode was requested against a sink whose
    /// HF-VSDB does not declare SCDC — the mode cannot be
    /// driven legally, and is refused rather than degraded.
    ScramblingUnsupported,
    /// A DVI sink's mode exceeds the 165 MHz single-link TMDS clock.
    DviClockTooHigh,
}

impl From<DdcError> for HdmiError {
    fn from(e: DdcError) -> Self {
        HdmiError::Ddc(e)
    }
}

impl From<GmbusError> for HdmiError {
    fn from(e: GmbusError) -> Self {
        HdmiError::Ddc(e.into())
    }
}

impl From<ModesetError> for HdmiError {
    fn from(e: ModesetError) -> Self {
        HdmiError::Modeset(e)
    }
}

/// The result of the DDC-side sink probe: everything
/// [`activate`] needs, plus the raw EDID.
#[derive(Clone, Debug)]
pub struct HdmiSinkProbe {
    /// The DDI the sink hangs off.
    pub ddi: Ddi,
    /// The DDC pin the probe used (`intel_hdmi_ddc_pin`: the VBT pin or
    /// the platform default); SCDC traffic uses the same pin.
    pub pin: PinPair,
    /// The sink's preferred mode (first detailed timing).
    pub mode: Mode,
    /// The complete EDID bytes (`edid_len` valid).
    pub edid: [u8; EDID_CAPACITY],
    /// Valid byte count in `edid`.
    pub edid_len: usize,
    /// The sink's HF-VSDB capabilities.
    pub hf_vsdb: HfVsdb,
    /// The mode's character rate exceeds 340 Mcsc, so SCDC
    /// scrambling is mandatory for this stream.
    pub scrambling_required: bool,
    /// The sink is HDMI ([`is_hdmi_sink`]); `false` is a DVI sink.
    pub hdmi_sink: bool,
    /// The link's pixel encoding ([`compute_output`]).
    pub format: SinkFormat,
    /// The port's bits per colour ([`compute_output`]): 8, 10 or 12.
    pub bpc: u8,
    /// The TMDS clock at that depth (the port clock).
    pub tmds_clock_khz: u32,
}

/// A live HDMI connection.
#[derive(Clone, Debug)]
pub struct HdmiConnection {
    /// Exact source family retained through disconnect.
    pub family: crate::intel_gpu_aux::SourceFamily,
    /// The DDI the sink hangs off.
    pub ddi: Ddi,
    /// The pipe scanning this connection out (Pipe A for [`activate`]).
    pub pipe: crate::intel_gpu_pipes::Pipe,
    /// The link's pixel encoding.
    pub format: SinkFormat,
    /// The mode being scanned out.
    pub mode: Mode,
    /// Whether an ELD was published for this connection.
    pub audio_published: bool,
    /// Whether SCDC scrambling is active for this stream.
    pub scrambling: bool,
    /// The DDC pin of the sink (SCDC reset on disconnect).
    pub pin: PinPair,
    /// SCRAMBLER_STATUS sampled once the scrambled stream ran
    /// (`drm_scdc_get_scrambling_status`); `None` when the stream is not
    /// scrambled or the read failed. Linux never gates a modeset on it,
    /// so neither does this session.
    pub scrambler_status: Option<bool>,
    /// The audio infoframe for this stream, packed for the
    /// HDA-side consumer that synthesises it on this hardware
    /// (see the module docs); `None` when the sink reported
    /// no audio.
    pub audio_infoframe: Option<[u8; 14]>,
}

/// Convert the EDID's preferred detailed timing into the
/// modeset's `Mode` shape (the same field mapping the DP
/// session uses).
fn mode_from_edid(edid_raw: &[u8]) -> Result<Mode, HdmiError> {
    let edid = narf_graphics::edid::Edid::parse(&edid_raw[..128]).map_err(HdmiError::Edid)?;
    let d = edid.preferred_timing().map_err(HdmiError::Edid)?;
    Ok(Mode {
        pixel_clock_khz: d.pixel_clock_khz,
        h_active: d.h_active,
        h_total: d.h_active + d.h_blanking,
        h_sync_start: d.h_active + d.h_sync_offset,
        h_sync_end: d.h_active + d.h_sync_offset + d.h_sync_width,
        v_active: d.v_active,
        v_total: d.v_active + d.v_blanking,
        v_sync_start: d.v_active + d.v_sync_offset,
        v_sync_end: d.v_active + d.v_sync_offset + d.v_sync_width,
        h_sync_positive: d.h_sync_positive,
        v_sync_positive: d.v_sync_positive,
    })
}

/// Phase 1 of a connect: run the DDC conversation — read the
/// complete EDID over GMBUS and derive the mode and the
/// sink's SCDC capabilities. No display registers are touched
/// beyond the GMBUS block. The DDC pin is the VBT's
/// (`ddc`, resolved by `intel_hdmi_ddc_pin`) or the family's default
/// ([`crate::intel_gpu_gmbus::gen12_ddc_pin`]); a DDI with neither
/// refuses before any access.
pub fn probe_sink<M: MmioWindow + ?Sized>(
    mmio: &M,
    ddi: Ddi,
    ddc: &Gen12DdcOverrides,
) -> Result<HdmiSinkProbe, HdmiError> {
    let family = crate::intel_gpu_aux::SourceFamily::of(mmio)
        .ok_or(HdmiError::Modeset(ModesetError::UnsupportedGeneration))?;
    let pch = mmio
        .gen12_hpd_profile()
        .and_then(|p| p.gen9_gmbus_table().or_else(|| p.rkl_gmbus_table()));
    let pin = ddc_pin(family, ddc, pch, ddi).ok_or(DdcError::NoPinPair)?;
    let (edid, edid_len) = read_edid(mmio, pin)?;
    let mode = mode_from_edid(&edid[..edid_len])?;
    let hf_vsdb = parse_hf_vsdb(&edid[..edid_len]);
    let vsdb = parse_hdmi_vsdb(&edid[..edid_len]);
    let hdmi_sink = vsdb.is_some();
    let y420 = parse_ycbcr420(&edid[..edid_len]);
    let (format, bpc, tmds_clock_khz) = compute_output(family, ddi, &mode, vsdb, &hf_vsdb, &y420);
    Ok(HdmiSinkProbe {
        hdmi_sink,
        format,
        bpc,
        tmds_clock_khz,
        ddi,
        pin,
        mode,
        edid,
        edid_len,
        hf_vsdb,
        scrambling_required: tmds_clock_khz > SCRAMBLING_THRESHOLD_KHZ,
    })
}

/// Phase 2 of a connect: SCDC (when the rate demands it),
/// the TMDS modeset, the AVI infoframe, and audio
/// publication. Ordering follows the hardware rules: SCDC is
/// programmed while the port is still disabled (the
/// TRANS_DDI_FUNC_CTL scrambling bits are written inside the
/// modeset and must not change while the port is enabled; Linux
/// also writes it before `intel_ddi_buf_enable`), the scrambler
/// status is sampled only after the stream runs, and the ELD
/// lands in the shared sink *before* the codec path enables and
/// ELD_VALID rises — the same invariant the DP session keeps.
pub fn activate<M: MmioWindow + ?Sized>(
    mmio: &M,
    probe: &HdmiSinkProbe,
    fb: &Framebuffer,
) -> Result<HdmiConnection, HdmiError> {
    activate_on_pipe(mmio, probe, fb, crate::intel_gpu_pipes::Pipe::A, None)
}

/// [`activate`] on `pipe`, claimed from `intel_gpu_multipipe` by the glue,
/// with `dbuf_share` when the coordinator computed one: the modeset, the
/// infoframes, GCP and the audio codec all run on that pipe's transcoder.
pub fn activate_on_pipe<M: MmioWindow + ?Sized>(
    mmio: &M,
    probe: &HdmiSinkProbe,
    fb: &Framebuffer,
    pipe: crate::intel_gpu_pipes::Pipe,
    dbuf_share: Option<(u16, u16)>,
) -> Result<HdmiConnection, HdmiError> {
    let trans = pipe.transcoder();
    let family = crate::intel_gpu_aux::SourceFamily::of(mmio)
        .ok_or(HdmiError::Modeset(ModesetError::UnsupportedGeneration))?;
    let pin = probe.pin;
    // A DVI sink is single-link TMDS: no SCDC, so the >340 Mcsc branch
    // below is unreachable for it.
    if !probe.hdmi_sink && probe.mode.pixel_clock_khz > DVI_MAX_TMDS_KHZ {
        return Err(HdmiError::DviClockTooHigh);
    }
    let mut scrambling = false;
    if probe.scrambling_required {
        configure_scdc(mmio, pin, &probe.hf_vsdb)?;
        scrambling = true;
    }
    let mut modeset = Modeset::for_pipe(mmio, probe.ddi, pipe);
    modeset.set_source_family(family);
    if let Some((start, end)) = dbuf_share {
        modeset.set_dbuf_share(start, end);
        modeset.set_shared_cdclk(true);
    }
    modeset.set_hdmi_dvi(!probe.hdmi_sink);
    modeset.set_hdmi_bpc(probe.bpc);
    modeset.set_hdmi_ycbcr420(probe.format == SinkFormat::Ycbcr420);
    let mode = modeset.modeset_hdmi(fb, &probe.mode, scrambling, scrambling)?;

    // Infoframes and audio are HDMI-sink only (`has_infoframe` and
    // `has_audio` both require `has_hdmi_sink`).
    if probe.hdmi_sink {
        let frame = pack_avi_infoframe_for(&mode, probe.format);
        write_avi_infoframe(mmio, trans, &frame);
        write_gcp(mmio, trans, probe.bpc, &mode);
    }
    // The stream is scrambled from here on; only now can the sink report
    // its scrambler status.
    let scrambler_status = if scrambling {
        scrambler_status(mmio, pin).ok()
    } else {
        None
    };

    let mut audio_published = false;
    let mut audio_infoframe = None;
    if let Some(publication) = build_eld(
        &probe.edid[..probe.edid_len],
        DisplayConnector::Hdmi,
        (probe.ddi as u64) + 1,
    )
    .filter(|_| probe.hdmi_sink)
    {
        let channels = publication.lpcm_max_channels;
        publish_display_audio(sink_id_for(probe.ddi), publication);
        intel_gpu_audio::hdmi_audio_codec_enable(mmio, trans, probe.tmds_clock_khz);
        intel_gpu_audio::set_eld_valid(mmio, trans, true);
        audio_published = true;
        audio_infoframe = Some(pack_audio_infoframe(channels));
    }

    Ok(HdmiConnection {
        family,
        ddi: probe.ddi,
        pipe,
        format: probe.format,
        mode,
        audio_published,
        scrambling,
        pin,
        scrambler_status,
        audio_infoframe,
    })
}

/// Full connect: [`probe_sink`] + [`activate`] composed, for
/// callers that already hold a framebuffer.
pub fn connect<M: MmioWindow + ?Sized>(
    mmio: &M,
    ddi: Ddi,
    ddc: &Gen12DdcOverrides,
    fb: &Framebuffer,
) -> Result<HdmiConnection, HdmiError> {
    crate::intel_gpu_aux::SourceFamily::of(mmio)
        .ok_or(HdmiError::Modeset(ModesetError::UnsupportedGeneration))?;
    let probe = probe_sink(mmio, ddi, ddc)?;
    activate(mmio, &probe, fb)
}

/// Disconnect: silence audio (codec disable + sink clear) and
/// stop the infoframes before the pipeline comes down — the
/// DP session's ordering, for the same reason: no consumer
/// may act on an ELD whose display is already gone. A scrambled
/// stream's sink gets its 1/10 ratio and scrambling reset first
/// (`intel_ddi_disable_hdmi`, best effort as in Linux). False means
/// source refusal or an unobserved/partial local stop; retain the
/// complete session.
pub fn disconnect<M: MmioWindow + ?Sized>(mmio: &M, conn: &HdmiConnection) -> bool {
    if crate::intel_gpu_aux::SourceFamily::of(mmio) != Some(conn.family) {
        return false;
    }
    let trans = conn.pipe.transcoder();
    if conn.audio_published {
        intel_gpu_audio::hdmi_audio_codec_disable(mmio, trans);
        clear_display_audio(sink_id_for(conn.ddi));
    }
    disable_infoframes(mmio, trans);
    if conn.scrambling {
        let _ = handle_sink_scrambling(mmio, conn.pin, false, false);
    }
    let mut modeset = Modeset::for_pipe(mmio, conn.ddi, conn.pipe);
    modeset.set_source_family(conn.family);
    if modeset.try_teardown().is_err() {
        return false;
    }
    // The 4:2:0 scaler, output CSC and PIPE_MISC encoding go with the
    // pipe (`skl_scaler_disable`), so a later RGB run starts clean.
    if conn.format == SinkFormat::Ycbcr420 {
        modeset.clear_ycbcr420_output();
    }
    true
}

/// The HDMI DDC pin for `ddi` on `family`: the Gen12 VBT overrides or
/// platform default, the Gen11 ICP default (`gen11_ddc_pin`), or the Gen9
/// default from the observed PCH's pin table (`pch`, SPT or CNP;
/// `gen9_ddc_pin`). A Gen9 source whose PCH was not observed has no pin.
fn ddc_pin(
    family: crate::intel_gpu_aux::SourceFamily,
    ddc: &Gen12DdcOverrides,
    pch: Option<crate::intel_gpu_gmbus::GmbusPinTable>,
    ddi: Ddi,
) -> Option<PinPair> {
    use crate::intel_gpu_aux::SourceFamily;
    use crate::intel_gpu_gmbus::GmbusPinTable;
    use crate::intel_gpu_gt::Gen12Platform::RocketLake;
    match family {
        // `rkl_encoder_to_ddc_pin`: TC1/TC2 (PHY C/D) take the Type-C pins
        // with TGP and `GMBUS_PIN_1_BXT + phy` with CMP.
        SourceFamily::Gen12(RocketLake) => ddc.pin(RocketLake, ddi).or(match (pch, ddi) {
            (Some(GmbusPinTable::Icp), Ddi::D) => Some(PinPair::Pin9Tc1),
            (Some(GmbusPinTable::Icp), Ddi::E) => Some(PinPair::Pin10Tc2),
            (Some(GmbusPinTable::Cnp), Ddi::D) => Some(PinPair::Pin3Bxt),
            (Some(GmbusPinTable::Cnp), Ddi::E) => Some(PinPair::Pin4Cnp),
            _ => None,
        }),
        SourceFamily::Gen12(family) => ddc.pin(family, ddi),
        SourceFamily::Gen11(platform) => crate::intel_gpu_gmbus::gen11_ddc_pin(platform, ddi),
        SourceFamily::Gen9 { .. } => {
            pch.and_then(|table| crate::intel_gpu_gmbus::gen9_ddc_pin(table, ddi))
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Sink-side fixtures for the HDMI-full lane (#1019).
    //!
    //! `HdmiSinkMmio` models the Gen12 display register block
    //! (same hardware behaviour rules as the DP lane's model:
    //! power-well STATE mirrors REQUEST, PIPECONF STATE mirrors
    //! ENABLE, DDI_BUF IDLE mirrors !ENABLE, the DPLL reads
    //! locked) plus a GMBUS block running real transactions
    //! against `GmbusSink` — an EDID store + SCDC register file
    //! that decodes the GMBUS1 program fields itself.
    //!
    //! Every protocol constant the sink speaks (GMBUS1 field
    //! positions, the SCDC register map, the CTA/HF-VSDB byte
    //! layout, the infoframe bytes) is written here from the
    //! HDMI/CTA specifications, not copied from the production
    //! side — the two are independent parties to the same
    //! conversation, and the byte-for-byte pins fail if either
    //! drifts.

    extern crate alloc;

    use super::*;
    use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
    use crate::intel_gpu_gmbus::{
        build_edid_read, GMBUS0, GMBUS0_RATE_100KHZ, GMBUS1, GMBUS1_CYCLE_INDEX, GMBUS1_CYCLE_STOP,
        GMBUS1_CYCLE_WAIT, GMBUS1_SW_CLR_INT, GMBUS1_SW_RDY, GMBUS2, GMBUS2_ACTIVE, GMBUS2_HW_RDY,
        GMBUS2_HW_WAIT_PHASE, GMBUS2_SATOER, GMBUS3, GMBUS5, GMBUS5_2BYTE_INDEX_EN,
    };
    use crate::intel_gpu_modeset::PixelFormat;
    use crate::intel_gpu_pipes::{Pipe as PipeIdx, PIPECONF_OFFSET, TRANS_DDI_FUNC_CTL_OFFSET};
    use crate::intel_gpu_pll::{dpll_cfgcr1, DPLL_CFGCR0_DPLL1};
    use alloc::collections::{BTreeMap, VecDeque};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── The sink ────────────────────────────────────────────────

    /// One DDC slave set behind a GMBUS controller, speaking the
    /// controller protocol `intel_gmbus.c` drives: a `SW_RDY` program
    /// starts a message (`CYCLE_INDEX` carries a 1-byte index in
    /// `GMBUS1[15:8]`, `GMBUS5` with `2BYTE_INDEX_EN` a 2-byte one), a
    /// write's first dword is preloaded into GMBUS3 before its program,
    /// a completed `CYCLE_WAIT` message holds the bus in the wait phase
    /// (the next program is a repeated START), and the `CYCLE_STOP`
    /// program releases the bus. The E-DDC segment pointer only reaches
    /// the read that follows it in the same transfer: STOP resets it.
    #[derive(Debug)]
    struct GmbusSink {
        edid: Vec<u8>,
        /// SCDC register file; SCRAMBLER_STATUS (0x21) mirrors
        /// TMDS_CONFIG bit 0 as a locking sink's does, unless
        /// `ignore_scrambling` is set.
        scdc: [u8; 256],
        segment: u8,
        gmbus5: u32,
        nack_all: bool,
        ignore_scrambling: bool,
        /// Active read: bytes still to deliver.
        read_queue: VecDeque<u8>,
        reading: bool,
        /// GMBUS3 dwords written ahead of (or during) a write message.
        tx: Vec<u8>,
        write_slave: u8,
        write_expected: usize,
        writing: bool,
        /// The running program asked for a wait cycle.
        wait_cycle: bool,
        /// The bus is held in the wait phase.
        waiting: bool,
        nack: bool,
        /// Every GMBUS1 write, in order (programs, STOP, SW_CLR_INT).
        programs: Vec<u32>,
        /// SCDC writes actually applied: (register, value).
        scdc_applied: Vec<(u8, u8)>,
        /// SCDC registers read: (register).
        scdc_reads: Vec<u8>,
        /// Every GMBUS5 write.
        gmbus5_log: Vec<u32>,
    }

    impl GmbusSink {
        fn new(edid: Vec<u8>) -> Self {
            Self {
                edid,
                scdc: [0u8; 256],
                segment: 0,
                gmbus5: 0,
                nack_all: false,
                ignore_scrambling: false,
                read_queue: VecDeque::new(),
                reading: false,
                tx: Vec::new(),
                write_slave: 0,
                write_expected: 0,
                writing: false,
                wait_cycle: false,
                waiting: false,
                nack: false,
                programs: Vec::new(),
                scdc_applied: Vec::new(),
                scdc_reads: Vec::new(),
                gmbus5_log: Vec::new(),
            }
        }

        fn on_gmbus5(&mut self, v: u32) {
            self.gmbus5 = v;
            self.gmbus5_log.push(v);
        }

        /// Decode a GMBUS1 write (fields per `intel_gmbus_regs.h`:
        /// slave [7:1], direction [0], index [15:8], byte count
        /// [24:16], cycle bits WAIT 25 / INDEX 26 / STOP 27, SW_RDY 30,
        /// SW_CLR_INT 31).
        fn on_gmbus1(&mut self, program: u32) {
            self.programs.push(program);
            if program & GMBUS1_SW_CLR_INT != 0 {
                self.nack = false;
                return;
            }
            if program & GMBUS1_SW_RDY == 0 {
                return;
            }
            let count = ((program >> 16) & 0x1FF) as usize;
            if program & GMBUS1_CYCLE_STOP != 0 && count == 0 {
                self.waiting = false;
                self.reading = false;
                self.writing = false;
                self.segment = 0;
                return;
            }
            let slave = ((program >> 1) & 0x7F) as u8;
            let dir_read = program & 1 != 0;
            self.wait_cycle = program & GMBUS1_CYCLE_WAIT != 0;
            self.waiting = false;
            self.nack = self.nack_all || !matches!(slave, 0x50 | 0x54 | 0x30);
            self.reading = false;
            self.writing = false;
            if self.nack {
                self.tx.clear();
                return;
            }
            let index = if program & GMBUS1_CYCLE_INDEX != 0 {
                Some(((program >> 8) & 0xFF) as usize)
            } else if self.gmbus5 & GMBUS5_2BYTE_INDEX_EN != 0 {
                Some((self.gmbus5 & 0xFFFF) as usize)
            } else {
                None
            };
            if dir_read {
                self.read_queue.clear();
                match slave {
                    0x50 => {
                        let start = (self.segment as usize) * 256 + index.unwrap_or(0);
                        for i in 0..count {
                            self.read_queue
                                .push_back(self.edid.get(start + i).copied().unwrap_or(0));
                        }
                    }
                    0x54 => {
                        let start = index.unwrap_or(0);
                        self.scdc_reads.push(start as u8);
                        for i in 0..count {
                            self.read_queue
                                .push_back(self.scdc.get(start + i).copied().unwrap_or(0));
                        }
                    }
                    _ => {}
                }
                self.reading = true;
            } else {
                self.write_slave = slave;
                self.write_expected = count;
                self.writing = true;
                self.try_complete_write();
            }
        }

        fn gmbus2(&self) -> u32 {
            if self.nack {
                // The aborted transfer has quiesced (ACTIVE clear);
                // SATOER stays latched until SW_CLR_INT.
                return GMBUS2_SATOER;
            }
            if self.reading && !self.read_queue.is_empty() {
                return GMBUS2_HW_RDY | GMBUS2_ACTIVE;
            }
            if self.writing {
                return GMBUS2_HW_RDY | GMBUS2_ACTIVE;
            }
            if self.waiting {
                return GMBUS2_HW_WAIT_PHASE | GMBUS2_HW_RDY | GMBUS2_ACTIVE;
            }
            0
        }

        fn on_gmbus3_read(&mut self) -> u32 {
            let mut v = 0u32;
            for b in 0..4 {
                if let Some(byte) = self.read_queue.pop_front() {
                    v |= (byte as u32) << (8 * b);
                }
            }
            if self.reading && self.read_queue.is_empty() {
                self.reading = false;
                self.waiting = self.wait_cycle;
            }
            v
        }

        fn on_gmbus3_write(&mut self, v: u32) {
            for b in 0..4 {
                self.tx.push((v >> (8 * b)) as u8);
            }
            self.try_complete_write();
        }

        fn try_complete_write(&mut self) {
            if !self.writing || self.tx.len() < self.write_expected {
                return;
            }
            let data: Vec<u8> = self.tx[..self.write_expected].to_vec();
            self.tx.clear();
            self.writing = false;
            self.waiting = self.wait_cycle;
            match self.write_slave {
                0x54 => {
                    if data.len() >= 2 {
                        let (reg, value) = (data[0], data[1]);
                        self.scdc[reg as usize] = value;
                        self.scdc_applied.push((reg, value));
                        if reg == 0x20 && !self.ignore_scrambling {
                            // A locking sink: SCRAMBLER_STATUS
                            // bit 0 follows the enable.
                            self.scdc[0x21] = value & 1;
                        }
                    }
                }
                0x30 => {
                    if let Some(segment) = data.first() {
                        self.segment = *segment;
                    }
                }
                _ => {}
            }
        }

        /// Slave addresses of every data program, in order.
        fn slaves_touched(&self) -> Vec<u8> {
            self.programs
                .iter()
                .filter(|p| *p & GMBUS1_SW_RDY != 0 && (*p >> 16) & 0x1FF != 0)
                .map(|p| ((p >> 1) & 0x7F) as u8)
                .collect()
        }

        /// Data programs only (no STOP, no recovery toggles).
        fn data_programs(&self) -> Vec<u32> {
            self.programs
                .iter()
                .copied()
                .filter(|p| *p & GMBUS1_SW_RDY != 0 && (*p >> 16) & 0x1FF != 0)
                .collect()
        }
    }

    // ── The MMIO register model ─────────────────────────────────

    const PWR_WELL_CTL2: u64 = 0x4_5404;
    /// DPLL0/1/2_ENABLE: combo DDIs A/B/C each lock their own PLL.
    const DPLL_ENABLES: [u64; 3] = [0x4_6010, 0x4_6014, 0x4_6018];
    const PLL_POWER_STATE: u32 = 1 << 26;
    const PLL_LOCK: u32 = 1 << 30;

    #[derive(Debug)]
    pub struct HdmiSinkMmio {
        family: RefCell<Option<crate::intel_gpu_gt::Gen12Platform>>,
        /// Tiger Lake UY (GT2) part: when true the window
        /// reports `tgl_uy`. Default false. HDMI always uses
        /// the shared ICL HDMI table (Linux
        /// `tgl_get_combo_buf_trans` returns
        /// `icl_combo_phy_trans_hdmi` for HDMI before any UY
        /// branch), so the flag must not change HDMI levels —
        /// the test below pins that.
        tgl_uy: RefCell<bool>,
        regs: RefCell<BTreeMap<u64, u32>>,
        pub writes: RefCell<Vec<(u64, u32)>>,
        sink: RefCell<GmbusSink>,
        ddi: Ddi,
    }

    impl HdmiSinkMmio {
        fn new(ddi: Ddi, sink: GmbusSink) -> Self {
            // DSSM strap: 19.2 MHz (field 1), so the modeset's
            // reference-family read (Q6, #1024) selects the
            // 19.2/38.4 family the WRPLL pins below assume.
            let mut regs = BTreeMap::new();
            regs.insert(crate::intel_gpu_pll::DSSM, 1u32 << 29);
            Self {
                family: RefCell::new(Some(crate::intel_gpu_gt::Gen12Platform::TigerLake)),
                tgl_uy: RefCell::new(false),
                regs: RefCell::new(regs),
                writes: RefCell::new(Vec::new()),
                sink: RefCell::new(sink),
                ddi,
            }
        }

        fn stored(&self, off: u64) -> u32 {
            self.regs.borrow().get(&off).copied().unwrap_or(0)
        }

        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn write_position(&self, off: u64) -> Option<usize> {
            self.writes.borrow().iter().position(|(o, _)| *o == off)
        }
    }

    impl MmioWindow for HdmiSinkMmio {
        fn gen12_display_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
            *self.family.borrow()
        }
        fn tgl_uy(&self) -> bool {
            *self.tgl_uy.borrow()
        }
        fn read32(&self, off: u64) -> u32 {
            if off == GMBUS2 {
                return self.sink.borrow().gmbus2();
            }
            if off == GMBUS3 {
                return self.sink.borrow_mut().on_gmbus3_read();
            }
            let v = self.stored(off);
            if off == PWR_WELL_CTL2 {
                return v | ((v & 0xAAAA_AAAA) >> 1);
            }
            if DPLL_ENABLES.contains(&off) {
                return v | PLL_POWER_STATE | PLL_LOCK;
            }
            // DBUF slices grant power when requested.
            {
                use crate::intel_gpu_wm::{
                    DBUF_CTL_S1, DBUF_CTL_S2, DBUF_POWER_REQUEST, DBUF_POWER_STATE,
                };
                if (off == DBUF_CTL_S1 || off == DBUF_CTL_S2) && v & DBUF_POWER_REQUEST != 0 {
                    return v | DBUF_POWER_STATE;
                }
            }
            let pipeconf_offs = [
                PipeIdx::A.base() + PIPECONF_OFFSET,
                Transcoder::A.conf_base() + PIPECONF_OFFSET,
                PipeIdx::B.base() + PIPECONF_OFFSET,
                Transcoder::B.conf_base() + PIPECONF_OFFSET,
                PipeIdx::C.base() + PIPECONF_OFFSET,
                Transcoder::C.conf_base() + PIPECONF_OFFSET,
            ];
            if pipeconf_offs.contains(&off) {
                use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
                let state = if v & PIPECONF_ENABLE != 0 {
                    PIPECONF_STATE
                } else {
                    0
                };
                return (v & !PIPECONF_STATE) | state;
            }
            if off == self.ddi.base() + DDI_BUF_CTL_OFFSET {
                use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS};
                let idle = if v & DDI_BUF_CTL_ENABLE != 0 {
                    0
                } else {
                    DDI_BUF_CTL_IDLE_STATUS
                };
                return (v & !DDI_BUF_CTL_IDLE_STATUS) | idle;
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().insert(off, val);
            match off {
                GMBUS5 => self.sink.borrow_mut().on_gmbus5(val),
                GMBUS1 => self.sink.borrow_mut().on_gmbus1(val),
                GMBUS3 => self.sink.borrow_mut().on_gmbus3_write(val),
                _ => {}
            }
        }
    }

    // ── EDID fixtures ───────────────────────────────────────────

    /// One detailed-timing descriptor, E-EDID §3.10 field
    /// layout (the same independent transcription the DP
    /// lane's fixture carries).
    #[allow(clippy::too_many_arguments)]
    fn detailed_timing(
        out: &mut [u8],
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        h_sync_off: u16,
        h_sync_w: u16,
        v_active: u16,
        v_blank: u16,
        v_sync_off: u16,
        v_sync_w: u16,
    ) {
        let pclk_10k = (pclk_khz / 10) as u16;
        out[0] = pclk_10k as u8;
        out[1] = (pclk_10k >> 8) as u8;
        out[2] = h_active as u8;
        out[3] = h_blank as u8;
        out[4] = (((h_active >> 8) as u8 & 0xF) << 4) | ((h_blank >> 8) as u8 & 0xF);
        out[5] = v_active as u8;
        out[6] = v_blank as u8;
        out[7] = (((v_active >> 8) as u8 & 0xF) << 4) | ((v_blank >> 8) as u8 & 0xF);
        out[8] = h_sync_off as u8;
        out[9] = h_sync_w as u8;
        out[10] = ((v_sync_off as u8 & 0xF) << 4) | (v_sync_w as u8 & 0xF);
        out[11] = (((h_sync_off >> 8) as u8 & 0x3) << 6)
            | (((h_sync_w >> 8) as u8 & 0x3) << 4)
            | (((v_sync_off >> 4) as u8 & 0x3) << 2)
            | ((v_sync_w >> 4) as u8 & 0x3);
        out[12] = 52;
        out[13] = 29;
        out[17] = 0x1E; // digital separate sync, +H +V
    }

    #[derive(Copy, Clone, PartialEq, Eq)]
    enum HfFixture {
        /// No HF-VSDB block at all.
        Absent,
        /// HF-VSDB present, SCDC_Present clear.
        NoScdc,
        /// HF-VSDB present with SCDC_Present set.
        Scdc,
    }

    /// Build a complete EDID (base + CTA extension) for an
    /// HDMI sink. The CTA carries, in order: an audio data
    /// block (LPCM + AC-3 SADs), the HDMI Licensing VSDB
    /// (OUI 0x000C03 — a decoy the HF parser must walk past),
    /// a speaker-allocation block, and (unless `hf` is
    /// Absent) the HDMI Forum VSDB LAST, so capability
    /// discovery has to iterate the whole collection.
    fn fixture_edid_hdmi(
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        v_active: u16,
        v_blank: u16,
        hf: HfFixture,
    ) -> Vec<u8> {
        let mut e = alloc::vec![0u8; 256];
        e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        let mfr: u16 = (14 << 10) | (1 << 5) | 18; // "NAR"
        e[8] = (mfr >> 8) as u8;
        e[9] = mfr as u8;
        e[10] = 0x34;
        e[11] = 0x12;
        e[18] = 1;
        e[19] = 4;
        e[126] = 1;
        detailed_timing(
            &mut e[0x36..0x36 + 18],
            pclk_khz,
            h_active,
            h_blank,
            88,
            44,
            v_active,
            v_blank,
            4,
            5,
        );
        let cta = 128usize;
        e[cta] = 0x02;
        e[cta + 1] = 3;
        e[cta + 3] = 0x40; // basic audio
        let mut p = cta + 4;
        // Audio data block: LPCM 2ch SAD + AC-3 6ch SAD.
        e[p] = (1 << 5) | 6;
        p += 1;
        e[p] = (1 << 3) | 1;
        e[p + 1] = 0x7F;
        e[p + 2] = 0x07;
        p += 3;
        e[p] = (2 << 3) | 5;
        e[p + 1] = 0x07;
        e[p + 2] = 0x00;
        p += 3;
        p += 1;
        // HDMI Licensing VSDB (tag 3, OUI 03 0C 00 LSB-first).
        e[p] = (3 << 5) | 5;
        e[p + 1] = 0x03;
        e[p + 2] = 0x0C;
        e[p + 3] = 0x00;
        e[p + 4] = 0x10; // source physical address 1.0.0.0
        e[p + 5] = 0x00;
        p += 6;
        // Speaker allocation block.
        e[p] = (4 << 5) | 3;
        e[p + 1] = 0x01;
        p += 1 + 3;
        if hf != HfFixture::Absent {
            // HDMI Forum VSDB (tag 3, OUI D8 5D C4): version 1,
            // max TMDS char rate 118 x 5 MHz = 590 MHz, feature
            // byte with SCDC_Present per the fixture kind.
            e[p] = (3 << 5) | 6;
            e[p + 1] = 0xD8;
            e[p + 2] = 0x5D;
            e[p + 3] = 0xC4;
            e[p + 4] = 1; // version
            e[p + 5] = 118; // max TMDS character rate
            e[p + 6] = if hf == HfFixture::Scdc { 0x80 } else { 0x00 };
            p += 7;
        }
        e[cta + 2] = (p - cta) as u8;
        for block in 0..2 {
            let start = block * 128;
            let sum: u32 = e[start..start + 127].iter().map(|&b| b as u32).sum();
            e[start + 127] = ((256 - (sum % 256)) % 256) as u8;
        }
        e
    }

    fn test_fb(stride_bytes: u32) -> Framebuffer {
        Framebuffer {
            phys_addr: 0x40_0000,
            stride_bytes,
            format: PixelFormat::Xrgb8888,
        }
    }

    fn mode_1080p() -> Mode {
        Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    /// VIC 97's timing (`edid_cea_modes_1`).
    fn mode_2160p60() -> Mode {
        Mode {
            pixel_clock_khz: 594_000,
            h_active: 3840,
            h_total: 4400,
            h_sync_start: 4016,
            h_sync_end: 4104,
            v_active: 2160,
            v_total: 2250,
            v_sync_start: 2168,
            v_sync_end: 2178,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    /// A base block plus one CTA extension holding `blocks` (each a full
    /// data block, header byte first).
    fn cta_edid(blocks: &[&[u8]]) -> Vec<u8> {
        let mut e = alloc::vec![0u8; 256];
        e[128] = 0x02;
        e[129] = 3;
        let mut p = 132;
        for b in blocks {
            e[p..p + b.len()].copy_from_slice(b);
            p += b.len();
        }
        e[130] = p as u8 - 128;
        e
    }

    // ── Smokes ──────────────────────────────────────────────────

    /// `drm_match_cea_mode`: the full timing, the clock or its 1000/1001
    /// twin, and the sync polarity select the VIC.
    fn smoke_hdmi_vic_matches_cta_timings() -> TestResult {
        let p1080 = mode_1080p();
        let mut p1080_50 = p1080;
        p1080_50.h_total = 2640;
        p1080_50.h_sync_start = 2448;
        p1080_50.h_sync_end = 2492;
        let mut p1080_5994 = p1080;
        p1080_5994.pixel_clock_khz = 148_352;
        let mut negative = p1080;
        negative.h_sync_positive = false;
        let p2160 = mode_2160p60();
        let mut p2160_50 = p2160;
        p2160_50.h_total = 5280;
        p2160_50.h_sync_start = 4896;
        p2160_50.h_sync_end = 4984;
        let mut p2160_30 = p2160;
        p2160_30.pixel_clock_khz = 297_000;
        for (mode, vic) in [
            (p1080, 16),
            (p1080_50, 31),
            (p1080_5994, 16),
            (negative, 0),
            (p2160, 97),
            (p2160_50, 96),
            (p2160_30, 95),
            (Mode::VESA_1024X768_60, 0),
        ] {
            if vic_for_mode(&mode) != vic {
                return TestResult::Fail("the VIC must follow the full CTA timing");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_vic_matches_cta_timings
    );

    /// `drm_parse_cea_ext`'s 4:2:0 parse: Y420VDB VICs, the Y420CMDB bitmap
    /// over the SVDs across every video data block, an empty CMDB marking
    /// all of them, and the HF-VSDB's 4:2:0 deep colour.
    fn smoke_hdmi_ycbcr420_parse() -> TestResult {
        // VDB 1: 16 (native flag set), 96; VDB 2: 97. Y420VDB: 102.
        // Y420CMDB: bit 2, the third SVD overall (97). HF-VSDB: DC_30|DC_36
        // for 4:2:0 in its seventh payload byte.
        let edid = cta_edid(&[
            &[(2 << 5) | 2, 0x80 | 16, 96],
            &[(2 << 5) | 1, 97],
            &[(7 << 5) | 2, 0x0E, 102],
            &[(7 << 5) | 2, 0x0F, 0b100],
            &[(3 << 5) | 7, 0xD8, 0x5D, 0xC4, 1, 120, 0x80, 0x03],
        ]);
        let caps = parse_ycbcr420(&edid);
        if !caps.only(102) || caps.only(97) || caps.only(16) {
            return TestResult::Fail("Y420VDB VICs are 4:2:0-only");
        }
        if !caps.also(97) || caps.also(96) || caps.also(16) || caps.also(102) {
            return TestResult::Fail("Y420CMDB marks the SVD it indexes across every VDB");
        }
        if !caps.dc_30 || !caps.dc_36 {
            return TestResult::Fail("the HF-VSDB carries the 4:2:0 deep colour");
        }
        let all = parse_ycbcr420(&cta_edid(&[&[(2 << 5) | 2, 16, 97], &[(7 << 5) | 1, 0x0F]]));
        if !all.also(16) || !all.also(97) || all.dc_30 {
            return TestResult::Fail("an empty Y420CMDB marks every SVD");
        }
        if parse_ycbcr420(&cta_edid(&[&[(2 << 5) | 1, 97]])) != Ycbcr420Caps::default() {
            return TestResult::Fail("no 4:2:0 blocks means no 4:2:0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_ycbcr420_parse);

    /// `drm_parse_hdmi_forum_scds`: the max FRL rate in `hf_scds[7]` and,
    /// with DSC 1.2 declared in `hf_scds[11]`, the DSC max FRL rate in
    /// `hf_scds[12]`.
    fn smoke_hf_vsdb_frl_rates() -> TestResult {
        let edid = cta_edid(&[&[
            (3 << 5) | 12,
            0xD8,
            0x5D,
            0xC4,
            1,
            120,
            0x80,
            0x60,
            0,
            0,
            0,
            0x80,
            0x30,
        ]]);
        let hf = parse_hf_vsdb(&edid);
        if hf.max_frl_gbps != 48 || hf.dsc_max_frl_gbps != 24 {
            return TestResult::Fail("the HF-VSDB must carry 48G FRL and 24G DSC FRL");
        }
        let no_dsc = cta_edid(&[&[
            (3 << 5) | 12,
            0xD8,
            0x5D,
            0xC4,
            1,
            120,
            0x80,
            0x30,
            0,
            0,
            0,
            0,
            0x30,
        ]]);
        let hf = parse_hf_vsdb(&no_dsc);
        if hf.max_frl_gbps != 24 || hf.dsc_max_frl_gbps != 0 {
            return TestResult::Fail("the DSC FRL rate needs DSC 1.2");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hf_vsdb_frl_rates);

    /// `intel_hdmi_compute_output_format`: 4:2:0-only VICs, the 4:2:0-also
    /// fallback when RGB fits at no depth (a TMDS limit or the ICL+ combo
    /// PLL hole), the halved clock, 4:2:0 deep colour, and no 4:2:0 on
    /// display 9 or a DVI sink.
    fn smoke_hdmi_output_format_selection() -> TestResult {
        use crate::intel_gpu_aux::SourceFamily;
        use crate::intel_gpu_gt::{Gen11Platform, Gen12Platform, Gen9Platform};
        let tgl = SourceFamily::Gen12(Gen12Platform::TigerLake);
        let icl = SourceFamily::Gen11(Gen11Platform::IceLake);
        let kbl = SourceFamily::Gen9 {
            platform: Gen9Platform::KabyLake,
            sku: crate::intel_gpu_gen9_ddi::SkuFamily::Ult,
        };
        let hdmi14 = Some(HdmiVsdb {
            dc_30: false,
            dc_36: false,
            max_tmds_khz: 340_000,
        });
        let none = HfVsdb::default();
        let scdc = HfVsdb {
            present: true,
            scdc_present: true,
            max_tmds_char_rate_khz: 600_000,
            ..HfVsdb::default()
        };
        let also = parse_ycbcr420(&cta_edid(&[&[(2 << 5) | 1, 97], &[(7 << 5) | 1, 0x0F]]));
        let only = parse_ycbcr420(&cta_edid(&[
            &[(7 << 5) | 2, 0x0E, 97],
            &[(3 << 5) | 7, 0xD8, 0x5D, 0xC4, 1, 120, 0x80, 0x02],
        ]));
        let p2160 = mode_2160p60();
        let cases = [
            // RGB 594 MHz does not fit a 340 MHz sink; 4:2:0 at 297 does.
            (
                tgl,
                hdmi14,
                &none,
                &also,
                (SinkFormat::Ycbcr420, 8, 297_000),
            ),
            // An SCDC sink takes RGB at 594 MHz.
            (tgl, hdmi14, &scdc, &also, (SinkFormat::Rgb, 8, 594_000)),
            // 4:2:0-only goes out as 4:2:0, at 12 bpc with DC_36 for 4:2:0.
            (
                tgl,
                hdmi14,
                &scdc,
                &only,
                (SinkFormat::Ycbcr420, 12, 445_500),
            ),
            // Display 9 never drives 4:2:0: RGB, which then cannot fit.
            (kbl, hdmi14, &none, &also, (SinkFormat::Rgb, 8, 594_000)),
            // A DVI sink has no 4:2:0.
            (tgl, None, &none, &also, (SinkFormat::Rgb, 8, 594_000)),
        ];
        for (family, vsdb, hf, y420, want) in cases {
            if compute_output(family, Ddi::B, &p2160, vsdb, hf, y420) != want {
                return TestResult::Fail("the sink format must follow compute_output_format");
            }
        }
        // ICL combo DDI B cannot make 500-533.2 MHz: a 525 MHz RGB mode
        // falls back to 4:2:0 at 262.5 MHz; Type-C DDI C's hole ends at
        // 532.8 MHz, so 533 MHz fits there and not on the combo port.
        let mut hole = p2160;
        hole.pixel_clock_khz = 525_000;
        let vic97 = Ycbcr420Caps {
            also: also.also,
            ..Ycbcr420Caps::default()
        };
        if vic_for_mode(&hole) != 0
            || compute_clock(
                icl,
                Some(Ddi::B),
                525_000,
                hdmi14,
                &scdc,
                &vic97,
                SinkFormat::Rgb,
            )
            .is_some()
            || compute_clock(
                icl,
                Some(Ddi::B),
                533_000,
                hdmi14,
                &scdc,
                &vic97,
                SinkFormat::Rgb,
            )
            .is_some()
            || compute_clock(
                icl,
                Some(Ddi::C),
                533_000,
                hdmi14,
                &scdc,
                &vic97,
                SinkFormat::Rgb,
            ) != Some((8, 533_000))
            || compute_clock(
                icl,
                Some(Ddi::B),
                525_000,
                hdmi14,
                &none,
                &vic97,
                SinkFormat::Ycbcr420,
            ) != Some((8, 262_500))
        {
            return TestResult::Fail("the ICL+ PLL holes refuse their clocks per PHY");
        }
        if tmds_clock_for(594_001, 10, SinkFormat::Ycbcr420) != 371_250 {
            return TestResult::Fail("4:2:0 halves the pixel clock before the bpc scaling");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_output_format_selection
    );

    /// A 4:2:0 connect on Tiger Lake: the TMDS PLL at half the pixel clock
    /// (the same WRPLL as a 297 MHz RGB stream), the 1:1 pipe scaler, the
    /// BT.709 output CSC, the `PIPE_MISC` encoding and AVI Y420; disconnect
    /// clears the scaler, CSC enable and encoding.
    fn smoke_hdmi_ycbcr420_connect() -> TestResult {
        use crate::intel_gpu_pipes::Pipe;
        use crate::intel_gpu_xelpg_scaler::{calc_phase, ps_ctrl, ps_hphase, ps_win_sz};
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Absent);
        let rgb = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid.clone()));
        let Ok(mut probe) = probe_sink(&rgb, Ddi::B, &Gen12DdcOverrides::NONE) else {
            return TestResult::Fail("probe");
        };
        // The RGB reference: a 297 MHz TMDS stream.
        probe.mode = mode_2160p60();
        probe.mode.pixel_clock_khz = 297_000;
        probe.tmds_clock_khz = 297_000;
        if activate(&rgb, &probe, &test_fb(16384)).is_err() {
            return TestResult::Fail("the RGB reference must activate");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        probe.mode = mode_2160p60();
        probe.format = SinkFormat::Ycbcr420;
        let conn = match activate(&mmio, &probe, &test_fb(16384)) {
            Ok(conn) => conn,
            Err(_) => return TestResult::Fail("the 4:2:0 connect must activate"),
        };
        if conn.format != SinkFormat::Ycbcr420
            || mmio.writes_to(DPLL_CFGCR0_DPLL1) != rgb.writes_to(DPLL_CFGCR0_DPLL1)
            || mmio.writes_to(dpll_cfgcr1(DPLL_CFGCR0_DPLL1))
                != rgb.writes_to(dpll_cfgcr1(DPLL_CFGCR0_DPLL1))
        {
            return TestResult::Fail("4:2:0 runs the TMDS PLL at half the pixel clock");
        }
        if mmio.writes_to(ps_ctrl(Pipe::A, 0)) != alloc::vec![1 << 31]
            || mmio.writes_to(ps_win_sz(Pipe::A, 0)) != alloc::vec![(3840 << 16) | 2160]
            || mmio.writes_to(ps_hphase(Pipe::A, 0)) != alloc::vec![u32::from(calc_phase(0x10000))]
        {
            return TestResult::Fail("scaler 0 must run 1:1 over the whole mode");
        }
        let csc = [
            (0x49050, 0x1e08_9cc0),
            (0x49054, 0xb528_0000),
            (0x49058, 0x2ba8_09d8),
            (0x4905c, 0x37e8_0000),
            (0x49060, 0xbce8_9ad8),
            (0x49064, 0x1e08_0000),
            (0x49068, 0),
            (0x49074, 0x800),
            (0x49078, 0x100),
            (0x4907c, 0x800),
        ];
        if csc
            .iter()
            .any(|&(r, v)| mmio.writes_to(r) != alloc::vec![v])
            || mmio
                .writes_to(0x49028)
                .last()
                .is_none_or(|v| v & (1 << 30) == 0)
        {
            return TestResult::Fail("the output CSC must carry the BT.709 RGB->YCbCr matrix");
        }
        let misc = mmio.writes_to(Pipe::A.base() + 0x30);
        if misc.last().is_none_or(|v| v & 0x0C00_0800 != 0x0C00_0800) {
            return TestResult::Fail("PIPE_MISC must select YUV 4:2:0 full blend");
        }
        let avi = mmio.writes_to(Transcoder::A.base() + VIDEO_DIP_AVI_DATA_OFFSET + 4);
        if avi.last().is_none_or(|v| (v >> 8) & 0xFF != 0x70) {
            return TestResult::Fail("AVI DB1 must carry Y420");
        }
        if !disconnect(&mmio, &conn) {
            return TestResult::Fail("the 4:2:0 disconnect must stop");
        }
        if mmio.writes_to(ps_ctrl(Pipe::A, 0)).last() != Some(&0)
            || mmio
                .writes_to(0x49028)
                .last()
                .is_none_or(|v| v & (1 << 30) != 0)
            || mmio
                .writes_to(Pipe::A.base() + 0x30)
                .last()
                .is_none_or(|v| v & 0x0C00_0800 != 0)
        {
            return TestResult::Fail("disconnect must clear the scaler, CSC and encoding");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_ycbcr420_connect);

    /// An HDMI route on a claimed pipe: the modeset, infoframes and
    /// teardown run on that pipe's transcoder, and Transcoder A (the
    /// panel's) is never touched.
    fn smoke_hdmi_on_claimed_pipe() -> TestResult {
        use crate::intel_gpu_pipes::Pipe;
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Absent);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let Ok(probe) = probe_sink(&mmio, Ddi::B, &Gen12DdcOverrides::NONE) else {
            return TestResult::Fail("probe");
        };
        let conn = match activate_on_pipe(&mmio, &probe, &test_fb(8192), Pipe::B, None) {
            Ok(conn) => conn,
            Err(_) => return TestResult::Fail("HDMI must light on Pipe B"),
        };
        let func_b = Transcoder::B.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        let func_a = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        if conn.pipe != Pipe::B
            || mmio.writes_to(func_b) != alloc::vec![0x9000_0006]
            || !mmio.writes_to(func_a).is_empty()
        {
            return TestResult::Fail("Transcoder B must bind DDI B; Transcoder A stays untouched");
        }
        let avi_b = Transcoder::B.base() + VIDEO_DIP_AVI_DATA_OFFSET;
        let avi_a = Transcoder::A.base() + VIDEO_DIP_AVI_DATA_OFFSET;
        if mmio.writes_to(avi_b).is_empty() || !mmio.writes_to(avi_a).is_empty() {
            return TestResult::Fail("the AVI infoframe must go out on Transcoder B");
        }
        if !disconnect(&mmio, &conn) {
            return TestResult::Fail("the Pipe B route must stop");
        }
        if mmio
            .writes_to(Transcoder::B.base() + VIDEO_DIP_CTL_OFFSET)
            .last()
            .is_none_or(|v| v & VIDEO_DIP_ENABLE_AVI != 0)
            || !mmio
                .writes_to(Transcoder::A.base() + VIDEO_DIP_CTL_OFFSET)
                .is_empty()
        {
            return TestResult::Fail("disconnect must stop Transcoder B's infoframes only");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_on_claimed_pipe);

    fn smoke_hdmi_infoframe_packing() -> TestResult {
        // AVI for 1080p60 (VIC 16), pinned byte-for-byte
        // against the CTA-861 layout worked by hand:
        // DB1 = 0x10 (active aspect present), DB2 = 0xA8
        // (ITU-709 | 16:9 | same-as-picture), DB3 = 0x08
        // (full range), DB4 = 16, checksum 0x9F.
        let avi = pack_avi_infoframe(&mode_1080p());
        let want: [u8; 17] = [
            0x82, 0x02, 0x0D, 0x9F, 0x10, 0xA8, 0x08, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        if avi != want {
            return TestResult::Fail("AVI infoframe bytes must match the spec layout");
        }
        if avi.iter().map(|&b| b as u32).sum::<u32>() % 256 != 0 {
            return TestResult::Fail("AVI frame must sum to 0 mod 256");
        }
        // 4K60: VIC 97, checksum 0x4E.
        let mode4k = mode_2160p60();
        let avi4k = pack_avi_infoframe(&mode4k);
        if avi4k[7] != 97 || avi4k[3] != 0x4E {
            return TestResult::Fail("4K60 AVI must carry VIC 97 + its checksum");
        }
        // Audio infoframes, byte-for-byte: stereo (CC=1,
        // CA=0x00, checksum 0x70) and 5.1 (CC=5, CA=0x0B,
        // checksum 0x61).
        let a2 = pack_audio_infoframe(2);
        if a2 != [0x84, 0x01, 0x0A, 0x70, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
            return TestResult::Fail("stereo audio infoframe bytes mismatch");
        }
        let a6 = pack_audio_infoframe(6);
        if a6 != [0x84, 0x01, 0x0A, 0x61, 0x05, 0, 0, 0x0B, 0, 0, 0, 0, 0, 0] {
            return TestResult::Fail("5.1 audio infoframe bytes mismatch");
        }
        if a6.iter().map(|&b| b as u32).sum::<u32>() % 256 != 0 {
            return TestResult::Fail("audio frame must sum to 0 mod 256");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_infoframe_packing);

    fn smoke_hf_vsdb_parse() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::Scdc);
        let hf = parse_hf_vsdb(&edid);
        if !hf.present || !hf.scdc_present {
            return TestResult::Fail("HF-VSDB with SCDC must parse past the decoy VSDB");
        }
        if hf.max_tmds_char_rate_khz != 590_000 {
            return TestResult::Fail("max TMDS rate must decode 118 x 5 MHz");
        }
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::NoScdc);
        let hf = parse_hf_vsdb(&edid);
        if !hf.present || hf.scdc_present {
            return TestResult::Fail("HF-VSDB without the SCDC bit must report no SCDC");
        }
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Absent);
        if parse_hf_vsdb(&edid).present {
            return TestResult::Fail("no HF-VSDB must report absent");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hf_vsdb_parse);

    fn smoke_hdmi_1080p_connect_no_scdc_traffic() -> TestResult {
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let conn = match connect(&mmio, Ddi::B, &Gen12DdcOverrides::NONE, &test_fb(8192)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("1080p connect over the sink model must succeed"),
        };
        if conn.mode.h_active != 1920 || conn.mode.v_active != 1080 || conn.scrambling {
            return TestResult::Fail("1080p connection must carry the EDID mode, unscrambled");
        }
        // drm_do_probe_ddc_edid writes the block offset before every
        // block read; gmbus_xfer runs offset + read as one INDEX
        // transfer: the codec's 128-byte read program plus
        // CYCLE_INDEX with offset 0 in GMBUS1[15:8], byte-for-byte
        // SW_RDY|INDEX|WAIT|count 128|slave 0x50|read. (The older
        // engine sent the bare codec program with no offset.)
        let sink = mmio.sink.borrow();
        let codec = build_edid_read(PinPair::Pin2Bxt, 128).map(|p| p.gmbus1);
        let first = sink.data_programs().first().copied();
        if codec != Ok(0x4280_00A1)
            || first != Some(0x4280_00A1 | GMBUS1_CYCLE_INDEX)
            || first != Some(0x4680_00A1)
        {
            return TestResult::Fail("first EDID program must index offset 0");
        }
        // Each transfer ends with its own STOP program before the next
        // select (the older engine never issued STOP and waited for an
        // idle bus that cannot come).
        let stop = GMBUS1_SW_RDY | GMBUS1_CYCLE_STOP;
        if sink.programs.iter().filter(|p| **p == stop).count() != 2 {
            return TestResult::Fail("each EDID block transfer must end with a STOP");
        }
        // Tiger Lake DDI B's DDC is GMBUS_PIN_2_BXT ("dpb" in
        // gmbus_pins_icp), selected at 100 kHz (Linux b90c984d).
        if mmio.writes_to(GMBUS0).first() != Some(&(GMBUS0_RATE_100KHZ | 2)) {
            return TestResult::Fail("DDI B DDC must select GMBUS pin 2 (dpb)");
        }
        // A <=340 Mcsc mode must not touch SCDC at all.
        if sink.slaves_touched().contains(&DDC_SLAVE_SCDC) || !sink.scdc_applied.is_empty() {
            return TestResult::Fail("HDMI 1.4-rate mode must not touch SCDC");
        }
        // The extension read was byte-indexed at 128 through
        // GMBUS1[15:8]; GMBUS5 (2-byte indices only) is untouched.
        if sink.data_programs().get(1) != Some(&0x4680_80A1) || !sink.gmbus5_log.is_empty() {
            return TestResult::Fail("extension EDID read must index 128 in GMBUS1");
        }
        drop(sink);
        // TRANS_DDI_FUNC_CTL: HDMI binding for DDI B, no
        // scrambling / high-rate bits at 148.5 Mcsc.
        let func_ctl_off = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        if mmio.writes_to(func_ctl_off) != alloc::vec![0x9000_0006] {
            return TestResult::Fail("TRANS_DDI_FUNC_CTL must be the plain HDMI binding");
        }
        // No M/N programming and no AUX traffic on an HDMI
        // modeset.
        use crate::intel_gpu_pipes::PIPE_DATA_M1_OFFSET;
        if !mmio
            .writes_to(Transcoder::A.base() + PIPE_DATA_M1_OFFSET)
            .is_empty()
        {
            return TestResult::Fail("HDMI modeset must not program DP M/N");
        }
        // The WRPLL rows for 148.5 MHz in the fixture's
        // DSSM-strapped 19.2 MHz family (see HdmiSinkMmio::new):
        // CFGCR0 = int 0x1D0 | frac 0x0800, CFGCR1 = 0xE87 —
        // the rows `smoke_hdmi_wrpll_rows` pins for this family
        // (the 0x173/0x2000 pair this assertion previously
        // carried is the 24 MHz family's row).
        if mmio.writes_to(DPLL_CFGCR0_DPLL1) != alloc::vec![0x0020_01D0] {
            return TestResult::Fail("CFGCR0 must carry the 148.5 MHz WRPLL solution");
        }
        if mmio.writes_to(dpll_cfgcr1(DPLL_CFGCR0_DPLL1)) != alloc::vec![0xE87] {
            return TestResult::Fail("CFGCR1 must carry the 148.5 MHz WRPLL dividers");
        }
        // DIP: AVI bank dwords pinned (hole at byte 3), CTL
        // written disable-then-enable.
        let dip_data = Transcoder::A.base() + VIDEO_DIP_AVI_DATA_OFFSET;
        let dwords = mmio.writes_to(dip_data);
        if dwords.first() != Some(&0x000D_0282) {
            return TestResult::Fail("DIP dword 0 must be the AVI header with the ECC hole");
        }
        let dwords1 = mmio.writes_to(dip_data + 4);
        if dwords1.first() != Some(&0x08A8_109F) {
            return TestResult::Fail("DIP dword 1 must carry checksum + DB1..DB3");
        }
        // The AVI write clears then sets its enable; the GCP every HDMI
        // sink gets then adds its own enable, keeping AVI's.
        let ctl_writes = mmio.writes_to(Transcoder::A.base() + VIDEO_DIP_CTL_OFFSET);
        if ctl_writes.len() != 3
            || ctl_writes[0] & VIDEO_DIP_ENABLE_AVI != 0
            || ctl_writes[1] & VIDEO_DIP_ENABLE_AVI == 0
            || ctl_writes[2] & (VIDEO_DIP_ENABLE_AVI | VIDEO_DIP_ENABLE_GCP)
                != VIDEO_DIP_ENABLE_AVI | VIDEO_DIP_ENABLE_GCP
        {
            return TestResult::Fail("DIP CTL must clear, then set, the AVI enable, then add GCP");
        }
        // Audio: ELD published with the HDMI connection type
        // (byte 5 bits[3:2] == 0) and the fixture's LPCM SAD.
        if !conn.audio_published {
            return TestResult::Fail("1080p sink with SADs must publish audio");
        }
        match narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B)) {
            Some(p) => {
                if p.eld_bytes()[5] & 0x0C != 0 {
                    return TestResult::Fail("ELD connection type must be HDMI (0)");
                }
                if p.lpcm_max_channels != 2 || p.sad_count != 2 {
                    return TestResult::Fail("ELD must carry the fixture SADs");
                }
            }
            None => return TestResult::Fail("connect must publish the ELD"),
        }
        if conn.audio_infoframe != Some(pack_audio_infoframe(2)) {
            return TestResult::Fail("connection must carry the stereo audio infoframe");
        }
        // AUD_CFG carries the 148.5 MHz pixel-clock code (9)
        // latched with N_PROG_ENABLE.
        let cfg_writes = mmio.writes_to(intel_gpu_audio::aud_cfg_off(Transcoder::A));
        if !cfg_writes.contains(&((9 << 16) | intel_gpu_audio::AUD_CONFIG_N_PROG_ENABLE)) {
            return TestResult::Fail("AUD_CFG must carry pixel-clock 9 + PROG_ENABLE");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_1080p_connect_no_scdc_traffic
    );

    fn smoke_hdmi_uy_part_keeps_icl_hdmi_table() -> TestResult {
        // Linux `tgl_get_combo_buf_trans` returns the shared
        // ICL HDMI table for HDMI before any UY branch, so a
        // Tiger Lake UY part must program exactly the same HDMI
        // levels as a standard part: the ICL HDMI default entry
        // (index 6: swing 0x6, N-scalar 0x7F, cursor 0x35,
        // post-cursor-1 0x0A) on PHY_B. The flag still flows
        // through — `activate` builds its `Modeset` over the
        // window and `Modeset::for_pipe` derives `tgl_uy` from
        // it — it just must not change the HDMI table.
        // PHY_B (DDI B, 0x6C000) TX DW2/DW4/DW7 lane-0 offsets.
        const DW2_LN0: u64 = 0x6C888;
        const DW4_LN0: u64 = 0x6C890;
        const DW7_LN0: u64 = 0x6C89C;
        fn run(uy: bool) -> Option<(u32, u32, u32)> {
            let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
            let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
            *mmio.tgl_uy.borrow_mut() = uy;
            let conn = connect(&mmio, Ddi::B, &Gen12DdcOverrides::NONE, &test_fb(8192)).ok()?;
            if conn.scrambling {
                return None;
            }
            let out = (
                mmio.writes_to(DW2_LN0).last().copied()?,
                mmio.writes_to(DW4_LN0).last().copied()?,
                mmio.writes_to(DW7_LN0).last().copied()?,
            );
            clear_display_audio(sink_id_for(Ddi::B));
            Some(out)
        }
        for uy in [true, false] {
            match run(uy) {
                Some((dw2, dw4, dw7)) => {
                    if dw2 != 0x3098 || dw4 != 0xA035 || dw7 != 0x7F00_0000 {
                        return TestResult::Fail(
                            "HDMI must program the ICL HDMI default entry either way",
                        );
                    }
                }
                None => {
                    return TestResult::Fail("HDMI 1080p connect must succeed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_uy_part_keeps_icl_hdmi_table
    );

    fn smoke_hdmi_4k60_scdc_scrambling() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::Scdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let probe = match probe_sink(&mmio, Ddi::B, &Gen12DdcOverrides::NONE) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("4K60 probe must succeed"),
        };
        if !probe.scrambling_required || !probe.hf_vsdb.scdc_present {
            return TestResult::Fail("594 MHz against an SCDC sink must require scrambling");
        }
        let conn = match activate(&mmio, &probe, &test_fb(16384)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("4K60 activate must succeed"),
        };
        if !conn.scrambling {
            return TestResult::Fail("4K60 connection must record scrambling");
        }
        // SCDC (intel_hdmi_handle_sink_scrambling): TMDS_CONFIG
        // read-modify-written twice — the 1/40 ratio
        // (drm_scdc_set_high_tmds_clock_ratio), then scrambling
        // (drm_scdc_set_scrambling) — before the modeset bound the
        // transcoder. (The older engine wrote 0x03 in one step.)
        let sink = mmio.sink.borrow();
        if sink.scdc_applied != alloc::vec![(SCDC_TMDS_CONFIG, 0x02), (SCDC_TMDS_CONFIG, 0x03)] {
            return TestResult::Fail("SCDC must set the ratio, then scrambling");
        }
        drop(sink);
        // SCRAMBLER_STATUS is read only once the stream runs: after
        // TRANS_DDI_FUNC_CTL and the DDI buffer enable.
        let status_read = mmio.writes.borrow().iter().position(|(o, v)| {
            *o == GMBUS1
                && ((*v >> 1) & 0x7F) == DDC_SLAVE_SCDC as u32
                && *v & 1 != 0
                && (*v >> 8) & 0xFF == SCDC_SCRAMBLER_STATUS as u32
        });
        let buf_on = mmio.writes.borrow().iter().position(|(o, v)| {
            *o == Ddi::B.base() + DDI_BUF_CTL_OFFSET
                && *v & crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE != 0
        });
        match (buf_on, status_read) {
            (Some(b), Some(st)) if b < st => {}
            _ => return TestResult::Fail("scrambler status must be read after the stream starts"),
        }
        if conn.scrambler_status != Some(true) {
            return TestResult::Fail("a locking sink must report scrambling after the stream runs");
        }
        let scdc_pos = mmio
            .writes
            .borrow()
            .iter()
            .position(|(o, v)| *o == GMBUS1 && ((*v >> 1) & 0x7F) == DDC_SLAVE_SCDC as u32);
        let func_pos = mmio.write_position(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET);
        match (scdc_pos, func_pos) {
            (Some(s), Some(f)) if s < f => {}
            _ => return TestResult::Fail("SCDC must be configured before TRANS_DDI_FUNC_CTL"),
        }
        // Func ctl carries both HDMI high-rate bits.
        let func_ctl_off = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        if mmio.writes_to(func_ctl_off) != alloc::vec![0x9000_0017] {
            return TestResult::Fail("TRANS_DDI_FUNC_CTL must set scrambling + high char rate");
        }
        // WRPLL for 594 MHz: CFGCR0 int 0x1D0 frac 0x0800,
        // CFGCR1 0x44B.
        if mmio.writes_to(DPLL_CFGCR0_DPLL1) != alloc::vec![0x0020_01D0] {
            return TestResult::Fail("CFGCR0 must carry the 594 MHz WRPLL solution");
        }
        if mmio.writes_to(dpll_cfgcr1(DPLL_CFGCR0_DPLL1)) != alloc::vec![0x44B] {
            return TestResult::Fail("CFGCR1 must carry the 594 MHz WRPLL dividers");
        }
        clear_display_audio(sink_id_for(Ddi::B));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_4k60_scdc_scrambling
    );

    fn smoke_hdmi_4k60_without_scdc_refused() -> TestResult {
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::NoScdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        match connect(&mmio, Ddi::B, &Gen12DdcOverrides::NONE, &test_fb(16384)) {
            Err(HdmiError::ScramblingUnsupported) => {}
            _ => return TestResult::Fail(">340 Mcsc without SCDC must be refused"),
        }
        // Nothing was programmed: no SCDC traffic, no func
        // ctl, no DIP.
        let sink = mmio.sink.borrow();
        if sink.slaves_touched().contains(&DDC_SLAVE_SCDC) {
            return TestResult::Fail("a refused mode must not touch SCDC");
        }
        drop(sink);
        if !mmio
            .writes_to(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET)
            .is_empty()
        {
            return TestResult::Fail("a refused mode must not reach the modeset");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_4k60_without_scdc_refused
    );

    fn smoke_hdmi_scdc_status_sampled_after_stream() -> TestResult {
        // Corrected from smoke_hdmi_scdc_verify_failure: the older
        // engine read SCRAMBLER_STATUS right after the TMDS_CONFIG write,
        // before any scrambled data flowed, and failed the connect. Linux
        // (intel_hdmi_handle_sink_scrambling) never reads it at enable;
        // the status is sampled once the stream runs and does not gate
        // the connect.
        let edid = fixture_edid_hdmi(594_000, 3840, 560, 2160, 90, HfFixture::Scdc);
        let mut sink = GmbusSink::new(edid);
        sink.ignore_scrambling = true; // never reports status
        let mmio = HdmiSinkMmio::new(Ddi::B, sink);
        let conn = match connect(&mmio, Ddi::B, &Gen12DdcOverrides::NONE, &test_fb(16384)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("an unlocked scrambler must not fail the connect"),
        };
        if !conn.scrambling || conn.scrambler_status != Some(false) {
            return TestResult::Fail("the post-stream status must report the sink unlocked");
        }
        let sink = mmio.sink.borrow();
        if sink.scdc_applied != alloc::vec![(SCDC_TMDS_CONFIG, 0x02), (SCDC_TMDS_CONFIG, 0x03)] {
            return TestResult::Fail("the config writes must have been made");
        }
        // TMDS_CONFIG is read for each read-modify-write; STATUS last.
        if sink.scdc_reads != alloc::vec![SCDC_TMDS_CONFIG, SCDC_TMDS_CONFIG, SCDC_SCRAMBLER_STATUS]
        {
            return TestResult::Fail("SCDC reads must be config, config, then status");
        }
        drop(sink);
        // Disconnect resets the sink to 1/10 and no scrambling before the
        // pipeline comes down (intel_ddi_disable_hdmi).
        let _ = disconnect(&mmio, &conn);
        clear_display_audio(sink_id_for(Ddi::B));
        let applied = mmio.sink.borrow().scdc_applied.clone();
        if applied.len() != 4
            || applied[2..] != [(SCDC_TMDS_CONFIG, 0x01), (SCDC_TMDS_CONFIG, 0x00)]
        {
            return TestResult::Fail("disconnect must reset the ratio, then scrambling");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_scdc_status_sampled_after_stream
    );

    fn smoke_hdmi_ddc_uses_index_cycle_and_gmbus5_enable() -> TestResult {
        // The older engine wrote the byte index to GMBUS5 without
        // GMBUS_2BYTE_INDEX_EN, so indexed reads were not indexed.
        // intel_gmbus.c::gmbus_index_xfer: a 1-byte index rides GMBUS1
        // (CYCLE_INDEX, [15:8]); a 2-byte index sets 2BYTE_INDEX_EN.
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(alloc::vec![0u8; 512]));
        mmio.sink.borrow_mut().scdc[0x21] = 0x01;
        match scdc_read(&mmio, PinPair::Pin2Bxt, SCDC_SCRAMBLER_STATUS) {
            Ok(0x01) => {}
            _ => return TestResult::Fail("SCDC register read must be indexed"),
        }
        if mmio.sink.borrow().data_programs() != alloc::vec![0x4601_21A9]
            || !mmio.sink.borrow().gmbus5_log.is_empty()
        {
            return TestResult::Fail("1-byte index must be CYCLE_INDEX|CYCLE_WAIT in GMBUS1");
        }
        let mut edid = alloc::vec![0u8; 512];
        edid[0x180] = 0x5A;
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let mut out = [0u8; 1];
        if crate::intel_gpu_gmbus::gmbus_read(&mmio, PinPair::Pin2Bxt, 0x50, 0x0180, &mut out)
            .is_err()
            || out != [0x5A]
        {
            return TestResult::Fail("2-byte index read must reach byte 0x180");
        }
        if mmio.sink.borrow().gmbus5_log != alloc::vec![GMBUS5_2BYTE_INDEX_EN | 0x0180, 0] {
            return TestResult::Fail("GMBUS5 must carry 2BYTE_INDEX_EN and be cleared");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_ddc_uses_index_cycle_and_gmbus5_enable
    );

    fn smoke_hdmi_sink_nack() -> TestResult {
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        let mut sink = GmbusSink::new(edid);
        sink.nack_all = true;
        let mmio = HdmiSinkMmio::new(Ddi::B, sink);
        match probe_sink(&mmio, Ddi::B, &Gen12DdcOverrides::NONE) {
            Err(HdmiError::Ddc(DdcError::SlaveNack)) => TestResult::Pass,
            _ => TestResult::Fail("a NACKing sink must surface SlaveNack"),
        }
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_sink_nack);

    fn smoke_hdmi_edid_segment_pointer() -> TestResult {
        // A 4-block EDID (base + CTA + two filler extensions):
        // blocks past 256 bytes ride the E-DDC segment
        // pointer.
        let mut edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        edid[126] = 3;
        edid.resize(512, 0);
        // Byte 126 lives in block 0, so its checksum moves
        // with the extension count; blocks 2/3 are new.
        for block in [0usize, 2, 3] {
            let start = block * 128;
            if block >= 2 {
                edid[start] = 0x00; // filler extension tag
                edid[start + 1] = block as u8;
            }
            let sum: u32 = edid[start..start + 127].iter().map(|&b| b as u32).sum();
            edid[start + 127] = ((256 - (sum % 256)) % 256) as u8;
        }
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid.clone()));
        let probe = match probe_sink(&mmio, Ddi::B, &Gen12DdcOverrides::NONE) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("4-block EDID probe must succeed"),
        };
        if probe.edid_len != 512 || probe.edid[..512] != edid[..] {
            return TestResult::Fail("all four EDID blocks must arrive verbatim");
        }
        // drm_do_probe_ddc_edid: segment write, offset write and read in
        // one transfer — the segment program is followed by the EDID
        // program with no STOP in between, and STOP resets the pointer.
        let sink = mmio.sink.borrow();
        let mut chained = 0;
        for (i, p) in sink.programs.iter().enumerate() {
            if *p & GMBUS1_SW_RDY != 0 && (p >> 1) & 0x7F == 0x30 {
                match sink.programs.get(i + 1) {
                    Some(next) if next & GMBUS1_CYCLE_STOP == 0 && (next >> 1) & 0x7F == 0x50 => {
                        chained += 1
                    }
                    _ => return TestResult::Fail("segment write must chain into the read"),
                }
            }
        }
        if chained != 2 || sink.segment != 0 {
            return TestResult::Fail("blocks 2 and 3 each chain a segment write; STOP resets it");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_edid_segment_pointer
    );

    fn smoke_hdmi_disconnect_tears_down() -> TestResult {
        let edid = fixture_edid_hdmi(148_500, 1920, 280, 1080, 45, HfFixture::Scdc);
        let mmio = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(edid));
        let conn = match connect(&mmio, Ddi::B, &Gen12DdcOverrides::NONE, &test_fb(8192)) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("connect must succeed"),
        };
        disconnect(&mmio, &conn);
        if narf_drivers_sound::display_audio::current_display_audio(sink_id_for(Ddi::B)).is_some() {
            return TestResult::Fail("disconnect must clear the ELD");
        }
        // DIP disabled: the last DIP CTL write has AVI clear.
        let ctl_writes = mmio.writes_to(Transcoder::A.base() + VIDEO_DIP_CTL_OFFSET);
        let last = ctl_writes[ctl_writes.len() - 1];
        if last & VIDEO_DIP_ENABLE_AVI != 0 {
            return TestResult::Fail("disconnect must disable the AVI DIP");
        }
        // The HDMI audio disable latched without N_VALUE_INDEX.
        let cfg_writes = mmio.writes_to(intel_gpu_audio::aud_cfg_off(Transcoder::A));
        let last = cfg_writes[cfg_writes.len() - 1];
        if last & intel_gpu_audio::AUD_CONFIG_N_PROG_ENABLE == 0
            || last & intel_gpu_audio::AUD_CONFIG_N_VALUE_INDEX != 0
        {
            return TestResult::Fail("HDMI audio disable must latch PROG_ENABLE only");
        }
        // DDI buffer disabled last by the teardown.
        let buf_writes = mmio.writes_to(Ddi::B.base() + DDI_BUF_CTL_OFFSET);
        use crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE;
        let last = buf_writes[buf_writes.len() - 1];
        if last & DDI_BUF_CTL_ENABLE != 0 {
            return TestResult::Fail("teardown must clear DDI_BUF_CTL ENABLE last");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_disconnect_tears_down
    );

    fn smoke_hdmi_source_family_arb_slots_and_missing_foreign_metadata_refusal() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        // Alder Lake S has no DDI B (port mask A + TC1..TC4,
        // intel_display_device.c), so it has no DDC pin there
        // (intel_gpu_gmbus::gen12_ddc_pin) and its row runs on DDI A.
        let no_b = HdmiSinkMmio::new(Ddi::B, GmbusSink::new(alloc::vec![0u8; 128]));
        *no_b.family.borrow_mut() = Some(Gen12Platform::AlderLakeS);
        if !matches!(
            probe_sink(&no_b, Ddi::B, &Gen12DdcOverrides::NONE),
            Err(HdmiError::Ddc(DdcError::NoPinPair))
        ) || !no_b.writes.borrow().is_empty()
        {
            return TestResult::Fail("ADL-S DDI B must refuse without a DDC pin");
        }
        for (family, ddi, expected) in [
            (Gen12Platform::TigerLake, Ddi::B, 0x84000000),
            (Gen12Platform::AlderLakeS, Ddi::A, 0x84000000),
            (Gen12Platform::AlderLakeP, Ddi::B, 0x94000000),
            (Gen12Platform::AlderLakeN, Ddi::B, 0x94000000),
        ] {
            let mmio = HdmiSinkMmio::new(
                ddi,
                GmbusSink::new(fixture_edid_hdmi(
                    148_500,
                    1920,
                    280,
                    1080,
                    45,
                    HfFixture::Scdc,
                )),
            );
            *mmio.family.borrow_mut() = Some(family);
            let conn = connect(&mmio, ddi, &Gen12DdcOverrides::NONE, &test_fb(8192)).unwrap();
            assert_eq!(
                conn.family,
                crate::intel_gpu_aux::SourceFamily::Gen12(family)
            );
            assert_eq!(mmio.writes_to(0x70180).last(), Some(&expected));
            let before = mmio.writes.borrow().len();
            *mmio.family.borrow_mut() = Some(if family == Gen12Platform::AlderLakeP {
                Gen12Platform::AlderLakeN
            } else {
                Gen12Platform::AlderLakeP
            });
            assert!(!disconnect(&mmio, &conn));
            *mmio.family.borrow_mut() = None;
            assert!(!disconnect(&mmio, &conn));
            assert_eq!(mmio.writes.borrow().len(), before);
            *mmio.family.borrow_mut() = Some(family);
            assert!(disconnect(&mmio, &conn));
            assert_eq!(
                mmio.writes_to(0x70180).last().unwrap() & 0x70000000,
                expected & 0x70000000
            );
        }
        let mmio = HdmiSinkMmio::new(
            Ddi::B,
            GmbusSink::new(fixture_edid_hdmi(
                594_000,
                3840,
                560,
                2160,
                90,
                HfFixture::Scdc,
            )),
        );
        *mmio.family.borrow_mut() = None;
        assert!(matches!(
            connect(&mmio, Ddi::B, &Gen12DdcOverrides::NONE, &test_fb(15360)),
            Err(HdmiError::Modeset(ModesetError::UnsupportedGeneration))
        ));
        assert!(mmio.writes.borrow().is_empty());
        assert!(mmio.sink.borrow().programs.is_empty());
        assert!(mmio.sink.borrow().scdc_applied.is_empty());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_source_family_arb_slots_and_missing_foreign_metadata_refusal
    );

    /// A mapping that reports one Gen11 or Gen9 identity and nothing else.
    struct Identity {
        gen11: Option<crate::intel_gpu_gt::Gen11Platform>,
        gen9: Option<(
            crate::intel_gpu_gt::Gen9Platform,
            crate::intel_gpu_gen9_ddi::SkuFamily,
        )>,
    }
    impl MmioWindow for Identity {
        fn gen11_display_platform(&self) -> Option<crate::intel_gpu_gt::Gen11Platform> {
            self.gen11
        }
        fn gen9_display_platform(
            &self,
        ) -> Option<(
            crate::intel_gpu_gt::Gen9Platform,
            crate::intel_gpu_gen9_ddi::SkuFamily,
        )> {
            self.gen9
        }
        fn read32(&self, _: u64) -> u32 {
            0
        }
        fn write32(&self, _: u64, _: u32) {}
    }

    /// Gen11 and Gen9 sources reach the session layer: `SourceFamily::of`
    /// reports them (Gen12 metadata first), the Ice Lake HDMI pin follows
    /// `icl_encoder_to_ddc_pin`, EHL/JSL C/D have no default, and Gen9 pins
    /// come from the observed PCH's table.
    fn smoke_hdmi_gen11_gen9_source_families() -> TestResult {
        use crate::intel_gpu_aux::SourceFamily;
        use crate::intel_gpu_gen9_ddi::SkuFamily;
        use crate::intel_gpu_gt::{Gen11Platform, Gen9Platform};
        let icl = Identity {
            gen11: Some(Gen11Platform::IceLake),
            gen9: None,
        };
        let kbl = Identity {
            gen11: None,
            gen9: Some((Gen9Platform::KabyLake, SkuFamily::Ult)),
        };
        let none = Identity {
            gen11: None,
            gen9: None,
        };
        if SourceFamily::of(&icl) != Some(SourceFamily::Gen11(Gen11Platform::IceLake))
            || SourceFamily::of(&kbl)
                != Some(SourceFamily::Gen9 {
                    platform: Gen9Platform::KabyLake,
                    sku: SkuFamily::Ult,
                })
            || SourceFamily::of(&none).is_some()
        {
            return TestResult::Fail("SourceFamily::of must report the mapping's identity");
        }
        let ddc = Gen12DdcOverrides::NONE;
        let gen11 = |p, ddi| ddc_pin(SourceFamily::Gen11(p), &ddc, None, ddi);
        if gen11(Gen11Platform::IceLake, Ddi::A) != Some(PinPair::Pin1Bxt)
            || gen11(Gen11Platform::IceLake, Ddi::D) != Some(PinPair::Pin10Tc2)
            || gen11(Gen11Platform::JasperLake, Ddi::B) != Some(PinPair::Pin2Bxt)
            || gen11(Gen11Platform::JasperLake, Ddi::C).is_some()
            || gen11(Gen11Platform::ElkhartLake, Ddi::D).is_some()
        {
            return TestResult::Fail("Gen11 DDC defaults must follow icl_encoder_to_ddc_pin");
        }
        let gen9 = SourceFamily::Gen9 {
            platform: Gen9Platform::Skylake,
            sku: SkuFamily::Desktop,
        };
        use crate::intel_gpu_gmbus::GmbusPinTable;
        if ddc_pin(gen9, &ddc, None, Ddi::B).is_some()
            || ddc_pin(gen9, &ddc, Some(GmbusPinTable::Spt), Ddi::B) != Some(PinPair::Pin5Mtp)
            || ddc_pin(gen9, &ddc, Some(GmbusPinTable::Cnp), Ddi::C) != Some(PinPair::Pin2Bxt)
        {
            return TestResult::Fail("a Gen9 pin comes from the observed PCH's pin table");
        }
        // rkl_encoder_to_ddc_pin: B is pin 2 with either PCH; TC1/TC2 (PHY
        // C/D) take the Type-C pins with TGP and pins 3/4 with CMP, and have
        // no default without the PCH. Their HDMI PLL hole is the combo one.
        let rkl = SourceFamily::Gen12(crate::intel_gpu_gt::Gen12Platform::RocketLake);
        if ddc_pin(rkl, &ddc, None, Ddi::B) != Some(PinPair::Pin2Bxt)
            || ddc_pin(rkl, &ddc, Some(GmbusPinTable::Icp), Ddi::D) != Some(PinPair::Pin9Tc1)
            || ddc_pin(rkl, &ddc, Some(GmbusPinTable::Icp), Ddi::E) != Some(PinPair::Pin10Tc2)
            || ddc_pin(rkl, &ddc, Some(GmbusPinTable::Cnp), Ddi::D) != Some(PinPair::Pin3Bxt)
            || ddc_pin(rkl, &ddc, Some(GmbusPinTable::Cnp), Ddi::E) != Some(PinPair::Pin4Cnp)
            || ddc_pin(rkl, &ddc, None, Ddi::D).is_some()
            || pll_holes(rkl, Some(Ddi::D)) != [Some((500_000, 533_200)), None]
        {
            return TestResult::Fail(
                "RKL TC1/TC2 DDC pins and PLL hole must follow rkl_encoder_to_ddc_pin",
            );
        }
        // Probing without a family still refuses before any access.
        if !matches!(
            probe_sink(&none, Ddi::B, &ddc),
            Err(HdmiError::Modeset(ModesetError::UnsupportedGeneration))
        ) {
            return TestResult::Fail("a mapping with no family must refuse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_gen11_gen9_source_families
    );

    /// Gen9 LP's `hdmi_port_clock_valid`: the DPLL ranges Broxton and
    /// Gemini Lake cannot generate are refused at their exclusive bounds;
    /// Gemini Lake reaches 594 MHz on an SCDC sink (scrambled), Broxton
    /// stops at 300 MHz, Skylake has no hole.
    fn smoke_hdmi_gen9_lp_pll_holes_and_scrambling() -> TestResult {
        use crate::intel_gpu_aux::SourceFamily;
        use crate::intel_gpu_gen9_ddi::SkuFamily;
        use crate::intel_gpu_gt::Gen9Platform;
        let gen9 = |platform| SourceFamily::Gen9 {
            platform,
            sku: SkuFamily::Ult,
        };
        let (bxt, glk, skl) = (
            gen9(Gen9Platform::Broxton),
            gen9(Gen9Platform::GeminiLake),
            gen9(Gen9Platform::Skylake),
        );
        let vsdb = Some(HdmiVsdb {
            max_tmds_khz: 340_000,
            ..HdmiVsdb::default()
        });
        let hf = HfVsdb {
            present: true,
            scdc_present: true,
            max_tmds_char_rate_khz: 600_000,
            ..HfVsdb::default()
        };
        let ok = |family, tmds| port_clock_valid(family, Some(Ddi::B), tmds, vsdb, &hf);
        for (family, tmds, want) in [
            (bxt, 223_333, true),
            (bxt, 223_334, false),
            (bxt, 239_999, false),
            (bxt, 240_000, true),
            (bxt, 300_000, true),
            (bxt, 300_001, false),
            (glk, 230_000, false),
            (glk, 446_666, true),
            (glk, 446_667, false),
            (glk, 479_999, false),
            (glk, 480_000, true),
            (glk, 594_000, true),
            (glk, 594_001, false),
            (skl, 230_000, true),
        ] {
            if ok(family, tmds) != want {
                return TestResult::Fail("Gen9 LP HDMI clock range");
            }
        }
        // Above 340 Mcsc only an SCDC sink is admitted.
        let no_scdc = HfVsdb {
            scdc_present: false,
            ..hf
        };
        if port_clock_valid(glk, Some(Ddi::B), 594_000, vsdb, &no_scdc) {
            return TestResult::Fail("594 MHz needs an SCDC sink");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_gen9_lp_pll_holes_and_scrambling
    );

    /// `is_hdmi_sink`: only the HDMI Licensing VSDB (00-0C-03) in a CTA
    /// extension makes a sink HDMI; an HF-VSDB alone, a base block alone
    /// or a non-CTA extension leave it DVI.
    fn smoke_hdmi_vsdb_decides_dvi() -> TestResult {
        let edid = |payload: &[u8], tag: u8| {
            let mut e = [0u8; 256];
            e[128] = tag;
            e[129] = 3;
            e[130] = (4 + 1 + payload.len()) as u8;
            e[132] = (3 << 5) | payload.len() as u8;
            e[133..133 + payload.len()].copy_from_slice(payload);
            e
        };
        let hdmi = edid(&[0x03, 0x0C, 0x00, 0x10, 0x00], 0x02);
        let hf_only = edid(&[0xD8, 0x5D, 0xC4, 0x01, 0x78], 0x02);
        let not_cta = edid(&[0x03, 0x0C, 0x00, 0x10, 0x00], 0x70);
        if !is_hdmi_sink(&hdmi)
            || is_hdmi_sink(&hf_only)
            || is_hdmi_sink(&not_cta)
            || is_hdmi_sink(&hdmi[..128])
        {
            return TestResult::Fail("only the HDMI VSDB makes an HDMI sink");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_hdmi", smoke_hdmi_vsdb_decides_dvi);

    /// `intel_hdmi_compute_bpc`: the deepest depth the source, the sink's
    /// DC flags and both TMDS limits allow, 8 bpc otherwise.
    fn smoke_hdmi_deep_colour_selection() -> TestResult {
        use crate::intel_gpu_aux::SourceFamily;
        use crate::intel_gpu_gen9_ddi::SkuFamily;
        use crate::intel_gpu_gt::{Gen11Platform, Gen12Platform, Gen9Platform};
        let tgl = SourceFamily::Gen12(Gen12Platform::TigerLake);
        let icl = SourceFamily::Gen11(Gen11Platform::IceLake);
        let skl = SourceFamily::Gen9 {
            platform: Gen9Platform::Skylake,
            sku: SkuFamily::Desktop,
        };
        let dc = |dc_30, dc_36, max| {
            Some(HdmiVsdb {
                dc_30,
                dc_36,
                max_tmds_khz: max,
            })
        };
        let none = HfVsdb::default();
        let scdc = HfVsdb {
            present: true,
            scdc_present: true,
            max_tmds_char_rate_khz: 600_000,
            ..HfVsdb::default()
        };
        for (family, clock, vsdb, hf, want, why) in [
            (
                tgl,
                148_500,
                dc(true, true, 340_000),
                &none,
                (12, 222_750),
                "1080p60 at 12 bpc",
            ),
            (
                tgl,
                297_000,
                dc(true, true, 340_000),
                &none,
                (8, 297_000),
                "4K30 12 bpc needs > 340",
            ),
            (
                tgl,
                297_000,
                dc(true, true, 0),
                &scdc,
                (12, 445_500),
                "SCDC sinks go past 340",
            ),
            (
                icl,
                148_500,
                dc(true, false, 0),
                &none,
                (10, 185_625),
                "10 bpc on display 11",
            ),
            (
                skl,
                148_500,
                dc(true, false, 0),
                &none,
                (8, 148_500),
                "no 10 bpc on display 9",
            ),
            (
                skl,
                148_500,
                dc(true, true, 0),
                &none,
                (12, 222_750),
                "12 bpc on display 9",
            ),
            (
                skl,
                297_000,
                dc(true, true, 0),
                &scdc,
                (8, 297_000),
                "display 9 stops at 300 MHz",
            ),
            (
                tgl,
                148_500,
                dc(false, false, 0),
                &none,
                (8, 148_500),
                "no DC flags",
            ),
            (
                tgl,
                148_500,
                None,
                &none,
                (8, 148_500),
                "a DVI sink is 8 bpc",
            ),
        ] {
            if compute_bpc(family, clock, vsdb, hf) != want {
                return TestResult::Fail(why);
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hdmi",
        smoke_hdmi_deep_colour_selection
    );
}
