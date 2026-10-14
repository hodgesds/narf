//! Orchestrated native Navi48 modeset on legacy DP SST and TMDS HDMI
//! connectors: one display (the first answering DisplayPort sink, else the
//! first HDMI sink), or every lightable sink as one configuration of up to
//! four displays, display k on pipe k. Each sink takes its EDID preferred
//! (or a requested) mode; the configuration is admitted jointly, its clocks
//! programmed once, then each display runs the retained owners' preparations
//! in their dependency order in its own records and its uploaded surface is
//! made visible. Inherited (GOP) consumers must already be retired; the
//! clock owners refuse otherwise.
use super::*;
use crate::amdgpu_dcn401_dml as dml;
use crate::amdgpu_dml::Timing;
use crate::dp_link_training::LinkRate;

/// The DIO stream and pipe are independent of the PHY; the first native
/// scanout uses one index for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModesetError {
    /// No routed DP connector answered with DPCD and an EDID preferred mode,
    /// and no HDMI connector with an HDMI (not DVI) sink.
    NoSink,
    /// The preferred mode cannot be carried by the sink's maximum link.
    Link,
    Boot(Error),
    /// The sink's SCDC could not be configured for a scrambled mode.
    Scdc(crate::amdgpu_ddc_navi48::Error),
    Clocks(clocks::Error),
    PipeClocks(dccg::Error),
    Display(otg::Error),
}
impl From<otg::Error> for ModesetError {
    fn from(e: otg::Error) -> Self {
        Self::Display(e)
    }
}

/// A sink chosen for the first native scanout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// Index into `display_paths()`, the `port` of every DP operation.
    pub port: usize,
    pub timing: Timing,
    /// DP link settings; unused (zero lanes) for HDMI.
    pub lanes: u8,
    pub rate: LinkRate,
    /// The sink's base EDID block, reported to DRM verbatim.
    pub edid: [u8; 128],
    /// A TMDS HDMI sink rather than DP SST.
    pub hdmi: bool,
    /// The HDMI sink declared SCDC (HF-VSDB/HF-SCDB SCDC_Present).
    pub scdc: bool,
    /// RGB output depth: 8 bpc for DP; for HDMI the deepest the sink, the
    /// TMDS rate and the requested maximum allow.
    pub depth: otg::ColorDepth,
    /// The HDMI sink's audio, when it declares any.
    pub audio: Option<otg::HdmiAudioInfo>,
    /// The HDMI AVI InfoFrame's VIC, aspect and range for this timing.
    pub avi: otg::Avi,
    /// Limited-range RGB output (COLOR_SPACE_SRGB_LIMITED).
    pub limited: bool,
    /// HDMI YCbCr 4:2:0 output (COLOR_SPACE_YCBCR709, 8 bpc).
    pub ycbcr420: bool,
}

/// The sink's audio description as amdgpu_dm_fill_audio_info builds it from
/// the EDID: vendor and product codes, the 0xFC monitor name (up to 13
/// characters, ended by LF), all Short Audio Descriptors when the CTA
/// revision is at least 3, the first 3-byte Speaker Allocation block (else
/// FL/FR + FC), and the HDMI VSDB progressive latencies. None when the sink
/// declares no audio mode: Linux then assigns no audio endpoint.
pub fn hdmi_audio_info(edid: &[u8]) -> Option<otg::HdmiAudioInfo> {
    use narf_edid::cta861::{CtaExtension, DataBlock};
    let base = edid.get(..128)?;
    let mut info = otg::HdmiAudioInfo {
        manufacturer_id: u16::from_le_bytes([base[8], base[9]]),
        product_id: u16::from_le_bytes([base[10], base[11]]),
        name: [0; 18],
        speakers: 5,
        modes: [otg::AudioMode::default(); 16],
        mode_count: 0,
        video_latency: 0,
        audio_latency: 0,
    };
    for d in base[54..126].chunks_exact(18) {
        if d[..5] == [0, 0, 0, 0xfc, 0] {
            info.name = [0; 18];
            for (i, &c) in d[5..18].iter().enumerate() {
                if c == 0x0a {
                    break;
                }
                info.name[i] = c;
            }
        }
    }
    let mut speakers = None;
    for block in edid.chunks_exact(128).skip(1) {
        let Ok(cta) = CtaExtension::parse(block) else {
            continue;
        };
        for db in &cta.data_blocks {
            match db {
                DataBlock::Audio(sads) if cta.revision >= 3 => {
                    for sad in sads {
                        if usize::from(info.mode_count) < info.modes.len() {
                            info.modes[usize::from(info.mode_count)] = otg::AudioMode {
                                format: sad.format,
                                channels: sad.max_channels,
                                rates: sad.sample_rates & 0x7f,
                                byte2: sad.format_dep,
                            };
                            info.mode_count += 1;
                        }
                    }
                }
                DataBlock::Speaker(alloc) if speakers.is_none() => speakers = Some(alloc.0),
                DataBlock::Vendor(v) if v.is_hdmi_licensing() => {
                    // HDMI VSDB byte 8 bit 7: progressive latencies follow.
                    if v.payload.len() >= 9 && v.payload[7] & 0x80 != 0 {
                        info.video_latency = v.payload[8];
                        info.audio_latency = v.payload.get(9).copied().unwrap_or(0);
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(s) = speakers {
        info.speakers = s;
    }
    (info.mode_count > 0).then_some(info)
}

/// Highest output depth modesets may pick, like DRM's max_requested_bpc,
/// which amdgpu_dm initialises to 8. Raised by `amdgpu.max_bpc`.
static MAX_BPC: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(8);
/// Set the highest output depth (8, 10 or 12; others leave it unchanged).
pub fn set_max_bpc(bpc: u8) {
    if matches!(bpc, 8 | 10 | 12) {
        MAX_BPC.store(bpc, core::sync::atomic::Ordering::Relaxed);
    }
}
pub fn max_bpc() -> u8 {
    MAX_BPC.load(core::sync::atomic::Ordering::Relaxed)
}

/// DRM's "Broadcast RGB" connector property values.
pub const BROADCAST_RGB_AUTO: u8 = 0;
pub const BROADCAST_RGB_FULL: u8 = 1;
pub const BROADCAST_RGB_LIMITED: u8 = 2;
static BROADCAST_RGB: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(BROADCAST_RGB_AUTO);
/// Set "Broadcast RGB" for later modesets (other values are ignored).
pub fn set_broadcast_rgb(value: u8) {
    if value <= BROADCAST_RGB_LIMITED {
        BROADCAST_RGB.store(value, core::sync::atomic::Ordering::Relaxed);
    }
}
pub fn broadcast_rgb() -> u8 {
    BROADCAST_RGB.load(core::sync::atomic::Ordering::Relaxed)
}
/// amdgpu_dm_get_output_color_space for RGB: COLOR_SPACE_SRGB_LIMITED only
/// when "Broadcast RGB" is Limited; Automatic outputs full range, as Linux
/// amdgpu does (it does not follow drm_default_rgb_quant_range).
pub fn limited_range(broadcast_rgb: u8) -> bool {
    broadcast_rgb == BROADCAST_RGB_LIMITED
}

/// The result of a successful modeset, retained by the caller for teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modeset {
    pub selection: Selection,
    pub pipe: u8,
    pub plan: dml::Plan,
    pub scanout: otg::ScanoutRunning,
    /// Every EDID timing this sink can be switched to on this link and
    /// pipe (the running one included), in EDID order: what KMS offers.
    pub modes: [Option<Timing>; MAX_MODES],
}

/// Modes offered per sink.
pub const MAX_MODES: usize = 16;

/// What `modeset_displays` lit: display k on pipe k, and the failure that
/// stopped lighting early, if one did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub displays: Vec<Modeset>,
    pub failed: Option<ModesetError>,
}

/// A selected sink's whole scanned EDID (extensions included).
fn edid_of(ports: &[display::Port], paths: &[inventory::Path], s: &Selection) -> Vec<u8> {
    ports
        .iter()
        .find(|p| paths.get(s.port) == Some(&p.path))
        .and_then(|p| p.sink.as_ref().ok())
        .map(|sink| sink.edid.clone())
        .unwrap_or_default()
}

/// The sink's modes the DCN timing model accepts, in Linux's
/// drm_edid_connector_add_modes order without duplicates: detailed timings
/// (base block first, which EDID 1.3+ makes the preferred mode, then each
/// CTA-861 extension's), standard timings DMT covers, established timings,
/// then the CTA extensions' short video descriptors. Interlaced and
/// pixel-repeated modes are left out (the pipeline drives neither), as are
/// standard timings needing CVT/GTF synthesis.
pub fn edid_timings(edid: &[u8]) -> Vec<Timing> {
    use narf_edid::modes;
    let base = edid
        .get(..128)
        .and_then(|b| narf_edid::Block::parse(b).ok());
    let ctas: Vec<narf_edid::cta861::CtaExtension> = edid
        .chunks_exact(128)
        .skip(1)
        .filter(|b| b[0] == 0x02)
        .filter_map(|b| narf_edid::cta861::CtaExtension::parse(b).ok())
        .collect();
    let mut detailed: Vec<narf_edid::DetailedTiming> = Vec::new();
    if let Some(base) = &base {
        detailed.extend(base.detailed_timings.iter().copied());
    }
    for cta in &ctas {
        detailed.extend(cta.detailed_timings.iter().copied());
    }
    let mut fixed: Vec<modes::FixedMode> = Vec::new();
    if let Some(base) = &base {
        fixed.extend(
            base.standard_timings
                .iter()
                .filter_map(|&(b0, b1)| modes::standard_mode(b0, b1, base.edid_revision)),
        );
        fixed.extend(modes::established_modes(
            base.established_timings_1,
            base.established_timings_2,
            edid[37],
        ));
    }
    // add_cea_modes: in data-block order, each Video Data Block's SVD
    // modes and each YCbCr 4:2:0 Video Data Block's 4:2:0-only modes.
    for cta in &ctas {
        for block in &cta.data_blocks {
            match block {
                narf_edid::cta861::DataBlock::Video(svds) => {
                    fixed.extend(svds.iter().filter_map(|svd| modes::cea_mode(svd.vic)));
                }
                narf_edid::cta861::DataBlock::Extended {
                    ext_tag: 14,
                    payload,
                } => fixed.extend(payload.iter().filter_map(|&b| modes::cea_mode(svd_vic(b)))),
                _ => {}
            }
        }
    }
    detailed.extend(
        fixed
            .into_iter()
            .filter(|m| !m.pixel_repeated())
            .map(modes::FixedMode::detailed),
    );
    let mut timings: Vec<Timing> = Vec::new();
    for d in detailed {
        if let Ok(t) = crate::amdgpu_dcn_display::timing_from_edid(&d) {
            if !timings.contains(&t) {
                timings.push(t);
            }
        }
    }
    timings
}

/// What a periodic check of a running modeset found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// Sink present, link locked, scanout fetching; the fresh frame count.
    Running(u32),
    /// Debounced HPD low: tear down with `unplug_modeset`.
    Unplugged,
    /// The D0 sink lost lane lock: `retrain_modeset` (Linux's link loss).
    LinkLost(otg::DpLinkStatus),
}

/// Maximum DPCD link of a DP receiver: MAX_LINK_RATE and MAX_LANE_COUNT.
/// The sink's maximum link, bounded by a repeater chain's (Linux
/// dp_get_max_link_cap takes the minimum with the LTTPR caps).
fn max_link(dpcd: &[u8; 16], lttpr: Option<(u8, u8)>) -> Option<(u8, LinkRate)> {
    let (mut lanes, mut rate) = (dpcd[2] & 0x1f, dpcd[1]);
    if let Some((max_rate, max_lanes)) = lttpr {
        lanes = lanes.min(max_lanes);
        rate = rate.min(max_rate);
    }
    let rate = LinkRate::from_dpcd_byte(rate)?;
    matches!(lanes, 1 | 2 | 4).then_some((lanes, rate))
}

/// The frontend's 8b/10b payload ceiling for 8-bpc RGB.
pub fn link_fits(timing: &Timing, lanes: u8, rate: LinkRate) -> bool {
    u64::from(timing.pixel_clock_khz) * 3 * 8 <= rate as u64 * 27_000 * 8 * u64::from(lanes)
}

/// HDMI 2.0 SCDC registers (Linux dc_hdmi_types.h).
pub mod scdc {
    pub const SINK_VERSION: u8 = 0x01;
    pub const SOURCE_VERSION: u8 = 0x02;
    pub const TMDS_CONFIG: u8 = 0x20;
}

/// What an HDMI sink's EDID declares, as DRM's HDMI VSDB and HF-VSDB/HF-SCDB
/// parsers read it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HdmiCaps {
    /// HDMI Licensing VSDB present: an HDMI sink, not DVI. HDMI data islands
    /// (GC and AVI packets) must not reach a DVI sink.
    pub hdmi: bool,
    /// VSDB Max_TMDS_Clock in kHz, zero when not declared.
    pub vsdb_max_khz: u32,
    /// HF Max_TMDS_Character_Rate in kHz, zero when not declared.
    pub forum_max_khz: u32,
    /// HF SCDC_Present.
    pub scdc: bool,
    /// VCDB QS: the sink takes the RGB quantization range the AVI
    /// InfoFrame names.
    pub qs: bool,
    /// A Y420 video or capability-map block declares 4:2:0: with SCDC,
    /// what makes Linux's is_hdmi2_sink.
    pub ycbcr420: bool,
    /// VICs the Video Data Blocks list, as a bitmap.
    pub vics: [u64; 4],
    /// VICs the sink takes only as YCbCr 4:2:0 (Y420VDB), and VICs it
    /// takes as 4:2:0 too (the SVDs a Y420CMDB maps), as bitmaps:
    /// drm_mode_is_420_only and drm_mode_is_420_also.
    pub y420_only: [u64; 4],
    pub y420_also: [u64; 4],
    /// VSDB DC_30bit / DC_36bit: RGB 4:4:4 at 10 / 12 bpc.
    pub dc30: bool,
    pub dc36: bool,
}
pub fn hdmi_caps(edid: &[u8]) -> HdmiCaps {
    use narf_edid::cta861::{CtaExtension, DataBlock};
    let mut caps = HdmiCaps::default();
    // Every SVD's VIC in order (DRM's display_info vics), which a Y420CMDB
    // indexes; the map, or None for one that covers every SVD.
    let mut svd_vics: Vec<u8> = Vec::new();
    let mut cmdb: Option<Option<u64>> = None;
    let set = |map: &mut [u64; 4], vic: u8| map[usize::from(vic / 64)] |= 1 << (vic % 64);
    for block in edid.chunks_exact(128).skip(1) {
        let Ok(cta) = CtaExtension::parse(block) else {
            continue;
        };
        for db in &cta.data_blocks {
            // HF fields from the version byte on: HF-VSDB after its OUI,
            // HF-SCDB (extended tag 0x79) after two reserved bytes.
            let forum = match db {
                // DRM's minimum lengths: VSDB 5, HF-VSDB 7, HF-SCDB 7 with its tag.
                DataBlock::Vendor(v) if v.is_hdmi_licensing() && v.payload.len() >= 5 => {
                    caps.hdmi = true;
                    if let Some(&flags) = v.payload.get(5) {
                        caps.dc30 = flags & 0x10 != 0;
                        caps.dc36 = flags & 0x20 != 0;
                    }
                    if let Some(&rate) = v.payload.get(6) {
                        caps.vsdb_max_khz = u32::from(rate) * 5000;
                    }
                    None
                }
                DataBlock::Vendor(v) if v.is_hdmi_forum() && v.payload.len() >= 7 => {
                    v.payload.get(3..)
                }
                DataBlock::Extended {
                    ext_tag: 0x79,
                    payload,
                } if payload.len() >= 6 => payload.get(2..),
                _ => None,
            };
            match db {
                DataBlock::Video(svds) => {
                    for d in svds {
                        set(&mut caps.vics, d.vic);
                        svd_vics.push(d.vic);
                    }
                }
                DataBlock::Extended {
                    ext_tag: 0,
                    payload,
                } => {
                    caps.qs |= payload.first().is_some_and(|b| b & 0x40 != 0);
                }
                // Y420VDB: any known VIC; Y420CMDB: an empty map covers all
                // SVDs, else any set bit.
                DataBlock::Extended {
                    ext_tag: 14,
                    payload,
                } => {
                    for &b in payload.iter() {
                        let vic = svd_vic(b);
                        if narf_edid::modes::cea_mode(vic).is_some() {
                            caps.ycbcr420 = true;
                            set(&mut caps.y420_only, vic);
                        }
                    }
                }
                DataBlock::Extended {
                    ext_tag: 15,
                    payload,
                } => {
                    caps.ycbcr420 |= payload.is_empty() || payload.iter().take(8).any(|&b| b != 0);
                    // parse_cta_y420cmdb: an empty map covers every SVD;
                    // at most 64 SVDs are mapped.
                    let map = payload
                        .iter()
                        .take(8)
                        .enumerate()
                        .fold(0u64, |m, (i, &b)| m | u64::from(b) << (8 * i));
                    let all = cmdb.get_or_insert(Some(0));
                    *all = if payload.is_empty() {
                        None
                    } else {
                        all.map(|m| m | map)
                    };
                }
                _ => {}
            }
            if let Some(&[_version, rate, flags, ..]) = forum {
                caps.forum_max_khz = u32::from(rate) * 5000;
                caps.scdc = flags & 0x80 != 0;
            }
        }
    }
    if let Some(map) = cmdb {
        for (i, &vic) in svd_vics.iter().enumerate().take(64) {
            if map.is_none_or(|m| m & 1 << i != 0) {
                set(&mut caps.y420_also, vic);
            }
        }
    }
    caps
}
/// Linux `svd_to_vic`.
fn svd_vic(svd: u8) -> u8 {
    narf_edid::cta861::ShortVideoDescriptor::parse(svd).vic
}

/// The AVI InfoFrame fields of `t` on this sink, as
/// drm_hdmi_avi_infoframe_from_display_mode and amdgpu's set_avi_info_frame
/// derive them: the CTA VIC (none for an HDMI 1.4b 4K mode on an HDMI sink,
/// whose HDMI VIC goes in the vendor InfoFrame, as drm_mode_hdmi_vic
/// gives it; and none above 64 for an HDMI 1.4 sink that does not list
/// it), the VIC's
/// picture aspect when 4:3 or 16:9, and whether the sink can select the
/// range. The aspect of a mode is taken from its VIC alone: narf modes carry
/// none of their own.
/// `t` as DRM's mode matchers take it.
fn edid_mode(t: &Timing) -> narf_edid::modes::FixedMode {
    let field = |active: u32, front: u32, sync: u32, total: u32| {
        let at = |x: u32| u16::try_from(x).unwrap_or(u16::MAX);
        [
            at(active),
            at(active + front),
            at(active + front + sync),
            at(total),
        ]
    };
    narf_edid::modes::progressive(
        t.pixel_clock_khz,
        field(t.h_active, t.h_front_porch, t.h_sync_width, t.h_total),
        field(t.v_active, t.v_front_porch, t.v_sync_width, t.v_total),
        t.h_sync_positive,
        t.v_sync_positive,
    )
}

/// How an HDMI sink carries `t`, in amdgpu's encoding order with 4:2:2 and
/// 4:4:4 YCbCr left out: a mode the sink takes only as YCbCr 4:2:0
/// (drm_mode_is_420_only) as 4:2:0; otherwise RGB at the deepest depth up
/// to `max_bpc` that fits, and failing that 4:2:0 where the sink takes the
/// mode as 4:2:0 too (drm_mode_is_420_also). 4:2:0 is 8 bpc, half the
/// pixel rate per TMDS character. The depth and whether it is 4:2:0; None
/// when nothing fits.
pub fn hdmi_format(caps: HdmiCaps, t: &Timing, max_bpc: u8) -> Option<(otg::ColorDepth, bool)> {
    let vic = narf_edid::modes::match_cea_mode(edid_mode(t));
    let listed = |map: [u64; 4]| vic != 0 && map[usize::from(vic / 64)] & 1 << (vic % 64) != 0;
    let fits_420 = || hdmi_fits(caps, t.pixel_clock_khz / 2);
    if listed(caps.y420_only) {
        return fits_420().then_some((otg::ColorDepth::Bpc8, true));
    }
    if let Some(depth) = hdmi_depth(caps, t.pixel_clock_khz, max_bpc) {
        return Some((depth, false));
    }
    (listed(caps.y420_also) && fits_420()).then_some((otg::ColorDepth::Bpc8, true))
}

pub fn hdmi_avi(caps: HdmiCaps, t: &Timing) -> otg::Avi {
    use narf_edid::modes::{cea_aspect, hdmi_aspect, match_cea_mode, match_hdmi_mode};
    let mode = edid_mode(t);
    let hdmi_vic = if caps.hdmi { match_hdmi_mode(mode) } else { 0 };
    let vic = if hdmi_vic != 0 {
        0
    } else {
        match_cea_mode(mode)
    };
    let aspect = match (vic, hdmi_vic) {
        (0, 0) => 0,
        (0, h) => hdmi_aspect(h),
        (v, _) => cea_aspect(v),
    };
    let hdmi2 = caps.scdc || caps.ycbcr420;
    let listed = caps.vics[usize::from(vic / 64)] & 1 << (vic % 64) != 0;
    otg::Avi {
        vic: if !hdmi2 && vic > 64 && !listed {
            0
        } else {
            vic
        },
        aspect: if aspect <= 2 { aspect } else { 0 },
        qs: caps.qs,
        hdmi_vic,
    }
}

/// Whether an HDMI sink can take `khz` as 8-bpc RGB TMDS: within a declared
/// VSDB Max_TMDS_Clock, and above 340 MHz only with SCDC and an HF rate that
/// covers it (DRM's scrambling-support rule).
pub fn hdmi_fits(caps: HdmiCaps, khz: u32) -> bool {
    if khz > otg::TMDS_MAX_KHZ {
        return false;
    }
    if khz <= otg::TMDS_SCRAMBLE_KHZ {
        return caps.vsdb_max_khz == 0 || khz <= caps.vsdb_max_khz;
    }
    caps.scdc && khz <= caps.forum_max_khz
}

/// The base block's preferred mode. Extension blocks follow the base block in
/// the scanned EDID; the base parser takes exactly one 128-byte block.
fn preferred(edid: &[u8]) -> Option<Timing> {
    narf_edid::Block::parse(edid.get(..128)?)
        .ok()
        .and_then(|b| b.preferred_mode())
        .and_then(|d| crate::amdgpu_dcn_display::timing_from_edid(&d).ok())
}

/// The deepest RGB depth up to `max_bpc` the sink declares and whose TMDS
/// character clock it can take, stepping down by 2 bpc like amdgpu_dm's
/// stream validation; None if not even 8 bpc fits.
pub fn hdmi_depth(caps: HdmiCaps, pixel_khz: u32, max_bpc: u8) -> Option<otg::ColorDepth> {
    use crate::amdgpu_dmub_navi48::TmdsDepth;
    [
        (12, caps.dc36, otg::ColorDepth::Bpc12, TmdsDepth::Bpc12),
        (10, caps.dc30, otg::ColorDepth::Bpc10, TmdsDepth::Bpc10),
        (8, true, otg::ColorDepth::Bpc8, TmdsDepth::Bpc8),
    ]
    .into_iter()
    .find(|&(bpc, declared, _, tmds)| {
        bpc <= max_bpc && declared && hdmi_fits(caps, tmds.character_khz(pixel_khz))
    })
    .map(|(_, _, depth, _)| depth)
}

/// First routed DP port whose sink answered with DPCD and an EDID preferred
/// mode the DCN timing model accepts, at the sink's maximum link; failing
/// that, the first HDMI sink whose preferred mode fits TMDS, at the deepest
/// depth up to `max_bpc` that fits.
pub fn select(
    paths: &[inventory::Path],
    ports: &[display::Port],
    max_bpc: u8,
    want: Option<Timing>,
) -> Result<Selection, ModesetError> {
    Ok(select_all(paths, ports, max_bpc, &|_| want)?[0])
}

/// Displays one configuration lights at most: one per pipe.
pub const MAX_DISPLAYS: usize = 4;

/// Every lightable sink, as `select` judges each: the DP ports in board
/// order, then the HDMI ports, at most `MAX_DISPLAYS`. `want(port)` is the
/// timing asked of that port's sink, used where the sink lists and fits it.
/// Empty is an error: `Link` when some sink's mode could not be carried.
pub fn select_all(
    paths: &[inventory::Path],
    ports: &[display::Port],
    max_bpc: u8,
    want: &dyn Fn(usize) -> Option<Timing>,
) -> Result<Vec<Selection>, ModesetError> {
    // The requested mode where the sink lists it and it fits, else the
    // preferred one.
    let pick = |index: usize, edid: &[u8], fits: &dyn Fn(&Timing) -> bool| {
        want(index)
            .filter(|w| edid_timings(edid).contains(w) && fits(w))
            .or_else(|| preferred(edid))
    };
    let mut link_short = false;
    let mut out = Vec::new();
    for port in ports {
        if port.path.connector != inventory::Connector::DisplayPort {
            continue;
        }
        let Ok(sink) = &port.sink else { continue };
        let Some((lanes, rate)) = sink.dpcd.as_ref().and_then(|d| max_link(d, sink.lttpr)) else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        let Some(timing) = pick(index, &sink.edid, &|t| link_fits(t, lanes, rate)) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        if !link_fits(&timing, lanes, rate) {
            link_short = true;
            continue;
        }
        out.push(Selection {
            port: index,
            timing,
            lanes,
            rate,
            edid,
            hdmi: false,
            scdc: false,
            depth: otg::ColorDepth::Bpc8,
            audio: None,
            avi: otg::Avi::default(),
            limited: false,
            ycbcr420: false,
        });
    }
    for port in ports {
        if port.path.connector != inventory::Connector::HdmiTypeA {
            continue;
        }
        let Ok(sink) = &port.sink else { continue };
        let caps = hdmi_caps(&sink.edid);
        if !caps.hdmi {
            continue;
        }
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        let Some(timing) = pick(index, &sink.edid, &|t| {
            hdmi_format(caps, t, max_bpc).is_some()
        }) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let Some((depth, ycbcr420)) = hdmi_format(caps, &timing, max_bpc) else {
            link_short = true;
            continue;
        };
        out.push(Selection {
            port: index,
            timing,
            lanes: 0,
            rate: LinkRate::Rbr,
            edid,
            hdmi: true,
            scdc: caps.scdc,
            depth,
            audio: hdmi_audio_info(&sink.edid),
            avi: hdmi_avi(caps, &timing),
            limited: false,
            ycbcr420,
        });
    }
    out.truncate(MAX_DISPLAYS);
    if out.is_empty() {
        return Err(if link_short {
            ModesetError::Link
        } else {
            ModesetError::NoSink
        });
    }
    Ok(out)
}

/// The largest leading run of `selections` the display pipeline can scan
/// out together, with its plans: Linux refuses a commit DML rejects, but
/// lighting a configuration as a whole, the displays that do not fit stay
/// dark instead (the last ones, so the first display stays the one `select`
/// picks). The error is the first display's alone.
pub fn admit_displays(
    soc: &dml::Soc,
    selections: &[Selection],
) -> Result<Vec<dml::Plan>, dml::Error> {
    let modes: Vec<dml::Mode> = selections.iter().map(selection_mode).collect();
    let mut n = modes.len().min(MAX_DISPLAYS);
    loop {
        match dml::admit_all(soc, &modes[..n]) {
            Ok(plans) => return Ok(plans),
            Err(e) if n <= 1 => return Err(e),
            Err(_) => n -= 1,
        }
    }
}

/// Link settings to try, best first: drop the rate; below RBR halve the lanes
/// and restart from the sink's maximum rate (narf's documented DP fallback
/// ladder, as in `dp_link_training`). Settings that cannot carry the mode are
/// never tried.
pub fn link_candidates(timing: &Timing, lanes: u8, rate: LinkRate) -> Vec<(u8, LinkRate)> {
    let mut out = Vec::new();
    let mut l = lanes;
    while l >= 1 {
        let mut r = Some(rate);
        while let Some(current) = r {
            if link_fits(timing, l, current) {
                out.push((l, current));
            }
            r = current.next_lower();
        }
        l /= 2;
    }
    out
}

/// Linear XRGB8888 pitch in pixels: 64-pixel (256-byte) aligned.
pub fn mode(timing: Timing) -> dml::Mode {
    dml::Mode {
        timing,
        pitch: (timing.h_active + 63) & !63,
        ycbcr420: false,
    }
}

/// The admission mode of a selected sink: its timing, as 4:2:0 output
/// when it leaves so.
pub fn selection_mode(s: &Selection) -> dml::Mode {
    dml::Mode {
        ycbcr420: s.ycbcr420,
        ..mode(s.timing)
    }
}

/// Global clocks at least as fast as the plan's DISPCLK and DPPREFCLK.
pub fn clock_request(plan: &dml::Plan) -> clocks::Request {
    clocks::Request {
        displays: 1,
        display_khz: plan.clocks.dispclk_khz,
        dpp_khz: plan.clocks.dpprefclk_khz,
        dtb_khz: 1, // legacy DIO: lowest DTB level
    }
}

/// DP's DPREF DTO, or for RGB TMDS the divide-by-four pixel rate (Linux's
/// dcn401_calculate_dccg_tmds_div_value) from the PHY PLL.
pub fn pipe_clock_request(pipe: u8, plan: &dml::Plan, hdmi: bool) -> dccg::Request {
    dccg::Request {
        pipe,
        dpp_khz: plan.clocks.dppclk_khz,
        // dcn401_calculate_dccg_tmds_div_value: 4:2:0 divides by two.
        pixel: if hdmi {
            dccg::PixelClock::Tmds {
                divider: if plan.mode.ycbcr420 {
                    dccg::TmdsDivider::By2
                } else {
                    dccg::TmdsDivider::By4
                },
            }
        } else {
            dccg::PixelClock::DisplayPort {
                pixel_hz: u64::from(plan.mode.timing.pixel_clock_khz) * 1000,
            }
        },
    }
}

pub fn timing_request(pipe: u8, plan: &dml::Plan, hdmi: bool) -> otg::Request {
    otg::Request {
        pipe,
        timing: plan.mode.timing,
        sync: plan.sync,
        signal: if hdmi {
            otg::Signal::Tmds
        } else {
            otg::Signal::DisplayPort
        },
        ycbcr420: plan.mode.ycbcr420,
    }
}

/// What retiring the inherited (GOP) display found and stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritedRetired {
    /// DIO streams whose video was active on entry.
    pub active_streams: u8,
    /// Timing generators found running after the streams were disabled.
    pub running_timing: u8,
    /// DIO frontends found routed to a DP SST backend, by bit.
    pub routed_frontends: u8,
    /// `display_paths()` indices whose transmitter firmware disable was sent.
    pub disabled_ports: u8,
}

impl ColdBoot {
    /// Retire whatever legacy DP SST output the firmware left running, in
    /// native dependency order: blank every DIO stream (a no-op when already
    /// blank), disable each board-routed DP backend that has a frontend
    /// routed to it, retire those encoders, then the planes and all timing.
    /// A port with no routed frontend is refused during planning, before any
    /// write, and skipped; any other failure stops here and quarantines.
    /// # Safety
    /// Stop every CPU writer of the inherited framebuffer's scanout role (its
    /// memory stays excluded from the pool), and exclude firmware/FAMS and
    /// concurrent display/audio/link/clock/power writers. HDMI, HPO and MST
    /// output are not retired here; their live state makes this fail.
    pub async unsafe fn retire_inherited_display(
        &mut self,
    ) -> Result<InheritedRetired, ModesetError> {
        let mut found = InheritedRetired {
            active_streams: 0,
            running_timing: 0,
            routed_frontends: 0,
            disabled_ports: 0,
        };
        // SAFETY: as documented; every step validates its own preconditions.
        unsafe {
            for i in 0..4 {
                if self
                    .blank_display_dp_stream(otg::DpStream::Dio(i))
                    .await?
                    .was_active
                {
                    found.active_streams |= 1 << i;
                }
            }
            let ports = self
                .display_paths()
                .map_err(|_| ModesetError::NoSink)?
                .len();
            for port in 0..ports.min(8) {
                let path = self.display_paths().map_err(|_| ModesetError::NoSink)?[port];
                if path.connector != inventory::Connector::DisplayPort {
                    continue;
                }
                match self.disable_display_dp_sst(port).await {
                    Ok(d) => {
                        found.routed_frontends |= 1 << d.frontend;
                        if d.command_sent {
                            found.disabled_ports |= 1 << port;
                        }
                    }
                    // Planning refusals (no single routed frontend) write
                    // nothing and leave the owner reusable.
                    Err(otg::Error::Unsupported)
                        if self
                            .display_timing_status()
                            .is_ok_and(|s| s.state.reusable()) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // An active stream must have been found behind some backend.
            if found.active_streams & !found.routed_frontends != 0 {
                return Err(ModesetError::Display(otg::Error::Busy));
            }
            for i in 0..4 {
                if found.routed_frontends & 1 << i != 0 {
                    self.retire_display_dp_encoder(otg::DpStream::Dio(i))
                        .await?;
                }
            }
            self.retire_display_planes().await?;
            // Only running generators: an idle (or soft-reset) OTG needs none.
            let running = self.display_running_timing()?;
            found.running_timing = running;
            for pipe in 0..4 {
                if running & 1 << pipe != 0 {
                    self.retire_display_timing(pipe).await?;
                }
            }
        }
        Ok(found)
    }
    /// Light the first answering DP SST sink at its preferred mode on `pipe`,
    /// with `fill(y, row)` supplying each visible row before fetch starts.
    /// # Safety
    /// Inherited display consumers must be retired and every display of
    /// this owner stopped. Exclude firmware/FAMS and concurrent
    /// display/hub/VM/IRQ/clock/reset/power/link writers; retain every owner
    /// and allocation on every outcome, including cancellation. A failure
    /// leaves the owners where they stopped; nothing is unwound.
    pub async unsafe fn modeset_display(
        &mut self,
        pipe: u8,
        fill: impl FnMut(u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
        // SAFETY: the caller's obligations.
        unsafe { self.modeset_display_mode(pipe, fill, None) }.await
    }
    /// `modeset_display` in `want` when the selected sink lists that timing
    /// and it fits (one of a previous `Modeset::modes`), else the preferred
    /// mode. One display only, on `pipe` (its display slot too).
    /// # Safety
    /// As for `modeset_display`.
    pub async unsafe fn modeset_display_mode(
        &mut self,
        pipe: u8,
        mut fill: impl FnMut(u32, &mut [u32]),
        want: Option<Timing>,
    ) -> Result<Modeset, ModesetError> {
        if pipe >= 4 {
            return Err(ModesetError::Display(otg::Error::Invalid));
        }
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let paths = self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .to_vec();
        let mut selection = select(&paths, &ports, max_bpc(), want)?;
        selection.limited = limited_range(broadcast_rgb()) && !selection.ycbcr420;
        self.select_display(pipe)?;
        let soc = self.prepare_configuration(&[selection]).await?;
        let plans = admit_displays(&soc, &[selection]).map_err(otg::Error::Admission)?;
        self.prepare_pipes(&[selection], &plans, &[pipe]).await?;
        // SAFETY: the caller's obligations.
        let mut lit =
            unsafe { self.light(pipe, selection, plans[0], &mut |_, y, row| fill(y, row)) }.await?;
        lit.modes = self.offered_modes(&soc, &[lit], 0, &edid_of(&ports, &paths, &selection));
        Ok(lit)
    }
    /// Light every lightable sink (`select_all`) as one configuration, each
    /// on the pipe `pipe_of` gives its port (its display slot too): sinks on
    /// ports without a pipe stay dark. The largest leading set the pipeline
    /// admits together (`admit_displays`) is lit, its clocks programmed once
    /// for all of them, then each display through the same steps as one
    /// display alone, next to the ones already lit. `want(port)` is the
    /// timing asked of that port's sink; `fill(pipe, y, row)` supplies each
    /// visible row before that display's fetch starts. If a display fails to
    /// light, the ones before it stay lit and are returned with the failure.
    /// # Safety
    /// As for `modeset_display`: every display of this owner stopped.
    pub async unsafe fn modeset_displays(
        &mut self,
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipe_of: impl Fn(usize) -> Option<u8>,
    ) -> Result<Configuration, ModesetError> {
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let paths = self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .to_vec();
        let mut selections = select_all(&paths, &ports, max_bpc(), &want)?;
        selections.retain(|s| pipe_of(s.port).is_some_and(|p| p < 4));
        if selections.is_empty() {
            return Err(ModesetError::NoSink);
        }
        // "Broadcast RGB" is RGB's: YCbCr is limited range by itself.
        let limited = limited_range(broadcast_rgb());
        for s in &mut selections {
            s.limited = limited && !s.ycbcr420;
        }
        let pipes: Vec<u8> = selections.iter().filter_map(|s| pipe_of(s.port)).collect();
        self.select_display(pipes[0])?;
        let soc = self.prepare_configuration(&selections).await?;
        let plans = admit_displays(&soc, &selections).map_err(otg::Error::Admission)?;
        selections.truncate(plans.len());
        self.prepare_pipes(&selections, &plans, &pipes).await?;
        let mut lit = Vec::with_capacity(selections.len());
        let mut failed = None;
        for ((selection, plan), &pipe) in selections.iter().zip(&plans).zip(&pipes) {
            // SAFETY: the caller's obligations; every earlier display is lit
            // in its own slot and left to it by each step.
            match unsafe { self.light(pipe, *selection, *plan, &mut fill) }.await {
                Ok(m) => lit.push(m),
                Err(e) if lit.is_empty() => return Err(e),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        for k in 0..lit.len() {
            let edid = edid_of(&ports, &paths, &lit[k].selection);
            lit[k].modes = self.offered_modes(&soc, &lit, k, &edid);
        }
        Ok(Configuration {
            displays: lit,
            failed,
        })
    }
    /// Start PMFW at the clock floor (which publishes the DPM levels
    /// admission needs) and return the board's admission inputs.
    async fn prepare_configuration(
        &mut self,
        selections: &[Selection],
    ) -> Result<dml::Soc, ModesetError> {
        // Requests are clamped up to each clock's minimum.
        let floor = clocks::Request {
            displays: selections.len().clamp(1, MAX_DISPLAYS) as u8,
            display_khz: 1,
            dpp_khz: 1,
            dtb_khz: 1,
        };
        self.prepare_display_clocks(floor)
            .await
            .map_err(ModesetError::Clocks)?;
        Ok(self.display_soc()?)
    }
    /// The configuration's global clocks (one DISPCLK/DPPREFCLK for every
    /// plan), then each display's pipe clocks on `pipes`, all while every
    /// display is stopped.
    async fn prepare_pipes(
        &mut self,
        selections: &[Selection],
        plans: &[dml::Plan],
        pipes: &[u8],
    ) -> Result<(), ModesetError> {
        let mut request = clock_request(&plans[0]);
        request.displays = plans.len() as u8;
        self.prepare_display_clocks(request)
            .await
            .map_err(ModesetError::Clocks)?;
        for ((s, plan), &pipe) in selections.iter().zip(plans).zip(pipes) {
            self.prepare_display_pipe_clocks(pipe_clock_request(pipe, plan, s.hdmi))
                .await
                .map_err(ModesetError::PipeClocks)?;
        }
        Ok(())
    }
    /// Light one admitted display on `pipe` (its display slot too), with its
    /// clocks prepared: surface, timing, OPP, DPP, MPC, requestor and
    /// deadlines, then its link, video and scanout.
    /// # Safety
    /// As for `modeset_display`, except that other displays of this owner
    /// may be lit in their own slots.
    async unsafe fn light(
        &mut self,
        pipe: u8,
        selection: Selection,
        plan: dml::Plan,
        fill: &mut impl FnMut(u8, u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
        self.select_display(pipe)?;
        let (width, height) = (selection.timing.h_active, selection.timing.v_active);
        // SAFETY: the caller's exclusion and retention obligations cover each
        // retained owner below; every step validates its own preconditions.
        unsafe {
            self.retire_display_planes().await?;
            self.set_display_hubp_power(pipe, true).await?;
            self.prepare_display_surface(otg::SurfaceRequest {
                pipe,
                width,
                height,
                format: otg::SurfaceFormat::Xrgb8888,
            })
            .await?;
            let mut row = alloc::vec![0u32; width as usize];
            for y in 0..height {
                fill(pipe, y, &mut row);
                self.upload_display_surface(pipe, 0, y, &row)?;
            }
            self.prepare_display_memory(pipe).await?;
            self.prepare_display_timing(timing_request(pipe, &plan, selection.hdmi))
                .await?;
            self.prepare_display_blank(otg::BlankRequest {
                pipe,
                depth: selection.depth,
                limited: selection.limited,
                ycbcr420: selection.ycbcr420,
            })
            .await?;
            self.prepare_display_dpp(pipe).await?;
            self.prepare_display_mpc(pipe)?;
            self.prepare_display_requestor(pipe).await?;
            self.prepare_display_deadlines(pipe, &plan).await?;
            match self.enable_display_hpd(selection.port) {
                // A board without an HPD selector still lights; monitoring
                // then reports Unsupported.
                Ok(()) | Err(otg::Error::Unsupported) => {}
                Err(e) => return Err(e.into()),
            }
            let (selection, scanout) = self.start_link(selection, pipe).await?;
            Ok(Modeset {
                selection,
                pipe,
                plan,
                scanout,
                modes: [None; MAX_MODES],
            })
        }
    }
    /// The timings of display `k`'s sink a later configuration could switch
    /// it to: they fit the link it trained (DP) or a TMDS depth (HDMI) and
    /// DML admits them together with the other lit displays' running modes.
    /// The running timing is always included.
    fn offered_modes(
        &mut self,
        soc: &dml::Soc,
        lit: &[Modeset],
        k: usize,
        edid: &[u8],
    ) -> [Option<Timing>; MAX_MODES] {
        let s = lit[k].selection;
        let caps = hdmi_caps(edid);
        let mut modes = [None; MAX_MODES];
        let mut n = 0;
        let mut joint: Vec<dml::Mode> = lit.iter().map(|m| selection_mode(&m.selection)).collect();
        for t in edid_timings(edid) {
            if n == MAX_MODES {
                break;
            }
            // How the link would carry it: HDMI may need 4:2:0.
            let format = if s.hdmi {
                hdmi_format(caps, &t, max_bpc()).map(|(_, ycbcr420)| ycbcr420)
            } else {
                link_fits(&t, s.lanes, s.rate).then_some(false)
            };
            if t == s.timing {
                modes[n] = Some(t);
                n += 1;
                continue;
            }
            let Some(ycbcr420) = format else {
                continue;
            };
            joint[k] = dml::Mode {
                ycbcr420,
                ..mode(t)
            };
            if dml::admit_all(soc, &joint).is_ok() {
                modes[n] = Some(t);
                n += 1;
            }
        }
        if !modes.contains(&Some(s.timing)) {
            modes[MAX_MODES - 1] = Some(s.timing);
        }
        modes
    }
    /// Train the selected sink down the fallback ladder from its selection,
    /// then start the frontend, video and scanout of the staged `pipe`.
    /// # Safety
    /// As for `modeset_display`, with the pipe's timing, surface and
    /// deadlines prepared and the port's PHY disabled.
    async unsafe fn start_link(
        &mut self,
        selection: Selection,
        pipe: u8,
    ) -> Result<(Selection, otg::ScanoutRunning), ModesetError> {
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            let port = selection.port;
            if selection.hdmi {
                self.configure_scdc(&selection).await?;
                let request = otg::HdmiLinkRequest {
                    stream: pipe,
                    pipe,
                    avi: selection.avi,
                };
                self.prepare_display_hdmi_link(port, request).await?;
                self.start_display_hdmi_video(port).await?;
                let scanout = self.start_display_scanout(pipe).await?;
                // As Linux's post-enable: audio after the stream runs.
                if let Some(info) = selection.audio {
                    self.start_display_hdmi_audio(port, info).await?;
                }
                return Ok((selection, scanout));
            }
            let mut selection = selection;
            let mut trained = false;
            let mut refused = ModesetError::Link;
            let transmitter =
                self.display_paths().map_err(|_| ModesetError::NoSink)?[port].transmitter;
            for (lanes, rate) in link_candidates(&selection.timing, selection.lanes, selection.rate)
            {
                self.enable_display_dp_phy(port, otg::DpPhySettings { lanes, rate })
                    .await?;
                match self.train_display_dp_link(port, false).await {
                    Ok(_) => {
                        (selection.lanes, selection.rate) = (lanes, rate);
                        trained = true;
                        break;
                    }
                    // The sink refused this link and training proved its idle
                    // exit: stop the link (sink D3, PHY off) and try the next
                    // setting, as Linux's training retries do.
                    Err(e @ otg::Error::DpTraining(_))
                        if self
                            .display_timing_status()
                            .is_ok_and(|s| s.state == otg::State::DpLinkRefused(transmitter)) =>
                    {
                        refused = e.into();
                        self.stop_display_dp_link(port).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if !trained {
                return Err(refused);
            }
            self.prepare_display_dp_frontend(port, otg::DpFrontendRequest { stream: pipe, pipe })
                .await?;
            self.start_display_dp_video(port).await?;
            let scanout = self.start_display_scanout(pipe).await?;
            Ok((selection, scanout))
        }
    }
    /// Check a running modeset: hot-plug first (no AUX to an absent sink),
    /// then the sink's lane lock, then the scanout itself.
    /// # Safety
    /// As for `modeset_display`; exclude other AUX users of the port.
    pub async unsafe fn check_modeset(&mut self, m: &Modeset) -> Result<Health, ModesetError> {
        // Display k runs on pipe k, in its own records.
        self.select_display(m.pipe)?;
        let port = m.selection.port;
        if !self.display_hpd(port)? {
            return Ok(Health::Unplugged);
        }
        // SAFETY: as documented above.
        unsafe {
            // TMDS has no sink-side lock status to read.
            if !m.selection.hdmi {
                let link = self.display_dp_link_status(port).await?;
                if link.lost() {
                    return Ok(Health::LinkLost(link));
                }
            }
            Ok(Health::Running(self.check_display_scanout(m.pipe).await?))
        }
    }
    /// Linux's dp_handle_link_loss: stop the stream and link, then train
    /// again from the current setting (falling back as needed) and restart
    /// video and scanout of the retained surface.
    /// # Safety
    /// As for `modeset_display`; stop every CPU writer of the surface first.
    pub async unsafe fn retrain_modeset(&mut self, m: &mut Modeset) -> Result<(), ModesetError> {
        // Display k runs on pipe k, in its own records.
        self.select_display(m.pipe)?;
        let port = m.selection.port;
        if m.selection.hdmi {
            return Err(ModesetError::Display(otg::Error::Unsupported));
        }
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            self.stop_display_scanout(m.pipe).await?;
            self.stop_display_dp_video(port).await?;
            self.stop_display_dp_frontend(port).await?;
            self.stop_display_dp_link(port).await?;
            (m.selection, m.scanout) = self.start_link(m.selection, m.pipe).await?;
        }
        Ok(())
    }
    /// Tear down a modeset whose sink left: as `stop_modeset`, but the link
    /// stops without addressing the sink, and only while HPD stays low.
    /// # Safety
    /// As for `stop_modeset`.
    pub async unsafe fn unplug_modeset(&mut self, m: &Modeset) -> Result<(), ModesetError> {
        // Display k runs on pipe k, in its own records.
        self.select_display(m.pipe)?;
        let port = m.selection.port;
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            if m.selection.hdmi && m.selection.audio.is_some() {
                self.stop_display_hdmi_audio(port).await?;
            }
            self.stop_display_scanout(m.pipe).await?;
            if m.selection.hdmi {
                // The departed sink's SCDC is not addressed.
                self.stop_hdmi(port, false).await?;
            } else {
                self.stop_display_dp_video(port).await?;
                self.stop_display_dp_frontend(port).await?;
                self.stop_unplugged_display_dp_link(port).await?;
            }
            self.retire_display_timing(m.pipe).await?;
            self.retire_display_planes().await?;
        }
        Ok(())
    }
    /// Reverse a successful modeset down to a disabled PHY with timing and
    /// planes retired. The surface allocation is retained by its pipe.
    /// # Safety
    /// As for `modeset_display`; stop every CPU writer of the surface first.
    pub async unsafe fn stop_modeset(&mut self, m: &Modeset) -> Result<(), ModesetError> {
        // Display k runs on pipe k, in its own records.
        self.select_display(m.pipe)?;
        let port = m.selection.port;
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            if m.selection.hdmi && m.selection.audio.is_some() {
                self.stop_display_hdmi_audio(port).await?;
            }
            self.stop_display_scanout(m.pipe).await?;
            if m.selection.hdmi {
                self.stop_hdmi(port, m.selection.scdc).await?;
            } else {
                self.stop_display_dp_video(port).await?;
                self.stop_display_dp_frontend(port).await?;
                self.stop_display_dp_link(port).await?;
            }
            self.retire_display_timing(m.pipe).await?;
            self.retire_display_planes().await?;
        }
        Ok(())
    }
    /// Linux's write_scdc_data before the TMDS link starts: with SCDC, read
    /// the sink version, answer version 1 with source version 1, then set
    /// TMDS_Config to scrambling plus the 1/40 clock ratio above 340 MHz, or
    /// to legacy HDMI. A scrambled mode the sink was not told about cannot
    /// display, so its SCDC failures fail the modeset; Linux ignores the
    /// legacy write's result, and so does this.
    async fn configure_scdc(&mut self, s: &Selection) -> Result<(), ModesetError> {
        use scdc::*;
        if !s.scdc {
            return Ok(());
        }
        let tmds = match s.depth {
            otg::ColorDepth::Bpc8 => crate::amdgpu_dmub_navi48::TmdsDepth::Bpc8,
            otg::ColorDepth::Bpc10 => crate::amdgpu_dmub_navi48::TmdsDepth::Bpc10,
            otg::ColorDepth::Bpc12 => crate::amdgpu_dmub_navi48::TmdsDepth::Bpc12,
        };
        // Linux decides on phy_pix_clk, the deep-colour character clock of
        // the TMDS pixel clock (halved for 4:2:0).
        let pixel_khz = s.timing.pixel_clock_khz >> u32::from(s.ycbcr420);
        let scrambled = tmds.character_khz(pixel_khz) > otg::TMDS_SCRAMBLE_KHZ;
        let result = async {
            if self.display_scdc_read(s.port, SINK_VERSION).await? == 1 {
                self.display_scdc_write(s.port, SOURCE_VERSION, 1).await?;
            }
            let config = if scrambled { 3 } else { 0 };
            self.display_scdc_write(s.port, TMDS_CONFIG, config).await
        }
        .await;
        match result {
            Err(e) if scrambled => Err(ModesetError::Scdc(e)),
            _ => Ok(()),
        }
    }
    /// Mute and stop HDMI video, tell an SCDC sink it returns to legacy HDMI
    /// (Linux's link_set_dpms_off), then stop the transmitter and frontend.
    /// # Safety
    /// As for `stop_modeset`, with scanout stopped.
    async unsafe fn stop_hdmi(&mut self, port: usize, scdc: bool) -> Result<(), ModesetError> {
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            self.stop_display_hdmi_video(port).await?;
            if scdc {
                let _ = self.display_scdc_write(port, scdc::TMDS_CONFIG, 0).await;
            }
            self.stop_display_hdmi_link(port).await?;
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_modeset_tests.rs"]
mod tests;
