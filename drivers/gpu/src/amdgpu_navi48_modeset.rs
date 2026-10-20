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

#[path = "amdgpu_navi48_sst.rs"]
mod sst;
pub use sst::SstOutput;
#[path = "amdgpu_navi48_planes.rs"]
mod planes;
pub use planes::PlanesChange;

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
    /// The port's MST branch or a payload on its link failed.
    Mst(super::MstFailure),
    /// Every 8b/10b setting carrying the selected stream (its DSC/PPS
    /// unchanged) was refused, and training proved a lower verified link
    /// (Linux's dp_verify_link_cap). Selection must run again: the sink's
    /// caps are now bounded by that link, which may need new DSC geometry.
    LinkReduced,
}
impl From<super::MstFailure> for ModesetError {
    fn from(e: super::MstFailure) -> Self {
        match e {
            super::MstFailure::Display(e) => Self::Display(e),
            e => Self::Mst(e),
        }
    }
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
    pub rate: DpRate,
    /// The DP sink's usable links; `DpCaps::NONE` for HDMI, with the HF DSC
    /// decoder (`DscSinkCaps::from_hdmi`) of a compressed FRL stream.
    pub caps: DpCaps,
    /// The sink's base EDID block, reported to DRM verbatim.
    pub edid: [u8; 128],
    /// An HDMI sink (TMDS or FRL) rather than DP.
    pub hdmi: bool,
    /// The HDMI sink declared SCDC (HF-VSDB/HF-SCDB SCDC_Present).
    pub scdc: bool,
    /// Output depth: for DP SST the deepest depth up to the sink's EDID bpc
    /// and `max_bpc` a link carries, uncompressed or compressed
    /// (`dp_sst_stream`; a compressed stream's `DscConfig::bpc`); for MST
    /// the deepest the port and the link's fairness search take when the
    /// link has a DSC decoder, else 8; for HDMI the deepest the sink, the
    /// link capacity and the requested maximum allow.
    pub depth: otg::ColorDepth,
    /// The sink's audio; FRL retains only supported LPCM modes.
    pub audio: Option<otg::AudioInfo>,
    /// The HDMI AVI InfoFrame's VIC, aspect and range for this timing.
    pub avi: otg::Avi,
    /// Limited-range RGB output (COLOR_SPACE_SRGB_LIMITED).
    pub limited: bool,
    /// HDMI YCbCr 4:2:0 output (COLOR_SPACE_YCBCR709, 8 bpc).
    pub ycbcr420: bool,
    /// HDMI over FRL at this rate rather than TMDS.
    pub frl: Option<FrlRate>,
    /// DP compressed by the pipe's DSC on this link.
    pub dsc: Option<crate::amdgpu_dsc::DscConfig>,
    /// A stream to a device behind the port's MST branch, on the port's
    /// 8b/10b MST link.
    pub mst: Option<MstStream>,
    /// The sink's FreeSync range (amdgpu_dm_update_freesync_caps): DP SST
    /// sinks only; None when the sink is not VRR-capable.
    pub vrr: Option<crate::amdgpu_freesync::VrrRange>,
    /// The primary plane's surface format: what DRM's framebuffer on the
    /// display's CRTC holds (`plane_format`), XRGB8888 by default.
    pub format: otg::SurfaceFormat,
    /// DRM's "Colorspace" on the display's connector (a
    /// DRM_MODE_COLORIMETRY_*, `output_color`), Default by default.
    pub colorspace: u32,
    /// DRM's HDR_OUTPUT_METADATA on the display's connector: the stream
    /// sends the HDR InfoFrame (HDMI) or SDP (DP).
    pub hdr: Option<crate::amdgpu_hdr::HdrOutputMetadata>,
    /// A DP sink that takes colorimetry in the VSC SDP
    /// (use_vsc_sdp_for_colorimetry: DPCD 1.4 and DPRX feature bit 3).
    pub vsc_colorimetry: bool,
    /// DRM's planes on the display's CRTC beyond a full-frame unscaled
    /// primary (`plane_setup`): the primary's placement and the overlays.
    pub planes: PlaneSetup,
}

/// Where one plane shows, as DRM's plane state hands it to DC
/// (amdgpu_dm_plane_fill_dc_scaling_info): its source rectangle (whose
/// size is the plane's surface; the presenter copies the framebuffer's
/// source rectangle into it) and its CRTC rectangle, with the plane's
/// rotation and blending (amdgpu_dm_plane_fill_blending_from_plane_state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaneGeometry {
    pub src_x: u32,
    pub src_y: u32,
    pub width: u32,
    pub height: u32,
    pub dst: crate::amdgpu_dcn401_spl::Rect,
    pub rotation: crate::amdgpu_dcn401_spl::Rotation,
    pub blend: otg::Blend,
    /// The framebuffer's tiling, DCC and YCbCr color space.
    pub surface: otg::PlaneSurface,
    /// The framebuffer's size: a tiled or 4:2:0 plane stages its whole
    /// framebuffer (`whole_framebuffer`) and scans the source rectangle out
    /// of it, as DC scans a framebuffer's viewport.
    pub fb_size: (u32, u32),
}
impl PlaneGeometry {
    /// Whether the plane's surface is its whole framebuffer: a tiled or
    /// 4:2:0 one, which cannot be cropped by copying rows. A linear RGB
    /// plane's surface is its source rectangle.
    pub fn whole_framebuffer(&self, format: otg::SurfaceFormat) -> bool {
        format.is_video() || self.surface.tiling != otg::Tiling::LINEAR
    }
}

/// One overlay plane DRM enabled on a display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayPlane {
    pub geometry: PlaneGeometry,
    pub format: otg::SurfaceFormat,
    /// Its normalized zpos is below the primary's.
    pub underlay: bool,
    /// The DRM plane's id (0: none known): a seamless plane change keeps a
    /// plane on its pipes across commits by it.
    pub plane: u32,
}

/// A display's planes: the primary's placement (None: the whole
/// framebuffer unscaled at the mode's size, blended as its format's
/// default) and up to three overlays, bottom first, each on a free pipe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlaneSetup {
    pub primary: Option<PlaneGeometry>,
    pub overlays: [Option<OverlayPlane>; otg::MAX_OVERLAYS],
}
impl PlaneSetup {
    /// The full-frame unscaled primary alone.
    pub const NONE: Self = Self {
        primary: None,
        overlays: [None; otg::MAX_OVERLAYS],
    };
    pub fn overlay_count(&self) -> usize {
        self.overlays.iter().flatten().count()
    }
}

/// One overlay plane's pipes: the pipe it is staged on, its stream's
/// further ODM segments' pipes, and on a stream in ODM bypass the pipes of
/// its further MPC slices.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlanePipes {
    pub pipe: u8,
    pub odm: otg::SplitPipes,
    pub mpc: otg::SplitPipes,
}
impl PlanePipes {
    /// Every pipe the plane fetches on.
    pub fn all(&self) -> impl Iterator<Item = u8> {
        core::iter::once(self.pipe).chain(self.odm).chain(self.mpc)
    }
}

/// Each overlay's pipes, bottom first.
pub type OverlayPipes = [Option<PlanePipes>; otg::MAX_OVERLAYS];

/// The pipes one display lights on beyond its own: its stream's further
/// ODM segments, its primary's further MPC slices, and each overlay's
/// pipes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayPipes {
    pub odm: otg::SplitPipes,
    pub mpc: otg::SplitPipes,
    pub overlays: OverlayPipes,
}
impl DisplayPipes {
    /// Every overlay pipe (all segments and slices), by bit.
    pub fn overlay_mask(&self) -> u8 {
        self.overlays
            .iter()
            .flatten()
            .flat_map(PlanePipes::all)
            .fold(0, |m, p| m | 1 << p)
    }
    /// Every pipe beyond the display's own, by bit.
    pub fn mask(&self) -> u8 {
        self.overlay_mask() | self.odm.mask() | self.mpc.mask()
    }
}

/// The surface requests of selection `s` lit on `pipe` with the further
/// pipes `pipes`: the primary, then each overlay on its pipes (pipe 0, and
/// stand-in segment pipes on an ODM stream, for an overlay without any:
/// DML and the checks do not depend on the pipe). Each plane's layout is
/// its source size at its CRTC rectangle on the stream; the unscaled
/// full-frame primary has none.
pub fn plane_requests(
    s: &Selection,
    pipe: u8,
    pipes: &DisplayPipes,
) -> (
    otg::SurfaceRequest,
    [Option<otg::SurfaceRequest>; otg::MAX_OVERLAYS],
) {
    stream_planes(
        &s.timing,
        s.ycbcr420,
        s.format,
        &s.planes,
        (pipe, pipes.odm, pipes.mpc),
        &pipes.overlays,
    )
}

/// `plane_requests` for planes `setup` (primary `format`) on a stream of
/// `timing`.
pub fn stream_planes(
    timing: &Timing,
    ycbcr420: bool,
    format: otg::SurfaceFormat,
    setup: &PlaneSetup,
    (pipe, odm, mpc): (u8, otg::SplitPipes, otg::SplitPipes),
    overlays: &OverlayPipes,
) -> (
    otg::SurfaceRequest,
    [Option<otg::SurfaceRequest>; otg::MAX_OVERLAYS],
) {
    use crate::amdgpu_dcn401_spl::Rect;
    // A plane's surface: its source rectangle, or (tiled / 4:2:0) its whole
    // framebuffer with the source rectangle placed in it.
    let request = |g: &PlaneGeometry, format: otg::SurfaceFormat, (p, q, m), underlay| {
        let whole = g.whole_framebuffer(format);
        let (x, y) = if whole { (g.src_x, g.src_y) } else { (0, 0) };
        let (width, height) = if whole {
            g.fb_size
        } else {
            (g.width, g.height)
        };
        otg::SurfaceRequest {
            pipe: p,
            width,
            height,
            format,
            odm: q,
            mpc: m,
            plane: Some(otg::PlaneLayout {
                src: Rect::new(x as i32, y as i32, g.width as i32, g.height as i32),
                dst: g.dst,
                stream_width: timing.h_active,
                stream_height: timing.v_active,
                ycbcr420,
                rotation: g.rotation,
                blend: g.blend,
                underlay,
            }),
            surface: g.surface,
        }
    };
    let primary = match &setup.primary {
        Some(g) => request(g, format, (pipe, odm, mpc), false),
        None => otg::SurfaceRequest {
            pipe,
            width: timing.h_active,
            height: timing.v_active,
            format,
            odm,
            mpc,
            plane: None,
            surface: otg::PlaneSurface::LINEAR,
        },
    };
    // Stand-in pipes 1.. for an overlay's segments beside stand-in pipe 0.
    let stand_in = PlanePipes {
        pipe: 0,
        odm: otg::SplitPipes::new(&[1, 2, 3][..odm.len()]).unwrap_or_default(),
        mpc: otg::SplitPipes::NONE,
    };
    let mut out = [None; otg::MAX_OVERLAYS];
    for ((slot, o), pipes) in out.iter_mut().zip(&setup.overlays).zip(overlays) {
        let Some(o) = o else { continue };
        let p = pipes.unwrap_or(stand_in);
        *slot = Some(request(
            &o.geometry,
            o.format,
            (p.pipe, p.odm, p.mpc),
            o.underlay,
        ));
    }
    (primary, out)
}

/// A selection's stream on an MST link: its end device and VC payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstStream {
    pub sink: crate::dp_mst_mgr::Sink,
    pub pbn: u16,
    pub slots: u8,
    /// DP_MSE_RATE X.Y (`otg::vc_rate`).
    pub rate: (u32, u32),
    /// A compressed stream's decoder: where DP_DSC_ENABLE goes.
    pub dsc: Option<super::mst::MstDsc>,
}

/// The sink's audio description as amdgpu_dm_fill_audio_info builds it from
/// the EDID: vendor and product codes, the 0xFC monitor name (up to 13
/// characters, ended by LF), all Short Audio Descriptors when the CTA
/// revision is at least 3, the first 3-byte Speaker Allocation block (else
/// FL/FR + FC), and the HDMI VSDB progressive latencies. None when the sink
/// declares no audio mode: Linux then assigns no audio endpoint.
pub fn sink_audio_info(edid: &[u8]) -> Option<otg::AudioInfo> {
    use narf_edid::cta861::{CtaExtension, DataBlock};
    let base = edid.get(..128)?;
    let mut info = otg::AudioInfo {
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

/// HDMI FRL, off by default as amdgpu keeps it (dcfeaturemask's
/// DC_FRL_MASK, 0x400): only then does a sink's Max_FRL_Rate count.
static FRL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Allow HDMI FRL (`amdgpu.dcfeaturemask` bit 0x400).
pub fn set_frl(enabled: bool) {
    FRL.store(enabled, core::sync::atomic::Ordering::Relaxed);
}

pub fn frl_enabled() -> bool {
    FRL.load(core::sync::atomic::Ordering::Relaxed)
}

/// An HDMI FRL link: Linux's hdmi_frl_link_rate, the SCDC FRL_Rate code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrlRate(u8);
impl FrlRate {
    /// The code, 1 (3 lanes x 3G) to 6 (4 lanes x 12G).
    pub fn new(code: u8) -> Option<Self> {
        (1..=6).contains(&code).then_some(Self(code))
    }
    pub fn code(self) -> u8 {
        self.0
    }
    /// Three lanes below 4 x 6G.
    pub fn lanes(self) -> u8 {
        if self.0 < 3 {
            3
        } else {
            4
        }
    }
    pub fn gbps(self) -> u8 {
        [3, 6, 6, 8, 10, 12][usize::from(self.0 - 1)]
    }
    /// The FRL character clock per lane, kHz (Gbps / 18 bits x 1e6).
    pub fn character_khz(self) -> u32 {
        [166_667, 333_333, 333_333, 444_444, 555_555, 666_667][usize::from(self.0 - 1)]
    }
    /// frl_link_bandwidth_kbps: lanes x the raw rate.
    pub fn kbps(self) -> u64 {
        u64::from(self.lanes()) * u64::from(self.gbps()) * 1_000_000
    }
}

/// hdmi_frl_retrieve_link_cap on DCN401: the encoder's 4 x 12G (forced on
/// while the VBIOS cannot say) bounded by the sink's Max_FRL_Rate; none
/// with FRL disabled or no SCDC.
pub fn frl_cap(caps: HdmiCaps) -> Option<FrlRate> {
    if !frl_enabled() || !caps.scdc {
        return None;
    }
    FrlRate::new(caps.max_frl_rate.min(6))
}

/// get_audio_check of the sink's audio modes with the timing's layout
/// (hpo_enc3_validate_hdmi_frl_output): audio sample packets, or 3D/HBR
/// packets above 192 kHz; layout 1 for more than two channels above 576
/// lines. A sink without audio still reserves ACR bandwidth.
pub fn frl_audio(audio: Option<otg::AudioInfo>, v_active: u32) -> crate::amdgpu_frl_cap::FrlAudio {
    const RATES: [u32; 7] = [32_000, 44_100, 48_000, 88_200, 96_000, 176_400, 192_000];
    let (mut rate, mut channels) = (0, 0);
    if let Some(info) = audio {
        for m in &info.modes[..usize::from(info.mode_count.min(16))] {
            let best = (0..7).rev().find(|&i| m.rates & 1 << i != 0);
            rate = rate.max(best.map_or(0, |i| RATES[i]));
            channels = channels.max(m.channels);
        }
    }
    crate::amdgpu_frl_cap::FrlAudio {
        packet_type: if rate > 192_000 { 9 } else { 2 },
        max_rate_hz: rate,
        layout: u8::from(channels > 2 && v_active > 576),
    }
}

/// frl_validate_mode_timing for RGB or YCbCr 4:2:0 at `bpc`: the stream within the raw
/// link rate, and Linux's capacity check passing.
pub fn frl_carries(
    t: &Timing,
    bpc: u8,
    ycbcr420: bool,
    rate: FrlRate,
    audio: crate::amdgpu_frl_cap::FrlAudio,
) -> Option<crate::amdgpu_frl_cap::FrlCap> {
    use crate::amdgpu_frl_cap::{frl_cap_check, FrlCap, FrlCapInput, FrlEncoding};
    let h_blank = t.h_total.checked_sub(t.h_active)?;
    if !matches!(bpc, 8 | 10 | 12)
        || t.pixel_clock_khz == 0
        || t.h_active == 0
        || h_blank == 0
        || ycbcr420 && (t.h_active | h_blank) & 1 != 0
        || u64::from(t.pixel_clock_khz) * u64::from(bpc) * 3
            > rate.kbps() * if ycbcr420 { 2 } else { 1 }
    {
        return None;
    }
    let check = frl_cap_check(&FrlCapInput {
        lanes: rate.lanes(),
        gbps: rate.gbps(),
        pixel_clock_100hz: t.pixel_clock_khz.checked_mul(10)?,
        h_active: t.h_active,
        h_blank,
        bpc,
        encoding: if ycbcr420 {
            FrlEncoding::Ycbcr420
        } else {
            FrlEncoding::Rgb444
        },
        audio,
        dsc: None,
    });
    matches!(check, FrlCap::Ok { .. }).then_some(check)
}

/// A compressed HDMI FRL stream: its DSC configuration and VICs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlDscStream {
    pub cfg: crate::amdgpu_dsc::DscConfig,
    pub vic: crate::amdgpu_dsc::Vic,
}
impl FrlDscStream {
    /// A selection's compressed FRL stream.
    pub fn of(s: &Selection) -> Option<Self> {
        let cfg = s.dsc.filter(|c| c.frl.is_some())?;
        s.frl?;
        Some(Self {
            cfg,
            vic: crate::amdgpu_dsc::Vic {
                cta: s.avi.vic,
                hdmi: s.avi.hdmi_vic,
            },
        })
    }
}

/// frl_validate_mode_timing for a DSC stream (RGB at `cfg.bpc`): Linux's
/// compressed capacity check (hpo_enc3_validate_hdmi_frl_output) with no
/// raw bandwidth bound, at the sink's DSC_Max_FRL_Rate when `rate` is
/// faster.
pub fn frl_dsc_carries(
    t: &Timing,
    dsc: FrlDscStream,
    rate: FrlRate,
    audio: crate::amdgpu_frl_cap::FrlAudio,
) -> Option<crate::amdgpu_frl_cap::FrlCap> {
    use crate::amdgpu_frl_cap::{frl_cap_check, FrlCap, FrlCapInput, FrlDsc, FrlEncoding};
    let link = dsc.cfg.frl?;
    let h_blank = t.h_total.checked_sub(t.h_active)?;
    if t.pixel_clock_khz == 0 || t.h_active == 0 || h_blank == 0 || dsc.cfg.slices_h == 0 {
        return None;
    }
    let checked = if rate.code() > link.max_rate {
        FrlRate::new(link.max_rate)?
    } else {
        rate
    };
    let check = frl_cap_check(&FrlCapInput {
        lanes: checked.lanes(),
        gbps: checked.gbps(),
        pixel_clock_100hz: t.pixel_clock_khz.checked_mul(10)?,
        h_active: t.h_active,
        h_blank,
        // The compressed check reads no depth; the stream's, as Linux
        // passes it.
        bpc: dsc.cfg.bpc,
        encoding: FrlEncoding::Rgb444,
        audio,
        dsc: Some(FrlDsc {
            slices: dsc.cfg.slices_h,
            slice_width: t.h_active.div_ceil(dsc.cfg.slices_h),
            bpp_x16: dsc.cfg.bpp_x16,
            vic: dsc.vic.cta_equivalent(),
            all_bpp: link.all_bpp,
        }),
    });
    matches!(check, FrlCap::Ok { .. }).then_some(check)
}

/// hdmi_frl_decide_link_settings for a DSC stream: validated at the cap,
/// then the lowest rate code from 3 x 3G up that carries it.
pub fn frl_dsc_link(
    t: &Timing,
    dsc: FrlDscStream,
    cap: FrlRate,
    audio: crate::amdgpu_frl_cap::FrlAudio,
) -> Option<FrlRate> {
    frl_dsc_carries(t, dsc, cap, audio)?;
    (1..=cap.code())
        .filter_map(FrlRate::new)
        .find(|&r| frl_dsc_carries(t, dsc, r, audio).is_some())
}

/// What the HPO FRL stream encoder takes for a stream on `rate`: packets
/// per line, borrow mode and HCactive/HCblank. Uncompressed, Linux's
/// capacity check's (no tribyte targets); compressed, its compressed check
/// with the borrow mode update_borrow_mode_from_dsc_padding gives `rate`.
pub fn frl_video_params(
    t: &Timing,
    bpc: u8,
    ycbcr420: bool,
    dsc: Option<FrlDscStream>,
    rate: FrlRate,
    audio: crate::amdgpu_frl_cap::FrlAudio,
) -> Option<(u8, crate::amdgpu_frl_cap::FrlBorrow, u16, u16)> {
    use crate::amdgpu_frl_cap::{dsc_borrow, FrlCap};
    let check = match dsc {
        Some(d) => frl_dsc_carries(t, d, rate, audio)?,
        None => frl_carries(t, bpc, ycbcr420, rate, audio)?,
    };
    let FrlCap::Ok {
        audio_packets_line,
        mut borrow,
        hc_active,
        hc_blank,
    } = check
    else {
        return None;
    };
    if dsc.is_some() {
        borrow = dsc_borrow(
            t.pixel_clock_khz * 10,
            t.h_active,
            t.h_total - t.h_active,
            hc_active,
            hc_blank,
            rate.lanes(),
            rate.gbps(),
        );
    }
    Some((
        u8::try_from(audio_packets_line).ok()?,
        borrow,
        u16::try_from(hc_active).ok()?,
        u16::try_from(hc_blank).ok()?,
    ))
}

/// The DSC view of an RGB HDMI FRL stream at `bpc`.
fn frl_dsc_timing(t: &Timing, bpc: u8) -> crate::amdgpu_dsc::DscTiming {
    dsc_timing(t, bpc)
}

/// update_dsc_caps for an HDMI FRL sink: its HF DSC decoder
/// (dc_dsc_parse_dsc_edid) only with FRL and a DSC_Max_FRL_Rate.
pub fn frl_dsc_caps(caps: HdmiCaps) -> Option<(crate::amdgpu_dsc::DscSinkCaps, u8)> {
    let dsc = caps.dsc?;
    (frl_cap(caps).is_some() && dsc.max_frl_rate > 0).then(|| {
        (
            crate::amdgpu_dsc::DscSinkCaps::from_hdmi(&dsc),
            dsc.max_frl_rate,
        )
    })
}

/// amdgpu_dm's HDMI FRL DSC policy for an RGB stream at `bpc` the verified
/// FRL link `cap` cannot carry raw: dc_dsc_compute_config at the sink's DSC
/// rate (`frl_dsc_caps`; the HF-VSDB's DSC_10bpc/DSC_12bpc decide the
/// deeper inputs), within the pipes admission gives it (as `dp_dsc`), then
/// the link for the compressed stream (`frl_dsc_link`).
#[allow(clippy::too_many_arguments)]
pub fn frl_dsc(
    t: &Timing,
    sink: &crate::amdgpu_dsc::DscSinkCaps,
    max_rate: u8,
    cap: FrlRate,
    audio: crate::amdgpu_frl_cap::FrlAudio,
    max_dispclk_khz: u32,
    vic: crate::amdgpu_dsc::Vic,
    bpc: u8,
) -> Option<(FrlRate, crate::amdgpu_dsc::DscConfig)> {
    let cfg = crate::amdgpu_dsc::compute_frl_config(
        sink,
        max_dispclk_khz,
        max_rate,
        &frl_dsc_timing(t, bpc),
        vic,
    )?;
    dml::dsc_shape(t, cfg.slices_h, max_dispclk_khz)?;
    let rate = frl_dsc_link(t, FrlDscStream { cfg, vic }, cap, audio)?;
    Some((rate, cfg))
}

/// hdmi_frl_decide_link_settings: the lowest rate code from 3 x 3G up
/// that carries the mode, provided the sink's cap does (Linux validates the
/// mode at the cap, then searches upward).
pub fn frl_link(
    t: &Timing,
    bpc: u8,
    ycbcr420: bool,
    cap: FrlRate,
    audio: crate::amdgpu_frl_cap::FrlAudio,
) -> Option<FrlRate> {
    frl_carries(t, bpc, ycbcr420, cap, audio)?;
    (1..=cap.code())
        .filter_map(FrlRate::new)
        .find(|&r| frl_carries(t, bpc, ycbcr420, r, audio).is_some())
}

/// FRL training on a ColdBoot port: SCDC over native DDC, the HPO FRL
/// encoder's patterns and the transmitter's TxFFE through the display
/// owner.
pub struct FrlPort<'a> {
    pub boot: &'a mut ColdBoot,
    pub port: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlPortError {
    Scdc(crate::amdgpu_ddc_navi48::Error),
    Display(otg::Error),
}
impl crate::amdgpu_frl_training::FrlTrainer for FrlPort<'_> {
    type Error = FrlPortError;
    async fn scdc_read(&mut self, offset: u8) -> Result<u8, FrlPortError> {
        self.boot
            .display_scdc_read(self.port, offset)
            .await
            .map_err(FrlPortError::Scdc)
    }
    async fn scdc_write(&mut self, offset: u8, value: u8) -> Result<(), FrlPortError> {
        self.boot
            .display_scdc_write(self.port, offset, value)
            .await
            .map_err(FrlPortError::Scdc)
    }
    fn pattern(&mut self, patterns: [u8; 4]) -> Result<(), FrlPortError> {
        // SAFETY: the FRL link this trainer drives is the port's own.
        unsafe { self.boot.display_frl_pattern(self.port, patterns) }.map_err(FrlPortError::Display)
    }
    async fn ffe(&mut self, lane_set: u8) -> Result<(), FrlPortError> {
        // SAFETY: as for `pattern`.
        unsafe { self.boot.display_frl_ffe(self.port, lane_set).await }
            .map_err(FrlPortError::Display)
    }
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}
impl crate::amdgpu_frl_training::FrlStatusIo for FrlPort<'_> {
    fn current_ffe(&mut self) -> Result<u8, FrlPortError> {
        self.boot
            .display_frl_current_ffe(self.port)
            .map_err(FrlPortError::Display)
    }
}
impl From<FrlPortError> for ModesetError {
    fn from(e: FrlPortError) -> Self {
        match e {
            FrlPortError::Scdc(e) => ModesetError::Scdc(e),
            FrlPortError::Display(e) => ModesetError::Display(e),
        }
    }
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

/// The surface format each pipe's next lighting scans out, as an index
/// into `otg::SurfaceFormat::ALL` (0: XRGB8888).
static PLANE_FORMATS: [core::sync::atomic::AtomicU8; 4] =
    [const { core::sync::atomic::AtomicU8::new(0) }; 4];
/// Scan out `format` on pipe `pipe` from its next lighting on (DRM's
/// framebuffer format on that CRTC). Other pipes are ignored.
pub fn set_plane_format(pipe: u8, format: otg::SurfaceFormat) {
    if let (Some(slot), Some(index)) = (
        PLANE_FORMATS.get(usize::from(pipe)),
        otg::SurfaceFormat::ALL.iter().position(|&f| f == format),
    ) {
        slot.store(index as u8, core::sync::atomic::Ordering::Relaxed);
    }
}
static OUTPUT_COLOR: [narf_lib::sync::IrqSafeSpinLock<(
    u32,
    Option<crate::amdgpu_hdr::HdrOutputMetadata>,
)>; 4] = [const { narf_lib::sync::IrqSafeSpinLock::new((0, None)) }; 4];
/// Light pipe `pipe` with DRM's Colorspace `colorspace` and HDR metadata
/// `hdr` (its connector's) from its next lighting on.
pub fn set_output_color(
    pipe: u8,
    colorspace: u32,
    hdr: Option<crate::amdgpu_hdr::HdrOutputMetadata>,
) {
    if let Some(slot) = OUTPUT_COLOR.get(usize::from(pipe)) {
        *slot.lock() = (colorspace, hdr);
    }
}
/// The Colorspace and HDR metadata pipe `pipe` lights with.
pub fn output_color(pipe: u8) -> (u32, Option<crate::amdgpu_hdr::HdrOutputMetadata>) {
    OUTPUT_COLOR
        .get(usize::from(pipe))
        .map_or((0, None), |slot| *slot.lock())
}
static PLANE_SETUPS: [narf_lib::sync::IrqSafeSpinLock<PlaneSetup>; 4] =
    [const { narf_lib::sync::IrqSafeSpinLock::new(PlaneSetup::NONE) }; 4];
/// Light pipe `pipe` with DRM's planes `setup` from its next lighting on.
pub fn set_plane_setup(pipe: u8, setup: PlaneSetup) {
    if let Some(slot) = PLANE_SETUPS.get(usize::from(pipe)) {
        *slot.lock() = setup;
    }
}
/// The planes pipe `pipe` lights with.
pub fn plane_setup(pipe: u8) -> PlaneSetup {
    PLANE_SETUPS
        .get(usize::from(pipe))
        .map_or(PlaneSetup::NONE, |slot| *slot.lock())
}
/// The surface format pipe `pipe` lights with.
pub fn plane_format(pipe: u8) -> otg::SurfaceFormat {
    PLANE_FORMATS
        .get(usize::from(pipe))
        .map(|slot| slot.load(core::sync::atomic::Ordering::Relaxed))
        .and_then(|index| otg::SurfaceFormat::ALL.get(usize::from(index)).copied())
        .unwrap_or(otg::SurfaceFormat::Xrgb8888)
}
/// amdgpu_dm_get_output_color_space for RGB: COLOR_SPACE_SRGB_LIMITED only
/// when "Broadcast RGB" is Limited; Automatic outputs full range, as Linux
/// amdgpu does (it does not follow drm_default_rgb_quant_range).
pub fn limited_range(broadcast_rgb: u8) -> bool {
    broadcast_rgb == BROADCAST_RGB_LIMITED
}

/// A successful modeset, retained by both the caller and device owner for teardown.
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

/// Keep the actual completed startup witnesses in the device owner until
/// native teardown completes, including while callers are publishing them.
/// On the heap: four whole modesets would dominate the device owner, which
/// recovery moves by value.
#[derive(Debug)]
pub(super) struct RetainedModesets(alloc::boxed::Box<[Option<Modeset>; 4]>);
impl RetainedModesets {
    pub(super) fn new() -> Self {
        // Built in place (a boxed array literal would pass the stack).
        let slots: alloc::boxed::Box<[Option<Modeset>]> = alloc::vec![None; 4].into_boxed_slice();
        Self(slots.try_into().expect("four modeset slots"))
    }
    pub(super) fn retain(&mut self, m: Modeset) {
        self.0[usize::from(m.pipe)] = Some(m);
    }
    fn stopped(&mut self, pipe: u8) {
        self.0[usize::from(pipe)] = None;
    }
    pub(super) fn check_stopped(&self) -> Result<(), ModesetError> {
        if self.0.iter().any(Option::is_some) {
            return Err(otg::Error::Busy.into());
        }
        Ok(())
    }
    fn restore(&self, to: &mut [Option<Modeset>; 4]) -> Result<u8, ModesetError> {
        // Validate the whole transfer before changing any caller's records.
        for (old, retained) in to.iter().zip(self.0.iter()) {
            if old.is_some() && retained.is_some() && old != retained {
                return Err(otg::Error::Busy.into());
            }
        }
        let mut recovered = 0;
        for (pipe, (old, retained)) in to.iter_mut().zip(self.0.iter()).enumerate() {
            if old.is_none() && retained.is_some() {
                *old = *retained;
                recovered |= 1 << pipe;
            }
        }
        Ok(recovered)
    }
}

impl ColdBoot {
    /// Actual completed startup witnesses, retained through failed/cancelled
    /// configuration publication and teardown. This is not a fresh health check.
    /// On the heap: four modesets by value are a large stack frame.
    pub fn display_modesets(&self) -> Vec<Option<Modeset>> {
        self.modesets.0.to_vec()
    }
    /// Recover missing caller handles without overwriting a different incarnation.
    pub(crate) fn restore_modesets(
        &self,
        to: &mut [Option<Modeset>; 4],
    ) -> Result<u8, ModesetError> {
        self.modesets.restore(to)
    }
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
    /// Sink present, source/link checks passed, scanout fetching; fresh frame count.
    Running(u32),
    /// Debounced HPD low: tear down with `unplug_modeset`.
    Unplugged,
    /// The D0 sink lost lane lock: `retrain_modeset` (Linux's link loss).
    LinkLost(otg::DpLinkStatus),
    /// FRL sink requests retraining: retire and readmit the configuration.
    FrlRetrain,
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

/// The frontend's 8b/10b payload ceiling for 8-bpc RGB, without FEC.
#[cfg(feature = "kernel-test")]
pub fn link_fits(timing: &Timing, lanes: u8, rate: LinkRate) -> bool {
    link_fits_bpc(timing, lanes, rate, 8)
}
/// `link_fits` for RGB at `bpc`.
pub fn link_fits_bpc(timing: &Timing, lanes: u8, rate: LinkRate, bpc: u8) -> bool {
    stream_kbps_bpc(timing, false, bpc) <= legacy_kbps(lanes, rate, false)
}

/// A DP main link's per-lane rate: 8b/10b through the DIO encoders, or
/// 128b/132b (UHBR) through the HPO encoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpRate {
    Legacy(LinkRate),
    Uhbr(otg::UhbrRate),
}

/// A DP sink's usable links, as Linux's dp_get_max_link_cap bounds them:
/// the repeater-bounded lane count and 8b/10b rate, and as a mask over
/// `UhbrRate::ALL` the 128b/132b rates up to the lowest of the board's
/// connector speed, the sink's best 0x2215 rate and a revision 1.4
/// repeater chain's best, UHBR13.5 only where the sink and that chain
/// list it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpCaps {
    pub lanes: u8,
    pub rate: LinkRate,
    pub uhbr: u8,
    /// 8b/10b trains with FEC (dp_should_enable_fec), costing 3% of the
    /// link.
    pub fec: bool,
    /// The sink's DSC decoder (no dongle, so no branch caps).
    pub dsc: Option<crate::amdgpu_dsc::DscSinkCaps>,
}
impl DpCaps {
    /// No DP link: an HDMI selection's.
    pub const NONE: Self = Self {
        lanes: 0,
        rate: LinkRate::Rbr,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    /// The usable UHBR rates, ascending.
    pub fn uhbr_rates(self) -> impl Iterator<Item = otg::UhbrRate> {
        otg::UhbrRate::ALL
            .into_iter()
            .enumerate()
            .filter(move |&(i, _)| self.uhbr & 1 << i != 0)
            .map(|(_, r)| r)
    }
}

/// dp_verify_link_cap's walk after a refused selection: the 8b/10b ladder
/// from the sink's caps (Linux's decide_fallback_link_setting order: rate
/// down, then fewer lanes from the top rate), skipping settings already
/// refused while carrying the stream.
pub(super) fn verify_ladder(caps: DpCaps, tried: &[(u8, DpRate)]) -> Vec<(u8, LinkRate)> {
    legacy_candidates(caps.lanes, caps.rate, |l, r| {
        !tried.contains(&(l, DpRate::Legacy(r)))
    })
}

/// The verified link to keep: the first setting that trained, else Linux's
/// fail-safe one lane at RBR. `None` when that is no lower than the caps
/// already are, so selecting again could not change anything.
pub(super) fn verified_link(
    caps: DpCaps,
    trained: Option<(u8, LinkRate)>,
) -> Option<(u8, LinkRate)> {
    let link = trained.unwrap_or((1, LinkRate::Rbr));
    (link != (caps.lanes, caps.rate)).then_some(link)
}

/// A retrain error after which start_link has stopped the link again: the
/// fallback ladder was refused or the link verified lower.
fn retrain_refused(e: &ModesetError) -> bool {
    matches!(
        e,
        ModesetError::Link
            | ModesetError::LinkReduced
            | ModesetError::Display(otg::Error::DpTraining(_))
    )
}

/// A DP SST sink's verified 8b/10b link, kept while that sink (its DPCD
/// caps and base EDID) stays on the port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedLink {
    pub path: inventory::Path,
    pub dpcd: [u8; 16],
    pub edid: [u8; 128],
    pub lanes: u8,
    pub rate: LinkRate,
}

/// Bound each scanned sink by its port's verified link. A port whose sink
/// changed, left or stopped answering drops its entry, so a new sink (or a
/// replug) is judged by its own caps again, as Linux re-verifies on
/// detection.
pub fn apply_verified_links(links: &mut Vec<VerifiedLink>, ports: &mut [display::Port]) {
    links.retain(|v| {
        ports.iter_mut().any(|port| {
            let Ok(sink) = &mut port.sink else {
                return false;
            };
            let same = port.path == v.path
                && sink.dpcd == Some(v.dpcd)
                && sink.edid.get(..128) == Some(&v.edid[..]);
            if same {
                sink.verified_link = Some((v.rate as u8, v.lanes));
            }
            same
        })
    });
}

/// The board's 128b/132b ceiling: dcn401_link_encoder_construct's UHBR
/// flags from the connector-speed record, the highest one set.
fn board_uhbr(path: &inventory::Path) -> Option<otg::UhbrRate> {
    use otg::UhbrRate::*;
    match path.max_speed_mhz {
        20_000.. => Some(Uhbr20),
        13_500.. => Some(Uhbr13_5),
        10_000.. => Some(Uhbr10),
        _ => None,
    }
}

/// The best rate in a 0x2215/0xF0007 mask.
fn best_uhbr(bits: u8) -> Option<otg::UhbrRate> {
    otg::UhbrRate::ALL
        .into_iter()
        .rev()
        .find(|r| bits & r.dpcd_bit() != 0)
}

/// A DP sink's usable links on its board path.
pub fn dp_caps(path: &inventory::Path, sink: &display::Sink) -> Option<DpCaps> {
    let (lanes, mut rate) = max_link(sink.dpcd.as_ref()?, sink.lttpr)?;
    let mut lanes = lanes;
    // A verified link bounds the 8b/10b link and excludes 128b/132b, as
    // Linux's verified_link_cap replaces the reported cap.
    if let Some((code, verified_lanes)) = sink.verified_link {
        lanes = lanes.min(verified_lanes);
        rate = LinkRate::from_dpcd_byte(code.min(rate as u8))?;
        if !matches!(lanes, 1 | 2 | 4) {
            return None;
        }
    }
    let mut max = board_uhbr(path)
        .zip(best_uhbr(sink.uhbr))
        .map(|(a, b)| a.min(b));
    if let Some(chain) = sink.lttpr_uhbr {
        max = max.zip(best_uhbr(chain)).map(|(a, b)| a.min(b));
    }
    let uhbr13_5 = sink.uhbr & 4 != 0 && sink.lttpr_uhbr.is_none_or(|c| c & 4 != 0);
    let uhbr = otg::UhbrRate::ALL
        .into_iter()
        .enumerate()
        .filter(|&(_, r)| max.is_some_and(|m| r <= m))
        .filter(|&(_, r)| r != otg::UhbrRate::Uhbr13_5 || uhbr13_5)
        .fold(0, |bits, (i, _)| bits | 1 << i);
    Some(DpCaps {
        lanes,
        rate,
        uhbr: if sink.verified_link.is_some() {
            0
        } else {
            uhbr
        },
        fec: sink.fec,
        dsc: sink
            .dsc
            .and_then(|b| crate::amdgpu_dsc::DscSinkCaps::parse(&b, &[0; 3])),
    })
}

/// dp_link_bandwidth_kbps for 8b/10b: 80% coding efficiency
/// (DATA_EFFICIENCY_8b_10b_x10000), times 97% with FEC.
pub(super) fn legacy_kbps(lanes: u8, rate: LinkRate, fec: bool) -> u64 {
    let efficiency = if fec { 8000 / 100 * 97 } else { 8000 };
    rate as u64 * 27_000 * 10 * u64::from(lanes) / 10_000 * efficiency
}

/// dp_link_bandwidth_kbps for 128b/132b: 96.71% coding efficiency less
/// 0.3% downspread (DATA_EFFICIENCY_128b_132b_x10000, 9641).
pub fn uhbr_kbps(lanes: u8, rate: otg::UhbrRate) -> u64 {
    u64::from(rate.link_rate()) * 10_000 * u64::from(lanes) / 10_000 * 9641
}

/// dc_bandwidth_in_kbps_from_timing for 8-bpc RGB. On a link that can code
/// 128b/132b (Linux's highest encoding format), the pixel-to-symbol padding
/// of apply_128b_132b_stream_overhead: the active line's 24-bit pixels in
/// 128-bit symbols, rounded up. Exact rational arithmetic where Linux uses
/// 31.32 fixed point.
#[cfg(feature = "kernel-test")]
pub fn stream_kbps(timing: &Timing, uhbr: bool) -> u64 {
    stream_kbps_bpc(timing, uhbr, 8)
}
/// `stream_kbps` for RGB at `bpc` (dc_bandwidth_in_kbps_from_timing's
/// display_color_depth).
pub fn stream_kbps_bpc(timing: &Timing, uhbr: bool, bpc: u8) -> u64 {
    let bpp = 3 * u64::from(bpc);
    let kbps = u64::from(timing.pixel_clock_khz) * bpp;
    let bits = u64::from(timing.h_active) * bpp;
    if !uhbr || bits == 0 {
        return kbps;
    }
    (kbps * bits.div_ceil(128) * 128).div_ceil(bits)
}

/// Whether `lanes` at `rate` carries `timing` on a link with `caps`.
pub fn dp_fits(timing: &Timing, caps: DpCaps, lanes: u8, rate: DpRate) -> bool {
    dp_fits_bpc(timing, caps, lanes, rate, 8)
}
/// `dp_fits` for RGB at `bpc`.
pub fn dp_fits_bpc(timing: &Timing, caps: DpCaps, lanes: u8, rate: DpRate, bpc: u8) -> bool {
    let have = match rate {
        DpRate::Legacy(r) => legacy_kbps(lanes, r, caps.fec),
        DpRate::Uhbr(r) => uhbr_kbps(lanes, r),
    };
    stream_kbps_bpc(timing, caps.uhbr != 0, bpc) <= have
}

/// The link a DP mode lights on: the sink's maximum 8b/10b link when that
/// carries it; otherwise 128b/132b only as Linux's decide_dp_link_settings
/// reaches it, searching upward (lanes first, then rate) past every 8b/10b
/// setting for the first UHBR setting that carries the mode.
pub fn dp_link(timing: &Timing, caps: DpCaps) -> Option<(u8, DpRate)> {
    dp_link_bpc(timing, caps, 8)
}
/// `dp_link` for RGB at `bpc`.
pub fn dp_link_bpc(timing: &Timing, caps: DpCaps, bpc: u8) -> Option<(u8, DpRate)> {
    let legacy = DpRate::Legacy(caps.rate);
    if dp_fits_bpc(timing, caps, caps.lanes, legacy, bpc) {
        return Some((caps.lanes, legacy));
    }
    caps.uhbr_rates()
        .flat_map(|r| [1, 2, 4].map(|l| (l, DpRate::Uhbr(r))))
        .find(|&(l, r)| l <= caps.lanes && dp_fits_bpc(timing, caps, l, r, bpc))
}

/// drm_add_display_info's display_info.bpc from an EDID 1.4 digital
/// input's color bit depth (bits 6:4 of byte 20: 6..16 bpc), 0 when
/// undefined or older.
pub fn edid_bpc(edid: &[u8]) -> u8 {
    let (Some(&rev), Some(&input)) = (edid.get(19), edid.get(20)) else {
        return 0;
    };
    if edid.get(18) != Some(&1) || rev < 4 || input & 0x80 == 0 {
        return 0;
    }
    match input >> 4 & 7 {
        1 => 6,
        2 => 8,
        3 => 10,
        4 => 12,
        5 => 14,
        6 => 16,
        _ => 0,
    }
}

/// The depths amdgpu_dm tries for an uncompressed DP SST stream, deepest
/// first: amdgpu_dm_convert_color_depth_from_display_info's
/// min(display_info.bpc (8 when undefined), max_requested_bpc rounded down
/// to even), then create_validate_stream_for_sink's steps of 2 down to 8
/// (the native encoders take 8, 10 and 12 bpc).
pub fn dp_depths(edid: &[u8], max_bpc: u8) -> Vec<otg::ColorDepth> {
    let sink = match edid_bpc(edid) {
        0 => 8,
        b => b,
    };
    let top = sink.min(max_bpc & !1);
    [
        (12, otg::ColorDepth::Bpc12),
        (10, otg::ColorDepth::Bpc10),
        (8, otg::ColorDepth::Bpc8),
    ]
    .into_iter()
    .filter(|&(b, _)| b <= top || b == 8)
    .map(|(_, d)| d)
    .collect()
}

/// Whether `lanes` at `rate` carries `cfg`'s compressed stream
/// (dc_dsc_stream_bandwidth_in_kbps, slice overhead included): 8b/10b only
/// with FEC, at FEC's efficiency; 128b/132b at its own, its stream
/// unpadded (apply_128b_132b_stream_overhead skips a DSC stream).
fn dsc_fits(
    timing: &Timing,
    cfg: crate::amdgpu_dsc::DscConfig,
    caps: DpCaps,
    lanes: u8,
    rate: DpRate,
) -> bool {
    let have = match rate {
        DpRate::Legacy(_) if !caps.fec => return false,
        DpRate::Legacy(r) => legacy_kbps(lanes, r, true),
        DpRate::Uhbr(r) => uhbr_kbps(lanes, r),
    };
    u64::from(crate::amdgpu_dsc::dsc_kbps(
        &dsc_timing(timing, cfg.bpc),
        cfg.bpp_x16,
        cfg.slices_h,
    )) <= have
}

/// The link a DSC stream lights on, as for an uncompressed one
/// (`dp_link`) but for its compressed bandwidth, which Linux's
/// link_decide_link_settings takes from the DSC config: the sink's maximum
/// 8b/10b link (with FEC) when that carries it, else the first 128b/132b
/// setting upward, lanes before rate.
pub fn dsc_link(
    timing: &Timing,
    cfg: crate::amdgpu_dsc::DscConfig,
    caps: DpCaps,
) -> Option<(u8, DpRate)> {
    let legacy = DpRate::Legacy(caps.rate);
    if dsc_fits(timing, cfg, caps, caps.lanes, legacy) {
        return Some((caps.lanes, legacy));
    }
    caps.uhbr_rates()
        .flat_map(|r| [1, 2, 4].map(|l| (l, DpRate::Uhbr(r))))
        .find(|&(l, r)| l <= caps.lanes && dsc_fits(timing, cfg, caps, l, r))
}

/// Admission shape for an alternative DP timing. Recompute its DSC with the
/// board's real DISPCLK limit, and after fallback require the configuration
/// that selection would produce to fit the link which actually trained.
/// The depths are amdgpu_dm's for the sink (`dp_depths` up to `max_bpc()`),
/// deepest first: at each the mode is carried uncompressed, else
/// compressed, else the next depth is tried (`dp_sst_stream`).
fn dp_offered_mode(timing: Timing, s: &Selection, max_dispclk_khz: u32) -> Option<dml::Mode> {
    let selected = match s.dsc {
        Some(cfg) => dsc_link(&s.timing, cfg, s.caps),
        None => dp_link_bpc(&s.timing, s.caps, depth_bpc(s.depth)),
    };
    let fell_back = selected != Some((s.lanes, s.rate));
    for depth in dp_depths(&s.edid, max_bpc()) {
        let bpc = depth_bpc(depth);
        if dp_link_bpc(&timing, s.caps, bpc).is_some() {
            if !fell_back || dp_fits_bpc(&timing, s.caps, s.lanes, s.rate, bpc) {
                return Some(plane_mode(timing, s.format));
            }
            continue;
        }
        let Some(cfg) = dp_dsc(&timing, s.caps, max_dispclk_khz, bpc) else {
            continue;
        };
        if fell_back && !dsc_fits(&timing, cfg, s.caps, s.lanes, s.rate) {
            continue;
        }
        return Some(dml::Mode {
            dsc: Some(dml::Dsc {
                slices: cfg.slices_h,
                bpp_x16: cfg.bpp_x16,
            }),
            ..plane_mode(timing, s.format)
        });
    }
    None
}

/// dcn4_soc_bb's DISPCLK maximum: DSC decisions before the board's levels
/// are known use it, and are redone with the board's (`refine_dsc`).
pub(super) const NOMINAL_DISPCLK_KHZ: u32 = 2_000_000;

/// The DSC view of an RGB stream at `bpc` (its display_color_depth).
fn dsc_timing(t: &Timing, bpc: u8) -> crate::amdgpu_dsc::DscTiming {
    crate::amdgpu_dsc::DscTiming {
        pix_clk_100hz: t.pixel_clock_khz * 10,
        h_active: t.h_active,
        h_total: t.h_total,
        v_active: t.v_active,
        v_total: t.v_total,
        bpc,
        encoding: crate::amdgpu_dsc::Encoding::Rgb,
    }
}

/// amdgpu_dm's SST DSC policy (apply_dsc_policy_for_stream) for a sink
/// without a dongle: a stream that no link carries uncompressed is
/// compressed by dc_dsc_compute_config to the highest bpp the sink's
/// maximum link (dc_link_get_link_cap) carries, with the highest link
/// encoding the link can code: 128b/132b at the best UHBR rate when the
/// sink, its repeaters and the board reach one (FEC is inherent there),
/// else 8b/10b with FEC. `dsc_link` then picks the link for the compressed
/// bandwidth. Each DSC takes at most four slices and DSC401's 5184-pixel
/// image, so the stream must fit the pipes DML gives it (`dml::dsc_shape`:
/// up to ODM 4:1, twelve slices on three pipes). The input is RGB at `bpc`
/// (the stream's display_color_depth), which the sink's DSC decoder must
/// take (DP_DSC_DEC_COLOR_DEPTH_CAP).
pub fn dp_dsc(
    timing: &Timing,
    caps: DpCaps,
    max_dispclk_khz: u32,
    bpc: u8,
) -> Option<crate::amdgpu_dsc::DscConfig> {
    use crate::amdgpu_dsc::{compute_config, LinkEncoding};
    let sink = caps.dsc?;
    let (target, encoding) = match caps.uhbr_rates().last() {
        Some(r) => (uhbr_kbps(caps.lanes, r), LinkEncoding::Dp128b132b),
        None if caps.fec => (
            legacy_kbps(caps.lanes, caps.rate, true),
            LinkEncoding::Dp8b10b,
        ),
        None => return None,
    };
    let cfg = compute_config(
        &sink,
        max_dispclk_khz,
        u32::try_from(target).ok()?,
        &dsc_timing(timing, bpc),
        encoding,
        false,
    )?;
    dml::dsc_shape(timing, cfg.slices_h, max_dispclk_khz).map(|_| cfg)
}

/// How a DP SST stream leaves: its link, DSC and depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpSstStream {
    pub lanes: u8,
    pub rate: DpRate,
    pub dsc: Option<crate::amdgpu_dsc::DscConfig>,
    pub depth: otg::ColorDepth,
}

/// amdgpu_dm_create_validate_stream_for_sink for a DP SST sink: each of
/// `depths` (`dp_depths`, deepest first) in turn, the stream at that
/// depth carried uncompressed when some link does (`dp_link_bpc`), else
/// compressed at that depth (apply_dsc_policy_for_stream: `dp_dsc`, which
/// also checks the native DSC shape DML gives it, then `dsc_link`), else
/// the next depth, as dc_validate_stream and dm_validate_stream_and_context
/// reject it. A deeper compressed stream is therefore preferred to a
/// shallower uncompressed one, as in Linux. None when no depth fits.
pub fn dp_sst_stream(
    timing: &Timing,
    caps: DpCaps,
    depths: &[otg::ColorDepth],
    max_dispclk_khz: u32,
) -> Option<DpSstStream> {
    depths.iter().find_map(|&depth| {
        let bpc = depth_bpc(depth);
        if let Some((lanes, rate)) = dp_link_bpc(timing, caps, bpc) {
            return Some(DpSstStream {
                lanes,
                rate,
                dsc: None,
                depth,
            });
        }
        let cfg = dp_dsc(timing, caps, max_dispclk_khz, bpc)?;
        let (lanes, rate) = dsc_link(timing, cfg, caps)?;
        Some(DpSstStream {
            lanes,
            rate,
            dsc: Some(cfg),
            depth,
        })
    })
}

/// Redo every DSC decision with the board's highest DISPCLK, as Linux's
/// clock manager reports it to dc_dsc_compute_config, and the link that
/// carries the new compressed bandwidth. A stream that no longer fits its
/// DSCs or a link is a link failure.
pub fn refine_dsc(soc: &dml::Soc, selections: &mut [Selection]) -> Result<(), ModesetError> {
    for s in selections.iter_mut().filter(|s| s.dsc.is_some()) {
        if let Some(m) = s.mst {
            // An MST stream keeps the link's fairness result (its PBN and
            // bpp); dc_dsc_compute_config with the board's DISPCLK must give
            // the same shape, which the native DSCs must take.
            let cfg = s.dsc.ok_or(ModesetError::Link)?;
            let caps = m.dsc.ok_or(ModesetError::Link)?.caps;
            let encoding = if s.uhbr() {
                crate::amdgpu_dsc::LinkEncoding::Dp128b132b
            } else {
                crate::amdgpu_dsc::LinkEncoding::Dp8b10b
            };
            let again = crate::amdgpu_dsc::compute_config(
                &caps,
                soc.dispclk_max_khz,
                0,
                &dsc_timing(&s.timing, cfg.bpc),
                encoding,
                false,
            )
            .ok_or(ModesetError::Link)?;
            if (again.slices_h, again.slices_v) != (cfg.slices_h, cfg.slices_v)
                || dml::dsc_shape(&s.timing, cfg.slices_h, soc.dispclk_max_khz).is_none()
            {
                return Err(ModesetError::Link);
            }
            continue;
        }
        if let Some(d) = FrlDscStream::of(s) {
            // HDMI FRL: the same policy at the selected (lowest carrying)
            // rate, which a compressed stream unchanged still fits, from the
            // selected depth down: a depth the board's DSCs cannot take
            // falls to the next compressed one (the raw FRL cap is not
            // kept, so a shallower raw stream is not retried here).
            let (sink, link) = s.caps.dsc.zip(d.cfg.frl).ok_or(ModesetError::Link)?;
            let rate = s.frl.ok_or(ModesetError::Link)?;
            let audio = frl_audio(s.audio, s.timing.v_active);
            let (rate, cfg) = [12, 10, 8]
                .into_iter()
                .filter(|&b| b <= d.cfg.bpc)
                .find_map(|bpc| {
                    frl_dsc(
                        &s.timing,
                        &sink,
                        link.max_rate,
                        rate,
                        audio,
                        soc.dispclk_max_khz,
                        d.vic,
                        bpc,
                    )
                })
                .ok_or(ModesetError::Link)?;
            s.frl = Some(rate);
            s.dsc = Some(cfg);
            s.depth = match cfg.bpc {
                12 => otg::ColorDepth::Bpc12,
                10 => otg::ColorDepth::Bpc10,
                _ => otg::ColorDepth::Bpc8,
            };
            continue;
        }
        // DP SST: the same depth search with the board's DISPCLK from the
        // selected depth down (uncompressed did not fit at the selected
        // one), so a configuration the board cannot compress at that
        // depth tries the next, as Linux's depth loop does.
        let below: Vec<_> = [
            otg::ColorDepth::Bpc12,
            otg::ColorDepth::Bpc10,
            otg::ColorDepth::Bpc8,
        ]
        .into_iter()
        .filter(|&d| depth_bpc(d) <= depth_bpc(s.depth))
        .collect();
        let found = dp_sst_stream(&s.timing, s.caps, &below, soc.dispclk_max_khz)
            .ok_or(ModesetError::Link)?;
        (s.lanes, s.rate, s.dsc, s.depth) = (found.lanes, found.rate, found.dsc, found.depth);
        if s.uhbr() {
            s.audio = None;
        }
    }
    Ok(())
}

/// One DP port's MST branch in a configuration: end device k (its
/// `MstLink::outputs` slot) lit on `pipes[k]` at `want(k)`, None dark.
pub struct MstRoute<'a> {
    pub port: usize,
    pub pipes: &'a [Option<u8>],
    pub want: &'a (dyn Fn(usize) -> Option<Timing> + Sync),
}
impl core::fmt::Debug for MstRoute<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MstRoute")
            .field("port", &self.port)
            .field("pipes", &self.pipes)
            .finish_non_exhaustive()
    }
}

/// Selection rounds after a link verifies below its sink's caps. Each
/// round records a strictly lower link, and the 8b/10b ladder has twelve
/// settings; real links settle within one or two.
const VERIFY_ROUNDS: usize = 4;

/// LINK_TRAINING_ATTEMPTS and LINK_TRAINING_RETRY_DELAY.
const UHBR_TRAINING_ATTEMPTS: u8 = 4;
const UHBR_RETRY_DELAY_MS: u64 = 50;

/// Linux's dp_lt_fallbacks, best bandwidth first, which its maximum
/// bandwidth fallback policy walks once a link can code 128b/132b.
const FALLBACKS: [(u8, DpRate); 21] = {
    use otg::UhbrRate::*;
    use DpRate::{Legacy as L, Uhbr as U};
    use LinkRate::*;
    [
        (4, U(Uhbr20)),
        (4, U(Uhbr13_5)),
        (2, U(Uhbr20)),
        (4, U(Uhbr10)),
        (2, U(Uhbr13_5)),
        (4, L(Hbr3)),
        (1, U(Uhbr20)),
        (2, U(Uhbr10)),
        (4, L(Hbr2)),
        (1, U(Uhbr13_5)),
        (2, L(Hbr3)),
        (1, U(Uhbr10)),
        (2, L(Hbr2)),
        (4, L(Hbr)),
        (1, L(Hbr3)),
        (4, L(Rbr)),
        (1, L(Hbr2)),
        (2, L(Hbr)),
        (2, L(Rbr)),
        (1, L(Hbr)),
        (1, L(Rbr)),
    ]
};

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
    /// HF DC_30bit_420 / DC_36bit_420, independent of RGB deep color.
    pub dc30_420: bool,
    pub dc36_420: bool,
    /// HF Max_FRL_Rate (drm_get_max_frl_rate's code: 1 = 3 x 3G ... 6 =
    /// 4 x 12G), zero for none or an unknown code.
    pub max_frl_rate: u8,
    /// The HF DSC 1.2 decoder (dc_edid_caps' frl_dsc_*), when declared.
    pub dsc: Option<crate::amdgpu_dsc::HdmiDscCaps>,
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
            if let Some(&frl) = forum.and_then(|f| f.get(3)) {
                caps.dc30_420 = frl & 1 != 0;
                caps.dc36_420 = frl & 2 != 0;
                caps.max_frl_rate = Some(frl >> 4).filter(|r| (1..=6).contains(r)).unwrap_or(0);
            }
            // HF-SCDS bytes 11-13 (drm_parse_dsc_info), parsed when byte 11
            // is present and nonzero; a zero byte 12 or 13 reads as absent.
            if let Some(&flags) = forum.and_then(|f| f.get(7)).filter(|&&b| b != 0) {
                let byte = |i: usize| forum.and_then(|f| f.get(i)).copied().filter(|&b| b != 0);
                caps.dsc = crate::amdgpu_dsc::HdmiDscCaps::parse(flags, byte(8), byte(9));
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

/// The tuple tests compare: depth, 4:2:0 and FRL rate of `hdmi_stream` at
/// DCN401's nominal DISPCLK, without its DSC configuration.
pub fn hdmi_output(
    caps: HdmiCaps,
    t: &Timing,
    max_bpc: u8,
    frl_cap: Option<FrlRate>,
    audio: Option<otg::AudioInfo>,
) -> Option<(otg::ColorDepth, bool, Option<FrlRate>)> {
    hdmi_stream(caps, t, max_bpc, frl_cap, audio, NOMINAL_DISPCLK_KHZ)
        .map(|s| (s.depth, s.ycbcr420, s.frl))
}

/// How an HDMI stream leaves: its depth, 4:2:0, FRL link and DSC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdmiStream {
    pub depth: otg::ColorDepth,
    pub ycbcr420: bool,
    pub frl: Option<FrlRate>,
    pub dsc: Option<crate::amdgpu_dsc::DscConfig>,
}

/// How an HDMI sink carries `t`: TMDS where `hdmi_format` finds a depth
/// (Linux keeps TMDS whenever it suffices), else FRL at `frl_cap` (none
/// when FRL is off or taken): RGB first unless the mode is 4:2:0-only,
/// then 4:2:0 where declared, each from the deepest declared depth up to
/// `max_bpc` down, as amdgpu_dm_create_validate_stream_for_sink tries them.
/// At each, as apply_dsc_policy_for_stream does for SIGNAL_TYPE_HDMI_FRL,
/// a stream whose raw bandwidth exceeds `frl_cap`'s is compressed from
/// that depth for a sink with an HF DSC decoder (`frl_dsc`, which needs
/// DSC_10bpc or DSC_12bpc for the deeper inputs; the native DSC path takes
/// RGB only, so 4:2:0 compressed streams are passed over), and any other is
/// carried uncompressed at the lowest carrying rate. A depth DSC cannot
/// form fails validation and the next is tried. FRL
/// reserves bandwidth for the sink's supported LPCM modes (layout 0 at SD
/// timings).
pub fn hdmi_stream(
    caps: HdmiCaps,
    t: &Timing,
    max_bpc: u8,
    frl_cap: Option<FrlRate>,
    audio: Option<otg::AudioInfo>,
    max_dispclk_khz: u32,
) -> Option<HdmiStream> {
    if let Some((depth, ycbcr420)) = hdmi_format(caps, t, max_bpc) {
        return Some(HdmiStream {
            depth,
            ycbcr420,
            frl: None,
            dsc: None,
        });
    }
    let cap = frl_cap?;
    let avi = hdmi_avi(caps, t);
    let stream_vic = crate::amdgpu_dsc::Vic {
        cta: avi.vic,
        hdmi: avi.hdmi_vic,
    };
    let dsc_caps = frl_dsc_caps(caps);
    let vic = narf_edid::modes::match_cea_mode(edid_mode(t));
    let listed = |map: [u64; 4]| vic != 0 && map[usize::from(vic / 64)] & 1 << (vic % 64) != 0;
    let only420 = listed(caps.y420_only);
    let audio = frl_audio(
        audio.and_then(|a| otg::frl_audio_info(a, t.v_active)),
        t.v_active,
    );
    // RGB first where allowed, then subsampling only for a declared mode.
    for ycbcr420 in [false, true] {
        if !ycbcr420 && only420 || ycbcr420 && !only420 && !listed(caps.y420_also) {
            continue;
        }
        let (dc30, dc36) = if ycbcr420 {
            (caps.dc30_420, caps.dc36_420)
        } else {
            (caps.dc30, caps.dc36)
        };
        for (bpc, declared, depth) in [
            (12, dc36, otg::ColorDepth::Bpc12),
            (10, dc30, otg::ColorDepth::Bpc10),
            (8, true, otg::ColorDepth::Bpc8),
        ] {
            if bpc > max_bpc || !declared {
                continue;
            }
            // dc_bandwidth_in_kbps_from_timing on the FRL link against
            // dc_link_frl_bandwidth_kbps of the verified cap.
            let raw = u64::from(t.pixel_clock_khz) * u64::from(bpc) * 3 / (1 + u64::from(ycbcr420));
            if raw > cap.kbps() {
                if let Some((sink, max_rate)) = &dsc_caps {
                    if !ycbcr420 {
                        let dispclk = max_dispclk_khz;
                        if let Some((rate, cfg)) =
                            frl_dsc(t, sink, *max_rate, cap, audio, dispclk, stream_vic, bpc)
                        {
                            return Some(HdmiStream {
                                depth,
                                ycbcr420,
                                frl: Some(rate),
                                dsc: Some(cfg),
                            });
                        }
                    }
                    // A compressed stream DSC cannot form fails validation.
                    continue;
                }
            }
            if let Some(rate) = frl_link(t, bpc, ycbcr420, cap, audio) {
                return Some(HdmiStream {
                    depth,
                    ycbcr420,
                    frl: Some(rate),
                    dsc: None,
                });
            }
        }
    }
    None
}

/// The bits per component of an output depth.
pub(super) fn depth_bpc(depth: otg::ColorDepth) -> u8 {
    match depth {
        otg::ColorDepth::Bpc8 => 8,
        otg::ColorDepth::Bpc10 => 10,
        otg::ColorDepth::Bpc12 => 12,
    }
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
        let Some(caps) = dp_caps(&port.path, sink) else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        // The depths create_validate_stream_for_sink tries, deepest first:
        // at each, uncompressed whenever a link carries the mode (Linux
        // enables DSC only when needed), otherwise DSC at that depth for the
        // maximum link, on the link its compressed bandwidth needs.
        let depths = dp_depths(&sink.edid, max_bpc);
        let Some(timing) = pick(index, &sink.edid, &|t| {
            dp_sst_stream(t, caps, &depths, NOMINAL_DISPCLK_KHZ).is_some()
        }) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let Some(DpSstStream {
            lanes,
            rate,
            dsc,
            depth,
        }) = dp_sst_stream(&timing, caps, &depths, NOMINAL_DISPCLK_KHZ)
        else {
            link_short = true;
            continue;
        };
        out.push(Selection {
            port: index,
            timing,
            lanes,
            rate,
            caps,
            edid,
            hdmi: false,
            scdc: false,
            depth,
            // HPO exposes only LPCM rates fitting its blanking budget; a
            // compressed stream's at its DSC bits per pixel and slices, as
            // build_audio_output hands dsc_cfg to check_audio_bandwidth_dp.
            audio: sink_audio_info(&sink.edid).and_then(|info| match rate {
                DpRate::Uhbr(rate) => otg::uhbr_audio_info_with(
                    info,
                    &timing,
                    u32::from(depth_bpc(depth)),
                    otg::UhbrSettings {
                        lanes,
                        rate,
                        mst: false,
                    },
                    dsc.as_ref(),
                ),
                _ => Some(info),
            }),
            avi: otg::Avi::default(),
            limited: false,
            ycbcr420: false,
            frl: None,
            dsc,
            mst: None,
            vrr: sink
                .dpcd
                .as_ref()
                .and_then(|d| crate::amdgpu_freesync::dp_sst_caps(&sink.edid, d)),
            format: otg::SurfaceFormat::Xrgb8888,
            planes: PlaneSetup::NONE,
            colorspace: 0,
            hdr: None,
            vsc_colorimetry: sink.dpcd.as_ref().is_some_and(|d| {
                crate::amdgpu_hdr::use_vsc_sdp_for_colorimetry(d[0], sink.dprx_feature)
            }),
        });
    }
    let mut frl_free = true;
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
        // DCN401 has one HPO FRL encoder: one FRL display at most.
        let frl_cap = frl_cap(caps).filter(|_| frl_free);
        let audio = sink_audio_info(&sink.edid);
        let Some(timing) = pick(index, &sink.edid, &|t| {
            hdmi_output(caps, t, max_bpc, frl_cap, audio).is_some()
        }) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let Some(HdmiStream {
            depth,
            ycbcr420,
            frl,
            dsc,
        }) = hdmi_stream(caps, &timing, max_bpc, frl_cap, audio, NOMINAL_DISPCLK_KHZ)
        else {
            link_short = true;
            continue;
        };
        frl_free &= frl.is_none();
        out.push(Selection {
            port: index,
            timing,
            lanes: 0,
            rate: DpRate::Legacy(LinkRate::Rbr),
            // A compressed FRL stream keeps the sink's HF DSC decoder for
            // `refine_dsc`.
            caps: DpCaps {
                dsc: dsc.and(frl_dsc_caps(caps)).map(|(sink, _)| sink),
                ..DpCaps::NONE
            },
            edid,
            hdmi: true,
            scdc: caps.scdc,
            depth,
            audio: if frl.is_some() {
                audio.and_then(|a| otg::frl_audio_info(a, timing.v_active))
            } else {
                audio
            },
            avi: hdmi_avi(caps, &timing),
            limited: false,
            ycbcr420,
            frl,
            dsc,
            mst: None,
            // HDMI FreeSync needs the AMD VSDB, which is not parsed.
            vrr: None,
            format: otg::SurfaceFormat::Xrgb8888,
            planes: PlaneSetup::NONE,
            colorspace: 0,
            hdr: None,
            vsc_colorimetry: false,
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
        match dml::admit_native(soc, &modes[..n]) {
            Ok(plans) => return Ok(plans),
            Err(e) if n <= 1 => return Err(e),
            Err(_) => n -= 1,
        }
    }
}

/// Link settings to try for `timing` from (`lanes`, `rate`), best first. A
/// 128b/132b link walks Linux's bandwidth-ordered fallback table from that
/// setting, as decide_fallback_link_setting's maximum bandwidth policy
/// does, but only through its 128b/132b settings: the timing (and its HPO
/// output mux) is staged for the encoding before the link trains, so a
/// mode that needs 8b/10b instead is a new selection. An 8b/10b link keeps
/// narf's ladder (`link_candidates`). Settings beyond `caps` or that cannot
/// carry the mode are never tried.
#[cfg(feature = "kernel-test")]
pub fn dp_candidates(timing: &Timing, caps: DpCaps, lanes: u8, rate: DpRate) -> Vec<(u8, DpRate)> {
    dp_candidates_bpc(timing, caps, lanes, rate, 8)
}
/// `dp_candidates` for RGB at `bpc`.
pub fn dp_candidates_bpc(
    timing: &Timing,
    caps: DpCaps,
    lanes: u8,
    rate: DpRate,
    bpc: u8,
) -> Vec<(u8, DpRate)> {
    if let DpRate::Legacy(r) = rate {
        return legacy_candidates(lanes, r, |l, r| link_fits_bpc(timing, l, r, bpc))
            .into_iter()
            .map(|(l, r)| (l, DpRate::Legacy(r)))
            .filter(|&(l, r)| dp_fits_bpc(timing, caps, l, r, bpc))
            .collect();
    }
    let usable = |(l, r): (u8, DpRate)| {
        l <= caps.lanes
            && match r {
                DpRate::Legacy(_) => false,
                DpRate::Uhbr(r) => caps.uhbr_rates().any(|u| u == r),
            }
            && dp_fits_bpc(timing, caps, l, r, bpc)
    };
    FALLBACKS
        .into_iter()
        .skip_while(|&setting| setting != (lanes, rate))
        .filter(|&setting| usable(setting))
        .collect()
}

/// Link settings to try, best first: drop the rate; below RBR halve the lanes
/// and restart from this attempt's starting rate (narf's DP fallback
/// ladder, as in `dp_link_training`). Settings that cannot carry the mode are
/// never tried.
#[cfg(feature = "kernel-test")]
pub fn link_candidates(timing: &Timing, lanes: u8, rate: LinkRate) -> Vec<(u8, LinkRate)> {
    legacy_candidates(lanes, rate, |l, r| link_fits(timing, l, r))
}

fn legacy_candidates(
    lanes: u8,
    rate: LinkRate,
    mut fits: impl FnMut(u8, LinkRate) -> bool,
) -> Vec<(u8, LinkRate)> {
    let mut out = Vec::new();
    let mut l = lanes;
    while l >= 1 {
        let mut r = Some(rate);
        while let Some(current) = r {
            if fits(l, current) {
                out.push((l, current));
            }
            r = current.next_lower();
        }
        l /= 2;
    }
    out
}

/// Preserve the staged DSC/PPS and DML plan while trying lower link settings
/// that still carry the compressed stream, as Linux's fallback keeps the
/// stream's DSC config: narf's 8b/10b ladder for an 8b/10b link, Linux's
/// bandwidth-ordered table through its 128b/132b settings for a 128b/132b
/// one. A configuration needing a different compressed bpp requires
/// re-admission.
fn selected_dp_candidates(s: &Selection) -> Vec<(u8, DpRate)> {
    let Some(cfg) = s.dsc else {
        return dp_candidates_bpc(&s.timing, s.caps, s.lanes, s.rate, depth_bpc(s.depth));
    };
    if !matches!(s.lanes, 1 | 2 | 4) {
        return Vec::new();
    }
    let usable = |l: u8, r: DpRate| l <= s.caps.lanes && dsc_fits(&s.timing, cfg, s.caps, l, r);
    match s.rate {
        DpRate::Legacy(rate) => legacy_candidates(s.lanes, rate, |l, r| {
            r as u8 <= s.caps.rate as u8 && usable(l, DpRate::Legacy(r))
        })
        .into_iter()
        .map(|(l, r)| (l, DpRate::Legacy(r)))
        .collect(),
        DpRate::Uhbr(_) => FALLBACKS
            .into_iter()
            .skip_while(|&setting| setting != (s.lanes, s.rate))
            .filter(|&(l, r)| match r {
                DpRate::Legacy(_) => false,
                DpRate::Uhbr(u) => s.caps.uhbr_rates().any(|c| c == u) && usable(l, r),
            })
            .collect(),
    }
}

fn admitted_modes(
    soc: &dml::Soc,
    lit: &[Modeset],
    k: usize,
    timings: impl IntoIterator<Item = Timing>,
    candidate: impl Fn(Timing) -> Option<dml::Mode>,
) -> [Option<Timing>; MAX_MODES] {
    let current = lit[k].selection.timing;
    let mut modes = [None; MAX_MODES];
    let mut n = 0;
    let mut joint: Vec<_> = lit.iter().map(|m| selection_mode(&m.selection)).collect();
    for t in timings {
        if n == MAX_MODES {
            break;
        }
        if t != current {
            let Some(mode) = candidate(t) else { continue };
            joint[k] = mode;
            if dml::admit_native(soc, &joint).is_err() {
                continue;
            }
        }
        modes[n] = Some(t);
        n += 1;
    }
    if !modes.contains(&Some(current)) {
        modes[n.min(MAX_MODES - 1)] = Some(current);
    }
    modes
}

/// Linear XRGB8888 pitch in pixels: 64-pixel (256-byte) aligned.
pub fn mode(timing: Timing) -> dml::Mode {
    plane_mode(timing, otg::SurfaceFormat::Xrgb8888)
}

/// A `format` plane on `timing`: its bytes per pixel and its pitch in
/// pixels, the line rounded up to whole 256-byte requests.
pub fn plane_mode(timing: Timing, format: otg::SurfaceFormat) -> dml::Mode {
    let mut mode = dml::Mode {
        timing,
        pitch: format.pitch_bytes(timing.h_active) / format.bytes_per_pixel(),
        bytes_per_pixel: format.bytes_per_pixel(),
        ycbcr420: false,
        dsc: None,
        planes: [None; dml::MAX_PLANES],
    };
    // A 4:2:0 primary is never the packed full-frame plane: DML takes it
    // as the explicit plane SPL scales its chroma for.
    if format.is_video() {
        let setup = PlaneSetup {
            primary: Some(PlaneGeometry {
                src_x: 0,
                src_y: 0,
                width: timing.h_active,
                height: timing.v_active,
                dst: crate::amdgpu_dcn401_spl::Rect::new(
                    0,
                    0,
                    timing.h_active as i32,
                    timing.v_active as i32,
                ),
                rotation: crate::amdgpu_dcn401_spl::Rotation::R0,
                blend: otg::Blend::default_for(format),
                surface: otg::PlaneSurface::LINEAR,
                fb_size: (timing.h_active, timing.v_active),
            }),
            ..PlaneSetup::NONE
        };
        mode = with_planes(mode, format, &setup);
    }
    mode
}

impl Selection {
    /// amdgpu_dm_get_output_color_space for this stream: its Colorspace,
    /// pixel encoding (RGB, or YCbCr for 4:2:0), pixel rate and "Broadcast
    /// RGB" (`limited`).
    pub fn color_space(&self) -> crate::amdgpu_hdr::DcColorSpace {
        crate::amdgpu_hdr::output_color_space(
            self.colorspace,
            !self.ycbcr420,
            false,
            self.timing.pixel_clock_khz.saturating_mul(10),
            self.limited,
        )
    }
    /// The output-format part of the blank request: depth, the color space
    /// and the range and encoding it implies.
    pub fn blank_request(&self, pipe: u8) -> otg::BlankRequest {
        use crate::amdgpu_hdr::DcColorSpace as C;
        let colorspace = self.color_space();
        otg::BlankRequest {
            pipe,
            depth: self.depth,
            limited: matches!(colorspace, C::SrgbLimited | C::Rgb2020Limited),
            ycbcr420: self.ycbcr420,
            colorspace,
        }
    }
    /// The HDR packet amdgpu_dm_fill_hdr_info_packet builds for this
    /// stream's connector type, while HDR_OUTPUT_METADATA is set.
    pub fn hdr_packet(&self) -> Option<crate::amdgpu_hdr::InfoPacket> {
        let connector = if self.hdmi {
            crate::amdgpu_hdr::HdrConnector::Hdmi
        } else {
            crate::amdgpu_hdr::HdrConnector::DisplayPort
        };
        self.hdr
            .as_ref()
            .map(|m| crate::amdgpu_hdr::hdr_info_packet(Some(m), connector))
    }
    /// The VSC/HDR SDPs a 128b/132b stream sends (resource_build_info_frame
    /// for a DP signal).
    pub fn uhbr_sdp(&self) -> otg::UhbrSdp {
        otg::UhbrSdp {
            vsc_colorimetry: self.vsc_colorimetry,
            hdr: self.hdr_packet(),
        }
    }
    /// A 128b/132b (UHBR) DP link.
    pub fn uhbr(&self) -> bool {
        matches!(self.rate, DpRate::Uhbr(_))
    }
    /// amdgpu_dm's vrr_supported: a VRR-capable sink whose range holds this
    /// mode's refresh. The stream then sets IGNORE_MSA_TIMING_PARAM.
    pub fn vrr_supported(&self) -> bool {
        self.mst.is_none() && self.vrr.is_some_and(|r| r.supports(&self.timing))
    }
    /// The DRR totals VRR_ENABLED runs this mode at, if any.
    pub fn drr(&self) -> Option<crate::amdgpu_freesync::Drr> {
        self.vrr
            .filter(|_| self.vrr_supported())
            .and_then(|r| crate::amdgpu_freesync::drr(&self.timing, r))
    }
}

/// The admission mode of a selected sink: its timing, as 4:2:0 output
/// when it leaves so, with its planes as DC hands them to DML21 (each
/// plane's SPL viewport, ratios and taps on the stream).
pub fn selection_mode(s: &Selection) -> dml::Mode {
    let mode = dml::Mode {
        ycbcr420: s.ycbcr420,
        dsc: s.dsc.map(|c| dml::Dsc {
            slices: c.slices_h,
            bpp_x16: c.bpp_x16,
        }),
        ..plane_mode(s.timing, s.format)
    };
    with_planes(mode, s.format, &s.planes)
}

/// `mode` (one stream's admission mode) with the planes `setup`, primary
/// in `format`: each plane as DC hands it to DML21 after SPL on the stream.
pub fn with_planes(
    mut mode: dml::Mode,
    format: otg::SurfaceFormat,
    setup: &PlaneSetup,
) -> dml::Mode {
    let (primary, overlays) = stream_planes(
        &mode.timing,
        mode.ycbcr420,
        format,
        setup,
        (0, otg::SplitPipes::NONE, otg::SplitPipes::NONE),
        &[None; otg::MAX_OVERLAYS],
    );
    mode.pitch = format.pitch_bytes(mode.timing.h_active) / format.bytes_per_pixel();
    mode.bytes_per_pixel = format.bytes_per_pixel();
    mode.planes = [None; dml::MAX_PLANES];
    if primary.plane.is_some() {
        mode.planes[0] = Some(primary.dml_plane());
    }
    for (slot, o) in mode.planes[1..].iter_mut().zip(overlays.iter().flatten()) {
        *slot = Some(o.dml_plane());
    }
    mode
}

/// The free pipes of a configuration lit on `used` (by bit), taken from
/// the top: none left is DML's `Pipes` (DML counts every DPP, so a
/// configuration it admits always has them; this assigns them).
struct FreePipes(u8);
impl FreePipes {
    fn take(&mut self) -> Result<u8, ModesetError> {
        let q = (0..4u8)
            .rev()
            .find(|&q| self.0 & 1 << q == 0)
            .ok_or(ModesetError::Display(otg::Error::Admission(
                dml::Error::Pipes,
            )))?;
        self.0 |= 1 << q;
        Ok(q)
    }
    fn split(&mut self, further: usize) -> Result<otg::SplitPipes, ModesetError> {
        let mut pipes = [0u8; 3];
        for p in pipes.iter_mut().take(further) {
            *p = self.take()?;
        }
        otg::SplitPipes::new(&pipes[..further.min(3)])
            .ok_or(ModesetError::Display(otg::Error::Invalid))
    }
}

/// Each lit display's primary MPC slices beyond its own pipe (DML's NoOfDPP
/// for an MPC-combined primary in ODM bypass), from the pipes no display,
/// ODM segment or earlier slice took, from the top
/// (acquire_dpp_pipe_and_add_mpc_slice's bottom pipe).
pub fn mpc_pipes(
    plans: &[dml::Plan],
    pipes: &[u8],
    odm: &[otg::SplitPipes],
) -> Result<Vec<otg::SplitPipes>, ModesetError> {
    let mut free = FreePipes(
        pipes.iter().fold(0u8, |m, &p| m | 1 << p) | odm.iter().fold(0, |m, o| m | o.mask()),
    );
    plans
        .iter()
        .map(|plan| {
            let slices = plan.plane(0).map_or(1, |p| p.mpc_slices(plan.pipes));
            free.split(usize::from(slices.max(1)) - 1)
        })
        .collect()
}

/// Each lit display's overlay pipes: free pipes (neither a display's nor
/// an ODM or primary MPC pipe, nor another overlay's), taken from the top
/// as ODM pipes are, one per overlay and one more per further ODM segment
/// of its stream or MPC slice of its own. A configuration whose planes
/// need more pipes than are free is refused (DML counts the pipes too;
/// this assigns them).
pub fn overlay_pipes(
    selections: &[Selection],
    plans: &[dml::Plan],
    pipes: &[u8],
    (odm, mpc): (&[otg::SplitPipes], &[otg::SplitPipes]),
) -> Result<Vec<OverlayPipes>, ModesetError> {
    overlay_pipes_of(plans, pipes, (odm, mpc), |i, k| {
        selections
            .get(i)
            .is_some_and(|s| s.planes.overlays[k].is_some())
    })
}
/// `overlay_pipes` for the overlays `present(display, k)` names.
fn overlay_pipes_of(
    plans: &[dml::Plan],
    pipes: &[u8],
    (odm, mpc): (&[otg::SplitPipes], &[otg::SplitPipes]),
    present: impl Fn(usize, usize) -> bool,
) -> Result<Vec<OverlayPipes>, ModesetError> {
    let mut free = FreePipes(
        pipes.iter().fold(0u8, |m, &p| m | 1 << p)
            | odm.iter().chain(mpc).fold(0, |m, o| m | o.mask()),
    );
    let mut out = Vec::with_capacity(plans.len());
    for (i, plan) in plans.iter().enumerate() {
        let mut stack = [None; otg::MAX_OVERLAYS];
        for (k, slot) in stack.iter_mut().enumerate() {
            if present(i, k) {
                let pipe = free.take()?;
                let odm = free.split(usize::from(plan.pipes.max(1)) - 1)?;
                let slices = plan.plane(k + 1).map_or(1, |p| p.mpc_slices(plan.pipes));
                let mpc = free.split(usize::from(slices.max(1)) - 1)?;
                *slot = Some(PlanePipes { pipe, odm, mpc });
            }
        }
        out.push(stack);
    }
    Ok(out)
}

/// Every lit display's further pipes, as DML split it (Linux's
/// dml21_map_dc_state_into_dml_display_cfg then
/// resource_update_pipes_for_stream_with_slice_count and
/// resource_update_pipes_for_plane_with_slice_count): first each stream's
/// ODM segments, then each primary's MPC slices, then each overlay's pipes,
/// all from the top of the pipes the displays leave free.
pub fn display_pipes(
    selections: &[Selection],
    plans: &[dml::Plan],
    pipes: &[u8],
) -> Result<Vec<DisplayPipes>, ModesetError> {
    let odm = odm_pipes(plans, pipes)?;
    let mpc = mpc_pipes(plans, pipes, &odm)?;
    let overlays = overlay_pipes(selections, plans, pipes, (&odm, &mpc))?;
    Ok(joined(odm, mpc, overlays))
}
/// `display_pipes` for the planes the plans were admitted with (each
/// plan's overlays the planes after its primary).
pub fn plan_pipes(plans: &[dml::Plan], pipes: &[u8]) -> Result<Vec<DisplayPipes>, ModesetError> {
    let odm = odm_pipes(plans, pipes)?;
    let mpc = mpc_pipes(plans, pipes, &odm)?;
    let overlays = overlay_pipes_of(plans, pipes, (&odm, &mpc), |i, k| {
        plans
            .get(i)
            .is_some_and(|p| p.mode.plane_list().count() > k + 1)
    })?;
    Ok(joined(odm, mpc, overlays))
}
fn joined(
    odm: Vec<otg::SplitPipes>,
    mpc: Vec<otg::SplitPipes>,
    overlays: Vec<OverlayPipes>,
) -> Vec<DisplayPipes> {
    odm.into_iter()
        .zip(mpc)
        .zip(overlays)
        .map(|((odm, mpc), overlays)| DisplayPipes { odm, mpc, overlays })
        .collect()
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
pub fn pipe_clock_request(pipe: u8, plan: &dml::Plan, selection: &Selection) -> dccg::Request {
    let pixel_hz = u64::from(plan.mode.timing.pixel_clock_khz) * 1000;
    dccg::Request {
        pipe,
        dpp_khz: plan.clocks.dppclk_khz,
        // dcn401_calculate_dccg_tmds_div_value: 4:2:0 divides by two. FRL
        // runs the full pixel clock from DTBCLK through the DP DTO.
        pixel: if selection.frl.is_some() {
            dccg::PixelClock::HdmiFrl { pixel_hz }
        } else if selection.hdmi {
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

/// Each plan's further ODM pipes: an n-pipe plan takes the n - 1 highest
/// pipes no display of the configuration is lit on and no other ODM display
/// took, left to right in that order. Admission counts every DPP, so a free
/// pipe exists for each.
pub fn odm_pipes(plans: &[dml::Plan], pipes: &[u8]) -> Result<Vec<otg::SplitPipes>, ModesetError> {
    let mut free = FreePipes(pipes.iter().fold(0u8, |m, &p| m | 1 << p));
    plans
        .iter()
        .map(|plan| {
            free.split(usize::from(plan.pipes.max(1)) - 1)
                .map_err(|_| ModesetError::Display(otg::Error::Busy))
        })
        .collect()
}

/// The timing a selection's link needs: TMDS, DP through the DIO
/// encoders, or (for a 128b/132b link) DP through the HPO encoders.
pub fn timing_request(pipe: u8, plan: &dml::Plan, selection: &Selection) -> otg::Request {
    otg::Request {
        pipe,
        timing: plan.mode.timing,
        sync: plan.sync,
        signal: if selection.frl.is_some() {
            otg::Signal::HdmiFrl
        } else if selection.hdmi {
            otg::Signal::Tmds
        } else if selection.uhbr() {
            otg::Signal::HpoDisplayPort
        } else {
            otg::Signal::DisplayPort
        },
        ycbcr420: plan.mode.ycbcr420,
        dsc: selection.dsc,
        odm: otg::SplitPipes::NONE,
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
    /// this owner stopped. Withdraw and drain all CPU views of retained
    /// surfaces; leave each activation unpublished until success.
    /// Exclude firmware/FAMS and concurrent
    /// display/hub/VM/IRQ/clock/reset/power/link writers; retain every owner
    /// and any allocations this API has not reclaimed, including on cancellation.
    /// A returned failure
    /// attempts to unwind checkpointed startup and retire the unpublished pipe
    /// using native proofs. Failed/in-flight owners and uncertain allocations
    /// stay held.
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
        // A link verified below the sink's caps selects and admits again
        // (new DSC geometry included); each round lowers that link.
        for _ in 0..VERIFY_ROUNDS {
            // SAFETY: the caller's obligations.
            match unsafe { self.modeset_display_once(pipe, &mut fill, want) }.await {
                Err(ModesetError::LinkReduced) => continue,
                result => return result,
            }
        }
        Err(ModesetError::Link)
    }
    /// One selection/admission/lighting round of `modeset_display_mode`.
    /// # Safety
    /// As for `modeset_display`.
    async unsafe fn modeset_display_once(
        &mut self,
        pipe: u8,
        mut fill: impl FnMut(u32, &mut [u32]),
        want: Option<Timing>,
    ) -> Result<Modeset, ModesetError> {
        self.teardowns.check_idle()?;
        self.modesets.check_stopped()?;
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
        selection.format = plane_format(pipe);
        selection.planes = plane_setup(pipe);
        (selection.colorspace, selection.hdr) = output_color(pipe);
        self.select_display(pipe)?;
        let soc = self.prepare_configuration(&[selection]).await?;
        refine_dsc(&soc, core::slice::from_mut(&mut selection))?;
        let plans = admit_displays(&soc, &[selection]).map_err(otg::Error::Admission)?;
        let pipes = self.prepare_pipes(&[selection], &plans, &[pipe]).await?;
        // SAFETY: the caller's obligations.
        let mut lit = unsafe {
            self.light(pipe, pipes[0], selection, plans[0], &mut |_, y, row| {
                fill(y, row)
            })
        }
        .await?;
        lit.modes = self.offered_modes(&soc, &[lit], 0, &edid_of(&ports, &paths, &selection));
        self.modesets.retain(lit);
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
    /// Completed displays remain in display_modesets even when this future is
    /// cancelled before returning their configuration.
    /// # Safety
    /// As for `modeset_display`: every display of this owner stopped.
    pub async unsafe fn modeset_displays(
        &mut self,
        fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipe_of: impl Fn(usize) -> Option<u8>,
    ) -> Result<Configuration, ModesetError> {
        // SAFETY: the caller's obligations.
        unsafe { self.modeset_routed(fill, want, pipe_of, None) }.await
    }
    /// `modeset_displays` with one DP port's MST branch beside the board's
    /// SST/HDMI sinks, all one configuration: the branch started and probed,
    /// board sinks (that root excluded) and end devices selected, then
    /// clocks and joint DML admission for every stream, and each display lit
    /// on its pipe. Board port p is lit on `pipe_of(p)` at `want(p)`; end
    /// device k on `mst.pipes[k]` at `mst.want(k)`. Pipes must be distinct.
    /// Admission truncates in pipe order. Dark board sinks and end devices
    /// are admitted beside every running stream.
    /// # Safety
    /// As for `modeset_displays`.
    pub async unsafe fn modeset_routed(
        &mut self,
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipe_of: impl Fn(usize) -> Option<u8>,
        mst: Option<MstRoute<'_>>,
    ) -> Result<Configuration, ModesetError> {
        // As `modeset_display_mode`: when the first display's link verifies
        // lower, nothing is lit yet and the configuration is chosen again.
        // A later display's reduction is returned in `failed`.
        for _ in 0..VERIFY_ROUNDS {
            // SAFETY: the caller's obligations.
            match unsafe { self.modeset_displays_once(&mut fill, &want, &pipe_of, mst.as_ref()) }
                .await
            {
                Err(ModesetError::LinkReduced) => continue,
                result => return result,
            }
        }
        Err(ModesetError::Link)
    }
    /// One selection/admission/lighting round of `modeset_displays`.
    /// # Safety
    /// As for `modeset_displays`.
    async unsafe fn modeset_displays_once(
        &mut self,
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipe_of: impl Fn(usize) -> Option<u8>,
        mst: Option<&MstRoute<'_>>,
    ) -> Result<Configuration, ModesetError> {
        self.teardowns.check_idle()?;
        self.modesets.check_stopped()?;
        self.sst_outputs.clear();
        if let Some(route) = mst {
            self.start_mst_route(route).await?;
        }
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let paths = self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .to_vec();
        let plan = match mst {
            Some(route) => Some(self.plan_mst_route(route, &ports)?),
            None => None,
        };
        // The MST root is the branch's, never a board SST sink.
        let root = mst.and_then(|r| paths.get(r.port).copied());
        let board: Vec<display::Port> = ports
            .iter()
            .filter(|p| Some(p.path) != root)
            .cloned()
            .collect();
        self.update_sst_outputs(None, &paths, &board, &[]);
        let mut routed: Vec<(Selection, u8)> = match select_all(&paths, &board, max_bpc(), &want) {
            Ok(selections) => selections,
            // A connected sink without a carrying preferred mode can still
            // offer other modes; an all-off configuration has no stream work.
            Err(ModesetError::NoSink | ModesetError::Link) => Vec::new(),
            Err(e) => return Err(e),
        }
        .into_iter()
        .filter_map(|s| Some((s, pipe_of(s.port).filter(|&p| p < 4)?)))
        .collect();
        if let Some(plan) = &plan {
            routed.extend(plan.selections.iter().copied());
        }
        // Admission keeps a leading set: pipe order decides who stays dark.
        routed.sort_by_key(|&(_, pipe)| pipe);
        if routed.windows(2).any(|w| w[0].1 == w[1].1) {
            return Err(ModesetError::Display(otg::Error::Invalid));
        }
        let (mut selections, pipes): (Vec<Selection>, Vec<u8>) = routed.into_iter().unzip();
        // "Broadcast RGB" is RGB's: YCbCr is limited range by itself.
        let limited = limited_range(broadcast_rgb());
        for (s, &pipe) in selections.iter_mut().zip(&pipes) {
            s.limited = limited && !s.ycbcr420;
            s.format = plane_format(pipe);
            s.planes = plane_setup(pipe);
            (s.colorspace, s.hdr) = output_color(pipe);
        }
        self.select_display(pipes.first().copied().unwrap_or(0))?;
        let soc = self.prepare_configuration(&selections).await?;
        self.update_sst_outputs(Some(&soc), &paths, &board, &[]);
        if selections.is_empty() {
            if let Some(plan) = &plan {
                self.finish_mst_plan(plan, &soc, &[]);
            }
            return Ok(Configuration {
                displays: Vec::new(),
                failed: None,
            });
        }
        refine_dsc(&soc, &mut selections)?;
        let plans = admit_displays(&soc, &selections).map_err(otg::Error::Admission)?;
        selections.truncate(plans.len());
        let extra = self.prepare_pipes(&selections, &plans, &pipes).await?;
        let mut lit = Vec::with_capacity(selections.len());
        let mut failed = None;
        for (((selection, plan), &pipe), &extra) in
            selections.iter().zip(&plans).zip(&pipes).zip(&extra)
        {
            // SAFETY: the caller's obligations; every earlier display is lit
            // in its own slot and left to it by each step.
            match unsafe { self.light(pipe, extra, *selection, *plan, &mut fill) }.await {
                Ok(m) => lit.push(m),
                Err(e) if lit.is_empty() => return Err(e),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        for k in 0..lit.len() {
            let s = lit[k].selection;
            let edid = match (&plan, s.mst) {
                (Some(plan), Some(_)) => Self::mst_plan_edid(plan, &s).unwrap_or_default(),
                _ => edid_of(&ports, &paths, &s),
            };
            lit[k].modes = self.offered_modes(&soc, &lit, k, &edid);
            self.modesets.retain(lit[k]);
        }
        self.update_sst_outputs(Some(&soc), &paths, &board, &lit);
        if let (Some(plan), None) = (&plan, failed) {
            let running: Vec<_> = lit.iter().map(|m| m.selection).collect();
            self.finish_mst_plan(plan, &soc, &running);
        }
        Ok(Configuration {
            displays: lit,
            failed,
        })
    }
    /// Query the DPM levels admission needs, install clock floors for a
    /// nonempty configuration, and return the board's admission inputs.
    pub(super) async fn prepare_configuration(
        &mut self,
        selections: &[Selection],
    ) -> Result<dml::Soc, ModesetError> {
        // An all-off MST branch still needs real board limits to enumerate
        // modes. Query them without claiming a display or setting clock floors.
        if selections.is_empty() {
            self.start_display_clocks()
                .await
                .map_err(ModesetError::Clocks)?;
            return Ok(self.display_soc()?);
        }
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
    /// plan), then each display's pipe clocks on `pipes` (and a DPP-only
    /// clock on each further ODM, MPC and overlay pipe, at its plane's
    /// DPPCLK), all while every display is stopped. Returns each display's
    /// further pipes.
    pub(super) async fn prepare_pipes(
        &mut self,
        selections: &[Selection],
        plans: &[dml::Plan],
        pipes: &[u8],
    ) -> Result<Vec<DisplayPipes>, ModesetError> {
        let extra = display_pipes(selections, plans, pipes)?;
        let mut request = clock_request(&plans[0]);
        request.displays = plans.len() as u8;
        // dcn401_update_clocks: an FRL stream holds DTBCLK at its highest
        // DPM level.
        if selections.iter().any(|s| s.frl.is_some()) {
            request.dtb_khz = self.top_dtb_khz()?;
        }
        self.prepare_display_clocks(request)
            .await
            .map_err(ModesetError::Clocks)?;
        for ((s, plan), &pipe) in selections.iter().zip(plans).zip(pipes) {
            self.prepare_display_pipe_clocks(pipe_clock_request(pipe, plan, s))
                .await
                .map_err(ModesetError::PipeClocks)?;
            if s.dsc.is_some() {
                self.start_display_dscclk(pipe)?;
            }
        }
        for ((s, plan), d) in selections.iter().zip(plans).zip(&extra) {
            for q in d.odm {
                self.prepare_display_pipe_clocks(dccg::Request {
                    pipe: q,
                    dpp_khz: plan.clocks.dppclk_khz,
                    pixel: dccg::PixelClock::OdmSegment,
                })
                .await
                .map_err(ModesetError::PipeClocks)?;
                if s.dsc.is_some() {
                    self.start_display_dscclk(q)?;
                }
            }
            // The primary's further MPC slices: DPP-only clocks at its DPPCLK.
            for q in d.mpc {
                self.prepare_display_pipe_clocks(dccg::Request {
                    pipe: q,
                    dpp_khz: plan.clocks.dppclk_khz,
                    pixel: dccg::PixelClock::OdmSegment,
                })
                .await
                .map_err(ModesetError::PipeClocks)?;
            }
        }
        for (plan, d) in plans.iter().zip(&extra) {
            for (k, o) in d.overlays.iter().enumerate() {
                let Some(o) = *o else { continue };
                let plane = plan
                    .plane(k + 1)
                    .ok_or(ModesetError::Display(otg::Error::Invalid))?;
                for pipe in o.all() {
                    self.prepare_display_pipe_clocks(dccg::Request {
                        pipe,
                        dpp_khz: plane.dppclk_khz,
                        pixel: dccg::PixelClock::OdmSegment,
                    })
                    .await
                    .map_err(ModesetError::PipeClocks)?;
                }
            }
        }
        Ok(extra)
    }
    /// Light one admitted display on `pipe` (its display slot too), with its
    /// clocks prepared: surface, timing, OPP, DPP, MPC, requestor and
    /// deadlines, then its link, video and scanout.
    /// # Safety
    /// As for `modeset_display`, except that other displays of this owner
    /// may be lit in their own slots.
    pub(super) async unsafe fn light(
        &mut self,
        pipe: u8,
        pipes: DisplayPipes,
        selection: Selection,
        plan: dml::Plan,
        fill: &mut impl FnMut(u8, u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
        self.select_display(pipe)?;
        self.teardowns
            .begin_activation(pipe, pipes.odm, &selection)?;
        // SAFETY: the caller owns this unpublished activation and every writer.
        match unsafe { self.light_inner(pipe, pipes, selection, plan, fill) }.await {
            Ok(m) => {
                // No await between native completion and retained ownership.
                // A later pipe or platform adoption can suspend or be dropped.
                self.modesets.retain(m);
                self.teardowns.finish_activation(pipe, true);
                Ok(m)
            }
            Err(e) => {
                self.teardowns.finish_activation(pipe, false);
                // SAFETY: no Modeset was returned or CPU scanout published.
                // Native guards validate each checkpoint; cleanup failure
                // retains the journal and memory. Preserve the original error.
                let _ = unsafe { self.abort_modeset_activation(pipe) }.await;
                Err(e)
            }
        }
    }
    /// The activation body, covered by light's retained in-flight marker.
    /// # Safety
    /// As for light.
    async unsafe fn light_inner(
        &mut self,
        pipe: u8,
        pipes: DisplayPipes,
        selection: Selection,
        plan: dml::Plan,
        fill: &mut impl FnMut(u8, u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
        let odm = pipes.odm;
        let (primary, overlays) = plane_requests(&selection, pipe, &pipes);
        let (width, height) = (primary.width, primary.height);
        // Each overlay's pipe(s), bottom first.
        let stack: Vec<otg::SurfaceRequest> = overlays.iter().flatten().copied().collect();
        let overlay_pipes: Vec<u8> = stack.iter().map(|o| o.pipe).collect();
        // SAFETY: the caller's exclusion and retention obligations cover each
        // retained owner below; every step validates its own preconditions.
        unsafe {
            self.retire_display_planes().await?;
            self.set_display_hubp_power(pipe, true).await?;
            for q in odm.into_iter().chain(pipes.mpc) {
                self.set_display_hubp_power(q, true).await?;
            }
            for o in &stack {
                for p in core::iter::once(o.pipe).chain(o.odm).chain(o.mpc) {
                    self.set_display_hubp_power(p, true).await?;
                }
            }
            self.prepare_display_surface(primary).await?;
            // `fill` draws XRGB8888 rows; any other format keeps the cleared
            // surface, which is black in each of them.
            if selection.format == otg::SurfaceFormat::Xrgb8888 {
                let mut row = alloc::vec![0u32; width as usize];
                for y in 0..height {
                    fill(pipe, y, &mut row);
                    self.upload_display_surface(pipe, 0, y, &row)?;
                }
            }
            // Each overlay's surface starts cleared: transparent in its
            // alpha formats, black in the others, until DRM presents.
            for &o in &stack {
                self.prepare_display_surface(o).await?;
            }
            // Every plane's apertures before any plane's DPP: a memory
            // restage keeps only the planes staged on the same context.
            self.prepare_display_memory(pipe).await?;
            for &o in &overlay_pipes {
                self.prepare_display_memory(o).await?;
            }
            self.prepare_display_timing(otg::Request {
                odm,
                ..timing_request(pipe, &plan, &selection)
            })
            .await?;
            self.prepare_display_blank(selection.blank_request(pipe))
                .await?;
            self.prepare_display_dpp(pipe).await?;
            for &o in &overlay_pipes {
                self.prepare_display_dpp(o).await?;
            }
            self.prepare_display_mpc(pipe)?;
            for &o in &overlay_pipes {
                self.prepare_display_mpc(o)?;
            }
            self.prepare_display_requestor_planes(pipe, &overlay_pipes)
                .await?;
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
    pub(super) fn offered_modes(
        &mut self,
        soc: &dml::Soc,
        lit: &[Modeset],
        k: usize,
        edid: &[u8],
    ) -> [Option<Timing>; MAX_MODES] {
        let s = lit[k].selection;
        let caps = hdmi_caps(edid);
        admitted_modes(soc, lit, k, edid_timings(edid), |t| {
            // How the link would carry it: HDMI may need 4:2:0.
            if s.hdmi {
                // FRL only for the display holding the HPO FRL encoder.
                let frl = s.frl.and_then(|_| frl_cap(caps));
                let audio = sink_audio_info(edid);
                hdmi_stream(caps, &t, max_bpc(), frl, audio, soc.dispclk_max_khz).map(|h| {
                    dml::Mode {
                        ycbcr420: h.ycbcr420,
                        dsc: h.dsc.map(|c| dml::Dsc {
                            slices: c.slices_h,
                            bpp_x16: c.bpp_x16,
                        }),
                        ..plane_mode(t, s.format)
                    }
                })
            } else if let Some(m) = s.mst {
                // Within the stream's own payload: uncompressed, or for a
                // compressed stream at the bpp its PBN carries
                // (bpp_x16_from_pbn).
                if super::mst::mst_slots(&t, s.lanes, s.rate, s.caps.fec)
                    .is_some_and(|(pbn, slots)| pbn <= m.pbn && slots <= m.slots)
                {
                    return Some(plane_mode(t, s.format));
                }
                let caps = m.dsc?.caps;
                let encoding = if s.uhbr() {
                    crate::amdgpu_dsc::LinkEncoding::Dp128b132b
                } else {
                    crate::amdgpu_dsc::LinkEncoding::Dp8b10b
                };
                let kbps = (u64::from(m.pbn) * 994 * 8 * 54 / 64) as u32;
                let dt = dsc_timing(&t, depth_bpc(s.depth));
                let cfg = crate::amdgpu_dsc::compute_config(
                    &caps,
                    soc.dispclk_max_khz,
                    kbps,
                    &dt,
                    encoding,
                    false,
                )?;
                let need = crate::amdgpu_dsc::dsc_kbps(&dt, cfg.bpp_x16, cfg.slices_h);
                (super::mst::dsc::peak_pbn(need, encoding) <= i32::from(m.pbn)
                    && dml::dsc_shape(&t, cfg.slices_h, soc.dispclk_max_khz).is_some())
                .then(|| dml::Mode {
                    dsc: Some(dml::Dsc {
                        slices: cfg.slices_h,
                        bpp_x16: cfg.bpp_x16,
                    }),
                    ..plane_mode(t, s.format)
                })
            } else {
                dp_offered_mode(t, &s, soc.dispclk_max_khz)
            }
        })
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
            if let Some(stream) = selection.mst {
                let scanout = self
                    .start_mst_stream(port, stream, &selection, pipe)
                    .await?;
                return Ok((selection, scanout));
            }
            if let Some(rate) = selection.frl {
                return self.start_frl_link(selection, rate, pipe).await;
            }
            if selection.hdmi {
                if selection.scdc {
                    // The sink may accept a write whose acknowledgement fails.
                    // Record its cleanup before any SCDC transaction, without
                    // inventing a native link which has not been prepared yet.
                    self.teardowns
                        .checkpoint_activation(pipe, super::TeardownStep::PreLinkScdc);
                }
                self.configure_scdc(&selection).await?;
                let request = otg::HdmiLinkRequest {
                    stream: pipe,
                    pipe,
                    avi: selection.avi,
                    hdr: selection.hdr_packet(),
                };
                self.prepare_display_hdmi_link(port, request).await?;
                self.teardowns
                    .checkpoint_activation(pipe, super::TeardownStep::Scdc);
                self.start_display_hdmi_video(port).await?;
                self.teardowns
                    .checkpoint_activation(pipe, super::TeardownStep::Video);
                let scanout = self.start_display_scanout(pipe).await?;
                self.teardowns
                    .checkpoint_activation(pipe, super::TeardownStep::Scanout);
                // As Linux's post-enable: audio after the stream runs.
                if let Some(info) = selection.audio {
                    self.start_display_audio(port, true, info).await?;
                }
                return Ok((selection, scanout));
            }
            if selection.uhbr() {
                return self.start_uhbr_link(selection, pipe).await;
            }
            let mut selection = selection;
            let mut trained = false;
            let mut refused = ModesetError::Link;
            let transmitter =
                self.display_paths().map_err(|_| ModesetError::NoSink)?[port].transmitter;
            let candidates = selected_dp_candidates(&selection);
            for &(lanes, link) in &candidates {
                let DpRate::Legacy(rate) = link else {
                    continue;
                };
                self.enable_display_dp_phy(
                    port,
                    otg::DpPhySettings {
                        lanes,
                        rate,
                        mst: false,
                    },
                )
                .await?;
                match self.train_display_dp_link(port, false).await {
                    Ok(_) => {
                        (selection.lanes, selection.rate) = (lanes, link);
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
                if matches!(refused, ModesetError::Display(otg::Error::DpTraining(_))) {
                    self.verify_dp_link(&selection, &candidates).await?;
                }
                return Err(refused);
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Link);
            self.prepare_display_dp_frontend(
                port,
                otg::DpFrontendRequest {
                    vsc_colorimetry: selection.vsc_colorimetry,
                    hdr: selection.hdr_packet(),
                    ..otg::DpFrontendRequest::new(pipe, pipe)
                },
            )
            .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Frontend);
            self.start_display_dp_video(port).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            // link_set_dpms_on's enable_stream_features once the stream
            // runs; Linux ignores the AUX result.
            let _ = self
                .set_display_dp_ignore_msa(port, selection.vrr_supported())
                .await;
            let scanout = self.start_display_scanout(pipe).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scanout);
            if let Some(info) = selection.audio {
                self.start_display_audio(port, false, info).await?;
            }
            Ok((selection, scanout))
        }
    }
    /// dp_verify_link_cap after every carrying setting was refused: train
    /// the rest of the 8b/10b ladder from the sink's caps (no stream) and
    /// keep the first setting that trains, else Linux's fail-safe one lane
    /// at RBR, as the port's verified link; stop the link again. Returns
    /// `LinkReduced` once a lower link is recorded. Sinks with 128b/132b
    /// caps keep Linux's UHBR fallback table instead.
    async unsafe fn verify_dp_link(
        &mut self,
        selection: &Selection,
        tried: &[(u8, DpRate)],
    ) -> Result<(), ModesetError> {
        let caps = selection.caps;
        if caps.uhbr != 0 || selection.mst.is_some() || selection.hdmi {
            return Ok(());
        }
        let port = selection.port;
        let path = self.display_paths().map_err(|_| ModesetError::NoSink)?[port];
        let transmitter = path.transmitter;
        let mut trained = None;
        for (lanes, rate) in verify_ladder(caps, tried) {
            // SAFETY: the caller's obligations; the port's PHY is stopped.
            unsafe {
                self.enable_display_dp_phy(
                    port,
                    otg::DpPhySettings {
                        lanes,
                        rate,
                        mst: false,
                    },
                )
                .await?;
                match self.train_display_dp_link(port, false).await {
                    Ok(_) => {
                        self.stop_display_dp_link(port).await?;
                        trained = Some((lanes, rate));
                        break;
                    }
                    Err(otg::Error::DpTraining(_))
                        if self
                            .display_timing_status()
                            .is_ok_and(|s| s.state == otg::State::DpLinkRefused(transmitter)) =>
                    {
                        self.stop_display_dp_link(port).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let Some(verified) = verified_link(caps, trained) else {
            return Ok(()); // nothing below the caps to select from
        };
        let (dpcd, edid) = self.verified_identity(port)?;
        self.record_verified_link(VerifiedLink {
            path,
            dpcd,
            edid,
            lanes: verified.0,
            rate: verified.1,
        });
        Err(ModesetError::LinkReduced)
    }
    /// The scanned DPCD and base EDID of the sink on `port`.
    fn verified_identity(&self, port: usize) -> Result<([u8; 16], [u8; 128]), ModesetError> {
        let path = self.display_paths().map_err(|_| ModesetError::NoSink)?[port];
        self.scanned_sinks
            .iter()
            .find(|(p, _, _)| *p == path)
            .map(|&(_, dpcd, edid)| (dpcd, edid))
            .ok_or(ModesetError::NoSink)
    }
    /// Replace the port's verified link.
    fn record_verified_link(&mut self, link: VerifiedLink) {
        self.verified_links.retain(|v| v.path != link.path);
        self.verified_links.push(link);
    }
    /// The 128b/132b half of `start_link`: train down Linux's fallback
    /// table on HPO link encoder `pipe` (one display per pipe, as Linux's
    /// first-free assignment gives in display order), then 128b/132b video
    /// on HPO stream encoder `pipe` and scanout. Each setting gets
    /// perform_link_training_with_retries' four attempts, the link stopped
    /// after each refusal and 50 ms more waited before each retry. LPCM
    /// capabilities are filtered again at the trained link before audio starts.
    /// # Safety
    /// As for `start_link`.
    async unsafe fn start_uhbr_link(
        &mut self,
        selection: Selection,
        pipe: u8,
    ) -> Result<(Selection, otg::ScanoutRunning), ModesetError> {
        let port = selection.port;
        let mut selection = selection;
        let mut refused = ModesetError::Link;
        let transmitter = self.display_paths().map_err(|_| ModesetError::NoSink)?[port].transmitter;
        let candidates = selected_dp_candidates(&selection);
        let mut trained = false;
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            'settings: for (lanes, link) in candidates {
                let DpRate::Uhbr(rate) = link else {
                    continue;
                };
                let settings = otg::UhbrSettings {
                    lanes,
                    rate,
                    mst: false,
                };
                for attempt in 0..UHBR_TRAINING_ATTEMPTS {
                    if attempt != 0 {
                        let ms = UHBR_RETRY_DELAY_MS * u64::from(attempt);
                        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant())
                            .await;
                    }
                    match self.train_display_uhbr_link(port, settings, pipe).await {
                        Ok(_) => {
                            (selection.lanes, selection.rate) = (lanes, link);
                            trained = true;
                            break 'settings;
                        }
                        // The sink refused this setting and training
                        // exited: stop the link before the next attempt.
                        Err(e @ otg::Error::DpTraining(_))
                            if self.display_timing_status().is_ok_and(|s| {
                                s.state == otg::State::UhbrLinkRefused(transmitter)
                            }) =>
                        {
                            refused = e.into();
                            self.stop_display_uhbr_link(port, false).await?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            if !trained {
                return Err(refused);
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Link);
            let video = self
                .start_display_uhbr_video(port, pipe, pipe, selection.uhbr_sdp())
                .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            // As for 8b/10b SST: enable_stream_features after the stream runs.
            let _ = self
                .set_display_dp_ignore_msa(port, selection.vrr_supported())
                .await;
            let scanout = self.start_display_scanout(pipe).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scanout);
            selection.audio = selection.audio.and_then(|info| {
                otg::uhbr_audio_info_with(
                    info,
                    &selection.timing,
                    u32::from(depth_bpc(selection.depth)),
                    video.link.settings,
                    selection.dsc.as_ref(),
                )
            });
            if let Some(info) = selection.audio {
                self.start_display_audio(port, false, info).await?;
            }
            Ok((selection, scanout))
        }
    }
    /// The FRL half of `start_link`: train (stepping down on the sink's
    /// request), then FRL video with the borrow parameters Linux's capacity
    /// check gives at the trained rate, then scanout and reserved LPCM audio.
    /// # Safety
    /// As for `start_link`.
    async unsafe fn start_frl_link(
        &mut self,
        selection: Selection,
        rate: FrlRate,
        pipe: u8,
    ) -> Result<(Selection, otg::ScanoutRunning), ModesetError> {
        let port = selection.port;
        let bpc = depth_bpc(selection.depth);
        let ycbcr420 = selection.ycbcr420;
        let audio = frl_audio(selection.audio, selection.timing.v_active);
        let dsc = FrlDscStream::of(&selection);
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            let trained = self
                .start_frl(port, &selection.timing, bpc, ycbcr420, dsc, rate, audio)
                .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scdc);
            // The trained link's capacity-check parameters (for DSC the
            // compressed check's tribyte targets and padding borrow mode).
            let (audio_packets_line, borrow, hc_active, hc_blank) =
                frl_video_params(&selection.timing, bpc, ycbcr420, dsc, trained, audio)
                    .ok_or(ModesetError::Link)?;
            let request = otg::FrlVideoRequest {
                pipe,
                audio_packets_line,
                borrow,
                hc_active,
                hc_blank,
                avi: selection.avi,
                hdr: selection.hdr_packet(),
            };
            self.start_display_frl_video(port, request).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            let scanout = self.start_display_scanout(pipe).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scanout);
            if let Some(info) = selection.audio {
                self.start_display_audio(port, true, info).await?;
            }
            Ok((
                Selection {
                    frl: Some(trained),
                    ..selection
                },
                scanout,
            ))
        }
    }
    /// Return an FRL sink to legacy TMDS after video stopped: rate/update
    /// cleared, Source_Version and TMDS_Config 0, all best effort as before.
    pub(super) async fn stop_frl_sink(&mut self, port: usize) {
        use crate::amdgpu_frl_training::{CONFIG_1, SINK_VERSION, SOURCE_VERSION, UPDATE_0};
        if self
            .display_scdc_read(port, CONFIG_1)
            .await
            .is_ok_and(|v| v & 0xf != 0)
        {
            let _ = self.display_scdc_write(port, CONFIG_1, 0).await;
        }
        if self
            .display_scdc_read(port, UPDATE_0)
            .await
            .is_ok_and(|v| v & 0x20 != 0)
        {
            let _ = self.display_scdc_write(port, UPDATE_0, 0x20).await;
        }
        if self.display_scdc_read(port, SINK_VERSION).await == Ok(1) {
            let _ = self.display_scdc_write(port, SOURCE_VERSION, 1).await;
        }
        let _ = self.display_scdc_write(port, scdc::TMDS_CONFIG, 0).await;
    }
    /// Stop a running 128b/132b display's video and link (scanout stopped).
    /// # Safety
    /// As for `stop_modeset`.
    async unsafe fn stop_uhbr(&mut self, port: usize, unplugged: bool) -> Result<(), ModesetError> {
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            self.stop_display_uhbr_video(port).await?;
            self.stop_display_uhbr_link(port, unplugged).await?;
        }
        Ok(())
    }
    /// Enable and train an FRL link for `timing` at `bpc`, preserving its
    /// RGB/4:2:0 encoding, on HDMI port
    /// `port`, from `rate` down: hdmi_frl_perform_link_training_with_retries
    /// at each rate, stepping one rate code down when the sink asks for a
    /// lower rate (as Linux's verification walk does), never below one that
    /// still carries the mode (a DSC stream `dsc`, compressed). A timeout or
    /// Sink_Version 0 ends it. On success the link sends FRL output and
    /// FRL_Start was awaited.
    /// # Safety
    /// As for `start_link`; the port's sink declared FRL and SCDC.
    #[allow(clippy::too_many_arguments)]
    pub async unsafe fn start_frl(
        &mut self,
        port: usize,
        timing: &Timing,
        bpc: u8,
        ycbcr420: bool,
        dsc: Option<FrlDscStream>,
        rate: FrlRate,
        audio: crate::amdgpu_frl_cap::FrlAudio,
    ) -> Result<FrlRate, ModesetError> {
        use crate::amdgpu_frl_training::{poll_start, train_with_retries, FrlTraining};
        let mut code = rate.code();
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            loop {
                let r = FrlRate::new(code).ok_or(ModesetError::Link)?;
                if frl_video_params(timing, bpc, ycbcr420, dsc, r, audio).is_none() {
                    return Err(ModesetError::Link);
                }
                self.start_display_frl_link(port, r.lanes(), r.character_khz())
                    .await?;
                let outcome =
                    train_with_retries(&mut FrlPort { boot: self, port }, code, r.lanes()).await?;
                match outcome {
                    FrlTraining::Success => {
                        self.display_frl_output(port)?;
                        poll_start(&mut FrlPort { boot: self, port }).await?;
                        return Ok(r);
                    }
                    FrlTraining::LowerRate => {
                        self.stop_display_frl_link(port).await?;
                        code -= 1;
                    }
                    FrlTraining::Timeout | FrlTraining::Fallback => {
                        self.stop_display_frl_link(port).await?;
                        return Err(ModesetError::Link);
                    }
                }
            }
        }
    }
    /// Check a running modeset: hot-plug first (no AUX to an absent sink),
    /// then DP lane lock or FRL status/source-test requests, then scanout.
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
            if m.selection.frl.is_some() {
                if crate::amdgpu_frl_training::poll_status(&mut FrlPort { boot: self, port })
                    .await?
                {
                    return Ok(Health::FrlRetrain);
                }
            } else if !m.selection.hdmi {
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
        self.teardowns.check_idle()?;
        // Display k runs on pipe k, in its own records.
        self.select_display(m.pipe)?;
        let port = m.selection.port;
        if m.selection.hdmi || m.selection.mst.is_some() {
            return Err(ModesetError::Display(otg::Error::Unsupported));
        }
        // Capture real board limits before changing the live link. Refilter
        // the old offered timings after training, beside every retained sibling.
        let soc = self.display_soc()?;
        // In flight from the first stop: a dropped or uncertain retrain is
        // never replayed or taken for a running display.
        self.teardowns.begin_retrain(m)?;
        // SAFETY: as documented above; each step checks its predecessor state.
        let stopped = unsafe {
            if m.selection.audio.is_some() {
                self.stop_display_audio(port, false).await?;
            }
            self.stop_display_scanout(m.pipe).await?;
            if m.selection.uhbr() {
                self.stop_uhbr(port, false).await?;
            } else {
                self.stop_display_dp_video(port).await?;
                self.stop_display_dp_frontend(port).await?;
                self.stop_display_dp_link(port).await?;
            }
            self.display_timing_status()?.state
        };
        // SAFETY: as above.
        match unsafe { self.start_link(m.selection, m.pipe) }.await {
            Ok((selection, scanout)) => {
                (m.selection, m.scanout) = (selection, scanout);
                self.teardowns.finish_retrain(m.pipe, None);
                self.retain_retrained_modeset(m, &soc);
                Ok(())
            }
            Err(e) => {
                // Every setting was refused (or the link verified lower) and
                // start_link stopped it again: the same native state as
                // before training. Ordinary teardown continues from timing;
                // the next configuration selects against the verified link.
                if retrain_refused(&e)
                    && self
                        .display_timing_status()
                        .is_ok_and(|s| s.state == stopped)
                {
                    self.teardowns
                        .finish_retrain(m.pipe, Some(super::TeardownStep::Timing));
                }
                Err(e)
            }
        }
    }
    fn retain_retrained_modeset(&mut self, m: &mut Modeset, soc: &dml::Soc) {
        // Preserve the actual completion before doing any further work.
        self.modesets.retain(*m);
        let lit: Vec<_> = self.display_modesets().into_iter().flatten().collect();
        let k = lit.iter().position(|old| old.pipe == m.pipe).unwrap();
        m.modes = admitted_modes(soc, &lit, k, m.modes.into_iter().flatten(), |t| {
            dp_offered_mode(t, &m.selection, soc.dispclk_max_khz)
        });
        self.modesets.retain(*m);
    }
    /// Tear down a modeset whose sink left: as `stop_modeset`, but a DP link
    /// stops without addressing the sink, and only while HPD stays low. An
    /// SCDC sink still gets the legacy TMDS_Config write, unchecked, as
    /// Linux's link_set_dpms_off sends it whether or not a sink answers (a
    /// sink back on the port before teardown is returned to legacy TMDS).
    /// # Safety
    /// As for `stop_modeset`.
    pub async unsafe fn unplug_modeset(&mut self, m: &Modeset) -> Result<(), ModesetError> {
        // SAFETY: caller has withdrawn CPU writers and retains exclusive owners.
        unsafe { self.teardown_modeset(m, true) }.await?;
        self.modesets.stopped(m.pipe);
        Ok(())
    }
    /// Reverse a successful modeset down to a disabled PHY with timing and
    /// planes retired. The surface allocation is retained by its pipe.
    /// Retained per-pipe progress lets the same Modeset resume from its first
    /// unfinished step; native failed/in-flight guards remain authoritative.
    /// # Safety
    /// As for `modeset_display`; stop every CPU writer of the surface first.
    pub async unsafe fn stop_modeset(&mut self, m: &Modeset) -> Result<(), ModesetError> {
        // SAFETY: caller has withdrawn CPU writers and retains exclusive owners.
        unsafe { self.teardown_modeset(m, false) }.await?;
        self.modesets.stopped(m.pipe);
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
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_modeset_tests.rs"]
mod tests;

/// The DPP DTO of every pipe display `m` runs on beside its own, as plan
/// `plan` (its stream admitted anew) clocks them: the timing pipe and its
/// ODM segments and primary MPC slices at the primary's DPPCLK, each
/// overlay's pipes at its plane's. What a live clock update's DTO steps
/// cover (dcn401_update_clocks_update_dpp_dto over the context's pipes).
pub fn running_dpp_targets(m: &Modeset, plan: &dml::Plan) -> Vec<(u8, u32)> {
    let s = &m.scanout;
    let primary = plan.clocks.dppclk_khz;
    let mut out: Vec<(u8, u32)> = core::iter::once(m.pipe)
        .chain(s.odm)
        .chain(s.mpc)
        .map(|p| (p, primary))
        .collect();
    for (k, o) in s.overlays.iter().enumerate() {
        let Some(o) = o else { continue };
        let dpp = plan.plane(k + 1).map_or(primary, |p| p.dppclk_khz);
        out.extend(
            core::iter::once(o.pipe)
                .chain(o.odm)
                .chain(o.mpc)
                .map(|p| (p, dpp)),
        );
    }
    out
}

/// Whether running display `m` can move to `plan` without relighting: the
/// same stream and planes, split the same way (its pipes cannot change
/// while it scans out).
pub fn keeps_pipes(m: &Modeset, plan: &dml::Plan) -> bool {
    plan.mode == m.plan.mode
        && plan.pipes == m.plan.pipes
        && (0..dml::MAX_PLANES)
            .all(|k| plan.plane(k).map(|p| p.dpps) == m.plan.plane(k).map(|p| p.dpps))
}

/// The global floors a configuration's plans need: the fastest DISPCLK
/// and DPPREFCLK (every plan of one admission shares them), DTBCLK at its
/// top level with an FRL stream (dcn401_update_clocks).
fn configuration_clocks(plans: &[dml::Plan], frl_dtb_khz: Option<u32>) -> clocks::Request {
    let mut request = clock_request(&plans[0]);
    request.displays = plans.len() as u8;
    if let Some(dtb) = frl_dtb_khz {
        request.dtb_khz = dtb;
    }
    request
}

impl ColdBoot {
    /// dc_commit_state_no_check for a configuration change that keeps every
    /// running display lit: prepare_bandwidth (the shared clocks only
    /// raised, the running pipes' DPP DTOs raised where they need more,
    /// each running display moved to its new plan with raise-only
    /// watermarks), then `between` (lighting the new displays), then
    /// optimize_bandwidth (each running display's exact watermarks, the
    /// clocks lowered to what the configuration needs, every pipe's DTO
    /// set). `running` are the displays kept, `plans` their plans in the
    /// new configuration (same order); `all_plans` every plan of it and
    /// `all_targets` every pipe's DPPCLK once `between` has lit the rest.
    /// Updated records go back into `running` and the retained modesets.
    /// # Safety
    /// As for `modeset_displays`, except that `running` stay lit.
    async unsafe fn transition_running(
        &mut self,
        running: &mut [Modeset],
        plans: &[dml::Plan],
        request: clocks::Request,
    ) -> Result<(), ModesetError> {
        if running.len() != plans.len() {
            return Err(otg::Error::Invalid.into());
        }
        if running.iter().zip(plans).any(|(m, p)| !keeps_pipes(m, p)) {
            return Err(otg::Error::Admission(dml::Error::Pipes).into());
        }
        // prepare_bandwidth: raise only.
        let targets: Vec<(u8, u32)> = running
            .iter()
            .zip(plans)
            .flat_map(|(m, p)| running_dpp_targets(m, p))
            .collect();
        self.update_live_display_clocks(request, &targets, false)
            .await?;
        for (m, plan) in running.iter_mut().zip(plans) {
            // SAFETY: the caller's obligations; the scanout stays live.
            let d = unsafe { self.update_live_display_plan(m.pipe, plan, true) }.await?;
            m.plan = d.plan;
            m.scanout.plan = d.plan;
            self.modesets.retain(*m);
        }
        Ok(())
    }
    /// optimize_bandwidth after `transition_running` (and any new displays):
    /// every running display's exact watermarks under its plan, then the
    /// clocks lowered to `request` with every pipe's DTO (`targets`) set.
    /// # Safety
    /// As for `transition_running`.
    async unsafe fn optimize_running(
        &mut self,
        running: &mut [Modeset],
        request: clocks::Request,
        targets: &[(u8, u32)],
    ) -> Result<(), ModesetError> {
        for m in running.iter_mut() {
            let plan = m.plan;
            // SAFETY: the caller's obligations; the scanout stays live.
            unsafe { self.update_live_display_plan(m.pipe, &plan, false) }.await?;
        }
        self.update_live_display_clocks(request, targets, true)
            .await?;
        Ok(())
    }
    /// Light every new lightable board sink beside the running displays,
    /// which stay lit: DML admits the running displays' modes with the new
    /// ones (as many of the new ones as fit, in pipe order; every running
    /// display must keep its pipes), and the change follows dcn401's
    /// prepare/optimize ordering (`transition_running`) around lighting the
    /// new displays on their pipes, whose pipe clocks are programmed beside
    /// the running ones. `None` when it is refused before any change (an
    /// MST display or none running, no free display slot, the running
    /// displays no longer admitted together or not on their pipes), so the
    /// caller relights instead. Returns every display lit, in pipe order.
    /// # Safety
    /// As for `modeset_displays`, except that the running displays stay
    /// lit and must stay published as they are.
    pub async unsafe fn modeset_beside(
        &mut self,
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipe_of: impl Fn(usize) -> Option<u8>,
    ) -> Result<Option<Configuration>, ModesetError> {
        self.teardowns.check_idle()?;
        let mut running: Vec<Modeset> = self.display_modesets().into_iter().flatten().collect();
        if running.is_empty() || running.iter().any(|m| m.selection.mst.is_some()) {
            return Ok(None);
        }
        let used = running.iter().fold(0u8, |acc, m| acc | 1 << m.pipe);
        let ports_used: Vec<usize> = running.iter().map(|m| m.selection.port).collect();
        // Scan from an idle display slot.
        let Some(idle) = (0..4u8).find(|p| used & 1 << p == 0) else {
            return Ok(None);
        };
        self.select_display(idle)?;
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let paths = self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .to_vec();
        if !self.mst.is_empty() {
            return Ok(None);
        }
        let mut new: Vec<(Selection, u8)> = match select_all(&paths, &ports, max_bpc(), &want) {
            Ok(selections) => selections,
            Err(ModesetError::NoSink | ModesetError::Link) => Vec::new(),
            Err(e) => return Err(e),
        }
        .into_iter()
        .filter(|s| !ports_used.contains(&s.port))
        .filter_map(|s| Some((s, pipe_of(s.port).filter(|&p| p < 4 && used & 1 << p == 0)?)))
        .collect();
        new.sort_by_key(|&(_, pipe)| pipe);
        if new.windows(2).any(|w| w[0].1 == w[1].1) {
            return Err(ModesetError::Display(otg::Error::Invalid));
        }
        let limited = limited_range(broadcast_rgb());
        for (s, pipe) in new.iter_mut() {
            s.limited = limited && !s.ycbcr420;
            s.format = plane_format(*pipe);
            s.planes = plane_setup(*pipe);
            (s.colorspace, s.hdr) = output_color(*pipe);
        }
        let soc = self.display_soc()?;
        {
            let mut selections: Vec<Selection> = new.iter().map(|&(s, _)| s).collect();
            refine_dsc(&soc, &mut selections)?;
            for ((s, _), r) in new.iter_mut().zip(selections) {
                *s = r;
            }
        }
        // The running displays with as many new ones as fit, in pipe order.
        let mut n = new.len();
        let (plans, order) = loop {
            let mut joint: Vec<(dml::Mode, Option<usize>, u8)> = running
                .iter()
                .map(|m| (m.plan.mode, None, m.pipe))
                .chain(
                    new[..n]
                        .iter()
                        .enumerate()
                        .map(|(i, &(s, p))| (selection_mode(&s), Some(i), p)),
                )
                .collect();
            joint.sort_by_key(|&(_, _, p)| p);
            let modes: Vec<dml::Mode> = joint.iter().map(|&(m, _, _)| m).collect();
            match dml::admit_native(&soc, &modes) {
                Ok(plans) => break (plans, joint),
                Err(_) if n == 0 => return Ok(None),
                Err(_) => n -= 1,
            }
        };
        new.truncate(n);
        if new.is_empty() {
            running.sort_by_key(|m| m.pipe);
            self.update_sst_outputs(Some(&soc), &paths, &ports, &running);
            return Ok(Some(Configuration {
                displays: running,
                failed: None,
            }));
        }
        // Each running display's plan, in `running` order; the new ones'.
        let plan_of = |pipe: u8| {
            order
                .iter()
                .position(|&(_, _, p)| p == pipe)
                .map(|i| plans[i])
        };
        let running_plans: Vec<dml::Plan> = running
            .iter()
            .map(|m| plan_of(m.pipe))
            .collect::<Option<_>>()
            .ok_or(otg::Error::Invalid)?;
        let new_plans: Vec<dml::Plan> = new
            .iter()
            .map(|&(_, p)| plan_of(p))
            .collect::<Option<_>>()
            .ok_or(otg::Error::Invalid)?;
        let frl = running.iter().any(|m| m.selection.frl.is_some())
            || new.iter().any(|(s, _)| s.frl.is_some());
        let frl_dtb = if frl { Some(self.top_dtb_khz()?) } else { None };
        let request = configuration_clocks(&plans, frl_dtb);
        // The new displays' further pipes, from what the running ones leave.
        let running_mask = running.iter().fold(0u8, |acc, m| {
            acc | 1 << m.pipe
                | running_dpp_targets(m, &m.plan)
                    .iter()
                    .fold(0, |a, &(p, _)| a | 1 << p)
        });
        let new_selections: Vec<Selection> = new.iter().map(|&(s, _)| s).collect();
        let new_pipes: Vec<u8> = new.iter().map(|&(_, p)| p).collect();
        let extra = display_pipes_beside(&new_selections, &new_plans, &new_pipes, running_mask)?;
        if running
            .iter()
            .zip(&running_plans)
            .any(|(m, p)| !keeps_pipes(m, p))
        {
            return Ok(None);
        }
        // SAFETY: the caller's obligations; the running displays stay lit.
        unsafe { self.transition_running(&mut running, &running_plans, request) }.await?;
        let mut lit = Vec::with_capacity(new.len());
        let mut failed = None;
        for ((&(selection, pipe), plan), d) in new.iter().zip(&new_plans).zip(&extra) {
            self.select_display(pipe)?;
            let clocks = async {
                self.prepare_display_pipe_clocks_beside(pipe_clock_request(pipe, plan, &selection))
                    .await
                    .map_err(ModesetError::PipeClocks)?;
                if selection.dsc.is_some() {
                    self.start_display_dscclk(pipe)?;
                }
                for q in d.odm {
                    self.prepare_display_pipe_clocks_beside(dccg::Request {
                        pipe: q,
                        dpp_khz: plan.clocks.dppclk_khz,
                        pixel: dccg::PixelClock::OdmSegment,
                    })
                    .await
                    .map_err(ModesetError::PipeClocks)?;
                    if selection.dsc.is_some() {
                        self.start_display_dscclk(q)?;
                    }
                }
                for q in d.mpc {
                    self.prepare_display_pipe_clocks_beside(dccg::Request {
                        pipe: q,
                        dpp_khz: plan.clocks.dppclk_khz,
                        pixel: dccg::PixelClock::OdmSegment,
                    })
                    .await
                    .map_err(ModesetError::PipeClocks)?;
                }
                for (k, o) in d.overlays.iter().enumerate() {
                    let Some(o) = o else { continue };
                    let dpp = plan
                        .plane(k + 1)
                        .ok_or(ModesetError::Display(otg::Error::Invalid))?
                        .dppclk_khz;
                    for q in o.all() {
                        self.prepare_display_pipe_clocks_beside(dccg::Request {
                            pipe: q,
                            dpp_khz: dpp,
                            pixel: dccg::PixelClock::OdmSegment,
                        })
                        .await
                        .map_err(ModesetError::PipeClocks)?;
                    }
                }
                Ok::<(), ModesetError>(())
            }
            .await;
            let result = match clocks {
                // SAFETY: the caller's obligations; earlier displays stay lit.
                Ok(()) => unsafe { self.light(pipe, *d, selection, *plan, &mut fill) }.await,
                Err(e) => Err(e),
            };
            match result {
                Ok(m) => lit.push(m),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        // optimize_bandwidth over what is lit now (a display that failed to
        // light is retired by its own unwind; its pipes are not targets).
        let mut targets: Vec<(u8, u32)> = running
            .iter()
            .flat_map(|m| running_dpp_targets(m, &m.plan))
            .collect();
        for m in &lit {
            targets.extend(running_dpp_targets(m, &m.plan));
        }
        // SAFETY: as above.
        unsafe { self.optimize_running(&mut running, request, &targets) }.await?;
        let mut displays = running;
        displays.extend(lit);
        displays.sort_by_key(|m| m.pipe);
        // Every display's offered modes beside the others, as lighting
        // computes them.
        let all = displays.clone();
        for (k, display) in displays.iter_mut().enumerate() {
            let edid = edid_of(&ports, &paths, &display.selection);
            display.modes = self.offered_modes(&soc, &all, k, &edid);
            self.modesets.retain(*display);
        }
        self.update_sst_outputs(Some(&soc), &paths, &ports, &displays);
        Ok(Some(Configuration { displays, failed }))
    }
    /// After a display left: DML admits the running displays' modes again
    /// and, if each keeps its pipes, the configuration moves to the new
    /// plans in dcn401's prepare/optimize order (the clocks the departed
    /// display needed lowered last). Returns the updated displays.
    /// # Safety
    /// As for `modeset_displays`, except that the running displays stay lit.
    pub async unsafe fn replan_displays(&mut self) -> Result<Vec<Modeset>, ModesetError> {
        self.teardowns.check_idle()?;
        let mut running: Vec<Modeset> = self.display_modesets().into_iter().flatten().collect();
        if running.is_empty() || running.iter().any(|m| m.selection.mst.is_some()) {
            return Ok(running);
        }
        running.sort_by_key(|m| m.pipe);
        let soc = self.display_soc()?;
        let modes: Vec<dml::Mode> = running.iter().map(|m| m.plan.mode).collect();
        let plans = dml::admit_native(&soc, &modes).map_err(otg::Error::Admission)?;
        if running.iter().zip(&plans).all(|(m, p)| *p == m.plan) {
            return Ok(running);
        }
        let frl = running.iter().any(|m| m.selection.frl.is_some());
        let frl_dtb = if frl { Some(self.top_dtb_khz()?) } else { None };
        let request = configuration_clocks(&plans, frl_dtb);
        // SAFETY: the caller's obligations.
        unsafe { self.transition_running(&mut running, &plans, request) }.await?;
        let targets: Vec<(u8, u32)> = running
            .iter()
            .flat_map(|m| running_dpp_targets(m, &m.plan))
            .collect();
        // SAFETY: as above.
        unsafe { self.optimize_running(&mut running, request, &targets) }.await?;
        Ok(running)
    }
}

/// `display_pipes` for new displays on `pipes` lit beside running ones
/// whose pipes (every one they scan out on, by bit) are `used`: every split
/// takes only what those leave.
pub fn display_pipes_beside(
    selections: &[Selection],
    plans: &[dml::Plan],
    pipes: &[u8],
    used: u8,
) -> Result<Vec<DisplayPipes>, ModesetError> {
    // Only the pipes named matter to the allocation, not their order.
    let mut taken: Vec<u8> = pipes.to_vec();
    taken.extend((0..4u8).filter(|p| used & 1 << p != 0 && !pipes.contains(p)));
    display_pipes(selections, plans, &taken)
}
