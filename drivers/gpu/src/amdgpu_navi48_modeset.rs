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
    /// The DP sink's usable links; `DpCaps::NONE` for HDMI.
    pub caps: DpCaps,
    /// The sink's base EDID block, reported to DRM verbatim.
    pub edid: [u8; 128],
    /// An HDMI sink (TMDS or FRL) rather than DP.
    pub hdmi: bool,
    /// The HDMI sink declared SCDC (HF-VSDB/HF-SCDB SCDC_Present).
    pub scdc: bool,
    /// Output depth: 8 bpc for DP; for HDMI the deepest the sink, the
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
}

/// A selection's stream on an MST link: its end device and VC payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstStream {
    pub sink: crate::dp_mst_mgr::Sink,
    pub pbn: u16,
    pub slots: u8,
    /// DP_MSE_RATE X.Y (`otg::vc_rate`).
    pub rate: (u32, u32),
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
    });
    matches!(check, FrlCap::Ok { .. }).then_some(check)
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
#[derive(Debug)]
pub(super) struct RetainedModesets([Option<Modeset>; 4]);
impl RetainedModesets {
    pub(super) fn new() -> Self {
        Self([None; 4])
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
        for (old, retained) in to.iter().zip(&self.0) {
            if old.is_some() && retained.is_some() && old != retained {
                return Err(otg::Error::Busy.into());
            }
        }
        let mut recovered = 0;
        for (pipe, (old, retained)) in to.iter_mut().zip(&self.0).enumerate() {
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
    pub fn display_modesets(&self) -> [Option<Modeset>; 4] {
        self.modesets.0
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
pub fn link_fits(timing: &Timing, lanes: u8, rate: LinkRate) -> bool {
    stream_kbps(timing, false) <= legacy_kbps(lanes, rate, false)
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
    let (lanes, rate) = max_link(sink.dpcd.as_ref()?, sink.lttpr)?;
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
        uhbr,
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
pub fn stream_kbps(timing: &Timing, uhbr: bool) -> u64 {
    let kbps = u64::from(timing.pixel_clock_khz) * 24;
    let bits = u64::from(timing.h_active) * 24;
    if !uhbr || bits == 0 {
        return kbps;
    }
    (kbps * bits.div_ceil(128) * 128).div_ceil(bits)
}

/// Whether `lanes` at `rate` carries `timing` on a link with `caps`.
pub fn dp_fits(timing: &Timing, caps: DpCaps, lanes: u8, rate: DpRate) -> bool {
    let have = match rate {
        DpRate::Legacy(r) => legacy_kbps(lanes, r, caps.fec),
        DpRate::Uhbr(r) => uhbr_kbps(lanes, r),
    };
    stream_kbps(timing, caps.uhbr != 0) <= have
}

/// The link a DP mode lights on: the sink's maximum 8b/10b link when that
/// carries it; otherwise 128b/132b only as Linux's decide_dp_link_settings
/// reaches it, searching upward (lanes first, then rate) past every 8b/10b
/// setting for the first UHBR setting that carries the mode.
pub fn dp_link(timing: &Timing, caps: DpCaps) -> Option<(u8, DpRate)> {
    let legacy = DpRate::Legacy(caps.rate);
    if dp_fits(timing, caps, caps.lanes, legacy) {
        return Some((caps.lanes, legacy));
    }
    caps.uhbr_rates()
        .flat_map(|r| [1, 2, 4].map(|l| (l, DpRate::Uhbr(r))))
        .find(|&(l, r)| l <= caps.lanes && dp_fits(timing, caps, l, r))
}

fn dsc_fits(
    timing: &Timing,
    cfg: crate::amdgpu_dsc::DscConfig,
    lanes: u8,
    rate: DpRate,
    fec: bool,
) -> bool {
    let DpRate::Legacy(rate) = rate else {
        return false;
    };
    fec && u64::from(crate::amdgpu_dsc::dsc_kbps(
        &dsc_timing(timing),
        cfg.bpp_x16,
        cfg.slices_h,
    )) <= legacy_kbps(lanes, rate, true)
}

/// Admission shape for an alternative DP timing. Recompute its DSC with the
/// board's real DISPCLK limit, and after fallback require the configuration
/// that selection would produce to fit the link which actually trained.
fn dp_offered_mode(timing: Timing, s: &Selection, max_dispclk_khz: u32) -> Option<dml::Mode> {
    let selected = if s.dsc.is_some() {
        Some((s.caps.lanes, DpRate::Legacy(s.caps.rate)))
    } else {
        dp_link(&s.timing, s.caps)
    };
    let fell_back = selected != Some((s.lanes, s.rate));
    if dp_link(&timing, s.caps).is_some() {
        return (!fell_back || dp_fits(&timing, s.caps, s.lanes, s.rate)).then(|| mode(timing));
    }
    let cfg = dp_dsc(&timing, s.caps, max_dispclk_khz)?;
    if fell_back && !dsc_fits(&timing, cfg, s.lanes, s.rate, s.caps.fec) {
        return None;
    }
    Some(dml::Mode {
        dsc: Some(dml::Dsc {
            slices: cfg.slices_h,
            bpp_x16: cfg.bpp_x16,
        }),
        ..mode(timing)
    })
}

/// dcn4_soc_bb's DISPCLK maximum: DSC decisions before the board's levels
/// are known use it, and are redone with the board's (`refine_dsc`).
const NOMINAL_DISPCLK_KHZ: u32 = 2_000_000;

/// The DSC view of an 8-bit RGB DP stream.
fn dsc_timing(t: &Timing) -> crate::amdgpu_dsc::DscTiming {
    crate::amdgpu_dsc::DscTiming {
        pix_clk_100hz: t.pixel_clock_khz * 10,
        h_active: t.h_active,
        h_total: t.h_total,
        v_active: t.v_active,
        v_total: t.v_total,
        bpc: 8,
        encoding: crate::amdgpu_dsc::Encoding::Rgb,
    }
}

/// amdgpu_dm's SST DSC policy (apply_dsc_policy_for_stream) where this
/// driver can carry DSC: a FEC-capable DSC sink without 128b/132b, whose
/// uncompressed stream exceeds its maximum 8b/10b link (FEC included) is
/// compressed to the highest bpp that link carries, on one DSC (at most
/// four slices). DSC over 128b/132b (HPO) is not implemented.
pub fn dp_dsc(
    timing: &Timing,
    caps: DpCaps,
    max_dispclk_khz: u32,
) -> Option<crate::amdgpu_dsc::DscConfig> {
    use crate::amdgpu_dsc::{compute_config, LinkEncoding};
    let sink = caps.dsc?;
    if !caps.fec || caps.uhbr != 0 {
        return None;
    }
    let target = u32::try_from(legacy_kbps(caps.lanes, caps.rate, true)).ok()?;
    let cfg = compute_config(
        &sink,
        max_dispclk_khz,
        target,
        &dsc_timing(timing),
        LinkEncoding::Dp8b10b,
        false,
    )?;
    (cfg.slices_h <= 4 && timing.h_active <= 5184).then_some(cfg)
}

/// Redo every DSC decision with the board's highest DISPCLK, as Linux's
/// clock manager reports it to dc_dsc_compute_config. A stream that no
/// longer fits one DSC is a link failure.
pub fn refine_dsc(soc: &dml::Soc, selections: &mut [Selection]) -> Result<(), ModesetError> {
    for s in selections.iter_mut().filter(|s| s.dsc.is_some()) {
        s.dsc = Some(dp_dsc(&s.timing, s.caps, soc.dispclk_max_khz).ok_or(ModesetError::Link)?);
    }
    Ok(())
}

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

/// How an HDMI sink carries `t`: TMDS where `hdmi_format` finds a depth
/// (Linux keeps TMDS whenever it suffices), else FRL at `frl_cap` (none
/// when FRL is off or taken): RGB first unless the mode is 4:2:0-only,
/// then 4:2:0 where declared. Each uses the deepest declared depth up to
/// `max_bpc` with a carrying rate, and the lowest such rate. FRL reserves
/// bandwidth for the sink's supported LPCM modes (layout 0 at SD timings).
pub fn hdmi_output(
    caps: HdmiCaps,
    t: &Timing,
    max_bpc: u8,
    frl_cap: Option<FrlRate>,
    audio: Option<otg::AudioInfo>,
) -> Option<(otg::ColorDepth, bool, Option<FrlRate>)> {
    if let Some((depth, ycbcr420)) = hdmi_format(caps, t, max_bpc) {
        return Some((depth, ycbcr420, None));
    }
    let cap = frl_cap?;
    let vic = narf_edid::modes::match_cea_mode(edid_mode(t));
    let listed = |map: [u64; 4]| vic != 0 && map[usize::from(vic / 64)] & 1 << (vic % 64) != 0;
    let only420 = listed(caps.y420_only);
    let audio = frl_audio(
        audio.and_then(|a| otg::frl_lpcm_info(a, t.v_active)),
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
            if bpc <= max_bpc && declared {
                if let Some(rate) = frl_link(t, bpc, ycbcr420, cap, audio) {
                    return Some((depth, ycbcr420, Some(rate)));
                }
            }
        }
    }
    None
}

/// The bits per component of an output depth.
fn depth_bpc(depth: otg::ColorDepth) -> u8 {
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
        let Some(timing) = pick(index, &sink.edid, &|t| {
            dp_link(t, caps).is_some() || dp_dsc(t, caps, NOMINAL_DISPCLK_KHZ).is_some()
        }) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        // Uncompressed whenever a link carries the mode, as Linux enables
        // DSC only when needed; otherwise DSC on the maximum 8b/10b link.
        let (lanes, rate, dsc) = match dp_link(&timing, caps) {
            Some((lanes, rate)) => (lanes, rate, None),
            None => match dp_dsc(&timing, caps, NOMINAL_DISPCLK_KHZ) {
                Some(cfg) => (caps.lanes, DpRate::Legacy(caps.rate), Some(cfg)),
                None => {
                    link_short = true;
                    continue;
                }
            },
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
            depth: otg::ColorDepth::Bpc8,
            // HPO (128b/132b) audio is not implemented. Legacy DIO audio
            // shares the secondary stream with DSC's independently owned PPS.
            audio: if matches!(rate, DpRate::Uhbr(_)) {
                None
            } else {
                sink_audio_info(&sink.edid)
            },
            avi: otg::Avi::default(),
            limited: false,
            ycbcr420: false,
            frl: None,
            dsc,
            mst: None,
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
        let Some((depth, ycbcr420, frl)) = hdmi_output(caps, &timing, max_bpc, frl_cap, audio)
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
            caps: DpCaps::NONE,
            edid,
            hdmi: true,
            scdc: caps.scdc,
            depth,
            audio: if frl.is_some() {
                audio.and_then(|a| otg::frl_lpcm_info(a, timing.v_active))
            } else {
                audio
            },
            avi: hdmi_avi(caps, &timing),
            limited: false,
            ycbcr420,
            frl,
            dsc: None,
            mst: None,
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

/// Link settings to try for `timing` from (`lanes`, `rate`), best first. A
/// 128b/132b link walks Linux's bandwidth-ordered fallback table from that
/// setting, as decide_fallback_link_setting's maximum bandwidth policy
/// does, but only through its 128b/132b settings: the timing (and its HPO
/// output mux) is staged for the encoding before the link trains, so a
/// mode that needs 8b/10b instead is a new selection. An 8b/10b link keeps
/// narf's ladder (`link_candidates`). Settings beyond `caps` or that cannot
/// carry the mode are never tried.
pub fn dp_candidates(timing: &Timing, caps: DpCaps, lanes: u8, rate: DpRate) -> Vec<(u8, DpRate)> {
    if let DpRate::Legacy(r) = rate {
        return link_candidates(timing, lanes, r)
            .into_iter()
            .map(|(l, r)| (l, DpRate::Legacy(r)))
            .filter(|&(l, r)| dp_fits(timing, caps, l, r))
            .collect();
    }
    let usable = |(l, r): (u8, DpRate)| {
        l <= caps.lanes
            && match r {
                DpRate::Legacy(_) => false,
                DpRate::Uhbr(r) => caps.uhbr_rates().any(|u| u == r),
            }
            && dp_fits(timing, caps, l, r)
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

/// Preserve the staged DSC/PPS and DML plan while trying lower link settings.
/// A configuration needing a different compressed bpp requires re-admission.
fn selected_dp_candidates(s: &Selection) -> Vec<(u8, DpRate)> {
    let Some(cfg) = s.dsc else {
        return dp_candidates(&s.timing, s.caps, s.lanes, s.rate);
    };
    let DpRate::Legacy(rate) = s.rate else {
        return Vec::new();
    };
    if s.caps.uhbr != 0 || !matches!(s.lanes, 1 | 2 | 4) {
        return Vec::new();
    }
    legacy_candidates(s.lanes, rate, |l, r| {
        l <= s.caps.lanes
            && r as u8 <= s.caps.rate as u8
            && dsc_fits(&s.timing, cfg, l, DpRate::Legacy(r), s.caps.fec)
    })
    .into_iter()
    .map(|(l, r)| (l, DpRate::Legacy(r)))
    .collect()
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
            if dml::admit_all(soc, &joint).is_err() {
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
    dml::Mode {
        timing,
        pitch: (timing.h_active + 63) & !63,
        ycbcr420: false,
        dsc: None,
    }
}

impl Selection {
    /// A 128b/132b (UHBR) DP link.
    pub fn uhbr(&self) -> bool {
        matches!(self.rate, DpRate::Uhbr(_))
    }
}

/// The admission mode of a selected sink: its timing, as 4:2:0 output
/// when it leaves so.
pub fn selection_mode(s: &Selection) -> dml::Mode {
    dml::Mode {
        ycbcr420: s.ycbcr420,
        dsc: s.dsc.map(|c| dml::Dsc {
            slices: c.slices_h,
            bpp_x16: c.bpp_x16,
        }),
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
        self.select_display(pipe)?;
        let soc = self.prepare_configuration(&[selection]).await?;
        refine_dsc(&soc, core::slice::from_mut(&mut selection))?;
        let plans = admit_displays(&soc, &[selection]).map_err(otg::Error::Admission)?;
        self.prepare_pipes(&[selection], &plans, &[pipe]).await?;
        // SAFETY: the caller's obligations.
        let mut lit =
            unsafe { self.light(pipe, selection, plans[0], &mut |_, y, row| fill(y, row)) }.await?;
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
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipe_of: impl Fn(usize) -> Option<u8>,
    ) -> Result<Configuration, ModesetError> {
        self.teardowns.check_idle()?;
        self.modesets.check_stopped()?;
        self.sst_outputs.clear();
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let paths = self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .to_vec();
        self.update_sst_outputs(None, &paths, &ports, &[]);
        let mut selections = match select_all(&paths, &ports, max_bpc(), &want) {
            Ok(selections) => selections,
            // A connected sink without a carrying preferred mode can still
            // offer other modes; an all-off configuration has no stream work.
            Err(ModesetError::NoSink | ModesetError::Link) => Vec::new(),
            Err(e) => return Err(e),
        };
        selections.retain(|s| pipe_of(s.port).is_some_and(|p| p < 4));
        // "Broadcast RGB" is RGB's: YCbCr is limited range by itself.
        let limited = limited_range(broadcast_rgb());
        for s in &mut selections {
            s.limited = limited && !s.ycbcr420;
        }
        let pipes: Vec<u8> = selections.iter().filter_map(|s| pipe_of(s.port)).collect();
        self.select_display(pipes.first().copied().unwrap_or(0))?;
        let soc = self.prepare_configuration(&selections).await?;
        self.update_sst_outputs(Some(&soc), &paths, &ports, &[]);
        if selections.is_empty() {
            return Ok(Configuration {
                displays: Vec::new(),
                failed: None,
            });
        }
        refine_dsc(&soc, &mut selections)?;
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
            self.modesets.retain(lit[k]);
        }
        self.update_sst_outputs(Some(&soc), &paths, &ports, &lit);
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
    /// plan), then each display's pipe clocks on `pipes`, all while every
    /// display is stopped.
    pub(super) async fn prepare_pipes(
        &mut self,
        selections: &[Selection],
        plans: &[dml::Plan],
        pipes: &[u8],
    ) -> Result<(), ModesetError> {
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
        Ok(())
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
        selection: Selection,
        plan: dml::Plan,
        fill: &mut impl FnMut(u8, u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
        self.select_display(pipe)?;
        self.teardowns.begin_activation(pipe, &selection)?;
        // SAFETY: the caller owns this unpublished activation and every writer.
        match unsafe { self.light_inner(pipe, selection, plan, fill) }.await {
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
        selection: Selection,
        plan: dml::Plan,
        fill: &mut impl FnMut(u8, u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
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
            self.prepare_display_timing(timing_request(pipe, &plan, &selection))
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
                hdmi_output(caps, &t, max_bpc(), frl, sink_audio_info(edid)).map(
                    |(_, ycbcr420, _)| dml::Mode {
                        ycbcr420,
                        ..mode(t)
                    },
                )
            } else if let Some(m) = s.mst {
                // Within the stream's own payload.
                super::mst::mst_slots(&t, s.lanes, s.rate, s.caps.fec)
                    .is_some_and(|(pbn, slots)| pbn <= m.pbn && slots <= m.slots)
                    .then(|| mode(t))
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
            for (lanes, link) in candidates {
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
                return Err(refused);
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Link);
            self.prepare_display_dp_frontend(port, otg::DpFrontendRequest { stream: pipe, pipe })
                .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Frontend);
            self.start_display_dp_video(port).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            let scanout = self.start_display_scanout(pipe).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scanout);
            if let Some(info) = selection.audio {
                self.start_display_audio(port, false, info).await?;
            }
            Ok((selection, scanout))
        }
    }
    /// The 128b/132b half of `start_link`: train down Linux's fallback
    /// table on HPO link encoder `pipe` (one display per pipe, as Linux's
    /// first-free assignment gives in display order), then 128b/132b video
    /// on HPO stream encoder `pipe` and scanout. Each setting gets
    /// perform_link_training_with_retries' four attempts, the link stopped
    /// after each refusal and 50 ms more waited before each retry. No
    /// audio: the HPO audio path (APG) is not implemented.
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
        let candidates = dp_candidates(
            &selection.timing,
            selection.caps,
            selection.lanes,
            selection.rate,
        );
        let mut trained = false;
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            'settings: for (lanes, link) in candidates {
                let DpRate::Uhbr(rate) = link else {
                    continue;
                };
                let settings = otg::UhbrSettings { lanes, rate };
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
            self.start_display_uhbr_video(port, pipe, pipe).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            let scanout = self.start_display_scanout(pipe).await?;
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
        use crate::amdgpu_frl_cap::{FrlBorrow, FrlCap};
        let port = selection.port;
        let bpc = depth_bpc(selection.depth);
        let ycbcr420 = selection.ycbcr420;
        let audio = frl_audio(selection.audio, selection.timing.v_active);
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            let trained = self
                .start_frl(port, &selection.timing, bpc, ycbcr420, rate, audio)
                .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scdc);
            let Some(FrlCap::Ok {
                audio_packets_line,
                borrow,
            }) = frl_carries(&selection.timing, bpc, ycbcr420, trained, audio)
            else {
                return Err(ModesetError::Link);
            };
            let request = otg::FrlVideoRequest {
                pipe,
                audio_packets_line: audio_packets_line as u8,
                borrow_from_blank: borrow == FrlBorrow::FromBlank,
                avi: selection.avi,
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
    /// still carries the mode. A timeout or Sink_Version 0 ends it. On
    /// success the link sends FRL output and FRL_Start was awaited.
    /// # Safety
    /// As for `start_link`; the port's sink declared FRL and SCDC.
    pub async unsafe fn start_frl(
        &mut self,
        port: usize,
        timing: &Timing,
        bpc: u8,
        ycbcr420: bool,
        rate: FrlRate,
        audio: crate::amdgpu_frl_cap::FrlAudio,
    ) -> Result<FrlRate, ModesetError> {
        use crate::amdgpu_frl_training::{poll_start, train_with_retries, FrlTraining};
        let mut code = rate.code();
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            loop {
                let r = FrlRate::new(code).ok_or(ModesetError::Link)?;
                if frl_carries(timing, bpc, ycbcr420, r, audio).is_none() {
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
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            if m.selection.uhbr() {
                self.stop_display_scanout(m.pipe).await?;
                self.stop_uhbr(port, false).await?;
                (m.selection, m.scanout) = self.start_link(m.selection, m.pipe).await?;
                self.retain_retrained_modeset(m, &soc);
                return Ok(());
            }
            if m.selection.audio.is_some() {
                self.stop_display_audio(port, false).await?;
            }
            self.stop_display_scanout(m.pipe).await?;
            self.stop_display_dp_video(port).await?;
            self.stop_display_dp_frontend(port).await?;
            self.stop_display_dp_link(port).await?;
            (m.selection, m.scanout) = self.start_link(m.selection, m.pipe).await?;
            self.retain_retrained_modeset(m, &soc);
        }
        Ok(())
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
