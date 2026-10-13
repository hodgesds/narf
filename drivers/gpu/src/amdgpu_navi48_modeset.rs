//! Orchestrated native Navi48 modeset on one legacy DP SST or TMDS HDMI
//! connector: choose the first answering DisplayPort sink (else the first HDMI
//! sink) and its EDID preferred mode, admit it,
//! then run the retained owners' preparations in their dependency order and
//! make the uploaded surface visible. Inherited (GOP) consumers must already
//! be retired; the clock owners refuse otherwise.
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
    for cta in &ctas {
        for block in &cta.data_blocks {
            if let narf_edid::cta861::DataBlock::Video(svds) = block {
                fixed.extend(svds.iter().filter_map(|svd| modes::cea_mode(svd.vic)));
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
    /// VSDB DC_30bit / DC_36bit: RGB 4:4:4 at 10 / 12 bpc.
    pub dc30: bool,
    pub dc36: bool,
}
pub fn hdmi_caps(edid: &[u8]) -> HdmiCaps {
    use narf_edid::cta861::{CtaExtension, DataBlock};
    let mut caps = HdmiCaps::default();
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
            if let Some(&[_version, rate, flags, ..]) = forum {
                caps.forum_max_khz = u32::from(rate) * 5000;
                caps.scdc = flags & 0x80 != 0;
            }
        }
    }
    caps
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
    // The requested mode where the sink lists it and it fits, else the
    // preferred one.
    let pick = |edid: &[u8], fits: &dyn Fn(&Timing) -> bool| {
        want.filter(|w| edid_timings(edid).contains(w) && fits(w))
            .or_else(|| preferred(edid))
    };
    let mut link_short = false;
    for port in ports {
        if port.path.connector != inventory::Connector::DisplayPort {
            continue;
        }
        let Ok(sink) = &port.sink else { continue };
        let Some((lanes, rate)) = sink.dpcd.as_ref().and_then(|d| max_link(d, sink.lttpr)) else {
            continue;
        };
        let Some(timing) = pick(&sink.edid, &|t| link_fits(t, lanes, rate)) else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        if !link_fits(&timing, lanes, rate) {
            link_short = true;
            continue;
        }
        return Ok(Selection {
            port: index,
            timing,
            lanes,
            rate,
            edid,
            hdmi: false,
            scdc: false,
            depth: otg::ColorDepth::Bpc8,
            audio: None,
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
        let Some(timing) = pick(&sink.edid, &|t| {
            hdmi_depth(caps, t.pixel_clock_khz, max_bpc).is_some()
        }) else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let Some(depth) = hdmi_depth(caps, timing.pixel_clock_khz, max_bpc) else {
            link_short = true;
            continue;
        };
        return Ok(Selection {
            port: index,
            timing,
            lanes: 0,
            rate: LinkRate::Rbr,
            edid,
            hdmi: true,
            scdc: caps.scdc,
            depth,
            audio: hdmi_audio_info(&sink.edid),
        });
    }
    Err(if link_short {
        ModesetError::Link
    } else {
        ModesetError::NoSink
    })
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
        pixel: if hdmi {
            dccg::PixelClock::Tmds {
                divider: dccg::TmdsDivider::By4,
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
    /// Inherited display consumers must be retired. Exclude firmware/FAMS and
    /// concurrent display/hub/VM/IRQ/clock/reset/power/link writers; retain
    /// every owner and allocation on every outcome, including cancellation.
    /// A failure leaves the owners where they stopped; nothing is unwound.
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
    /// mode.
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
        let paths = self.display_paths().map_err(|_| ModesetError::NoSink)?;
        let selection = select(paths, &ports, max_bpc(), want)?;
        let full_edid = ports
            .iter()
            .find(|p| paths.get(selection.port) == Some(&p.path))
            .and_then(|p| p.sink.as_ref().ok())
            .map(|sink| sink.edid.clone())
            .unwrap_or_default();
        let mode = mode(selection.timing);
        // The first clock request starts PMFW and publishes the DPM levels
        // admission needs; requests are clamped up to each clock's minimum.
        let floor = clocks::Request {
            displays: 1,
            display_khz: 1,
            dpp_khz: 1,
            dtb_khz: 1,
        };
        self.prepare_display_clocks(floor)
            .await
            .map_err(ModesetError::Clocks)?;
        let plan = self.display_admission(&mode)?;
        self.prepare_display_clocks(clock_request(&plan))
            .await
            .map_err(ModesetError::Clocks)?;
        self.prepare_display_pipe_clocks(pipe_clock_request(pipe, &plan, selection.hdmi))
            .await
            .map_err(ModesetError::PipeClocks)?;
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
                fill(y, &mut row);
                self.upload_display_surface(pipe, 0, y, &row)?;
            }
            self.prepare_display_memory(pipe).await?;
            self.prepare_display_timing(timing_request(pipe, &plan, selection.hdmi))
                .await?;
            self.prepare_display_blank(otg::BlankRequest {
                pipe,
                depth: selection.depth,
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
            let modes = self.offered_modes(&selection, &full_edid);
            Ok(Modeset {
                selection,
                pipe,
                plan,
                scanout,
                modes,
            })
        }
    }
    /// The sink's timings a later modeset could switch to: they fit the link
    /// the selection trained (DP) or a TMDS depth (HDMI) and DML admits them
    /// at the current clock levels. The running timing is always included.
    fn offered_modes(&mut self, s: &Selection, edid: &[u8]) -> [Option<Timing>; MAX_MODES] {
        let caps = hdmi_caps(edid);
        let mut modes = [None; MAX_MODES];
        let mut n = 0;
        for t in edid_timings(edid) {
            if n == MAX_MODES {
                break;
            }
            let fits = if s.hdmi {
                hdmi_depth(caps, t.pixel_clock_khz, max_bpc()).is_some()
            } else {
                link_fits(&t, s.lanes, s.rate)
            };
            if t == s.timing || (fits && self.display_admission(&mode(t)).is_ok()) {
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
                let request = otg::HdmiLinkRequest { stream: pipe, pipe };
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
        // Linux decides on phy_pix_clk, the deep-colour character clock.
        let scrambled = tmds.character_khz(s.timing.pixel_clock_khz) > otg::TMDS_SCRAMBLE_KHZ;
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
