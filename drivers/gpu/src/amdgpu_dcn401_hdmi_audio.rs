//! Native DCN401 audio on a running TMDS, FRL or DP stream: the display half
//! only (the HD-Audio controller and codec stream the samples).
//!
//! HDMI, in Linux's order: dce_aud_wall_dto_setup (DTO0 from the pixel
//! clock; DCN401 has no audio DTBCLK DTO), enc3_se_hdmi_audio_setup (AFMT
//! clock, AFMT channel status, ACR N/CTS, audio source and channel enable),
//! dce_aud_az_configure (the Azalia endpoint the codec reports as ELD), the
//! Audio InfoFrame enable of enc401_stream_encoder_hdmi_set_stream_attribute,
//! dce_aud_az_enable and enc3_audio_mute_control(false). Stopping reverses
//! it: mute, AFMT clock off (enc1_se_hdmi_audio_disable), then
//! dce_aud_az_disable.
//!
//! FRL: the child module programs AFMT4 and lane-rate ACR. The first HDMI
//! audio pipe selects the shared wall clock: TMDS uses DTO0; FRL uses DTO1
//! from DPREFCLK. DP uses DTO1 when no HDMI audio pipe is present.
//! DP: enc3_se_dp_audio_setup (audio source, channel enable),
//! dce_aud_az_configure for a DP connection, dce_aud_az_enable, then
//! enable_dio_audio_packet: enc3_se_dp_audio_enable (AFMT clock, audio N and
//! timestamp mode, AFMT channel status, then the DP secondary audio stream,
//! timestamp and InfoFrame packets) and unmute. Stopping is
//! disable_dio_audio_packet (mute, packets off, AFMT clock off), then
//! dce_aud_az_disable.
use super::*;
#[path = "amdgpu_dcn401_frl_audio.rs"]
mod frl_audio;
#[path = "amdgpu_dcn401_uhbr_audio.rs"]
mod uhbr_audio;
pub(crate) use uhbr_audio::uhbr_audio_info;
#[path = "amdgpu_dcn401_dp_audio_bw.rs"]
mod bandwidth;
#[path = "amdgpu_dcn401_mst_audio.rs"]
mod mst_audio;
pub(crate) use mst_audio::mst_audio_info;
pub use mst_audio::MstAudioPayload;

/// One CEA Short Audio Descriptor, as amdgpu_dm copies it from the EDID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AudioMode {
    /// CEA audio format code, 1 (LPCM) to 14.
    pub format: u8,
    pub channels: u8,
    /// Sample-rate bits: 32, 44.1, 48, 88.2, 96, 176.4, 192 kHz.
    pub rates: u8,
    /// LPCM sample sizes, or the format's max bit rate / vendor byte.
    pub byte2: u8,
}
/// What the sink's EDID says about audio, as amdgpu_dm_fill_audio_info builds
/// Linux's audio_info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioInfo {
    pub manufacturer_id: u16,
    pub product_id: u16,
    /// Monitor name, NUL-padded (AUDIO_INFO_DISPLAY_NAME_SIZE_IN_CHARS).
    pub name: [u8; 18],
    /// Speaker Allocation byte (bit 7: SUPPORT_AI), default 5 (FL/FR, FC).
    pub speakers: u8,
    pub modes: [AudioMode; 16],
    pub mode_count: u8,
    /// HDMI VSDB progressive latencies, zero when not declared.
    pub video_latency: u8,
    pub audio_latency: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayAudio {
    pub info: AudioInfo,
    /// Carried by DP secondary packets rather than HDMI's AFMT packets.
    pub dp: bool,
    /// Azalia endpoint (Linux's audio instance): the stream's own.
    pub endpoint: u8,
    /// AFMT channel enables from speakers, or APG pair-mode enables (0xff).
    pub channels: u8,
    /// What the endpoint advertised: per-format words, HBR capability.
    pub descriptors: [u32; 14],
    pub hbr: bool,
}

/// The SADs dce_aud_az_configure can program for a transport whose LPCM
/// rates the caller filters: LPCM with channels, rates and sample sizes, and
/// compressed formats (passed through unfiltered, as Linux does) with
/// channels and rates, except one-bit audio and DST, which the endpoint
/// never carries. `None` without LPCM: the codec cannot stream anything.
pub(crate) fn audio_info(mut info: AudioInfo) -> Option<AudioInfo> {
    if info.mode_count == 0 || info.mode_count > 16 {
        return None;
    }
    let mut count = 0;
    let mut lpcm = false;
    let modes = info.modes;
    for mut mode in modes[..usize::from(info.mode_count)].iter().copied() {
        mode.rates &= 0x7f;
        if !(1..=8).contains(&mode.channels) || mode.rates == 0 {
            continue;
        }
        match mode.format {
            1 => {
                mode.byte2 &= 7;
                if mode.byte2 == 0 {
                    continue;
                }
                lpcm = true;
            }
            2..=8 | 10..=12 | 14 => {}
            _ => continue,
        }
        info.modes[count] = mode;
        count += 1;
    }
    info.modes[count..].fill(AudioMode::default());
    info.mode_count = count as u8;
    lpcm.then_some(info)
}

/// `audio_info` with each LPCM SAD's rates narrowed by `filter(channels,
/// rates)`; a `None` filter result rejects the whole timing/link.
pub(crate) fn filtered_audio_info(
    info: AudioInfo,
    mut filter: impl FnMut(u8, u8) -> Option<u8>,
) -> Option<AudioInfo> {
    let mut info = audio_info(info)?;
    for mode in &mut info.modes[..usize::from(info.mode_count)] {
        if mode.format == 1 {
            mode.rates = filter(mode.channels, mode.rates)?;
        }
    }
    audio_info(info)
}

/// FRL's SD layouts are limited to two LPCM channels by dce_aud_az_configure.
pub(crate) fn frl_audio_info(info: AudioInfo, v_active: u32) -> Option<AudioInfo> {
    let mut info = audio_info(info)?;
    if v_active <= 576 {
        for mode in &mut info.modes[..usize::from(info.mode_count)] {
            if mode.format == 1 {
                mode.channels = mode.channels.min(2);
            }
        }
        info.speakers = (info.speakers & 0x80) | 1;
    }
    Some(info)
}

// DIG/AFMT registers (DIG stride).
const AFMT_CNTL: u64 = 0x20ba;
const AUDIO_PACKET: u64 = 0x20a0;
const ACR_PACKET: u64 = 0x20a1;
const INFOFRAME0: u64 = 0x20a3;
const INFOFRAME1: u64 = 0x20a4;
const ACR: u64 = 0x20b2; // 32k CTS, N; 44.1k CTS, N; 48k CTS, N
const AFMT_PACKET2: u64 = 0x2075;
const AFMT_60958: [u64; 3] = [0x2078, 0x2079, 0x207f];
const AFMT_PACKET: u64 = 0x2082;
const AFMT_INFOFRAME0: u64 = 0x2083;
const AFMT_SRC: u64 = 0x2085;
const AFMT_MEM_PWR: u64 = 0x2087;
// Azalia endpoint indirect registers (dce_11_0_d.h ix* indices).
const AZ_SPEAKER: u32 = 0x25;
const AZ_ACP: u32 = 0x27;
const AZ_DESCRIPTOR0: u32 = 0x28;
const AZ_LIPSYNC: u32 = 0x37;
const AZ_HBR: u32 = 0x38;
const AZ_SINK_INFO0: u32 = 0x3a;
const AZ_HOT_PLUG: u32 = 0x54;
// DP stream encoder secondary-data registers (DIG stride).
const DP_SEC_CNTL: u64 = 0x2141;
const DP_SEC_AUD_N: u64 = 0x2147;
const DP_SEC_TIMESTAMP: u64 = 0x214b;
/// DP_SEC_STREAM_ENABLE, ASP (audio stream), ATP (audio timestamp) and AIP
/// (audio InfoFrame) packet enables: what DP audio owns of DP_SEC_CNTL.
pub(in crate::amdgpu_dcn401_otg) const DP_SEC_AUDIO: u32 = 0x1111;
// Global DCCG audio wall clock (DCN bank 1).
const AUDIO_DTO_SOURCE: u64 = 0xab;
const AUDIO_DTO0_PHASE: u64 = 0xac;
const AUDIO_DTO0_MODULE: u64 = 0xad;
const AUDIO_DTO1_PHASE: u64 = 0xae;
const AUDIO_DTO1_MODULE: u64 = 0xaf;
const CLOCK_GATING_DISABLE: u32 = 1;
const AUDIO_ENABLED: u32 = 0x8000_0000;
/// Linux's hard-coded audio_info.port_id when no container id exists.
const PORT_ID: [u32; 2] = [0x5558859e, 0x0d989449];

/// {pixel clock in 10 kHz, N/CTS for 32, 44.1 and 48 kHz}: Linux's
/// audio_clock_info_table (24 and 30 bpc) and its 36-bpc table.
type AcrRow = (u32, [u32; 6]);
const ACR_24: [AcrRow; 16] = [
    (2517, [4576, 28125, 7007, 31250, 6864, 28125]),
    (2518, [4576, 28125, 7007, 31250, 6864, 28125]),
    (2520, [4096, 25200, 6272, 28000, 6144, 25200]),
    (2700, [4096, 27000, 6272, 30000, 6144, 27000]),
    (2702, [4096, 27027, 6272, 30030, 6144, 27027]),
    (2703, [4096, 27027, 6272, 30030, 6144, 27027]),
    (5400, [4096, 54000, 6272, 60000, 6144, 54000]),
    (5405, [4096, 54054, 6272, 60060, 6144, 54054]),
    (7417, [11648, 210937, 17836, 234375, 11648, 140625]),
    (7425, [4096, 74250, 6272, 82500, 6144, 74250]),
    (14835, [11648, 421875, 8918, 234375, 5824, 140625]),
    (14850, [4096, 148500, 6272, 165000, 6144, 148500]),
    (29670, [5824, 421875, 4459, 234375, 5824, 281250]),
    (29700, [3072, 222750, 4704, 247500, 5120, 247500]),
    (59340, [5824, 843750, 8918, 937500, 5824, 562500]),
    (59400, [3072, 445500, 9408, 990000, 6144, 594000]),
];
const ACR_36: [AcrRow; 14] = [
    (2517, [9152, 84375, 7007, 48875, 9152, 56250]),
    (2518, [9152, 84375, 7007, 48875, 9152, 56250]),
    (2520, [4096, 37800, 6272, 42000, 6144, 37800]),
    (2700, [4096, 40500, 6272, 45000, 6144, 40500]),
    (2702, [8192, 81081, 6272, 45045, 8192, 54054]),
    (2703, [8192, 81081, 6272, 45045, 8192, 54054]),
    (5400, [4096, 81000, 6272, 90000, 6144, 81000]),
    (5405, [4096, 81081, 6272, 90090, 6144, 81081]),
    (7417, [11648, 316406, 17836, 351562, 11648, 210937]),
    (7425, [4096, 111375, 6272, 123750, 6144, 111375]),
    (14835, [11648, 632812, 17836, 703125, 11648, 421875]),
    (14850, [4096, 222750, 6272, 247500, 6144, 222750]),
    (29670, [5824, 632812, 8918, 703125, 5824, 421875]),
    (29700, [4096, 445500, 4704, 371250, 5120, 371250]),
];
/// Linux get_audio_clock_info: an exact table match, else HDMI's "Other"
/// column (N 4096/6272/6144, CTS = pixel clock in kHz). Returns
/// [N32, CTS32, N44, CTS44, N48, CTS48].
pub(crate) fn acr(depth: dmub::TmdsDepth, pixel_khz: u32) -> [u32; 6] {
    let table: &[AcrRow] = match depth {
        dmub::TmdsDepth::Bpc12 => &ACR_36,
        _ => &ACR_24,
    };
    let key = pixel_khz / 10;
    if let Some((_, row)) = table.iter().find(|(clock, _)| *clock == key) {
        return *row;
    }
    [4096, pixel_khz, 6272, pixel_khz, 6144, pixel_khz]
}
/// dcn30_afmt speakers_to_channels: CEA channel enables from speaker bits
/// (FL_FR, LFE, FC, RL_RR, RC, FLC_FRC, RLC_RRC).
pub(crate) fn channels(speakers: u8) -> u8 {
    let s = |bit: u8| speakers >> bit & 1;
    let (fl_fr, lfe, fc, rl_rr, rc, flc_frc, rlc_rrc) = (s(0), s(1), s(2), s(3), s(4), s(5), s(6));
    // Rear left/right present: RC moves to channel 7, else to channel 5.
    let (rl_rc, rr) = if rl_rr != 0 { (rl_rr, rl_rr) } else { (rc, 0) };
    // Front and rear centre pairs are exclusive.
    let pair = if flc_frc != 0 { flc_frc } else { rlc_rrc };
    fl_fr | fl_fr << 1 | lfe << 2 | fc << 3 | rl_rc << 4 | rr << 5 | pair << 6 | pair << 7
}
/// check_audio_bandwidth_hdmi: drop LPCM rates the timing's blanking cannot
/// carry (progressive, no pixel repetition).
pub(in crate::amdgpu_dcn401_otg) fn hdmi_rates(
    t: &crate::amdgpu_dml::Timing,
    depth: dmub::TmdsDepth,
    channels: u8,
    rates: u8,
) -> u8 {
    let pixel_100hz = u64::from(t.pixel_clock_khz) * 10;
    let (mut to_48, mut to_88, mut to_96, mut to_176) = (false, false, false, false);
    if channels > 2 {
        if pixel_100hz <= 270_000 && t.v_active <= 576 {
            to_48 = true;
        } else if pixel_100hz <= 540_000 && t.v_active <= 576 {
            to_176 = true;
        }
    }
    let refresh = pixel_100hz * 100 / (u64::from(t.h_total) * u64::from(t.v_total));
    let blank = u64::from(t.h_total - t.h_active).saturating_sub(58 + 16);
    let mut samples = blank * 10 / 32 * u64::from(t.v_active) * (refresh & 0xffff) / 10;
    samples = samples
        * match depth {
            dmub::TmdsDepth::Bpc8 => 4,
            dmub::TmdsDepth::Bpc10 => 5,
            dmub::TmdsDepth::Bpc12 => 6,
        }
        / 4;
    if samples < 88_200 {
        to_48 = true;
    } else if samples < 96_000 {
        to_88 = true;
    } else if samples < 176_400 {
        to_96 = true;
    } else if samples < 192_000 {
        to_176 = true;
    }
    let mut r = rates;
    if to_176 {
        r &= !0x40;
    }
    if to_96 {
        r &= !0x60;
    }
    if to_88 {
        r &= !0x70;
    }
    if to_48 {
        r &= !0x78;
    }
    r
}
/// check_audio_bandwidth for a stream: HDMI's blanking limit, or every
/// rate for DP SST over 8b/10b (Linux's check_audio_bandwidth_dp leaves
/// that case unvalidated).
fn stream_rates(
    t: &crate::amdgpu_dml::Timing,
    depth: Option<dmub::TmdsDepth>,
    channels: u8,
    rates: u8,
) -> u8 {
    match depth {
        Some(depth) => hdmi_rates(t, depth, channels, rates),
        None => rates,
    }
}
/// dce_aud_az_configure's per-format descriptor words and HBR capability,
/// for an HDMI stream at `depth` or (None) a DP SST one.
pub(crate) fn descriptors(
    info: &AudioInfo,
    t: &crate::amdgpu_dml::Timing,
    depth: Option<dmub::TmdsDepth>,
) -> ([u32; 14], bool, bool) {
    let modes = &info.modes[..usize::from(info.mode_count.min(16))];
    let mut words = [0u32; 14];
    let mut ac3 = false;
    for code in 1u8..=14 {
        // The mode with the most channels, first on ties.
        let Some(m) = modes.iter().filter(|m| m.format == code).fold(
            None::<&AudioMode>,
            |best, m| match best {
                Some(b) if b.channels >= m.channels => Some(b),
                _ => Some(m),
            },
        ) else {
            continue;
        };
        let mut rates = m.rates;
        let mut word = 0;
        if code == 1 {
            rates = stream_rates(t, depth, m.channels, rates);
            word |= u32::from(rates) << 24; // SUPPORTED_FREQUENCIES_STEREO
        }
        ac3 |= code == 2;
        word |= u32::from(m.channels.saturating_sub(1)) & 7;
        word |= u32::from(rates) << 8;
        word |= u32::from(m.byte2) << 16;
        words[usize::from(code - 1)] = word;
    }
    let hbr = stream_rates(t, depth, 8, 0x40) & 0x40 != 0;
    (words, ac3, hbr)
}
impl<I: Io> Engine<I> {
    fn az_at(&self, endpoint: u8) -> u64 {
        self.layout.base + (0x386 + 6 * u64::from(endpoint)) * 4
    }
    fn az_read(&mut self, endpoint: u8, index: u32) -> Result<u32, Error> {
        let at = self.az_at(endpoint);
        self.access(|io| {
            io.write(at, index);
            checked(io.read(at + 4))
        })
    }
    /// The endpoint data port is an indirect window: written, never echoed.
    fn az_write(&mut self, endpoint: u8, index: u32, value: u32) -> Result<(), Error> {
        let at = self.az_at(endpoint);
        self.access(|io| {
            io.write(at, index);
            io.write(at + 4, value);
            Ok(())
        })
    }
    fn az_update(&mut self, endpoint: u8, index: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.az_read(endpoint, index)?;
        self.az_write(endpoint, index, (old & !mask) | (value & mask))
    }
    /// Every display's records, the selected one's current. Borrowed: the
    /// records are large.
    fn display_records(&self) -> impl Iterator<Item = &Status> {
        let selected = usize::from(self.displays.selected);
        self.displays
            .parked
            .iter()
            .enumerate()
            .map(move |(k, s)| if k == selected { &*self.status } else { s })
    }
    fn audio_endpoint_available(&self, endpoint: u8) -> bool {
        endpoint < 4
            && self.display_records().all(|s| {
                [s.hdmi_audio, s.dp_audio, s.frl_audio, s.uhbr_audio]
                    .into_iter()
                    .flatten()
                    .all(|a| a.endpoint != endpoint)
            })
    }
    /// dce110_setup_audio_dto: one audio wall clock serves every display.
    /// The lowest HDMI audio pipe wins: TMDS uses DTO0 from its pixel clock,
    /// FRL uses DTO1 from DPREFCLK (DCN401 has no audio DTBCLK DTO). With no
    /// HDMI audio, the lowest DP audio pipe selects DTO1. No audio leaves
    /// the clock as it was. Reference clocks have no atomfirmware v4 spread.
    fn audio_wall_dto(&mut self) -> Result<(), Error> {
        let hdmi = self
            .display_records()
            .filter_map(|s| {
                if s.hdmi_audio.is_some() {
                    s.hdmi_video_running
                        .map(|v| (v.link.request.pipe, Some(v.link.pixel_khz), 0))
                } else if s.frl_audio.is_some() {
                    s.frl_video_running.map(|v| {
                        (
                            v.request.pipe,
                            None,
                            v.timing.blank.timing.clock.reference_hz,
                        )
                    })
                } else {
                    None
                }
            })
            .min_by_key(|&(pipe, _, _)| pipe);
        let dp = self
            .display_records()
            .filter_map(|s| {
                if s.dp_audio.is_some() {
                    s.dp_video_running.map(|v| v.frontend.blank)
                } else if s.uhbr_audio.is_some() {
                    s.uhbr_video_running.map(|v| v.timing.blank)
                } else {
                    None
                }
            })
            .min_by_key(|b| b.request.pipe);
        let bank1 = self.layout.dio_clock - 0xa0 * 4;
        let at = |r: u64| bank1 + r * 4;
        if let Some((pipe, Some(pixel_khz), _)) = hdmi {
            // Source and DTO select before modulo and phase.
            self.update(at(AUDIO_DTO_SOURCE), 0x37, u32::from(pipe))?;
            self.update(at(AUDIO_DTO0_MODULE), u32::MAX, pixel_khz * 10)?;
            self.update(at(AUDIO_DTO0_PHASE), u32::MAX, 24 * 10_000)
        } else if let Some(reference_hz) = hdmi
            .map(|(_, _, hz)| hz)
            .or_else(|| dp.map(|b| b.timing.clock.reference_hz))
        {
            let dpref_khz = reference_hz / 1000;
            if dpref_khz == 0 {
                return Err(Error::Invalid);
            }
            self.update(at(AUDIO_DTO_SOURCE), 0x30, 0x10)?;
            self.update(at(AUDIO_DTO1_MODULE), u32::MAX, dpref_khz * 10)?;
            self.update(at(AUDIO_DTO1_PHASE), u32::MAX, 24 * 10_000)?;
            // DCCG_AUDIO_DTO2_USE_512FBR_DTO.
            self.update(at(AUDIO_DTO_SOURCE), 0x10_0000, 0x10_0000)
        } else {
            Ok(())
        }
    }
    fn hdmi_audio_encoder(&mut self, link: &HdmiLinkReady, a: &DisplayAudio) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Dio(link.request.stream).at(l, r);
        self.update(at(AFMT_CNTL), 1, 1)?;
        // afmt3_setup_hdmi_audio: channel-status update request, no layout or
        // OSF override, IEC 60958 channel numbers 1..8.
        self.access(|io| {
            let v = checked(io.read(at(AFMT_PACKET)))?;
            io.write(at(AFMT_PACKET), v | 0x0400_0000);
            Ok(())
        })?;
        self.update(at(AFMT_PACKET2), 0x1000_0001, 0)?;
        self.update(at(AFMT_60958[0]), 0x30f0_0000, 0x0010_0000)?;
        self.update(at(AFMT_60958[1]), 0x00f0_0000, 0x0020_0000)?;
        self.update(at(AFMT_60958[2]), 0x00ff_ffff, 0x0087_6543)?;
        self.update(at(AUDIO_PACKET), 0x30, 0x10)?; // HDMI_AUDIO_DELAY_EN
                                                    // Automatic ACR with hardware CTS; N per Linux's tables.
        self.update(at(ACR_PACKET), 0x8000_1100, 0x1000)?;
        let nc = acr(link.depth, link.pixel_khz);
        for (i, rate) in nc.chunks_exact(2).enumerate() {
            let base = ACR + 2 * i as u64;
            self.update(at(base), 0xffff_f000, rate[1] << 12)?;
            self.update(at(base + 1), 0x000f_ffff, rate[0])?;
        }
        self.audio_source(link.request.stream, a)
    }
    /// afmt3_se_audio_setup: endpoint -> DIG, channel enables, memory on.
    fn audio_source(&mut self, stream: u8, a: &DisplayAudio) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Dio(stream).at(l, r);
        self.update(at(AFMT_SRC), u32::MAX, u32::from(a.endpoint))?; // REG_SET
        self.update(at(AFMT_PACKET2), 0xff00, u32::from(a.channels) << 8)?;
        self.update(at(AFMT_MEM_PWR), 0x30, 0)
    }
    fn hdmi_audio_endpoint(&mut self, a: &DisplayAudio, ac3: bool) -> Result<(), Error> {
        let e = a.endpoint;
        let info = &a.info;
        self.az_update(e, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, CLOCK_GATING_DISABLE)?;
        // Speakers, the HDMI or DP connection (which the codec reports as
        // the ELD's connection type), LFE level 0, EXTRA_CONNECTION_INFO bit
        // 0 cleared.
        let connection = if a.dp { 0x2_0000 } else { 0x1_0000 };
        self.az_update(
            e,
            AZ_SPEAKER,
            0x7f | 0x3_0000 | 0x4_0000 | 0x300_0000,
            u32::from(info.speakers & 0x7f) | connection,
        )?;
        self.az_update(e, AZ_ACP, 0x40, u32::from(info.speakers >> 7) << 6)?;
        for code in 1u32..=14 {
            if code == 9 || code == 13 {
                continue; // One-bit audio and DST are never programmed
            }
            let word = a.descriptors[(code - 1) as usize];
            self.az_write(e, AZ_DESCRIPTOR0 + code - 1, word)?;
        }
        if ac3 {
            self.update(self.layout.base + 0x40c * 4, u32::MAX, 5)?;
        }
        self.az_update(e, AZ_HBR, 1, u32::from(a.hbr))?;
        self.az_update(e, AZ_LIPSYNC, 0xff, u32::from(info.video_latency))?;
        self.az_update(e, AZ_LIPSYNC, 0xff00, u32::from(info.audio_latency) << 8)?;
        let id = u32::from(info.manufacturer_id) | u32::from(info.product_id) << 16;
        self.az_write(e, AZ_SINK_INFO0, id)?;
        let len = info
            .name
            .iter()
            .position(|b| *b == 0)
            .map_or(18, |n| (n + 1).min(18));
        self.az_write(e, AZ_SINK_INFO0 + 1, len as u32)?;
        self.az_write(e, AZ_SINK_INFO0 + 2, PORT_ID[0])?;
        self.az_write(e, AZ_SINK_INFO0 + 3, PORT_ID[1])?;
        for (i, chunk) in info.name.chunks(4).enumerate() {
            let mut b = [0u8; 4];
            b[..chunk.len()].copy_from_slice(chunk);
            self.az_write(e, AZ_SINK_INFO0 + 4 + i as u32, u32::from_le_bytes(b))?;
        }
        self.az_update(e, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, 0)
    }
    /// The audio owner's live registers on top of the link's.
    pub(in crate::amdgpu_dcn401_otg) fn hdmi_audio_verify(
        &mut self,
        link: &HdmiLinkReady,
        a: &DisplayAudio,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Dio(link.request.stream).at(l, r);
        for (reg, mask, value) in [
            (at(AFMT_CNTL), 1, 1),
            (at(AFMT_PACKET), 1, 1),
            (at(AFMT_SRC), 7, u32::from(a.endpoint)),
            (at(AFMT_PACKET2), 0xff00, u32::from(a.channels) << 8),
            (at(INFOFRAME0), 0x10, 0x10),
            (at(ACR_PACKET), 0x8000_1100, 0x1000),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | CLOCK_GATING_DISABLE)
            != AUDIO_ENABLED
        {
            return Err(Error::Readback(self.az_at(a.endpoint)));
        }
        Ok(())
    }
    /// The HDMI link a running video carries, from video to live scanout.
    fn hdmi_audio_link(&self, path: Path) -> Result<HdmiLinkReady, Error> {
        let running = self.status.hdmi_video_running.ok_or(Error::Busy)?;
        let link = running.link;
        let live = match self.status.state {
            State::HdmiVideoRunning(s) => s == link.request.stream,
            State::ScanoutRunning(p) => p == link.request.pipe,
            _ => false,
        };
        if !live {
            return Err(Error::Busy);
        }
        if link.path != path {
            return Err(Error::Invalid);
        }
        Ok(link)
    }
    async fn hdmi_audio_start(
        &mut self,
        link: HdmiLinkReady,
        a: DisplayAudio,
        ac3: bool,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Dio(link.request.stream).at(l, r);
        self.audio_wall_dto()?;
        self.hdmi_audio_encoder(&link, &a)?;
        self.hdmi_audio_endpoint(&a, ac3)?;
        // Audio InfoFrame on line 2; the hardware builds it from the codec's
        // channel allocation. Latch the double-buffered AUDIO_INFO now.
        self.update(at(INFOFRAME0), 0x10, 0x10)?;
        self.access(|io| {
            let v = checked(io.read(at(AFMT_INFOFRAME0)))?;
            io.write(at(AFMT_INFOFRAME0), v | 0x80);
            Ok(())
        })?;
        self.update(at(INFOFRAME1), 0x3f00, 2 << 8)?;
        // dce_aud_az_enable, then unmute (AFMT_AUDIO_SAMPLE_SEND).
        self.az_update(
            a.endpoint,
            AZ_HOT_PLUG,
            AUDIO_ENABLED | 1,
            AUDIO_ENABLED | 1,
        )?;
        self.az_update(a.endpoint, AZ_HOT_PLUG, 1, 0)?;
        self.update(at(AFMT_PACKET), 1, 1)?;
        self.hdmi_audio_verify(&link, &a)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_hdmi_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
    ) -> Result<DisplayAudio, Error> {
        if self.status.frl_video_running.is_some() {
            return self.start_frl_audio(path, info);
        }
        if self.status.hdmi_audio.is_some() || info.mode_count == 0 || info.mode_count > 16 {
            return Err(if self.status.hdmi_audio.is_some() {
                Error::Busy
            } else {
                Error::Invalid
            });
        }
        let link = self.hdmi_audio_link(path)?;
        let t = link.blank.timing.request.timing;
        let (descriptors, ac3, hbr) = descriptors(&info, &t, Some(link.depth));
        if descriptors[0] == 0 {
            return Err(Error::Unsupported); // no LPCM: nothing the codec can stream
        }
        let a = DisplayAudio {
            info,
            dp: false,
            endpoint: link.request.stream,
            channels: channels(info.speakers),
            descriptors,
            hbr,
        };
        if !self.audio_endpoint_available(a.endpoint) {
            return Err(Error::Busy);
        }
        // Quiet before the first write: no audio clock, samples or packets.
        let at = |r| DpStream::Dio(link.request.stream).at(self.layout, r);
        for (reg, mask) in [
            (at(AFMT_CNTL), 1),
            (at(AFMT_PACKET), 1),
            (at(INFOFRAME0), 0x30),
        ] {
            if self.read(reg)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // Recorded first: the wall clock is chosen from every record.
        self.status.hdmi_audio = Some(a);
        match self.hdmi_audio_start(link, a, ac3).await {
            Ok(()) => Ok(a),
            Err(e) => {
                self.status.hdmi_audio = None;
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_hdmi_audio(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        if self.status.frl_video_running.is_some() {
            return self.stop_frl_audio(path);
        }
        let a = self.status.hdmi_audio.ok_or(Error::Invalid)?;
        let link = self.hdmi_audio_link(path)?;
        self.hdmi_audio_verify(&link, &a)?;
        let l = self.layout;
        let at = |r| DpStream::Dio(link.request.stream).at(l, r);
        let result = (|| {
            // disable_dio_audio_packet: mute, then the AFMT audio clock.
            self.update(at(AFMT_PACKET), 1, 0)?;
            self.update(at(AFMT_CNTL), 1, 0)?;
            self.update(at(INFOFRAME0), 0x30, 0)?;
            self.az_disable(a.endpoint)
        })();
        match result {
            Ok(()) => {
                self.status.hdmi_audio = None;
                // The next display's audio, if any, takes the wall clock.
                self.audio_wall_dto()
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl<I: Io> Engine<I> {
    /// dce_aud_az_disable.
    fn az_disable(&mut self, endpoint: u8) -> Result<(), Error> {
        self.az_update(endpoint, AZ_HOT_PLUG, 1, 1)?;
        self.az_update(endpoint, AZ_HOT_PLUG, AUDIO_ENABLED, 0)?;
        self.az_update(endpoint, AZ_HOT_PLUG, 1, 0)
    }
    /// The DP frontend a running video carries, from video to live scanout.
    fn dp_audio_frontend(&self, path: Path) -> Result<DpFrontendReady, Error> {
        let running = self.status.dp_video_running.ok_or(Error::Busy)?;
        let frontend = running.frontend;
        let live = match self.status.state {
            State::DpVideoRunning(s) => s == frontend.request.stream,
            State::ScanoutRunning(p) => p == frontend.request.pipe,
            _ => false,
        };
        if !live {
            return Err(Error::Busy);
        }
        if frontend.link.phy.path != path {
            return Err(Error::Invalid);
        }
        Ok(frontend)
    }
    /// DSC's running video owns PPS and the shared AFMT/secondary enables.
    /// A recorded DSC request alone does not prove those packets are live.
    fn dp_audio_pps_verify(&mut self, frontend: &DpFrontendReady) -> Result<(), Error> {
        if frontend.blank.timing.request.dsc.is_none() {
            return Ok(());
        }
        let at = |r| DpStream::Dio(frontend.request.stream).at(self.layout, r);
        for (reg, mask, value) in [
            (at(AFMT_CNTL), 1, 1),
            (at(DP_SEC_CNTL), 1, 1),
            (at(0x2169), 0x1000_0000, 0x1000_0000), // PPS packet size
            (at(0x2177), 0xffff_0010, 2 << 16 | 0x10), // GSP11 on line 2
            (at(0x2170), 0xffff_8000, 3 << 16),     // VBID[6] on line 3
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        Ok(())
    }
    /// The DP audio owner's live registers on top of the video's.
    pub(in crate::amdgpu_dcn401_otg) fn dp_audio_verify(
        &mut self,
        frontend: &DpFrontendReady,
        a: &DisplayAudio,
    ) -> Result<(), Error> {
        self.dp_audio_pps_verify(frontend)?;
        if frontend.link.phy.settings.mst {
            self.mst_audio_verify_payload(
                frontend,
                self.status.mst_audio_payload.ok_or(Error::Invalid)?,
            )?;
        }
        let l = self.layout;
        let at = |r| DpStream::Dio(frontend.request.stream).at(l, r);
        for (reg, mask, value) in [
            (at(AFMT_CNTL), 1, 1),
            (at(AFMT_PACKET), 1, 1),
            (at(AFMT_SRC), 7, u32::from(a.endpoint)),
            (at(AFMT_PACKET2), 0xff00, u32::from(a.channels) << 8),
            (at(DP_SEC_CNTL), DP_SEC_AUDIO, DP_SEC_AUDIO),
            (at(DP_SEC_TIMESTAMP), 1, 1),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | CLOCK_GATING_DISABLE)
            != AUDIO_ENABLED
        {
            return Err(Error::Readback(self.az_at(a.endpoint)));
        }
        Ok(())
    }
    async fn dp_audio_start(
        &mut self,
        frontend: DpFrontendReady,
        a: DisplayAudio,
        ac3: bool,
    ) -> Result<(), Error> {
        let l = self.layout;
        let stream = frontend.request.stream;
        let at = |r| DpStream::Dio(stream).at(l, r);
        self.audio_wall_dto()?;
        self.audio_source(stream, &a)?;
        self.hdmi_audio_endpoint(&a, ac3)?;
        // dce_aud_az_enable.
        self.az_update(
            a.endpoint,
            AZ_HOT_PLUG,
            AUDIO_ENABLED | 1,
            AUDIO_ENABLED | 1,
        )?;
        self.az_update(a.endpoint, AZ_HOT_PLUG, 1, 0)?;
        // enc3_se_dp_audio_enable: AFMT audio clock, then the audio N
        // default and auto-calculated timestamps (both REG_SET).
        self.update(at(AFMT_CNTL), 1, 1)?;
        self.update(at(DP_SEC_AUD_N), u32::MAX, 0x8000)?;
        self.update(at(DP_SEC_TIMESTAMP), u32::MAX, 1)?;
        // afmt3_setup_dp_audio: channel-status update request, no layout or
        // OSF override, AUDIO_INFO latched now, clock accuracy level II.
        self.access(|io| {
            let v = checked(io.read(at(AFMT_PACKET)))?;
            io.write(at(AFMT_PACKET), v | 0x0400_0000);
            Ok(())
        })?;
        self.update(at(AFMT_PACKET2), 0x1000_0001, 0)?;
        self.access(|io| {
            let v = checked(io.read(at(AFMT_INFOFRAME0)))?;
            io.write(at(AFMT_INFOFRAME0), v | 0x80);
            Ok(())
        })?;
        self.update(at(AFMT_60958[0]), 0x3000_0000, 0)?;
        // enc1_se_enable_dp_audio: audio stream packets, then timestamp and
        // InfoFrame packets, then the secondary stream after the rest.
        self.update(at(DP_SEC_CNTL), 0x10, 0x10)?;
        self.update(at(DP_SEC_CNTL), 0x1100, 0x1100)?;
        self.update(at(DP_SEC_CNTL), 1, 1)?;
        // Unmute (AFMT_AUDIO_SAMPLE_SEND).
        self.update(at(AFMT_PACKET), 1, 1)?;
        self.dp_audio_verify(&frontend, &a)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_dp_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
    ) -> Result<DisplayAudio, Error> {
        if self.status.uhbr_video_running.is_some() {
            return self.start_uhbr_audio(path, info, None).await;
        }
        if self.status.dp_audio.is_some() {
            return Err(Error::Busy);
        }
        if info.mode_count == 0 || info.mode_count > 16 {
            return Err(Error::Invalid);
        }
        let frontend = self.dp_audio_frontend(path)?;
        if frontend.link.phy.settings.mst {
            // MST needs a completed manager payload as well as running video.
            return Err(Error::Unsupported);
        }
        let t = frontend.blank.timing.request.timing;
        let (descriptors, ac3, hbr) = descriptors(&info, &t, None);
        if descriptors[0] == 0 {
            return Err(Error::Unsupported); // no LPCM: nothing the codec can stream
        }
        let a = DisplayAudio {
            info,
            dp: true,
            endpoint: frontend.request.stream,
            channels: channels(info.speakers),
            descriptors,
            hbr,
        };
        if !self.audio_endpoint_available(a.endpoint) {
            return Err(Error::Busy);
        }
        // Quiet before the first write: no audio samples or packets. DSC's
        // verified PPS owner already holds the clock and secondary master.
        let pps = u32::from(frontend.blank.timing.request.dsc.is_some());
        self.dp_audio_pps_verify(&frontend)?;
        let at = |r| DpStream::Dio(frontend.request.stream).at(self.layout, r);
        for (reg, mask, value) in [
            (at(AFMT_CNTL), 1, pps),
            (at(AFMT_PACKET), 1, 0),
            (at(DP_SEC_CNTL), 0x1ff1_1111, pps),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Busy);
            }
        }
        // Recorded first: the wall clock is chosen from every record, and
        // the video owner's checks exempt the audio packet enables.
        self.status.dp_audio = Some(a);
        match self.dp_audio_start(frontend, a, ac3).await {
            Ok(()) => Ok(a),
            Err(e) => {
                self.status.dp_audio = None;
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_dp_audio(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        if self.status.uhbr_video_running.is_some() {
            return self.stop_uhbr_audio(path);
        }
        let a = self.status.dp_audio.ok_or(Error::Invalid)?;
        let frontend = self.dp_audio_frontend(path)?;
        if frontend.link.phy.settings.mst {
            return self.stop_mst_audio(frontend, a);
        }
        self.dp_audio_verify(&frontend, &a)?;
        let l = self.layout;
        let at = |r| DpStream::Dio(frontend.request.stream).at(l, r);
        let pps = u32::from(frontend.blank.timing.request.dsc.is_some());
        let result = (|| {
            // disable_dio_audio_packet: mute, then enc1_se_disable_dp_audio
            // (packets and ACM off). Preserve the secondary master and AFMT
            // clock while the video owner still sends DSC PPS in GSP11.
            self.update(at(AFMT_PACKET), 1, 0)?;
            self.update(at(DP_SEC_CNTL), DP_SEC_AUDIO | 0x1_0000, pps)?;
            if pps == 0 && self.read(at(DP_SEC_CNTL))? != 0 {
                self.update(at(DP_SEC_CNTL), 1, 1)?;
            }
            self.update(at(AFMT_CNTL), 1, pps)?;
            self.az_disable(a.endpoint)
        })();
        match result {
            Ok(()) => {
                self.status.dp_audio = None;
                self.audio_wall_dto()
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Start legacy or UHBR DP SST audio on this owner's running DP video (or live
    /// scanout): the audio wall clock, audio source, the Azalia endpoint
    /// the codec reports as ELD, then the secondary audio packets, unmuted.
    /// # Safety
    /// start_dp_video's obligations; no other agent may program this
    /// stream's AFMT or secondary packets, the audio wall clock or this
    /// Azalia endpoint. The HD-Audio controller and codec are separate owners.
    pub(crate) async unsafe fn start_dp_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
    ) -> Result<DisplayAudio, Error> {
        self.0.start_dp_audio(path, info).await
    }
    /// Mute and stop this owner's SST or legacy MST DP audio, keeping video running.
    /// # Safety
    /// As for start_dp_audio.
    pub(crate) async unsafe fn stop_dp_audio(&mut self, path: Path) -> Result<(), Error> {
        self.0.stop_dp_audio(path).await
    }
    /// Start HDMI audio on owned TMDS/FRL video (or live scanout):
    /// program the audio DTO, encoder ACR/AFMT, the Azalia endpoint the codec
    /// reports as ELD, the Audio InfoFrame, then unmute.
    /// # Safety
    /// start_hdmi_video/start_frl_video's obligations; no other agent may program this
    /// stream's AFMT, the audio DTO or this Azalia endpoint. The HD-Audio
    /// controller and codec are separate owners.
    pub(crate) async unsafe fn start_hdmi_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
    ) -> Result<DisplayAudio, Error> {
        self.0.start_hdmi_audio(path, info).await
    }
    /// Mute and stop this owner's HDMI audio, keeping video running.
    /// # Safety
    /// As for start_hdmi_audio.
    pub(crate) async unsafe fn stop_hdmi_audio(&mut self, path: Path) -> Result<(), Error> {
        self.0.stop_hdmi_audio(path).await
    }
}
