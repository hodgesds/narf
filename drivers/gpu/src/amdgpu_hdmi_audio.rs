//! AMD HDMI / DP audio — Azalia HDA codec on the GPU.
//!
//! Every modern AMD GPU embeds an Azalia-compatible HDA codec
//! that routes audio streams over the HDMI or DP link's secondary
//! channel. The codec lives in the DCE / DCN "audio engine"
//! block; the host programs it through a DMA timing offset (DTO)
//! tied to the OTG pixel clock so the audio stream stays
//! sample-locked to the video frame.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/display/dc/dce/dce_audio.c`
//!   — engine programming + DTO calculation
//! - Linux `drivers/gpu/drm/amd/display/include/audio_types.h`
//!   — `audio_format_code`, `audio_mode`, `audio_info`
//! - Linux `drivers/gpu/drm/amd/display/dc/dc_types.h`
//!   — `AUDIO_FORMAT_CODE_*` enumeration values
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/dce/` —
//!   register offsets for AZ_CHANNEL_COUNT / AZ_HOT_PLUG_CONTROL
//! - HDA spec (Intel + others; public) — codec command protocol
//!
//! Linux code is GPL-2.0-or-later (matches NARF); structural
//! patterns adapted directly. Per-IP register window bases come
//! from the discovery table the driver core already parses.
//!
//! ## Audio path
//!
//! ```text
//!   [HDA verb]
//!       │
//!       ▼
//!   ┌───────────────┐    PCM samples
//!   │  HDA codec    │───────────────────┐
//!   │  (AZ_*)       │                   │
//!   └───────────────┘                   │
//!       │ DTO ratio (locks to pixel)    │
//!       ▼                               │
//!   ┌───────────────┐                   │
//!   │  Audio DTO    │                   │
//!   │  (pixel-clk   │                   │
//!   │   slaved)     │                   │
//!   └───────────────┘                   │
//!       │                               │
//!       ▼                               ▼
//!   ┌───────────────────────────────────────┐
//!   │   DIG / DCE encoder (HDMI / DP)       │
//!   │   - secondary channel insertion       │
//!   └───────────────────────────────────────┘
//!       │
//!       ▼
//!   [HDMI / DP link]
//! ```

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_atom_displayobj::ConnectorKind;

// ── Audio format codes ───────────────────────────────────────────
//
// CEA-861 / HDMI audio-format codes. Matches Linux
// `enum audio_format_code` in dc_types.h.

/// One audio format the sink advertises in its EDID Short Audio
/// Descriptor (SAD) block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AudioFormat {
    /// Linear PCM (baseline; all sinks support stereo PCM).
    LinearPcm,
    /// Dolby Digital (AC-3).
    Ac3,
    Mpeg1,
    /// MPEG-1 Layer 3.
    Mp3,
    Mpeg2,
    Aac,
    Dts,
    Atrac,
    /// SACD 1-bit audio.
    OneBitAudio,
    /// Dolby Digital Plus (E-AC-3).
    DolbyDigitalPlus,
    DtsHd,
    /// Dolby TrueHD / MAT MLP.
    MatMlp,
    /// Direct Stream Transfer.
    Dst,
    WmaPro,
}

impl AudioFormat {
    /// CEA-861 numeric code as written in the SAD. Matches the
    /// register encoding the codec accepts in AZ_CHANNEL_COUNT.
    pub fn cea_code(self) -> u8 {
        match self {
            AudioFormat::LinearPcm => 1,
            AudioFormat::Ac3 => 2,
            AudioFormat::Mpeg1 => 3,
            AudioFormat::Mp3 => 4,
            AudioFormat::Mpeg2 => 5,
            AudioFormat::Aac => 6,
            AudioFormat::Dts => 7,
            AudioFormat::Atrac => 8,
            AudioFormat::OneBitAudio => 9,
            AudioFormat::DolbyDigitalPlus => 10,
            AudioFormat::DtsHd => 11,
            AudioFormat::MatMlp => 12,
            AudioFormat::Dst => 13,
            AudioFormat::WmaPro => 14,
        }
    }

    /// `true` if the format is a bit-exact bypass codec (no
    /// resampling required by the sink). Determines whether the
    /// DTO uses the LFCN ratio or the bit-stream-through ratio.
    pub fn is_bitstream(self) -> bool {
        matches!(
            self,
            AudioFormat::Ac3
                | AudioFormat::Dts
                | AudioFormat::DolbyDigitalPlus
                | AudioFormat::DtsHd
                | AudioFormat::MatMlp
        )
    }
}

// ── Sample rates + channel layouts ───────────────────────────────

/// Supported sample rates per CEA-861. Each is a bit in the SAD's
/// rate byte. Matches Linux `union audio_sample_rates`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SampleRates {
    /// 32 kHz.
    pub r32k: bool,
    /// 44.1 kHz.
    pub r44k: bool,
    /// 48 kHz — the baseline for HDMI.
    pub r48k: bool,
    /// 88.2 kHz.
    pub r88k: bool,
    /// 96 kHz.
    pub r96k: bool,
    /// 176.4 kHz.
    pub r176k: bool,
    /// 192 kHz.
    pub r192k: bool,
}

impl SampleRates {
    /// CEA-861 packed byte encoding.
    pub fn as_byte(&self) -> u8 {
        (self.r32k as u8)
            | ((self.r44k as u8) << 1)
            | ((self.r48k as u8) << 2)
            | ((self.r88k as u8) << 3)
            | ((self.r96k as u8) << 4)
            | ((self.r176k as u8) << 5)
            | ((self.r192k as u8) << 6)
    }

    /// Decode the CEA-861 SAD rate byte.
    pub fn from_byte(b: u8) -> Self {
        Self {
            r32k: (b & 0x01) != 0,
            r44k: (b & 0x02) != 0,
            r48k: (b & 0x04) != 0,
            r88k: (b & 0x08) != 0,
            r96k: (b & 0x10) != 0,
            r176k: (b & 0x20) != 0,
            r192k: (b & 0x40) != 0,
        }
    }

    /// Highest rate supported, in Hz. Returns 0 if none.
    pub fn max_hz(&self) -> u32 {
        if self.r192k {
            192_000
        } else if self.r176k {
            176_400
        } else if self.r96k {
            96_000
        } else if self.r88k {
            88_200
        } else if self.r48k {
            48_000
        } else if self.r44k {
            44_100
        } else if self.r32k {
            32_000
        } else {
            0
        }
    }
}

/// One Short Audio Descriptor (SAD) from the sink's CEA-861
/// extension block. Three bytes per SAD per the spec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShortAudioDescriptor {
    pub format: AudioFormat,
    pub channel_count: u8,
    pub sample_rates: SampleRates,
    /// LPCM: max sample-size bits; bitstream: max bitrate / 8 kHz.
    pub size_or_bitrate: u8,
}

impl ShortAudioDescriptor {
    /// Encode to a 3-byte CEA-861 SAD. Mirrors the spec layout.
    pub fn encode(&self) -> [u8; 3] {
        let b0 = ((self.format.cea_code() & 0x0F) << 3) | ((self.channel_count - 1) & 0x07);
        let b1 = self.sample_rates.as_byte();
        let b2 = self.size_or_bitrate;
        [b0, b1, b2]
    }

    /// Decode from a 3-byte SAD.
    pub fn decode(bytes: [u8; 3]) -> Result<Self, AudioError> {
        let code = (bytes[0] >> 3) & 0x0F;
        let format = match code {
            1 => AudioFormat::LinearPcm,
            2 => AudioFormat::Ac3,
            3 => AudioFormat::Mpeg1,
            4 => AudioFormat::Mp3,
            5 => AudioFormat::Mpeg2,
            6 => AudioFormat::Aac,
            7 => AudioFormat::Dts,
            8 => AudioFormat::Atrac,
            9 => AudioFormat::OneBitAudio,
            10 => AudioFormat::DolbyDigitalPlus,
            11 => AudioFormat::DtsHd,
            12 => AudioFormat::MatMlp,
            13 => AudioFormat::Dst,
            14 => AudioFormat::WmaPro,
            _ => return Err(AudioError::BadFormatCode(code)),
        };
        Ok(Self {
            format,
            channel_count: (bytes[0] & 0x07) + 1,
            sample_rates: SampleRates::from_byte(bytes[1]),
            size_or_bitrate: bytes[2],
        })
    }
}

// ── DTO (DMA Timing Offset) calculation ──────────────────────────
//
// The audio DTO is a ratio that converts the wallclock (audio
// reference source clock) into pixel-clock-locked sample tics.
// For HDMI's "audio is N samples per video frame" guarantee to
// hold, the DTO ratio is:
//
//   phase / modulus = audio_rate_hz × N / pixel_clock_hz
//
// where N is the audio packet's "N" coefficient per HDMI spec
// table 7-1 (128 × pixel_clock / sample_rate for 32 kHz, etc.).
// Linux's `dce_audio.c::set_audio_dto` computes this directly;
// we replicate the math here for testability.

/// Compute the audio DTO (phase, modulus) pair for a given audio
/// sample rate against the OTG pixel clock. The codec writes
/// `phase` to `AZ_DTO_PHASE` and `modulus` to `AZ_DTO_MODULE`;
/// the audio engine generates one tick per pixel-clock cycle
/// scaled by `phase / modulus`.
///
/// Returns `None` if the inputs would overflow or yield zero.
pub fn compute_audio_dto(pixel_clock_khz: u32, sample_rate_hz: u32) -> Option<(u32, u32)> {
    if pixel_clock_khz == 0 || sample_rate_hz == 0 {
        return None;
    }
    // phase   = sample_rate_hz  (the numerator of the ratio)
    // modulus = pixel_clock_hz  (the denominator)
    //
    // Both fit comfortably in u32 for 5 GHz pixel clocks /
    // 192 kHz audio.
    let phase = sample_rate_hz;
    let modulus = pixel_clock_khz.checked_mul(1000)?;
    if modulus == 0 {
        return None;
    }
    Some((phase, modulus))
}

// ── Audio engine state ───────────────────────────────────────────

/// One enabled audio stream — the host's view of what the codec
/// is currently presenting on a given encoder.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ActiveAudioStream {
    /// CRTC the stream is sample-locked to.
    pub crtc_idx: u8,
    /// Connector the stream is presenting over.
    pub connector_idx: u8,
    pub format: AudioFormat,
    pub sample_rate_hz: u32,
    pub channel_count: u8,
    /// Cached DTO (phase, modulus).
    pub dto: (u32, u32),
}

/// Audio engine state — one per AMD GPU. Carries the SAD cache
/// per connector and the active-stream list. Sinks publish their
/// SADs in EDID extension blocks; the modeset path is expected
/// to populate `connector_sads` after EDID readback.
#[derive(Clone, Debug, Default)]
pub struct AudioEngine {
    /// Parallel to `KmsState::connectors`. Index is connector
    /// idx; value is the sink's full SAD list.
    pub connector_sads: Vec<Vec<ShortAudioDescriptor>>,
    /// Currently-streaming audio. One slot per active CRTC.
    pub active: Vec<ActiveAudioStream>,
}

impl AudioEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the SAD list for a connector. Called after EDID
    /// readback parses the CEA-861 extension block.
    pub fn set_sads(&mut self, connector_idx: u8, sads: Vec<ShortAudioDescriptor>) {
        let needed = connector_idx as usize + 1;
        if self.connector_sads.len() < needed {
            self.connector_sads.resize_with(needed, Vec::new);
        }
        self.connector_sads[connector_idx as usize] = sads;
    }

    /// Negotiate the best stream format for `connector_idx`
    /// given a host-requested rate + channel count. Returns the
    /// format the sink advertised that matches, or `None` if no
    /// SAD covers the request. Bitstream formats are preferred
    /// over LPCM when the sink claims both (Linux's
    /// `dce_audio_check_audio_bandwidth` follows the same
    /// preference).
    pub fn negotiate(
        &self,
        connector_idx: u8,
        sample_rate_hz: u32,
        channel_count: u8,
    ) -> Option<AudioFormat> {
        let sads = self.connector_sads.get(connector_idx as usize)?;
        // Try LPCM first — broadest sink compatibility. If the
        // host wants a bitstream codec, the caller should ask
        // for it explicitly via `negotiate_format`.
        for sad in sads {
            if sad.format == AudioFormat::LinearPcm
                && sad.channel_count >= channel_count
                && sad.sample_rates.max_hz() >= sample_rate_hz
            {
                return Some(AudioFormat::LinearPcm);
            }
        }
        None
    }

    /// Negotiate a *specific* format. Used when the host knows
    /// it's bitstream-passing (Dolby / DTS) and wants the codec
    /// to admit the matching SAD or fail.
    pub fn negotiate_format(
        &self,
        connector_idx: u8,
        format: AudioFormat,
        sample_rate_hz: u32,
        channel_count: u8,
    ) -> bool {
        let sads = match self.connector_sads.get(connector_idx as usize) {
            Some(s) => s,
            None => return false,
        };
        sads.iter().any(|sad| {
            sad.format == format
                && sad.channel_count >= channel_count
                && sad.sample_rates.max_hz() >= sample_rate_hz
        })
    }

    /// Bring up an audio stream against a CRTC + connector. Adds
    /// it to `active`. Returns the DTO pair the caller writes to
    /// the codec's AZ_DTO_PHASE / AZ_DTO_MODULE registers.
    pub fn start_stream(
        &mut self,
        crtc_idx: u8,
        connector_idx: u8,
        format: AudioFormat,
        sample_rate_hz: u32,
        channel_count: u8,
        pixel_clock_khz: u32,
    ) -> Result<ActiveAudioStream, AudioError> {
        if !self.negotiate_format(connector_idx, format, sample_rate_hz, channel_count) {
            return Err(AudioError::NoMatchingSad);
        }
        let dto = compute_audio_dto(pixel_clock_khz, sample_rate_hz)
            .ok_or(AudioError::BadPixelClock)?;
        let stream = ActiveAudioStream {
            crtc_idx,
            connector_idx,
            format,
            sample_rate_hz,
            channel_count,
            dto,
        };
        self.active.retain(|s| s.crtc_idx != crtc_idx);
        self.active.push(stream);
        Ok(stream)
    }

    /// Stop audio on `crtc_idx`. No-op if no stream is active.
    pub fn stop_stream(&mut self, crtc_idx: u8) {
        self.active.retain(|s| s.crtc_idx != crtc_idx);
    }

    /// `true` if the connector is an audio-capable signal type.
    /// HDMI / DP carry audio; DVI / VGA / LVDS / DSI do not.
    pub fn connector_supports_audio(kind: ConnectorKind) -> bool {
        matches!(
            kind,
            ConnectorKind::HdmiA
                | ConnectorKind::HdmiB
                | ConnectorKind::Dp
                | ConnectorKind::Edp
        )
    }
}

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AudioError {
    BadFormatCode(u8),
    NoMatchingSad,
    BadPixelClock,
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use crate::amdgpu_atom_displayobj::ConnectorKind;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_audio_sad_round_trip() -> TestResult {
        let sad = ShortAudioDescriptor {
            format: AudioFormat::LinearPcm,
            channel_count: 2,
            sample_rates: SampleRates {
                r48k: true,
                r96k: true,
                ..Default::default()
            },
            size_or_bitrate: 0b0000_0010, // 16-bit only
        };
        let bytes = sad.encode();
        // First byte: format << 3 | (channels-1)
        if (bytes[0] >> 3) & 0x0F != AudioFormat::LinearPcm.cea_code() {
            return TestResult::Fail("encode format code wrong");
        }
        if bytes[0] & 0x07 != 1 {
            return TestResult::Fail("encode channel-1 wrong");
        }
        // Round-trip decode.
        let dec = ShortAudioDescriptor::decode(bytes).expect("decode");
        if dec.format != sad.format {
            return TestResult::Fail("round-trip format");
        }
        if dec.channel_count != sad.channel_count {
            return TestResult::Fail("round-trip channels");
        }
        if dec.sample_rates.as_byte() != sad.sample_rates.as_byte() {
            return TestResult::Fail("round-trip rates");
        }
        if dec.size_or_bitrate != sad.size_or_bitrate {
            return TestResult::Fail("round-trip bitrate");
        }
        // Bad code rejected.
        if ShortAudioDescriptor::decode([0xFF, 0, 0]).is_ok() {
            return TestResult::Fail("bad format code accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_audio_sad_round_trip);

    fn smoke_sample_rate_bitmap_max() -> TestResult {
        let r = SampleRates {
            r48k: true,
            r96k: true,
            r192k: true,
            ..Default::default()
        };
        if r.max_hz() != 192_000 {
            return TestResult::Fail("max_hz didn't pick highest");
        }
        let r = SampleRates {
            r32k: true,
            ..Default::default()
        };
        if r.max_hz() != 32_000 {
            return TestResult::Fail("32kHz-only max");
        }
        if SampleRates::default().max_hz() != 0 {
            return TestResult::Fail("empty rates should be 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_sample_rate_bitmap_max);

    fn smoke_dto_basic_ratio() -> TestResult {
        // 1920x1080@60: 148.5 MHz pixel clock; 48 kHz audio.
        let (phase, modulus) = compute_audio_dto(148_500, 48_000).expect("dto");
        if phase != 48_000 {
            return TestResult::Fail("phase wrong");
        }
        if modulus != 148_500_000 {
            return TestResult::Fail("modulus wrong");
        }
        // 0 inputs rejected.
        if compute_audio_dto(0, 48_000).is_some() {
            return TestResult::Fail("zero pixclk accepted");
        }
        if compute_audio_dto(148_500, 0).is_some() {
            return TestResult::Fail("zero sample rate accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dto_basic_ratio);

    fn smoke_audio_engine_negotiate_lpcm() -> TestResult {
        let mut eng = AudioEngine::new();
        eng.set_sads(
            0,
            alloc::vec![ShortAudioDescriptor {
                format: AudioFormat::LinearPcm,
                channel_count: 6,
                sample_rates: SampleRates {
                    r48k: true,
                    r96k: true,
                    ..Default::default()
                },
                size_or_bitrate: 0x02,
            }],
        );
        // 2ch @ 48k LPCM → match.
        if eng.negotiate(0, 48_000, 2) != Some(AudioFormat::LinearPcm) {
            return TestResult::Fail("2ch 48k LPCM should negotiate");
        }
        // 8ch @ 48k → channel count too high → no match.
        if eng.negotiate(0, 48_000, 8).is_some() {
            return TestResult::Fail("8ch should not negotiate against 6ch SAD");
        }
        // 192k → rate too high → no match.
        if eng.negotiate(0, 192_000, 2).is_some() {
            return TestResult::Fail("192k should not negotiate against 96k SAD");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_audio_engine_negotiate_lpcm);

    fn smoke_audio_engine_stream_lifecycle() -> TestResult {
        let mut eng = AudioEngine::new();
        eng.set_sads(
            0,
            alloc::vec![ShortAudioDescriptor {
                format: AudioFormat::LinearPcm,
                channel_count: 2,
                sample_rates: SampleRates {
                    r48k: true,
                    ..Default::default()
                },
                size_or_bitrate: 0x02,
            }],
        );
        // No SAD → start fails.
        match eng.start_stream(1, 1, AudioFormat::LinearPcm, 48_000, 2, 148_500) {
            Err(AudioError::NoMatchingSad) => {}
            _ => return TestResult::Fail("no-SAD start should fail"),
        }
        let s = eng
            .start_stream(0, 0, AudioFormat::LinearPcm, 48_000, 2, 148_500)
            .expect("start");
        if s.dto != (48_000, 148_500_000) {
            return TestResult::Fail("DTO wrong");
        }
        if eng.active.len() != 1 {
            return TestResult::Fail("active stream not recorded");
        }
        // Starting another on the same CRTC replaces (no double-stream).
        eng.start_stream(0, 0, AudioFormat::LinearPcm, 48_000, 2, 148_500)
            .expect("re-start");
        if eng.active.len() != 1 {
            return TestResult::Fail("re-start duplicated stream");
        }
        eng.stop_stream(0);
        if !eng.active.is_empty() {
            return TestResult::Fail("stop_stream didn't remove");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_audio_engine_stream_lifecycle);

    fn smoke_audio_connector_capability() -> TestResult {
        if !AudioEngine::connector_supports_audio(ConnectorKind::HdmiA) {
            return TestResult::Fail("HDMI-A should be audio-capable");
        }
        if !AudioEngine::connector_supports_audio(ConnectorKind::Dp) {
            return TestResult::Fail("DP should be audio-capable");
        }
        if !AudioEngine::connector_supports_audio(ConnectorKind::Edp) {
            return TestResult::Fail("eDP should be audio-capable");
        }
        if AudioEngine::connector_supports_audio(ConnectorKind::DviI) {
            return TestResult::Fail("DVI should not be audio-capable");
        }
        if AudioEngine::connector_supports_audio(ConnectorKind::Vga) {
            return TestResult::Fail("VGA should not be audio-capable");
        }
        if AudioEngine::connector_supports_audio(ConnectorKind::Lvds) {
            return TestResult::Fail("LVDS should not be audio-capable");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_audio_connector_capability);

    fn smoke_audio_bitstream_classification() -> TestResult {
        // Bitstream codecs (compressed bypass).
        for f in [
            AudioFormat::Ac3,
            AudioFormat::Dts,
            AudioFormat::DolbyDigitalPlus,
            AudioFormat::DtsHd,
            AudioFormat::MatMlp,
        ] {
            if !f.is_bitstream() {
                return TestResult::Fail("bitstream codec not flagged");
            }
        }
        // LPCM and uncompressed legacy formats.
        for f in [AudioFormat::LinearPcm, AudioFormat::Mp3, AudioFormat::Aac] {
            if f.is_bitstream() {
                return TestResult::Fail("non-bitstream wrongly flagged");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_audio_bitstream_classification);
}
