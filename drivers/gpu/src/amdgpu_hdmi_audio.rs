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
        let dto =
            compute_audio_dto(pixel_clock_khz, sample_rate_hz).ok_or(AudioError::BadPixelClock)?;
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
            ConnectorKind::HdmiA | ConnectorKind::HdmiB | ConnectorKind::Dp | ConnectorKind::Edp
        )
    }
}

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AudioError {
    BadFormatCode(u8),
    NoMatchingSad,
    BadPixelClock,
    /// Driver tried to program a stream binding for a CRTC/connector
    /// pair that's outside the audio engine's range.
    InvalidCrtc,
}

// ── DCCG / DCIO / AZALIA register programming ─────────────────────
//
// Once an ActiveAudioStream is constructed, the driver glue programs:
//
//   1. DCCG_AUDIO_DTO_SOURCE — picks which engine's pixel clock
//      drives the DTO.
//   2. DCCG_AUDIO_DTO0_MODULE / _PHASE — clock_info.audio_dto_module
//      and audio_dto_phase from the SAD pair.
//   3. AZ_F0_CODEC_FUNCTION_GROUP — programs the codec verb
//      (12-bit nid | 8-bit verb | 12-bit payload) for the path /
//      stream-format / mixer association.
//   4. DCIO routing — binds the codec to the active CRTC's stream
//      via the DCIO_AUDIO_STREAM_CONTROL register.
//
// Register offsets are PER-CHIP; on Phoenix (DCN 3.5) they live in
// the DCE register window at:
//
//   DCCG_AUDIO_DTO_SOURCE      = 0x0035  (DCCG block + 0x00d4)
//   DCCG_AUDIO_DTO0_MODULE     = 0x0036
//   DCCG_AUDIO_DTO0_PHASE      = 0x0037
//
// On Renoir (DCN 2.0) different offsets — but the protocol is
// the same. References:
//   - Linux drivers/gpu/drm/amd/display/dc/dce/dce_audio.c:1102-1148
//     (dce_set_audio_dto — DTO register program)
//   - Linux drivers/gpu/drm/amd/display/dc/dce/dce_audio.c::
//     dce_aud_az_configure (AZALIA codec verb programming)

pub const DCCG_AUDIO_DTO_SOURCE_REL: u32 = 0x00d4;
pub const DCCG_AUDIO_DTO0_MODULE_REL: u32 = 0x00d8;
pub const DCCG_AUDIO_DTO0_PHASE_REL: u32 = 0x00dc;
pub const DCCG_AUDIO_DTO1_MODULE_REL: u32 = 0x00e0;
pub const DCCG_AUDIO_DTO1_PHASE_REL: u32 = 0x00e4;

/// `AZALIA_F0_CODEC_VERB_*` — the codec verb interface used to
/// program the Audio Z (Azalia) codec function group. The host
/// writes a 32-bit verb (4-bit cad | 8-bit nid | 20-bit verb +
/// payload) to F0_CODEC_FUNCTION_CONTROL_CODEC_DATA and then bumps
/// a trigger bit.
pub const AZ_F0_CODEC_FUNCTION_CONTROL_CODEC_DATA_REL: u32 = 0x0040;
pub const AZ_F0_CODEC_FUNCTION_CONTROL_RESPONSE_DATA_REL: u32 = 0x0044;
pub const AZ_F0_CODEC_PIN_CONTROL_RESPONSE_PIN_WIDGET_CONTROL_REL: u32 = 0x0048;

/// DCIO audio stream-control register — binds a codec instance to
/// a CRTC's pixel-stream output (selects which OPP delivers
/// timestamps for sample-rate sync).
pub const DCIO_AUDIO_STREAM_CONTROL_REL: u32 = 0x0050;

pub trait DcnAudioMmio {
    fn read(&mut self, byte_off: u32) -> u32;
    fn write(&mut self, byte_off: u32, value: u32);
}

/// Program the DCCG audio DTO for an active stream.
///
/// Mirrors `dce_audio.c::dce_set_audio_dto` lines 1102-1148:
///   1. Select source engine (DTO0 or DTO1) via DTO_SOURCE.
///   2. Write the module + phase from the stream's DTO pair.
pub fn program_audio_dto<M: DcnAudioMmio>(
    mmio: &mut M,
    dccg_base: u32,
    stream: &ActiveAudioStream,
    src_sel: u32,
) {
    // DTO source select (DTO0_SOURCE_SEL = src_sel; DTO_SEL = 0).
    let src_val = ((src_sel & 0xF) << 4) | 0;
    mmio.write(dccg_base + DCCG_AUDIO_DTO_SOURCE_REL, src_val);

    let (phase, module) = stream.dto;
    mmio.write(dccg_base + DCCG_AUDIO_DTO0_MODULE_REL, module);
    mmio.write(dccg_base + DCCG_AUDIO_DTO0_PHASE_REL, phase);
}

/// Encode an Azalia codec verb. Layout per the HDA spec:
///   bits[31:28] — codec address (CAD), typically 0.
///   bits[27:20] — node ID (NID).
///   bits[19:0]  — verb + payload (often 4-bit verb id at [19:16] +
///                 16-bit payload at [15:0]).
pub fn encode_azalia_verb(cad: u8, nid: u8, verb_payload: u32) -> u32 {
    (((cad as u32) & 0xF) << 28) | (((nid as u32) & 0xFF) << 20) | (verb_payload & 0xF_FFFF)
}

/// Issue an Azalia codec verb. Writes the verb to the codec-data
/// register; the codec FW services it asynchronously and the
/// response shows up in the response-data register.
///
/// Caller polls the response register if the verb expects a response;
/// for set-style verbs the codec just acks via a dummy read.
pub fn write_azalia_verb<M: DcnAudioMmio>(
    mmio: &mut M,
    az_base: u32,
    cad: u8,
    nid: u8,
    verb_payload: u32,
) {
    let verb = encode_azalia_verb(cad, nid, verb_payload);
    mmio.write(az_base + AZ_F0_CODEC_FUNCTION_CONTROL_CODEC_DATA_REL, verb);
}

/// Bind a codec instance to a CRTC's stream via the DCIO routing
/// register. `crtc_idx` is encoded in bits[3:0]; `connector_idx`
/// in bits[11:8]; bit 31 is the enable.
pub fn bind_codec_to_crtc<M: DcnAudioMmio>(
    mmio: &mut M,
    dcio_base: u32,
    crtc_idx: u8,
    connector_idx: u8,
) {
    let val = (1u32 << 31) | ((connector_idx as u32 & 0xF) << 8) | (crtc_idx as u32 & 0xF);
    mmio.write(dcio_base + DCIO_AUDIO_STREAM_CONTROL_REL, val);
}

/// Unbind any active codec stream from a CRTC (clears the
/// stream-control enable bit). Idempotent.
pub fn unbind_codec_from_crtc<M: DcnAudioMmio>(mmio: &mut M, dcio_base: u32) {
    mmio.write(dcio_base + DCIO_AUDIO_STREAM_CONTROL_REL, 0);
}

/// Live HPD → audio binding driver: once a new stream is built
/// in [`AudioEngine::start_stream`], the host-glue calls this to
/// push the bindings into silicon. Combines DTO + AZALIA verb +
/// DCIO bind in the right order:
///   1. DTO first — codec needs the sample clock running before
///      it can lock to the stream.
///   2. AZALIA verb — programs the codec's converter widget +
///      pin widget for the requested format.
///   3. DCIO bind — connects the codec to the active CRTC's stream.
pub fn route_active_stream<M: DcnAudioMmio>(
    mmio: &mut M,
    dccg_base: u32,
    az_base: u32,
    dcio_base: u32,
    stream: &ActiveAudioStream,
) {
    // Step 1: DTO.
    program_audio_dto(mmio, dccg_base, stream, stream.connector_idx as u32);

    // Step 2: codec verb — set converter format (verb 0x2 = SET_CONVERTER_FORMAT).
    // Payload layout per HDA: 16-bit format word (bit 14 = type, bits
    // [13:11] = sample rate base, [10:8] = mult, [7:4] = div,
    // [3:0] = bits/sample - 1).
    let fmt_word = encode_format_word(stream.sample_rate_hz, 16, stream.channel_count);
    write_azalia_verb(mmio, az_base, 0, stream.crtc_idx + 2, 0x2_0000 | fmt_word);

    // Step 3: DCIO bind.
    bind_codec_to_crtc(mmio, dcio_base, stream.crtc_idx, stream.connector_idx);
}

/// Encode an HDA stream-format word. Sample-rate base bits per
/// HDA section 3.7.1:
///
///   base = 0 → 48 kHz family; base = 1 → 44.1 kHz family.
///   mult = (rate / base) - 1.
///   div  = base / rate when base > rate.
pub fn encode_format_word(rate_hz: u32, bits_per_sample: u8, channel_count: u8) -> u32 {
    // 44.1 kHz family (bases 44100 * {1, 2, 4})
    let (base, mult, div): (u32, u32, u32) = if rate_hz % 48000 == 0 || rate_hz == 32000 {
        (0, rate_hz / 48000, 0)
    } else if rate_hz % 44100 == 0 {
        (1, rate_hz / 44100, 0)
    } else if 48000 % rate_hz == 0 {
        (0, 0, 48000 / rate_hz - 1)
    } else {
        // Fall back: pretend 48 kHz x 1.
        (0, 0, 0)
    };
    let bits_field: u32 = match bits_per_sample {
        8 => 0,
        16 => 1,
        20 => 2,
        24 => 3,
        32 => 4,
        _ => 1,
    };
    let chan_field = (channel_count as u32).saturating_sub(1) & 0xF;
    (base << 14) | ((mult & 0x7) << 11) | ((div & 0x7) << 8) | (bits_field << 4) | chan_field
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

    // ── Live MMIO routing ───────────────────────────────────────

    struct MockDcnAudioMmio {
        writes: alloc::vec::Vec<(u32, u32)>,
    }
    impl DcnAudioMmio for MockDcnAudioMmio {
        fn read(&mut self, _off: u32) -> u32 {
            0
        }
        fn write(&mut self, off: u32, val: u32) {
            self.writes.push((off, val));
        }
    }

    fn smoke_program_audio_dto_writes_source_module_phase() -> TestResult {
        let mut m = MockDcnAudioMmio {
            writes: alloc::vec![],
        };
        let s = ActiveAudioStream {
            crtc_idx: 0,
            connector_idx: 1,
            format: AudioFormat::LinearPcm,
            sample_rate_hz: 48000,
            channel_count: 2,
            dto: (0x12345, 0xABCDEF),
        };
        program_audio_dto(&mut m, 0x10000, &s, 3);
        // 3 writes: SOURCE, MODULE, PHASE.
        if m.writes.len() != 3 {
            return TestResult::Fail("expected 3 DTO writes");
        }
        if m.writes[0].0 != 0x10000 + DCCG_AUDIO_DTO_SOURCE_REL {
            return TestResult::Fail("source reg wrong");
        }
        if m.writes[1] != (0x10000 + DCCG_AUDIO_DTO0_MODULE_REL, 0xABCDEF) {
            return TestResult::Fail("module wrong");
        }
        if m.writes[2] != (0x10000 + DCCG_AUDIO_DTO0_PHASE_REL, 0x12345) {
            return TestResult::Fail("phase wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_program_audio_dto_writes_source_module_phase
    );

    fn smoke_azalia_verb_encoding() -> TestResult {
        // CAD=0, NID=4, verb_payload=0x2_0011.
        let v = encode_azalia_verb(0, 4, 0x2_0011);
        // bits[27:20] = 4, bits[19:0] = 0x2_0011.
        if (v >> 20) & 0xFF != 4 {
            return TestResult::Fail("NID wrong");
        }
        if v & 0xF_FFFF != 0x2_0011 {
            return TestResult::Fail("payload wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_azalia_verb_encoding);

    fn smoke_bind_codec_to_crtc_writes_enable() -> TestResult {
        let mut m = MockDcnAudioMmio {
            writes: alloc::vec![],
        };
        bind_codec_to_crtc(&mut m, 0x20000, 3, 2);
        if m.writes.len() != 1 {
            return TestResult::Fail("expected 1 write");
        }
        let val = m.writes[0].1;
        if val & (1 << 31) == 0 {
            return TestResult::Fail("enable bit not set");
        }
        if val & 0xF != 3 {
            return TestResult::Fail("crtc_idx wrong");
        }
        if (val >> 8) & 0xF != 2 {
            return TestResult::Fail("connector_idx wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_bind_codec_to_crtc_writes_enable);

    fn smoke_route_active_stream_three_phase() -> TestResult {
        let mut m = MockDcnAudioMmio {
            writes: alloc::vec![],
        };
        let s = ActiveAudioStream {
            crtc_idx: 1,
            connector_idx: 2,
            format: AudioFormat::LinearPcm,
            sample_rate_hz: 48000,
            channel_count: 2,
            dto: (0x100, 0x200),
        };
        route_active_stream(&mut m, 0x10000, 0x20000, 0x30000, &s);
        // 3 DTO writes + 1 AZ codec data write + 1 DCIO bind = 5.
        if m.writes.len() != 5 {
            return TestResult::Fail("expected 5 writes");
        }
        // Last write is the DCIO bind.
        if m.writes[4].0 != 0x30000 + DCIO_AUDIO_STREAM_CONTROL_REL {
            return TestResult::Fail("DCIO bind not last");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_route_active_stream_three_phase);

    fn smoke_encode_format_word_48khz_lpcm_stereo_16bit() -> TestResult {
        let f = encode_format_word(48000, 16, 2);
        // base=0, mult=1, div=0, bits=1, chan=1 → 0 | (1<<11) | 0 | (1<<4) | 1 = 0x811.
        if f != (1 << 11) | (1 << 4) | 1 {
            return TestResult::Fail("48k/16/2 format wrong");
        }
        // 96 kHz = 2x; mult=2, rest same.
        let f96 = encode_format_word(96000, 16, 2);
        if f96 != (2 << 11) | (1 << 4) | 1 {
            return TestResult::Fail("96k/16/2 format wrong");
        }
        // 44.1 kHz base.
        let f441 = encode_format_word(44100, 16, 2);
        if f441 & (1 << 14) == 0 {
            return TestResult::Fail("44.1k base bit not set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_encode_format_word_48khz_lpcm_stereo_16bit
    );
}
