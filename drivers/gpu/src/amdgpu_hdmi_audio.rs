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
//   3. The codec's endpoint registers, reached indirectly through an
//      index/data pair.
//
// References:
//   - Linux drivers/gpu/drm/amd/display/dc/dce/dce_audio.c
//     (dce_aud_wall_dto_setup, write_indirect_azalia_reg)
//   - Register ids from dcn/dcn_3_1_4_offset.h and _sh_mask.h. Phoenix is
//     DCN 3.1.4; dcn35's offsets do not apply.

/// `regDCCG_AUDIO_DTO_SOURCE`, BASE_IDX 1. `DCCG_AUDIO_DTO0_SOURCE_SEL` is
/// three bits at **0** and `DCCG_AUDIO_DTO_SEL` two bits at 4 — the source
/// select is the low field, not the one at 4.
pub const DCCG_AUDIO_DTO_SOURCE: u32 = 0x00ab;
pub const DCCG_AUDIO_DTO0_SOURCE_SEL_SHIFT: u32 = 0;
pub const DCCG_AUDIO_DTO0_SOURCE_SEL_MASK: u32 = 0x0000_0007;
pub const DCCG_AUDIO_DTO_SEL_SHIFT: u32 = 4;

/// The DTO phase/module pairs. **Phase is below module** for both instances,
/// and the two pairs are interleaved phase-then-module rather than grouped:
/// 0x00ac phase0, 0x00ad module0, 0x00ae phase1, 0x00af module1.
pub const DCCG_AUDIO_DTO0_PHASE: u32 = 0x00ac;
pub const DCCG_AUDIO_DTO0_MODULE: u32 = 0x00ad;
pub const DCCG_AUDIO_DTO1_PHASE: u32 = 0x00ae;
pub const DCCG_AUDIO_DTO1_MODULE: u32 = 0x00af;

/// The Azalia codec's per-endpoint state is **not** directly mapped. Each
/// endpoint has an index/data pair — `regAZF0ENDPOINTn_AZALIA_F0_CODEC_
/// ENDPOINT_INDEX` and `_DATA` — and `write_indirect_azalia_reg` writes the
/// `ix…` index first, then the value (`dce_audio.c`). BASE_IDX 2.
pub const AZF0ENDPOINT0_CODEC_ENDPOINT_INDEX: u32 = 0x0386;
pub const AZF0ENDPOINT0_CODEC_ENDPOINT_DATA: u32 = 0x0387;
/// Six dwords per endpoint, eight endpoints: endpoint 7's index is 0x03b0.
pub const AZF0ENDPOINT_STRIDE: u32 = 6;
pub const AZF0ENDPOINTS: u8 = 8;
/// `AZALIA_ENDPOINT_REG_INDEX` is fourteen bits; a wider index would spill
/// into the reserved bits above it.
pub const AZALIA_ENDPOINT_REG_INDEX_MASK: u32 = 0x0000_3FFF;

/// The indirect indices this module programs, from `ixAZALIA_F0_CODEC_
/// PIN_CONTROL_*`. These are endpoint-register indices written into
/// `..._ENDPOINT_INDEX`, not register offsets.
pub const IX_PIN_CONTROL_CHANNEL_SPEAKER: u32 = 0x0025;
pub const IX_PIN_CONTROL_AUDIO_DESCRIPTOR0: u32 = 0x0028;
pub const IX_PIN_CONTROL_MULTICHANNEL_ENABLE: u32 = 0x0036;
pub const IX_PIN_CONTROL_SINK_INFO0: u32 = 0x003A;
pub const IX_PIN_CONTROL_HOT_PLUG_CONTROL: u32 = 0x0054;

/// The dword id of `reg` for `endpoint`.
pub const fn for_endpoint(reg: u32, endpoint: u8) -> u32 {
    reg + (endpoint as u32) * AZF0ENDPOINT_STRIDE
}

pub trait DcnAudioMmio {
    /// `reg` is an absolute DCN dword id, as the headers spell them.
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
}

/// Program the DCCG audio DTO for an active stream.
///
/// `dce_aud_wall_dto_setup`: the source select and DTO select go first,
/// because "these bits must be programmed before DTO modulo and DTO phase",
/// then module, then phase.
pub fn program_audio_dto<M: DcnAudioMmio>(mmio: &mut M, stream: &ActiveAudioStream, src_sel: u32) {
    // DTO0_SOURCE_SEL is the low three bits; DTO_SEL at 4 stays zero to pick
    // DTO0.
    let src_val = (src_sel << DCCG_AUDIO_DTO0_SOURCE_SEL_SHIFT) & DCCG_AUDIO_DTO0_SOURCE_SEL_MASK;
    mmio.write(DCCG_AUDIO_DTO_SOURCE, src_val);

    let (phase, module) = stream.dto;
    mmio.write(DCCG_AUDIO_DTO0_MODULE, module);
    mmio.write(DCCG_AUDIO_DTO0_PHASE, phase);
}

/// Write one of the codec's indirect endpoint registers.
///
/// `write_indirect_azalia_reg`: the endpoint-register index goes to
/// `..._ENDPOINT_INDEX`, then the value to `..._ENDPOINT_DATA`. The index is
/// one of the `IX_*` constants above.
///
/// LINUX-GAP: what stood here encoded an HDA verb — `cad << 28 | nid << 20 |
/// payload` — and wrote it to `AZ_F0_CODEC_FUNCTION_CONTROL_CODEC_DATA`,
/// polling `..._RESPONSE_DATA` for a reply. Neither register exists: the
/// header has no `regAZ_F0_CODEC_*` at all, the real prefix being
/// `regAZALIA_F0_CODEC_*`, and nothing in it carries a verb or a response.
/// The display driver never speaks HDA verbs; the HDA controller on the GPU's
/// separate PCI audio function does, and what the display side programs is
/// this indirect endpoint space.
pub fn write_endpoint_reg<M: DcnAudioMmio>(
    mmio: &mut M,
    endpoint: u8,
    index: u32,
    value: u32,
) -> bool {
    if endpoint >= AZF0ENDPOINTS {
        return false;
    }
    mmio.write(
        for_endpoint(AZF0ENDPOINT0_CODEC_ENDPOINT_INDEX, endpoint),
        index & AZALIA_ENDPOINT_REG_INDEX_MASK,
    );
    mmio.write(
        for_endpoint(AZF0ENDPOINT0_CODEC_ENDPOINT_DATA, endpoint),
        value,
    );
    true
}

/// Read one of the codec's indirect endpoint registers.
pub fn read_endpoint_reg<M: DcnAudioMmio>(mmio: &mut M, endpoint: u8, index: u32) -> Option<u32> {
    if endpoint >= AZF0ENDPOINTS {
        return None;
    }
    mmio.write(
        for_endpoint(AZF0ENDPOINT0_CODEC_ENDPOINT_INDEX, endpoint),
        index & AZALIA_ENDPOINT_REG_INDEX_MASK,
    );
    Some(mmio.read(for_endpoint(AZF0ENDPOINT0_CODEC_ENDPOINT_DATA, endpoint)))
}

// LINUX-GAP: `bind_codec_to_crtc` wrote a `DCIO_AUDIO_STREAM_CONTROL`
// register at a "dcio_base + 0x0050", with a CRTC index in bits 3:0, a
// connector index in 11:8 and an enable at 31. No register of that name
// exists in any DCN header. Binding a codec endpoint to a stream is done in
// the stream encoder (`dce110_stream_encoder.c::dce110_se_audio_mute_control`
// and the `AFMT_*` / `HDMI_*` blocks), which this module does not model, so
// the binding is simply absent rather than fabricated.

/// Live HPD → audio binding driver: once a new stream is built in
/// [`AudioEngine::start_stream`], the host glue calls this to push the
/// bindings into silicon.
///
/// `dce_aud_wall_dto_setup` first, so the codec has its sample clock before
/// anything locks to the stream, then the codec's channel-count and
/// multichannel-enable endpoint registers.
///
/// LINUX-GAP: the third step was a `DCIO_AUDIO_STREAM_CONTROL` write that has
/// no register behind it, and the second was an HDA verb written to a register
/// that does not exist. The stream-encoder side of the binding — the `AFMT`
/// audio packet setup and the encoder's audio enable — is not modelled here,
/// so a real HDMI audio path still needs that work; what this does is the
/// DCCG DTO and the indirect endpoint writes, both of which can be checked
/// against the header.
pub fn route_active_stream<M: DcnAudioMmio>(mmio: &mut M, stream: &ActiveAudioStream) -> bool {
    // Step 1: the DTO, with the source select carrying the connector.
    program_audio_dto(mmio, stream, stream.connector_idx as u32);

    // Step 2: the codec endpoint. One endpoint per connector.
    let channels = stream.channel_count.max(1) as u32;
    if !write_endpoint_reg(
        mmio,
        stream.connector_idx,
        IX_PIN_CONTROL_CHANNEL_SPEAKER,
        channels - 1,
    ) {
        return false;
    }
    write_endpoint_reg(
        mmio,
        stream.connector_idx,
        IX_PIN_CONTROL_MULTICHANNEL_ENABLE,
        u32::from(channels > 2),
    )
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

    /// Dword ids spelled out from `dcn_3_1_4_offset.h`: DTO_SOURCE 0x00ab,
    /// then **phase 0x00ac below module 0x00ad**.
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
        program_audio_dto(&mut m, &s, 3);
        // Three writes: SOURCE, then MODULE, then PHASE — the source select
        // must land before the ratio, per the comment in
        // `dce_aud_wall_dto_setup`.
        if m.writes.len() != 3 {
            return TestResult::Fail("expected 3 DTO writes");
        }
        // DCCG_AUDIO_DTO0_SOURCE_SEL is three bits at 0, so a source select
        // of 3 is the literal value 3 — not 3 << 4, which is DTO_SEL.
        if m.writes[0] != (0x00ab, 3) {
            return TestResult::Fail("DTO_SOURCE is 0x00ab, SOURCE_SEL the low three bits");
        }
        if m.writes[1] != (0x00ad, 0xABCDEF) {
            return TestResult::Fail("regDCCG_AUDIO_DTO0_MODULE is 0x00ad");
        }
        if m.writes[2] != (0x00ac, 0x12345) {
            return TestResult::Fail("regDCCG_AUDIO_DTO0_PHASE is 0x00ac, below module");
        }
        // And the DTO1 pair follows the same phase-then-module order.
        if DCCG_AUDIO_DTO1_PHASE != 0x00ae || DCCG_AUDIO_DTO1_MODULE != 0x00af {
            return TestResult::Fail("the DTO1 pair is 0x00ae phase, 0x00af module");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_program_audio_dto_writes_source_module_phase
    );

    /// The codec's endpoint space is indirect: index then data, two writes,
    /// at `regAZF0ENDPOINTn_AZALIA_F0_CODEC_ENDPOINT_INDEX`/`_DATA`.
    fn smoke_azalia_endpoint_is_indirect() -> TestResult {
        let mut m = MockDcnAudioMmio {
            writes: alloc::vec![],
        };
        // Endpoint 2: 0x0386 + 2 * 6 = 0x0392, which the header spells
        // regAZF0ENDPOINT2_….
        if !write_endpoint_reg(&mut m, 2, IX_PIN_CONTROL_HOT_PLUG_CONTROL, 0x1) {
            return TestResult::Fail("endpoint 2 rejected");
        }
        if m.writes.len() != 2 {
            return TestResult::Fail("an indirect write is index then data");
        }
        if m.writes[0] != (0x0392, 0x0054) {
            return TestResult::Fail("the ixAZALIA_… index goes to 0x0392 on endpoint 2");
        }
        if m.writes[1] != (0x0393, 0x1) {
            return TestResult::Fail("the value goes to the DATA register above it");
        }
        // Endpoint 7 is the last; 8 is not addressable.
        if for_endpoint(AZF0ENDPOINT0_CODEC_ENDPOINT_INDEX, 7) != 0x03b0 {
            return TestResult::Fail("endpoint 7's index register is 0x03b0");
        }
        if write_endpoint_reg(&mut m, AZF0ENDPOINTS, 0, 0) {
            return TestResult::Fail("endpoint 8 accepted");
        }
        // The indirect indices are endpoint-register indices, not offsets,
        // and are not ordered by what they do: hot-plug control at 0x0054
        // sits above the sink-info block at 0x003a.
        if IX_PIN_CONTROL_CHANNEL_SPEAKER != 0x0025
            || IX_PIN_CONTROL_AUDIO_DESCRIPTOR0 != 0x0028
            || IX_PIN_CONTROL_MULTICHANNEL_ENABLE != 0x0036
            || IX_PIN_CONTROL_SINK_INFO0 != 0x003A
            || IX_PIN_CONTROL_HOT_PLUG_CONTROL != 0x0054
        {
            return TestResult::Fail("ixAZALIA_F0_CODEC_PIN_CONTROL_* indices");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_azalia_endpoint_is_indirect);

    fn smoke_route_active_stream_dto_then_endpoint() -> TestResult {
        let mut m = MockDcnAudioMmio {
            writes: alloc::vec![],
        };
        let s = ActiveAudioStream {
            crtc_idx: 1,
            connector_idx: 2,
            format: AudioFormat::LinearPcm,
            sample_rate_hz: 48000,
            channel_count: 6,
            dto: (0x100, 0x200),
        };
        if !route_active_stream(&mut m, &s) {
            return TestResult::Fail("routing rejected");
        }
        // Three DTO writes, then two indirect endpoint writes of two each.
        if m.writes.len() != 7 {
            return TestResult::Fail("expected 3 DTO writes and two indirect writes");
        }
        if m.writes[0].0 != 0x00ab {
            return TestResult::Fail("the DTO comes first");
        }
        // Connector 2 selects endpoint 2.
        if m.writes[3] != (0x0392, IX_PIN_CONTROL_CHANNEL_SPEAKER) {
            return TestResult::Fail("channel count goes to the connector's endpoint");
        }
        if m.writes[4] != (0x0393, 5) {
            return TestResult::Fail("CHANNEL_SPEAKER carries channels minus one");
        }
        // Six channels is multichannel.
        if m.writes[6] != (0x0393, 1) {
            return TestResult::Fail("six channels must enable multichannel");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_route_active_stream_dto_then_endpoint);

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
