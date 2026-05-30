//! Sample formats, rates, channel counts, hw_params.
//!
//! The HDA stream-format register (`SDxFMT`, §3.3.41) packs the
//! triple `(rate, sample size, channels)` into 16 bits:
//!
//! ```text
//!   bit 15      type (0 = PCM, 1 = non-PCM)
//!   bit 14      sample base rate (0 = 48 kHz family, 1 = 44.1 kHz family)
//!   bits 13:11  sample base rate multiplier
//!   bits 10:8   sample base rate divisor
//!   bits  6:4   bits per sample (0 = 8 bit, 1 = 16, 2 = 20, 3 = 24, 4 = 32)
//!   bits  3:0   number of channels (encoded as N-1)
//! ```
//!
//! Linux references:
//! - `sound/hda/core/controller.c::snd_hdac_stream_setup_periods` —
//!   sample-rate encoder for the FMT register.
//! - `sound/hda/codecs/helpers/sigmatel.c::stac_get_format_bits` —
//!   reference encoder used by many codecs for the same field.

/// PCM sample format. Maps to the `SDxFMT.bits` field plus a
/// signed/little-endian convention enforced by the HDA spec (only
/// signed LE is meaningful on the wire).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SampleFormat {
    /// 16-bit signed little-endian.
    S16LE,
    /// 20-bit signed LE, 24-bit container (left-justified, pad in
    /// the high byte).
    S20LE,
    /// 24-bit signed LE, 24-bit container.
    S24LE,
    /// 32-bit signed LE.
    S32LE,
}

impl SampleFormat {
    /// Encoded `SDxFMT.bits` field for this format (HDA §3.3.41).
    pub const fn fmt_bits(self) -> u16 {
        match self {
            SampleFormat::S16LE => 0b001,
            SampleFormat::S20LE => 0b010,
            SampleFormat::S24LE => 0b011,
            SampleFormat::S32LE => 0b100,
        }
    }

    /// Container size in bytes (size of one sample on the wire,
    /// padded up to a byte multiple).
    pub const fn bytes_per_sample(self) -> usize {
        match self {
            SampleFormat::S16LE => 2,
            SampleFormat::S20LE | SampleFormat::S24LE => 4,
            SampleFormat::S32LE => 4,
        }
    }
}

/// Sample rate in Hz. The HDA spec lays out a fixed table; only the
/// values that the codec advertises in
/// `PARAM_SUPP_PCM_SIZE_RATES` are usable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SampleRate {
    R44100,
    R48000,
    R88200,
    R96000,
    R176400,
    R192000,
}

impl SampleRate {
    /// Numeric Hz value.
    pub const fn hz(self) -> u32 {
        match self {
            SampleRate::R44100 => 44_100,
            SampleRate::R48000 => 48_000,
            SampleRate::R88200 => 88_200,
            SampleRate::R96000 => 96_000,
            SampleRate::R176400 => 176_400,
            SampleRate::R192000 => 192_000,
        }
    }

    /// HDA SDxFMT base / mult / div bits (HDA §3.3.41 table).
    /// Bit-15 is for non-PCM and is zero for everything here.
    pub const fn fmt_rate_field(self) -> u16 {
        match self {
            // 48 kHz family: bit 14 = 0.
            SampleRate::R48000 => 0b0_000_000_0000,         // 48k × 1 / 1
            SampleRate::R96000 => 0b0_001_000_0000,         // 48k × 2 / 1
            SampleRate::R192000 => 0b0_011_000_0000,        // 48k × 4 / 1
            // 44.1 kHz family: bit 14 = 1.
            SampleRate::R44100 => 0b1_000_000_0000,
            SampleRate::R88200 => 0b1_001_000_0000,
            SampleRate::R176400 => 0b1_011_000_0000,
        }
    }
}

/// Channel count. Encoded as N-1 in the SDxFMT register.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ChannelCount {
    Mono,
    Stereo,
    Quad,
    Surround51,
    Surround71,
}

impl ChannelCount {
    pub const fn count(self) -> u8 {
        match self {
            ChannelCount::Mono => 1,
            ChannelCount::Stereo => 2,
            ChannelCount::Quad => 4,
            ChannelCount::Surround51 => 6,
            ChannelCount::Surround71 => 8,
        }
    }

    /// SDxFMT.channels field (N-1).
    pub const fn fmt_channels_field(self) -> u16 {
        (self.count() - 1) as u16
    }
}

/// Hardware parameters for a substream — what `pcm_hw_params` accepts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HwParams {
    pub format: SampleFormat,
    pub rate: SampleRate,
    pub channels: ChannelCount,
    /// Period size in frames. One BDL entry per period.
    pub period_size: u32,
    /// Number of periods in the cyclic buffer. `period_size * periods`
    /// is the full DMA-buffer length.
    pub periods: u32,
}

impl HwParams {
    /// Total cyclic buffer length in bytes.
    pub const fn buffer_bytes(self) -> usize {
        let frame_bytes = self.channels.count() as usize * self.format.bytes_per_sample();
        (self.period_size as usize) * frame_bytes * (self.periods as usize)
    }

    /// Bytes in one period.
    pub const fn period_bytes(self) -> usize {
        let frame_bytes = self.channels.count() as usize * self.format.bytes_per_sample();
        (self.period_size as usize) * frame_bytes
    }
}

/// Build the SDxFMT register word for the given params.
/// HDA §3.3.41: `[15] type | [14:8] rate | [6:4] bits | [3:0] chans`.
pub const fn pack_sdfmt(fmt: SampleFormat, rate: SampleRate, ch: ChannelCount) -> u16 {
    rate.fmt_rate_field()
        | ((fmt.fmt_bits()) << 4)
        | ch.fmt_channels_field()
}

/// Format/rate/channel feasibility check. Real HW reports its actual
/// support via the codec parameter `PARAM_SUPP_PCM_SIZE_RATES`;
/// here we only filter unrepresentable combinations (`Mono` 192 kHz
/// 8 ch, etc.).
pub fn supported(fmt: SampleFormat, _rate: SampleRate, ch: ChannelCount) -> bool {
    // The HDA fmt encoding only allows up to 16 channels — anything we
    // expose fits. Container-size combos are all encodable.
    let _ = fmt;
    let _ = ch;
    true
}
