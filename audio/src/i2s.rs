//! I2S (Inter-IC Sound) transport — frame-format descriptor types.
//!
//! ## Sources
//!
//! - **Philips Semiconductors, "I2S bus specification"**, June 5,
//!   1996. The original Philips public bus specification.
//!   <https://web.archive.org/web/20060702004954/http://www.semiconductors.philips.com/acrobat_download/various/I2SBUS.pdf>
//! - **Wolfson WM8960 datasheet** — codec-side I2S timing variants;
//!   the `FrameFormat` variants map to the WM8960 R7 format field.
//!
//! NARF is GPL-2.0-or-later as of 2026-05-20, so Linux's
//! `sound/soc/codecs/wm8960.c` + `sound/soc/amd/raven/acp3x-i2s.c`
//! are freely citable; the host-side ACP I2S programming lives in
//! `crate::acp6_pcm` and follows Linux's encoding for the
//! frame-format field.
//!
//! ## What this is
//!
//! I2S is a *physical* serial bus — three lines (Bit Clock, Word
//! Select, Serial Data) — so "an I2S codec" describes how a host
//! drives the lines, not a packet format. This module defines the
//! [`I2sFormat`] descriptor every host controller / codec consumes
//! when negotiating: word length, frame width, channel order,
//! sample-rate / bit-clock relationship, and the timing variant
//! (Standard I2S, Left-Justified, Right-Justified, DSP/PCM).
//!
//! Live SoC-specific host registers (Qualcomm LPASS, Rockchip
//! I2S, NXP SAI, Allwinner I2S) build on top of this descriptor;
//! they're not in this module — those vendor blocks have very
//! different MMIO shapes despite producing the same wire signals.

extern crate alloc;

/// Word length in bits per sample (per channel). Standard values
/// across most codecs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WordLength {
    Bits16 = 16,
    Bits20 = 20,
    Bits24 = 24,
    Bits32 = 32,
}

/// Frame timing variants (Philips I2S §3 + de-facto extensions).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameFormat {
    /// "Standard I2S": MSB delayed by 1 bit-clock from frame-sync
    /// edge. Frame sync = 0 indicates left channel, = 1 right
    /// channel — opposite of LJ/RJ.
    Standard,
    /// Left-Justified: MSB on the same edge as frame-sync. Frame
    /// sync = 1 left, = 0 right.
    LeftJustified,
    /// Right-Justified: data right-aligned within the frame.
    RightJustified,
    /// DSP / PCM mode: short frame-sync pulse one bit-clock wide;
    /// both channels packed back-to-back (TDM-like).
    DspPcm,
}

/// Number of channels in the frame. I2S is natively 2-channel
/// (stereo); TDM extensions allow 4 / 6 / 8.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Channels {
    Mono = 1,
    Stereo = 2,
    Tdm4 = 4,
    Tdm6 = 6,
    Tdm8 = 8,
}

/// I2S frame format descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct I2sFormat {
    pub word_length: WordLength,
    pub frame_format: FrameFormat,
    pub channels: Channels,
    pub sample_rate_hz: u32,
    /// `true` if the host generates BCLK + WS (master); `false` if
    /// the codec does (host = slave).
    pub host_is_master: bool,
}

impl I2sFormat {
    /// Standard CD-quality stereo: 16-bit, 44.1 kHz, host master,
    /// Standard I2S timing.
    pub const fn cd_quality_stereo() -> Self {
        Self {
            word_length: WordLength::Bits16,
            frame_format: FrameFormat::Standard,
            channels: Channels::Stereo,
            sample_rate_hz: 44_100,
            host_is_master: true,
        }
    }

    /// Bit-clock frequency in Hz. BCLK = sample-rate × channels ×
    /// word-length-bits.
    pub fn bit_clock_hz(self) -> u64 {
        (self.sample_rate_hz as u64)
            * (self.channels as u8 as u64)
            * (self.word_length as u8 as u64)
    }

    /// Master-clock frequency for a given oversampling ratio. Codecs
    /// typically run on 256× or 384× the sample rate.
    pub fn master_clock_hz(self, oversample: u32) -> u64 {
        (self.sample_rate_hz as u64) * (oversample as u64)
    }
}
