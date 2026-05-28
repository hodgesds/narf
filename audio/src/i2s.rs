//! I2S (Inter-IC Sound) transport — frame-format descriptor types and
//! ACP3x I2S register encoding.
//!
//! ## Sources
//!
//! - **Philips Semiconductors, "I2S bus specification"**, June 5,
//!   1996. The original Philips public bus specification.
//!   <https://web.archive.org/web/20060702004954/http://www.semiconductors.philips.com/acrobat_download/various/I2SBUS.pdf>
//! - **Wolfson WM8960 datasheet** — codec-side I2S timing variants;
//!   the `FrameFormat` variants map to the WM8960 R7 format field.
//! - **Linux `sound/soc/amd/raven/acp3x-i2s.c`** (GPL-2.0-or-later) —
//!   `acp3x_i2s_hwparams` (lines ~72-145): sample-length encoding in
//!   `ACP_BTTDM_ITER` bits [5:3]; `acp3x_i2s_set_tdm_slot` (lines
//!   ~41-70): frame-length / slot-width encoding in `ACP_BTTDM_TXFRMT`.
//! - **Linux `sound/soc/amd/raven/acp3x.h`** — `ACP3x_ITER_IRER_SAMP_LEN_MASK`
//!   = 0x38 (bits [5:3]), `SLOT_WIDTH_*` constants.
//!
//! NARF is GPL-2.0-or-later as of 2026-05-20, so these sources are
//! freely citable and adapted; the host-side ACP I2S programming lives in
//! `crate::acp6_pcm` and follows Linux's encoding for the
//! frame-format field.
//!
//! ## What this is
//!
//! I2S is a *physical* serial bus — three lines (Bit Clock, Word
//! Select, Serial Data) — so "an I2S codec" describes how a host
//! drives the lines, not a packet format. This module defines:
//!
//!  1. The [`I2sFormat`] descriptor every host controller / codec
//!     consumes when negotiating: word length, frame width, channel
//!     order, sample-rate / bit-clock relationship, and the timing
//!     variant (Standard I2S, Left-Justified, Right-Justified, DSP/PCM).
//!
//!  2. [`Acp3xIter`] — the I2S TX enable register (`ACP_BTTDM_ITER`)
//!     encoding used by Renoir (ACP3-class). Bit 0 = link enable; bits
//!     [5:3] = sample-length code; bits [2:1] = TDM enable + mode.
//!
//!  3. [`Acp3xTxFrmt`] — the TX frame-format register
//!     (`ACP_BTTDM_TXFRMT`) encoding: slot count (bits [18:15]) and
//!     slot-width code (bits [23:18]) per `acp3x_i2s_set_tdm_slot`.
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

// ── ACP3x I2S TX enable register (ACP_BTTDM_ITER / ACP_I2STDM_ITER) ──
//
// Layout (Linux `sound/soc/amd/raven/acp3x-i2s.c::acp3x_i2s_hwparams`):
//
//   bit 0          — link enable (set to start the engine)
//   bit 1          — TDM mode enable (0 = standard I2S, 1 = DSP/TDM)
//   bits [5:3]     — sample-length code per `ACP3x_ITER_IRER_SAMP_LEN_MASK`
//                    (mask 0x38 = bits [5:3] in the shift-3 field):
//                      0x00 = 8-bit  (SNDRV_PCM_FORMAT_S8)
//                      0x10 = 16-bit (SNDRV_PCM_FORMAT_S16_LE)  << val=2, shift=3
//                      0x20 = 24-bit (SNDRV_PCM_FORMAT_S24_LE)  << val=4, shift=3
//                      0x28 = 32-bit (SNDRV_PCM_FORMAT_S32_LE)  << val=5, shift=3
//
// Source: Linux `acp3x-i2s.c::acp3x_i2s_hwparams` lines 95-145 +
//         `acp3x.h::ACP3x_ITER_IRER_SAMP_LEN_MASK = 0x38`.

/// ITER sample-length mask (bits [5:3]).
pub const ITER_SAMP_LEN_MASK: u32 = 0x38;

/// Sample-length codes for `ACP_BTTDM_ITER` bits [5:3].
///
/// The code is `value << 3` where value comes from Linux's switch on
/// `params_format`: 0 for 8-bit, 2 for S16LE, 4 for S24LE, 5 for S32LE.
///
/// Reference: `acp3x-i2s.c::acp3x_i2s_hwparams` lines ~96-115.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum IterSampLen {
    /// 8-bit samples (u8 / s8). ITER bits[5:3] = 0b000.
    Bits8 = 0x00,
    /// 16-bit samples (S16_LE). ITER bits[5:3] = 0b010 → value 2 << 3.
    Bits16 = 0x10,
    /// 24-bit samples (S24_LE). ITER bits[5:3] = 0b100 → value 4 << 3.
    Bits24 = 0x20,
    /// 32-bit samples (S32_LE). ITER bits[5:3] = 0b101 → value 5 << 3.
    Bits32 = 0x28,
}

impl IterSampLen {
    /// Convert from a `WordLength` to the matching ITER code.
    pub const fn from_word_length(wl: WordLength) -> Self {
        match wl {
            WordLength::Bits16 => Self::Bits16,
            WordLength::Bits20 => Self::Bits24, // nearest supported slot
            WordLength::Bits24 => Self::Bits24,
            WordLength::Bits32 => Self::Bits32,
        }
    }
}

/// Encoded `ACP_BTTDM_ITER` / `ACP_I2STDM_ITER` value.
///
/// Constructed via [`Acp3xIter::build`]. The value is ready to OR into
/// an existing ITER word (clear `ITER_SAMP_LEN_MASK` first) or to write
/// directly after setting bit 0 to start the engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Acp3xIter(pub u32);

impl Acp3xIter {
    /// Bit 0 — I2S link enable.
    pub const ENABLE: u32 = 1 << 0;
    /// Bit 1 — TDM/DSP mode enable.
    pub const TDM_ENABLE: u32 = 1 << 1;

    /// Build an ITER value for `fmt`.
    ///
    /// Sets the sample-length field from `fmt.word_length`. Does NOT set
    /// the enable bit — callers set that when actually starting the
    /// engine.
    pub const fn build(fmt: I2sFormat) -> Self {
        let samp = IterSampLen::from_word_length(fmt.word_length) as u32;
        let tdm = if matches!(fmt.frame_format, FrameFormat::DspPcm) {
            Self::TDM_ENABLE
        } else {
            0
        };
        Self(samp | tdm)
    }

    /// Return the ITER value with the link-enable bit set.
    pub const fn with_enable(self) -> Self {
        Self(self.0 | Self::ENABLE)
    }

    /// Raw 32-bit ITER value, ready to write.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Apply the sample-length field from `self` into `existing`, clearing
    /// `ITER_SAMP_LEN_MASK` first. Used by the register-modify pattern
    /// (read-modify-write without disturbing other fields).
    pub const fn apply_to(self, existing: u32) -> u32 {
        (existing & !ITER_SAMP_LEN_MASK) | (self.0 & ITER_SAMP_LEN_MASK)
    }
}

// ── ACP3x TX frame-format register (ACP_BTTDM_TXFRMT / ACP_I2STDM_TXFRMT) ──
//
// Layout (Linux `sound/soc/amd/raven/acp3x-i2s.c::acp3x_i2s_set_tdm_slot`
//         lines ~41-70):
//
//   bits [14:0]  — FRM_LEN base (0x100 per `acp3x.h::FRM_LEN`)
//   bits [18:15] — slot count (number of TDM slots, written as count)
//   bits [23:18] — slot-width code:
//                    8 → 8-bit slot
//                   16 → 16-bit slot
//                   24 → 24-bit slot
//                    0 → 32-bit slot (SLOT_WIDTH_32 maps to 0 in Linux)
//
// The formula from Linux: `frm_len = FRM_LEN | (slots << 15) | (slot_len << 18)`
// where FRM_LEN = 0x100.

/// `FRM_LEN` base value for `ACP_BTTDM_TXFRMT` (Linux `acp3x.h::FRM_LEN`).
pub const TXFRMT_FRM_LEN: u32 = 0x100;

/// Slot-width codes for `ACP_BTTDM_TXFRMT` bits [23:18].
///
/// Source: Linux `acp3x-i2s.c::acp3x_i2s_set_tdm_slot` switch on
/// `slot_width` — 8→8, 16→16, 24→24, 32→0.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TxFrmtSlotWidth {
    Bits8 = 8,
    Bits16 = 16,
    Bits24 = 24,
    Bits32 = 0, // HW uses 0 to mean 32 bits
}

impl TxFrmtSlotWidth {
    /// Convert from a `WordLength` to the matching slot-width code.
    pub const fn from_word_length(wl: WordLength) -> Self {
        match wl {
            WordLength::Bits16 => Self::Bits16,
            WordLength::Bits20 => Self::Bits24,
            WordLength::Bits24 => Self::Bits24,
            WordLength::Bits32 => Self::Bits32,
        }
    }
}

/// Encoded `ACP_BTTDM_TXFRMT` value.
///
/// Built via [`Acp3xTxFrmt::build`]. Only meaningful when TDM mode is
/// selected (bit 1 of ITER set); in standard I2S mode this register is
/// ignored by the hardware.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Acp3xTxFrmt(pub u32);

impl Acp3xTxFrmt {
    /// Build a TXFRMT value for the given slot count and word length.
    ///
    /// Formula mirrors Linux `acp3x_i2s_set_tdm_slot`:
    /// `FRM_LEN | (slots << 15) | (slot_len << 18)`.
    pub const fn build(slots: u32, wl: WordLength) -> Self {
        let slot_len = TxFrmtSlotWidth::from_word_length(wl) as u32;
        Self(TXFRMT_FRM_LEN | (slots << 15) | (slot_len << 18))
    }

    /// Raw 32-bit TXFRMT value, ready to write.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// ITER sample-length field: the four standard word lengths encode
    /// into the correct bit patterns and mask correctly.
    ///
    /// Reference: Linux `acp3x-i2s.c::acp3x_i2s_hwparams` lines ~95-115.
    /// `ACP3x_ITER_IRER_SAMP_LEN_MASK = 0x38`.
    fn smoke_i2s_iter_samp_len_encoding() -> TestResult {
        // S16LE → val 2, shift 3 → 0x10.
        let fmt16 = I2sFormat {
            word_length: WordLength::Bits16,
            frame_format: FrameFormat::Standard,
            channels: Channels::Stereo,
            sample_rate_hz: 48_000,
            host_is_master: true,
        };
        let iter16 = Acp3xIter::build(fmt16);
        if iter16.raw() & ITER_SAMP_LEN_MASK != IterSampLen::Bits16 as u32 {
            return TestResult::Fail("S16LE sample-length code wrong");
        }
        // Enable bit must not be set by build().
        if iter16.raw() & Acp3xIter::ENABLE != 0 {
            return TestResult::Fail("ENABLE bit set by build()");
        }
        // with_enable() sets bit 0.
        if iter16.with_enable().raw() & Acp3xIter::ENABLE == 0 {
            return TestResult::Fail("with_enable() did not set ENABLE");
        }

        // S32LE → val 5, shift 3 → 0x28.
        let fmt32 = I2sFormat { word_length: WordLength::Bits32, ..fmt16 };
        let iter32 = Acp3xIter::build(fmt32);
        if iter32.raw() & ITER_SAMP_LEN_MASK != IterSampLen::Bits32 as u32 {
            return TestResult::Fail("S32LE sample-length code wrong");
        }

        // DSP/PCM sets TDM bit.
        let fmt_tdm = I2sFormat { frame_format: FrameFormat::DspPcm, ..fmt16 };
        let iter_tdm = Acp3xIter::build(fmt_tdm);
        if iter_tdm.raw() & Acp3xIter::TDM_ENABLE == 0 {
            return TestResult::Fail("DspPcm did not set TDM_ENABLE");
        }

        // apply_to() merges sample-length into an existing value.
        let existing: u32 = 0xFFFF_FFC7; // bits [5:3] = 0, other bits set
        let merged = iter32.apply_to(existing);
        if merged & ITER_SAMP_LEN_MASK != IterSampLen::Bits32 as u32 {
            return TestResult::Fail("apply_to() wrong sample-length");
        }
        if merged & !ITER_SAMP_LEN_MASK != existing & !ITER_SAMP_LEN_MASK {
            return TestResult::Fail("apply_to() disturbed non-mask bits");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/i2s", smoke_i2s_iter_samp_len_encoding);

    /// TXFRMT slot-count and slot-width encoding mirrors Linux's
    /// `acp3x_i2s_set_tdm_slot` formula.
    ///
    /// Formula: `FRM_LEN | (slots << 15) | (slot_len << 18)`.
    /// FRM_LEN = 0x100.
    fn smoke_i2s_txfrmt_slot_encoding() -> TestResult {
        // 2 slots × 16-bit: FRM_LEN | (2 << 15) | (16 << 18).
        let frmt = Acp3xTxFrmt::build(2, WordLength::Bits16);
        let expected = TXFRMT_FRM_LEN | (2 << 15) | (16 << 18);
        if frmt.raw() != expected {
            return TestResult::Fail("2-slot 16-bit TXFRMT encoding wrong");
        }

        // 2 slots × 32-bit: slot_len code = 0 (HW 32-bit sentinel).
        let frmt32 = Acp3xTxFrmt::build(2, WordLength::Bits32);
        let expected32 = TXFRMT_FRM_LEN | (2 << 15) | (0 << 18);
        if frmt32.raw() != expected32 {
            return TestResult::Fail("2-slot 32-bit TXFRMT encoding wrong");
        }

        // FRM_LEN base is always present.
        if frmt.raw() & TXFRMT_FRM_LEN == 0 {
            return TestResult::Fail("FRM_LEN base missing from TXFRMT");
        }
        if frmt32.raw() & TXFRMT_FRM_LEN == 0 {
            return TestResult::Fail("FRM_LEN base missing from 32-bit TXFRMT");
        }

        // Slot-width bits [23:18]: 24-bit slots → 24 << 18.
        let frmt24 = Acp3xTxFrmt::build(4, WordLength::Bits24);
        let sw24 = (frmt24.raw() >> 18) & 0x3F;
        if sw24 != 24 {
            return TestResult::Fail("24-bit slot-width code wrong");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/i2s", smoke_i2s_txfrmt_slot_encoding);
}
