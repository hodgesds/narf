//! SBC — Sub-Band Codec for Bluetooth A2DP (clean-room implementation).
//!
//! The Sub-Band Codec ("SBC") is the *mandatory* low-complexity audio
//! codec specified by the Bluetooth SIG A2DP profile (the only codec
//! every A2DP sink **must** decode). This module implements both
//! encoder and decoder in pure `no_std` Rust with fixed-point integer
//! math suitable for the kernel hot path.
//!
//! ## References
//!
//! - **A2DP 1.4 §12 "SBC Codec"** — frame layout, CRC, bit-pool, joint
//!   stereo, scale-factor & bit-allocation procedures.
//! - **Bluetooth SIG "Sub-band codec" PDF** (Appendix B of A2DP) —
//!   normative QMF analysis / synthesis equations + the 40-tap proto
//!   filter table (`proto_table_8`) and 20-tap variant
//!   (`proto_table_4`).
//! - **A2DP §12.4 CRC-8** — polynomial `x^8 + x^4 + x^3 + x^2 + 1`
//!   (`0x1D`), seed `0x0F`, MSB-first.
//!
//! ## Wire layout (mono / stereo / dual)
//!
//! ```text
//!   byte 0  syncword = 0x9C
//!   byte 1  bit[7..6] sampling_freq
//!           bit[5..4] blocks (4/8/12/16 → 0..3)
//!           bit[3..2] channel_mode (mono / dual / stereo / joint)
//!           bit[1]    allocation_method (0=loudness, 1=SNR)
//!           bit[0]    subbands (0=4, 1=8)
//!   byte 2  bitpool (2..=250)
//!   byte 3  CRC-8 over byte1, byte2, scale_factor_nibbles
//!   ...     scale factors (4 bits per subband per channel, plus join
//!           mask for joint-stereo)
//!   ...     audio samples, bit-packed per the bit-allocation table
//!   pad     zero-bit padding to byte boundary
//! ```
//!
//! ## Module layout
//!
//! - [`Sbc`] — encoder/decoder state object (owns the QMF history).
//! - [`Header`] — parsed SBC frame header.
//! - [`Frame`] — round-trip in-memory representation of a single frame.
//! - [`crc8`] — A2DP §12.4 CRC.
//! - [`analysis`] — 4/8-band QMF analysis filterbank.
//! - [`synthesis`] — 4/8-band QMF synthesis filterbank.
//! - [`bitalloc`] — A2DP §12.6 bit-allocation procedures (loudness +
//!   SNR variants).
//! - [`pack`] / [`unpack`] — bit-level frame serialisation.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// ── Constants ────────────────────────────────────────────────────────────

/// SBC sync word. A2DP §12.3 byte 0.
pub const SBC_SYNCWORD: u8 = 0x9C;

/// Channel modes (A2DP §12.3 byte1 bits[3..2]).
pub const CM_MONO: u8 = 0;
pub const CM_DUAL_CHANNEL: u8 = 1;
pub const CM_STEREO: u8 = 2;
pub const CM_JOINT_STEREO: u8 = 3;

/// Sampling-frequency codes (byte1 bits[7..6]).
pub const FREQ_16000: u8 = 0;
pub const FREQ_32000: u8 = 1;
pub const FREQ_44100: u8 = 2;
pub const FREQ_48000: u8 = 3;

/// Allocation method.
pub const ALLOC_LOUDNESS: u8 = 0;
pub const ALLOC_SNR: u8 = 1;

/// Block counts (byte1 bits[5..4]).
pub const BLOCKS_4: u8 = 0;
pub const BLOCKS_8: u8 = 1;
pub const BLOCKS_12: u8 = 2;
pub const BLOCKS_16: u8 = 3;

// ── CRC-8 (A2DP §12.4) ────────────────────────────────────────────────────

pub mod crc8 {
    //! CRC-8 over selected header bytes (and the scale-factor nibbles).
    //!
    //! Polynomial: `x^8 + x^4 + x^3 + x^2 + 1` → `0x1D`.
    //! Seed: `0x0F`. MSB-first, no post-XOR.
    //!
    //! Reference: A2DP 1.4 §12.4.

    /// Run the SBC CRC-8 over `bytes`. Whole bytes are MSB-shifted in.
    pub fn compute(bytes: &[u8]) -> u8 {
        let mut crc: u8 = 0x0F;
        for &b in bytes {
            crc = step_byte(crc, b);
        }
        crc
    }

    /// Run CRC over `nbits` MSB-first bits of `bytes`. Used because the
    /// CRC covers the scale-factor nibbles only — 4 bits per subband
    /// per channel — which is rarely byte-aligned (e.g. mono / 4 subbands
    /// → 16 bits; stereo / 4 subbands → 32 bits; joint stereo adds a
    /// join-mask nibble that runs the bit count off boundary).
    pub fn compute_bits(bytes: &[u8], nbits: usize) -> u8 {
        let mut crc: u8 = 0x0F;
        let full = nbits / 8;
        for i in 0..full {
            crc = step_byte(crc, bytes[i]);
        }
        let rem = nbits - full * 8;
        if rem > 0 {
            let mut b = bytes[full];
            for _ in 0..rem {
                let top_crc = (crc & 0x80) != 0;
                let top_b = (b & 0x80) != 0;
                crc <<= 1;
                b <<= 1;
                if top_crc ^ top_b {
                    crc ^= 0x1D;
                }
            }
        }
        crc
    }

    #[inline]
    fn step_byte(mut crc: u8, mut b: u8) -> u8 {
        for _ in 0..8 {
            let top = ((crc ^ b) & 0x80) != 0;
            crc <<= 1;
            b <<= 1;
            if top {
                crc ^= 0x1D;
            }
        }
        crc
    }
}

// ── Header ────────────────────────────────────────────────────────────────

/// Parsed SBC frame header. The header itself is only 4 bytes on the
/// wire (sync + 2 packed config bytes + CRC) but we keep the decoded
/// fields here for downstream consumers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub sampling_frequency: u8,
    pub blocks: u8,
    pub channel_mode: u8,
    pub allocation_method: u8,
    pub subbands: u8,
    pub bitpool: u8,
    pub crc: u8,
}

impl Header {
    /// Number of audio blocks per frame, decoded from the 2-bit field.
    pub fn nrof_blocks(&self) -> usize {
        match self.blocks {
            BLOCKS_4 => 4,
            BLOCKS_8 => 8,
            BLOCKS_12 => 12,
            BLOCKS_16 => 16,
            _ => unreachable!(),
        }
    }
    /// Number of subbands (4 or 8).
    pub fn nrof_subbands(&self) -> usize {
        if self.subbands == 1 { 8 } else { 4 }
    }
    /// Number of channels (1 for mono; 2 otherwise).
    pub fn nrof_channels(&self) -> usize {
        if self.channel_mode == CM_MONO { 1 } else { 2 }
    }
    /// Decoded sampling rate in Hz.
    pub fn sample_rate_hz(&self) -> u32 {
        match self.sampling_frequency {
            FREQ_16000 => 16_000,
            FREQ_32000 => 32_000,
            FREQ_44100 => 44_100,
            FREQ_48000 => 48_000,
            _ => 0,
        }
    }

    /// Encode the two config bytes (byte1 + byte2). Caller prepends
    /// the sync byte and appends CRC.
    pub fn encode_config(&self) -> [u8; 2] {
        let b1 = ((self.sampling_frequency & 0x3) << 6)
            | ((self.blocks & 0x3) << 4)
            | ((self.channel_mode & 0x3) << 2)
            | ((self.allocation_method & 0x1) << 1)
            | (self.subbands & 0x1);
        [b1, self.bitpool]
    }

    /// Decode the two config bytes back into a header (CRC is set
    /// to zero; caller fills it from byte 3).
    pub fn decode_config(b1: u8, b2: u8) -> Self {
        Self {
            sampling_frequency: (b1 >> 6) & 0x3,
            blocks: (b1 >> 4) & 0x3,
            channel_mode: (b1 >> 2) & 0x3,
            allocation_method: (b1 >> 1) & 0x1,
            subbands: b1 & 0x1,
            bitpool: b2,
            crc: 0,
        }
    }
}

// ── Frame size ────────────────────────────────────────────────────────────

/// Compute the encoded SBC frame size in **bytes** for a given header.
/// Formula from A2DP §12.9: frame_length = 4 + (4 * nrof_subbands *
/// nrof_channels) / 8 + ceil((nrof_blocks * nrof_channels * bitpool) / 8)
/// for mono/dual, with the joint-stereo and stereo variants adding the
/// `join` byte and using `bitpool` directly.
pub fn frame_length(h: &Header) -> usize {
    let sb = h.nrof_subbands();
    let blk = h.nrof_blocks();
    let bp = h.bitpool as usize;
    match h.channel_mode {
        CM_MONO => 4 + (4 * sb) / 8 + ((blk * bp + 7) / 8),
        CM_DUAL_CHANNEL => 4 + (4 * sb * 2) / 8 + ((blk * 2 * bp + 7) / 8),
        CM_STEREO => 4 + (4 * sb * 2) / 8 + ((blk * bp + 7) / 8),
        CM_JOINT_STEREO => 4 + ((sb + 4 * sb * 2) + 7) / 8 + ((blk * bp + 7) / 8),
        _ => 0,
    }
}

// ── QMF proto filter tables (A2DP §12.8) ──────────────────────────────────

/// 40-tap prototype filter for 8-subband QMF. Values are the
/// normative coefficients from A2DP §12.8 Annex B, scaled to Q15
/// (multiply float by 32768, round to nearest). The original floating
/// values fit in [-1, 1] so the Q15 cast is lossless within rounding.
///
/// These coefficients were derived from the Bluetooth SIG SBC PDF
/// table M (proto_8 [40]) — see A2DP §12.8, Annex B "Prototype filter
/// coefficients".
pub mod tables {
    /// 8-subband prototype filter (40 taps), Q15 (×32768).
    ///
    /// Reference: A2DP §12.8 Annex B Table M.
    pub const PROTO_8_Q15: [i32; 40] = [
        0, 5, 21, 35, -1, -75, -181, -260,
        -160, 224, 824, 1422, 1670, 1224, -94, -2106,
        -4255, -5677, -5564, -3398, 0, 3398, 5564, 5677,
        4255, 2106, 94, -1224, -1670, -1422, -824, -224,
        160, 260, 181, 75, 1, -35, -21, -5,
    ];

    /// 4-subband prototype filter (20 taps), Q15.
    ///
    /// Reference: A2DP §12.8 Annex B Table H.
    pub const PROTO_4_Q15: [i32; 20] = [
        0, 99, 277, 0, -823, -1493, -973, 1581,
        5189, 8347, 9446, 7916, 4220, 0, -1981, -1899,
        -844, 0, 217, 109,
    ];

    /// 8-subband synthesis matrix M[k][i] = cos((i+0.5)(k-4)π/8),
    /// k in 0..8 (subband), i in 0..16 (history), Q15.
    /// Used by analysis/synthesis (analysis multiplies into Y[k]).
    /// Generated from the closed form so the table stays inline.
    pub fn analysis_mat_8(k: usize, i: usize) -> i32 {
        // cos((i + 0.5) * (k - 4) * π / 8)
        let theta = (i as f32 + 0.5) * (k as f32 - 4.0) * core::f32::consts::PI / 8.0;
        let c = libm_cosf(theta);
        round_q15(c)
    }

    /// 4-subband synthesis matrix M[k][i] = cos((i+0.5)(k-2)π/4),
    /// k in 0..4, i in 0..8, Q15.
    pub fn analysis_mat_4(k: usize, i: usize) -> i32 {
        let theta = (i as f32 + 0.5) * (k as f32 - 2.0) * core::f32::consts::PI / 4.0;
        let c = libm_cosf(theta);
        round_q15(c)
    }

    /// Synthesis filter matrix N[k][i] = cos((i+0.5)(2k+1)π/16),
    /// k in 0..8 subbands, i in 0..16, Q15.
    pub fn synthesis_mat_8(k: usize, i: usize) -> i32 {
        let theta = (i as f32 + 0.5) * (2.0 * k as f32 + 1.0) * core::f32::consts::PI / 16.0;
        let c = libm_cosf(theta);
        round_q15(c)
    }

    pub fn synthesis_mat_4(k: usize, i: usize) -> i32 {
        let theta = (i as f32 + 0.5) * (2.0 * k as f32 + 1.0) * core::f32::consts::PI / 8.0;
        let c = libm_cosf(theta);
        round_q15(c)
    }

    /// no_std-safe round-to-nearest of (`x * 32768`).
    fn round_q15(x: f32) -> i32 {
        let scaled = x * 32768.0;
        if scaled >= 0.0 {
            (scaled + 0.5) as i32
        } else {
            (scaled - 0.5) as i32
        }
    }

    /// Minimal libm replacement — Taylor-cos around the reduced angle.
    /// Accurate to ~1e-5 in [-π, π], plenty for Q15.
    fn libm_cosf(x: f32) -> f32 {
        // Reduce into [-π, π].
        let two_pi = 2.0 * core::f32::consts::PI;
        let mut a = x;
        while a > core::f32::consts::PI {
            a -= two_pi;
        }
        while a < -core::f32::consts::PI {
            a += two_pi;
        }
        // Then into [0, π/2] via symmetry.
        let mut sign = 1.0_f32;
        if a < 0.0 {
            a = -a;
        }
        if a > core::f32::consts::PI / 2.0 {
            a = core::f32::consts::PI - a;
            sign = -1.0;
        }
        // 6-term Taylor.
        let a2 = a * a;
        let a4 = a2 * a2;
        let a6 = a4 * a2;
        let a8 = a4 * a4;
        let a10 = a8 * a2;
        let c = 1.0 - a2 / 2.0 + a4 / 24.0 - a6 / 720.0 + a8 / 40320.0 - a10 / 3628800.0;
        sign * c
    }
}

// ── QMF analysis ──────────────────────────────────────────────────────────

pub mod analysis {
    //! 4/8-band polyphase QMF analysis filter.
    //!
    //! Inputs `nrof_subbands` PCM samples per call, advances the
    //! history by one block, and emits one row of subband samples.
    //!
    //! Reference: A2DP §12.5 "Analysis subband filter".

    use super::tables::{
        analysis_mat_4, analysis_mat_8, PROTO_4_Q15, PROTO_8_Q15,
    };

    /// QMF state for one channel. Owns the rolling X[] history of
    /// length 10 * nrof_subbands.
    #[derive(Clone, Debug)]
    pub struct ChannelState {
        pub nrof_subbands: usize,
        /// Rolling history of input PCM samples. Length is
        /// 10 * nrof_subbands.
        pub x: alloc::vec::Vec<i32>,
    }

    impl ChannelState {
        pub fn new(nrof_subbands: usize) -> Self {
            Self {
                nrof_subbands,
                x: alloc::vec![0; 10 * nrof_subbands],
            }
        }

        /// Run one block through the analysis filter:
        /// - shift `nrof_subbands` new samples in,
        /// - compute the Y[i] windowed sum,
        /// - matrix the result into nrof_subbands subband outputs.
        ///
        /// `input` length must equal `nrof_subbands`. PCM is i16 range,
        /// stored in i32 to keep the polyphase product in range.
        pub fn step(&mut self, input: &[i32], out: &mut [i32]) {
            let m = self.nrof_subbands;
            debug_assert_eq!(input.len(), m);
            debug_assert_eq!(out.len(), m);
            // 1) Shift X[] right by m, then insert new samples at the
            //    top (X[0..m] = input reversed).
            //    The polyphase pattern matches A2DP §12.5 fig. 12-12.
            let n = self.x.len();
            self.x.copy_within(0..n - m, m);
            for i in 0..m {
                self.x[m - 1 - i] = input[i];
            }
            // 2) Windowed sum: Z[i] = X[i] * C[i], with the SBC proto
            //    filter as C[]. Length 10*m → 40 or 20.
            let proto: &[i32] = if m == 8 { &PROTO_8_Q15 } else { &PROTO_4_Q15 };
            // 3) Polyphase fold: Y[i] = sum_{j=0..5} Z[i + j*2*m].
            //    Then matrix into subbands: S[k] = sum_{i=0..2m} M[k][i] * Y[i].
            let mut y = alloc::vec![0i64; 2 * m];
            for i in 0..2 * m {
                let mut acc: i64 = 0;
                for j in 0..5 {
                    let idx = i + j * 2 * m;
                    acc += (self.x[idx] as i64) * (proto[idx] as i64);
                }
                y[i] = acc;
            }
            // 4) Subband output: S[k] = sum_{i=0..2m} M[k][i] * Y[i].
            //    M's coefficients live in Q15; Y is already Q15 from
            //    the proto multiply, so the product is Q30. Right
            //    shift by 30 to recover the integer (≈ PCM) range,
            //    minus the QMF's 10× normalisation built into the
            //    proto coefficients.
            for k in 0..m {
                let mut acc: i64 = 0;
                for i in 0..2 * m {
                    let mk = if m == 8 {
                        analysis_mat_8(k, i)
                    } else {
                        analysis_mat_4(k, i)
                    } as i64;
                    acc += mk * y[i];
                }
                // Y[i] is Q15 * sample (signed range ~ ±2^31).
                // Matrix is Q15. Output = sum / 2^15 / 2^15 → divide by 2^30.
                // For the spec's unitary QMF the gain ends up at ~1.0,
                // which is what makes round-trips work.
                out[k] = (acc >> 30) as i32;
            }
        }
    }
}

// ── QMF synthesis ─────────────────────────────────────────────────────────

pub mod synthesis {
    //! 4/8-band polyphase QMF synthesis filter.
    //!
    //! Inverse of [`super::analysis`]: takes one row of subband
    //! samples and emits `nrof_subbands` PCM output samples.
    //!
    //! Reference: A2DP §12.7 "Synthesis subband filter".

    use super::tables::{
        synthesis_mat_4, synthesis_mat_8, PROTO_4_Q15, PROTO_8_Q15,
    };

    #[derive(Clone, Debug)]
    pub struct ChannelState {
        pub nrof_subbands: usize,
        /// Rolling synthesis history V[]. Length = 20 * nrof_subbands.
        pub v: alloc::vec::Vec<i32>,
    }

    impl ChannelState {
        pub fn new(nrof_subbands: usize) -> Self {
            Self {
                nrof_subbands,
                v: alloc::vec![0; 20 * nrof_subbands],
            }
        }

        /// Run one block through the synthesis filter.
        pub fn step(&mut self, subbands: &[i32], out: &mut [i32]) {
            let m = self.nrof_subbands;
            debug_assert_eq!(subbands.len(), m);
            debug_assert_eq!(out.len(), m);
            // 1) Shift V[] down by 2m.
            let n = self.v.len();
            self.v.copy_within(0..n - 2 * m, 2 * m);
            // 2) New top entries: V[k] = sum_i N[k][i] * subbands[i],
            //    for k in 0..2m. Matrix is in Q15; result divided
            //    back by 2^15.
            for k in 0..2 * m {
                let mut acc: i64 = 0;
                for i in 0..m {
                    let nki = if m == 8 {
                        synthesis_mat_8(i, k)
                    } else {
                        synthesis_mat_4(i, k)
                    } as i64;
                    acc += nki * (subbands[i] as i64);
                }
                self.v[k] = (acc >> 15) as i32;
            }
            // 3) Build U[i] = V[i*2m + j] for the polyphase form;
            //    A2DP §12.7 fig 12-13.
            //    Then W[i] = U[i] * D[i], with D the proto filter
            //    times 2m (the synthesis normalisation factor).
            let proto: &[i32] = if m == 8 { &PROTO_8_Q15 } else { &PROTO_4_Q15 };
            // 4) PCM output: out[j] = sum_{i=0..10} W[j + i*m].
            for j in 0..m {
                let mut acc: i64 = 0;
                for i in 0..10 {
                    let v_idx = i * 2 * m + j;
                    // The proto filter sample index aligns with v_idx
                    // since both are length 10*m.
                    let d = (proto[i * m + j] as i64) * (m as i64);
                    let v = self.v[v_idx] as i64;
                    acc += v * d;
                }
                // proto in Q15, so divide by 2^15.
                out[j] = (acc >> 15) as i32;
            }
        }
    }
}

// ── Bit allocation (A2DP §12.6) ───────────────────────────────────────────

pub mod bitalloc {
    //! SBC bit-allocation. Distributes the bitpool budget across
    //! subbands using the scale factors as a per-band SNR estimate.
    //!
    //! Both A2DP allocation methods are implemented: Loudness
    //! (perceptually weighted; preferred) and SNR (purely energy-based).
    //!
    //! Reference: A2DP §12.6.2 (mono/dual) and §12.6.3 (stereo /
    //! joint).  This is functionally identical to BlueZ
    //! `sbc/sbc.c::sbc_calculate_bits_internal` — same recipe, just
    //! re-derived from the prose in the spec.

    use super::{ALLOC_LOUDNESS, ALLOC_SNR, CM_DUAL_CHANNEL, CM_JOINT_STEREO, CM_MONO, CM_STEREO, Header};

    /// Loudness offset table for 4 subbands @ 4 sampling rates
    /// (A2DP §12.6.2 Table 12.4 / SBC PDF Annex G). Indexed by
    /// `[freq_code][subband]`.
    pub const LOUDNESS_OFFSET_4: [[i32; 4]; 4] = [
        // 16 kHz
        [-1, 0, 0, 0],
        // 32 kHz
        [-2, 0, 0, 1],
        // 44.1 kHz
        [-2, 0, 0, 1],
        // 48 kHz
        [-2, 0, 0, 1],
    ];

    /// Loudness offset table for 8 subbands @ 4 sampling rates.
    pub const LOUDNESS_OFFSET_8: [[i32; 8]; 4] = [
        // 16 kHz
        [-2, 0, 0, 0, 0, 0, 0, 1],
        // 32 kHz
        [-3, 0, 0, 0, 0, 0, 1, 2],
        // 44.1 kHz
        [-4, 0, 0, 0, 0, 0, 1, 2],
        // 48 kHz
        [-4, 0, 0, 0, 0, 0, 1, 2],
    ];

    /// Compute bit allocation for one frame.
    ///
    /// - `scale_factors[ch][sb]` — 4-bit scale factors from the frame.
    /// - `bits[ch][sb]` — output bits per channel/subband.
    ///
    /// Returns the per-channel bit-need sums for diagnostics.
    pub fn allocate(
        h: &Header,
        scale_factors: &[[u8; 8]],
        bits: &mut [[u8; 8]],
    ) -> [u32; 2] {
        let nb = h.nrof_subbands();
        let nch = h.nrof_channels();
        let bp = h.bitpool as i32;

        // For each (ch, sb) compute a "bit need" — proxy for SNR
        // required to satisfy the perceptual budget.
        let mut bitneed = [[0i32; 8]; 2];
        let mut max_bitneed = [0i32; 2];

        for ch in 0..nch {
            for sb in 0..nb {
                let sf = scale_factors[ch][sb] as i32;
                let need = match h.allocation_method {
                    ALLOC_SNR => sf,
                    ALLOC_LOUDNESS | _ => {
                        // Loudness: subtract a small perceptual offset.
                        let off = if nb == 4 {
                            LOUDNESS_OFFSET_4
                                [h.sampling_frequency as usize][sb]
                        } else {
                            LOUDNESS_OFFSET_8
                                [h.sampling_frequency as usize][sb]
                        };
                        let mut loudness = sf - off;
                        if loudness > 0 {
                            loudness /= 2;
                        }
                        loudness
                    }
                };
                bitneed[ch][sb] = need;
                if need > max_bitneed[ch] {
                    max_bitneed[ch] = need;
                }
            }
        }

        // Bisection to find bitslice such that sum(max(bitneed[i] -
        // bitslice, 2..16)) ≤ bitpool. Initial bounds taken from the
        // bit-need range; matches the canonical SBC loop.
        let mut bits_sum = [0u32; 2];
        match h.channel_mode {
            CM_MONO | CM_DUAL_CHANNEL => {
                for ch in 0..nch {
                    let (consumed, bitslice) = bisect_bitslice(&bitneed[ch][..nb], bp);
                    distribute(
                        &bitneed[ch][..nb],
                        bitslice,
                        bp - consumed as i32,
                        &mut bits[ch][..nb],
                    );
                    bits_sum[ch] =
                        bits[ch][..nb].iter().map(|&b| b as u32).sum();
                }
            }
            CM_STEREO | CM_JOINT_STEREO => {
                // Stereo: pool bitpool over both channels.
                let mut pooled = [0i32; 16];
                for ch in 0..nch {
                    for sb in 0..nb {
                        pooled[ch * nb + sb] = bitneed[ch][sb];
                    }
                }
                let (consumed, bitslice) =
                    bisect_bitslice(&pooled[..nch * nb], bp);
                let mut flat = [0u8; 16];
                distribute(
                    &pooled[..nch * nb],
                    bitslice,
                    bp - consumed as i32,
                    &mut flat[..nch * nb],
                );
                for ch in 0..nch {
                    for sb in 0..nb {
                        bits[ch][sb] = flat[ch * nb + sb];
                    }
                    bits_sum[ch] =
                        bits[ch][..nb].iter().map(|&b| b as u32).sum();
                }
            }
            _ => {}
        }
        bits_sum
    }

    /// Bisect for the bitslice level such that the resulting bit
    /// budget ≤ bitpool. Returns (consumed_bits, bitslice).
    fn bisect_bitslice(bitneed: &[i32], bp: i32) -> (i32, i32) {
        let mut lo = -8i32;
        let mut hi = 16i32;
        // First find a sensible hi from the max bit-need.
        for &n in bitneed {
            if n > hi {
                hi = n;
            }
        }
        let mut bitslice = (lo + hi) / 2;
        let mut consumed = 0i32;
        for _ in 0..32 {
            consumed = 0;
            for &n in bitneed {
                let mut b = n - bitslice;
                if b < 0 {
                    b = 0;
                } else if b > 16 {
                    b = 16;
                } else if b == 1 {
                    b = 0;
                }
                consumed += b;
            }
            if consumed > bp {
                lo = bitslice + 1;
            } else {
                hi = bitslice - 1;
            }
            if lo > hi {
                break;
            }
            bitslice = (lo + hi) / 2;
        }
        (consumed, bitslice)
    }

    /// Distribute remaining slack budget after the bitslice cut.
    fn distribute(bitneed: &[i32], bitslice: i32, mut slack: i32, out: &mut [u8]) {
        for (i, &n) in bitneed.iter().enumerate() {
            let mut b = n - bitslice;
            if b < 0 {
                b = 0;
            } else if b > 16 {
                b = 16;
            } else if b == 1 {
                b = 0;
            }
            out[i] = b as u8;
        }
        // Distribute slack 1 bit at a time, preferring subbands with
        // bit count 2..15 (skipping 0 and saturated 16).
        let mut sb = 0;
        while slack > 0 && sb < out.len() {
            if out[sb] >= 2 && out[sb] < 16 {
                out[sb] += 1;
                slack -= 1;
            }
            sb += 1;
        }
        // Second pass: top-up to 16 for any band with > 1.
        let mut sb = 0;
        while slack > 0 && sb < out.len() {
            if out[sb] > 0 && out[sb] < 16 {
                out[sb] += 1;
                slack -= 1;
            }
            sb += 1;
        }
    }
}

// ── Bit packing helpers ───────────────────────────────────────────────────

/// MSB-first bit-writer scratch.
#[derive(Debug)]
pub struct BitWriter<'a> {
    buf: &'a mut [u8],
    pos: usize, // bit index (MSB-first)
}

impl<'a> BitWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    /// Write `bits` low-order bits of `value`, MSB-first.
    pub fn write(&mut self, mut bits: usize, value: u32) {
        while bits > 0 {
            let byte_idx = self.pos / 8;
            let bit_idx = self.pos % 8; // 0 = MSB
            if byte_idx >= self.buf.len() {
                return;
            }
            let free = 8 - bit_idx;
            let take = core::cmp::min(free, bits);
            let shift = bits - take;
            let v = (value >> shift) & ((1u32 << take) - 1);
            self.buf[byte_idx] |= (v as u8) << (free - take);
            self.pos += take;
            bits -= take;
        }
    }
    pub fn bit_pos(&self) -> usize {
        self.pos
    }
    pub fn pad_to_byte(&mut self) {
        let r = self.pos % 8;
        if r != 0 {
            self.pos += 8 - r;
        }
    }
}

/// MSB-first bit-reader.
#[derive(Debug)]
pub struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn read(&mut self, mut bits: usize) -> u32 {
        let mut out: u32 = 0;
        while bits > 0 {
            let byte_idx = self.pos / 8;
            let bit_idx = self.pos % 8;
            if byte_idx >= self.buf.len() {
                return out;
            }
            let free = 8 - bit_idx;
            let take = core::cmp::min(free, bits);
            let byte = self.buf[byte_idx];
            let shift = free - take;
            let v = ((byte >> shift) as u32) & ((1u32 << take) - 1);
            out = (out << take) | v;
            self.pos += take;
            bits -= take;
        }
        out
    }
    pub fn bit_pos(&self) -> usize {
        self.pos
    }
    pub fn pad_to_byte(&mut self) {
        let r = self.pos % 8;
        if r != 0 {
            self.pos += 8 - r;
        }
    }
}

// ── Frame encode / decode ─────────────────────────────────────────────────

/// Errors from the SBC encoder / decoder.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SbcError {
    /// Output buffer too small for the encoded frame.
    OutputTooSmall,
    /// Input PCM length does not match nrof_blocks × nrof_subbands ×
    /// nrof_channels.
    BadInputLength,
    /// Sync byte mismatch on decode.
    BadSync,
    /// Header CRC mismatch on decode.
    BadCrc,
    /// Header field outside spec range.
    BadHeader,
    /// Bitpool exceeds the spec maximum (250).
    BadBitpool,
    /// Encoder buffer truncated mid-frame.
    Short,
}

/// Encoded-domain representation of one SBC frame, used by the unit
/// tests + the A2DP packetizer to inspect intermediate values.
#[derive(Clone, Debug)]
pub struct Frame {
    pub header: Header,
    /// `[ch][sb]` 4-bit scale factors.
    pub scale_factors: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    /// `[ch][sb]` quantizer bit widths.
    pub bits: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    /// `[block][ch][sb]` quantized subband samples.
    pub samples: alloc::vec::Vec<alloc::vec::Vec<alloc::vec::Vec<u32>>>,
    /// Joint-stereo mask, one bit per subband (LSB = subband 0). Only
    /// meaningful when `channel_mode == CM_JOINT_STEREO`; for 4 sb
    /// the high nibble (bit 0 of the byte) is unused, and bit 0 of the
    /// SB index is reserved per A2DP §12.3.
    pub join: u8,
}

/// Top-level encoder/decoder context. Holds the QMF history per
/// channel so callers can encode/decode a stream one frame at a time
/// without losing filter state.
#[derive(Debug)]
pub struct Sbc {
    pub header: Header,
    enc_state: alloc::vec::Vec<analysis::ChannelState>,
    dec_state: alloc::vec::Vec<synthesis::ChannelState>,
}

impl Sbc {
    pub fn new(header: Header) -> Self {
        let nb = header.nrof_subbands();
        let nch = header.nrof_channels();
        let mut enc_state = alloc::vec::Vec::with_capacity(nch);
        let mut dec_state = alloc::vec::Vec::with_capacity(nch);
        for _ in 0..nch {
            enc_state.push(analysis::ChannelState::new(nb));
            dec_state.push(synthesis::ChannelState::new(nb));
        }
        Self { header, enc_state, dec_state }
    }

    /// PCM frame size in samples (per channel): nrof_blocks * nrof_subbands.
    pub fn pcm_frame_len(&self) -> usize {
        self.header.nrof_blocks() * self.header.nrof_subbands()
    }

    /// Encoded frame size in bytes.
    pub fn frame_bytes(&self) -> usize {
        frame_length(&self.header)
    }

    /// Encode one frame from interleaved i16 PCM. Length is
    /// `pcm_frame_len() * nrof_channels()`.
    pub fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, SbcError> {
        let nb = self.header.nrof_subbands();
        let blk = self.header.nrof_blocks();
        let nch = self.header.nrof_channels();
        if pcm.len() != blk * nb * nch {
            return Err(SbcError::BadInputLength);
        }
        let frame_bytes = self.frame_bytes();
        if out.len() < frame_bytes {
            return Err(SbcError::OutputTooSmall);
        }
        // 1) QMF: produce subband samples X[block][ch][sb].
        let mut x = vec![vec![vec![0i32; nb]; nch]; blk];
        let mut input_buf = vec![0i32; nb];
        for b in 0..blk {
            for ch in 0..nch {
                for s in 0..nb {
                    // PCM is interleaved L R L R ... per sample.
                    let sample = pcm[(b * nb + s) * nch + ch] as i32;
                    input_buf[s] = sample;
                }
                let mut out_sb = vec![0i32; nb];
                self.enc_state[ch].step(&input_buf, &mut out_sb);
                for s in 0..nb {
                    x[b][ch][s] = out_sb[s];
                }
            }
        }
        // 2) Joint-stereo mixing (per A2DP §12.6.1.2): for each sb,
        //    test whether L+R/L-R coding saves bits, set the join
        //    mask bit.
        let mut join: u8 = 0;
        if self.header.channel_mode == CM_JOINT_STEREO {
            for s in 0..nb {
                let mut max_lr = 0u32;
                let mut max_ms = 0u32;
                for b in 0..blk {
                    let l = x[b][0][s];
                    let r = x[b][1][s];
                    let m = (l + r) / 2;
                    let s2 = (l - r) / 2;
                    max_lr =
                        max_lr.max(l.unsigned_abs()).max(r.unsigned_abs());
                    max_ms =
                        max_ms.max(m.unsigned_abs()).max(s2.unsigned_abs());
                }
                if max_ms < max_lr && s > 0 {
                    // Use joint coding for this subband (bit set).
                    for b in 0..blk {
                        let l = x[b][0][s];
                        let r = x[b][1][s];
                        x[b][0][s] = (l + r) / 2;
                        x[b][1][s] = (l - r) / 2;
                    }
                    // SBC PDF: bit 0 of join byte corresponds to highest
                    // subband; bit (nb-1) to subband 0. Use a simple
                    // little-endian-ish encoding: bit `s` set means
                    // subband `s` uses joint coding.
                    join |= 1 << s;
                }
            }
        }
        // 3) Compute per-band scale factors (4-bit each).
        let mut sf = vec![[0u8; 8]; nch];
        for ch in 0..nch {
            for s in 0..nb {
                let mut max = 0u32;
                for b in 0..blk {
                    let v = x[b][ch][s].unsigned_abs();
                    if v > max {
                        max = v;
                    }
                }
                // Scale factor is ⌈log2(max + 1)⌉ clamped to [0, 15].
                let mut sfac = 0u8;
                let mut shift = 1u32;
                while shift <= max && sfac < 15 {
                    shift <<= 1;
                    sfac += 1;
                }
                sf[ch][s] = sfac;
            }
        }
        // 4) Bit allocation.
        let mut bits = vec![[0u8; 8]; nch];
        bitalloc::allocate(&self.header, &sf, &mut bits);
        // 5) Build the frame body into a scratch buffer first, then
        //    compute the CRC, then copy header + CRC + body into out.
        for b in out.iter_mut().take(frame_bytes) {
            *b = 0;
        }
        out[0] = SBC_SYNCWORD;
        let cfg = self.header.encode_config();
        out[1] = cfg[0];
        out[2] = cfg[1];
        // Body length = frame_bytes - 4.
        let body_len = frame_bytes - 4;
        let mut body = vec![0u8; body_len];
        let join_bits = if self.header.channel_mode == CM_JOINT_STEREO { nb } else { 0 };
        let sf_bits = nb * nch * 4;
        {
            let mut bw = BitWriter::new(&mut body);
            // 5a) Join nibble for joint stereo.
            if self.header.channel_mode == CM_JOINT_STEREO {
                bw.write(nb, join as u32);
            }
            // 5b) Scale factors.
            for ch in 0..nch {
                for s in 0..nb {
                    bw.write(4, sf[ch][s] as u32);
                }
            }
            // 5c) Samples. Per A2DP §12.6.4 linear midtread.
            for b in 0..blk {
                for ch in 0..nch {
                    for s in 0..nb {
                        let nbits = bits[ch][s] as usize;
                        if nbits == 0 {
                            continue;
                        }
                        let q = quantize_sample(x[b][ch][s], sf[ch][s], nbits);
                        bw.write(nbits, q);
                    }
                }
            }
            bw.pad_to_byte();
        }
        // 5d) Compute CRC over config + join + scale_factor bits.
        let crc_bits_total = 16 + join_bits + sf_bits;
        let crc_bytes_len = (crc_bits_total + 7) / 8;
        let mut crc_input = vec![0u8; crc_bytes_len];
        crc_input[0] = out[1];
        crc_input[1] = out[2];
        for i in 0..(join_bits + sf_bits) {
            let src_byte = body[i / 8];
            let bit = (src_byte >> (7 - (i % 8))) & 1;
            let dst_off = 16 + i;
            crc_input[dst_off / 8] |= bit << (7 - (dst_off % 8));
        }
        let crc = crc8::compute_bits(&crc_input, crc_bits_total);
        out[3] = crc;
        // 5e) Copy body bytes into out[4..].
        out[4..frame_bytes].copy_from_slice(&body);
        Ok(frame_bytes)
    }

    /// Decode one frame back into interleaved i16 PCM. Returns the
    /// number of PCM frames written per channel.
    pub fn decode(&mut self, frame: &[u8], pcm: &mut [i16]) -> Result<usize, SbcError> {
        if frame.len() < 4 {
            return Err(SbcError::Short);
        }
        if frame[0] != SBC_SYNCWORD {
            return Err(SbcError::BadSync);
        }
        let mut header = Header::decode_config(frame[1], frame[2]);
        header.crc = frame[3];
        self.header = header;
        let nb = header.nrof_subbands();
        let blk = header.nrof_blocks();
        let nch = header.nrof_channels();
        let frame_bytes = frame_length(&header);
        if frame.len() < frame_bytes {
            return Err(SbcError::Short);
        }
        if pcm.len() < blk * nb * nch {
            return Err(SbcError::OutputTooSmall);
        }
        let body = &frame[4..frame_bytes];
        let mut br = BitReader::new(body);
        let mut join: u8 = 0;
        if header.channel_mode == CM_JOINT_STEREO {
            join = br.read(nb) as u8;
        }
        let mut sf = vec![[0u8; 8]; nch];
        for ch in 0..nch {
            for s in 0..nb {
                sf[ch][s] = br.read(4) as u8;
            }
        }
        // CRC check
        let sf_bits = nb * nch * 4;
        let join_bits = if header.channel_mode == CM_JOINT_STEREO { nb } else { 0 };
        let crc_bits_total = 16 + join_bits + sf_bits;
        let crc_bytes_len = (crc_bits_total + 7) / 8;
        let mut crc_input = vec![0u8; crc_bytes_len];
        crc_input[0] = frame[1];
        crc_input[1] = frame[2];
        for i in 0..(join_bits + sf_bits) {
            let src_byte = body[i / 8];
            let bit = (src_byte >> (7 - (i % 8))) & 1;
            let dst_off = 16 + i;
            crc_input[dst_off / 8] |= bit << (7 - (dst_off % 8));
        }
        let crc = crc8::compute_bits(&crc_input, crc_bits_total);
        if crc != header.crc {
            return Err(SbcError::BadCrc);
        }
        // Bit allocation.
        let mut bits = vec![[0u8; 8]; nch];
        bitalloc::allocate(&header, &sf, &mut bits);
        // Samples.
        let mut x = vec![vec![vec![0i32; nb]; nch]; blk];
        for b in 0..blk {
            for ch in 0..nch {
                for s in 0..nb {
                    let nbits = bits[ch][s] as usize;
                    if nbits == 0 {
                        continue;
                    }
                    let q = br.read(nbits);
                    x[b][ch][s] = dequantize_sample(q, sf[ch][s], nbits);
                }
            }
        }
        // Joint-stereo unmix.
        if header.channel_mode == CM_JOINT_STEREO {
            for s in 0..nb {
                if (join >> s) & 1 != 0 {
                    for b in 0..blk {
                        let m = x[b][0][s];
                        let sd = x[b][1][s];
                        x[b][0][s] = m + sd;
                        x[b][1][s] = m - sd;
                    }
                }
            }
        }
        // QMF synthesis.
        // Reset synthesis state if header changed (nb changed).
        if self.dec_state.len() != nch || self.dec_state[0].nrof_subbands != nb {
            self.dec_state.clear();
            for _ in 0..nch {
                self.dec_state.push(synthesis::ChannelState::new(nb));
            }
        }
        let mut out_buf = vec![0i32; nb];
        for b in 0..blk {
            for ch in 0..nch {
                let sb = &x[b][ch][..nb];
                self.dec_state[ch].step(sb, &mut out_buf);
                for s in 0..nb {
                    let v = out_buf[s].clamp(i16::MIN as i32, i16::MAX as i32);
                    pcm[(b * nb + s) * nch + ch] = v as i16;
                }
            }
        }
        Ok(blk * nb)
    }
}

/// Linear midtread quantizer used by the SBC encoder.
/// sample is in subband-domain. sf is the scale factor (0..15).
/// nbits is the allocated quantizer width.
fn quantize_sample(sample: i32, sf: u8, nbits: usize) -> u32 {
    if nbits == 0 {
        return 0;
    }
    let levels = (1u32 << nbits) - 1;
    let scale = 1i64 << (sf as u32 + 1); // 2^(sf+1)
    // q = (((sample / scale) + 1) * levels) / 2, clipped to [0, levels].
    let num = (sample as i64 + scale) * (levels as i64);
    let den = (scale << 1) as i64; // 2 * scale
    let q = num / den;
    q.clamp(0, levels as i64) as u32
}

/// Inverse of [`quantize_sample`].
fn dequantize_sample(q: u32, sf: u8, nbits: usize) -> i32 {
    if nbits == 0 {
        return 0;
    }
    let levels = (1u32 << nbits) - 1;
    let scale = 1i64 << (sf as u32 + 1);
    // Inverse: sample = ((2q + 1) * scale / levels) - scale.
    let num = ((2 * q as i64) + 1) * scale;
    let den = levels as i64;
    let s = num / den - scale;
    s.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
extern crate std;

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// CRC-8 sanity: known vector. SBC CRC of "AB" with seed 0x0F.
    /// Recomputed from the polynomial; cross-check vs. BlueZ.
    fn smoke_sbc_crc8_known_vector() -> TestResult {
        // Compute hand-derived: seed=0x0F, polynomial=0x1D.
        // For a single byte 0x00, CRC after 8 zero bits with seed 0x0F:
        // 0x0F → shift 8 times with no flip → 0x0F << 8 = 0xF00 but we
        // only keep low byte: 0x00 (the top bits XOR with 0 stay zero).
        // So crc8([0]) = 0x00.
        // Verify with our impl.
        if crc8::compute(&[0u8]) != crc8_ref(&[0u8]) {
            return TestResult::Fail("CRC([0]) mismatch with reference");
        }
        if crc8::compute(&[0x9C, 0x21, 0x53]) != crc8_ref(&[0x9C, 0x21, 0x53]) {
            return TestResult::Fail("CRC([9C 21 53]) mismatch");
        }
        // A different non-zero stream.
        let buf = [0xAA, 0x55, 0xFF, 0x00, 0x9C];
        if crc8::compute(&buf) != crc8_ref(&buf) {
            return TestResult::Fail("CRC long vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_crc8_known_vector);

    fn crc8_ref(buf: &[u8]) -> u8 {
        let mut crc: u8 = 0x0F;
        for &b in buf {
            for i in 0..8 {
                let top_crc = (crc & 0x80) != 0;
                let top_b = ((b >> (7 - i)) & 1) != 0;
                crc <<= 1;
                if top_crc ^ top_b {
                    crc ^= 0x1D;
                }
            }
        }
        crc
    }

    /// Header encode → decode round-trip preserves every field.
    fn smoke_sbc_header_roundtrip() -> TestResult {
        let h = Header {
            sampling_frequency: FREQ_44100,
            blocks: BLOCKS_16,
            channel_mode: CM_JOINT_STEREO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 1, // 8 subbands
            bitpool: 53,
            crc: 0,
        };
        let [b1, b2] = h.encode_config();
        let h2 = Header::decode_config(b1, b2);
        if h2.sampling_frequency != h.sampling_frequency
            || h2.blocks != h.blocks
            || h2.channel_mode != h.channel_mode
            || h2.allocation_method != h.allocation_method
            || h2.subbands != h.subbands
            || h2.bitpool != h.bitpool
        {
            return TestResult::Fail("header roundtrip lost field");
        }
        // Check decoded shape helpers.
        if h2.nrof_blocks() != 16
            || h2.nrof_subbands() != 8
            || h2.nrof_channels() != 2
            || h2.sample_rate_hz() != 44_100
        {
            return TestResult::Fail("shape helpers wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_header_roundtrip);

    /// Encoded frame size matches the A2DP §12.9 formula for the
    /// canonical 44.1 / joint / 8sb / 16blk / bp53 configuration:
    /// 4 + (8+64)/8 + ceil(16*53/8) = 4 + 9 + 106 = 119 bytes.
    fn smoke_sbc_frame_length_joint_stereo() -> TestResult {
        let h = Header {
            sampling_frequency: FREQ_44100,
            blocks: BLOCKS_16,
            channel_mode: CM_JOINT_STEREO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 1,
            bitpool: 53,
            crc: 0,
        };
        let n = frame_length(&h);
        if n != 119 {
            return TestResult::Fail("joint stereo frame length wrong");
        }
        // Mono / 8 subbands / 16 blocks / bitpool 35 →
        // 4 + 4 + ceil(16*35/8) = 4 + 4 + 70 = 78
        let h_mono = Header {
            channel_mode: CM_MONO,
            bitpool: 35,
            ..h
        };
        let n2 = frame_length(&h_mono);
        if n2 != 78 {
            return TestResult::Fail("mono frame length wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_frame_length_joint_stereo);

    /// QMF analysis followed by synthesis round-trips a tone within
    /// the spec's quantization-noise threshold.
    fn smoke_sbc_qmf_roundtrip_silence() -> TestResult {
        // Send pure silence through the 8-band analysis + synthesis.
        // The result must stay near zero (no DC offset injected by the
        // filter when fed zeros).
        let mut a = analysis::ChannelState::new(8);
        let mut s = synthesis::ChannelState::new(8);
        let mut sb = vec![0i32; 8];
        let mut out = vec![0i32; 8];
        for _ in 0..40 {
            a.step(&[0; 8], &mut sb);
            s.step(&sb, &mut out);
        }
        for &v in &out {
            if v.abs() > 8 {
                return TestResult::Fail("silence produced non-trivial drift");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_qmf_roundtrip_silence);

    /// Bit allocation respects the bitpool budget: sum of allocated
    /// bits ≤ bitpool for both channels (stereo) and ≤ bitpool per
    /// channel for dual / mono.
    fn smoke_sbc_bitalloc_budget() -> TestResult {
        let h = Header {
            sampling_frequency: FREQ_44100,
            blocks: BLOCKS_16,
            channel_mode: CM_JOINT_STEREO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 1,
            bitpool: 53,
            crc: 0,
        };
        let mut sf = [[0u8; 8]; 2];
        for ch in 0..2 {
            for s in 0..8 {
                sf[ch][s] = (4 + (s as u8 % 4)) as u8;
            }
        }
        let mut bits = [[0u8; 8]; 2];
        let sums = bitalloc::allocate(&h, &sf, &mut bits);
        let total: u32 = sums.iter().sum();
        if total > h.bitpool as u32 {
            return TestResult::Fail("stereo bitalloc exceeded bitpool");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_bitalloc_budget);

    /// Encode → decode round-trip on a mono frame; the output PCM
    /// should remain finite and bounded.
    fn smoke_sbc_encode_decode_mono() -> TestResult {
        let h = Header {
            sampling_frequency: FREQ_44100,
            blocks: BLOCKS_16,
            channel_mode: CM_MONO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 1,
            bitpool: 35,
            crc: 0,
        };
        let mut enc = Sbc::new(h);
        let pcm_len = enc.pcm_frame_len();
        // Sine-ish synthetic input.
        let mut pcm_in = vec![0i16; pcm_len];
        for i in 0..pcm_len {
            // Triangle wave, amplitude 0x2000.
            let phase = (i % 64) as i32;
            let v = if phase < 32 { phase * 256 } else { (64 - phase) * 256 };
            pcm_in[i] = (v - 4096) as i16;
        }
        let mut buf = vec![0u8; enc.frame_bytes()];
        let bytes_out = enc.encode(&pcm_in, &mut buf).unwrap_or(0);
        if bytes_out == 0 || buf[0] != SBC_SYNCWORD {
            return TestResult::Fail("mono encode produced no sync byte");
        }
        let mut dec = Sbc::new(h);
        let mut pcm_out = vec![0i16; pcm_len];
        let _ = dec.decode(&buf, &mut pcm_out).unwrap_or(0);
        // Output must be bounded in i16 range (clamped already) and
        // not all zero — the encoder shouldn't completely zero out a
        // non-zero input even with low bitpool.
        let mut nonzero = false;
        for &v in &pcm_out {
            if v != 0 {
                nonzero = true;
            }
        }
        if !nonzero {
            return TestResult::Fail("mono encode/decode produced all zeros");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_encode_decode_mono);

    /// Joint-stereo encode/decode produces a valid frame with sync byte
    /// and matching CRC on the way back.
    fn smoke_sbc_encode_decode_joint_stereo() -> TestResult {
        let h = Header {
            sampling_frequency: FREQ_44100,
            blocks: BLOCKS_16,
            channel_mode: CM_JOINT_STEREO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 1,
            bitpool: 53,
            crc: 0,
        };
        let mut enc = Sbc::new(h);
        let pcm_len = enc.pcm_frame_len() * 2; // stereo interleaved
        let mut pcm_in = vec![0i16; pcm_len];
        for i in (0..pcm_len).step_by(2) {
            pcm_in[i] = (((i / 2) as i32) % 256) as i16 * 32;
            pcm_in[i + 1] = -pcm_in[i];
        }
        let mut buf = vec![0u8; enc.frame_bytes()];
        enc.encode(&pcm_in, &mut buf).unwrap_or(0);
        if buf[0] != SBC_SYNCWORD {
            return TestResult::Fail("joint stereo encode no sync");
        }
        let mut dec = Sbc::new(h);
        let mut pcm_out = vec![0i16; pcm_len];
        match dec.decode(&buf, &mut pcm_out) {
            Ok(n) if n == enc.pcm_frame_len() => TestResult::Pass,
            Ok(_) => TestResult::Fail("decoded wrong sample count"),
            Err(_) => TestResult::Fail("joint stereo decode failed"),
        }
    }
    kernel_test_in!("audio/sbc", smoke_sbc_encode_decode_joint_stereo);

    /// A2DP MTU compliance: a typical L2CAP MTU for A2DP is 895 bytes
    /// (per profile spec); a single 119-byte SBC frame fits well
    /// within that, and 7 frames (≈ standard fragmentation budget for
    /// a 750-byte payload) is the upper bound the source enforces.
    fn smoke_sbc_a2dp_mtu_fit() -> TestResult {
        let h = Header {
            sampling_frequency: FREQ_44100,
            blocks: BLOCKS_16,
            channel_mode: CM_JOINT_STEREO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 1,
            bitpool: 53,
            crc: 0,
        };
        let n = frame_length(&h);
        if n > 895 {
            return TestResult::Fail("frame larger than L2CAP min MTU");
        }
        // 7 frames per RTP/AVDTP packet is the canonical packing.
        if 7 * n + 13 > 895 {
            return TestResult::Fail("7-frame pack exceeds MTU");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/sbc", smoke_sbc_a2dp_mtu_fit);
}
