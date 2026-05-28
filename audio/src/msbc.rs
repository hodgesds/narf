//! mSBC — Modified SBC codec for Bluetooth HFP Wideband Audio.
//!
//! mSBC is the fixed-parameter variant of SBC mandated by HFP 1.6+
//! (§11.1) for wide-band speech (16 kHz, mono). All codec parameters
//! are locked; there is no negotiation of subbands, blocks, bitpool, or
//! allocation method. The mSBC frame fits inside a single eSCO/SCO
//! packet (60-byte HCI SCO payload, of which 57 bytes carry the mSBC
//! frame).
//!
//! ## Fixed parameters (HFP 1.8 §11.1 / Bluetooth SIG SBC PDF)
//!
//! | Parameter          | Value    |
//! |--------------------|----------|
//! | Sampling rate      | 16 kHz   |
//! | Channel mode       | Mono     |
//! | Subbands           | 4        |
//! | Blocks             | 15       |
//! | Bitpool            | 26       |
//! | Allocation method  | Loudness |
//!
//! ## Frame layout (57 bytes per SCO packet)
//!
//! ```text
//!  byte  0     sync byte   0xAD
//!  byte  1     sequence byte (rotates: 0x08, 0x38, 0xC8, 0xF8)
//!  byte  2     SBC header byte 1 (fixed: FREQ_16000|BLOCKS_15|CM_MONO|ALLOC_LOUDNESS|4sb)
//!  byte  3     bitpool = 26
//!  byte  4     CRC-8 over byte 2, byte 3, and scale-factor nibbles
//!  bytes 5..56 scale factors + packed audio samples (53 bytes)
//! ```
//!
//! Note: "BLOCKS_15" is not a standard SBC block count; the 2-bit
//! field encodes up to 16 blocks (0b11 = 16). mSBC uses 15 blocks, so
//! the SBC `blocks` field would need to encode 15. However, per the
//! HFP spec, the mSBC SBC header is treated as a fixed opaque blob
//! whose `blocks` field is 0b11 (= BLOCKS_16 in SBC notation) but the
//! actual frame carries only 15 blocks of audio. This is a deliberate
//! spec anomaly; we follow BlueZ's interpretation: encode/decode 15
//! blocks of audio despite the header field reading as 16.
//!
//! ## References
//!
//! - **HFP 1.8 §11.1** — mSBC codec definition, frame layout, sequence byte.
//! - **Bluetooth SIG SBC PDF §B.3** — mSBC fixed parameters.
//! - **BlueZ `sbc/sbc.c`** (GPL-2.0-or-later, NARF relicense 2026-05-20) —
//!   reference implementation of mSBC encode/decode.

extern crate alloc;

use alloc::vec;

use crate::sbc::{
    analysis, bitalloc, crc8, synthesis, BitReader, BitWriter, Header,
    ALLOC_LOUDNESS, BLOCKS_16, CM_MONO, FREQ_16000,
};

// ── mSBC constants ────────────────────────────────────────────────────

/// mSBC sync byte (HFP 1.8 §11.1).  First byte of every 57-byte frame.
pub const MSBC_SYNC: u8 = 0xAD;

/// mSBC frame total size in bytes (HFP 1.8 §11.1).
pub const MSBC_FRAME_BYTES: usize = 57;

/// mSBC PCM samples per frame: 15 blocks × 4 subbands = 60.
pub const MSBC_PCM_SAMPLES: usize = 60;

/// Fixed bitpool for mSBC (HFP 1.8 §11.1).
pub const MSBC_BITPOOL: u8 = 26;

/// Fixed number of subbands for mSBC.
pub const MSBC_SUBBANDS: usize = 4;

/// Fixed number of blocks for mSBC audio (15; see module-level note).
pub const MSBC_BLOCKS: usize = 15;

/// Sequence bytes in order (HFP 1.8 §11.1 table 5.8).
/// Byte 1 of the mSBC frame rotates through these four values.
pub const MSBC_SEQ_BYTES: [u8; 4] = [0x08, 0x38, 0xC8, 0xF8];

/// SBC header byte 1 (config byte) for mSBC.
///
/// FREQ_16000 (0b00) << 6 | BLOCKS_16 (0b11) << 4 | CM_MONO (0b00) << 2
/// | ALLOC_LOUDNESS (0b0) << 1 | 4sb (0b0) = 0x30.
///
/// The `blocks` field is 0b11 (BLOCKS_16) as specified in the mSBC
/// header — the actual audio uses 15 blocks (see module doc).
pub const MSBC_SBC_CFG1: u8 = (FREQ_16000 << 6) | (BLOCKS_16 << 4) | (CM_MONO << 2)
    | (ALLOC_LOUDNESS << 1)
    | 0; // subbands=0 → 4 subbands

/// SBC header byte 2 (bitpool) for mSBC.
pub const MSBC_SBC_CFG2: u8 = MSBC_BITPOOL;

// ── Error type ────────────────────────────────────────────────────────

/// Errors from the mSBC encoder / decoder.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsbcError {
    /// Output buffer is too small for the encoded frame (need
    /// [`MSBC_FRAME_BYTES`] = 57 bytes).
    OutputTooSmall,
    /// Input PCM length is not [`MSBC_PCM_SAMPLES`] = 60 samples.
    BadInputLength,
    /// Frame sync byte (byte 0) is not 0xAD.
    BadSync,
    /// SBC CRC mismatch (bytes 4 covers config + scale-factor nibbles).
    BadCrc,
    /// Input slice shorter than 57 bytes.
    Short,
}

// ── Sequence counter ──────────────────────────────────────────────────

/// Rolling mSBC sequence counter.  Wraps at 4 per HFP 1.8 §11.1.
#[derive(Clone, Debug)]
pub struct SeqCounter {
    idx: usize,
}

impl SeqCounter {
    /// Create a new counter starting at index 0 (first seq byte = 0x08).
    pub fn new() -> Self {
        Self { idx: 0 }
    }

    /// Return the current sequence byte and advance to the next.
    pub fn next(&mut self) -> u8 {
        let b = MSBC_SEQ_BYTES[self.idx];
        self.idx = (self.idx + 1) % 4;
        b
    }

    /// Current sequence index (0..4).
    pub fn index(&self) -> usize {
        self.idx
    }
}

impl Default for SeqCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ── mSBC encoder/decoder ──────────────────────────────────────────────

/// mSBC encoder/decoder state.  Owns QMF filter history for one
/// mono channel and a sequence counter.
///
/// Parameters are fully fixed (see module doc); no configuration is
/// needed beyond constructing this struct.
#[derive(Debug)]
pub struct Msbc {
    enc_state: analysis::ChannelState,
    dec_state: synthesis::ChannelState,
    seq: SeqCounter,
}

impl Msbc {
    /// Build the fixed mSBC [`Header`] used by the SBC engine internals.
    ///
    /// The `blocks` field is 0b11 (BLOCKS_16) so `Header::nrof_blocks()`
    /// returns 16; we drive the codec engine with 15 actual blocks by
    /// overriding the loop count directly in encode/decode.
    fn header() -> Header {
        Header {
            sampling_frequency: FREQ_16000,
            blocks: BLOCKS_16,   // wire value = 0b11; actual blocks = 15
            channel_mode: CM_MONO,
            allocation_method: ALLOC_LOUDNESS,
            subbands: 0, // 0 → 4 subbands
            bitpool: MSBC_BITPOOL,
            crc: 0,
        }
    }

    /// Construct a new mSBC codec instance with zeroed filter state.
    pub fn new() -> Self {
        Self {
            enc_state: analysis::ChannelState::new(MSBC_SUBBANDS),
            dec_state: synthesis::ChannelState::new(MSBC_SUBBANDS),
            seq: SeqCounter::new(),
        }
    }

    /// Encode one mSBC frame.
    ///
    /// - `pcm`: exactly [`MSBC_PCM_SAMPLES`] (60) mono i16 samples at 16 kHz.
    /// - `out`: output buffer; must be at least [`MSBC_FRAME_BYTES`] (57) bytes.
    ///
    /// Returns the number of bytes written (always 57 on success).
    ///
    /// ## Frame layout written
    ///
    /// ```text
    /// [0]     0xAD  (MSBC_SYNC)
    /// [1]     sequence byte  (advances SeqCounter)
    /// [2]     0x30  (MSBC_SBC_CFG1: FREQ_16K|BLK_16|MONO|LOUDNESS|4sb)
    /// [3]     0x1A  (MSBC_SBC_CFG2: bitpool = 26)
    /// [4]     CRC-8 over bytes [2],[3] + scale-factor nibbles
    /// [5..57] packed scale-factors + subband audio samples (52 bytes)
    /// ```
    pub fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, MsbcError> {
        if pcm.len() != MSBC_PCM_SAMPLES {
            return Err(MsbcError::BadInputLength);
        }
        if out.len() < MSBC_FRAME_BYTES {
            return Err(MsbcError::OutputTooSmall);
        }

        // Zero the output frame.
        for b in out[..MSBC_FRAME_BYTES].iter_mut() {
            *b = 0;
        }

        // Bytes 0..2: sync + sequence + SBC config.
        out[0] = MSBC_SYNC;
        out[1] = self.seq.next();
        out[2] = MSBC_SBC_CFG1;
        out[3] = MSBC_SBC_CFG2;
        // byte[4] = CRC — filled below.

        // Run QMF analysis: 15 blocks × 4 subbands → x[blk][sb].
        let mut x = [[0i32; 4]; MSBC_BLOCKS];
        let mut input_buf = [0i32; MSBC_SUBBANDS];
        let mut out_sb = [0i32; MSBC_SUBBANDS];
        for b in 0..MSBC_BLOCKS {
            for s in 0..MSBC_SUBBANDS {
                input_buf[s] = pcm[b * MSBC_SUBBANDS + s] as i32;
            }
            self.enc_state.step(&input_buf, &mut out_sb);
            x[b] = out_sb;
        }

        // Compute per-subband scale factors (4-bit each, 0..15).
        let mut sf = [0u8; 8]; // indexed 0..4; rest unused
        for s in 0..MSBC_SUBBANDS {
            let mut max = 0u32;
            for b in 0..MSBC_BLOCKS {
                let v = x[b][s].unsigned_abs();
                if v > max {
                    max = v;
                }
            }
            let mut sfac: u8 = 0;
            let mut shift = 1u32;
            while shift <= max && sfac < 15 {
                shift <<= 1;
                sfac += 1;
            }
            sf[s] = sfac;
        }

        // Bit allocation (reuse SBC bitalloc; pass a 1-channel sf table).
        let h = Self::header();
        let sf_table = [sf; 2]; // bitalloc expects [[u8;8]; nch] but we only read [0]
        let mut bits_table = [[0u8; 8]; 2];
        bitalloc::allocate(&h, &sf_table, &mut bits_table);
        let bits = bits_table[0];

        // Build the body (bytes 5..57 = 52 bytes).
        // Body layout: 4 scale-factor nibbles (2 bytes) + packed samples.
        let body_len = MSBC_FRAME_BYTES - 5; // 52 bytes
        let mut body = vec![0u8; body_len];
        {
            let mut bw = BitWriter::new(&mut body);
            // Scale factors: 4 × 4 bits = 16 bits = 2 bytes.
            for s in 0..MSBC_SUBBANDS {
                bw.write(4, sf[s] as u32);
            }
            // Packed subband samples: 15 blocks × (bits per subband).
            for b in 0..MSBC_BLOCKS {
                for s in 0..MSBC_SUBBANDS {
                    let nb = bits[s] as usize;
                    if nb == 0 {
                        continue;
                    }
                    let q = quantize_sample(x[b][s], sf[s], nb);
                    bw.write(nb, q);
                }
            }
            bw.pad_to_byte();
        }

        // CRC-8 over: cfg1, cfg2, scale-factor nibbles (4×4 = 16 bits).
        // Total CRC input: 16 (config) + 16 (sf) = 32 bits = 4 bytes.
        let crc_bits = 32usize;
        let mut crc_input = [0u8; 4];
        crc_input[0] = MSBC_SBC_CFG1;
        crc_input[1] = MSBC_SBC_CFG2;
        // Copy scale-factor nibbles from body[0..2] into crc_input[2..4].
        crc_input[2] = body[0];
        crc_input[3] = body[1];
        out[4] = crc8::compute_bits(&crc_input, crc_bits);

        // Copy body into out[5..57].
        out[5..MSBC_FRAME_BYTES].copy_from_slice(&body);

        Ok(MSBC_FRAME_BYTES)
    }

    /// Decode one mSBC frame.
    ///
    /// - `frame`: exactly [`MSBC_FRAME_BYTES`] (57) bytes or more;
    ///   only the first 57 bytes are consumed.
    /// - `pcm`: output buffer; must hold at least [`MSBC_PCM_SAMPLES`] (60)
    ///   i16 samples.
    ///
    /// Returns the number of PCM samples written (always 60 on success).
    pub fn decode(&mut self, frame: &[u8], pcm: &mut [i16]) -> Result<usize, MsbcError> {
        if frame.len() < MSBC_FRAME_BYTES {
            return Err(MsbcError::Short);
        }
        if frame[0] != MSBC_SYNC {
            return Err(MsbcError::BadSync);
        }
        if pcm.len() < MSBC_PCM_SAMPLES {
            return Err(MsbcError::OutputTooSmall);
        }

        // Byte 1: sequence byte (0x08/0x38/0xC8/0xF8) — accept any valid
        // rotation; we don't enforce ordering to tolerate first-frame start.
        // Bytes 2-3: SBC config (fixed; we validate via CRC).
        let body = &frame[5..MSBC_FRAME_BYTES]; // 52 bytes

        // CRC check: re-derive over cfg1, cfg2, body[0..2] (sf nibbles).
        let mut crc_input = [0u8; 4];
        crc_input[0] = frame[2];
        crc_input[1] = frame[3];
        crc_input[2] = body[0];
        crc_input[3] = body[1];
        let expected_crc = crc8::compute_bits(&crc_input, 32);
        if expected_crc != frame[4] {
            return Err(MsbcError::BadCrc);
        }

        // Read scale factors from body[0..2] (4 × 4-bit nibbles).
        let mut sf = [0u8; 8];
        {
            let mut br = BitReader::new(body);
            for s in 0..MSBC_SUBBANDS {
                sf[s] = br.read(4) as u8;
            }

            // Bit allocation.
            let h = Self::header();
            let sf_table = [sf; 2];
            let mut bits_table = [[0u8; 8]; 2];
            bitalloc::allocate(&h, &sf_table, &mut bits_table);
            let bits = bits_table[0];

            // Decode subband samples.
            let mut x = [[0i32; 4]; MSBC_BLOCKS];
            for b in 0..MSBC_BLOCKS {
                for s in 0..MSBC_SUBBANDS {
                    let nb = bits[s] as usize;
                    if nb == 0 {
                        continue;
                    }
                    let q = br.read(nb);
                    x[b][s] = dequantize_sample(q, sf[s], nb);
                }
            }

            // QMF synthesis: 15 blocks → 60 PCM samples.
            let mut out_buf = [0i32; MSBC_SUBBANDS];
            for b in 0..MSBC_BLOCKS {
                self.dec_state.step(&x[b], &mut out_buf);
                for s in 0..MSBC_SUBBANDS {
                    let v = out_buf[s].clamp(i16::MIN as i32, i16::MAX as i32);
                    pcm[b * MSBC_SUBBANDS + s] = v as i16;
                }
            }
        }

        Ok(MSBC_PCM_SAMPLES)
    }
}

impl Default for Msbc {
    fn default() -> Self {
        Self::new()
    }
}

// ── Quantization helpers (mirrored from sbc.rs private fns) ──────────

/// Linear midtread quantizer.  Mirrors `sbc::quantize_sample`.
fn quantize_sample(sample: i32, sf: u8, nbits: usize) -> u32 {
    if nbits == 0 {
        return 0;
    }
    let levels = (1u32 << nbits) - 1;
    let scale = 1i64 << (sf as u32 + 1);
    let num = (sample as i64 + scale) * (levels as i64);
    let den = (scale << 1) as i64;
    let q = num / den;
    q.clamp(0, levels as i64) as u32
}

/// Inverse quantizer.  Mirrors `sbc::dequantize_sample`.
fn dequantize_sample(q: u32, sf: u8, nbits: usize) -> i32 {
    if nbits == 0 {
        return 0;
    }
    let levels = (1u32 << nbits) - 1;
    let scale = 1i64 << (sf as u32 + 1);
    let num = ((2 * q as i64) + 1) * scale;
    let den = levels as i64;
    let s = num / den - scale;
    s.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
extern crate std;

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// mSBC sync byte and sequence rotation: first four frames must
    /// emit byte[0] = 0xAD and byte[1] cycling through 0x08, 0x38,
    /// 0xC8, 0xF8 (HFP 1.8 §11.1 table 5.8).
    fn smoke_msbc_sync_and_seq_rotation() -> TestResult {
        let mut codec = Msbc::new();
        let pcm = [0i16; MSBC_PCM_SAMPLES];
        let mut frame = [0u8; MSBC_FRAME_BYTES];

        for (i, &expected_seq) in MSBC_SEQ_BYTES.iter().enumerate() {
            let _ = codec.encode(&pcm, &mut frame).unwrap_or(0);
            if frame[0] != MSBC_SYNC {
                return TestResult::Fail("sync byte != 0xAD");
            }
            if frame[1] != expected_seq {
                return TestResult::Fail("sequence byte rotation mismatch");
            }
            let _ = i; // suppress unused warning
        }
        // 5th frame wraps back to seq[0] = 0x08.
        let _ = codec.encode(&pcm, &mut frame).unwrap_or(0);
        if frame[1] != MSBC_SEQ_BYTES[0] {
            return TestResult::Fail("seq did not wrap after 4 frames");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/msbc", smoke_msbc_sync_and_seq_rotation);

    /// mSBC header layout: byte[2] must be the fixed SBC config byte
    /// (0x30) and byte[3] must be the bitpool (0x1A = 26).
    fn smoke_msbc_header_layout() -> TestResult {
        let mut codec = Msbc::new();
        let pcm = [0i16; MSBC_PCM_SAMPLES];
        let mut frame = [0u8; MSBC_FRAME_BYTES];
        let _ = codec.encode(&pcm, &mut frame).unwrap_or(0);

        // MSBC_SBC_CFG1 = FREQ_16000 (0) << 6 | BLOCKS_16 (3) << 4 |
        //                  CM_MONO (0) << 2 | ALLOC_LOUDNESS (0) << 1 |
        //                  4sb (0) = 0x30.
        if frame[2] != MSBC_SBC_CFG1 {
            return TestResult::Fail("SBC config byte (byte 2) wrong");
        }
        if frame[3] != MSBC_BITPOOL {
            return TestResult::Fail("bitpool byte (byte 3) != 26");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/msbc", smoke_msbc_header_layout);

    /// Frame size must be exactly 57 bytes (HFP 1.8 §11.1).
    fn smoke_msbc_frame_size() -> TestResult {
        let mut codec = Msbc::new();
        let pcm = [0i16; MSBC_PCM_SAMPLES];
        let mut frame = [0u8; MSBC_FRAME_BYTES];
        let n = match codec.encode(&pcm, &mut frame) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("encode returned error"),
        };
        if n != MSBC_FRAME_BYTES {
            return TestResult::Fail("encoded frame != 57 bytes");
        }
        if MSBC_FRAME_BYTES != 57 {
            return TestResult::Fail("MSBC_FRAME_BYTES constant != 57");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/msbc", smoke_msbc_frame_size);

    /// Encode → decode round-trip on a non-trivial PCM frame.
    ///
    /// Feeds a triangle wave (amplitude 0x1000, 16 kHz mono) through
    /// the encoder and verifies the decoder produces non-zero output.
    fn smoke_msbc_encode_decode_roundtrip() -> TestResult {
        let mut enc = Msbc::new();
        let mut dec = Msbc::new();

        // Build a triangle wave: 60 samples, amplitude ±4096.
        let mut pcm_in = [0i16; MSBC_PCM_SAMPLES];
        for i in 0..MSBC_PCM_SAMPLES {
            let phase = (i % 32) as i32;
            let v = if phase < 16 { phase * 256 } else { (32 - phase) * 256 };
            pcm_in[i] = (v - 2048) as i16;
        }

        let mut frame = [0u8; MSBC_FRAME_BYTES];
        match enc.encode(&pcm_in, &mut frame) {
            Ok(n) if n == MSBC_FRAME_BYTES => {}
            Ok(_) => return TestResult::Fail("encode returned wrong byte count"),
            Err(_) => return TestResult::Fail("encode failed"),
        }

        // Sync byte must be present.
        if frame[0] != MSBC_SYNC {
            return TestResult::Fail("encoded frame missing sync byte");
        }

        let mut pcm_out = [0i16; MSBC_PCM_SAMPLES];
        match dec.decode(&frame, &mut pcm_out) {
            Ok(n) if n == MSBC_PCM_SAMPLES => {}
            Ok(_) => return TestResult::Fail("decode returned wrong sample count"),
            Err(e) => {
                // Map error to static str for TestResult.
                let msg: &'static str = match e {
                    MsbcError::BadCrc => "decode: CRC mismatch",
                    MsbcError::BadSync => "decode: bad sync",
                    MsbcError::Short => "decode: short frame",
                    MsbcError::BadInputLength => "decode: bad input length",
                    MsbcError::OutputTooSmall => "decode: output too small",
                };
                return TestResult::Fail(msg);
            }
        }

        // Output must not be all-zero for a non-trivial input.
        let any_nonzero = pcm_out.iter().any(|&v| v != 0);
        if !any_nonzero {
            return TestResult::Fail("decoded PCM is all zeros");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/msbc", smoke_msbc_encode_decode_roundtrip);
}
