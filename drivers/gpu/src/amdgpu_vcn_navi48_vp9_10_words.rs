// SPDX-License-Identifier: MIT
// VP9 probability data: Copyright 2018 Advanced Micro Devices, Inc.
// Original permissive notice retained in ../VCN-NOTICES.
//! Original fixed Profile2 keyframe; Mesa VCN5 tier3/unified-DT descriptor.
use super::{hevc10_words, vp9_words, Error};
pub(super) const STREAM: &[u8] = &[
    0x93, 0x49, 0x83, 0x42, 0x00, 0x03, 0xf8, 0x03, 0xf8, 0x00, 0x70, 0x48, 0x38, 0x30, 0x00, 0x00,
    0x01, 0x40, 0x7d, 0x8f, 0xf8, 0xec, 0xa9, 0x1d, 0x07, 0x5e, 0xd0, 0x00, 0x78, 0xb7, 0xf9, 0xb6,
    0x9f, 0x84, 0xfe, 0x2a, 0x50, 0x9f, 0xd5, 0x55, 0xf9, 0x87, 0x5e, 0x0c, 0xa7, 0x13, 0x50, 0x99,
    0x70, 0x2f, 0x2d, 0xd7, 0xe3, 0xff, 0x13, 0x50, 0x80, 0x16, 0xaf, 0xc9, 0x02, 0x66, 0x00, 0x0c,
    0x80, 0xef, 0x78, 0x30, 0x00,
];
pub(super) const DEFAULT_PROBS: &[u8] = vp9_words::DEFAULT_PROBS;
pub(super) const TARGET_BYTES: u64 = 128 * 128 * 3;
pub(super) const CONTEXT_BYTES: u64 =
    2304 * 5 + 32 * 2 * 128 * 68 + 9 * 64 * 2 * 128 * 68 + 8 * 2 * 2 * 8192 + 8 * 2 * 4096;
pub(super) const GUARD: u32 = 0x75b18a43;
pub(super) const HANDLE: u32 = 0x4e415204;
const fn page(n: u64) -> u64 {
    (n + 4095) & !4095
}
pub(super) const SESSION: u64 = 4096;
pub(super) const CONTEXT: u64 = SESSION + (128 << 10);
pub(super) const SESSION_END_GUARD: u64 = CONTEXT + page(CONTEXT_BYTES);
pub(super) const CREATE_MSG: u64 = SESSION_END_GUARD + 4096;
pub(super) const DECODE_MSG: u64 = CREATE_MSG + 4096;
pub(super) const DESTROY_MSG: u64 = DECODE_MSG + 4096;
pub(super) const FEEDBACK: u64 = DESTROY_MSG + 4096;
pub(super) const PROBS: u64 = FEEDBACK + 4096;
pub(super) const BITSTREAM: u64 = PROBS + 4096;
pub(super) const TARGET_GUARD: u64 = BITSTREAM + 4096;
pub(super) const TARGET: u64 = TARGET_GUARD + 4096;
pub(super) const TARGET_END_GUARD: u64 = TARGET + TARGET_BYTES;
pub(super) const CREATE_IB: u64 = TARGET_END_GUARD + 4096;
pub(super) const DECODE_IB: u64 = CREATE_IB + 4096;
pub(super) const DESTROY_IB: u64 = DECODE_IB + 4096;
pub(super) const END_GUARD: u64 = DESTROY_IB + 4096;
pub(super) const BYTES: u64 = END_GUARD + 4096;
pub(super) const GUARDS: [u64; 5] = [
    0,
    SESSION_END_GUARD,
    TARGET_GUARD,
    TARGET_END_GUARD,
    END_GUARD,
];
pub(super) const fn expected(at: u64) -> u8 {
    hevc10_words::expected(at)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Create,
    Decode,
    Destroy,
}
fn put(out: &mut [u8], at: usize, word: u32) {
    out[at..at + 4].copy_from_slice(&word.to_le_bytes());
}
pub(super) fn create_message() -> [u8; 56] {
    let mut out = [0; 56];
    for (i, w) in [40, 56, 1, 0, HANDLE, 0, 1, 40, 16, 0, 17, 0, 128, 128]
        .into_iter()
        .enumerate()
    {
        put(&mut out, i * 4, w);
    }
    out
}
pub(super) fn destroy_message() -> [u8; 24] {
    let mut out = [0; 24];
    for (i, w) in [40, 24, 0, 2, HANDLE, 0].into_iter().enumerate() {
        put(&mut out, i * 4, w);
    }
    out
}
pub(super) fn decode_message() -> [u8; 364] {
    let mut out = [0; 364];
    for (i, w) in [40, 364, 2, 1, HANDLE, 0, 2, 56, 188, 0, 14, 244, 120, 0]
        .into_iter()
        .enumerate()
    {
        put(&mut out, i * 4, w);
    }
    let mut dec = [0u32; 47];
    dec[0] = 17;
    dec[1] = 0x200;
    dec[2] = 128;
    dec[3] = 128;
    dec[4] = STREAM.len() as u32;
    dec[6] = TARGET_BYTES as u32;
    dec[9] = CONTEXT_BYTES as u32;
    dec[10] = 128 << 10;
    dec[17] = 0x20181d;
    dec[18] = 128;
    dec[19] = 128;
    dec[22] = 3;
    dec[25] = 128;
    dec[26] = 64;
    dec[29] = 3;
    dec[36] = 128 * 128 * 2;
    dec[40] = 1;
    dec[41] = 64;
    for (i, w) in dec.into_iter().enumerate() {
        put(&mut out, 56 + i * 4, w);
    }
    let v = &mut out[244..];
    put(v, 0, 0x5844);
    for seg in 0..8 {
        v[10 + seg * 8] = 1;
    }
    v[82] = 1;
    v[83..94].fill(0x7f);
    v[98] = 2;
    v[99] = 2;
    v[100] = 1;
    v[101] = 1;
    put(v, 108, 10);
    put(v, 112, 18);
    out
}
pub(super) fn validate(base: u64) -> Result<(), Error> {
    if base == 0 || base & 4095 != 0 || base.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
        return Err(Error::Invalid);
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Ib {
    words: [u32; 47],
    len: usize,
}
impl Ib {
    pub(super) fn as_slice(&self) -> &[u32] {
        &self.words[..self.len]
    }
}
/// Tier3 has no external references for this first keyframe. Its real unified
/// reference-list packet is still present (num_bufs0); no legacy8K DPB exists.
pub(super) fn ib(base: u64, phase: Phase) -> Result<Ib, Error> {
    validate(base)?;
    let len = if phase == Phase::Decode { 47 } else { 43 };
    let mut out = Ib {
        words: [0; 47],
        len,
    };
    out.words[..10].copy_from_slice(&[
        16,
        0x30000002,
        0,
        len as u32 - 4,
        16,
        0x30000001,
        3,
        (len as u32 - 4) * 4,
        140,
        1,
    ]);
    let (msg, flags) = match phase {
        Phase::Create => (CREATE_MSG, 0x100001),
        Phase::Decode => (DECODE_MSG, 0x30181d),
        Phase::Destroy => (DESTROY_MSG, 0x100001),
    };
    out.words[10] = flags;
    let mut bind = |i: usize, off: u64| {
        let addr = base + off;
        out.words[i] = (addr >> 32) as u32;
        out.words[i + 1] = addr as u32;
    };
    bind(11, msg);
    bind(17, SESSION);
    if phase == Phase::Decode {
        for (i, off) in [
            (15, TARGET),
            (19, BITSTREAM),
            (21, CONTEXT),
            (23, FEEDBACK),
            (27, PROBS),
        ] {
            bind(i, off);
        }
        out.words[43..47].copy_from_slice(&[16, 12, 8, 0]);
    }
    out.words[2] = out.words[4..len]
        .iter()
        .fold(0u32, |sum, w| sum.wrapping_add(*w));
    Ok(out)
}
