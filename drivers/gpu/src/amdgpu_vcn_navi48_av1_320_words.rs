// SPDX-License-Identifier: MIT
//! Bounded 320x128 Main8 decoder descriptor for the native AV1 encoder roundtrip.
//! Actual compact Addrlib layout: Y 384/UV 192 samples, UV 49152, target 73728 B.
pub(super) use super::av1_words::{Keyframe, Phase};
use super::{av1_words as base_words, Error};
pub(super) const DEFAULT_CDF: &[u8] = base_words::DEFAULT_CDF;
pub(super) const CONTEXT_BYTES: u64 = base_words::CONTEXT_BYTES;
pub(super) const TARGET_BYTES: u64 = 73728;
pub(super) const LOGICAL_BYTES: u64 = 320 * 128 * 3 / 2;
pub(super) const GUARD: u32 = 0x31768ab4;
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
pub(super) const PROBS_BYTES: u64 = 24576;
pub(super) const BITSTREAM_BYTES: u64 = 128 * 1024;
pub(super) const BITSTREAM: u64 = PROBS + PROBS_BYTES;
pub(super) const TARGET_GUARD: u64 = BITSTREAM + BITSTREAM_BYTES;
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
/// Pixel reference for logical NV12 coordinates; padding must remain zero and
/// is excluded from fidelity counts. Both planes have 384-byte physical rows.
pub(super) const fn expected(at: u64) -> Option<u8> {
    if at < 49152 {
        let (x, y) = (at % 384, at / 384);
        if x >= 320 {
            None
        } else if y < 64 {
            Some(if x < 160 { 32 } else { 80 })
        } else {
            Some(if x < 160 { 144 } else { 208 })
        }
    } else if at < TARGET_BYTES {
        let x = (at - 49152) % 384;
        if x >= 320 {
            None
        } else {
            Some(if x & 1 == 0 { 64 } else { 192 })
        }
    } else {
        None
    }
}
pub(super) fn create_message() -> [u8; 56] {
    let mut out = base_words::create_message();
    put(&mut out, 48, 320);
    out
}
pub(super) fn destroy_message() -> [u8; 24] {
    base_words::destroy_message()
}
fn put(out: &mut [u8], at: usize, word: u32) {
    out[at..at + 4].copy_from_slice(&word.to_le_bytes());
}
/// Same parsed fixed-sequence contract as Keyframe; the 320x128 encoder has
/// its own sequence prefix. Caller already checked that exact sequence/tools.
pub(super) fn keyframe_message(frame: Keyframe) -> Result<[u8; 3828], Error> {
    let mut out = base_words::keyframe_message(frame)?;
    for (index, value) in [
        (2, 320),
        (6, TARGET_BYTES as u32),
        (18, 384),
        (25, 384),
        (26, 192),
        (36, 49152),
        (41, 192),
    ] {
        put(&mut out, 56 + index * 4, value);
    }
    for (offset, value) in [(64, 5), (580, 320), (588, 320), (596, 320)] {
        put(&mut out, 244 + offset, value);
    }
    Ok(out)
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
