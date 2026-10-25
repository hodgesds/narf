// SPDX-License-Identifier: MIT
//! Original fixed Main8 lossless keyframe and bounded parsed-keyframe builder.
//! Mesa VCN5 tier3/unified-DT. Decoder CDF notice in ../VCN-NOTICES.
use super::Error;
pub(super) const STREAM: &[u8] = &[
    0x12, 0x00, 0x0a, 0x06, 0x18, 0x1d, 0xbf, 0xff, 0x80, 0x01, 0x32, 0xb4, 0x01, 0x90, 0x00, 0x00,
    0x00, 0x4b, 0x1a, 0xd5, 0x33, 0xda, 0x5f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf2, 0x08,
    0xde, 0x0a, 0x88, 0x52, 0x5f, 0xff, 0xff, 0xfa, 0xf6, 0xd0, 0xbb, 0xec, 0x6b, 0x2f, 0xff, 0xff,
    0xfe, 0xc4, 0x88, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xb8, 0x64, 0x28, 0x64, 0x5f, 0xb3, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0x0e, 0x5f, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf3, 0x13, 0x1a, 0x64,
    0x4b, 0xbc, 0xa4, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xbb, 0x41, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xa7, 0x5d, 0x5a, 0xf5, 0x5d, 0xa5, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf9, 0x31, 0xbf,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x40,
];
pub(super) const DEFAULT_CDF: &[u8] = include_bytes!("../fixtures/av1/default_cdf.bin");
pub(super) const TARGET_BYTES: u64 = 256 * 128 * 3 / 2;
pub(super) const FRAME_CONTEXT_BYTES: u64 = 20480;
pub(super) const CONTEXT_BYTES: u64 = {
    let pitch64 = (32u64 * 68).div_ceil(256) * 256 * 2;
    let pitch128 = (32u64 * 34).div_ceil(256) * 256 * 2;
    let lf64 = pitch64 * 1728u64.div_ceil(64);
    let lf128 = pitch128 * 3008u64.div_ceil(64);
    let lf = if lf64 > lf128 { lf64 } else { lf128 };
    let superres = 4352u64.div_ceil(64) * ((78u64 + 2) * 3 * 32).div_ceil(256) * 256;
    (9 + 4) * FRAME_CONTEXT_BYTES
        + 9 * 64 * 34 * 512
        + 9 * 64 * 34 * 256 * 5
        + (lf + superres) * 2
        + 68 * 512
};
pub(super) const GUARD: u32 = 0x31768ab4;
pub(super) const HANDLE: u32 = 0x4e415205;
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
pub(super) const fn expected(at: u64) -> u8 {
    if at < 256 * 128 {
        let (x, y) = (at % 256, at / 256);
        if y < 64 {
            if x < 128 {
                32
            } else {
                80
            }
        } else if x < 128 {
            144
        } else {
            208
        }
    } else if (at - 256 * 128) & 1 == 0 {
        64
    } else {
        192
    }
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
    for (i, w) in [40, 56, 1, 0, HANDLE, 0, 1, 40, 16, 0, 19, 0, 256, 128]
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
/// Already-parsed fixed reduced-still256x128 Main8 keyframe, one tile. Offsets
/// include the compact sequence+frame bytes, with CPU alignment padding removed.
/// Quant deltas are [Ydc,Udc,Uac,Vdc,Vac], matching coding order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Keyframe {
    pub bitstream_bytes: u32,
    pub tile_offset: u32,
    pub tile_bytes: u32,
    pub base_q_idx: u8,
    pub quant_delta: [i8; 5],
    pub filter_level: [u8; 4],
    pub sharpness: u8,
    pub mode_ref_delta_enabled: bool,
    pub mode_ref_delta_update: bool,
    pub ref_deltas: [i8; 8],
    pub mode_deltas: [i8; 2],
    pub tx_mode: u8,
    pub reduced_tx_set: bool,
}
impl Keyframe {
    fn lossless(self) -> bool {
        self.base_q_idx == 0 && self.quant_delta == [0; 5]
    }
    pub(super) fn validate(self) -> Result<(), Error> {
        let signed = |x: i8| (-64..=63).contains(&x);
        if self.bitstream_bytes == 0
            || u64::from(self.bitstream_bytes) > BITSTREAM_BYTES
            || self.tile_offset == 0
            || self.tile_bytes == 0
            || self.tile_offset.checked_add(self.tile_bytes) != Some(self.bitstream_bytes)
            || self.quant_delta.iter().any(|&x| !signed(x))
            || self.quant_delta[1] != self.quant_delta[3]
            || self.quant_delta[2] != self.quant_delta[4]
            || self.filter_level.iter().any(|&x| x > 63)
            || self.sharpness > 7
            || self
                .ref_deltas
                .iter()
                .chain(&self.mode_deltas)
                .any(|&x| !signed(x))
            || self.mode_ref_delta_update && !self.mode_ref_delta_enabled
            || self.tx_mode > 2
            || self.reduced_tx_set
            || self.lossless()
                && (self.tx_mode != 0
                    || self.filter_level != [0; 4]
                    || self.sharpness != 0
                    || self.mode_ref_delta_enabled
                    || self.mode_ref_delta_update)
            || !self.lossless() && self.tx_mode == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub(super) const fn fixed() -> Keyframe {
    Keyframe {
        bitstream_bytes: STREAM.len() as u32,
        tile_offset: 16,
        tile_bytes: 177,
        base_q_idx: 0,
        quant_delta: [0; 5],
        filter_level: [0; 4],
        sharpness: 0,
        mode_ref_delta_enabled: false,
        mode_ref_delta_update: false,
        ref_deltas: [1, 0, 0, 0, -1, 0, -1, -1],
        mode_deltas: [0; 2],
        tx_mode: 0,
        reduced_tx_set: false,
    }
}
/// Validate dynamic encoder output bounds and parsed quant/filter/tx fields before
/// any address publication. This does not parse or trust an arbitrary client IB.
pub(super) fn keyframe_message(frame: Keyframe) -> Result<[u8; 3828], Error> {
    frame.validate()?;
    Ok(build_message(frame))
}
fn build_message(frame: Keyframe) -> [u8; 3828] {
    let mut out = [0; 3828];
    for (i, w) in [40, 3828, 2, 1, HANDLE, 0, 2, 56, 188, 0, 17, 244, 3584, 0]
        .into_iter()
        .enumerate()
    {
        put(&mut out, i * 4, w);
    }
    let mut dec = [0u32; 47];
    dec[0] = 19;
    dec[1] = 0x200;
    dec[2] = 256;
    dec[3] = 128;
    dec[4] = frame.bitstream_bytes;
    dec[6] = TARGET_BYTES as u32;
    dec[9] = CONTEXT_BYTES as u32;
    dec[10] = 128 << 10;
    dec[17] = 0x20181d;
    dec[18] = 256;
    dec[19] = 128;
    dec[22] = 3;
    dec[25] = 256;
    dec[26] = 128;
    dec[29] = 3;
    dec[36] = 256 * 128;
    dec[40] = 1;
    dec[41] = 128;
    for (i, w) in dec.into_iter().enumerate() {
        put(&mut out, 56 + i * 4, w);
    }
    let v = &mut out[244..];
    put(
        v,
        0,
        0x80000003
            | (u32::from(frame.mode_ref_delta_enabled) << 20)
            | (u32::from(frame.mode_ref_delta_update) << 21)
            | (u32::from(frame.reduced_tx_set) << 24),
    );
    v[15] = 7;
    v[19..23].copy_from_slice(&frame.filter_level);
    v[23] = frame.sharpness;
    for (i, &d) in frame.ref_deltas.iter().enumerate() {
        v[24 + i] = d as u8;
    }
    for (i, &d) in frame.mode_deltas.iter().enumerate() {
        v[32 + i] = d as u8;
    }
    v[34] = frame.base_q_idx;
    for (i, q) in [
        frame.quant_delta[0],
        frame.quant_delta[1],
        frame.quant_delta[3],
        frame.quant_delta[2],
        frame.quant_delta[4],
    ]
    .into_iter()
    .enumerate()
    {
        v[35 + i] = q as u8;
    }
    v[40..43].fill(0xff);
    v[43] = 1;
    v[44] = 1;
    v[45] = 1;
    v[46] = 1;
    v[47] = frame.tx_mode;
    v[49] = 1;
    put(v, 52, 0xff);
    put(v, 64, 4);
    put(v, 324, 2);
    for (at, n) in [(580, 256), (584, 128), (588, 256), (592, 128), (596, 256)] {
        put(v, at, n);
    }
    v[600] = 8;
    v[602..610].fill(0x7f);
    v[644..651].fill(0x7f);
    v[924] = 3;
    v[1002] = if frame.lossless() { 0xff } else { 0 };
    for i in 0..8 {
        put(v, 1176 + i * 44 + 4 + 2 * 4, 1 << 16);
        put(v, 1176 + i * 44 + 4 + 5 * 4, 1 << 16);
    }
    put(v, 1528, frame.tile_offset);
    put(v, 1532, frame.tile_bytes);
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
