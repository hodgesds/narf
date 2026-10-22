// SPDX-License-Identifier: MIT
//! Fixed original HEVC Main8 picture and Mesa 26.2.4 VCN5 ABI builder.
//! This constructor is intentionally not a client bitstream parser.
use super::Error;

pub(super) const STREAM: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
    0x90, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x1e, 0xba, 0x02, 0x40, 0x00, 0x00, 0x00, 0x01,
    0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03,
    0x00, 0x1e, 0xa0, 0x10, 0x20, 0x20, 0x59, 0x6e, 0xa4, 0x93, 0x08, 0x80, 0x40, 0x00, 0x00, 0xfa,
    0x00, 0x00, 0x03, 0x00, 0xfa, 0x02, 0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xc0, 0x71, 0x81, 0xa4,
    0x80, 0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xac, 0x7c, 0x83, 0x8b, 0xff, 0xef, 0x9b, 0x8f, 0xff,
    0xa7, 0x31, 0xbf, 0xe6, 0x3b, 0xfe, 0xb1, 0x2a, 0x5d, 0x15, 0x6e, 0xb5, 0xee, 0x8f, 0xe3, 0xb6,
    0x5f, 0xfe, 0x3c, 0x2c, 0xe7, 0x9d, 0x84, 0xff, 0xf3, 0x38, 0x9d, 0x63, 0x37,
];
pub(super) const WIDTH: u64 = 128;
pub(super) const HEIGHT: u64 = 128;
pub(super) const REFERENCES: u64 = 3; // SPS sps_max_dec_pic_buffering_minus1 + 1.
pub(super) const TARGET_BYTES: u64 = WIDTH * HEIGHT * 3 / 2;
pub(super) const DPB_BYTES: u64 = TARGET_BYTES * REFERENCES;
// ac_vcn_dec.c::calc_ctx_size_hevc, Main8 and three reference slots.
pub(super) const CONTEXT_BYTES: u64 =
    ((WIDTH + 255) / 16) * ((HEIGHT + 255) / 16) * 16 * REFERENCES + 52 * 1024;
pub(super) const GUARD: u32 = 0xb1c43967;
pub(super) const HANDLE: u32 = 0x4e415201;
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
pub(super) const SCALING: u64 = FEEDBACK + 4096;
pub(super) const BITSTREAM: u64 = SCALING + 4096;
pub(super) const DPB_GUARD: u64 = BITSTREAM + 4096;
pub(super) const DPB: u64 = DPB_GUARD + 4096;
pub(super) const TARGET_GUARD: u64 = DPB + page(DPB_BYTES);
pub(super) const TARGET: u64 = TARGET_GUARD + 4096;
pub(super) const TARGET_END_GUARD: u64 = TARGET + TARGET_BYTES;
pub(super) const CREATE_IB: u64 = TARGET_END_GUARD + 4096;
pub(super) const DECODE_IB: u64 = CREATE_IB + 4096;
pub(super) const DESTROY_IB: u64 = DECODE_IB + 4096;
pub(super) const END_GUARD: u64 = DESTROY_IB + 4096;
pub(super) const BYTES: u64 = END_GUARD + 4096;
pub(super) const GUARDS: [u64; 6] = [
    0,
    SESSION_END_GUARD,
    DPB_GUARD,
    TARGET_GUARD,
    TARGET_END_GUARD,
    END_GUARD,
];
const _: () = assert!(TARGET_BYTES & 4095 == 0 && STREAM.len() <= 4096);

/// Exact independently decoded NV12 picture: four luma quadrants, U=64,V=192.
pub(super) const fn expected(at: u64) -> u8 {
    if at >= WIDTH * HEIGHT {
        if at & 1 == 0 {
            64
        } else {
            192
        }
    } else if at / WIDTH < HEIGHT / 2 {
        if at % WIDTH < WIDTH / 2 {
            32
        } else {
            80
        }
    } else if at % WIDTH < WIDTH / 2 {
        144
    } else {
        208
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
    for (i, w) in [40, 56, 1, 0, HANDLE, 0, 1, 40, 16, 0, 16, 0, 128, 128]
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
pub(super) fn decode_message() -> [u8; 540] {
    let mut out = [0; 540];
    for (i, w) in [40, 540, 2, 1, HANDLE, 0, 2, 56, 188, 0, 13, 244, 296, 0]
        .into_iter()
        .enumerate()
    {
        put(&mut out, i * 4, w);
    }
    let mut dec = [0u32; 47];
    dec[0] = 16;
    dec[2] = 128;
    dec[3] = 128;
    dec[4] = STREAM.len() as u32;
    dec[5] = DPB_BYTES as u32;
    dec[6] = TARGET_BYTES as u32;
    dec[9] = CONTEXT_BYTES as u32;
    dec[10] = 128 << 10;
    dec[17] = 0xa1f;
    dec[18] = 128;
    dec[19] = 128;
    dec[21] = 1;
    dec[22] = 3;
    dec[25] = 128;
    // UV surf_pitch is in two-component format blocks, not luma samples.
    dec[26] = 64;
    dec[29] = 3;
    dec[36] = 128 * 128;
    dec[40] = 1;
    dec[41] = 64;
    for (i, w) in dec.into_iter().enumerate() {
        put(&mut out, 56 + i * 4, w);
    }
    let h = &mut out[244..];
    put(h, 4, (1 << 15) | (1 << 17)); // PPS across-slices enabled, deblocking disabled.
    h[8] = 1;
    h[11] = 4;
    h[12] = 2;
    h[14] = 3;
    h[16] = 3;
    h[124..139].fill(0x7f); // Fifteen invalid references, no inter prediction.
    h[204..228].fill(0xff); // Empty short/long-term current reference sets.
    h[228..236].fill(16); // Flat disabled scaling lists/DC coefficients.
    h[236] = 0xff; // Mesa's highestTid; IDR is a reference picture (isNonRef=0).
    out
}
pub(super) fn validate(base: u64) -> Result<(), Error> {
    if base == 0 || base & 4095 != 0 || base.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Mesa rvcn_decode_buffer, high word first; all targets belong to one arena.
pub(super) fn ib(base: u64, phase: Phase) -> Result<[u32; 43], Error> {
    validate(base)?;
    let mut out = [0; 43];
    out[..10].copy_from_slice(&[16, 0x30000002, 0, 39, 16, 0x30000001, 3, 156, 140, 1]);
    let (msg, flags) = match phase {
        Phase::Create => (CREATE_MSG, 0x100001),
        Phase::Decode => (DECODE_MSG, 0x100a1f),
        Phase::Destroy => (DESTROY_MSG, 0x100001),
    };
    out[10] = flags;
    let mut bind = |i: usize, off: u64| {
        let addr = base + off;
        out[i] = (addr >> 32) as u32;
        out[i + 1] = addr as u32;
    };
    bind(11, msg);
    bind(17, SESSION);
    if phase == Phase::Decode {
        for (i, off) in [
            (13, DPB),
            (15, TARGET),
            (19, BITSTREAM),
            (21, CONTEXT),
            (23, FEEDBACK),
            (31, SCALING),
        ] {
            bind(i, off);
        }
    }
    out[2] = out[4..].iter().fold(0u32, |sum, w| sum.wrapping_add(*w));
    Ok(out)
}
