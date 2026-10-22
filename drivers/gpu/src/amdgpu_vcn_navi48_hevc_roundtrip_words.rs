// SPDX-License-Identifier: MIT
//! Fixed encoder SPS/PPS parameters and dynamic output length for roundtrip.
//! This constructor is intentionally not a client bitstream parser.
use super::Error;

pub(super) const WIDTH: u64 = 384;
pub(super) const HEIGHT: u64 = 128;
pub(super) const REFERENCES: u64 = 2; // SPS sps_max_dec_pic_buffering_minus1 + 1.
pub(super) const TARGET_BYTES: u64 = WIDTH * HEIGHT * 3 / 2;
pub(super) const DPB_BYTES: u64 = TARGET_BYTES * REFERENCES;
// ac_vcn_dec.c::calc_ctx_size_hevc, Main8 and two reference slots.
pub(super) const CONTEXT_BYTES: u64 =
    ((WIDTH + 255) / 16) * ((HEIGHT + 255) / 16) * 16 * REFERENCES + 52 * 1024;
pub(super) const GUARD: u32 = 0xb1c43967;
pub(super) const HANDLE: u32 = 0x4e415203;
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
pub(super) const BITSTREAM_BYTES: u64 = 0x1f000;
pub(super) const DPB_GUARD: u64 = BITSTREAM + BITSTREAM_BYTES;
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
const _: () = assert!(TARGET_BYTES & 4095 == 0);

/// Original deterministic source, tightly packed NV12.
pub(super) const fn expected(at: u64) -> u8 {
    if at >= WIDTH * HEIGHT {
        if at & 1 == 0 {
            80
        } else {
            176
        }
    } else if (at / WIDTH < HEIGHT / 2) == (at % WIDTH < WIDTH / 2) {
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
    for (i, w) in [
        40,
        56,
        1,
        0,
        HANDLE,
        0,
        1,
        40,
        16,
        0,
        16,
        0,
        WIDTH as u32,
        HEIGHT as u32,
    ]
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
pub(super) fn decode_message(size: u32) -> Result<[u8; 540], Error> {
    if size == 0 || u64::from(size) > BITSTREAM_BYTES {
        return Err(Error::EncodeOutput);
    }
    let mut out = [0; 540];
    for (i, w) in [40, 540, 2, 1, HANDLE, 0, 2, 56, 188, 0, 13, 244, 296, 0]
        .into_iter()
        .enumerate()
    {
        put(&mut out, i * 4, w);
    }
    let mut dec = [0u32; 47];
    dec[0] = 16;
    dec[2] = WIDTH as u32;
    dec[3] = 128;
    dec[4] = size;
    dec[5] = DPB_BYTES as u32;
    dec[6] = TARGET_BYTES as u32;
    dec[9] = CONTEXT_BYTES as u32;
    dec[10] = 128 << 10;
    dec[17] = 0xa1f;
    dec[18] = WIDTH as u32;
    dec[19] = 128;
    dec[21] = 1;
    dec[22] = 3;
    dec[25] = WIDTH as u32;
    // UV surf_pitch is in two-component format blocks, not luma samples.
    dec[26] = WIDTH as u32 / 2;
    dec[29] = 3;
    dec[36] = (WIDTH * HEIGHT) as u32;
    dec[40] = 1;
    dec[41] = WIDTH as u32 / 2;
    for (i, w) in dec.into_iter().enumerate() {
        put(&mut out, 56 + i * 4, w);
    }
    let h = &mut out[244..];
    put(h, 0, 1 << 7); // strong intra smoothing, no SAO/AMP/scaling/temporal MVP.
    put(h, 4, 1 << 17); // PPS deblocking disabled.
    h[8] = 1;
    h[11] = 4;
    h[12] = 1;
    h[14] = 3;
    h[16] = 3;
    h[124..139].fill(0x7f); // Fifteen invalid references, no inter prediction.
    h[204..228].fill(0xff); // Empty short/long-term current reference sets.
    h[228..236].fill(16); // Flat disabled scaling lists/DC coefficients.
    h[236] = 0xff; // Mesa's highestTid; IDR is a reference picture (isNonRef=0).
    Ok(out)
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
