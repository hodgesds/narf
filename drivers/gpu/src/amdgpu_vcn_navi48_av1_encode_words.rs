// SPDX-License-Identifier: MIT
// VCN5 AV1 packets adapted from Mesa 26.2.4 radeonsi/mm/radeon_vcn_enc_*.c:
// Copyright 2017, 2024, 2025 Advanced Micro Devices, Inc.
// Upstream permission notice: ../VCN-NOTICES.
//! Fixed Main8 320x128 NV12 AV1 keyframe, one tile, no inter references.
use super::Error;
use alloc::{vec, vec::Vec};

pub(super) const FRAME: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/frame.bin");
pub(super) const HEADERS: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/headers.bin");
pub(super) const DEFAULT_CDF: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/cdf.bin");
pub(super) const WIDTH: u32 = 320;
pub(super) const HEIGHT: u32 = 128;
pub(super) const PITCH: u64 = 512;
pub(super) const LUMA_BYTES: u64 = PITCH * HEIGHT as u64;
pub(super) const INPUT_BYTES: u64 = LUMA_BYTES * 3 / 2;
pub(super) const OUTPUT_BYTES: u64 = 0x1f000;
pub(super) const HEADER_PREFIX: u64 = 16;
pub(super) const REC_LUMA_BYTES: u64 = PITCH * 256;
pub(super) const REC_BYTES: u64 = REC_LUMA_BYTES * 3 / 2;
pub(super) const SDB_BYTES: u64 = 947200;
pub(super) const FRAME_META_BYTES: u64 = 25088;
pub(super) const GUARD: u32 = 0x6a91c8d3;
const fn page(n: u64) -> u64 {
    (n + 4095) & !4095
}
pub(super) const SESSION: u64 = 4096;
pub(super) const CPB: u64 = SESSION + (128 << 10);
pub(super) const CPB_END_GUARD: u64 = CPB + page(SDB_BYTES + REC_BYTES * 2);
pub(super) const CDF: u64 = CPB_END_GUARD + 4096;
pub(super) const CDF_END_GUARD: u64 = CDF + 81920;
pub(super) const INPUT: u64 = CDF_END_GUARD + 4096;
pub(super) const INPUT_END_GUARD: u64 = INPUT + INPUT_BYTES;
pub(super) const FEEDBACK: u64 = INPUT_END_GUARD + 4096;
pub(super) const METADATA: u64 = FEEDBACK + 4096;
pub(super) const OUTPUT_GUARD: u64 = METADATA + page(FRAME_META_BYTES * 2);
pub(super) const OUTPUT: u64 = OUTPUT_GUARD + 4096;
pub(super) const OUTPUT_END_GUARD: u64 = OUTPUT + OUTPUT_BYTES;
pub(super) const CREATE_IB: u64 = OUTPUT_END_GUARD + 4096;
pub(super) const ENCODE_IB: u64 = CREATE_IB + 4096;
pub(super) const DESTROY_IB: u64 = ENCODE_IB + 8192;
pub(super) const END_GUARD: u64 = DESTROY_IB + 4096;
pub(super) const BYTES: u64 = END_GUARD + 4096;
pub(super) const GUARDS: [u64; 7] = [
    0,
    CPB_END_GUARD,
    CDF_END_GUARD,
    INPUT_END_GUARD,
    OUTPUT_GUARD,
    OUTPUT_END_GUARD,
    END_GUARD,
];
const _: () = assert!(
    FRAME.len() == WIDTH as usize * HEIGHT as usize * 3 / 2
        && HEADERS.len() <= HEADER_PREFIX as usize
        && DEFAULT_CDF.len() == 81920
);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Create,
    Encode,
    Destroy,
}

pub(super) fn validate(base: u64) -> Result<(), Error> {
    if base == 0 || base & 4095 != 0 || base.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
        return Err(Error::Invalid);
    }
    Ok(())
}
struct Builder {
    words: Vec<u32>,
    task: usize,
}
impl Builder {
    fn new(base: u64, phase: Phase, interface: u32) -> Self {
        let mut this = Self {
            words: vec![0; 8],
            task: 0,
        };
        let at = base + SESSION;
        this.packet(1, &[interface, (at >> 32) as u32, at as u32, 1]);
        this.task = this.words.len();
        let (task, feedback) = match phase {
            Phase::Create => (1, 0),
            Phase::Encode => (2, 1),
            Phase::Destroy => (3, 0),
        };
        this.packet(2, &[0, task, feedback]);
        this
    }
    fn packet(&mut self, id: u32, data: &[u32]) {
        self.words
            .extend_from_slice(&[((data.len() + 2) * 4) as u32, id]);
        self.words.extend_from_slice(data);
    }
    fn finish(mut self) -> Vec<u32> {
        let len = self.words.len() as u32;
        self.words[self.task + 2] = (len - self.task as u32) * 4;
        self.words[..8].copy_from_slice(&[
            0x10,
            0x30000002,
            0,
            len - 4,
            0x10,
            0x30000001,
            2,
            (len - 4) * 4,
        ]);
        self.words[2] = self.words[4..].iter().fold(0u32, |s, w| s.wrapping_add(*w));
        self.words
    }
}

pub(super) fn ib(base: u64, phase: Phase, interface: u32) -> Result<Vec<u32>, Error> {
    validate(base)?;
    if !(0x10008..=0x1000a).contains(&interface) {
        return Err(Error::Unsupported);
    }
    let mut b = Builder::new(base, phase, interface);
    match phase {
        Phase::Create => {
            b.packet(0x01000001, &[]);
            b.packet(3, &[2, WIDTH, HEIGHT, 0, 0, 0, 0, 0, 0, 0]);
            b.packet(4, &[1, 1]);
            b.packet(6, &[0, 48]);
            b.packet(0x18, &[0]);
            b.packet(5, &[0]);
            b.packet(7, &[0, 0, 25, 1, 0, 0, 0, 0]);
            b.packet(5, &[0]);
            b.packet(8, &[1, 1, 1, 1, 255, 1, 255, 1, 255, 0, 0, 0, 0, 0, 0, 0]);
            b.packet(0x01000004, &[]);
            b.packet(0x01000005, &[]);
        }
        Phase::Destroy => b.packet(0x01000002, &[]),
        Phase::Encode => {
            b.packet(5, &[0]);
            b.packet(9, &[0; 5]);
            let mut spec = vec![0; 48];
            spec[38] = 1;
            spec[39] = 1;
            b.packet(0x300001, &spec);
            // Mesa VCN5 legacy single-tile layout:5x2 superblocks, one group.
            let mut tile = vec![0; 88];
            tile[0] = 1;
            tile[1] = 1;
            tile[2] = 5;
            tile[4] = 2;
            tile[20] = 1;
            tile[85] = 2;
            tile[87] = 3;
            b.packet(0x300002, &tile);
            // Unchanged Mesa instruction constructors regenerate this fixed
            // template in the primary oracle; dynamic quant/filter/tx bits
            // are emitted by firmware and parsed before roundtrip publication.
            b.packet(
                0x300003,
                &[
                    0xc, 0x2, 0x1, 0x10, 0x1, 0x8, 0x32000000, 0x8, 0x3, 0x10, 0x1, 0x6,
                    0x90000000, 0x8, 0xa, 0x10, 0x1, 0x5, 0x0, 0x8, 0xb, 0x8, 0x6, 0x8, 0x8, 0x8,
                    0xc, 0x8, 0xd, 0x10, 0x1, 0x1, 0x0, 0x8, 0xe, 0x8, 0x4, 0x8, 0x0,
                ],
            );
            let luma = base + INPUT;
            let chroma = luma + LUMA_BYTES;
            b.packet(
                0x0f,
                &[
                    2,
                    (OUTPUT_BYTES - HEADER_PREFIX) as u32,
                    (luma >> 32) as u32,
                    luma as u32,
                    (chroma >> 32) as u32,
                    chroma as u32,
                    PITCH as u32,
                    // UV uses two-component surface blocks; CPU row bytes
                    // remain512, matching actual GFX12 Addrlib NV12 planes.
                    (PITCH / 2) as u32,
                    0,
                    0,
                ],
            );
            b.packet(
                0x300004,
                &[255, 255, 255, 255, 255, 255, 255, u32::MAX, u32::MAX, 0],
            );
            let cdf = base + CDF;
            b.packet(0x19, &[1, (cdf >> 32) as u32, cdf as u32]);
            let cpb = base + CPB;
            let meta = base + METADATA;
            let mut context = vec![(cpb >> 32) as u32, cpb as u32, 2];
            for i in 0..34 {
                let frame_meta = meta + if i < 2 { i * FRAME_META_BYTES } else { 0 };
                context.extend_from_slice(&[
                    (cpb >> 32) as u32,
                    cpb as u32,
                    PITCH as u32,
                    (cpb >> 32) as u32,
                    cpb as u32,
                    (PITCH / 2) as u32,
                    (cpb >> 32) as u32,
                    cpb as u32,
                    0,
                    1,
                    (frame_meta >> 32) as u32,
                    frame_meta as u32,
                    if i < 2 { 1024 } else { 0 },
                    if i < 2 { 23552 } else { 0 },
                    0,
                ]);
            }
            // Disabled pre-encode records are still emitted by Mesa's legacy
            // constructor, with valid base addresses and zero relative offsets.
            for _ in 0..34 {
                context.extend_from_slice(&[
                    (cpb >> 32) as u32,
                    cpb as u32,
                    PITCH as u32,
                    (cpb >> 32) as u32,
                    cpb as u32,
                    (PITCH / 2) as u32,
                    (cpb >> 32) as u32,
                    cpb as u32,
                    0,
                    1,
                    (meta >> 32) as u32,
                    meta as u32,
                    0,
                    0,
                    0,
                ]);
            }
            context.extend_from_slice(&[PITCH as u32, (PITCH / 2) as u32, 0, 0, 0, 0]);
            b.packet(0x11, &context);
            let mut offsets = vec![
                SDB_BYTES as u32,
                (SDB_BYTES + REC_LUMA_BYTES) as u32,
                0,
                (SDB_BYTES + REC_BYTES) as u32,
                (SDB_BYTES + REC_BYTES + REC_LUMA_BYTES) as u32,
                0,
            ];
            offsets.resize(offsets.len() + (34 + 32) * 3, 0);
            b.packet(0x1d, &offsets);
            let output = base + OUTPUT;
            b.packet(
                0x12,
                &[
                    0,
                    (output >> 32) as u32,
                    output as u32,
                    OUTPUT_BYTES as u32,
                    HEADER_PREFIX as u32,
                ],
            );
            let feedback = base + FEEDBACK;
            b.packet(
                0x15,
                &[0, (feedback >> 32) as u32, feedback as u32, 0x10, 0x28],
            );
            b.packet(0x1c, &[(meta >> 32) as u32, meta as u32, 0]);
            b.packet(0x10, &[0; 3]);
            b.packet(0x14, &[0; 4]);
            b.packet(0x0c, &[0; 7]);
            b.packet(0x0d, &[0; 5]);
            b.packet(0x01000006, &[]);
            b.packet(0x01000003, &[]);
        }
    }
    let words = b.finish();
    let capacity = if phase == Phase::Encode { 8192 } else { 4096 };
    if words.len() * 4 > capacity {
        return Err(Error::Invalid);
    }
    Ok(words)
}
