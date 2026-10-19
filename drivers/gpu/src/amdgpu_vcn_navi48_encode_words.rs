// SPDX-License-Identifier: MIT
// VCN5 packet sequence adapted from IGT 2.4 tests/amdgpu/amd_vcn.c:
// Copyright 2023 Advanced Micro Devices, Inc.
// Copyright 2014 Advanced Micro Devices, Inc.
// Upstream permission notice: ../VCN-NOTICES.
//! Fixed 160x128 NV12 IDR task and NARF's guarded, fully backed arena.
use super::Error;
use alloc::{vec, vec::Vec};

pub(super) const FRAME: &[u8] = include_bytes!("../fixtures/vcn5/encode/frame.bin");
pub(super) const WIDTH: u32 = 160;
pub(super) const HEIGHT: u32 = 128;
pub(super) const PITCH: u64 = 256;
pub(super) const LUMA_BYTES: u64 = PITCH * HEIGHT as u64;
pub(super) const INPUT_BYTES: u64 = LUMA_BYTES * 3 / 2;
// The upstream command declares 0x1f000 bytes even though the test allocates
// 4096. Back the entire declared range before publishing this task.
pub(super) const OUTPUT_BYTES: u64 = 0x1f000;
pub(super) const GUARD: u32 = 0xe5c3a791;
pub(super) const SESSION: u64 = 4096;
pub(super) const CPB: u64 = SESSION + (128 << 10);
pub(super) const INPUT_GUARD: u64 = CPB + INPUT_BYTES * 2;
pub(super) const INPUT: u64 = INPUT_GUARD + 4096;
pub(super) const INPUT_END_GUARD: u64 = INPUT + INPUT_BYTES;
pub(super) const FEEDBACK: u64 = INPUT_END_GUARD + 4096;
pub(super) const METADATA: u64 = FEEDBACK + 4096;
pub(super) const OUTPUT_GUARD: u64 = METADATA + 4096;
pub(super) const OUTPUT: u64 = OUTPUT_GUARD + 4096;
pub(super) const OUTPUT_END_GUARD: u64 = OUTPUT + OUTPUT_BYTES;
pub(super) const CREATE_IB: u64 = OUTPUT_END_GUARD + 4096;
pub(super) const ENCODE_IB: u64 = CREATE_IB + 4096;
pub(super) const DESTROY_IB: u64 = ENCODE_IB + 8192;
pub(super) const END_GUARD: u64 = DESTROY_IB + 4096;
pub(super) const BYTES: u64 = END_GUARD + 4096;
pub(super) const GUARDS: [u64; 6] = [
    0,
    INPUT_GUARD,
    INPUT_END_GUARD,
    OUTPUT_GUARD,
    OUTPUT_END_GUARD,
    END_GUARD,
];
const _: () = assert!(FRAME.len() == WIDTH as usize * HEIGHT as usize * 3 / 2);

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
    fn new(base: u64, phase: Phase) -> Self {
        let mut this = Self {
            words: vec![0; 8],
            task: 0,
        };
        let at = base + SESSION;
        this.packet(1, &[0x10009, (at >> 32) as u32, at as u32, 1]);
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

pub(super) fn ib(base: u64, phase: Phase) -> Result<Vec<u32>, Error> {
    validate(base)?;
    let mut b = Builder::new(base, phase);
    match phase {
        Phase::Create => {
            b.packet(0x01000001, &[]);
            b.packet(3, &[1, WIDTH, HEIGHT, 0, 0, 0, 0, 0, 0]);
            b.packet(0x00200001, &[0, (WIDTH / 16) * (HEIGHT / 16)]);
            b.packet(0x00200002, &[0, 0, 0, 0, 1, 1, 100, 11, 0, 0]);
            b.packet(0x00200004, &[0; 5]);
            b.packet(4, &[1, 1]);
            b.packet(6, &[0, 48]);
            b.packet(9, &[0; 5]);
            b.packet(5, &[0]);
            b.packet(7, &[0, 0, 25, 1, 0x01312d00, 0, 0, 0]);
            b.packet(5, &[0]);
            b.packet(8, &[20, 0, 51, 0, 1, 0, 1, 0]);
            b.packet(0x01000004, &[]);
            b.packet(0x01000005, &[]);
        }
        Phase::Destroy => b.packet(0x01000002, &[]),
        Phase::Encode => {
            b.packet(
                0x0a,
                &[2, 17, 1, 0x6764440b, 0xac54c284, 0x68078442, 0x37000000],
            );
            b.packet(0x0a, &[3, 8, 1, 0x68ce3c80]);
            let mut slice = vec![0x65000000, 0x11040000, 0xe0000000];
            slice.extend_from_slice(&[0; 13]);
            slice.extend_from_slice(&[1, 8, 0x20000, 0, 1, 0x15, 0x20001, 0, 1, 3]);
            slice.extend_from_slice(&[0; 22]);
            b.packet(0x0b, &slice);
            let luma = base + INPUT;
            let chroma = luma + LUMA_BYTES;
            b.packet(
                0x0f,
                &[
                    2,
                    OUTPUT_BYTES as u32,
                    (luma >> 32) as u32,
                    luma as u32,
                    (chroma >> 32) as u32,
                    chroma as u32,
                    PITCH as u32,
                    HEIGHT,
                    0,
                    0,
                ],
            );
            let mut h264 = vec![0, 0, 1, 0, 0, u32::MAX];
            h264.extend_from_slice(&[0; 31 + 1 + 32 + 1]);
            h264.extend_from_slice(&[0, u32::MAX, 0, u32::MAX]);
            b.packet(0x00200003, &h264);
            let cpb = base + CPB;
            let meta = base + METADATA;
            let mut context = vec![(cpb >> 32) as u32, cpb as u32, 2];
            for _ in 0..2 {
                context.extend_from_slice(&[
                    (cpb >> 32) as u32,
                    cpb as u32,
                    PITCH as u32,
                    (cpb >> 32) as u32,
                    cpb as u32,
                    PITCH as u32,
                    (cpb >> 32) as u32,
                    cpb as u32,
                    0,
                    1,
                    (meta >> 32) as u32,
                    meta as u32,
                    u32::MAX,
                    0,
                    0,
                ]);
            }
            context.resize(context.len() + 15 * (32 + 34) + 6, 0);
            b.packet(0x11, &context);
            let mut offsets = vec![
                0,
                LUMA_BYTES as u32,
                0,
                INPUT_BYTES as u32,
                (LUMA_BYTES * 5 / 2) as u32,
                0,
            ];
            offsets.resize(offsets.len() + (34 + 32) * 3, 0);
            b.packet(0x1d, &offsets);
            b.packet(0x1c, &[(meta >> 32) as u32, meta as u32, 0]);
            let output = base + OUTPUT;
            b.packet(
                0x12,
                &[
                    0,
                    (output >> 32) as u32,
                    output as u32,
                    OUTPUT_BYTES as u32,
                    0,
                ],
            );
            let feedback = base + FEEDBACK;
            b.packet(
                0x15,
                &[0, (feedback >> 32) as u32, feedback as u32, 0x10, 0x28],
            );
            b.packet(0x10, &[0; 3]);
            b.packet(0x0c, &[0; 7]);
            b.packet(0x0d, &[0; 4]);
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
