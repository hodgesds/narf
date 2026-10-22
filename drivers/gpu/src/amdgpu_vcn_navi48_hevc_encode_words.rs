// SPDX-License-Identifier: MIT
// VCN5 HEVC packets adapted from Mesa 26.2.4 radeonsi/mm/radeon_vcn_enc_*.c:
// Copyright 2017, 2024, 2025 Advanced Micro Devices, Inc.
// Upstream permission notice: ../VCN-NOTICES.
//! Fixed Main8 384x128 NV12 IDR, no references, SAO or rate control.
use super::Error;
use alloc::{vec, vec::Vec};

pub(super) const FRAME: &[u8] = include_bytes!("../fixtures/vcn5/hevc_encode/frame.bin");
pub(super) const WIDTH: u32 = 384;
pub(super) const HEIGHT: u32 = 128;
pub(super) const PITCH: u64 = 512;
pub(super) const LUMA_BYTES: u64 = PITCH * HEIGHT as u64;
pub(super) const INPUT_BYTES: u64 = LUMA_BYTES * 3 / 2;
// CPU-generated parameter sets use Mesa's exact bitstream builders. Firmware
// writes the IDR slice after a 16-byte aligned prefix, as Mesa does for raw headers.
pub(super) const HEADERS: &[u8] = include_bytes!("../fixtures/vcn5/hevc_encode/headers.bin");
pub(super) const HEADER_PREFIX: u64 = 80;
pub(super) const REC_LUMA_BYTES: u64 = PITCH * 256;
pub(super) const REC_BYTES: u64 = REC_LUMA_BYTES * 3 / 2;
pub(super) const OUTPUT_BYTES: u64 = 0x1f000;
pub(super) const GUARD: u32 = 0xe5c3a791;
pub(super) const SESSION: u64 = 4096;
pub(super) const CPB: u64 = SESSION + (128 << 10);
pub(super) const INPUT_GUARD: u64 = CPB + REC_BYTES * 2;
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
            b.packet(3, &[0, WIDTH, HEIGHT, 0, 0, 0, 0, 0, 0, 0]);
            b.packet(4, &[1, 1]);
            b.packet(6, &[0, 48]);
            b.packet(0x18, &[0]);
            b.packet(5, &[0]);
            b.packet(7, &[0, 0, 25, 1, 0, 0, 0, 0]);
            b.packet(5, &[0]);
            b.packet(8, &[20, 20, 20, 0, 51, 0, 51, 0, 51, 0, 0, 0, 0, 0, 0, 0]);
            b.packet(0x01000004, &[]);
            b.packet(0x01000005, &[]);
        }
        Phase::Destroy => b.packet(0x01000002, &[]),
        Phase::Encode => {
            b.packet(0x00100001, &[0, 12, 12]);
            b.packet(5, &[0]);
            b.packet(9, &[0; 5]);
            b.packet(0x00100001, &[0, 12, 12]);
            b.packet(0x00100002, &[0, 1, 1, 0, 0, 1, 1, 1, 0, 0]);
            b.packet(0x00100003, &[0, 1, 0, 0, 0, 0, 1]);
            // Exact Mesa slice template: IDR_W_RADL, temporal_id 0, PPS0,
            // no_output_of_prior_pics=0, I slice. Dynamic first/address/QP.
            let mut slice = vec![0x26010000, 0x40000000, 0x60000000];
            slice.resize(16, 0);
            slice.extend_from_slice(&[
                1, 16, 0x10001, 0, 1, 2, 0x10006, 0, 0x10000, 0, 1, 3, 0x10003, 0, 0, 0,
            ]);
            slice.resize(48, 0);
            b.packet(0x0b, &slice);
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
            let mut refs = vec![u32::MAX];
            refs.resize(17, 0);
            b.packet(0x00100004, &refs);
            let cpb = base + CPB;
            let meta = base + METADATA;
            let mut context = vec![(cpb >> 32) as u32, cpb as u32, 2];
            for i in 0..34 {
                let frame_meta = meta + if i < 2 { i * 1024 } else { 0 };
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
                    0,
                    0,
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
                0,
                REC_LUMA_BYTES as u32,
                0,
                REC_BYTES as u32,
                (REC_BYTES + REC_LUMA_BYTES) as u32,
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

/// Only this exact CPU prefix and a single IDR slice are accepted. The later
/// native decoder validates CABAC/picture data; this gate is not a decoder.
pub(super) fn valid_output(stream: &[u8]) -> bool {
    let prefix = HEADER_PREFIX as usize;
    if stream.len() <= prefix + 8
        || stream.len() > OUTPUT_BYTES as usize
        || stream.get(..HEADERS.len()) != Some(HEADERS)
        || !stream[HEADERS.len()..prefix].iter().all(|b| *b == 0)
    {
        return false;
    }
    let slice = &stream[prefix..];
    let at = if slice.starts_with(&[0, 0, 0, 1]) {
        4
    } else if slice.starts_with(&[0, 0, 1]) {
        3
    } else {
        return false;
    };
    if slice.len() < at + 6
        || !matches!(slice[at], 0x26 | 0x28)
        || slice[at + 1] != 1
        || slice[at + 2] & 0xfc != 0xac
    {
        return false;
    }
    // Four CTBs are one slice. Reject extra VCL/header units or unescaped start
    // codes rather than decode a stream outside this task's fixed parameters.
    !slice[at + 2..].windows(3).any(|w| w == [0, 0, 1])
}

/// Mesa ac_gpu_info.c firmware version decomposition; the newer dependent
/// slice-address template is supported on VCN5 encoder interface >=1.8.
pub(super) const fn interface(firmware: u32) -> Option<u32> {
    let major = (firmware >> 20) & 0xf;
    let minor = (firmware >> 12) & 0xff;
    if major != 1 || minor < 8 {
        None
    } else {
        Some(0x10000 | if minor < 10 { minor } else { 10 })
    }
}
