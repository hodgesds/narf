// SPDX-License-Identifier: GPL-2.0-or-later
// JPEG packets adapted from Linux jpeg_v4_0_3.{c,h}:
// Copyright 2022 Advanced Micro Devices, Inc.
// Kernel pitch IB adapted from amdgpu_jpeg.c:
// Copyright 2019 Advanced Micro Devices, Inc.
// Upstream permission notices: ../JPEG-NOTICES.
//! Kernel VMID0 transport words for JPEG5 on MMHUB4.1.
use alloc::{vec, vec::Vec};
pub(super) const PITCH: u32 = 0x4043;
pub(super) const NOP: u32 = 0x60000000;
pub(super) fn kernel_ib() -> [u32; 16] {
    let mut words = [0; 16];
    words[..2].copy_from_slice(&[PITCH, 0xdeadbeef]);
    for pair in words[2..].chunks_exact_mut(2) {
        pair[0] = NOP;
    }
    words
}
pub(super) fn direct() -> Vec<u32> {
    let mut words = vec![0x1bfff, 0x69004, 0x18000, 0x80010000, PITCH, 0xabadcafe];
    words.extend_from_slice(&[0x1bfff, 0x69004, 0x18000, 0x10000]);
    words
}
pub(super) fn ib_frame(ring: u64, ib: u64, fence: u64, seq: u32) -> Vec<u32> {
    let mut words = vec![0x1bfff, 0x69004, 0x18000, 0x80010000];
    // jpeg_v4_0_3_dec_ring_emit_wreg: ordered HDP flush before the IB.
    words.extend_from_slice(&[0x1bfff, 0x7f000, 0x18000, 0]);
    words.extend_from_slice(&[
        0x40a4,
        0,
        0x40a6,
        0,
        0x40b6,
        ib as u32,
        0x40b7,
        (ib >> 32) as u32,
        0x4082,
        16,
        0x42d4,
        ring as u32,
        0x42d5,
        (ring >> 32) as u32,
        0x20000000,
        0,
        0x4085,
        0x01400200,
        0x4084,
        2,
        0x33004089,
        2,
    ]);
    words.extend_from_slice(&[
        0x404e,
        seq,
        0x404f,
        seq,
        0x40ab,
        fence as u32,
        0x40ac,
        (fence >> 32) as u32,
        0x404d,
        8,
        0x4000404d,
        0,
        NOP,
        0,
        NOP,
        0,
        0x70000000,
        0,
    ]);
    words.extend_from_slice(&[0x1bfff, 0x69004, 0x18000, 0x10000]);
    words
}
