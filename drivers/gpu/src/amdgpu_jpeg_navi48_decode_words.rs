// SPDX-License-Identifier: MIT
// JPEG5 command sequence adapted from IGT 2.4 amd_jpeg_shared.{c,h}:
// Copyright 2025 Advanced Micro Devices, Inc. Full notice: ../JPEG-NOTICES.
//! NARF's guarded arena and fixed JPEG picture IB. Binary fixture notices
//! are retained separately in ../fixtures/jpeg5/LICENSE.
use super::Error;
use alloc::vec::Vec;
pub(super) const STREAM: &[u8] = include_bytes!("../fixtures/jpeg5/jpeg_bitstream.bin");
pub(super) const INPUT: u64 = 4096;
pub(super) const INPUT_BYTES: u64 = 8192;
pub(super) const INPUT_END_GUARD: u64 = INPUT + INPUT_BYTES;
pub(super) const TARGET: u64 = INPUT_END_GUARD + 4096;
pub(super) const TARGET_BYTES: u64 = 24576;
pub(super) const TARGET_END_GUARD: u64 = TARGET + TARGET_BYTES;
pub(super) const IB: u64 = TARGET_END_GUARD + 4096;
pub(super) const END_GUARD: u64 = IB + 4096;
pub(super) const BYTES: u64 = END_GUARD + 4096;
pub(super) const GUARDS: [u64; 4] = [0, INPUT_END_GUARD, TARGET_END_GUARD, END_GUARD];
pub(super) const GUARD: u32 = 0xd7c3a591;
pub(super) const PITCH: u64 = 256;
pub(super) const WIDTH: u64 = 64;
pub(super) const CHROMA: u64 = 0x4000;
pub(super) const EXPECTED_SUM: u64 = 262144;
const _: () = assert!(STREAM.len() <= 512 && CHROMA + PITCH * WIDTH / 2 == TARGET_BYTES);
pub(super) fn validate(base: u64) -> Result<(), Error> {
    if base == 0 || base & 4095 != 0 || base.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(super) fn ib(base: u64) -> Result<Vec<u32>, Error> {
    validate(base)?;
    let input = base + INPUT;
    let target = base + TARGET;
    let mut words = Vec::with_capacity(64);
    for (reg, cond, kind, value) in [
        (0x4051, 0, 0, 1),
        (0x408e, 0, 0, 0x01400200),
        (0x408f, 0, 0, 1 << 16),
        (0x4051, 3, 3, 1 << 16),
        (0x4051, 0, 0, 0),
        (0x408f, 0, 0, 0),
        (0x4051, 3, 3, 1 << 16),
        (0x40b3, 0, 0, (input >> 32) as u32),
        (0x40b2, 0, 0, input as u32),
        (0x4001, 0, 0, 0),
        (0x4004, 0, 0, 0xfffffff0),
        (0x4002, 0, 0, 128),
        (0x4043, 0, 0, 16),
        (0x4044, 0, 0, 16),
        (0x404b, 0, 0, 0),
        (0x4048, 0, 0, 0),
        (0x4049, 0, 0, 0),
        (0x40b5, 0, 0, (target >> 32) as u32),
        (0x40b4, 0, 0, target as u32),
        (0x41c0, 0, 0, 0),
        (0x41c1, 0, 0, CHROMA as u32),
        (0x400e, 0, 0, 0),
        (0x4042, 0, 0, 0),
        (0x4040, 0, 0, 0x14c7),
        (0x400a, 0, 0, 0xfffffffe),
        (0x4000, 0, 0, 0xe),
        (0x408f, 0, 0, 128),
        (0x408e, 0, 0, 0x01400200),
        (0x4003, 3, 3, u32::MAX),
        (0x408f, 0, 0, u32::MAX),
        (0x4041, 3, 3, 1),
        (0x4000, 0, 0, 4),
    ] {
        words.extend_from_slice(&[reg | (cond << 24) | (kind << 28), value]);
    }
    while words.len() & 15 != 0 {
        words.extend_from_slice(&[0x60000000, 0]);
    }
    Ok(words)
}
