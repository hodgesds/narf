// SPDX-License-Identifier: MIT
// ABI reference: IGT 2.4 lib/amdgpu/amd_vcn_shared.{c,h},
// Copyright 2025 Advanced Micro Devices, Inc. See ../VCN-NOTICES.
//! NARF's guarded layout and Rust builder for the unified decode-buffer ABI.
//! Included IGT fixture data has separate 2017/2023 AMD notices in
//! ../fixtures/vcn5/LICENSE; those notices do not attribute this Rust code.
use super::Error;

pub(super) const CREATE_MSG_BYTES: &[u8] =
    include_bytes!("../fixtures/vcn5/vcn_dec_create_msg.bin");
pub(super) const DECODE_MSG_BYTES: &[u8] =
    include_bytes!("../fixtures/vcn5/vcn_dec_decode_msg.bin");
pub(super) const DESTROY_MSG_BYTES: &[u8] =
    include_bytes!("../fixtures/vcn5/vcn_dec_destroy_msg.bin");
pub(super) const AVC_BYTES: &[u8] = include_bytes!("../fixtures/vcn5/avc_decode_msg.bin");
pub(super) const FEEDBACK_BYTES: &[u8] = include_bytes!("../fixtures/vcn5/feedback_msg.bin");
pub(super) const SCALING_BYTES: &[u8] = include_bytes!("../fixtures/vcn5/uvd_it_scaling_table.bin");
pub(super) const STREAM: &[u8] = include_bytes!("../fixtures/vcn5/uvd_bitstream.bin");

pub(super) const DPB_BYTES: u64 = 15_923_584;
pub(super) const TARGET_BYTES: u64 = 737_280;
pub(super) const EXPECTED_SUM: u64 = 0x20345d8;
pub(super) const GUARD: u32 = 0xa6c35a91;
const fn page(bytes: u64) -> u64 {
    (bytes + 4095) & !4095
}
pub(super) const SESSION: u64 = 4096;
pub(super) const CREATE_MSG: u64 = SESSION + (128 << 10);
pub(super) const DECODE_MSG: u64 = CREATE_MSG + 4096;
pub(super) const DESTROY_MSG: u64 = DECODE_MSG + 4096;
pub(super) const FEEDBACK: u64 = DESTROY_MSG + 4096;
pub(super) const SCALING: u64 = FEEDBACK + 4096;
pub(super) const BITSTREAM: u64 = SCALING + 4096;
pub(super) const DPB: u64 = BITSTREAM + page(STREAM.len() as u64);
pub(super) const CONTEXT: u64 = DPB + page(0x006b9400);
pub(super) const TARGET_GUARD: u64 = DPB + page(DPB_BYTES);
pub(super) const TARGET: u64 = TARGET_GUARD + 4096;
pub(super) const TARGET_END_GUARD: u64 = TARGET + TARGET_BYTES;
pub(super) const CREATE_IB: u64 = TARGET_END_GUARD + 4096;
pub(super) const DECODE_IB: u64 = CREATE_IB + 4096;
pub(super) const DESTROY_IB: u64 = DECODE_IB + 4096;
pub(super) const END_GUARD: u64 = DESTROY_IB + 4096;
pub(super) const BYTES: u64 = END_GUARD + 4096;
pub(super) const GUARDS: [u64; 4] = [0, TARGET_GUARD, TARGET_END_GUARD, END_GUARD];
const _: () = assert!(DECODE_MSG_BYTES.len() + AVC_BYTES.len() <= 4096);
const _: () = assert!(CONTEXT < TARGET_GUARD && TARGET_BYTES & 4095 == 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Create,
    Decode,
    Destroy,
}

pub(super) fn validate(base: u64) -> Result<(), Error> {
    if base == 0 || base & 4095 != 0 || base.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Descriptor fields follow IGT's `rvcn_decode_buffer`; addresses are high
/// word first. All backing belongs to this one validated reservation.
pub(super) fn ib(base: u64, phase: Phase) -> Result<[u32; 43], Error> {
    validate(base)?;
    let mut words = [0; 43];
    words[..10].copy_from_slice(&[0x10, 0x3000_0002, 0, 39, 0x10, 0x3000_0001, 3, 156, 140, 1]);
    let (message, flags) = match phase {
        Phase::Create => (CREATE_MSG, 0x100001),
        Phase::Decode => (DECODE_MSG, 0x100a1f),
        Phase::Destroy => (DESTROY_MSG, 0x100001),
    };
    words[10] = flags;
    let mut bind = |at: usize, offset: u64| {
        let address = base + offset;
        words[at] = (address >> 32) as u32;
        words[at + 1] = address as u32;
    };
    bind(11, message);
    bind(17, SESSION);
    if phase == Phase::Decode {
        for (at, offset) in [
            (13, DPB),
            (15, TARGET),
            (19, BITSTREAM),
            (21, CONTEXT),
            (23, FEEDBACK),
            (31, SCALING),
        ] {
            bind(at, offset);
        }
    }
    words[2] = words[4..]
        .iter()
        .fold(0u32, |sum, word| sum.wrapping_add(*word));
    Ok(words)
}
