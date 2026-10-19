// SPDX-License-Identifier: GPL-2.0-or-later
// Fixed session data and protocol builders adapted from Linux amdgpu_vcn.c:
// Copyright 2016-2024 Advanced Micro Devices, Inc.
// Original permissive notices are retained in ../VCN-NOTICES.
//! Fixed unified session IBs from Linux amdgpu_vcn_unified_ring_test_ib.
//! These test firmware IB transport; they do not encode/decode video frames.
use super::Error;

pub(super) const ENCODE_CONTEXT_BYTES: u64 = 128 << 10;
pub(super) const ENCODE_CREATE: u64 = ENCODE_CONTEXT_BYTES;
pub(super) const ENCODE_DESTROY: u64 = ENCODE_CREATE + 4096;
pub(super) const DECODE_CREATE_MSG: u64 = ENCODE_DESTROY + 4096;
pub(super) const DECODE_DESTROY_MSG: u64 = DECODE_CREATE_MSG + 4096;
pub(super) const DECODE_CREATE: u64 = DECODE_DESTROY_MSG + 4096;
pub(super) const DECODE_DESTROY: u64 = DECODE_CREATE + 4096;
pub(super) const IB_BYTES: u64 = DECODE_DESTROY + 4096;

fn address(at: u64) -> Result<(), Error> {
    if at == 0 || at & 4095 != 0 || at >= 1 << 48 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn header(words: &mut [u32], encode: bool) {
    let packet_dwords = words.len() as u32 - 4;
    words[..8].copy_from_slice(&[
        0x10,
        0x3000_0002,
        0,
        packet_dwords,
        0x10,
        0x3000_0001,
        if encode { 2 } else { 3 },
        packet_dwords * 4,
    ]);
}
fn checksum(words: &mut [u32]) {
    words[2] = words[4..]
        .iter()
        .fold(0u32, |sum, value| sum.wrapping_add(*value));
}
/// Linux's 21-dword encode session initialize/close task, handle 1. The
/// caller owns the complete 128 KiB context at this page-aligned address.
pub(super) fn encode(context: u64, create: bool) -> Result<[u32; 21], Error> {
    address(context)?;
    if context
        .checked_add(ENCODE_CONTEXT_BYTES)
        .is_none_or(|end| end > 1 << 48)
    {
        return Err(Error::Invalid);
    }
    let mut words = [0; 21];
    header(&mut words, true);
    words[8..].copy_from_slice(&[
        0x18,
        1,
        1,
        (context >> 32) as u32,
        context as u32,
        0,
        0x14,
        2,
        0x1c,
        0,
        0,
        8,
        if create { 0x0800_0001 } else { 0x0800_0002 },
    ]);
    checksum(&mut words);
    Ok(words)
}
/// `amdgpu_vcn_decode_buffer` is 33 dwords: flags, message address high/low
/// and 30 reserved words. The unified wrapper adds 10 dwords.
pub(super) fn decode(message: u64) -> Result<[u32; 43], Error> {
    address(message)?;
    let mut words = [0; 43];
    header(&mut words, false);
    words[8..13].copy_from_slice(&[33 * 4 + 8, 1, 1, (message >> 32) as u32, message as u32]);
    checksum(&mut words);
    Ok(words)
}
/// Linux's fixed decoder session messages, handle 1, followed by zeroes to
/// the end of their individually owned pages.
pub(super) fn decode_message(create: bool) -> [u32; 14] {
    if create {
        [0x28, 0x38, 1, 0, 1, 0, 1, 0x28, 0x10, 0, 7, 0, 0x780, 0x440]
    } else {
        [0x28, 0x18, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }
}
