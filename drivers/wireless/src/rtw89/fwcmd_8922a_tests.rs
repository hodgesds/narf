// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the RTL8922A FWCMD framing layer. Expected
//! header words are computed in the test from the Linux `fw.h`
//! field layout (`H2C_HDR_*`, `fw.h:4750..4757`), never by
//! calling the encoder under test.

use super::fwcmd_8922a::*;
use super::h2c::H2cSeqAllocator;
use super::rx_packet::Ack;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_fwcmd_8922a_frame() -> TestResult {
    let alloc = H2cSeqAllocator::new();
    // MAC / FR_EXCHG / CCTLINFO_UD (2), payload 4 bytes, both acks.
    let payload = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut out = [0u8; 32];
    let (framed, total) = match frame_h2c(
        &alloc,
        H2cCmd {
            cat: 0x1,
            class: 0x5,
            func: 0x2,
        },
        &payload,
        true,
        true,
        &mut out,
    ) {
        Some(framed) => framed,
        None => return TestResult::Fail("frame_h2c refused a valid command"),
    };
    if framed.seq != 0 || framed.cat != 0x1 || framed.class != 0x5 || framed.func != 0x2 {
        return TestResult::Fail("framed identity wrong");
    }
    if total != 12 {
        return TestResult::Fail("framed total length must be header + payload");
    }
    // dword0 = CAT (1:0) | CLASS (7:2) | FUNC (15:8) |
    // DEL_TYPE (19:16) = 0 | SEQ (31:24).
    let dw0 = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    if dw0 != 0x1 | (0x5 << 2) | (0x2 << 8) | (0x0 << 24) {
        return TestResult::Fail("FWCMD hdr0 fields wrong");
    }
    // dword1 = TOTAL_LEN (13:0) | REC_ACK (14) | DONE_ACK (15).
    let dw1 = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
    if dw1 != 12 | (1 << 14) | (1 << 15) {
        return TestResult::Fail("FWCMD hdr1 fields wrong");
    }
    if out[8..12] != payload {
        return TestResult::Fail("FWCMD payload bytes wrong");
    }
    // Sequences allocate monotonically, wrapping at 256; the BE
    // path never forces rec_ack (the AX seq%4 quirk is absent):
    // a no-ack command at seq 1 keeps both ack bits clear.
    let mut out = [0u8; 8];
    let (framed, _) = match frame_h2c(
        &alloc,
        H2cCmd {
            cat: 0x1,
            class: 0x5,
            func: 0x2,
        },
        &[],
        false,
        false,
        &mut out,
    ) {
        Some(framed) => framed,
        None => return TestResult::Fail("frame_h2c refused an empty payload"),
    };
    if framed.seq != 1 {
        return TestResult::Fail("second command must take seq 1");
    }
    let dw1 = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
    if dw1 != 8 {
        return TestResult::Fail("BE framing must not force rec_ack on any seq");
    }
    // Refusals: short output buffer, over-long payload.
    let mut out = [0u8; 11];
    if frame_h2c(
        &alloc,
        H2cCmd {
            cat: 0x1,
            class: 0x5,
            func: 0x2,
        },
        &payload,
        false,
        false,
        &mut out,
    )
    .is_some()
    {
        return TestResult::Fail("frame_h2c accepted a short output buffer");
    }
    let big = [0u8; MAX_PAYLOAD_LEN + 1];
    let mut out = [0u8; 16];
    if frame_h2c(
        &alloc,
        H2cCmd {
            cat: 0x1,
            class: 0x5,
            func: 0x2,
        },
        &big,
        false,
        false,
        &mut out,
    )
    .is_some()
    {
        return TestResult::Fail("frame_h2c accepted an over-long payload");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwcmd_8922a_frame);

fn smoke_rtw89_fwcmd_8922a_ack_match() -> TestResult {
    let framed = FramedH2c {
        seq: 7,
        cat: 1,
        class: 9,
        func: 0x2C,
    };
    // Exact match (REC_ACK: result None).
    let ack = Ack {
        category: 1,
        class: 9,
        function: 0x2C,
        sequence: 7,
        result: None,
    };
    if !matches_ack(&ack, &framed) {
        return TestResult::Fail("exact ack must match");
    }
    // DONE_ACK with a nonzero return still matches (result is
    // reported, not part of the key).
    let ack = Ack {
        result: Some(3),
        ..ack
    };
    if !matches_ack(&ack, &framed) {
        return TestResult::Fail("DONE_ACK must match regardless of its return code");
    }
    // Each address field is part of the key.
    for (cat, class, func, seq) in [
        (2, 9, 0x2C, 7),
        (1, 8, 0x2C, 7),
        (1, 9, 0x2B, 7),
        (1, 9, 0x2C, 8),
    ] {
        let ack = Ack {
            category: cat,
            class,
            function: func,
            sequence: seq,
            result: None,
        };
        if matches_ack(&ack, &framed) {
            return TestResult::Fail("ack with a different address field must not match");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwcmd_8922a_ack_match);
