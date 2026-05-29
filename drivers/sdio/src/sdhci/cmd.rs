// SPDX-License-Identifier: GPL-2.0-or-later
//! SDHCI command descriptors for CMD0 / CMD3 / CMD5 / CMD7 / CMD52 / CMD53.
//!
//! References:
//! - SD Host Controller Simplified Spec v4.20 §3 (command protocol).
//! - SDIO Simplified Specification v3.00 §5 (CMD52/CMD53).
//! - Linux `drivers/mmc/host/sdhci.c`, `drivers/mmc/core/sdio_ops.c`
//!   (GPL-2.0-or-later, adapted).

#![allow(dead_code)]

use super::regs::{
    make_cmd, CMD_CRC, CMD_DATA, CMD_INDEX, CMD_RESP_NONE,
    CMD_RESP_SHORT, CMD_RESP_SHORT_BUSY,
};

// ── Command indices ────────────────────────────────────────────────────
pub const CMD_IDX_GO_IDLE: u8    = 0;   // CMD0
pub const CMD_IDX_SEND_RCA: u8   = 3;   // CMD3
pub const CMD_IDX_SEND_OP: u8    = 5;   // CMD5 (SDIO only)
pub const CMD_IDX_SELECT: u8     = 7;   // CMD7
pub const CMD_IDX_IO_RW_DIRECT: u8   = 52; // CMD52
pub const CMD_IDX_IO_RW_EXTENDED: u8 = 53; // CMD53

// ── Pre-built COMMAND register words ─────────────────────────────────
/// CMD0 — broadcast, no response.
pub const CMD0_WORD: u16 = make_cmd(CMD_IDX_GO_IDLE, CMD_RESP_NONE);

/// CMD3 — short response (R6: new RCA).
pub const CMD3_WORD: u16 = make_cmd(CMD_IDX_SEND_RCA, CMD_RESP_SHORT | CMD_CRC | CMD_INDEX);

/// CMD5 — short response (R4: OCR).  CRC not checked per SDIO spec.
pub const CMD5_WORD: u16 = make_cmd(CMD_IDX_SEND_OP, CMD_RESP_SHORT);

/// CMD7 — short-busy response (R1b).
pub const CMD7_WORD: u16 = make_cmd(CMD_IDX_SELECT, CMD_RESP_SHORT_BUSY | CMD_CRC | CMD_INDEX);

/// CMD52 — short response (R5).
pub const CMD52_WORD: u16 = make_cmd(CMD_IDX_IO_RW_DIRECT, CMD_RESP_SHORT | CMD_CRC | CMD_INDEX);

/// CMD53 — short response (R5) + data.
pub const CMD53_WORD: u16 =
    make_cmd(CMD_IDX_IO_RW_EXTENDED, CMD_RESP_SHORT | CMD_CRC | CMD_INDEX | CMD_DATA);

// ── CMD5 argument helpers ─────────────────────────────────────────────
/// Voltage window bits in the CMD5 argument (negotiation phase).
/// Pass 0 on the first send to get the card's supported range (query phase).
pub const CMD5_ARG_QUERY: u32 = 0x0000_0000;
/// Accept 3.3 V nominal range (bits[24:23] in R4 / OCR).
pub const CMD5_ARG_VDD_33: u32 = 0x00FF_8000;
/// Accept 1.8 V switch (bit 24 of OCR = S18R).
pub const CMD5_ARG_S18R: u32 = 0x0100_0000;

// OCR response field masks (R4)
/// OCR memory-present bit in CMD5 R4 response.
pub const OCR_MEM_PRESENT: u32 = 0x0800_0000;
/// OCR card ready bit.
pub const OCR_CARD_READY: u32  = 0x8000_0000;
/// S18A (1.8 V accepted) bit in R4.
pub const OCR_S18A: u32        = 0x0100_0000;
/// Number-of-SDIO-functions field (R4 bits[30:28]).
pub const OCR_FUNC_COUNT_SHIFT: u32 = 28;
pub const OCR_FUNC_COUNT_MASK: u32  = 0x7000_0000;

// ── CMD52 argument builder ─────────────────────────────────────────────
/// Build the 32-bit CMD52 argument word.
///
/// ```
/// 31    | 30-28 | 27  | 26 | 25-9  | 8 | 7-0
/// RW/RD | FN    | RAW | 0  | ADDR  | 0 | DATA
/// ```
#[inline]
pub const fn cmd52_arg(write: bool, func: u8, raw: bool, addr: u32, data: u8) -> u32 {
    let rw  = if write { 1u32 } else { 0u32 };
    let raw = if raw   { 1u32 } else { 0u32 };
    (rw << 31)
        | ((func as u32 & 0b111) << 28)
        | (raw << 27)
        | ((addr & 0x1_FFFF) << 9)
        | (data as u32)
}

// ── CMD53 argument builder ─────────────────────────────────────────────
/// Build the 32-bit CMD53 argument word.
///
/// ```
/// 31    | 30-28 | 27    | 26   | 25-9 | 8-0
/// RW/RD | FN    | BLOCK | INCR | ADDR | COUNT
/// ```
///
/// * `count` — bytes (byte mode) or blocks (block mode); 0 ≡ 512 bytes / "infinite" blocks.
#[inline]
pub const fn cmd53_arg(
    write: bool,
    func: u8,
    block_mode: bool,
    increment: bool,
    addr: u32,
    count: u16,
) -> u32 {
    let rw    = if write      { 1u32 } else { 0u32 };
    let block = if block_mode { 1u32 } else { 0u32 };
    let incr  = if increment  { 1u32 } else { 0u32 };
    (rw << 31)
        | ((func as u32 & 0b111) << 28)
        | (block << 27)
        | (incr << 26)
        | ((addr & 0x1_FFFF) << 9)
        | (count as u32 & 0x1FF)
}

// ── R5 response decoding ────────────────────────────────────────────────
/// Flags in the R5 response byte (CMD52 / CMD53 response).
pub const R5_COM_CRC_ERROR: u8  = 0x80;
pub const R5_ILLEGAL_COMMAND: u8 = 0x40;
pub const R5_ERROR: u8           = 0x08;
pub const R5_FUNCTION_NUM: u8    = 0x02;
pub const R5_OUT_OF_RANGE: u8    = 0x01;
pub const R5_IO_CURRENT_STATE_TRAN: u8 = 0x10; // bits [5:4] = 0b01 → Transfer

/// Decode the R5 flags from a raw 32-bit response word (bits[15:8]).
#[inline]
pub fn r5_flags(response: u32) -> u8 {
    ((response >> 8) & 0xFF) as u8
}

/// True if R5 indicates an error condition.
#[inline]
pub fn r5_is_error(flags: u8) -> bool {
    flags & (R5_COM_CRC_ERROR | R5_ILLEGAL_COMMAND | R5_ERROR
             | R5_FUNCTION_NUM | R5_OUT_OF_RANGE) != 0
}

/// Extract the read-data byte from an R5 response.
#[inline]
pub fn r5_data(response: u32) -> u8 {
    (response & 0xFF) as u8
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── CMD52 encode ───────────────────────────────────────────────────

    fn smoke_cmd52_read_fn0() -> TestResult {
        // Read from function 0, address 0x00 (CCCR).
        let arg = cmd52_arg(false, 0, false, 0x00, 0);
        if (arg >> 31) & 1 != 0 {
            return TestResult::Fail("read bit should be 0");
        }
        if (arg >> 28) & 0b111 != 0 {
            return TestResult::Fail("function should be 0");
        }
        if (arg >> 9) & 0x1_FFFF != 0 {
            return TestResult::Fail("address should be 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_cmd52_read_fn0);

    fn smoke_cmd52_write_fn0() -> TestResult {
        // Write 0x02 to CCCR IO_ENABLE (addr=0x02) on function 0.
        let arg = cmd52_arg(true, 0, false, 0x02, 0x02);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit should be 1");
        }
        if (arg >> 9) & 0x1_FFFF != 0x02 {
            return TestResult::Fail("address mismatch");
        }
        if arg & 0xFF != 0x02 {
            return TestResult::Fail("data byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_cmd52_write_fn0);

    fn smoke_cmd52_write_fn1() -> TestResult {
        // Write to function 1 — verify function field is encoded correctly.
        let arg = cmd52_arg(true, 1, false, 0x100, 0xAB);
        if (arg >> 28) & 0b111 != 1 {
            return TestResult::Fail("function should be 1");
        }
        if (arg >> 9) & 0x1_FFFF != 0x100 {
            return TestResult::Fail("address mismatch");
        }
        if arg & 0xFF != 0xAB {
            return TestResult::Fail("data byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_cmd52_write_fn1);

    // ── CMD53 encode ───────────────────────────────────────────────────

    fn smoke_cmd53_byte_mode_read() -> TestResult {
        // Read 64 bytes from function 1, address 0x000, auto-increment.
        let arg = cmd53_arg(false, 1, false, true, 0x000, 64);
        if (arg >> 31) & 1 != 0 {
            return TestResult::Fail("read bit should be 0");
        }
        if (arg >> 28) & 0b111 != 1 {
            return TestResult::Fail("function should be 1");
        }
        if (arg >> 27) & 1 != 0 {
            return TestResult::Fail("block-mode should be 0 for byte mode");
        }
        if arg & 0x1FF != 64 {
            return TestResult::Fail("count should be 64");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_cmd53_byte_mode_read);

    fn smoke_cmd53_block_mode_write() -> TestResult {
        // Write 8 blocks to function 2, address 0x000, fixed address (FIFO).
        let arg = cmd53_arg(true, 2, true, false, 0x000, 8);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit should be 1");
        }
        if (arg >> 28) & 0b111 != 2 {
            return TestResult::Fail("function should be 2");
        }
        if (arg >> 27) & 1 != 1 {
            return TestResult::Fail("block-mode should be 1");
        }
        if (arg >> 26) & 1 != 0 {
            return TestResult::Fail("op-increment should be 0 (FIFO)");
        }
        if arg & 0x1FF != 8 {
            return TestResult::Fail("count should be 8");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_cmd53_block_mode_write);

    // ── OCR decode ────────────────────────────────────────────────────

    fn smoke_ocr_voltage_decode_33v() -> TestResult {
        // A typical CMD5 R4 response with 3.3 V range + card-ready.
        let r4: u32 = OCR_CARD_READY | 0x00FF_8000;
        if r4 & OCR_CARD_READY == 0 {
            return TestResult::Fail("card-ready bit not set");
        }
        if r4 & OCR_S18A != 0 {
            return TestResult::Fail("1.8 V accepted should not be set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_ocr_voltage_decode_33v);

    fn smoke_ocr_voltage_decode_18v_switch() -> TestResult {
        // R4 with 1.8 V switch accepted.
        let r4: u32 = OCR_CARD_READY | OCR_S18A | 0x00FF_8000;
        if r4 & OCR_S18A == 0 {
            return TestResult::Fail("S18A bit should be set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_ocr_voltage_decode_18v_switch);

    fn smoke_r5_error_flags() -> TestResult {
        // A clean R5 in Transfer state has bits [5:4] == 0b01,
        // error bits all zero.
        let resp: u32 = 0x0000_1000; // state = Transfer, no error
        let flags = r5_flags(resp);
        if r5_is_error(flags) {
            return TestResult::Fail("clean R5 should not be an error");
        }
        // An R5 with FUNCTION_NUM bit set.
        let bad: u32 = 0x0000_0200; // R5_FUNCTION_NUM in bit[9] = flags byte
        if !r5_is_error(r5_flags(bad)) {
            return TestResult::Fail("R5 with FUNCTION_NUM should be an error");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/cmd", smoke_r5_error_flags);
}
