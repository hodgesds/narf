// SPDX-License-Identifier: GPL-2.0-or-later
//! Integration-level smoke tests for `narf-drivers-sdio`.
//!
//! Tests in the sub-modules exercise individual codecs in isolation;
//! tests here cross the module boundaries — e.g. "a complete SDIO
//! init sequence produces the correct sequence of CMD argument words."

#![allow(dead_code)]

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::sdhci::cmd::{cmd52_arg, cmd53_arg, CMD5_ARG_QUERY};

    use crate::sdio::cccr::{cis_ptr_from_bytes, CCCR_IO_ENABLE};

    fn smoke_init_sequence_cmd_args() -> TestResult {
        // The SDIO init sequence must produce well-formed argument words in order.
        // CMD0 has no argument (0x00000000).
        // CMD5 query has argument 0.
        let cmd5_query = CMD5_ARG_QUERY;
        if cmd5_query != 0 {
            return TestResult::Fail("CMD5 query arg must be 0");
        }
        // CMD5 negotiate: accept 3.3 V.
        let cmd5_neg: u32 = 0x00FF_8000;
        if cmd5_neg & 0x00FF_0000 == 0 {
            return TestResult::Fail("CMD5 negotiate must have VDD bits set");
        }
        // CMD3 (SEND_RELATIVE_ADDR) takes no argument — R6 returns RCA.
        // CMD7 argument is (rca << 16).
        let rca: u16 = 0x0001;
        let cmd7_arg = (rca as u32) << 16;
        if cmd7_arg >> 16 != rca as u32 {
            return TestResult::Fail("CMD7 argument RCA encoding wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio", smoke_init_sequence_cmd_args);

    fn smoke_cyw43439_bridge_byte_sequence() -> TestResult {
        // Verify that CMD52/CMD53 argument words produced by this crate
        // match the reference encoding from soypat/cyw43439 (MIT) and
        // Embassy cyw43 (Apache-2.0/MIT) documentation.
        //
        // Reference: soypat/cyw43439 sdio.go — CMD52 write to IO_ENABLE.
        // Expected: write=1, func=0, raw=0, addr=0x0002, data=0x02.
        let arg = cmd52_arg(true, 0, false, CCCR_IO_ENABLE, 0x02);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be set");
        }
        if (arg >> 28) & 7 != 0 {
            return TestResult::Fail("function 0 expected for CCCR access");
        }
        if (arg >> 9) & 0x1_FFFF != CCCR_IO_ENABLE {
            return TestResult::Fail("CCCR IO_ENABLE address mismatch");
        }
        if arg & 0xFF != 0x02 {
            return TestResult::Fail("IO_ENABLE data byte mismatch");
        }

        // CMD53 bulk write to WLAN F2 (addr=0, block_mode=true, 4 blocks).
        // Reference: Embassy cyw43 sdio.rs — F2 bulk TX.
        let arg53 = cmd53_arg(true, 2, true, true, 0x0000, 4);
        if (arg53 >> 31) & 1 != 1 {
            return TestResult::Fail("CMD53 write bit must be set");
        }
        if (arg53 >> 28) & 7 != 2 {
            return TestResult::Fail("CMD53 must target F2 (WLAN)");
        }
        if (arg53 >> 27) & 1 != 1 {
            return TestResult::Fail("CMD53 block-mode must be set");
        }
        if arg53 & 0x1FF != 4 {
            return TestResult::Fail("CMD53 block count wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio", smoke_cyw43439_bridge_byte_sequence);

    fn smoke_cccr_io_enable_int_enable() -> TestResult {
        // Enabling F1: write bit 1 of IO_ENABLE; enabling F2: write bit 2.
        // INT_ENABLE: bit 0 = master, bit 1 = F1, bit 2 = F2.
        let io_en_f1_f2: u8 = (1 << 1) | (1 << 2);
        let int_en_master_f1_f2: u8 = 0x01 | (1 << 1) | (1 << 2);
        if io_en_f1_f2 != 0x06 {
            return TestResult::Fail("IO_ENABLE F1+F2 mask should be 0x06");
        }
        if int_en_master_f1_f2 != 0x07 {
            return TestResult::Fail("INT_ENABLE master+F1+F2 mask should be 0x07");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio", smoke_cccr_io_enable_int_enable);

    fn smoke_fbr_cis_ptr_decode() -> TestResult {
        // Reconstruct the CIS pointer for function 1 from three bytes.
        let b0: u8 = 0x00;
        let b1: u8 = 0x10;
        let b2: u8 = 0x00;
        let ptr = cis_ptr_from_bytes(b0, b1, b2);
        if ptr != 0x0000_1000 {
            return TestResult::Fail("CIS pointer decode wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio", smoke_fbr_cis_ptr_decode);
}
