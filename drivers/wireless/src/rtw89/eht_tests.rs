// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture tests for RTL8922A EHT width programming and PHY programs.
//! Expected values are Linux literals (`rtw8922a.c` / `reg.h` @
//! cbbddb6), written out in the test, never read from the module
//! under test — except where the test independently recomputes a
//! positioned value from a field value plus its mask.

use super::eht::*;
use super::irq::Regs;
use super::power;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: Vec<(u32, u32)>,
}

impl Fake {
    fn new() -> Self {
        Self { regs: Vec::new() }
    }
    fn set(&mut self, addr: u32, val: u32) {
        if let Some(slot) = self.regs.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = val;
        } else {
            self.regs.push((addr, val));
        }
    }
    fn get(&self, addr: u32) -> u32 {
        self.regs
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
}

impl Regs for Fake {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        Ok(self.get(address))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.set(address, value);
        Ok(())
    }
}

fn smoke_rtw89_eht_width_tables() -> TestResult {
    // Widths in MHz.
    if Width::Mhz20.mhz() != 20
        || Width::Mhz40.mhz() != 40
        || Width::Mhz80.mhz() != 80
        || Width::Mhz160.mhz() != 160
        || Width::Mhz320.mhz() != 320
    {
        return TestResult::Fail("EHT width MHz table wrong");
    }
    // RFMOD: 20->0, 40->1, 80->2, 160->3, 320->None (no Linux arm).
    if rfmod_value(Width::Mhz20) != Some(0)
        || rfmod_value(Width::Mhz40) != Some(1)
        || rfmod_value(Width::Mhz80) != Some(2)
        || rfmod_value(Width::Mhz160) != Some(3)
        || rfmod_value(Width::Mhz320).is_some()
    {
        return TestResult::Fail("EHT RFMOD table wrong");
    }
    if R_BE_WMAC_RFMOD != 0x10010
        || B_BE_WMAC_RFMOD_MASK != 0x7
        || R_BE_TX_SUB_BAND_VALUE != 0x10088
    {
        return TestResult::Fail("EHT RFMOD register/mask wrong");
    }
    // SIFS pairs: 20 -> (0x3f, 0x3e); 40/80/160/320 -> (0x41, 0x41).
    if sifs_values(Width::Mhz20) != (0x3F, 0x3E)
        || sifs_values(Width::Mhz40) != (0x41, 0x41)
        || sifs_values(Width::Mhz80) != (0x41, 0x41)
        || sifs_values(Width::Mhz160) != (0x41, 0x41)
        || sifs_values(Width::Mhz320) != (0x41, 0x41)
    {
        return TestResult::Fail("EHT SIFS table wrong");
    }
    if R_BE_PREBKF_CFG_1 != 0x1033C
        || B_BE_SIFS_MACTXEN_T1_MASK != 0x7F
        || R_BE_MUEDCA_EN != 0x10370
        || B_BE_SIFS_MACTXEN_TB_T1_MASK != (0x7F << 16)
    {
        return TestResult::Fail("EHT SIFS register/mask wrong");
    }
    // CFGCH codes 0..4 and fields positioned in bits 12..10.
    if cfgch_bw_code(Width::Mhz20) != 0
        || cfgch_bw_code(Width::Mhz40) != 1
        || cfgch_bw_code(Width::Mhz80) != 2
        || cfgch_bw_code(Width::Mhz160) != 3
        || cfgch_bw_code(Width::Mhz320) != 4
        || RR_CFGCH_BW_V2 != (0x7 << 10)
        || cfgch_bw_field(Width::Mhz320) != (4 << 10)
        || cfgch_bw_field(Width::Mhz80) != (2 << 10)
    {
        return TestResult::Fail("EHT CFGCH table wrong");
    }
    // BB class: <=40 narrow, >=80 wide.
    if bb_bw_class(Width::Mhz20) != BbBwClass::Narrow20_40
        || bb_bw_class(Width::Mhz40) != BbBwClass::Narrow20_40
        || bb_bw_class(Width::Mhz80) != BbBwClass::Wide80_160_320
        || bb_bw_class(Width::Mhz160) != BbBwClass::Wide80_160_320
        || bb_bw_class(Width::Mhz320) != BbBwClass::Wide80_160_320
    {
        return TestResult::Fail("EHT BB class table wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_bb_postinit_program() -> TestResult {
    // Register addresses and masks, from reg.h, independent of the
    // module's program table.
    if R_SLOPE != 0x6B6C
        || B_EHT_RATE_TH != (0xF << 28)
        || R_BEDGE != 0x6BFC
        || B_EHT_MCS14 != (1 << 31)
        || R_BEDGE2 != 0x6C00
        || B_EHT_MCS15 != (1 << 31)
        || R_BEDGE3 != 0x6C04
        || B_EHTTB_EN != (1 << 15)
    {
        return TestResult::Fail("EHT bb_postinit register/mask wrong");
    }
    // Masking-defeating case: preseed every target register with all
    // bits set, so a whole-register write (instead of a masked write)
    // would be visible, and a wrong field position would be visible.
    let mut io = Fake::new();
    io.set(R_SLOPE, u32::MAX);
    io.set(R_BEDGE, u32::MAX);
    io.set(R_BEDGE2, u32::MAX);
    io.set(R_BEDGE3, u32::MAX);
    if apply_program(&mut io, &BB_POSTINIT_EHT).is_err() {
        return TestResult::Fail("EHT bb_postinit apply failed");
    }
    // Field values positioned from Linux: rate threshold 0xA in bits
    // 31..28; MCS14/MCS15 bits set; EHTTB bit cleared.
    if io.get(R_SLOPE) != (0xA << 28) | 0x0FFF_FFFF
        || io.get(R_BEDGE) != u32::MAX
        || io.get(R_BEDGE2) != u32::MAX
        || io.get(R_BEDGE3) != u32::MAX & !(1 << 15)
    {
        return TestResult::Fail("EHT bb_postinit apply wrong");
    }
    // Zero-start case: only the programmed fields appear.
    let mut io = Fake::new();
    if apply_program(&mut io, &BB_POSTINIT_EHT).is_err() {
        return TestResult::Fail("EHT bb_postinit apply failed");
    }
    if io.get(R_SLOPE) != (0xA << 28)
        || io.get(R_BEDGE) != (1 << 31)
        || io.get(R_BEDGE2) != (1 << 31)
        || io.get(R_BEDGE3) != 0
    {
        return TestResult::Fail("EHT bb_postinit zero-start wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_rx_nss_program() -> TestResult {
    if R_BRK_EHT != 0x0474
        || B_RXEHT_NSS_MAX != (0x7 << 2)
        || R_BRK_RXEHT != 0x0478
        || B_RXEHTTB_NSS_MAX != (0x7 << 14)
        || B_RXEHT_N_USER_MAX != (0xFF << 24)
        || HE_N_USER_MAX_8922A != 4
    {
        return TestResult::Fail("EHT rx_nss register/mask wrong");
    }
    // Rejected counts mirror Linux's -EINVAL arm.
    if rx_nss_eht_program(0).is_some() || rx_nss_eht_program(3).is_some() {
        return TestResult::Fail("EHT rx_nss rejects wrong counts");
    }
    // 1 stream: NSS fields 0, user max 4.
    let mut io = Fake::new();
    let prog = rx_nss_eht_program(1).unwrap();
    if apply_program(&mut io, &prog).is_err() {
        return TestResult::Fail("EHT rx_nss(1) apply failed");
    }
    if io.get(R_BRK_EHT) != 0 || io.get(R_BRK_RXEHT) != (4 << 24) {
        return TestResult::Fail("EHT rx_nss(1) wrong");
    }
    // 2 streams: NSS fields 1 (positioned), user max 4.
    let mut io = Fake::new();
    let prog = rx_nss_eht_program(2).unwrap();
    if apply_program(&mut io, &prog).is_err() {
        return TestResult::Fail("EHT rx_nss(2) apply failed");
    }
    if io.get(R_BRK_EHT) != (1 << 2) || io.get(R_BRK_RXEHT) != (1 << 14) | (4 << 24) {
        return TestResult::Fail("EHT rx_nss(2) wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_operation_profile() -> TestResult {
    if !EHT_8922A.width_320 || EHT_8922A.max_mpdu_len != 7991 {
        return TestResult::Fail("EHT operation profile wrong");
    }
    if R_CNT_EHT_CRC != 0x2F00 || B_CNT_EHT_CRC_OK != 0xFFFF || B_CNT_EHT_CRC_ERR != (0xFFFF << 16)
    {
        return TestResult::Fail("EHT CRC counter block wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_width_tables);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_eht_bb_postinit_program
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_rx_nss_program);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_operation_profile);
