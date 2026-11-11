// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture tests for RTL8852A NHM noise monitoring. Expected values are
//! Linux literals (`rtw8852a.c` / `reg.h` / `phy.c` @ 05441d6), written
//! out in the test, never read from the module under test — except
//! where the test independently recomputes a positioned value from a
//! field value plus its mask.

use super::irq::Regs;
use super::nhm::*;
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

fn smoke_rtw89_nhm_tables() -> TestResult {
    if !SUPPORT_NOISE_8852A {
        return TestResult::Fail("8852A must support noise");
    }
    if NHM_TH_NUM != 11 || NHM_RPT_NUM != 12 {
        return TestResult::Fail("NHM table sizes wrong");
    }
    // Threshold table, verbatim from rtw8852a.c:484..496.
    let th = [
        (0x0C08u32, 0xFF00_0000u32),
        (0x0C0Cu32, 0x0000_00FFu32),
        (0x0C0Cu32, 0x0000_FF00u32),
        (0x0C0Cu32, 0x00FF_0000u32),
        (0x0C0Cu32, 0xFF00_0000u32),
        (0x0C10u32, 0x0000_00FFu32),
        (0x0C10u32, 0x0000_FF00u32),
        (0x0C10u32, 0x00FF_0000u32),
        (0x0C10u32, 0xFF00_0000u32),
        (0x0C14u32, 0x0000_00FFu32),
        (0x0C14u32, 0x0000_FF00u32),
    ];
    for i in 0..NHM_TH_NUM {
        if NHM_TH[i].addr != th[i].0 || NHM_TH[i].mask != th[i].1 {
            return TestResult::Fail("NHM threshold table wrong");
        }
    }
    // Report table, verbatim from rtw8852a.c:498..512.
    let rpt = [
        (0x1A88u32, 0x0000_FFFFu32),
        (0x1A88u32, 0xFFFF_0000u32),
        (0x1A8Cu32, 0x0000_FFFFu32),
        (0x1A8Cu32, 0xFFFF_0000u32),
        (0x1A90u32, 0x0000_FFFFu32),
        (0x1A90u32, 0xFFFF_0000u32),
        (0x1A94u32, 0x0000_FFFFu32),
        (0x1A94u32, 0xFFFF_0000u32),
        (0x1A98u32, 0x0000_FFFFu32),
        (0x1A98u32, 0xFFFF_0000u32),
        (0x1A9Cu32, 0x0000_FFFFu32),
        (0x1A9Cu32, 0xFFFF_0000u32),
    ];
    for i in 0..NHM_RPT_NUM {
        if NHM_RPT[i].addr != rpt[i].0 || NHM_RPT[i].mask != rpt[i].1 {
            return TestResult::Fail("NHM report table wrong");
        }
    }
    // Control registers, AX CCX block + reg.h.
    if R_NHM_CFG != 0x0C08
        || B_NHM_PERIOD_MSK != 0xFFFF
        || B_NHM_COUNTER_MSK != (0x3 << 16)
        || B_NHM_EN_MSK != (1 << 18)
        || B_NHM_INCLUDE_CCA_MSK != (1 << 19)
        || R_NHM_AX != 0x1AA4
        || B_NHM_READY_MSK != (1 << 16)
        || B_NHM_PWDB_METHOD_MSK != (0x3 << 16)
    {
        return TestResult::Fail("NHM control registers wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_nhm_thresholds_and_average() -> TestResult {
    // 11k defaults shifted by 1, with the 8852A/B/C workaround override.
    if th_values(true) != [36, 42, 48, 54, 60, 70, 80, 90, 100, 110, 218, 0] {
        return TestResult::Fail("NHM WA thresholds wrong");
    }
    if th_values(false) != [36, 42, 48, 54, 60, 70, 80, 90, 100, 110, 120, 0] {
        return TestResult::Fail("NHM plain thresholds wrong");
    }
    // Empty sum yields 0 without touching results.
    let mut state = NhmState::new();
    state.th = th_values(true);
    state.result = [7; NHM_RPT_NUM];
    if weighted_avg(&mut state) != 0 || state.result != [7; NHM_RPT_NUM] {
        return TestResult::Fail("NHM empty-sum average wrong");
    }
    // Hand-computed WA case: every counter 10, WA thresholds. Weights
    // 34, 39, 45, 51, 57, 65, 75, 85, 95, 105, 112, 112 (last two
    // overridden from 164/220); fold moves counter 11 into counter 0,
    // so weight 11 multiplies a zero counter (phy.c
    // `rtw89_nhm_weighted_avg`). (20*34 + 10*(39+45+51+57+65+75+85
    // +95+105+112)) / 120 >> 1 = (680 + 7290) / 120 >> 1 = 33.
    let mut state = NhmState::new();
    state.th = th_values(true);
    state.result = [10; NHM_RPT_NUM];
    state.sum = 120;
    if weighted_avg(&mut state) != 33 {
        return TestResult::Fail("NHM WA weighted average wrong");
    }
    if state.result[0] != 20 || state.result[NHM_RPT_NUM - 1] != 0 {
        return TestResult::Fail("NHM WA fold wrong");
    }
    // Non-WA case: same counters, plain thresholds. Weights 34, 39, 45,
    // 51, 57, 65, 75, 85, 95, 105, 115, 122 (last = th[10]+2 = 122);
    // fold still applies on this path, zeroing counter 11.
    // (20*34 + 10*(39+45+51+57+65+75+85+95+105+115)) / 120 >> 1 =
    // (680 + 7320) / 120 >> 1 = 33.
    let mut state = NhmState::new();
    state.th = th_values(false);
    state.result = [10; NHM_RPT_NUM];
    state.sum = 120;
    if weighted_avg(&mut state) != 33 {
        return TestResult::Fail("NHM plain weighted average wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_nhm_period_units() -> TestResult {
    if ms_to_period_unit(40) != (10000, 0) {
        return TestResult::Fail("NHM 40ms period wrong");
    }
    if ms_to_period_unit(262) != (65500, 0) {
        return TestResult::Fail("NHM 262ms period wrong");
    }
    if ms_to_period_unit(263) != (32875, 1) {
        return TestResult::Fail("NHM 263ms period wrong");
    }
    // Clamp: 3000ms -> 2097ms, quotient 32 -> 32us unit.
    if ms_to_period_unit(3000) != (65531, 3) {
        return TestResult::Fail("NHM clamp period wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_nhm_init_and_trigger() -> TestResult {
    // setting_init preserves unrelated bits and sets EN + PWDB bits.
    let mut io = Fake::new();
    io.set(R_NHM_CFG, 0xFF00_0000);
    io.set(R_NHM_TH9, 0x0000_00FF);
    let mut state = NhmState::new();
    if setting_init(&mut io, &mut state).is_err() {
        return TestResult::Fail("NHM setting_init failed");
    }
    if io.get(R_NHM_CFG) != 0xFF04_0000 || io.get(R_NHM_TH9) != 0x0003_00FF {
        return TestResult::Fail("NHM setting_init bits wrong");
    }
    if state.include_cca || state.mntr_time_ms != 0 || state.sum != 0 {
        return TestResult::Fail("NHM setting_init state wrong");
    }
    // Zero monitor time is rejected.
    if set_params(&mut io, &mut state, 0, true) != Err(Error::InvalidMonitorTime) {
        return TestResult::Fail("NHM zero monitor time accepted");
    }
    // Full trigger on zeroed registers. CFG = TH0 field (36<<24 =
    // 0x2400_0000) | period 10000 (0x2710) | unit field (Linux writes
    // `period` there: (10000 << 16) & GENMASK(17, 16) = 0) | EN (bit
    // 18) | INCLUDE_CCA (bit 19).
    let mut io = Fake::new();
    let mut state = NhmState::new();
    if trigger(&mut io, &mut state).is_err() {
        return TestResult::Fail("NHM trigger failed");
    }
    if io.get(R_NHM_CFG) != 0x240C_2710 {
        return TestResult::Fail("NHM trigger CFG word wrong");
    }
    // TH1 = 42 | 48<<8 | 54<<16 | 60<<24; TH5 = 70 | 80<<8 | 90<<16 |
    // 100<<24; TH9 = 110 | 218<<8 (PWDB bits only come from setting_init).
    if io.get(R_NHM_TH1) != 0x3C36_302A
        || io.get(R_NHM_TH5) != 0x645A_5046
        || io.get(R_NHM_TH9) != 0x0000_DA6E
    {
        return TestResult::Fail("NHM trigger threshold words wrong");
    }
    if !state.include_cca
        || state.mntr_time_ms != 40
        || state.period != 10000
        || state.unit_idx != 0
        || !state.ccx_ongoing
        || state.th != th_values(true)
    {
        return TestResult::Fail("NHM trigger state wrong");
    }
    // setting_init then trigger: TH9 gains the PWDB bits.
    let mut io = Fake::new();
    let mut state = NhmState::new();
    if setting_init(&mut io, &mut state).is_err() || trigger(&mut io, &mut state).is_err() {
        return TestResult::Fail("NHM init+trigger failed");
    }
    if io.get(R_NHM_TH9) != 0x0003_DA6E {
        return TestResult::Fail("NHM init+trigger TH9 word wrong");
    }
    // Racing arbitration.
    let mut state = NhmState::new();
    if racing_ctrl(&mut state, 5) != Err(Error::RacingConflict) {
        return TestResult::Fail("NHM racing level ceiling wrong");
    }
    if racing_ctrl(&mut state, 1).is_err() {
        return TestResult::Fail("NHM racing level 1 rejected");
    }
    state.ccx_ongoing = true;
    if racing_ctrl(&mut state, 1) != Err(Error::RacingConflict) {
        return TestResult::Fail("NHM racing lower-or-equal level accepted");
    }
    if racing_ctrl(&mut state, 2).is_err() || state.ccx_ongoing {
        return TestResult::Fail("NHM racing higher level wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_nhm_get_result() -> TestResult {
    // Not ready -> None, state untouched.
    let mut io = Fake::new();
    let mut state = NhmState::new();
    state.th = th_values(true);
    if get_result(&mut io, &mut state) != Ok(None) {
        return TestResult::Fail("NHM not-ready result wrong");
    }
    // Ready with every counter 10: same WA arithmetic as the pure case.
    let mut io = Fake::new();
    io.set(R_NHM_AX, 1 << 16);
    for addr in [
        R_NHM_CNT0,
        R_NHM_CNT2,
        R_NHM_CNT4,
        R_NHM_CNT6,
        R_NHM_CNT8,
        R_NHM_CNT10,
    ] {
        io.set(addr, 10 | (10 << 16));
    }
    let mut state = NhmState::new();
    state.th = th_values(true);
    if get_result(&mut io, &mut state) != Ok(Some(33)) {
        return TestResult::Fail("NHM get_result noise wrong");
    }
    if state.sum != 120 || state.result[0] != 20 || state.result[NHM_RPT_NUM - 1] != 0 {
        return TestResult::Fail("NHM get_result state wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_nhm_tables);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_nhm_thresholds_and_average
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_nhm_period_units);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_nhm_init_and_trigger);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_nhm_get_result);
