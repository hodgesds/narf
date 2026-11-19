// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the RTL8922AE PCIe `mac_pre_init` programs.
//! Expected words come from the `pci_be.c` / `reg.h` / `pci.h`
//! literals, not from the module under test.

use super::*;
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Model {
    regs: BTreeMap<u32, u32>,
}

impl Model {
    fn get(&self, addr: u32) -> u32 {
        *self.regs.get(&addr).unwrap_or(&0)
    }
}

impl Regs for Model {
    fn read32(&mut self, address: u32) -> u32 {
        self.get(address)
    }
    fn write32(&mut self, address: u32, value: u32) {
        self.regs.insert(address, value);
    }
    fn write16(&mut self, address: u32, value: u16) {
        self.regs.insert(address, u32::from(value));
    }
}

fn smoke_rtw89_8922a_pci_pre_init_settings() -> TestResult {
    // io_rcy: ANA_172US (0x800) on the eight analog timers, MAC_1MS
    // (0x27100) on WLAN/AXIDMA, AUX_1MS (0x1E848) on LOCAL.
    let mut m = Model::default();
    io_rcy(&mut m);
    for addr in [
        0x306C, 0x3090, 0x309C, 0x3144, 0x3150, 0x315C, 0x3164, 0x316C,
    ] {
        if m.get(addr) != 0x800 {
            return TestResult::Fail("analog IO-recovery timer must be 0x800");
        }
    }
    if m.get(0x3054) != 0x27100 || m.get(0x3060) != 0x27100 || m.get(0x3084) != 0x1E848 {
        return TestResult::Fail("WLAN/AXIDMA/LOCAL IO-recovery timers");
    }
    // power wake: HCI_OPT_CTRL (0x74) bit 23.
    power_wake(&mut m, true);
    if m.get(0x0074) != 1 << 23 {
        return TestResult::Fail("power wake must set BIT_WAKE_CTRL_V1");
    }
    // CBV (cv 1): debounce + LDO + full PCIe setting + CAV/CBV SER arm.
    let mut m = Model::default();
    m.regs.insert(0x000C, 0b11 << 22);
    m.regs.insert(0x0070, (1 << 15) | (1 << 14) | (1 << 12) | 1);
    m.regs.insert(0x3110, 1);
    m.regs.insert(0x3008, 1 << 7);
    m.regs.insert(0x34A8, (1 << 31) | (0b111 << 17));
    m.regs.insert(0x34B0, 0x3f);
    m.regs.insert(0x3120, 0xdead);
    settings(&mut m, 1);
    if m.get(0x000C) != (1 << 24) | (1 << 21) | (1 << 20) | (1 << 18) {
        return TestResult::Fail("SYS_PAGE_CLK_GATED debounce/LDO bits");
    }
    if m.get(0x0004) != 1 << 14 || m.get(0x0070) != 1 || m.get(0x3110) != 0 {
        return TestResult::Fail("LDO low-power writes");
    }
    if m.get(0x3004) != 1
        || m.get(0x3008) != 0
        || m.get(0x00A4) != 1 << 24
        || m.get(0x3044) != 1 << 15
    {
        return TestResult::Fail("non-CAV PCIe setting writes");
    }
    if m.get(0x3120) != 0 || m.get(0x34A8) != 0b010 << 17 || m.get(0x34B0) != 0 {
        return TestResult::Fail("CAV/CBV SER arm: SER off, unit 2, all PL1 IMRs masked");
    }
    // CAV (cv 0) stops the PCIe setting after FRZ_CLK / PS_CTRL.
    let mut m = Model::default();
    pcie_setting(&mut m, 0);
    if m.get(0x3004) != 1 || m.regs.contains_key(&0x00A4) || m.regs.contains_key(&0x3044) {
        return TestResult::Fail("CAV must skip the autoload/aux-clock writes");
    }
    // CCV (cv 2): SER enabled with unit 2; IMRs on except L1SUB.
    let mut m = Model::default();
    m.regs.insert(0x34B0, 1 << 1);
    if !ser_setting(&mut m, 2) {
        return TestResult::Fail("clear PL1 ISR must report cleared");
    }
    if m.get(0x34A8) != (1 << 31) | (0b010 << 17) || m.get(0x34B0) != 0b11_1101 {
        return TestResult::Fail("CCV SER arm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_pci_pre_init_settings
);
