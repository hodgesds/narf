// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture tests for the BE v2 interrupt mask. Expected values are
//! computed in the test from the Linux `pci.c`/`pci.h`/`reg.h` bit
//! positions, never from the module under test.

use super::irq::Regs;
use super::irq_be::*;
use super::power;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: Vec<(u32, u32)>,
    reads: Vec<u32>,
    writes: Vec<(u32, u32)>,
}

impl Fake {
    fn new() -> Self {
        Self {
            regs: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
        }
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
        self.reads.push(address);
        Ok(self.get(address))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.writes.push((address, value));
        self.set(address, value);
        Ok(())
    }
}

fn smoke_rtw89_be_irq_mask_config() -> TestResult {
    // Default: ind = AXIDMA_EN0 | HS0_EN0, halt = HALT | WDT,
    // intrs[0] = RDU_CH1 | RDU_CH0, intrs[1] = RX0P2 | RPQ0.
    let m = MaskBe::config(false, false);
    if m.ind != (1 << 5) | (1 << 0)
        || m.halt_c2h != (1 << 21) | (1 << 22)
        || m.intrs[0] != (1 << 26) | (1 << 25)
        || m.intrs[1] != (1 << 16) | (1 << 17)
    {
        return TestResult::Fail("BE v2 default mask wrong");
    }
    // Low-power: HS0 | HS1, intrs[0] = 0, intrs[1] unchanged.
    let m = MaskBe::config(false, true);
    if m.ind != (1 << 0) | (1 << 1)
        || m.halt_c2h != (1 << 21) | (1 << 22)
        || m.intrs[0] != 0
        || m.intrs[1] != (1 << 16) | (1 << 17)
    {
        return TestResult::Fail("BE v2 low-power mask wrong");
    }
    // Recovery: ind = HS0 only, both intrs zero.
    let m = MaskBe::config(true, false);
    if m.ind != (1 << 0) || m.intrs != [0, 0] {
        return TestResult::Fail("BE v2 recovery mask wrong");
    }
    // Recovery takes precedence over low-power, as in Linux.
    let m = MaskBe::config(true, true);
    if m.ind != (1 << 0) || m.intrs != [0, 0] {
        return TestResult::Fail("BE v2 recovery must win over low-power");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_irq_mask_config);

fn smoke_rtw89_be_irq_enable_disable() -> TestResult {
    let m = MaskBe::config(false, false);
    let mut fake = Fake::new();
    if m.enable(&mut fake).is_err() {
        return TestResult::Fail("BE v2 enable failed");
    }
    // Linux's write order: HIMR0, HAXI_HIMR00, DMA_IMR_0_V1, PCIE_HIMR0.
    if fake.writes
        != [
            (R_BE_HIMR0, m.halt_c2h),
            (R_BE_HAXI_HIMR00, m.intrs[0]),
            (R_BE_PCIE_DMA_IMR_0_V1, m.intrs[1]),
            (R_BE_PCIE_HIMR0, m.ind),
        ]
    {
        return TestResult::Fail("BE v2 enable write order/values wrong");
    }
    fake.writes.clear();
    if MaskBe::disable(&mut fake).is_err() {
        return TestResult::Fail("BE v2 disable failed");
    }
    // Faithful asymmetry: only the indirect enable and DMA IMR clear.
    if fake.writes != [(R_BE_PCIE_HIMR0, 0), (R_BE_PCIE_DMA_IMR_0_V1, 0)] {
        return TestResult::Fail("BE v2 disable must clear only HIMR0 + DMA IMR");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_irq_enable_disable);

fn smoke_rtw89_be_irq_recognize() -> TestResult {
    let m = MaskBe::config(false, false);
    let mut fake = Fake::new();
    // Indirect status has both gating bits; halt + HAXI + DMA pending.
    fake.set(R_BE_PCIE_HISR, (1 << 0) | (1 << 5) | (1 << 9));
    fake.set(R_BE_HISR0, (1 << 21) | (1 << 22) | (1 << 3));
    fake.set(R_BE_HAXI_HISR00, (1 << 25) | (1 << 2));
    fake.set(R_BE_PCIE_DMA_ISR, (1 << 16) | (1 << 7));
    let isrs = match m.recognize(&mut fake) {
        Ok(isrs) => isrs,
        Err(_) => return TestResult::Fail("BE v2 recognize failed"),
    };
    // Only masked bits survive; bit 9 of the indirect word is not in
    // the mask, and unmasked pending bits are left for their owner.
    if isrs.ind != (1 << 0) | (1 << 5)
        || isrs.halt_c2h != (1 << 21) | (1 << 22)
        || isrs.isrs[0] != (1 << 25)
        || isrs.isrs[1] != (1 << 16)
    {
        return TestResult::Fail("BE v2 recognize masked values wrong");
    }
    // Acks: nonzero fields written back; indirect always written back.
    // The ack writes land after the reads in the write log.
    let acks = &fake.writes[fake.writes.len() - 4..];
    if acks
        != [
            (R_BE_HISR0, (1 << 21) | (1 << 22)),
            (R_BE_HAXI_HISR00, (1 << 25)),
            (R_BE_PCIE_DMA_ISR, (1 << 16)),
            (R_BE_PCIE_HISR, (1 << 0) | (1 << 5)),
        ]
    {
        return TestResult::Fail("BE v2 recognize ack writes wrong");
    }
    // Gating: with no indirect bits set, the HAXI/HALT registers must
    // not even be read, and the DMA status is still read.
    let mut fake = Fake::new();
    fake.set(R_BE_PCIE_HISR, 0);
    fake.set(R_BE_HISR0, 0xFFFF_FFFF);
    fake.set(R_BE_HAXI_HISR00, 0xFFFF_FFFF);
    fake.set(R_BE_PCIE_DMA_ISR, 1 << 17);
    let isrs = match m.recognize(&mut fake) {
        Ok(isrs) => isrs,
        Err(_) => return TestResult::Fail("BE v2 gated recognize failed"),
    };
    if isrs.ind != 0 || isrs.halt_c2h != 0 || isrs.isrs[0] != 0 || isrs.isrs[1] != (1 << 17) {
        return TestResult::Fail("BE v2 gated recognize must skip HAXI/HALT reads");
    }
    if fake.reads.contains(&R_BE_HISR0) || fake.reads.contains(&R_BE_HAXI_HISR00) {
        return TestResult::Fail("BE v2 recognize read a gated register");
    }
    if !fake.reads.contains(&R_BE_PCIE_DMA_ISR) {
        return TestResult::Fail("BE v2 recognize must always read DMA status");
    }
    // Only the DMA ack + the unconditional indirect ack are written.
    if fake.writes != [(R_BE_PCIE_DMA_ISR, 1 << 17), (R_BE_PCIE_HISR, 0)] {
        return TestResult::Fail("BE v2 gated recognize ack writes wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_irq_recognize);
