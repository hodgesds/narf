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
    fail_at: Option<u32>,
}

impl Fake {
    fn new() -> Self {
        Self {
            regs: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
            fail_at: None,
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
        if self.fail_at == Some(address) {
            return Err(power::Error::Access);
        }
        self.reads.push(address);
        Ok(self.get(address))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        if self.fail_at == Some(address) {
            return Err(power::Error::Access);
        }
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

fn smoke_rtw89_be_irq_events_classify() -> TestResult {
    // Expected values are computed here from the Linux `pci_be.c:868`
    // `rtw89_pci_isr_be` bit positions, never from the module under test.
    // Full house: RX0P2 + RPQ0 in the DMA word, RDU CH0 in the HAXI
    // word, HALT + WDT in the halt word.
    let busy = IsrsBe {
        ind: (1 << 0) | (1 << 5),
        halt_c2h: (1 << 21) | (1 << 22),
        isrs: [(1 << 25), (1 << 16) | (1 << 17)],
    }
    .events();
    if !busy.rx
        || !busy.rpq
        || !busy.rx_unavailable
        || !busy.halt_c2h
        || !busy.watchdog
        || !busy.fatal()
    {
        return TestResult::Fail("BE v2 event classification wrong for full house");
    }
    // RDU alone polls RX without being fatal (threadfn's `isr_rdu`
    // branch runs before the NAPI schedule, not the SER path).
    let rdu = IsrsBe {
        ind: 1 << 5,
        halt_c2h: 0,
        isrs: [(1 << 26), 0],
    }
    .events();
    if rdu.rx || rdu.rpq || !rdu.rx_unavailable || rdu.fatal() {
        return TestResult::Fail("BE v2 RDU must poll RX without being fatal");
    }
    // RPQ alone: only the RPQ drain is scheduled.
    let rpq = IsrsBe {
        ind: 1 << 5,
        halt_c2h: 0,
        isrs: [0, 1 << 17],
    }
    .events();
    if !rpq.rpq || rpq.rx || rpq.rx_unavailable || rpq.fatal() {
        return TestResult::Fail("BE v2 RPQ-only classification wrong");
    }
    // Bits outside the `rtw89_pci_isr_be` sources classify as nothing:
    // no stuck source exists for v2, and DMA bit 7 is not RX0P2/RPQ0.
    let noise = IsrsBe {
        ind: 0,
        halt_c2h: 1 << 3,
        isrs: [1 << 2, 1 << 7],
    }
    .events();
    if noise.rx
        || noise.rpq
        || noise.rx_unavailable
        || noise.stuck
        || noise.halt_c2h
        || noise.watchdog
        || noise.fatal()
    {
        return TestResult::Fail("BE v2 unrecognized bits must classify as no events");
    }
    // Quiet device: nothing pending, nothing fatal.
    if IsrsBe::default().events() != super::irq::Events::default() {
        return TestResult::Fail("BE v2 quiet device must report default events");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_irq_events_classify);

fn smoke_rtw89_be_irq_service_masks_then_rearms() -> TestResult {
    let m = MaskBe::config(false, false);
    let mut fake = Fake::new();
    if m.enable(&mut fake).is_err() || fake.get(R_BE_PCIE_HIMR0) != m.ind {
        return TestResult::Fail("BE v2 enable did not program PCIE_HIMR0");
    }
    fake.writes.clear();
    fake.set(R_BE_PCIE_HISR, (1 << 0) | (1 << 5));
    fake.set(R_BE_HISR0, 0);
    fake.set(R_BE_HAXI_HISR00, 0);
    fake.set(R_BE_PCIE_DMA_ISR, 1 << 17);
    // Same sequence as BindingBe::service, independent of a PCI function.
    if MaskBe::disable(&mut fake).is_err() {
        return TestResult::Fail("BE v2 service disable failed");
    }
    let Ok(isrs) = m.recognize(&mut fake) else {
        return TestResult::Fail("BE v2 service recognize failed");
    };
    let order: Vec<u32> = fake.writes.iter().map(|(a, _)| *a).collect();
    if order.get(..2) != Some(&[R_BE_PCIE_HIMR0, R_BE_PCIE_DMA_IMR_0_V1][..])
        || fake.writes.iter().take(2).any(|(_, v)| *v != 0)
        || !isrs.events().rpq
    {
        return TestResult::Fail("BE v2 service did not mask before acknowledging");
    }
    if m.enable(&mut fake).is_err()
        || fake.get(R_BE_HIMR0) != m.halt_c2h
        || fake.get(R_BE_PCIE_DMA_IMR_0_V1) != m.intrs[1]
    {
        return TestResult::Fail("BE v2 rearm did not restore the mask");
    }
    let mut broken = Fake::new();
    broken.fail_at = Some(R_BE_PCIE_DMA_ISR);
    if m.recognize(&mut broken).is_ok() {
        return TestResult::Fail("BE v2 register failure was swallowed");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_irq_service_masks_then_rearms
);
