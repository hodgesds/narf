// SPDX-License-Identifier: GPL-2.0-or-later
//! AX interrupt mask/recognize programs and line/vector ownership.
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::AtomicUsize;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Register file with AX write-1-clear HISR semantics.
#[derive(Default)]
struct Model {
    regs: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    fail_at: Option<u32>,
}
impl Model {
    fn get(&self, address: u32) -> u32 {
        *self.regs.get(&address).unwrap_or(&0)
    }
}
impl Regs for Model {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        if self.fail_at == Some(address) {
            return Err(power::Error::Access);
        }
        Ok(*self.regs.get(&address).unwrap_or(&0))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        if self.fail_at == Some(address) {
            return Err(power::Error::Access);
        }
        self.writes.push((address, value));
        let entry = self.regs.entry(address).or_insert(0);
        if matches!(address, R_AX_HISR0 | R_AX_PCIE_HISR00 | R_AX_PCIE_HISR10) {
            *entry &= !value;
        } else {
            *entry = value;
        }
        Ok(())
    }
}

fn smoke_rtw89_irq_mask_matches_linux_config_intr_mask() -> TestResult {
    let Some(b) = Mask::config(ChipId::Rtl8852B, false) else {
        return TestResult::Fail("8852B AX v0 mask rejected");
    };
    // Literal Linux rtw89_pci_config_intr_mask values (pci.h bit positions).
    if b.halt_c2h != 0x0020_0000 || b.intrs != [0x011e_0007, 0x1000_0000] {
        return TestResult::Fail("8852B normal mask differs from Linux");
    }
    let Some(r) = Mask::config(ChipId::Rtl8852B, true) else {
        return TestResult::Fail("8852B recovery mask rejected");
    };
    if r.halt_c2h != 0x0020_0000 || r.intrs != [0x0100_0000, 0] {
        return TestResult::Fail("8852B recovery mask differs from Linux");
    }
    let Some(s) = Mask::config(ChipId::Rtl8851B, false) else {
        return TestResult::Fail("8851B mask rejected");
    };
    if s.intrs[0] != 0x009e_0007 {
        return TestResult::Fail("8851B HS0ISR workaround bit missing");
    }
    if Mask::config(ChipId::Rtl8852C, false).is_some()
        || Mask::config(ChipId::Rtl8922A, false).is_some()
    {
        return TestResult::Fail("v1/v2 interrupt layouts accepted by the AX v0 program");
    }
    TestResult::Pass
}

fn smoke_rtw89_irq_recognize_acks_only_enabled_sources() -> TestResult {
    let Some(mask) = Mask::config(ChipId::Rtl8852B, false) else {
        return TestResult::Fail("8852B mask rejected");
    };
    let mut model = Model::default();
    // RX + RPQ + an unmasked bit 5 that belongs to no enabled source.
    model.regs.insert(
        R_AX_PCIE_HISR00,
        B_AX_RXDMA_INT_EN | B_AX_RPQDMA_INT_EN | (1 << 5),
    );
    model
        .regs
        .insert(R_AX_HISR0, B_AX_HALT_C2H_INT_EN | (1 << 3));
    model.regs.insert(R_AX_PCIE_HISR10, 0);
    let Ok(isrs) = mask.recognize(&mut model) else {
        return TestResult::Fail("recognize failed on a healthy register file");
    };
    if isrs.isrs[0] != B_AX_RXDMA_INT_EN | B_AX_RPQDMA_INT_EN
        || isrs.halt_c2h != B_AX_HALT_C2H_INT_EN
    {
        return TestResult::Fail("recognize reported unmasked status");
    }
    if model.get(R_AX_PCIE_HISR00) != 1 << 5 || model.get(R_AX_HISR0) != 1 << 3 {
        return TestResult::Fail("recognize cleared status it does not own");
    }
    let events = isrs.events();
    if !events.rx || !events.rpq || events.rx_unavailable || !events.halt_c2h || !events.fatal() {
        return TestResult::Fail("event classification wrong");
    }
    let quiet = Isrs {
        halt_c2h: 0,
        isrs: [B_AX_RDU_INT_EN, 0],
    }
    .events();
    if !quiet.rx || !quiet.rx_unavailable || quiet.fatal() {
        return TestResult::Fail("RDU must poll RX without being fatal");
    }
    TestResult::Pass
}

fn smoke_rtw89_irq_service_masks_then_rearms_and_propagates_errors() -> TestResult {
    let line = Line::new();
    let Some(mask) = Mask::config(ChipId::Rtl8852B, false) else {
        return TestResult::Fail("8852B mask rejected");
    };
    let mut model = Model::default();
    if mask.enable(&mut model).is_err() || model.get(R_AX_PCIE_HIMR00) != mask.intrs[0] {
        return TestResult::Fail("enable did not program HIMR00");
    }
    model.writes.clear();
    model.regs.insert(R_AX_PCIE_HISR00, B_AX_RPQBD_FULL_INT_EN);
    // Same sequence as Binding::service, independent of a PCI function.
    if Mask::disable(&mut model).is_err() {
        return TestResult::Fail("disable failed");
    }
    let Ok(isrs) = mask.recognize(&mut model) else {
        return TestResult::Fail("recognize failed");
    };
    let order: Vec<u32> = model.writes.iter().map(|(a, _)| *a).collect();
    if order.get(..3) != Some(&[R_AX_HIMR0, R_AX_PCIE_HIMR00, R_AX_PCIE_HIMR10][..])
        || model.writes.iter().take(3).any(|(_, v)| *v != 0)
        || !isrs.events().rpq
    {
        return TestResult::Fail("service did not mask before acknowledging");
    }
    if mask.enable(&mut model).is_err()
        || model.get(R_AX_HIMR0) != B_AX_HALT_C2H_INT_EN
        || model.get(R_AX_PCIE_HIMR10) != B_AX_HC10ISR_IND_INT_EN
    {
        return TestResult::Fail("rearm did not restore the mask");
    }
    let mut broken = Model {
        fail_at: Some(R_AX_PCIE_HISR00),
        ..Model::default()
    };
    if mask.recognize(&mut broken).is_ok() {
        return TestResult::Fail("register failure was swallowed");
    }
    drop(line);
    TestResult::Pass
}

struct Count(AtomicUsize);
impl alloc::task::Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn smoke_rtw89_irq_line_wakes_waiter_without_lost_raise() -> TestResult {
    let line = Line::new();
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let seen = line.raised();
    let mut wait = core::pin::pin!(line.wait(seen));
    if wait.as_mut().poll(&mut cx).is_ready() {
        return TestResult::Fail("wait completed without a raise");
    }
    line.raise();
    if count.0.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("raise did not wake the parked worker");
    }
    let Poll::Ready(next) = wait.as_mut().poll(&mut cx) else {
        return TestResult::Fail("wait still pending after raise");
    };
    // A raise that happens before the next wait is observed immediately.
    line.raise();
    let mut again = core::pin::pin!(line.wait(next));
    if again.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("raise between waits was lost");
    }
    if line.delivered() != 0 {
        return TestResult::Fail("software kick counted as hardware delivery");
    }
    TestResult::Pass
}

fn smoke_rtw89_irq_vector_delivery_and_release() -> TestResult {
    let line = Line::new();
    let Ok(vector) = Vector::install(&line) else {
        return TestResult::Skip("no free interrupt vector");
    };
    let number = vector.number();
    narf_interrupts::enable_irq(number);
    narf_interrupts::on_irq(number);
    if line.delivered() != 1 || line.raised() != 1 {
        vector.release();
        return TestResult::Fail("MSI dispatch did not reach the line");
    }
    vector.release();
    if narf_interrupts::vector::is_allocated(number)
        || !narf_interrupts::installed_handler_names(number).is_empty()
    {
        return TestResult::Fail("release leaked the vector or handler");
    }
    // A stale delivery after release cannot reach the old line.
    narf_interrupts::on_irq(number);
    if line.delivered() != 1 {
        return TestResult::Fail("released line still receives interrupts");
    }
    if LINES.iter().any(|slot| {
        slot.lock()
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, &line))
    }) {
        return TestResult::Fail("release kept the line slot");
    }
    TestResult::Pass
}

fn smoke_rtw89_irq_quarantine_keeps_vector_reserved() -> TestResult {
    let line = Line::new();
    let Ok(vector) = Vector::install(&line) else {
        return TestResult::Skip("no free interrupt vector");
    };
    let number = vector.number();
    vector.quarantine();
    let reserved = narf_interrupts::vector::is_allocated(number);
    narf_interrupts::on_irq(number);
    let leaked = line.delivered() != 0;
    // Test cleanup only: a real quarantined vector stays reserved.
    let _ = narf_interrupts::vector::free(number);
    narf_interrupts::enable_irq(number);
    if !reserved {
        return TestResult::Fail("quarantine returned a possibly targeted vector");
    }
    if leaked {
        return TestResult::Fail("quarantined vector still dispatches to the line");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89/irq",
    smoke_rtw89_irq_mask_matches_linux_config_intr_mask
);
kernel_test_in!(
    "drivers/wireless/rtw89/irq",
    smoke_rtw89_irq_recognize_acks_only_enabled_sources
);
kernel_test_in!(
    "drivers/wireless/rtw89/irq",
    smoke_rtw89_irq_service_masks_then_rearms_and_propagates_errors
);
kernel_test_in!(
    "drivers/wireless/rtw89/irq",
    smoke_rtw89_irq_line_wakes_waiter_without_lost_raise
);
kernel_test_in!(
    "drivers/wireless/rtw89/irq",
    smoke_rtw89_irq_vector_delivery_and_release
);
kernel_test_in!(
    "drivers/wireless/rtw89/irq",
    smoke_rtw89_irq_quarantine_keeps_vector_reserved
);
