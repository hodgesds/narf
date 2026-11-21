//! Fixture tests for the interrupter service order (Linux `xhci_irq` /
//! `xhci_handle_events`). The fake records every register access and
//! demux step the service makes, so the order — EINT, IMAN.IP, drain,
//! one ERDP write with EHB — is checked directly.
use super::*;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    ClearUsbsts(u32),
    WriteIman(u32),
    Demux,
    Finish,
    Fatal,
}

struct Fake {
    usbsts: u32,
    iman: u32,
    events: Cell<usize>,
    ops: RefCell<Vec<Op>>,
}

impl Fake {
    fn new(usbsts: u32, events: usize) -> Self {
        Self {
            usbsts,
            iman: IMAN_IE | IMAN_IP,
            events: Cell::new(events),
            ops: RefCell::new(Vec::new()),
        }
    }
    fn ops(&self) -> Vec<Op> {
        self.ops.borrow().clone()
    }
}

impl Regs for Fake {
    fn usbsts(&self) -> u32 {
        self.usbsts
    }
    fn clear_usbsts(&self, bits: u32) {
        self.ops.borrow_mut().push(Op::ClearUsbsts(bits));
    }
    fn iman(&self) -> u32 {
        self.iman
    }
    fn write_iman(&self, value: u32) {
        self.ops.borrow_mut().push(Op::WriteIman(value));
    }
    fn demux(&self) -> bool {
        self.ops.borrow_mut().push(Op::Demux);
        let left = self.events.get();
        if left == 0 {
            return false;
        }
        self.events.set(left - 1);
        true
    }
    fn finish(&self) {
        self.ops.borrow_mut().push(Op::Finish);
    }
    fn fatal(&self, _usbsts: u32) {
        self.ops.borrow_mut().push(Op::Fatal);
    }
}

/// EINT then IMAN.IP are acknowledged before the drain, and ERDP (with
/// EHB) is written once after it, not once per event; moderation is
/// Linux's 40 µs.
fn smoke_xhci_interrupt_service_follows_linux_order() -> TestResult {
    let fake = Fake::new(USBSTS_EINT, 3);
    if service(&fake, false) != Serviced::Drained(3) {
        return TestResult::Fail("interrupt service did not drain the pending events");
    }
    let expected = [
        Op::ClearUsbsts(USBSTS_EINT),
        Op::WriteIman(IMAN_IE | IMAN_IP),
        Op::Demux,
        Op::Demux,
        Op::Demux,
        Op::Demux,
        Op::Finish,
    ];
    if fake.ops() != expected {
        return TestResult::Fail("interrupt not acked EINT, IP, drain, one ERDP|EHB write");
    }
    // A burst larger than one service drains the cap and still clears
    // EHB once, so the controller interrupts again for the rest.
    let burst = Fake::new(USBSTS_EINT, MAX_EVENTS_PER_IRQ + 5);
    if service(&burst, false) != Serviced::Drained(MAX_EVENTS_PER_IRQ)
        || burst.ops().iter().filter(|op| **op == Op::Finish).count() != 1
        || burst.ops().last() != Some(&Op::Finish)
    {
        return TestResult::Fail("a burst was not bounded with one final ERDP write");
    }
    if IMODI != 160 {
        return TestResult::Fail("interrupt moderation is not Linux's 40 us");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/irq",
    smoke_xhci_interrupt_service_follows_linux_order
);

/// Without EINT the interrupt is another device's (shared line) and
/// nothing is touched; HCE, HSE or an all-ones USBSTS is fatal and no
/// event is handled.
fn smoke_xhci_interrupt_service_checks_usbsts() -> TestResult {
    let foreign = Fake::new(0, 2);
    if service(&foreign, false) != Serviced::NotOurs || !foreign.ops().is_empty() {
        return TestResult::Fail("an interrupt without EINT touched the controller");
    }
    for status in [USBSTS_EINT | USBSTS_HCE, USBSTS_EINT | USBSTS_HSE, u32::MAX] {
        let fake = Fake::new(status, 2);
        if service(&fake, false) != Serviced::Fatal || fake.ops() != [Op::Fatal] {
            return TestResult::Fail("HCE/HSE/dead controller was not handled as fatal");
        }
    }
    // The bring-up drain runs without EINT.
    let forced = Fake::new(0, 1);
    if service(&forced, true) != Serviced::Drained(1) {
        return TestResult::Fail("forced bring-up drain did not run");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/irq",
    smoke_xhci_interrupt_service_checks_usbsts
);
