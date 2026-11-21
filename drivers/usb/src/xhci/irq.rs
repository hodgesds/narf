//! Interrupter 0 service, in Linux's order (`drivers/usb/host/xhci-ring.c`
//! `xhci_irq` → `xhci_handle_events`):
//!
//! 1. Read USBSTS. All-ones means the controller is gone
//!    (`xhci_hc_died`); without EINT the interrupt is not this
//!    controller's (`IRQ_NONE` on a shared line); HCE or HSE is fatal
//!    (Linux `xhci_halt`) and no event is handled.
//! 2. Clear USBSTS.EINT ("so we can receive interrupts from other
//!    MSI-X interrupters"), then IMAN.IP (`xhci_clear_interrupt_pending`)
//!    — before the drain, so an event posted while draining pends a
//!    fresh interrupt instead of being acknowledged unseen.
//! 3. Drain the event ring (bounded per interrupt).
//! 4. Write ERDP once, with EHB cleared (`xhci_update_erst_dequeue(...,
//!    true)`): the controller holds further interrupts while EHB is set,
//!    so clearing it once per drain — not once per event — is what lets
//!    the moderation interval batch events.
//!
//! Interrupt moderation is Linux's default `imod_interval` of 40 µs.

/// Linux `xhci->imod_interval` default, in nanoseconds.
pub(super) const IMOD_INTERVAL_NS: u32 = 40_000;
/// IMAN.IMODI value: the interval in 250 ns units
/// (`xhci_set_interrupter_moderation`).
pub(super) const IMODI: u32 = IMOD_INTERVAL_NS / 250;
/// Events drained per interrupt; the rest raise the next one once EHB
/// clears.
pub(super) const MAX_EVENTS_PER_IRQ: usize = 64;

/// USBSTS.HSE — Host System Error (RW1C).
pub(super) const USBSTS_HSE: u32 = 1 << 2;
/// USBSTS.EINT — Event Interrupt (RW1C).
pub(super) const USBSTS_EINT: u32 = 1 << 3;
/// USBSTS.HCE — Host Controller Error.
pub(super) const USBSTS_HCE: u32 = 1 << 12;
/// IMAN.IP — Interrupt Pending (RW1C).
pub(super) const IMAN_IP: u32 = 1 << 0;
/// IMAN.IE — Interrupt Enable.
pub(super) const IMAN_IE: u32 = 1 << 1;

/// What one interrupter service did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Serviced {
    /// USBSTS.EINT clear: not this controller's interrupt.
    NotOurs,
    /// The controller is dead or in error; recovery was requested.
    Fatal,
    /// This many events were drained.
    Drained(usize),
}

/// The registers and demux one interrupter service touches.
pub(super) trait Regs {
    fn usbsts(&self) -> u32;
    /// Write `bits` to USBSTS (RW1C bits clear where set).
    fn clear_usbsts(&self, bits: u32);
    fn iman(&self) -> u32;
    fn write_iman(&self, value: u32);
    /// Demux one event; false when the ring is empty.
    fn demux(&self) -> bool;
    /// Write ERDP with the software dequeue pointer, clearing EHB.
    fn finish(&self);
    /// The controller is dead (`usbsts` all ones) or reports HCE/HSE.
    fn fatal(&self, usbsts: u32);
}

/// Service interrupter 0. `forced` drains even without EINT (the
/// bring-up drain of events latched before the interrupt was armed).
pub(super) fn service<R: Regs>(regs: &R, forced: bool) -> Serviced {
    let status = regs.usbsts();
    if status == u32::MAX {
        regs.fatal(status);
        return Serviced::Fatal;
    }
    if !forced && status & USBSTS_EINT == 0 {
        return Serviced::NotOurs;
    }
    if status & (USBSTS_HCE | USBSTS_HSE) != 0 {
        regs.fatal(status);
        return Serviced::Fatal;
    }
    if status & USBSTS_EINT != 0 {
        regs.clear_usbsts(USBSTS_EINT);
    }
    // W1C IP, keep IE.
    let iman = regs.iman();
    regs.write_iman((iman & IMAN_IE) | IMAN_IP);
    let mut drained = 0;
    while drained < MAX_EVENTS_PER_IRQ && regs.demux() {
        drained += 1;
    }
    regs.finish();
    Serviced::Drained(drained)
}

#[cfg(feature = "kernel-test")]
#[path = "irq_tests.rs"]
mod tests;
