//! MT7921/MT7922 host interrupt delivery for the retained native owner.
//!
//! Linux `mt7921_pci_probe` allocates one vector
//! (`pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES)`), enables the
//! PCIe MAC interrupt (`MT_PCIE_MAC_INT_ENABLE = 0xff`) and the WFDMA
//! sources (`mt76_connac_irq_enable`: TX done, RX done of the event, data
//! and WM2 rings, `MT_INT_MCU_CMD`; `MT_MCU2HOST_SW_INT_ENA` WAKE_RX_PCIE).
//! `mt792x_irq_handler` masks `MT_WFDMA0_HOST_INT_ENA`; `mt792x_irq_tasklet`
//! reads and acknowledges `MT_WFDMA0_HOST_INT_STA` (and `MT_MCU_CMD`) and
//! schedules NAPI; NAPI re-enables the sources once the rings are drained.
//! Nothing touches the device while the link is idle.
//!
//! Here BAR0 belongs to the retained async owner, so the hard handler only
//! counts the MSI and wakes the owner's service worker ([`Line`]). The
//! worker performs the same mask -> recognize/acknowledge -> ring service
//! -> unmask sequence under the owner (`firmware_transport_hw`). MSI is
//! raised when `HOST_INT_STA & HOST_INT_ENA` becomes non-zero, so a source
//! set while the worker serviced the rings raises a fresh message when the
//! enable is restored: no event waits for a timer.
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// `MT_INT_RX_DONE_ALL`: the event (WM), data and WM2 RX rings.
pub(super) const MT_INT_RX_DONE_ALL: u32 = (1 << 2) | (1 << 0) | (1 << 22);
/// `MT_INT_TX_DONE_ALL`: MCU WM, band 0 data and rings 4..18.
pub(super) const MT_INT_TX_DONE_ALL: u32 = (1 << 27) | (1 << 4) | 0x0007_fff0;
/// `MT_INT_MCU_CMD` (`MCU2HOST_SW_INT_ENA`).
pub(super) const MT_INT_MCU_CMD: u32 = 1 << 29;
/// The sources `mt7921e` enables (`mt792x_dma_enable` / `mt7921e_mac_reset`).
pub(super) const HOST_INT_MASK: u32 = MT_INT_TX_DONE_ALL | MT_INT_RX_DONE_ALL | MT_INT_MCU_CMD;

/// One wakeable interrupt line shared by the hard handler, software kicks
/// (TX enqueue, configuration changes) and the single service worker.
#[derive(Debug)]
pub(crate) struct Line {
    raised: AtomicU64,
    delivered: AtomicU64,
    /// A device vector is bound and its sources are routed to this line.
    bound: AtomicBool,
    waker: IrqSafeSpinLock<Option<Waker>>,
}

impl Line {
    const fn new() -> Self {
        Self {
            raised: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            bound: AtomicBool::new(false),
            waker: IrqSafeSpinLock::new(None),
        }
    }
    /// Record a source and wake the worker.
    pub(crate) fn raise(&self) {
        self.raised.fetch_add(1, Ordering::AcqRel);
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    pub(crate) fn raised(&self) -> u64 {
        self.raised.load(Ordering::Acquire)
    }
    /// Hardware MSI deliveries on this line.
    pub(crate) fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }
    /// Whether device interrupts reach the line (an MSI vector is bound).
    pub(crate) fn bound(&self) -> bool {
        self.bound.load(Ordering::Acquire)
    }
    /// Wait for any raise after `seen`.
    pub(crate) fn wait(&self, seen: u64) -> Wait<'_> {
        Wait { line: self, seen }
    }
}

/// Future returned by [`Line::wait`].
#[derive(Debug)]
pub(crate) struct Wait<'a> {
    line: &'a Line,
    seen: u64,
}

impl Future for Wait<'_> {
    type Output = u64;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        let now = self.line.raised();
        if now != self.seen {
            return Poll::Ready(now);
        }
        *self.line.waker.lock() = Some(cx.waker().clone());
        // A raise between the first load and the waker store is caught here.
        let now = self.line.raised();
        if now != self.seen {
            self.line.waker.lock().take();
            return Poll::Ready(now);
        }
        Poll::Pending
    }
}

/// The driver's single line: one retained owner per bound function.
pub(crate) static LINE: Line = Line::new();

/// Wake the service worker for host-side work (a queued TX frame, a
/// configuration change the owner applies on its next pass).
pub(crate) fn kick() {
    LINE.raise();
}

const HANDLER: &str = "mt7921e";

/// `mt792x_irq_handler`: hand the interrupt to the worker (the tasklet's
/// work runs there, under the owner of BAR0).
fn handler(_cookie: u64) -> narf_interrupts::IrqStatus {
    LINE.delivered.fetch_add(1, Ordering::Relaxed);
    LINE.raise();
    narf_interrupts::IrqStatus::Handled
}

/// MSI delivery bound to the exact owned PCI function.
#[derive(Debug)]
pub(super) struct Binding {
    vector: u8,
    msi: narf_bus::msi::MsiConfig,
}

impl Binding {
    /// `pci_alloc_irq_vectors(pdev, 1, 1, ...)` + `devm_request_irq`: one
    /// MSI vector to the boot CPU (the default affinity). `None` leaves the
    /// owner polled. Only x86_64 programs MSI here; other architectures
    /// need an interrupt-translation mapping this owner does not make.
    pub(super) fn bind(device: &BusDevice, authority: &Cap<BusDeviceCap, Write>) -> Option<Self> {
        if !cfg!(target_arch = "x86_64") {
            return None;
        }
        let mut msi = super::pci::invoke(authority, || {
            narf_bus::msi::enable_msi(authority, device, 1)
        })
        .ok()?
        .ok()?;
        let vector = narf_interrupts::vector::alloc().ok()?;
        narf_interrupts::install_handler_named(vector, HANDLER, 0, handler);
        narf_interrupts::enable_irq(vector);
        let programmed = super::pci::invoke(authority, || {
            // SAFETY: the claimed transport exclusively owns this function's
            // configuration space; the vector and its handler are installed.
            unsafe {
                narf_bus::msi::program_msi(&mut msi, 0, vector)?;
                narf_bus::msi::enable(&msi)
            }
        });
        if !matches!(programmed, Ok(Ok(()))) {
            let disabled = super::pci::invoke(authority, || {
                // SAFETY: same exclusive configuration owner.
                unsafe { narf_bus::msi::disable(&msi) }
            });
            release_vector(vector, matches!(disabled, Ok(Ok(()))));
            return None;
        }
        LINE.bound.store(true, Ordering::Release);
        Some(Self { vector, msi })
    }

    /// `devm_free_irq` + `pci_free_irq_vectors`, after the device sources
    /// are masked. A vector the device may still target is quarantined.
    pub(super) fn release(self, authority: &Cap<BusDeviceCap, Write>) {
        LINE.bound.store(false, Ordering::Release);
        let disabled = super::pci::invoke(authority, || {
            // SAFETY: exclusive configuration owner of this function.
            unsafe { narf_bus::msi::disable(&self.msi) }
        });
        release_vector(self.vector, matches!(disabled, Ok(Ok(()))));
        // The worker re-plans its wait without the interrupt.
        LINE.raise();
    }
}

fn release_vector(vector: u8, free: bool) {
    narf_interrupts::disable_irq(vector);
    let _ = narf_interrupts::remove_handler(vector, HANDLER, 0);
    narf_interrupts::synchronize_irq(vector);
    if free {
        let _ = narf_interrupts::vector::free(vector);
    }
}

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A raise before, between or after the worker's sample is never lost:
    /// the wait completes at once for every raise after `seen`, and a
    /// pending wait is woken by the next one.
    fn mt76_interrupt_line_never_loses_a_raise() -> TestResult {
        let line = Line::new();
        let seen = line.raised();
        line.raise();
        let mut cx = Context::from_waker(Waker::noop());
        let mut wait = core::pin::pin!(line.wait(seen));
        if wait.as_mut().poll(&mut cx) != Poll::Ready(seen + 1) {
            return TestResult::Fail("a raise after the sample did not complete the wait");
        }
        let seen = line.raised();
        let mut wait = core::pin::pin!(line.wait(seen));
        if wait.as_mut().poll(&mut cx).is_ready() || line.waker.lock().is_none() {
            return TestResult::Fail("an idle wait did not park with its waker");
        }
        line.raise();
        if line.waker.lock().is_some() || wait.as_mut().poll(&mut cx) != Poll::Ready(seen + 1) {
            return TestResult::Fail("a raise did not wake and complete the parked wait");
        }
        if line.bound() || line.delivered() != 0 {
            return TestResult::Fail("a software raise counted as a device interrupt");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/irq",
        mt76_interrupt_line_never_loses_a_raise
    );
}
