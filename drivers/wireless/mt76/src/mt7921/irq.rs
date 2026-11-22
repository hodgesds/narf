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
/// (TX enqueue, configuration changes), the service worker and the
/// data-queue poll.
#[derive(Debug)]
pub(crate) struct Line {
    raised: AtomicU64,
    delivered: AtomicU64,
    /// A device vector is bound and its sources are routed to this line.
    bound: AtomicBool,
    /// The service worker's wait.
    waker: IrqSafeSpinLock<Option<Waker>>,
    /// An owner operation's MCU or scan wait (Linux `mcu.wait`): its own
    /// slot, so it never displaces the worker's waker.
    owner_waker: IrqSafeSpinLock<Option<Waker>>,
    /// The data-queue poll's wait (`napi[MT_RXQ_MAIN]`): its own slot too.
    data_waker: IrqSafeSpinLock<Option<Waker>>,
}

impl Line {
    const fn new() -> Self {
        Self {
            raised: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            bound: AtomicBool::new(false),
            waker: IrqSafeSpinLock::new(None),
            owner_waker: IrqSafeSpinLock::new(None),
            data_waker: IrqSafeSpinLock::new(None),
        }
    }
    /// Record a source and wake the worker, the data-queue poll and any
    /// parked owner wait (the tasklet's `napi_schedule` of each queue).
    pub(crate) fn raise(&self) {
        self.raised.fetch_add(1, Ordering::AcqRel);
        for slot in [&self.waker, &self.data_waker, &self.owner_waker] {
            let waker = slot.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
    /// Park an owner wait (`wait_event_timeout(dev->mcu.wait, ...)`) until
    /// the next raise after `seen`. False when one already happened: the
    /// caller polls again at once.
    pub(crate) fn park(&self, waker: &Waker, seen: u64) -> bool {
        *self.owner_waker.lock() = Some(waker.clone());
        if self.raised() != seen {
            self.owner_waker.lock().take();
            return false;
        }
        true
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
        Wait {
            line: self,
            slot: &self.waker,
            seen,
        }
    }
    /// The data-queue poll's wait for any raise after `seen`
    /// (`napi_schedule(&dev->mt76.napi[MT_RXQ_MAIN])` from the tasklet).
    pub(crate) fn wait_data(&self, seen: u64) -> Wait<'_> {
        Wait {
            line: self,
            slot: &self.data_waker,
            seen,
        }
    }
}

/// Future returned by [`Line::wait`].
#[derive(Debug)]
pub(crate) struct Wait<'a> {
    line: &'a Line,
    /// The waiter's own waker slot on the line.
    slot: &'a IrqSafeSpinLock<Option<Waker>>,
    seen: u64,
}

impl Future for Wait<'_> {
    type Output = u64;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        let now = self.line.raised();
        if now != self.seen {
            return Poll::Ready(now);
        }
        *self.slot.lock() = Some(cx.waker().clone());
        // A raise between the first load and the waker store is caught here.
        let now = self.line.raised();
        if now != self.seen {
            self.slot.lock().take();
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
        // An owner wait parks in its own slot beside the worker's wait.
        let seen = line.raised();
        let mut wait = core::pin::pin!(line.wait(seen));
        if wait.as_mut().poll(&mut cx).is_ready() || !line.park(cx.waker(), seen) {
            return TestResult::Fail("an owner wait did not park beside the worker");
        }
        line.raise();
        if line.waker.lock().is_some() || line.owner_waker.lock().is_some() {
            return TestResult::Fail("a raise did not wake both the worker and the owner wait");
        }
        if line.park(cx.waker(), seen) {
            return TestResult::Fail("an owner wait parked past a raise it had not seen");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/irq",
        mt76_interrupt_line_never_loses_a_raise
    );

    struct Wakes(core::sync::atomic::AtomicU32);
    impl alloc::task::Wake for Wakes {
        fn wake(self: alloc::sync::Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
        fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// The data-queue poll parks beside the service worker and an owner
    /// wait (Linux: its own NAPI, scheduled by the tasklet), and one raise
    /// wakes all three: none displaces another's waker.
    fn mt76_interrupt_line_wakes_the_data_poll_beside_the_worker() -> TestResult {
        use alloc::sync::Arc;
        use core::sync::atomic::AtomicU32;
        let line = Line::new();
        let worker = Arc::new(Wakes(AtomicU32::new(0)));
        let data = Arc::new(Wakes(AtomicU32::new(0)));
        let owner = Arc::new(Wakes(AtomicU32::new(0)));
        let worker_waker = Waker::from(worker.clone());
        let data_waker = Waker::from(data.clone());
        let owner_waker = Waker::from(owner.clone());
        let mut worker_cx = Context::from_waker(&worker_waker);
        let mut data_cx = Context::from_waker(&data_waker);
        let seen = line.raised();
        let mut worker_wait = core::pin::pin!(line.wait(seen));
        let mut data_wait = core::pin::pin!(line.wait_data(seen));
        let worker_parked = worker_wait.as_mut().poll(&mut worker_cx).is_pending();
        let data_parked = data_wait.as_mut().poll(&mut data_cx).is_pending();
        if !worker_parked || !data_parked || !line.park(&owner_waker, seen) {
            return TestResult::Fail("an idle wait did not park");
        }
        line.raise();
        let woken = (
            worker.0.load(Ordering::Acquire),
            data.0.load(Ordering::Acquire),
            owner.0.load(Ordering::Acquire),
        );
        if woken != (1, 1, 1) {
            return TestResult::Fail("a raise did not wake the worker, data poll and owner");
        }
        if data_wait.as_mut().poll(&mut data_cx) != Poll::Ready(seen + 1) {
            return TestResult::Fail("the woken data poll did not see the raise");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/mt7921/irq-data",
        mt76_interrupt_line_wakes_the_data_poll_beside_the_worker
    );
}
