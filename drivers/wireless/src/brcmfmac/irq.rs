// SPDX-License-Identifier: GPL-2.0-or-later
//! PCIe MSI delivery for the retained BCM43602 msgbuf owner.
//!
//! Linux v7.2 `pcie.c::brcmf_pcie_request_irq` masks the mailbox
//! (`brcmf_pcie_intr_disable`), calls `pci_enable_msi` and installs the
//! threaded pair `brcmf_pcie_quick_check_isr` / `brcmf_pcie_isr_thread`;
//! `brcmf_pcie_release_irq` masks, frees, disables MSI and clears any latched
//! `MAILBOXINT`. In NARF the BAR0 window belongs to the async runtime owner,
//! so the vector handler never touches the device: it only raises the
//! owner's [`Signal`]. The owner's next service performs the quick-check and
//! thread halves (`runtime/mailbox.rs`). Without an MSI capability or vector
//! the owner keeps its 1 ms polled service (INTx stays disabled: the retained
//! command register keeps `INTX_DISABLE` set and NARF has no shared
//! level-triggered GSI route that could clear `MAILBOXINT` from hard IRQ).
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;

/// Edge-latched wake shared by the vector handler and the service owner.
pub struct Signal {
    count: AtomicU64,
    waker: IrqSafeSpinLock<Option<Waker>>,
}
impl Signal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU64::new(0),
            waker: IrqSafeSpinLock::new(None),
        })
    }
    /// Vector top half (and explicit reschedules): count and wake; never
    /// touches the BAR.
    pub fn raise(&self) {
        self.count.fetch_add(1, Ordering::AcqRel);
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }
    /// Resolve once the count moves past `seen`, or when `fallback` ends.
    pub fn wait<F: Future<Output = ()> + Unpin>(&self, seen: u64, fallback: F) -> Wait<'_, F> {
        Wait {
            signal: self,
            seen,
            fallback,
        }
    }
}
impl core::fmt::Debug for Signal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmfSignal")
            .field("count", &self.count())
            .finish()
    }
}
pub struct Wait<'a, F> {
    signal: &'a Signal,
    seen: u64,
    fallback: F,
}
impl<F> core::fmt::Debug for Wait<'_, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmfWait")
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}
impl<F: Future<Output = ()> + Unpin> Future for Wait<'_, F> {
    /// `true` when a vector (or explicit raise) ended the wait.
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        if self.signal.count() != self.seen {
            return Poll::Ready(true);
        }
        *self.signal.waker.lock() = Some(cx.waker().clone());
        // A raise between the two loads either saw the waker or left the count.
        if self.signal.count() != self.seen {
            return Poll::Ready(true);
        }
        match Pin::new(&mut self.fallback).poll(cx) {
            Poll::Ready(()) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Owner service period: with a delivered vector the timer is only a
/// missed-edge backstop; without one the owner keeps its 1 ms poll.
pub const fn fallback_ms(delivered: bool) -> u64 {
    if delivered {
        10
    } else {
        1
    }
}

/// One retained MSI binding (single BCM43602 owner per boot, as
/// `pcie.rs::OWNED`).
#[derive(Debug)]
pub(super) struct Msi {
    config: narf_bus::msi::MsiConfig,
    vector: u8,
    signal: Arc<Signal>,
}

static SIGNAL: IrqSafeSpinLock<Option<Arc<Signal>>> = IrqSafeSpinLock::new(None);

fn vector_irq(_cookie: u64) -> narf_interrupts::IrqStatus {
    let signal = { SIGNAL.lock().clone() };
    match signal {
        Some(signal) => {
            signal.raise();
            narf_interrupts::IrqStatus::Handled
        }
        None => narf_interrupts::IrqStatus::None,
    }
}

fn release(msi: Msi) {
    narf_interrupts::disable_irq(msi.vector);
    let _ = narf_interrupts::remove_handler(msi.vector, "brcmfmac", 0);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
    let _ = narf_interrupts::vector::free(msi.vector);
    let mut signal = SIGNAL.lock();
    if signal.as_ref().is_some_and(|s| Arc::ptr_eq(s, &msi.signal)) {
        *signal = None;
    }
}

impl super::pcie::PcieBackplane {
    /// `pci_enable_msi` + `request_threaded_irq`: discover, program and
    /// install one vector with MSI Enable set only after the handler exists.
    /// Any failure leaves polled service and no allocated vector.
    pub(super) fn arm_msi(&mut self, signal: &Arc<Signal>) -> bool {
        if self.msi.is_some() || SIGNAL.lock().is_some() {
            return false;
        }
        let cap = self.cap;
        let device = self.device;
        let Ok(Ok(mut config)) =
            super::pcie::invoke_registers(&cap, || narf_bus::msi::enable_msi(&cap, &device, 1))
        else {
            return false;
        };
        let Ok(vector) = narf_interrupts::vector::alloc() else {
            return false;
        };
        // SAFETY: this retained owner is the sole user of the function's
        // configuration space; MSI Enable stays clear until the handler exists.
        let programmed = super::pcie::invoke_registers(&cap, || unsafe {
            narf_bus::msi::program_msi(&mut config, 0, vector)
        });
        if !matches!(programmed, Ok(Ok(_))) {
            let _ = narf_interrupts::vector::free(vector);
            return false;
        }
        *SIGNAL.lock() = Some(signal.clone());
        narf_interrupts::install_handler_named(vector, "brcmfmac", 0, vector_irq);
        let msi = Msi {
            config,
            vector,
            signal: signal.clone(),
        };
        narf_interrupts::enable_irq(vector);
        // SAFETY: as above.
        let enabled =
            super::pcie::invoke_registers(&cap, || unsafe { narf_bus::msi::enable(&msi.config) });
        if !matches!(enabled, Ok(Ok(()))) {
            self.msi = Some(msi);
            self.disarm_msi();
            return false;
        }
        self.msi = Some(msi);
        true
    }
    /// `pci_disable_msi` + `free_irq`. A failed disable keeps the vector
    /// quarantined (allocated, masked, no waker) rather than reusing it.
    pub(super) fn disarm_msi(&mut self) {
        let Some(msi) = self.msi.take() else {
            return;
        };
        let cap = self.cap;
        // SAFETY: sole owner of this function's MSI capability.
        let disabled =
            super::pcie::invoke_registers(&cap, || unsafe { narf_bus::msi::disable(&msi.config) });
        if matches!(disabled, Ok(Ok(()))) {
            release(msi);
        } else {
            narf_interrupts::disable_irq(msi.vector);
            narf_interrupts::dispatch::clear_all_wakers(msi.vector);
            narf_interrupts::synchronize_irq(msi.vector);
            core::mem::forget(msi);
        }
    }
}
