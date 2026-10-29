// SPDX-License-Identifier: GPL-2.0-or-later
//! Runtime interrupt delivery for the retained PCIe owner: Linux
//! `pci.c::ath10k_pci_init_irq` (MSI first), `ath10k_pci_hif_start`
//! (`ath10k_pci_irq_enable`) and `ath10k_pci_hif_stop`/`ath10k_pci_free_irq`.
//! The vector handler only raises the owner's [`Signal`]; every BAR access
//! stays in the owner's service (`irq.rs`). Without an MSI capability or
//! vector the owner keeps 1 ms polling with chip interrupts disabled: NARF
//! has no ath10k INTx route (no level-triggered GSI handler that may write
//! `PCIE_INTR_CLR` from the hard IRQ), so the INTx program is only used for
//! its `ath10k_pci_irq_pending` cause check.
use super::*;
use crate::ath10k::irq::{self, Program, Service, Signal};
use alloc::sync::Arc;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
pub(super) struct Msi {
    config: narf_bus::msi::MsiConfig,
    vector: u8,
    signal: Arc<Signal>,
}

/// Single-function vector slot (one retained ath10k controller per boot,
/// as `pci.rs::CONTROLLER`).
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

fn quarantine(msi: &Msi) {
    narf_interrupts::disable_irq(msi.vector);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
}
fn release(msi: Msi) {
    narf_interrupts::disable_irq(msi.vector);
    let _ = narf_interrupts::remove_handler(msi.vector, "ath10k", 0);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
    let _ = narf_interrupts::vector::free(msi.vector);
    let mut signal = SIGNAL.lock();
    if signal.as_ref().is_some_and(|s| Arc::ptr_eq(s, &msi.signal)) {
        *signal = None;
    }
}

impl PciBoot {
    /// Discover, program and install one MSI vector with delivery still
    /// disabled at the function. Any failure leaves polled service.
    fn arm_msi(&mut self) -> Option<Msi> {
        if SIGNAL.lock().is_some() {
            return None;
        }
        let cap = &self.mmio.cap;
        let device = &self.device;
        let mut config =
            crate::qualcomm_pci::invoke(cap, || narf_bus::msi::enable_msi(cap, device, 1))
                .ok()?
                .ok()?;
        let vector = narf_interrupts::vector::alloc().ok()?;
        // SAFETY: this retained owner is the sole user of the function's cfg
        // space; MSI Enable is set only after the handler is installed.
        let programmed = crate::qualcomm_pci::invoke(cap, || unsafe {
            narf_bus::msi::program_msi(&mut config, 0, vector)
        });
        if !matches!(programmed, Ok(Ok(_))) {
            let _ = narf_interrupts::vector::free(vector);
            return None;
        }
        let signal = self.signal.clone();
        *SIGNAL.lock() = Some(signal.clone());
        narf_interrupts::install_handler_named(vector, "ath10k", 0, vector_irq);
        let msi = Msi {
            config,
            vector,
            signal,
        };
        narf_interrupts::enable_irq(vector);
        // SAFETY: as above.
        let enabled =
            crate::qualcomm_pci::invoke(cap, || unsafe { narf_bus::msi::enable(&msi.config) });
        if !matches!(enabled, Ok(Ok(()))) {
            self.drop_msi(msi);
            return None;
        }
        Some(msi)
    }
    /// Clear MSI Enable and return the vector; a failed disable keeps the
    /// vector quarantined (allocated, masked, no waker) forever.
    fn drop_msi(&mut self, msi: Msi) {
        let cap = &self.mmio.cap;
        // SAFETY: sole owner of this function's MSI capability.
        let disabled =
            crate::qualcomm_pci::invoke(cap, || unsafe { narf_bus::msi::disable(&msi.config) });
        if matches!(disabled, Ok(Ok(()))) {
            release(msi);
        } else {
            quarantine(&msi);
            core::mem::forget(msi);
        }
    }
    /// `ath10k_pci_hif_start`: called once firmware runs after BMI_DONE.
    pub(super) fn start_interrupts(&mut self) {
        let Some(program) = Program::for_hw(self.hardware) else {
            return;
        };
        // Known-masked state before any vector can observe the chip.
        program.disable(&mut self.mmio);
        let Some(msi) = self.arm_msi() else {
            return;
        };
        let present: alloc::vec::Vec<u8> = self
            .hif
            .as_ref()
            .map(|h| h.pipes.iter().map(|p| p.number).collect())
            .unwrap_or_default();
        program.enable(&mut self.mmio, &irq::serviced_pipes(&present));
        self.msi = Some(msi);
        self.interrupts = Some(program);
    }
    /// `ath10k_pci_irq_disable` + `ath10k_pci_free_irq`. Safe to repeat.
    pub(super) fn stop_interrupts(&mut self) {
        if let Some(program) = self.interrupts.take() {
            program.disable(&mut self.mmio);
        }
        if let Some(msi) = self.msi.take() {
            self.drop_msi(msi);
        }
    }
    /// Service prologue run before every runtime ring poll. A firmware crash
    /// poisons this generation and hands it to automatic recovery.
    pub(super) fn service_begin(&mut self) -> Result<Option<Program>, BmiError> {
        let program = match self.interrupts {
            Some(program) => program,
            None => Program::for_hw(self.hardware).ok_or(BmiError::Unsupported)?,
        };
        if self.interrupts.is_none() {
            // Polled: the indicator is still checked on every service.
            if program.take_crash(&mut self.mmio) {
                return Err(self.crashed());
            }
            return Ok(None);
        }
        let count = self.signal.count();
        if count == self.serviced && program.summary(&mut self.mmio) == 0 {
            if program.take_crash(&mut self.mmio) {
                return Err(self.crashed());
            }
            return Ok(None);
        }
        self.serviced = count;
        match program.begin(&mut self.mmio) {
            Service::Crashed => Err(self.crashed()),
            Service::Engines(_) => Ok(Some(program)),
        }
    }
    pub(super) fn service_finish(&mut self, program: Option<Program>) {
        if let Some(program) = program {
            if program.finish(&mut self.mmio) {
                // napi_schedule: the owner's next wait returns immediately.
                self.signal.raise();
            }
        }
    }
    fn crashed(&mut self) -> BmiError {
        self.poisoned = true;
        self.firmware_crashed = true;
        if !self.retired {
            crate::ath10k::pci::firmware_crashed();
        }
        BmiError::FirmwareCrashed
    }
    /// The owner's wake source and whether a vector actually delivers it.
    pub(in crate::ath10k) fn interrupt(&self) -> (Arc<Signal>, bool) {
        (self.signal.clone(), self.msi.is_some())
    }
    pub(in crate::ath10k) fn has_crashed(&self) -> bool {
        self.firmware_crashed
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "interrupts_tests.rs"]
mod tests;
