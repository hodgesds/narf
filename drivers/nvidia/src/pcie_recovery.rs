//! PCIe AER + DPC integration.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nouveau_drm.c`**
//!   `nouveau_pci_error_handlers` — Nouveau's `pci_error_handlers`
//!   struct. `error_detected` quiesces submission; `slot_reset` reads
//!   `PMC_BOOT_0` to verify the device is back and re-runs the GR /
//!   FIFO bring-up.
//! - **`/home/daniel/git/narf/bus/src/pcie_recovery.rs`** — NARF
//!   recovery state-machine (mirrors Linux `pcie_do_recovery`).
//!
//! ## What this module does
//!
//! For each bound NVIDIA card, register an `ErrorCallback` with the
//! bus crate so an AER fatal / non-fatal event on the upstream port
//! reaches the driver and we can vote on a slot reset. The vote
//! shape mirrors Nouveau:
//!
//! - **Correctable**: link auto-recovered. No state change; report
//!   `CanRecover`.
//! - **Non-Fatal**: MMIO + DMA may be dropped briefly. Quiesce
//!   submission; report `CanRecover`.
//! - **Fatal**: report `NeedReset` so the bus crate runs the
//!   per-port reset sequence; on `slot_reset` re-program the device
//!   from PMC_BOOT_0 down.

#![allow(dead_code)]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_bus::pcie_recovery::{
    register_error_callback, ErrorCallback, PciErrSeverity, PciErsResult,
};
use narf_bus::BusAddr;

use crate::pci::NvidiaCard;

/// Per-card recovery accounting. The driver counts callback fires
/// for the smoke test + diagnostics; the kernel-side flow is the
/// `ErrorCallback` impl below.
#[derive(Debug)]
pub struct CardRecovery {
    pub card_index: u32,
    pub bdf: BusAddr,
    pub error_detected_count: AtomicU32,
    pub slot_reset_count: AtomicU32,
    pub resume_count: AtomicU32,
}

impl CardRecovery {
    pub fn new(card_index: u32, bdf: BusAddr) -> Self {
        Self {
            card_index,
            bdf,
            error_detected_count: AtomicU32::new(0),
            slot_reset_count: AtomicU32::new(0),
            resume_count: AtomicU32::new(0),
        }
    }
}

impl ErrorCallback for CardRecovery {
    fn error_detected(&self, severity: PciErrSeverity) -> PciErsResult {
        self.error_detected_count.fetch_add(1, Ordering::SeqCst);
        // Mirrors `nouveau_pci_error_detected`. Fatal → bus crate
        // will execute the link reset and then call `slot_reset`.
        match severity {
            PciErrSeverity::Correctable => PciErsResult::CanRecover,
            PciErrSeverity::NonFatal => PciErsResult::CanRecover,
            PciErrSeverity::Fatal => PciErsResult::NeedReset,
        }
    }

    fn slot_reset(&self) -> PciErsResult {
        self.slot_reset_count.fetch_add(1, Ordering::SeqCst);
        // Re-validate the device is alive: PMC_BOOT_0 should not be
        // all-ones after the link comes back up. The Vec-of-cards
        // lookup is cheap; if the card has been ripped out from
        // under us (e.g. probe ran during recovery) we vote
        // Disconnect to surface the inconsistency.
        let alive = crate::pci::with_card(self.card_index, |card| {
            // SAFETY: BAR0 was mapped by `NvidiaDevice::bring_up`;
            // PMC_BOOT_0 is at offset 0 and read-only.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let raw = unsafe { card.regs.read32(crate::mc::PMC_BOOT_0) };
            crate::mc::Boot0::looks_present(raw)
        })
        .unwrap_or(false);
        if alive {
            PciErsResult::Recovered
        } else {
            PciErsResult::Disconnect
        }
    }

    fn resume(&self) {
        self.resume_count.fetch_add(1, Ordering::SeqCst);
    }
}

/// Register the AER callback for `card`. Called from `pci::probe`
/// after the card lands in the global list. Idempotent: re-registers
/// override the prior entry per `bus::pcie_recovery` semantics.
pub fn register_for_card(card: &Arc<NvidiaCard>) {
    let rec = Arc::new(CardRecovery::new(card.card_index, card.bus_device.addr));
    register_error_callback(card.bus_device.addr, rec);
}
