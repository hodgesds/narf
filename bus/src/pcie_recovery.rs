//! PCIe error-recovery state machine.
//!
//! Implements the driver-facing error-recovery callbacks plus the
//! `do_recovery` walker that maps an AER / DPC event onto the
//! per-driver `error_detected` → `mmio_enabled` → `slot_reset` →
//! `resume` lifecycle.
//!
//! ## Sources
//!
//! - **PCIe Base Specification, Revision 6.0**, PCI-SIG —
//!   §6.2 (Advanced Error Reporting), §6.14 (Error Reporting and
//!   Recovery), §6.16 (Downstream Port Containment).
//!   <https://pcisig.com/specifications>
//! - **Linux**, `drivers/pci/pcie/err.c` (`pcie_do_recovery` + voting),
//!   GPL-2.0. See `include/linux/pci.h` for the
//!   `pci_ers_result_t` / `pci_channel_state_t` shape we mirror.
//!
//! ## Shape
//!
//! Recovery is broadcast: when a Root Port or Downstream Port reports
//! an error, every device beneath that port has its driver's
//! `error_detected` callback invoked. The callbacks vote on the
//! recovery mode; the highest-severity vote wins (see
//! [`merge_result`]). Then, depending on the consensus, mmio_enabled
//! and/or slot_reset are broadcast next, finishing with resume.
//!
//! A device that has no registered callback votes
//! `NoAerDriver`; the recovery is then aborted with permanent failure
//! per Linux semantics (a single un-handled endpoint poisons the
//! whole subtree, since slot_reset would orphan its driver).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::addr::BusAddr;

/// What kind of error the Root Port / DPC port saw. Mirrors Linux's
/// `pci_channel_state_t`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciChannelState {
    /// Channel is operational; this is the post-recovery state.
    /// Used by `error_detected` for non-fatal errors that don't
    /// freeze MMIO.
    Normal,
    /// Channel is frozen — MMIO + DMA are dropped. Driver must
    /// quiesce, then wait for `slot_reset`. Used by DPC and fatal
    /// AER.
    Frozen,
    /// Channel is permanently dead. Driver should release all
    /// resources; no future callback will fire.
    PermFailure,
}

/// Per-device error severity passed to `error_detected`. Mirrors the
/// PCIe AER classification: a Root Port aggregates correctable +
/// non-fatal + fatal messages into this triple.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciErrSeverity {
    /// Correctable error — link auto-recovered, driver gets a
    /// notification only (no state-machine churn).
    Correctable,
    /// Non-Fatal — operation failed but link is up. Driver retries.
    NonFatal,
    /// Fatal — link is unusable; reset required.
    Fatal,
}

/// A driver's vote on what should happen next. Mirrors Linux's
/// `pci_ers_result_t`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciErsResult {
    /// Driver had nothing to say — falls through to the prior vote.
    None,
    /// Driver thinks the device can recover without a slot reset.
    /// Promotes the recovery into the `mmio_enabled` phase.
    CanRecover,
    /// Driver requires a slot reset before it can resume.
    NeedReset,
    /// Driver has given up — device is to be marked disconnected.
    Disconnect,
    /// Recovery is complete; driver has reattached.
    Recovered,
    /// No registered AER-aware driver on this device. Linux treats
    /// this as a hard stop because un-coordinated drivers can't
    /// safely cross a slot reset.
    NoAerDriver,
}

/// Merge an existing recovery vote with a new one. Linux's
/// `merge_result()` in `err.c` — the order matters because the
/// recovery state machine progresses monotonically through:
///   `CanRecover` → `Recovered` (mmio_enabled phase) →
///   `NeedReset` → slot_reset → `Recovered` (resume phase).
///
/// `Disconnect` only gives way to `NeedReset` (a chance to revive);
/// `NoAerDriver` is absorbing — once any device votes it, the
/// whole subtree fails.
pub fn merge_result(orig: PciErsResult, new: PciErsResult) -> PciErsResult {
    if new == PciErsResult::NoAerDriver {
        return PciErsResult::NoAerDriver;
    }
    if new == PciErsResult::None {
        return orig;
    }
    match orig {
        PciErsResult::CanRecover | PciErsResult::Recovered => new,
        PciErsResult::Disconnect => {
            if new == PciErsResult::NeedReset {
                PciErsResult::NeedReset
            } else {
                orig
            }
        }
        _ => orig,
    }
}

/// Driver hook into the recovery pipeline. Each driver implements
/// this and registers via [`register_error_callback`].
///
/// Mirrors `struct pci_error_handlers` from Linux's `include/linux/
/// pci.h`. The methods are deliberately small (`fn` not `async fn`)
/// because they fire from an interrupt-or-near-IRQ context where
/// allocation and blocking are out.
pub trait ErrorCallback: Send + Sync {
    /// Called immediately after the Root Port detects an error.
    /// `severity` is the AER classification (Correctable, NonFatal,
    /// or Fatal). Driver should quiesce any in-flight work and
    /// return what kind of recovery is needed.
    fn error_detected(&self, severity: PciErrSeverity) -> PciErsResult;

    /// Called after every driver in the affected subtree returned
    /// `CanRecover` — MMIO is back, no slot reset needed. Driver
    /// re-validates state. Default: nothing.
    fn mmio_enabled(&self) -> PciErsResult {
        PciErsResult::Recovered
    }

    /// Called after a slot / link reset has completed. Driver
    /// re-programs BARs, re-arms MSI, returns `Recovered` if it's
    /// back in business.
    fn slot_reset(&self) -> PciErsResult {
        PciErsResult::Recovered
    }

    /// Called at the end of a successful recovery — driver resumes
    /// normal operation.
    fn resume(&self);
}

// ── Per-BDF callback registry ─────────────────────────────────────
//
// Linux ties `pci_error_handlers` to the `pci_driver` struct and
// looks it up via the driver model. We don't have that — we have a
// flat table keyed by `BusAddr`. The table is small (≤ low double
// digits in practice — only AER-aware drivers register) so a Vec
// scan beats a HashMap for both space and IRQ-context safety.

/// Registry entry — opaque to consumers.
struct CallbackEntry {
    addr: BusAddr,
    cb: Arc<dyn ErrorCallback>,
}

impl core::fmt::Debug for CallbackEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallbackEntry")
            .field("addr", &self.addr)
            .finish()
    }
}

static CALLBACKS: IrqSafeSpinLock<Vec<CallbackEntry>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a driver's error callback for `bdf`. Replaces any
/// previously registered entry. Safe to call from any context.
pub fn register_error_callback(bdf: BusAddr, cb: Arc<dyn ErrorCallback>) {
    let mut tbl = CALLBACKS.lock();
    if let Some(slot) = tbl.iter_mut().find(|e| e.addr == bdf) {
        slot.cb = cb;
        return;
    }
    tbl.push(CallbackEntry { addr: bdf, cb });
}

/// Remove a callback. Called when a driver is being unbound.
pub fn unregister_error_callback(bdf: BusAddr) {
    let mut tbl = CALLBACKS.lock();
    tbl.retain(|e| e.addr != bdf);
}

/// Look up a registered callback. Returns `None` if no driver opted in.
pub fn lookup_error_callback(bdf: BusAddr) -> Option<Arc<dyn ErrorCallback>> {
    let tbl = CALLBACKS.lock();
    tbl.iter().find(|e| e.addr == bdf).map(|e| e.cb.clone())
}

/// Test helper — clear all registered callbacks.
#[doc(hidden)]
pub fn __clear_error_callbacks() {
    CALLBACKS.lock().clear();
}

/// Test helper — return the number of registered callbacks.
#[doc(hidden)]
pub fn error_callback_count() -> usize {
    CALLBACKS.lock().len()
}

// ── Recovery state machine ────────────────────────────────────────

/// Outcome of [`do_recovery`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Every device under the affected port reported `Recovered`
    /// after the broadcast lifecycle ran. Channel is back to Normal.
    Recovered,
    /// A device required a slot reset and the platform-supplied
    /// reset callback failed. Subtree is permanently failed.
    ResetFailed,
    /// At least one device in the subtree had no AER-aware driver,
    /// so the recovery couldn't safely cross a slot reset.
    NoDriver,
    /// At least one device voted Disconnect after slot_reset —
    /// recovery did the broadcast but driver refused to come back.
    Disconnected,
}

/// Result of the platform-supplied reset callback.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResetResult {
    /// Reset succeeded; link is back up.
    Recovered,
    /// Reset failed; subtree is dead.
    Failed,
}

/// Drive the AER / DPC recovery pipeline for the subtree named by
/// `subtree`. Each entry is broadcast in iteration order — caller
/// passes the BDFs in tree order from the affected port downwards.
///
/// `state` is the initial channel state. `Frozen` skips straight to
/// the slot_reset arm (driver must rebuild MMIO after reset);
/// `Normal` runs the can_recover → mmio_enabled fast path first.
///
/// `reset_fn` is the platform-supplied function that does the
/// actual link / slot reset between the `error_detected` and
/// `slot_reset` broadcasts. For DPC this is "clear TRIGGERED and
/// wait for link Active"; for non-DPC AER it's the link-disable /
/// re-enable dance in [`crate::pcie_aer::link_retrain`].
///
/// Reference: Linux `pcie_do_recovery()` in `drivers/pci/pcie/err.c`.
pub fn do_recovery(
    subtree: &[BusAddr],
    severity: PciErrSeverity,
    state: PciChannelState,
    reset_fn: &mut dyn FnMut() -> ResetResult,
) -> RecoveryOutcome {
    // Snapshot all the callbacks up-front so a concurrent
    // register/unregister can't change the broadcast set mid-flight.
    let cbs: Vec<(BusAddr, Option<Arc<dyn ErrorCallback>>)> = subtree
        .iter()
        .map(|a| (*a, lookup_error_callback(*a)))
        .collect();

    // Phase 1 — error_detected broadcast.
    let mut status = PciErsResult::CanRecover;
    for (_, cb) in &cbs {
        let vote = match cb {
            Some(cb) => cb.error_detected(severity),
            None => PciErsResult::NoAerDriver,
        };
        status = merge_result(status, vote);
    }

    if status == PciErsResult::NoAerDriver {
        return RecoveryOutcome::NoDriver;
    }

    // Phase 2 — if every driver voted CanRecover, run the
    // mmio_enabled broadcast (no reset needed).
    if status == PciErsResult::CanRecover {
        status = PciErsResult::Recovered;
        for (_, cb) in &cbs {
            if let Some(cb) = cb {
                status = merge_result(status, cb.mmio_enabled());
            }
        }
    }

    // Phase 3 — reset path. Triggered if any driver voted NeedReset
    // OR if the channel started frozen (DPC / fatal-severity AER).
    if status == PciErsResult::NeedReset || state == PciChannelState::Frozen {
        match reset_fn() {
            ResetResult::Recovered => {}
            ResetResult::Failed => return RecoveryOutcome::ResetFailed,
        }
    }

    // Phase 4 — slot_reset broadcast if status said NeedReset OR if
    // the channel was frozen (we ran the reset above either way).
    if status == PciErsResult::NeedReset || state == PciChannelState::Frozen {
        status = PciErsResult::Recovered;
        for (_, cb) in &cbs {
            if let Some(cb) = cb {
                status = merge_result(status, cb.slot_reset());
            }
        }
    }

    if status != PciErsResult::Recovered {
        return RecoveryOutcome::Disconnected;
    }

    // Phase 5 — resume broadcast. Drivers re-arm queues / MSI.
    for (_, cb) in &cbs {
        if let Some(cb) = cb {
            cb.resume();
        }
    }

    RecoveryOutcome::Recovered
}
