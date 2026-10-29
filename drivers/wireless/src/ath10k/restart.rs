// SPDX-License-Identifier: GPL-2.0-or-later
//! Automatic firmware recovery.
//!
//! Linux (v6.10) `pci.c::ath10k_pci_napi_poll` checks
//! `ath10k_pci_has_fw_crashed` before any CE service, clears the indicator
//! and queues `ath10k_pci_fw_dump_work`, which bumps `fw_crash_counter` and
//! calls `core.c::ath10k_core_start_recovery`. That function deduplicates
//! with `ATH10K_FLAG_RESTARTING` and queues `ath10k_core_restart`, which
//! halts the old state and restarts the hardware; a restart that fails while
//! already restarting marks the device `ATH10K_STATE_WEDGED`.
//!
//! Here the PCIe owner's interrupt/poll service detects the indicator
//! (`boot/interrupts.rs`), poisons its generation and calls
//! [`super::pci::firmware_crashed`]. That gate spawns one supervisor which
//! drives the existing `pci::recover()` fresh-generation path (retire with
//! the DMA-stop proof, chip reset, ROM/firmware/BDF, HTC/WMI/HTT, interface
//! registration). The bounded per-boot attempt budget is the WEDGED state.
//! Rejoin is through the newly registered interface; credentials, keys and
//! association state are not replayed (no `ieee80211_restart_hw`
//! reconfiguration equivalent exists in the shared wireless crate).
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::pci::{RecoveryError, RecoveryScheduled};

/// `ATH10K_FLAG_RESTARTING` plus `ar->stats.fw_crash_counter`.
pub(super) struct Gate {
    restarting: AtomicBool,
    crashes: AtomicU32,
}
impl Gate {
    pub const fn new() -> Self {
        Self {
            restarting: AtomicBool::new(false),
            crashes: AtomicU32::new(0),
        }
    }
    /// Count the crash; `true` only for the request that must start the
    /// supervisor (`test_and_set_bit` in `ath10k_core_start_recovery`).
    pub fn request(&self) -> bool {
        self.crashes.fetch_add(1, Ordering::AcqRel);
        !self.restarting.swap(true, Ordering::AcqRel)
    }
    pub fn complete(&self) {
        self.restarting.store(false, Ordering::Release);
    }
    pub fn restarting(&self) -> bool {
        self.restarting.load(Ordering::Acquire)
    }
    pub fn crashes(&self) -> u32 {
        self.crashes.load(Ordering::Acquire)
    }
}

/// Terminal result of one automatic recovery request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A fresh generation was scheduled (not yet ready).
    Scheduled { attempt: u8 },
    /// The per-boot attempt budget is spent (`ATH10K_STATE_WEDGED`).
    Wedged,
    /// Retirement of the crashed generation failed; it stays pinned.
    Failed(super::bmi::BmiError),
    /// No retained generation appeared within the wait budget.
    Abandoned,
}

/// Polls between `Busy` retries: a crash observed by a boot stage stores its
/// owner in the session slot only after that stage returns.
pub(super) const BUSY_RETRIES: u32 = 100;
pub(super) const BUSY_DELAY_MS: u64 = 50;

pub(super) async fn supervise<R, RF, D, DF>(mut recover: R, mut delay: D, retries: u32) -> Outcome
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<RecoveryScheduled, RecoveryError>>,
    D: FnMut() -> DF,
    DF: Future<Output = ()>,
{
    for _ in 0..retries {
        match recover().await {
            Ok(RecoveryScheduled { attempt }) => return Outcome::Scheduled { attempt },
            Err(RecoveryError::Exhausted) => return Outcome::Wedged,
            Err(RecoveryError::Transport(error)) => return Outcome::Failed(error),
            Err(RecoveryError::Busy) => delay().await,
        }
    }
    Outcome::Abandoned
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "restart/tests.rs"]
mod tests;
