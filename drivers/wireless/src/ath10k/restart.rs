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
use alloc::collections::VecDeque;
use alloc::sync::Arc;
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
        self.request_non_crash()
    }
    /// A transport/policy cleanup failure needs the same serialized owner,
    /// but is not a firmware-crash event and must not inflate that counter.
    pub fn request_non_crash(&self) -> bool {
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

/// Immutable automatic-request scope. The current SESSION lock serializes
/// this comparison with physical retirement and successor publication.
pub(super) struct Scope<T> {
    pub generation: u64,
    pub owner: Option<Arc<T>>,
}
impl<T> Clone for Scope<T> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            owner: self.owner.clone(),
        }
    }
}
impl<T> Scope<T> {
    pub fn matches(&self, generation: u64, owner: Option<&Arc<T>>) -> bool {
        self.generation == generation
            && match &self.owner {
                Some(expected) => owner.is_some_and(|actual| Arc::ptr_eq(expected, actual)),
                None => true,
            }
    }
}

/// Pending work for the newest requested physical generation. Distinct
/// exact owners must not coalesce: a stale Arc observed late can share the
/// current epoch while still failing the final SESSION pointer comparison.
pub(super) struct Requests<T>(VecDeque<Scope<T>>);
impl<T> Requests<T> {
    pub const fn new() -> Self {
        Self(VecDeque::new())
    }
    /// Return rejected/superseded owners for dropping after the queue lock.
    pub fn enqueue(&mut self, request: Scope<T>) -> (Option<Scope<T>>, VecDeque<Scope<T>>) {
        let mut superseded = VecDeque::new();
        if self
            .0
            .front()
            .is_some_and(|old| old.generation > request.generation)
            || self.0.iter().any(|old| {
                old.generation == request.generation
                    && match (&old.owner, &request.owner) {
                        (None, _) => true,
                        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                        _ => false,
                    }
            })
        {
            return (Some(request), superseded);
        }
        if request.owner.is_none()
            || self
                .0
                .front()
                .is_some_and(|old| old.generation < request.generation)
        {
            core::mem::swap(&mut self.0, &mut superseded);
        }
        self.0.push_back(request);
        (None, superseded)
    }
    pub fn take(&mut self) -> Option<Scope<T>> {
        self.0.pop_front()
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

/// `None` means this exact request's physical owner was already retired.
/// Never retry such a request against whichever successor now occupies SESSION.
pub(super) async fn supervise_scoped<R, RF, D, DF>(
    mut recover: R,
    mut delay: D,
    retries: u32,
) -> Outcome
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<Option<RecoveryScheduled>, RecoveryError>>,
    D: FnMut() -> DF,
    DF: Future<Output = ()>,
{
    for _ in 0..retries {
        match recover().await {
            Ok(Some(RecoveryScheduled { attempt })) => return Outcome::Scheduled { attempt },
            Ok(None) => return Outcome::Abandoned,
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
