// SPDX-License-Identifier: GPL-2.0-or-later
//! System suspend/resume without WoWLAN.
//!
//! Linux v6.10 without a WoWLAN configuration: mac80211 `ieee80211_suspend`
//! calls `drv_stop` -> `mac.c::ath10k_stop` -> `ath10k_halt` +
//! `ath10k_hif_power_down`; `pci.c::ath10k_pci_pm_suspend` ->
//! `ath10k_pci_suspend` puts the target to sleep. On resume
//! `ath10k_pci_pm_resume` -> `ath10k_pci_resume` re-disables the PCI
//! RETRY_TIMEOUT byte (config 0x41, reset by D3) and wakes the target, then
//! mac80211 `ieee80211_reconfig` -> `ath10k_start` -> `ath10k_hif_power_up`
//! performs a full chip reset and firmware boot.
//!
//! Here `prepare_suspend` retires the live generation with the same DMA-stop
//! proof as recovery (every CE source masked, CE halted, bus mastering off,
//! ordered flush), parks the function identity and resume clears config
//! 0x41 then schedules the ordinary fresh-ROM boot. WoWLAN
//! (`wow.c`, `wake_offload` row) and host-bus runtime PM are not provided.
use super::bmi::BmiError;

/// Why system suspend was refused; the live generation stays usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspendError {
    /// Boot or automatic recovery is in progress (no retained session).
    Busy,
    /// Earlier unprovable retirements already pinned the bounded number of
    /// DMA generations; another power-down could leak further memory.
    Pinned,
    /// Retiring the generation failed; it is terminal and stays pinned.
    Failed(BmiError),
}

/// Unreclaimed generations a suspend may leave pinned per boot (matching
/// the recovery attempt bound).
pub(super) const PINNED_LIMIT: u8 = 3;

/// Facts sampled under the session lock before retiring anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    pub device: bool,
    pub session: bool,
    pub restarting: bool,
    pub pinned: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// No ath10k function is bound: nothing to quiesce.
    Nothing,
    /// Retire the generation and park its function identity.
    Retire,
}

pub(super) fn plan(facts: Facts) -> Result<Plan, SuspendError> {
    if !facts.device {
        return Ok(Plan::Nothing);
    }
    if facts.restarting || !facts.session {
        return Err(SuspendError::Busy);
    }
    if facts.pinned >= PINNED_LIMIT {
        return Err(SuspendError::Pinned);
    }
    Ok(Plan::Retire)
}

/// `ath10k_pci_resume`: clear the RETRY_TIMEOUT byte of config dword 0x40.
pub(super) fn retry_timeout(value: u32) -> Option<u32> {
    (value & 0x0000_ff00 != 0).then_some(value & 0xffff_00ff)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "pm/tests.rs"]
mod tests;
