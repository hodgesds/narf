//! PCIe AER + DPC integration for AMD GPUs.
//!
//! Each bound AMD GPU registers an `ErrorCallback` with the narf-bus
//! PCIe recovery machinery. When an AER fatal / non-fatal event hits
//! the GPU's upstream port, the bus crate routes it here:
//!
//!   1. [`AmdgpuRecovery::error_detected`] votes on what recovery the
//!      channel state calls for.
//!   2. On a frozen channel the bus crate does the link reset and then
//!      calls [`AmdgpuRecovery::slot_reset`], which confirms the ASIC
//!      is back by reading `RCC_CONFIG_MEMSIZE` — and votes
//!      `Disconnect` when it is not.
//!   3. [`AmdgpuRecovery::resume`] runs only for a channel that was
//!      frozen, which is the only case with anything to resume.
//!
//! ## What this does not do
//!
//! The ladder stops at the vote. Linux's `amdgpu_pci_slot_reset` also
//! restores saved PCI config space and runs a full ASIC reset through
//! `amdgpu_device_asic_reset`, and its `amdgpu_pci_resume` restarts the
//! schedulers; neither is wired up here, and `resume` is a counter plus
//! the frozen gate. That is a gap, not a design: it is recorded here
//! rather than described in the present tense, because an earlier
//! version of this file documented the vendor-ID check, a soft-reset
//! quiesce and an end-to-end `BacoController` run that no line of code
//! performed.
//!
//! ## References
//!
//! - Linux drivers/gpu/drm/amd/amdgpu/amdgpu_device.c::
//!   amdgpu_pci_error_detected / amdgpu_pci_slot_reset / amdgpu_pci_resume
//! - NARF bus/src/pcie_recovery.rs

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};

use narf_bus::pcie_recovery::{ErrorCallback, PciChannelState, PciErrSeverity, PciErsResult};
use narf_bus::BusAddr;

/// Per-card recovery state. Bumps counters on each callback so the
/// kernel-side observability surface can see how often a GPU has
/// surfaced AER events.
#[derive(Debug)]
pub struct AmdgpuRecovery {
    pub card_index: u32,
    pub bdf: BusAddr,
    pub error_detected_count: AtomicU32,
    pub slot_reset_count: AtomicU32,
    /// Resumes that did work — i.e. that followed a frozen channel.
    pub resume_count: AtomicU32,
    /// Resumes skipped because the channel was never frozen. Linux
    /// returns early in that case; this counts the early returns so a
    /// skipped resume is visible rather than silent.
    pub resume_skipped_count: AtomicU32,
    /// Highest-severity error seen this recovery cycle, as
    /// [`severity_byte`]. Observability only — nothing in the ladder
    /// branches on it, because the channel state is what the vote and
    /// the resume gate key off.
    pub last_severity_byte: AtomicU32,
    /// Channel state from the last `error_detected`, as
    /// [`channel_state_byte`]. Read by [`AmdgpuRecovery::resume`],
    /// standing in for Linux's `adev->pci_channel_state`.
    pub last_state_byte: AtomicU32,
}

impl AmdgpuRecovery {
    pub fn new(card_index: u32, bdf: BusAddr) -> Self {
        Self {
            card_index,
            bdf,
            error_detected_count: AtomicU32::new(0),
            slot_reset_count: AtomicU32::new(0),
            resume_count: AtomicU32::new(0),
            resume_skipped_count: AtomicU32::new(0),
            last_severity_byte: AtomicU32::new(0),
            last_state_byte: AtomicU32::new(0),
        }
    }

    pub fn error_count(&self) -> u32 {
        self.error_detected_count.load(Ordering::SeqCst)
    }

    pub fn last_severity(&self) -> Option<PciErrSeverity> {
        match self.last_severity_byte.load(Ordering::SeqCst) {
            1 => Some(PciErrSeverity::Correctable),
            2 => Some(PciErrSeverity::NonFatal),
            3 => Some(PciErrSeverity::Fatal),
            _ => None,
        }
    }

    pub fn last_state(&self) -> Option<PciChannelState> {
        match self.last_state_byte.load(Ordering::SeqCst) {
            1 => Some(PciChannelState::Normal),
            2 => Some(PciChannelState::Frozen),
            3 => Some(PciChannelState::PermFailure),
            _ => None,
        }
    }
}

fn severity_byte(sev: PciErrSeverity) -> u32 {
    match sev {
        PciErrSeverity::Correctable => 1,
        PciErrSeverity::NonFatal => 2,
        PciErrSeverity::Fatal => 3,
    }
}

fn channel_state_byte(state: PciChannelState) -> u32 {
    match state {
        PciChannelState::Normal => 1,
        PciChannelState::Frozen => 2,
        PciChannelState::PermFailure => 3,
    }
}

impl ErrorCallback for AmdgpuRecovery {
    fn error_detected(&self, severity: PciErrSeverity, state: PciChannelState) -> PciErsResult {
        self.error_detected_count.fetch_add(1, Ordering::SeqCst);
        self.last_severity_byte
            .store(severity_byte(severity), Ordering::SeqCst);
        self.last_state_byte
            .store(channel_state_byte(state), Ordering::SeqCst);

        // `amdgpu_pci_error_detected` switches on the channel state and
        // never looks at the AER severity:
        //
        //   io_normal       -> CAN_RECOVER   (MMIO still works)
        //   io_frozen       -> NEED_RESET    (after halting activities)
        //   io_perm_failure -> DISCONNECT    (device is gone)
        //
        // The third arm is why the state has to reach us. Severity has
        // no value meaning "permanently dead", so a callback that keys
        // off severity can only ever vote CanRecover or NeedReset, and
        // the bus crate would go on to call `mmio_enabled` against a
        // device that will never answer.
        match state {
            PciChannelState::Normal => PciErsResult::CanRecover,
            PciChannelState::Frozen => PciErsResult::NeedReset,
            PciChannelState::PermFailure => PciErsResult::Disconnect,
        }
    }

    fn slot_reset(&self) -> PciErsResult {
        self.slot_reset_count.fetch_add(1, Ordering::SeqCst);

        // Linux polls the PCI vendor ID for up to 10 s and then polls
        // `amdgpu_asic_get_config_memsize` until it is not 0xffffffff,
        // failing with -ETIME either way and returning DISCONNECT. We
        // have no config-space accessor in this layer, but the second
        // poll is the one that proves the die is back rather than the
        // link, and it is an MMIO read we can make. A single read, not
        // a poll: the bus crate's reset path has already waited.
        let alive = crate::amdgpu::with_controller(|gpu| {
            // SAFETY: `gpu.regs` maps BAR5, mapped at probe and alive
            // for as long as the controller is; `with_controller` holds
            // the controller lock, so the MM_INDEX latch is ours.
            unsafe { crate::amdgpu::config_memsize_alive(&gpu.regs) }
        });
        match alive {
            Some(true) => PciErsResult::Recovered,
            // Either the ASIC answered all-ones, or there is no bound
            // controller to ask. Both mean we cannot claim recovery.
            Some(false) | None => PciErsResult::Disconnect,
        }
    }

    fn resume(&self) {
        // `amdgpu_pci_resume` returns immediately unless the channel
        // was frozen: a non-fatal error that recovered through
        // `mmio_enabled` never halted anything, so there is nothing to
        // restart and restarting anyway would be a reset the hardware
        // did not ask for.
        if self.last_state() != Some(PciChannelState::Frozen) {
            self.resume_skipped_count.fetch_add(1, Ordering::SeqCst);
            return;
        }
        self.resume_count.fetch_add(1, Ordering::SeqCst);
        // The driver glue that belongs here — restoring config space
        // and running the reset ladder back to Active — is the gap
        // named in the module docs.
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn rec() -> Arc<AmdgpuRecovery> {
        Arc::new(AmdgpuRecovery::new(
            0,
            BusAddr::Pcie(narf_bus::PcieAddr::new(0, 1, 0, 0)),
        ))
    }

    fn smoke_recovery_votes_follow_channel_state() -> TestResult {
        // One case per arm of `amdgpu_pci_error_detected`'s switch.
        let cases = [
            (
                PciErrSeverity::NonFatal,
                PciChannelState::Normal,
                PciErsResult::CanRecover,
            ),
            (
                PciErrSeverity::Fatal,
                PciChannelState::Frozen,
                PciErsResult::NeedReset,
            ),
            (
                PciErrSeverity::Fatal,
                PciChannelState::PermFailure,
                PciErsResult::Disconnect,
            ),
        ];
        for (sev, state, want) in cases {
            let r = rec();
            if r.error_detected(sev, state) != want {
                return TestResult::Fail("channel state voted the wrong recovery");
            }
            if r.error_count() != 1 {
                return TestResult::Fail("error count not bumped");
            }
            if r.last_severity() != Some(sev) {
                return TestResult::Fail("last severity wrong");
            }
            if r.last_state() != Some(state) {
                return TestResult::Fail("last channel state wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_recovery_votes_follow_channel_state);

    /// A permanently-dead device must be able to lose. This is the vote
    /// the callback could not express while it was handed only the AER
    /// severity, and it is the whole reason the state is a parameter.
    fn smoke_recovery_perm_failure_disconnects() -> TestResult {
        let r = rec();
        // Severity deliberately varied: none of the three may turn a
        // dead channel into a recoverable one.
        for sev in [
            PciErrSeverity::Correctable,
            PciErrSeverity::NonFatal,
            PciErrSeverity::Fatal,
        ] {
            if r.error_detected(sev, PciChannelState::PermFailure) != PciErsResult::Disconnect {
                return TestResult::Fail("perm failure must vote Disconnect at any severity");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_recovery_perm_failure_disconnects);

    /// Linux's `amdgpu_pci_resume` early-returns unless the channel was
    /// frozen. Without a bound controller the state is `None`, which is
    /// also not frozen, so both of these skip.
    fn smoke_recovery_resume_runs_only_after_frozen() -> TestResult {
        let r = rec();
        r.resume();
        if r.resume_count.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("resume before any error must not do work");
        }
        if r.resume_skipped_count.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("skipped resume must be counted");
        }

        r.error_detected(PciErrSeverity::NonFatal, PciChannelState::Normal);
        r.resume();
        if r.resume_count.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("resume after a normal channel must not do work");
        }
        if r.resume_skipped_count.load(Ordering::SeqCst) != 2 {
            return TestResult::Fail("second skipped resume must be counted");
        }

        r.error_detected(PciErrSeverity::Fatal, PciChannelState::Frozen);
        r.resume();
        r.resume();
        if r.resume_count.load(Ordering::SeqCst) != 2 {
            return TestResult::Fail("resume after a frozen channel must do work");
        }
        if r.resume_skipped_count.load(Ordering::SeqCst) != 2 {
            return TestResult::Fail("a frozen resume must not count as skipped");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_recovery_resume_runs_only_after_frozen);

    /// With no GPU bound — which is the state under the test harness —
    /// the liveness read has nobody to ask, and that cannot read as
    /// recovered.
    fn smoke_recovery_slot_reset_without_asic_disconnects() -> TestResult {
        let r = rec();
        let res = r.slot_reset();
        if crate::amdgpu::is_probed() {
            // A real card is bound; either vote is legitimate, only the
            // counter is assertable here.
            if res == PciErsResult::None {
                return TestResult::Fail("slot_reset must cast a vote");
            }
        } else if res != PciErsResult::Disconnect {
            return TestResult::Fail("slot_reset with no ASIC to probe must vote Disconnect");
        }
        if r.slot_reset_count.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("slot reset count not bumped");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_recovery_slot_reset_without_asic_disconnects
    );

    fn smoke_recovery_state_bytes_round_trip() -> TestResult {
        for state in [
            PciChannelState::Normal,
            PciChannelState::Frozen,
            PciChannelState::PermFailure,
        ] {
            let r = rec();
            r.last_state_byte
                .store(channel_state_byte(state), Ordering::SeqCst);
            if r.last_state() != Some(state) {
                return TestResult::Fail("channel state byte did not round-trip");
            }
        }
        // Zero is "nothing seen yet", and must not decode as a state.
        let r = rec();
        if r.last_state().is_some() || r.last_severity().is_some() {
            return TestResult::Fail("a fresh recovery must report no state");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_recovery_state_bytes_round_trip);
}
