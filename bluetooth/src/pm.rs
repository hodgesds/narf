//! Per-controller power-management state (issue #820).
//!
//! The Bluetooth stack used to track power as a bare mgmt settings
//! bitmap (`mgmt::SETTING_POWERED`): `SET_POWERED` flipped the bit
//! and nothing in the datapath changed, and the sysfs
//! `idle_timeout` attribute was a hard-coded `"0"`. This module is
//! the single source of truth for what a controller is actually
//! doing, power-wise:
//!
//! - **park causes** — three independent reasons the HCI pump must
//!   not touch the transport. The pump gate ([`is_parked`]) is the
//!   OR of all three; each cause is set and cleared by its owner:
//!   - `mgmt` — userspace powered the controller off (mgmt
//!     `SET_POWERED(0)` / `HCIDEVDOWN`). Cleared by power-on.
//!   - `system` — the machine is suspending (device-PM
//!     [`suspend_controller`] / [`resume_controller`], driven by
//!     `power::device_pm`). Cleared by the resume fan-out.
//!   - `autosuspend` — the USB hub idle-suspend pass parked the
//!     controller's port (`drivers/usb` `btusb` suspend hook).
//!     Cleared by the wake-watch (remote-wakeup edge) or by the
//!     transport's TX-demand resume.
//! - **power reporting** — [`parked_for_power`] is the mgmt/system
//!   subset: `mgmt::is_powered` is the `POWERED` setting bit AND NOT
//!   parked-for-power. Runtime (autosuspend) parking deliberately
//!   does NOT clear the powered bit: Linux keeps `HCI_UP` across a
//!   runtime suspend, and userspace would see the adapter flap
//!   up/down every idle window otherwise.
//! - **idle policy** — [`idle_timeout_ms`] is the per-controller
//!   idle timeout the sysfs `idle_timeout` attribute reports
//!   (Linux `hdev->idle_timeout`). Default
//!   [`DEFAULT_IDLE_TIMEOUT_MS`] mirrors the USB hub autosuspend
//!   window (`narf_drivers_usb::attach::IDLE_SUSPEND_NS`, 30 s) —
//!   that window is the idle power-down that actually runs in
//!   NARF, so reporting Linux's default 0 would lie about it.
//!   `0` keeps its Linux meaning ("never autosuspend"): the btusb
//!   suspend hook vetoes gating for a controller whose timeout is
//!   0. [`set_idle_timeout_ms`] is the setter for a future sysfs
//!   store path; nothing in-tree writes it yet.
//!
//! All operations are plain flag stores under one short spinlock
//! hold: callable from device-PM handlers (interrupts gated, no
//! scheduling), from the mgmt socket path, and from the pump task.
//! No function here performs I/O, sleeps, or calls back into
//! `power` — the park flags are the contract; the drivers that own
//! each cause do their own hardware work around them.
//!
//! PCIe controllers (`btintel_pcie`) are not covered yet: they
//! never enter the HCI controller registry (their transport is
//! registered but `register_ready_transport` is never called), so
//! there is no HCI index to key this state off. Wiring PCIe PM is
//! a follow-up (see the #820 PR body).

extern crate alloc;

use alloc::collections::BTreeMap;

use narf_lib::sync::IrqSafeSpinLock;

/// Idle timeout (ms) a fresh controller reports, and the value the
/// USB hub autosuspend pass effectively enforces.
///
/// 30 000 ms = the hub's `IDLE_SUSPEND_NS` (30 s). Linux defaults
/// `hdev->idle_timeout` to 0, but NARF's hub pass gates idle USB
/// ports after 30 s regardless, so 0 would misreport the policy
/// that actually runs. `0` still means "never autosuspend" when
/// explicitly set (see [`set_idle_timeout_ms`]).
pub const DEFAULT_IDLE_TIMEOUT_MS: u32 = 30_000;

/// Per-controller park/power state. All causes default to
/// unparked; the idle timeout defaults to
/// [`DEFAULT_IDLE_TIMEOUT_MS`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PmState {
    /// Parked by mgmt power-off (`SET_POWERED(0)` / `HCIDEVDOWN`).
    parked_mgmt: bool,
    /// Parked by system suspend (device-PM fan-out).
    parked_system: bool,
    /// Parked by USB autosuspend (hub idle-suspend pass).
    parked_autosuspend: bool,
    /// Idle timeout in ms; 0 = never autosuspend.
    idle_timeout_ms: u32,
}

impl Default for PmState {
    fn default() -> Self {
        Self {
            parked_mgmt: false,
            parked_system: false,
            parked_autosuspend: false,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
        }
    }
}

/// Per-controller PM state, keyed by HCI index. A missing entry
/// reads as the default state (unparked, default idle timeout).
static STATES: IrqSafeSpinLock<BTreeMap<usize, PmState>> = IrqSafeSpinLock::new(BTreeMap::new());

fn state(index: usize) -> PmState {
    *STATES.lock().entry(index).or_default()
}

fn update(index: usize, f: impl FnOnce(&mut PmState)) {
    f(STATES.lock().entry(index).or_default());
}

/// Whether the pump must not touch controller `index`'s transport
/// right now — parked for any cause (mgmt off, system suspend, or
/// USB autosuspend). The pump gate in `pump::pump_once` reads this.
pub fn is_parked(index: usize) -> bool {
    let s = state(index);
    s.parked_mgmt || s.parked_system || s.parked_autosuspend
}

/// Whether controller `index` is parked for a *power* reason (mgmt
/// power-off or system suspend). This is what clears the truthful
/// `mgmt::is_powered` report; a runtime (autosuspend) park does
/// not — Linux keeps `HCI_UP` across runtime suspend.
pub fn parked_for_power(index: usize) -> bool {
    let s = state(index);
    s.parked_mgmt || s.parked_system
}

/// Whether controller `index` is parked by USB autosuspend (its
/// hub port gated by the idle-suspend pass). Read by the btusb
/// wake-watch to find ports that may resume on a remote-wakeup
/// edge.
pub fn is_runtime_suspended(index: usize) -> bool {
    state(index).parked_autosuspend
}

/// Park controller `index` for mgmt power-off. Idempotent.
pub fn park_mgmt(index: usize) {
    update(index, |s| s.parked_mgmt = true);
}

/// Clear the mgmt power-off park. Idempotent; does not clear a
/// system-suspend or autosuspend park (see [`is_parked`]).
pub fn unpark_mgmt(index: usize) {
    update(index, |s| s.parked_mgmt = false);
}

/// Park controller `index` for system suspend. Called by the
/// device-PM suspend handler (`narf_power::device_pm`). Idempotent.
pub fn suspend_controller(index: usize) {
    update(index, |s| s.parked_system = true);
}

/// Clear the system-suspend park. Called by the device-PM resume
/// handler. Idempotent; does not clear a mgmt or autosuspend park.
pub fn resume_controller(index: usize) {
    update(index, |s| s.parked_system = false);
}

/// Park controller `index` for USB autosuspend. Called by the
/// btusb class suspend hook before the hub pass gates the port.
/// Idempotent.
pub fn park_autosuspend(index: usize) {
    update(index, |s| s.parked_autosuspend = true);
}

/// Clear the USB-autosuspend park. Called by the btusb wake-watch
/// (remote-wakeup edge) and by the transport's TX-demand resume.
/// Idempotent.
pub fn unpark_autosuspend(index: usize) {
    update(index, |s| s.parked_autosuspend = false);
}

/// Idle timeout (ms) for controller `index` — the value sysfs
/// `idle_timeout` reports. Defaults to
/// [`DEFAULT_IDLE_TIMEOUT_MS`]; 0 means "never autosuspend".
pub fn idle_timeout_ms(index: usize) -> u32 {
    state(index).idle_timeout_ms
}

/// Set controller `index`'s idle timeout (ms). `0` disables
/// autosuspend for the controller (Linux semantics); any other
/// value is the idle window after which the hub pass may gate its
/// port. Writable from userspace via the sysfs `idle_timeout`
/// store path (`sysfs_bridge`); see #1577.
pub fn set_idle_timeout_ms(index: usize, ms: u32) {
    update(index, |s| s.idle_timeout_ms = ms);
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATES.lock().clear();
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pm_park_causes_are_independent() -> TestResult {
        __reset_for_test();
        // Fresh controller: unparked on every cause.
        if is_parked(0) || parked_for_power(0) || is_runtime_suspended(0) {
            return TestResult::Fail("fresh controller reads parked");
        }
        // Autosuspend park alone: parked, but NOT parked-for-power
        // (HCI_UP stays up across runtime suspend).
        park_autosuspend(0);
        if !is_parked(0) || !is_runtime_suspended(0) || parked_for_power(0) {
            return TestResult::Fail("autosuspend park mis-reported");
        }
        // Clearing it unparks fully — no other cause was set.
        unpark_autosuspend(0);
        if is_parked(0) || is_runtime_suspended(0) {
            return TestResult::Fail("autosuspend unpark did not clear");
        }
        // Mgmt park: parked-for-power; a concurrent autosuspend
        // park does not change that, and clearing mgmt alone
        // leaves the autosuspend park standing.
        park_mgmt(0);
        park_autosuspend(0);
        if !parked_for_power(0) || !is_runtime_suspended(0) {
            return TestResult::Fail("combined parks mis-reported");
        }
        unpark_mgmt(0);
        if parked_for_power(0) || !is_parked(0) {
            return TestResult::Fail("mgmt unpark cleared the autosuspend park too");
        }
        unpark_autosuspend(0);
        if is_parked(0) {
            return TestResult::Fail("controller still parked after all causes cleared");
        }
        // System suspend park is independent of the mgmt park.
        suspend_controller(0);
        if !parked_for_power(0) || !is_parked(0) {
            return TestResult::Fail("system suspend park mis-reported");
        }
        resume_controller(0);
        if is_parked(0) || parked_for_power(0) {
            return TestResult::Fail("system resume did not clear");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pm", smoke_pm_park_causes_are_independent);

    fn smoke_pm_suspend_resume_idempotent() -> TestResult {
        __reset_for_test();
        suspend_controller(3);
        suspend_controller(3);
        if !is_parked(3) {
            return TestResult::Fail("double suspend did not park");
        }
        resume_controller(3);
        resume_controller(3);
        if is_parked(3) {
            return TestResult::Fail("double resume did not unpark");
        }
        // Controllers are independent: index 3's park never
        // touched index 4.
        suspend_controller(3);
        if is_parked(4) {
            return TestResult::Fail("park leaked across controller indices");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pm", smoke_pm_suspend_resume_idempotent);

    fn smoke_pm_idle_timeout_default_and_set() -> TestResult {
        __reset_for_test();
        if idle_timeout_ms(0) != DEFAULT_IDLE_TIMEOUT_MS {
            return TestResult::Fail("idle timeout default is not the hub window");
        }
        set_idle_timeout_ms(0, 0);
        if idle_timeout_ms(0) != 0 {
            return TestResult::Fail("idle timeout 0 did not stick");
        }
        set_idle_timeout_ms(0, 5_000);
        if idle_timeout_ms(0) != 5_000 {
            return TestResult::Fail("idle timeout set did not stick");
        }
        // Setting one controller's timeout leaves the other's default.
        if idle_timeout_ms(1) != DEFAULT_IDLE_TIMEOUT_MS {
            return TestResult::Fail("idle timeout set leaked across indices");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pm", smoke_pm_idle_timeout_default_and_set);
}
