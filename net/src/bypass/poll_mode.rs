//! DPDK-style polling-mode toggle.
//!
//! When polling mode is ON, the NIC's RX IRQ is masked and the
//! userspace daemon (or the kernel's RX-pump task) drives FILL/RX
//! synchronously. When OFF, the driver re-enables the IRQ and
//! returns to interrupt-driven RX.
//!
//! Linux ref: DPDK `rte_eth_dev_promiscuous_enable` +
//! `rte_intr_disable`. There's no direct AF_XDP equivalent — the
//! IRQ stays live on XSK and the kernel pumps on each receive — but
//! NARF needs the toggle because a userspace stack daemon will
//! want to pin a CPU on the FILL/RX rings and not pay per-frame
//! IRQ latency.
//!
//! The actual IRQ mask happens in the driver via the per-iface
//! `set_rx_irq_enabled` callback installed at probe. This module
//! holds the registration table + per-iface state bit so a caller
//! that doesn't own the driver vtable can still query the iface's
//! mode.

use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Invoke};
use narf_lib::sync::IrqSafeSpinLock;

use crate::AdminCap;

use super::classifier;

/// Per-iface driver callback. Returns `Ok(())` on a successful mask
/// toggle, `Err(())` if the driver doesn't support runtime IRQ
/// gating (rare for modern NICs but possible on the legacy paths).
pub type SetIrqEnabledFn = fn(bool) -> Result<(), ()>;

struct Entry {
    iface_name: String,
    set_irq: SetIrqEnabledFn,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("iface_name", &self.iface_name)
            .finish_non_exhaustive()
    }
}

static IRQ_TABLE: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Errors from the poll-mode API.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PollModeError {
    /// No IRQ-mask callback registered for this iface.
    UnknownIface,
    /// Driver-side toggle returned an error.
    DriverFailed,
    /// AdminCap is revoked / wrong-region.
    AdminCapRevoked,
}

/// Register a driver-side IRQ-mask callback. Called from the NIC
/// driver's probe path after the iface has been registered with
/// `iface::register`. Idempotent: a re-probe overwrites the
/// previous callback.
pub fn register_driver(iface_name: &str, set_irq: SetIrqEnabledFn) {
    let mut g = IRQ_TABLE.lock();
    if let Some(e) = g.iter_mut().find(|e| e.iface_name == iface_name) {
        e.set_irq = set_irq;
        return;
    }
    g.push(Entry {
        iface_name: alloc::string::String::from(iface_name),
        set_irq,
    });
}

/// Toggle poll mode for `iface_name`. Verifies the supplied
/// `AdminCap` is live, calls the driver to mask/unmask, then
/// updates the classifier's per-iface bit.
///
/// Linux ref: `rte_intr_disable` (DPDK) + `napi_disable` (XDP
/// path in `linux/net/core/dev.c`).
pub fn set_poll_mode(
    admin: &Cap<AdminCap, Invoke>,
    iface_name: &str,
    on: bool,
) -> Result<(), PollModeError> {
    admin
        .check_live()
        .map_err(|_| PollModeError::AdminCapRevoked)?;
    let set_irq = {
        let g = IRQ_TABLE.lock();
        g.iter()
            .find(|e| e.iface_name == iface_name)
            .map(|e| e.set_irq)
    };
    match set_irq {
        Some(f) => {
            // Driver wants `enabled` (the opposite of `poll mode on`).
            f(!on).map_err(|_| PollModeError::DriverFailed)?;
        }
        None => {
            // No driver-side callback registered (loopback, test
            // fakes). Track the state in software anyway; the
            // poll-mode query API returns the right answer and the
            // smokes can validate plumbing without a real driver.
        }
    }
    classifier::set_poll_mode(iface_name, on);
    Ok(())
}

/// `true` iff the iface is currently in poll mode (RX IRQ masked).
pub fn is_poll_mode(iface_name: &str) -> bool {
    classifier::is_poll_mode(iface_name)
}

/// `true` iff the iface's RX IRQ is enabled (opposite of poll mode).
pub fn rx_irq_enabled(iface_name: &str) -> bool {
    !classifier::is_poll_mode(iface_name)
}

/// Test reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    IRQ_TABLE.lock().clear();
}
