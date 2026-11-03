// SPDX-License-Identifier: GPL-2.0-or-later
//! System-wake arming for interrupt lines: Linux `enable_irq_wake` /
//! `disable_irq_wake` (`kernel/irq/manage.c::irq_set_irq_wake`) and the
//! suspend-time wakeup check (`kernel/irq/pm.c::irq_pm_check_wakeup` ->
//! `pm_system_irq_wakeup`).
//!
//! Both in-tree controllers are `IRQCHIP_SKIP_SET_WAKE` in Linux (x86
//! `io_apic.c` `ioapic_chip`/`ioapic_ir_chip`, `irq-gic-v3.c` `gic_chip`):
//! arming programs nothing in the controller and only records a per-line
//! wake depth. What makes an armed line a wake source is the system-PM
//! owner: while it holds the suspend window open ([`set_suspend_window`],
//! Linux `suspend_device_irqs`/`resume_device_irqs`) it leaves every
//! [`armed_vectors`] entry unmasked, and a delivery on an armed vector
//! latches [`wakeup_pending`] (Linux `IRQD_WAKEUP_ARMED` ->
//! `pm_system_irq_wakeup`). Outside the window a delivery is an ordinary
//! interrupt and latches nothing.
//!
//! Whether the platform then actually resumes from a given sleep state is
//! not decided here: an s2idle park keeps the CPU powered so the armed
//! vector itself ends the park (`narf-power` `s2idle`), while ACPI S3 wake
//! is firmware-owned (GPE/PME routing, `narf-power` `pci_wake`). An
//! aarch64 platform has no s2idle park yet; its system-PM owner must keep
//! armed SPIs enabled and consume [`wakeup_pending`] the same way.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeError {
    /// The interrupt controller cannot route a wake (no in-tree backend).
    Unsupported,
    /// Exceptions (vectors below 32) are never wake sources.
    InvalidVector,
    /// Wake depth would overflow.
    Overflow,
    /// `disable_irq_wake` without a matching enable (Linux: "Unbalanced
    /// IRQ %d wake disable").
    Unbalanced,
}

const NO_DEPTH: AtomicU8 = AtomicU8::new(0);
static DEPTH: [AtomicU8; 256] = [NO_DEPTH; 256];
static WINDOW: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicBool = AtomicBool::new(false);
/// Last wake vector + 1 (0 = none).
static LAST: AtomicU16 = AtomicU16::new(0);

fn controller_supported() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

/// Linux `enable_irq_wake`: count one more wake user of `vector`.
pub fn enable_irq_wake(vector: u8) -> Result<(), WakeError> {
    if vector < 32 {
        return Err(WakeError::InvalidVector);
    }
    if !controller_supported() {
        return Err(WakeError::Unsupported);
    }
    DEPTH[usize::from(vector)]
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
            depth.checked_add(1)
        })
        .map(|_| ())
        .map_err(|_| WakeError::Overflow)
}

/// Linux `disable_irq_wake`: drop one wake user of `vector`.
pub fn disable_irq_wake(vector: u8) -> Result<(), WakeError> {
    if vector < 32 {
        return Err(WakeError::InvalidVector);
    }
    DEPTH[usize::from(vector)]
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
            depth.checked_sub(1)
        })
        .map(|_| ())
        .map_err(|_| WakeError::Unbalanced)
}

/// Whether `vector` has at least one wake user.
pub fn wake_armed(vector: u8) -> bool {
    DEPTH[usize::from(vector)].load(Ordering::Acquire) != 0
}

/// Every wake-armed vector, for the system-PM owner's suspend mask
/// allowlist.
pub fn armed_vectors() -> alloc::vec::Vec<u8> {
    (32u8..=255).filter(|&vector| wake_armed(vector)).collect()
}

/// The system-PM owner opens the window right before it parks/suspends
/// (clearing any stale wakeup) and closes it once resumed. Closing
/// consumes the pending latch; [`last_wakeup`] keeps the reason.
pub fn set_suspend_window(open: bool) {
    if open {
        LAST.store(0, Ordering::Release);
    }
    PENDING.store(false, Ordering::Release);
    WINDOW.store(open, Ordering::Release);
}

/// Hard-IRQ hook (atomics only): a delivery on `vector`. Latches a system
/// wakeup only for an armed vector inside the suspend window.
pub fn note_delivery(vector: u8) {
    if WINDOW.load(Ordering::Acquire) && wake_armed(vector) {
        LAST.store(u16::from(vector) + 1, Ordering::Release);
        PENDING.store(true, Ordering::Release);
    }
}

/// A wake-armed interrupt fired inside the suspend window.
pub fn wakeup_pending() -> bool {
    PENDING.load(Ordering::Acquire)
}

/// The vector of the last wakeup, if any (Linux `pm_wakeup_irq`).
pub fn last_wakeup() -> Option<u8> {
    match LAST.load(Ordering::Acquire) {
        0 => None,
        n => Some((n - 1) as u8),
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    for depth in DEPTH.iter() {
        depth.store(0, Ordering::Release);
    }
    set_suspend_window(false);
}

#[path = "wake_tests.rs"]
mod tests;
