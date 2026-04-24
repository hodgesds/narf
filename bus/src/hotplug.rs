//! PCIe Native Hot Plug event dispatch.
//!
//! Spec: `bus/specification/spec.md` §3.4 — Stage 3 covers the event
//! type + listener registration surface. Real hardware event sources
//! (Attention Button / Presence Detect Changed interrupts on PCIe
//! downstream bridges, ACPI `Notify(0|1)` from firmware) arrive with
//! the Stage-4 `interrupts/` routing work; until then the canonical
//! dispatch path is the manual `dispatch_event` hook, which is how the
//! Stage-3 tests drive the subsystem.
//!
//! Cap-gating: `register_listener` requires a live
//! `Cap<BusRegistryCap, Grant>`. Dispatch is not cap-gated — the
//! intent is that only the bus driver (TCB) calls it, and Stage-4's
//! PCIe-bridge IRQ handler will be the sole caller on real hardware.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_capabilities::{Cap, CapError, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::addr::BusAddr;
use crate::device::DeviceId;
use crate::registry::BusRegistryCap;

/// A hot-plug event. `Attach` carries full device identification so
/// listeners can decide whether they care; `Detach` is just the
/// coordinate because by the time the event fires the device is gone
/// and its `DeviceId` may not be readable from config space anymore.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum HotplugEvent {
    Attach { addr: BusAddr, device_id: DeviceId },
    Detach { addr: BusAddr },
}

impl fmt::Debug for HotplugEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HotplugEvent::Attach { addr, device_id } => f
                .debug_struct("Attach")
                .field("addr",       addr)
                .field("device_id",  device_id)
                .finish(),
            HotplugEvent::Detach { addr } => f
                .debug_struct("Detach")
                .field("addr", addr)
                .finish(),
        }
    }
}

/// Subscriber interface. Listeners are `Send + Sync` so the Stage-4
/// IRQ-driven dispatch can fan out from the bridge interrupt directly
/// without bouncing through another task.
pub trait HotplugListener: Send + Sync {
    fn on_event(&self, ev: HotplugEvent);
}

/// Errors surfaced by the hot-plug subsystem.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HotplugError {
    /// The authority cap was revoked before registration completed.
    AuthorityRevoked,
}

impl From<CapError> for HotplugError {
    fn from(_: CapError) -> Self { HotplugError::AuthorityRevoked }
}

// The listener list is stored under the simplest primitive that
// satisfies the Stage-3 invariant: exactly one writer at a time (the
// bridge ISR) fanning out to N readers. `IrqSafeSpinLock` suffices —
// the same contention argument that justifies it in `net/` and
// `drivers/` applies. Stage-4 moves this behind the `rcu/` reader path
// so dispatch never blocks on a registration.
static LISTENERS: IrqSafeSpinLock<Vec<Arc<dyn HotplugListener>>>
    = IrqSafeSpinLock::new(Vec::new());

/// Register a hot-plug listener.
///
/// Cap-gated on the `Cap<BusRegistryCap, Grant>` authority — the
/// rationale is the same as for `register_loopback` in `net/`: only
/// the subsystem minted this authority is allowed to subscribe to
/// global device events, because listeners can observe the identities
/// of every device that appears on the bus.
pub fn register_listener(
    authority: &Cap<BusRegistryCap, Grant>,
    listener:  Arc<dyn HotplugListener>,
) -> Result<(), HotplugError> {
    authority.check_live()?;
    LISTENERS.lock().push(listener);
    Ok(())
}

/// Fire a hot-plug event to every registered listener. Called by the
/// bus driver on a real PCIe bridge IRQ (Stage 4) or by tests that
/// want to exercise the listener path directly.
///
/// Not cap-gated: dispatch is the bus driver's private responsibility
/// and the trust boundary lives at registration time.
pub fn dispatch_event(ev: HotplugEvent) {
    // Copy the Arc list out of the lock so listeners can themselves
    // call back into `register_listener` without deadlocking.
    let list: Vec<Arc<dyn HotplugListener>> = {
        let g = LISTENERS.lock();
        g.clone()
    };
    for l in list.iter() {
        l.on_event(ev);
    }
}

/// Count of currently-registered listeners — useful for tests.
pub fn listener_count() -> usize {
    LISTENERS.lock().len()
}

/// Test-only: clear the listener list. The Stage-3 harness runs all
/// tests in one process and `register_listener` appends globally;
/// without this helper, tests that inspect the count would observe
/// leftover state from a previous run. Not cap-gated — scope is the
/// harness only.
#[doc(hidden)]
pub fn __clear_listeners() {
    LISTENERS.lock().clear();
}
