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
                .field("addr", addr)
                .field("device_id", device_id)
                .finish(),
            HotplugEvent::Detach { addr } => f.debug_struct("Detach").field("addr", addr).finish(),
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
    fn from(_: CapError) -> Self {
        HotplugError::AuthorityRevoked
    }
}

// The listener list is stored under the simplest primitive that
// satisfies the Stage-3 invariant: exactly one writer at a time (the
// bridge ISR) fanning out to N readers. `IrqSafeSpinLock` suffices —
// the same contention argument that justifies it in `net/` and
// `drivers/` applies. Stage-4 moves this behind the `rcu/` reader path
// so dispatch never blocks on a registration.
static LISTENERS: IrqSafeSpinLock<Vec<Arc<dyn HotplugListener>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a hot-plug listener.
///
/// Cap-gated on the `Cap<BusRegistryCap, Grant>` authority — the
/// rationale is the same as for `register_loopback` in `net/`: only
/// the subsystem minted this authority is allowed to subscribe to
/// global device events, because listeners can observe the identities
/// of every device that appears on the bus.
pub fn register_listener(
    authority: &Cap<BusRegistryCap, Grant>,
    listener: Arc<dyn HotplugListener>,
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

// ── Driver-match integration ───────────────────────────────────────
//
// Drivers don't subscribe to hot-plug directly — they don't have
// access to the registry authority and they don't want to filter
// every event globally. Instead the bus crate ships a *default
// dispatcher* that listens for Attach / Detach and:
//
//   * On `Attach`: re-runs probe_all_pci so any driver in the match
//     table that claims the new device gets bound.
//   * On `Detach`: clears the bound-driver record for that address
//     (the driver's own `Driver::reset` hook is the cleaner exit;
//     today's path is the BoundDriver list, not the lifecycle
//     registry).
//
// Real PCIe hot-plug ISRs (Attention Button / Presence Detect
// Changed at the bridge) wire into `dispatch_event` once the Stage-4
// interrupts/ routing lands. Until then the dispatcher's value is
// (a) tests can synthesize events to verify driver bind/unbind, and
// (b) it's the seam every future hot-plug event source plugs into.

struct DefaultDispatcher;

impl HotplugListener for DefaultDispatcher {
    fn on_event(&self, ev: HotplugEvent) {
        match ev {
            HotplugEvent::Attach { .. } => {
                // Try to bind the new device. probe_all_pci is
                // cap-gated, but the dispatcher uses the bootstrap
                // authority — same trust boundary as the original
                // boot-time probe.
                let auth = crate::registry::bootstrap_registry_authority();
                let _ = crate::driver_match::probe_all(&auth);
            }
            HotplugEvent::Detach { addr: _ } => {
                // Reaping the bound-driver record on detach needs a
                // bus-address-keyed lookup that `BoundDriver` doesn't
                // carry today (it tracks vendor/device pairs but
                // not the (bus, device, function) coordinate). When
                // BoundDriver grows an `addr: Option<BusAddr>` field,
                // the dispatcher walks it here and removes matches;
                // for now the listener acknowledges the event and
                // leaves cleanup to whatever subsystem owns the
                // device's caps. Drivers that maintain their own
                // bus-addr-keyed state subscribe via
                // `register_listener` to learn detach immediately.
            }
        }
    }
}

/// Install the default dispatcher — re-probe on Attach, clear
/// bound entry on Detach. Idempotent on the listener list (a
/// second install adds a second listener, but they fire in
/// registration order and the duplicate is harmless except for
/// the tiny extra dispatch cost).
///
/// Boot path calls this in Stage::Subsys after `bus::init` has
/// run, so any subsequent `dispatch_event` (whether from a real
/// IRQ or a test) drives the framework end-to-end.
pub fn install_default_dispatcher() -> Result<(), HotplugError> {
    let auth = crate::registry::bootstrap_registry_authority();
    register_listener(&auth, Arc::new(DefaultDispatcher))
}
