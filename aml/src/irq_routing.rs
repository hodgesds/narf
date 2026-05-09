//! Boot-time PCI INTx → GSI routing table built from `_PRT` results.
//!
//! `frame::bare_main` walks every PCIe root bridge declared in the
//! AML namespace, calls `prt_crs::evaluate_prt_for(bridge)`, and
//! deposits the entries here. Consumers (the future IOAPIC
//! programmer, the PCI bind path that needs a legacy IRQ for an
//! INTx-only device) read back via [`for_each_route`] or
//! [`route_for`].
//!
//! Today this is "build it once at boot, read-only after." A future
//! pass that re-routes IRQs at runtime (CPU hotplug, NUMA migration)
//! will need a richer surface; this module is the seam.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::resource::PrtEntry;

/// One entry in the global routing table. Carries the originating
/// bridge path so a per-bridge IOAPIC programmer can find its own
/// rows; the embedded `PrtEntry` is the raw decoded shape from
/// `_PRT`'s 4-tuple package.
#[derive(Clone, Debug)]
pub struct Route {
    /// Path of the PCIe root bridge whose `_PRT` produced this row,
    /// e.g. `"\\_SB.PCI0"`. Useful when multiple bridges expose the
    /// same `(slot, pin)` pair behind different IOAPICs.
    pub bridge: String,
    /// The decoded `_PRT` 4-tuple.
    pub entry: PrtEntry,
}

static ROUTES: IrqSafeSpinLock<Vec<Route>> = IrqSafeSpinLock::new(Vec::new());

/// Append every entry in `entries` to the global routing table,
/// tagged with `bridge`. Idempotent across `_PRT` re-evaluations
/// only when the caller drains the table first; a future
/// `_PIC` mode-switch redo would call [`clear`] before reposting.
pub fn register_bridge(bridge: &str, entries: &[PrtEntry]) {
    let mut g = ROUTES.lock();
    g.reserve(entries.len());
    for e in entries {
        g.push(Route {
            bridge: bridge.to_string(),
            entry: e.clone(),
        });
    }
}

/// Iterate every registered route. The lock is held across `f` —
/// callers should not re-enter `narf_aml::eval::*` from within
/// the closure (would deadlock the namespace lock).
pub fn for_each_route<F: FnMut(&Route)>(mut f: F) {
    let g = ROUTES.lock();
    for r in g.iter() {
        f(r);
    }
}

/// Look up a single (bridge, slot, pin) triple. `pin` is 0..3 for
/// INTA..INTD. Returns the first matching route — usually exactly
/// one entry per (bridge, slot, pin).
pub fn route_for(bridge: &str, slot: u8, pin: u8) -> Option<Route> {
    let g = ROUTES.lock();
    for r in g.iter() {
        if r.bridge != bridge {
            continue;
        }
        let r_slot = ((r.entry.address >> 16) & 0xFFFF) as u32;
        if r_slot as u8 == slot && r.entry.pin == pin {
            return Some(r.clone());
        }
    }
    None
}

/// Number of registered routes.
pub fn len() -> usize {
    ROUTES.lock().len()
}

/// Drain the global table — useful before re-evaluating `_PRT`
/// after an interrupt-mode change.
pub fn clear() {
    ROUTES.lock().clear();
}
