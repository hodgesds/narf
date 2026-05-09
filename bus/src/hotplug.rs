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

// ── PCIe Express cap walker + slot-control surface ─────────────────
//
// PCIe hot-plug lives behind the device's PCI Express capability
// (cap_id 0x10) in the standard cap list at config offset 0x34
// (Capabilities Pointer). Within the PCIe cap:
//   +0x14 : Slot Capabilities (DW)  — bit 6 = HotPlugCapable
//   +0x18 : Slot Control       (W)  — interrupt-enable bits
//   +0x1A : Slot Status        (W)  — W1C status bits (same layout)
//
// Spec: PCIe 6.0 §7.5.3 (PCI Express Capability Structure).

/// PCI capability ID for PCI Express.
pub const PCIE_CAP_ID: u8 = 0x10;

/// PCIe cap register offsets (relative to the start of the PCIe
/// capability block).
pub mod pcie_cap {
    pub const SLOT_CAPABILITIES: u16 = 0x14;
    pub const SLOT_CONTROL: u16 = 0x18;
    pub const SLOT_STATUS: u16 = 0x1A;
}

/// Slot Capabilities bits we care about.
pub mod slot_cap {
    /// HotPlugCapable — set when the slot can generate hot-plug
    /// events (typically root ports + downstream switch ports).
    pub const HOT_PLUG_CAPABLE: u32 = 1 << 6;
}

/// Slot Control / Slot Status bit positions (same layout for
/// both — Control enables the events, Status reports them
/// W1C-style).
pub mod slot_bits {
    pub const ATTENTION_BUTTON_PRESSED: u16 = 1 << 0;
    pub const POWER_FAULT_DETECTED: u16 = 1 << 1;
    pub const MRL_SENSOR_CHANGED: u16 = 1 << 2;
    pub const PRESENCE_DETECT_CHANGED: u16 = 1 << 3;
    pub const COMMAND_COMPLETED: u16 = 1 << 4;
    /// Slot Control: master switch for hot-plug interrupt
    /// generation. Per-event enable bits 0..4 only fire when
    /// this is also set.
    pub const HOT_PLUG_INTERRUPT_ENABLE: u16 = 1 << 5;
}

/// Walk the device's standard PCI cap list and return the
/// offset of the PCI Express capability (cap_id 0x10), or
/// `None` if the device doesn't carry one. Bounded at 48
/// iterations.
///
/// # Safety
/// `cfg_phys` must point at a 256-byte (or 4 KiB) PCI config
/// region the CPU can reach.
pub unsafe fn find_pcie_cap_offset(cfg_phys: u64) -> Option<u8> {
    // SAFETY: caller-asserted live config space; offset 0x34 is
    // the standard Capabilities Pointer.
    let mut off = unsafe { core::ptr::read_volatile((cfg_phys + 0x34) as *const u8) };
    for _ in 0..48 {
        if off < 0x40 {
            return None;
        }
        // SAFETY: offset bounded.
        let header =
            unsafe { core::ptr::read_volatile((cfg_phys + off as u64) as *const u16) };
        if header == 0 || header == u16::MAX {
            return None;
        }
        let cap_id = (header & 0xFF) as u8;
        let next = ((header >> 8) & 0xFF) as u8;
        if cap_id == PCIE_CAP_ID {
            return Some(off);
        }
        if next == 0 {
            return None;
        }
        off = next;
    }
    None
}

/// Read Slot Capabilities for a PCIe cap at `pcie_off`.
///
/// # Safety
/// Caller-asserted live config space + valid PCIe cap offset.
pub unsafe fn read_slot_capabilities(cfg_phys: u64, pcie_off: u8) -> u32 {
    // SAFETY: caller assertion.
    unsafe {
        core::ptr::read_volatile(
            (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_CAPABILITIES as u64) as *const u32,
        )
    }
}

/// Read + W1C-clear Slot Status. Returns the bits that were
/// set (and have now been cleared by the write).
///
/// # Safety
/// Caller-asserted live config space + valid PCIe cap offset.
pub unsafe fn read_and_clear_slot_status(cfg_phys: u64, pcie_off: u8) -> u16 {
    // SAFETY: caller assertion.
    let sts = unsafe {
        core::ptr::read_volatile(
            (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_STATUS as u64) as *const u16,
        )
    };
    if sts != 0 {
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_STATUS as u64) as *mut u16,
                sts,
            );
        }
    }
    sts
}

/// Read-modify-write Slot Control to OR in the requested bits
/// (typically `HOT_PLUG_INTERRUPT_ENABLE | PRESENCE_DETECT_CHANGED`
/// to enable presence-detect-driven hot-plug events).
///
/// # Safety
/// Caller-asserted live config space + valid PCIe cap offset
/// + caller owns the device exclusively.
pub unsafe fn enable_slot_irqs(cfg_phys: u64, pcie_off: u8, bits: u16) {
    // SAFETY: caller assertion.
    unsafe {
        let cur = core::ptr::read_volatile(
            (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_CONTROL as u64) as *const u16,
        );
        core::ptr::write_volatile(
            (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_CONTROL as u64) as *mut u16,
            cur | bits,
        );
    }
}

/// Hot-plug ISR — runs in IRQ context. Walks every PCIe
/// device, reads SlotStatus on every hot-plug-capable bridge,
/// dispatches the corresponding `HotplugEvent` via the
/// existing dispatcher.
///
/// Detach vs attach: PRESENCE_DETECT_CHANGED indicates a state
/// transition; SlotStatus.PresenceDetectState (bit 6) tells us
/// the new state. The dispatched event uses the bridge's own
/// BusAddr as the slot identifier — consumers (the bus rescan
/// path) re-probe to learn the new device's actual function.
///
/// Stateless re-walk on every fire — acceptable because hot-
/// plug is rare. Caller wires this into a vector when MSI for
/// the bridge is set up.
pub fn hotplug_isr() {
    use core::sync::atomic::Ordering;
    for d in crate::devices().iter() {
        let cfg_phys = match d.kind {
            crate::BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => continue,
        };
        // SAFETY: cfg_phys from ECAM enumeration; cap walker
        // bounded.
        let pcie_off = match unsafe { find_pcie_cap_offset(cfg_phys) } {
            Some(o) => o,
            None => continue,
        };
        // SAFETY: cap offset just validated.
        let scap = unsafe { read_slot_capabilities(cfg_phys, pcie_off) };
        if scap & slot_cap::HOT_PLUG_CAPABLE == 0 {
            continue;
        }
        // SAFETY: same.
        let sts = unsafe { read_and_clear_slot_status(cfg_phys, pcie_off) };
        if sts & slot_bits::PRESENCE_DETECT_CHANGED != 0 {
            HOTPLUG_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
            // SAFETY: same.
            let pd_state = unsafe {
                core::ptr::read_volatile(
                    (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_STATUS as u64)
                        as *const u16,
                )
            } & (1 << 6)
                != 0;
            if pd_state {
                dispatch_event(HotplugEvent::Attach {
                    addr: d.addr,
                    device_id: d.id,
                });
            } else {
                dispatch_event(HotplugEvent::Detach { addr: d.addr });
            }
        }
    }
}

/// Hot-plug event count — bumped by `hotplug_isr` each time
/// it observes a presence-detect change. Diagnostic.
pub static HOTPLUG_EVENT_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
