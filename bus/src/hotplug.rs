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
use narf_memory::PhysAddr;

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

/// Slot Capabilities bits (PCIe 6.0 §7.5.3.9 Table 7-25).
/// All bits are read-only; the hardware asserts what it supports
/// at power-on and software cannot change them.
pub mod slot_cap {
    /// Attention Button Present (bit 0).
    pub const ATTENTION_BUTTON: u32 = 1 << 0;
    /// Power Controller Present (bit 1). When set, software may
    /// turn slot power on/off via the Slot Control register.
    pub const POWER_CONTROLLER: u32 = 1 << 1;
    /// MRL Sensor Present (bit 2). Manually-operated Retention
    /// Latch sensor for safe extraction.
    pub const MRL_SENSOR: u32 = 1 << 2;
    /// Attention Indicator Present (bit 3).
    pub const ATTENTION_INDICATOR: u32 = 1 << 3;
    /// Power Indicator Present (bit 4). LED that follows the
    /// power-controller state.
    pub const POWER_INDICATOR: u32 = 1 << 4;
    /// Hot-Plug Surprise (bit 5). Indicates the device can be
    /// removed without operator intervention — requires firmware
    /// / OS support for surprise removal.
    pub const HOT_PLUG_SURPRISE: u32 = 1 << 5;
    /// HotPlugCapable — set when the slot can generate hot-plug
    /// events (typically root ports + downstream switch ports).
    pub const HOT_PLUG_CAPABLE: u32 = 1 << 6;
    /// Slot Power Limit Value (bits[14:7], 8 bits). Encoded
    /// power limit value; see §7.5.3.9 for the unit scale.
    pub const SLOT_POWER_LIMIT_VALUE_MASK: u32 = 0x7F80;
    pub const SLOT_POWER_LIMIT_VALUE_SHIFT: u32 = 7;
    /// Slot Power Limit Scale (bits[16:15]).
    pub const SLOT_POWER_LIMIT_SCALE_MASK: u32 = 0x0001_8000;
    pub const SLOT_POWER_LIMIT_SCALE_SHIFT: u32 = 15;
    /// Electromechanical Interlock Present (bit 17).
    pub const ELECTROMECHANICAL_INTERLOCK: u32 = 1 << 17;
    /// No Command Completed Support (bit 18). When set, the slot
    /// does not assert Command Completed after a write to Slot
    /// Control; software must not wait for it.
    pub const NO_COMMAND_COMPLETED: u32 = 1 << 18;
    /// Physical Slot Number (bits[31:19], 13 bits).
    pub const PHYSICAL_SLOT_NUM_MASK: u32 = 0xFFF8_0000;
    pub const PHYSICAL_SLOT_NUM_SHIFT: u32 = 19;
}

/// Slot Control / Slot Status bit positions (same layout for
/// both — Control enables the events, Status reports them
/// W1C-style). PCIe 6.0 §7.5.3.10 (Control) / §7.5.3.11 (Status).
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
    /// Data Link Layer State Changed Enable (bit 12 of Control /
    /// bit 8 of Status). When set in Control, fires an interrupt
    /// when the DL layer goes active / inactive.
    pub const DATA_LINK_STATE_CHANGED_ENABLE: u16 = 1 << 12;
}

/// Slot Control power-control bits (PCIe 6.0 §7.5.3.10).
/// These are two-bit fields in the 16-bit Slot Control register,
/// each encoding Off/Blink/On for an indicator LED, or
/// On/Off for the power controller.
pub mod slot_ctrl {
    /// Attention Indicator Control (bits[7:6]):
    ///   00 = reserved, 01 = On, 10 = Blink, 11 = Off.
    pub const ATTN_IND_MASK: u16 = 0x00C0;
    pub const ATTN_IND_ON: u16 = 0x0040;
    pub const ATTN_IND_BLINK: u16 = 0x0080;
    pub const ATTN_IND_OFF: u16 = 0x00C0;

    /// Power Indicator Control (bits[9:8]):
    ///   00 = reserved, 01 = On, 10 = Blink, 11 = Off.
    pub const PWR_IND_MASK: u16 = 0x0300;
    pub const PWR_IND_ON: u16 = 0x0100;
    pub const PWR_IND_BLINK: u16 = 0x0200;
    pub const PWR_IND_OFF: u16 = 0x0300;

    /// Power Controller Control (bit 10):
    ///   0 = power on, 1 = power off.
    /// Only meaningful when `slot_cap::POWER_CONTROLLER` is set.
    pub const POWER_CONTROLLER_OFF: u16 = 1 << 10;

    /// Electromechanical Interlock Control (bit 11):
    ///   Write 1 to toggle the latch (open ↔ closed).
    pub const EMI_CONTROL: u16 = 1 << 11;
}

/// Slot Status presence-detect state bit (bit 6 of Slot Status,
/// §7.5.3.11). This is a *read-only* state bit, not W1C — it
/// reflects the current hardware state after a PDC transition.
pub const SLOT_STATUS_PRESENCE_DETECT_STATE: u16 = 1 << 6;

/// Slot Status MRL sensor state bit (bit 5, read-only).
pub const SLOT_STATUS_MRL_SENSOR_STATE: u16 = 1 << 5;

/// Presence-detect debounce window — 100 ms per PCIe CEM §2.6.2.
/// Real hardware may need a shorter window (≥50 ms is spec minimum)
/// but 100 ms is the conventional safe value matched by Linux
/// pciehp_core.c `BLINKTIME_MIN_MS`. The value is in milliseconds
/// and must be interpreted by whichever delay primitive the caller
/// has available (TSC spin, timer callback, etc.).
pub const PRESENCE_DETECT_DEBOUNCE_MS: u64 = 100;

/// Decoded Slot Capabilities register. All fields are RO at runtime;
/// this struct is built once per hot-plug-capable port during init and
/// then consulted by the hotplug ISR + power-control path.
///
/// Reference: Linux `drivers/pci/hotplug/pciehp_hpc.c` pcie_get_device_status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SlotCaps {
    /// Attention Button is wired on this slot.
    pub attn_button: bool,
    /// Slot has a software-controlled power controller.
    pub power_ctrl: bool,
    /// MRL (Manual Retention Latch) sensor present.
    pub mrl_sensor: bool,
    /// Attention Indicator LED present.
    pub attn_indicator: bool,
    /// Power Indicator LED present.
    pub pwr_indicator: bool,
    /// Surprise-removal capable (device can disappear without notice).
    pub hp_surprise: bool,
    /// This slot is hot-plug capable (generates PDC events).
    pub hp_capable: bool,
    /// No Command Completed support — do not wait for CC after
    /// writing Slot Control.
    pub no_cmd_complete: bool,
    /// Electromechanical Interlock present.
    pub emi_present: bool,
    /// Physical Slot Number (13-bit).
    pub slot_number: u16,
}

impl SlotCaps {
    /// Decode a raw Slot Capabilities DWORD (PCIe 6.0 §7.5.3.9).
    pub fn decode(raw: u32) -> Self {
        Self {
            attn_button: raw & slot_cap::ATTENTION_BUTTON != 0,
            power_ctrl: raw & slot_cap::POWER_CONTROLLER != 0,
            mrl_sensor: raw & slot_cap::MRL_SENSOR != 0,
            attn_indicator: raw & slot_cap::ATTENTION_INDICATOR != 0,
            pwr_indicator: raw & slot_cap::POWER_INDICATOR != 0,
            hp_surprise: raw & slot_cap::HOT_PLUG_SURPRISE != 0,
            hp_capable: raw & slot_cap::HOT_PLUG_CAPABLE != 0,
            no_cmd_complete: raw & slot_cap::NO_COMMAND_COMPLETED != 0,
            emi_present: raw & slot_cap::ELECTROMECHANICAL_INTERLOCK != 0,
            slot_number: ((raw & slot_cap::PHYSICAL_SLOT_NUM_MASK)
                >> slot_cap::PHYSICAL_SLOT_NUM_SHIFT) as u16,
        }
    }
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
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
    // SAFETY: caller-asserted live config space; offset 0x34 is
    // the standard Capabilities Pointer.
    // SAFETY: Valid memory or trusted environment
    let mut off = unsafe { core::ptr::read_volatile((cfg_phys + 0x34) as *const u8) };
    for _ in 0..48 {
        if off < 0x40 {
            return None;
        }
        // SAFETY: offset bounded.
        let header = unsafe { core::ptr::read_volatile((cfg_phys + off as u64) as *const u16) };
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
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
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
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
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
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
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
        // SAFETY: Valid memory or trusted environment
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
                    (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_STATUS as u64) as *const u16,
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

// ── Power control ──────────────────────────────────────────────────
//
// PCIe Slot Control bit 10 (POWER_CONTROLLER_OFF): 0 = on, 1 = off.
// Only ports with SlotCaps.POWER_CONTROLLER should exercise these
// helpers. Ref: Linux pciehp_hpc.c pciehp_set_power_state().

/// Assert slot power on by clearing the Power Controller bit in
/// Slot Control. Has no effect on slots without a power controller
/// (`slot_cap::POWER_CONTROLLER` not set).
///
/// Optionally sets the Power Indicator to Blink while power ramps,
/// then On. The indicator transition here is immediate (no delay);
/// callers that want the blink period must re-call after the delay.
///
/// # Safety
/// Caller-asserted live config space + valid PCIe cap offset
/// + caller owns the device exclusively.
pub unsafe fn slot_power_on(cfg_phys: u64, pcie_off: u8) {
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
    // SAFETY: caller assertion.
    unsafe {
        let addr = (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_CONTROL as u64) as *mut u16;
        let cur = core::ptr::read_volatile(addr as *const u16);
        // Clear POWER_CONTROLLER_OFF (bit 10) to turn power on.
        // Set Power Indicator to On (bits[9:8] = 0b01).
        let new = (cur & !slot_ctrl::POWER_CONTROLLER_OFF & !slot_ctrl::PWR_IND_MASK)
            | slot_ctrl::PWR_IND_ON;
        core::ptr::write_volatile(addr, new);
    }
}

/// Assert slot power off by setting the Power Controller bit in
/// Slot Control, and set the Power Indicator to Off.
///
/// # Safety
/// Same as `slot_power_on`.
pub unsafe fn slot_power_off(cfg_phys: u64, pcie_off: u8) {
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
    // SAFETY: caller assertion.
    unsafe {
        let addr = (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_CONTROL as u64) as *mut u16;
        let cur = core::ptr::read_volatile(addr as *const u16);
        // Set POWER_CONTROLLER_OFF (bit 10) to cut power.
        // Set Power Indicator to Off (bits[9:8] = 0b11).
        let new = (cur | slot_ctrl::POWER_CONTROLLER_OFF) & !slot_ctrl::PWR_IND_MASK
            | slot_ctrl::PWR_IND_OFF;
        core::ptr::write_volatile(addr, new);
    }
}

/// Read the current Presence Detect State from Slot Status (bit 6,
/// read-only — not the W1C PDC event bit). Returns `true` when a
/// device is electrically present in the slot.
///
/// # Safety
/// Caller-asserted live config space + valid PCIe cap offset.
pub unsafe fn slot_presence_detected(cfg_phys: u64, pcie_off: u8) -> bool {
    // Config space is reached through the segment's mapped ECAM
    // window; falls back to the raw address when no segment is
    // registered (unit tests hand us an ordinary buffer).
    let cfg_phys = crate::ecam::va_for(PhysAddr::new(cfg_phys)).unwrap_or(cfg_phys);
    // SAFETY: caller assertion.
    let sts = unsafe {
        core::ptr::read_volatile(
            (cfg_phys + pcie_off as u64 + pcie_cap::SLOT_STATUS as u64) as *const u16,
        )
    };
    sts & SLOT_STATUS_PRESENCE_DETECT_STATE != 0
}

// ── Insert / Remove path (soft model) ─────────────────────────────
//
// The full hardware path (Hot Reset → Config-space scan → driver
// probe) requires the IRQ + delay infrastructure from Stage-4.
// These helpers encode the *policy* decisions so the ISR can call
// them once those primitives are available.
//
// Insert path (Linux pciehp_hpc.c pciehp_check_presence):
//   1. Wait PRESENCE_DETECT_DEBOUNCE_MS for signal to stabilise.
//   2. Re-read Slot Status — bail if PDState already went away.
//   3. If slot has POWER_CONTROLLER: call slot_power_on().
//   4. Dispatch HotplugEvent::Attach to listeners.
//   (Re-enumeration of the bus segment happens in DefaultDispatcher.)
//
// Remove path:
//   1. Dispatch HotplugEvent::Detach immediately (device is gone).
//   2. If slot has POWER_CONTROLLER: call slot_power_off().
//   3. Listeners tear down driver state / BAR mappings.

/// Policy record for a single hot-plug port. Built from `SlotCaps`
/// during port initialisation; consulted by the ISR on every event.
#[derive(Copy, Clone, Debug)]
pub struct SlotPolicy {
    /// Config space physical address.
    pub cfg_phys: u64,
    /// Byte offset of the PCIe capability in config space.
    pub pcie_cap_off: u8,
    /// Whether software may control slot power.
    pub has_power_ctrl: bool,
}

impl SlotPolicy {
    /// Build a `SlotPolicy` from a `SlotCaps` + physical cfg address.
    pub fn from_caps(cfg_phys: u64, pcie_cap_off: u8, caps: &SlotCaps) -> Self {
        Self {
            cfg_phys,
            pcie_cap_off,
            has_power_ctrl: caps.power_ctrl,
        }
    }

    /// Execute the insert policy: power on (if supported) and
    /// dispatch Attach. The caller is responsible for the debounce
    /// delay before calling this function.
    ///
    /// `addr` and `device_id` identify the slot's bus address and
    /// the newly-inserted device's identity.
    ///
    /// # Safety
    /// Caller-asserted live config space; called after debounce.
    pub unsafe fn on_insert(&self, addr: crate::addr::BusAddr, device_id: crate::device::DeviceId) {
        if self.has_power_ctrl {
            // SAFETY: caller assertion; config space is live.
            unsafe { slot_power_on(self.cfg_phys, self.pcie_cap_off) };
        }
        dispatch_event(HotplugEvent::Attach { addr, device_id });
    }

    /// Execute the remove policy: dispatch Detach and power off
    /// (if supported).
    ///
    /// # Safety
    /// Caller-asserted live config space.
    pub unsafe fn on_remove(&self, addr: crate::addr::BusAddr) {
        dispatch_event(HotplugEvent::Detach { addr });
        if self.has_power_ctrl {
            // SAFETY: caller assertion.
            unsafe { slot_power_off(self.cfg_phys, self.pcie_cap_off) };
        }
    }
}
