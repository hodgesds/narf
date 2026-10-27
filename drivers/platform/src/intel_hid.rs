//! Intel HID Event Filter (`INT33D5` family) and Intel Virtual
//! Buttons (`INT33D3` / `INT33D6`) drivers.
//!
//! Two ACPI devices implement the Intel "5 button array" + hotkey
//! surface on modern Intel laptops and convertibles:
//!
//! * The **HID Event Filter** (`INT33D5`, plus the `INTCxxxx`
//!   successors) delivers ordinary hotkeys indirectly: firmware
//!   raises `Notify(0xC0)` and the driver evaluates the `HDEM`
//!   method to learn which HID usage fired. The same device can
//!   also expose the **5-button array** (Windows logo, volume,
//!   rotation-lock, power) as raw Notify codes, and — on
//!   convertibles whose firmware implements `VGBS` — the
//!   tablet-mode switch.
//! * The **Virtual Buttons** device (`INT33D3`, newer `INT33D6`)
//!   delivers the same 5-button array as Notify codes directly,
//!   plus the tablet-mode / dock switches backed by its `VGBS`
//!   state method.
//!
//! Both publish into the global input ring (`narf_input`): buttons
//! and hotkeys as key pulses, switches as `InputEvent::Switch`
//! (`SW_TABLET_MODE` / `SW_DOCK`). The switch state is also cached
//! in this module ([`tablet_mode`] / [`docked`]) with a subscriber
//! surface modelled on `lid.rs`, so platform consumers that join
//! late do not have to wait for the next edge.
//!
//! # References (GPL-2.0-or-later; used as the protocol reference)
//! - Linux `drivers/platform/x86/intel/hid.c` — `_DSM` function
//!   table, `HDEM` usage map, 5-button array map, `VGBS` handling.
//! - Linux `drivers/platform/x86/intel/vbtn.c` — virtual-buttons
//!   keymap/switchmap, `VGBS` state read at bind, `VBDL` load call.
//! - Intel "HID Event Filter" specification (`_DSM` UUID
//!   `eeec56b3-4442-408f-a792-4edd4d758054`, revision 1).
//!
//! # Protocol summary (all values from the references above)
//!
//! `_DSM` function indices on the filter device: 1 `BTNL`,
//! 2 `HDMM`, 3 `HDSM`, 4 `HDEM`, 5 `BTNS`, 6 `BTNE`, 7 `HEBC`
//! (v1), 8 `VGBS`, 9 `HEBC` (v2). Function 0 returns a Buffer
//! whose little-endian bits name the functions the firmware
//! implements through the `_DSM`; a function whose bit is clear —
//! or whose `_DSM` call fails — is invoked as the plain named
//! method under the device instead. `HDMM` must return 0
//! ("simple" mode) or the device is not bound. `HEBC` reports the
//! button-array capability: v2 bit mask `0x60000`, v1 `0x20000`.
//! The array itself is armed at bind: `BTNC` yields the button
//! capability mask which is handed back through `BTNE`, `HDSM`
//! enables hotkeys, and `BTNL` loads the HID power button.
//!
//! `VGBS` returns a state bitmap in which bit 6 (`0x40`) is set
//! when the machine is **not** in tablet mode; tablet mode is the
//! bit's inverse. On the filter device the switch surface is
//! trusted only on DMI allow-listed models (initial state read at
//! bind) or, on convertible/detachable chassis (SMBIOS chassis
//! types 31/32), from the first switch event onward — the same
//! policy as the reference driver, minus its dual-accelerometer
//! veto (no such detection exists in NARF yet; the at-event mode
//! still requires firmware to actually send a switch event).
//!
//! Notify values on both devices share one numbering: `0xC0` on
//! the filter means "evaluate `HDEM`"; the 5-button array uses
//! even press / odd release code pairs of which only the press is
//! reported (the release codes are explicitly ignored, matching
//! the reference keymaps' `KE_IGNORE` entries, and the press is
//! delivered as a press+release pulse like the reference's
//! autorelease); `0xCC`/`0xCD` report tablet mode on/off and
//! `0xCA`/`0xCB` docked/undocked (virtual buttons only). On a
//! filter device *without* the array, `0xCE`/`0xCF` are the power
//! button's real press/release pair and are reported as such.
//!
//! # Relationship to the vendor WMI tablet events (wave item 1)
//!
//! The vendor WMI drivers (`wmi_vendors.rs`, `dell_laptop.rs`)
//! decode their own tablet-mode events. Those modules are owned
//! by a parallel lane; the shared surface they should converge on
//! is the one defined here: [`publish_tablet_mode`] /
//! [`publish_dock`] (plus the `SW_TABLET_MODE` / `SW_DOCK` input
//! events they feed). Wiring the vendor decoders into those entry
//! points is a follow-up in that lane, deliberately not done here.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_aml::find_all_devices_by_hid;
use narf_aml::sync::register_notify_handler;
use narf_aml::Value;
use narf_input::{push_global, sw, InputEvent, KeyCode, KeyEvent, Modifiers, SwitchEvent};
use narf_lib::sync::IrqSafeSpinLock;

// ── ACPI device IDs ───────────────────────────────────────────────

/// HID Event Filter IDs — Linux `intel_hid_ids`.
const FILTER_HIDS: [&str; 12] = [
    "INT33D5", "INTC1051", "INTC1054", "INTC1070", "INTC1076", "INTC1077", "INTC1078", "INTC107B",
    "INTC10CB", "INTC10CC", "INTC10F1", "INTC10F2",
];

/// Virtual Buttons IDs — Linux `intel_vbtn_ids`.
const VBTN_HIDS: [&str; 2] = ["INT33D3", "INT33D6"];

// ── HID Event Filter _DSM ─────────────────────────────────────────

/// `_DSM` UUID `eeec56b3-4442-408f-a792-4edd4d758054` in the
/// mixed-endian wire form `narf_aml::eval::evaluate_dsm` expects
/// (same convention as the UCSI `_DSM` caller).
const DSM_UUID: [u8; 16] = [
    0xb3, 0x56, 0xec, 0xee, 0x42, 0x44, 0x8f, 0x40, 0xa7, 0x92, 0x4e, 0xdd, 0x4d, 0x75, 0x80, 0x54,
];
/// `_DSM` revision the filter protocol is defined at.
const DSM_REVISION: u64 = 1;

const DSM_BTNL: u8 = 1;
const DSM_HDMM: u8 = 2;
const DSM_HDSM: u8 = 3;
const DSM_HDEM: u8 = 4;
const DSM_BTNE: u8 = 6;
const DSM_HEBC_V1: u8 = 7;
const DSM_VGBS: u8 = 8;
const DSM_HEBC_V2: u8 = 9;

/// `HEBC` v2 bits: 5-button array or v2 power button present.
const HEBC_V2_ARRAY_MASK: u64 = 0x6_0000;
/// `HEBC` v1 bit: 5-button array present.
const HEBC_V1_ARRAY_MASK: u64 = 0x2_0000;

/// `VGBS` bit 6: set when the machine is NOT in tablet mode
/// (Linux `TABLET_MODE_FLAG`).
const TABLET_MODE_FLAG: u64 = 0x40;

// ── Notify values ─────────────────────────────────────────────────

/// Filter notify: a HID event is pending; evaluate `HDEM`.
const NOTIFY_HID_EVENT: u64 = 0xC0;
/// Switch notify: docked (virtual buttons).
const NOTIFY_DOCK_ON: u64 = 0xCA;
/// Switch notify: undocked (virtual buttons).
const NOTIFY_DOCK_OFF: u64 = 0xCB;
/// Switch notify: tablet mode entered.
const NOTIFY_TABLET_ON: u64 = 0xCC;
/// Switch notify: tablet mode left.
const NOTIFY_TABLET_OFF: u64 = 0xCD;
/// Power button press (array code pair 0xCE/0xCF).
const NOTIFY_POWER_PRESS: u64 = 0xCE;
/// Power button release.
const NOTIFY_POWER_RELEASE: u64 = 0xCF;

/// Map an `HDEM` event index (a HID usage number, per the filter
/// spec's "in theory, these are HID usages" table in the reference
/// driver) to a key. Indices 1 (LSuper), 2 (rotate-lock switch),
/// 13 (ambiguous in the spec) and 27 (wake) are deliberately
/// unmapped, as in the reference keymap.
fn hdem_key(index: u64) -> Option<KeyCode> {
    Some(match index {
        3 => KeyCode::NumLock,
        4 => KeyCode::Home,
        5 => KeyCode::End,
        6 => KeyCode::PageUp,
        7 => KeyCode::PageDown,
        8 => KeyCode::RfKill,
        9 => KeyCode::Power,
        11 => KeyCode::Sleep,
        14 => KeyCode::StopCd,
        15 => KeyCode::PlayPause,
        16 => KeyCode::Mute,
        17 => KeyCode::VolumeUp,
        18 => KeyCode::VolumeDown,
        19 => KeyCode::BrightnessUp,
        20 => KeyCode::BrightnessDown,
        _ => return None,
    })
}

/// What a 5-button-array Notify code means. The array keymap is
/// identical on the filter and virtual-buttons devices.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ArrayAction {
    /// Press code: report a key pulse.
    Pulse(KeyCode),
    /// Release code: the reference keymaps mark these `KE_IGNORE`;
    /// the press already pulsed, so the release is dropped.
    Ignore,
    /// Not an array code.
    Unknown,
}

fn array_action(code: u64) -> ArrayAction {
    match code {
        0xC2 => ArrayAction::Pulse(KeyCode::LeftMeta),
        0xC4 => ArrayAction::Pulse(KeyCode::VolumeUp),
        0xC6 => ArrayAction::Pulse(KeyCode::VolumeDown),
        0xC8 => ArrayAction::Pulse(KeyCode::RotateLockToggle),
        NOTIFY_POWER_PRESS => ArrayAction::Pulse(KeyCode::Power),
        0xC3 | 0xC5 | 0xC7 | 0xC9 | NOTIFY_POWER_RELEASE => ArrayAction::Ignore,
        _ => ArrayAction::Unknown,
    }
}

// ── AML method-access seam ────────────────────────────────────────

/// The AML conversation one Intel HID device needs. The production
/// implementation ([`AmlBus`]) talks to `narf_aml`; fixtures
/// substitute a scripted implementation so the full bind + notify
/// conversation can be driven end-to-end without a DSDT.
///
/// The `eval_fn` / `exec_fn` pair encodes the filter protocol's
/// dispatch rule: when the function's bit is set in the `_DSM`
/// function mask, call the `_DSM`; otherwise — or when the `_DSM`
/// call itself fails — execute/evaluate the plain named method
/// under the device.
pub(crate) trait MethodBus {
    /// Function mask from `_DSM` function 0. 0 when the device
    /// has no usable `_DSM` (every function then goes direct).
    fn dsm_fn_mask(&mut self, path: &str) -> u64;
    /// Evaluate a zero-argument function expected to return an
    /// integer, via the `_DSM` when masked in, else the named
    /// method. `None` on any failure or non-integer result.
    fn eval_fn(&mut self, path: &str, mask: u64, dsm_fn: u8, name: &str) -> Option<u64>;
    /// Execute a function with one integer argument (packaged for
    /// the `_DSM` form). True when the call succeeded.
    fn exec_fn(&mut self, path: &str, mask: u64, dsm_fn: u8, name: &str, arg: u64) -> bool;
    /// Evaluate a plain named zero-argument method (no `_DSM`
    /// involvement — `BTNC`, `VGBS` on the virtual-buttons
    /// device). `None` on failure or non-integer result.
    fn eval_named(&mut self, path: &str, name: &str) -> Option<u64>;
    /// Call a plain named zero-argument method, ignoring its
    /// result (`VBDL`). True when the call succeeded.
    fn call_named(&mut self, path: &str, name: &str) -> bool;
}

fn method_path(path: &str, name: &str) -> String {
    let mut s = String::from(path);
    if !s.ends_with('.') {
        s.push('.');
    }
    s.push_str(name);
    s
}

/// Production [`MethodBus`] over the global AML interpreter.
#[derive(Debug)]
pub(crate) struct AmlBus;

impl MethodBus for AmlBus {
    fn dsm_fn_mask(&mut self, path: &str) -> u64 {
        // Function 0 returns a Buffer; the reference reads a u16
        // mask (a 1-byte buffer yields just that byte, an empty
        // buffer yields 0).
        match narf_aml::eval::evaluate_dsm(
            path,
            DSM_UUID,
            DSM_REVISION,
            0,
            Value::Package(Vec::new()),
        ) {
            Ok(Value::Buffer(b)) => match b.len() {
                0 => 0,
                1 => b[0] as u64,
                _ => u16::from_le_bytes([b[0], b[1]]) as u64,
            },
            _ => 0,
        }
    }

    fn eval_fn(&mut self, path: &str, mask: u64, dsm_fn: u8, name: &str) -> Option<u64> {
        if mask & (1u64 << dsm_fn) != 0 {
            if let Ok(Value::Integer(v)) = narf_aml::eval::evaluate_dsm(
                path,
                DSM_UUID,
                DSM_REVISION,
                dsm_fn as u64,
                Value::Package(Vec::new()),
            ) {
                return Some(v);
            }
        }
        self.eval_named(path, name)
    }

    fn exec_fn(&mut self, path: &str, mask: u64, dsm_fn: u8, name: &str, arg: u64) -> bool {
        if mask & (1u64 << dsm_fn) != 0 {
            if narf_aml::eval::evaluate_dsm(
                path,
                DSM_UUID,
                DSM_REVISION,
                dsm_fn as u64,
                Value::Package(alloc::vec![Value::Integer(arg)]),
            )
            .is_ok()
            {
                return true;
            }
        }
        narf_aml::eval::evaluate_method(&method_path(path, name), &[Value::Integer(arg)]).is_ok()
    }

    fn eval_named(&mut self, path: &str, name: &str) -> Option<u64> {
        match narf_aml::eval::evaluate_method(&method_path(path, name), &[]) {
            Ok(Value::Integer(v)) => Some(v),
            _ => None,
        }
    }

    fn call_named(&mut self, path: &str, name: &str) -> bool {
        narf_aml::eval::evaluate_method(&method_path(path, name), &[]).is_ok()
    }
}

// ── DMI policy ────────────────────────────────────────────────────

/// The SMBIOS facts the reference driver's DMI tables key on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DmiInfo {
    pub manufacturer: String,
    pub product_name: String,
    /// SMBIOS Type-3 chassis type (lock bit stripped): 31 =
    /// convertible, 32 = detachable.
    pub chassis_type: u8,
}

/// Substring match, mirroring Linux `DMI_MATCH` semantics.
fn dmi_entry_matches(dmi: &DmiInfo, vendor: &str, product: &str) -> bool {
    dmi.manufacturer.contains(vendor) && dmi.product_name.contains(product)
}

fn dmi_table_matches(table: &[(&str, &str)], dmi: &DmiInfo) -> bool {
    table.iter().any(|&(v, p)| dmi_entry_matches(dmi, v, p))
}

/// Models whose 5-button array is enabled even when `HEBC` does
/// not advertise it — Linux `button_array_table` (vendor,
/// product). The three Lenovo entries are matched on the product
/// name because NARF's SMBIOS parser does not surface the Type-1
/// Family string the reference matches there; the named models
/// carry the same strings as their product names.
const BUTTON_ARRAY_DMI: &[(&str, &str)] = &[
    ("Wacom Co.,Ltd", "Wacom MobileStudio Pro 13"),
    ("Wacom Co.,Ltd", "Wacom MobileStudio Pro 16"),
    ("HP", "HP Spectre x2 Detachable"),
    ("LENOVO", "ThinkPad X12 Detachable Gen 1"),
    ("LENOVO", "ThinkPad X1 Tablet Gen 2"),
    ("LENOVO", "ThinkPad X1 Fold 16 Gen 1"),
    ("Microsoft Corporation", "Surface Go 3"),
    ("Microsoft Corporation", "Surface Go 4"),
    ("HP", "HP ProBook x360 440 G1"),
];

/// Models whose `VGBS` returns are trusted from probe time —
/// Linux `dmi_vgbs_allow_list` (vendor, product).
const VGBS_ALLOW_DMI: &[(&str, &str)] = &[
    ("HP", "HP Spectre x360 Convertible 15-df0xxx"),
    ("Microsoft Corporation", "Surface Go"),
    ("HP", "HP Elite Dragonfly G2 Notebook PC"),
    ("Dell Inc.", "Dell Pro Rugged 10 Tablet RA00260"),
    ("Dell Inc.", "Dell Pro Rugged 12 Tablet RA02260"),
    ("Dell Inc.", "Dell 14 Plus 2-in-1 DB04250"),
    ("Dell Inc.", "Dell 16 Plus 2-in-1 DB06250"),
];

/// When the tablet-mode switch surface may go live on a filter
/// device — Linux `intel_hid_tablet_sw_mode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TabletPolicy {
    /// Never publish `SW_TABLET_MODE` from this device.
    Off,
    /// Publish from the first switch event onward.
    AtEvent,
    /// Publish from bind, with the initial state read via `VGBS`.
    AtProbe,
}

pub(crate) fn tablet_policy(dmi: &DmiInfo) -> TabletPolicy {
    if dmi_table_matches(VGBS_ALLOW_DMI, dmi) {
        return TabletPolicy::AtProbe;
    }
    if dmi.chassis_type == 31 || dmi.chassis_type == 32 {
        return TabletPolicy::AtEvent;
    }
    TabletPolicy::Off
}

pub(crate) fn button_array_dmi_matches(dmi: &DmiInfo) -> bool {
    dmi_table_matches(BUTTON_ARRAY_DMI, dmi)
}

// ── Switch publication surface ────────────────────────────────────

/// Cached switch states: 0 = never reported, 1 = off, 2 = on.
static TABLET_STATE: AtomicU8 = AtomicU8::new(0);
static DOCK_STATE: AtomicU8 = AtomicU8::new(0);

type SwitchSubscriber = Box<dyn Fn(bool) + Send + Sync>;
static TABLET_SUBSCRIBERS: IrqSafeSpinLock<Vec<SwitchSubscriber>> =
    IrqSafeSpinLock::new(Vec::new());
static DOCK_SUBSCRIBERS: IrqSafeSpinLock<Vec<SwitchSubscriber>> = IrqSafeSpinLock::new(Vec::new());

fn state_of(cell: &AtomicU8) -> Option<bool> {
    match cell.load(Ordering::SeqCst) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

/// Latest reported tablet-mode state, from any Intel HID source.
pub fn tablet_mode() -> Option<bool> {
    state_of(&TABLET_STATE)
}

/// Latest reported dock state, from any Intel HID source.
pub fn docked() -> Option<bool> {
    state_of(&DOCK_STATE)
}

/// Subscribe to tablet-mode changes. Callbacks run in the
/// publisher's context (ACPI Notify / driver bind) with the
/// subscriber registry lock held: they must be short,
/// non-blocking, and must not subscribe or publish switches.
pub fn subscribe_tablet_mode<F: Fn(bool) + Send + Sync + 'static>(cb: F) {
    TABLET_SUBSCRIBERS.lock().push(Box::new(cb));
}

/// Subscribe to dock-state changes. Same contract as
/// [`subscribe_tablet_mode`].
pub fn subscribe_dock<F: Fn(bool) + Send + Sync + 'static>(cb: F) {
    DOCK_SUBSCRIBERS.lock().push(Box::new(cb));
}

/// Publish a tablet-mode state: pushes the `SW_TABLET_MODE` input
/// event, updates the cached state, and fires subscribers. This
/// is the shared entry point vendor WMI tablet events (wave
/// item 1) should converge on; their decoders live in a parallel
/// lane and are not wired here yet.
pub fn publish_tablet_mode(on: bool) {
    publish_switch(&TABLET_STATE, &TABLET_SUBSCRIBERS, sw::SW_TABLET_MODE, on);
}

/// Publish a dock state. See [`publish_tablet_mode`].
pub fn publish_dock(on: bool) {
    publish_switch(&DOCK_STATE, &DOCK_SUBSCRIBERS, sw::SW_DOCK, on);
}

fn publish_switch(
    cell: &AtomicU8,
    subscribers: &IrqSafeSpinLock<Vec<SwitchSubscriber>>,
    code: u16,
    on: bool,
) {
    cell.store(if on { 2 } else { 1 }, Ordering::SeqCst);
    let _ = push_global(InputEvent::Switch(SwitchEvent { code, on }));
    let g = subscribers.lock();
    for cb in g.iter() {
        cb(on);
    }
}

/// Test-only reset of the cached switch state + subscribers.
#[doc(hidden)]
pub fn __reset_switch_state_for_test() {
    TABLET_STATE.store(0, Ordering::SeqCst);
    DOCK_STATE.store(0, Ordering::SeqCst);
    TABLET_SUBSCRIBERS.lock().clear();
    DOCK_SUBSCRIBERS.lock().clear();
}

// ── Key publication ───────────────────────────────────────────────

fn push_key(code: KeyCode, pressed: bool) {
    let _ = push_global(InputEvent::Key(KeyEvent {
        code,
        pressed,
        modifiers: Modifiers::EMPTY,
    }));
}

/// Report a key as a press+release pulse — the reference's
/// autorelease behaviour for one-shot buttons and hotkeys.
fn pulse_key(code: KeyCode) {
    push_key(code, true);
    push_key(code, false);
}

fn log_unknown(path: &str, what: &str, value: u64) {
    let _ = writeln!(
        narf_console::Writer,
        "  intel-hid: {}: unknown {} {:#x}",
        path,
        what,
        value
    );
}

// ── Devices ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    Filter,
    VirtualButtons,
}

/// One bound Intel HID device and its conversation state.
#[derive(Debug)]
pub(crate) struct Device {
    pub(crate) path: String,
    pub(crate) kind: DeviceKind,
    /// `_DSM` function mask (filter only; 0 on virtual buttons).
    pub(crate) mask: u64,
    pub(crate) array_present: bool,
    /// Filter switch policy; unused for virtual buttons, whose
    /// switch surface is gated on `VGBS` evaluating at bind.
    pub(crate) policy: TabletPolicy,
    /// The switch surface is live: switch events publish.
    pub(crate) switches_live: bool,
    pub(crate) tablet: Option<bool>,
    pub(crate) dock: Option<bool>,
}

impl Device {
    fn set_tablet(&mut self, on: bool) {
        if self.tablet != Some(on) {
            self.tablet = Some(on);
            publish_tablet_mode(on);
        }
    }

    fn set_dock(&mut self, on: bool) {
        if self.dock != Some(on) {
            self.dock = Some(on);
            publish_dock(on);
        }
    }

    /// Publish the tablet state a `VGBS` value encodes (bit 6 set
    /// means NOT tablet mode).
    fn report_vgbs_state(&mut self, vgbs: Option<u64>) {
        if let Some(vgbs) = vgbs {
            let tablet = vgbs & TABLET_MODE_FLAG == 0;
            self.set_tablet(tablet);
        }
    }

    /// Dispatch one ACPI Notify value. This is the single entry
    /// point the production notify trampoline and the fixtures
    /// both drive.
    pub(crate) fn notify(&mut self, bus: &mut dyn MethodBus, value: u64) {
        match self.kind {
            DeviceKind::Filter => self.notify_filter(bus, value),
            DeviceKind::VirtualButtons => self.notify_vbtn(bus, value),
        }
    }

    fn notify_filter(&mut self, bus: &mut dyn MethodBus, value: u64) {
        // At-event switch policy: the first switch event turns
        // the surface on (reference: "switch event received,
        // enable switches supports").
        if !self.switches_live
            && self.policy == TabletPolicy::AtEvent
            && (value == NOTIFY_TABLET_ON || value == NOTIFY_TABLET_OFF)
        {
            self.switches_live = true;
            let _ = writeln!(
                narf_console::Writer,
                "  intel-hid: {}: switch event received, enabling switch reports",
                self.path
            );
        }

        // Without the array, the power codes are the button's
        // real press/release pair, reported as such.
        if !self.array_present {
            match value {
                NOTIFY_POWER_PRESS => {
                    push_key(KeyCode::Power, true);
                    return;
                }
                NOTIFY_POWER_RELEASE => {
                    push_key(KeyCode::Power, false);
                    return;
                }
                _ => {}
            }
        }

        // Tablet-mode switch events.
        if self.switches_live {
            match value {
                NOTIFY_TABLET_ON => {
                    self.set_tablet(true);
                    return;
                }
                NOTIFY_TABLET_OFF => {
                    self.set_tablet(false);
                    return;
                }
                _ => {}
            }
        }

        // 0xC0 is for HID events; every other value is a
        // 5-button-array code.
        if value != NOTIFY_HID_EVENT {
            if self.array_present {
                match array_action(value) {
                    ArrayAction::Pulse(k) => pulse_key(k),
                    ArrayAction::Ignore => {}
                    ArrayAction::Unknown => log_unknown(&self.path, "event", value),
                }
            } else {
                log_unknown(&self.path, "event", value);
            }
            return;
        }

        match bus.eval_fn(&self.path, self.mask, DSM_HDEM, "HDEM") {
            Some(index) => match hdem_key(index) {
                Some(k) => pulse_key(k),
                None => log_unknown(&self.path, "event index", index),
            },
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-hid: {}: failed to get event index",
                    self.path
                );
            }
        }
    }

    fn notify_vbtn(&mut self, bus: &mut dyn MethodBus, value: u64) {
        match value {
            NOTIFY_TABLET_ON if self.switches_live => self.set_tablet(true),
            NOTIFY_TABLET_OFF if self.switches_live => self.set_tablet(false),
            NOTIFY_DOCK_ON if self.switches_live => self.set_dock(true),
            NOTIFY_DOCK_OFF if self.switches_live => self.set_dock(false),
            _ => match array_action(value) {
                ArrayAction::Pulse(k) => pulse_key(k),
                ArrayAction::Ignore => {}
                ArrayAction::Unknown => log_unknown(&self.path, "event index", value),
            },
        }
        // Some devices need VBDL to report further events
        // (reference behaviour; best-effort, result ignored).
        let _ = bus.call_named(&self.path, "VBDL");
    }
}

/// Whether the filter device exposes the 5-button array:
/// `HEBC` v2 bits, else `HEBC` v1 bit, else the DMI table.
fn button_array_present(bus: &mut dyn MethodBus, path: &str, mask: u64, dmi: &DmiInfo) -> bool {
    if let Some(cap) = bus.eval_fn(path, mask, DSM_HEBC_V2, "HEBC") {
        if cap & HEBC_V2_ARRAY_MASK != 0 {
            return true;
        }
    }
    if let Some(cap) = bus.eval_fn(path, mask, DSM_HEBC_V1, "HEBC") {
        if cap & HEBC_V1_ARRAY_MASK != 0 {
            return true;
        }
    }
    button_array_dmi_matches(dmi)
}

/// Bind one HID Event Filter device. Returns `None` when the
/// firmware conversation rejects the device (no `HDMM`,
/// non-simple mode, or the `HDSM` enable fails) — the reference's
/// `-ENODEV` / `-EIO` probe failures.
pub(crate) fn bind_filter(bus: &mut dyn MethodBus, path: &str, dmi: &DmiInfo) -> Option<Device> {
    let mask = bus.dsm_fn_mask(path);

    let mode = bus.eval_fn(path, mask, DSM_HDMM, "HDMM")?;
    if mode != 0 {
        // "platform is not in simple mode" — the reference only
        // implements simple mode and refuses the device.
        let _ = writeln!(
            narf_console::Writer,
            "  intel-hid: {}: platform is not in simple mode ({})",
            path,
            mode
        );
        return None;
    }

    let array_present = button_array_present(bus, path, mask, dmi);
    let policy = tablet_policy(dmi);
    let mut dev = Device {
        path: String::from(path),
        kind: DeviceKind::Filter,
        mask,
        array_present,
        policy,
        switches_live: false,
        tablet: None,
        dock: None,
    };

    // Allow-listed models: switches live from probe, with the
    // initial state read back through VGBS.
    if policy == TabletPolicy::AtProbe {
        dev.switches_live = true;
        let vgbs = bus.eval_fn(path, mask, DSM_VGBS, "VGBS");
        dev.report_vgbs_state(vgbs);
    }

    // Enable hotkeys; the reference fails the probe when this
    // does.
    if !bus.exec_fn(path, mask, DSM_HDSM, "HDSM", 1) {
        let _ = writeln!(
            narf_console::Writer,
            "  intel-hid: {}: failed to enable hotkeys",
            path
        );
        return None;
    }

    // Arm the 5-button array: BTNC's capability mask is handed
    // back through BTNE (the power button is always enabled).
    // Failures here are warnings in the reference, not fatal.
    if array_present {
        match bus.eval_named(path, "BTNC") {
            Some(cap) => {
                if !bus.exec_fn(path, mask, DSM_BTNE, "BTNE", cap) {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  intel-hid: {}: failed to set button capability",
                        path
                    );
                }
            }
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  intel-hid: {}: failed to get button capability",
                    path
                );
            }
        }
    }

    // Load the HID power button; always attempted (it activates
    // events on some array-less devices too). Warn-only.
    if bus.eval_fn(path, mask, DSM_BTNL, "BTNL").is_none() {
        let _ = writeln!(
            narf_console::Writer,
            "  intel-hid: {}: failed to enable HID power button",
            path
        );
    }

    Some(dev)
}

/// Bind one Virtual Buttons device. The button array is always
/// armed; the switch surface goes live only when `VGBS`
/// evaluates, and its initial state is published at bind (the
/// reference's `detect_tablet_mode`). Only the tablet bit of
/// `VGBS` is decoded: the dock bit's position is not pinned by
/// the references this implementation was derived from, so dock
/// state is taken from the `0xCA`/`0xCB` notify pair instead.
pub(crate) fn bind_vbtn(bus: &mut dyn MethodBus, path: &str) -> Device {
    let mut dev = Device {
        path: String::from(path),
        kind: DeviceKind::VirtualButtons,
        mask: 0,
        array_present: true,
        policy: TabletPolicy::Off,
        switches_live: false,
        tablet: None,
        dock: None,
    };
    // Load the virtual buttons (best-effort; some devices need
    // this before they report events).
    let _ = bus.call_named(path, "VBDL");
    if let Some(vgbs) = bus.eval_named(path, "VGBS") {
        dev.switches_live = true;
        dev.report_vgbs_state(Some(vgbs));
    }
    dev
}

// ── Production wiring ─────────────────────────────────────────────

static DEVICES: IrqSafeSpinLock<Vec<Device>> = IrqSafeSpinLock::new(Vec::new());

/// ACPI Notify trampoline: route to the bound device by path.
fn on_notify(path: &str, value: u64) {
    let mut bus = AmlBus;
    let mut devs = DEVICES.lock();
    if let Some(dev) = devs.iter_mut().find(|d| d.path == path) {
        dev.notify(&mut bus, value);
    }
}

fn smbios_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().into()
}

fn read_dmi() -> DmiInfo {
    let mut dmi = DmiInfo::default();
    let mut sys = [narf_firmware_smbios::SmbiosSystem::ZERO];
    if narf_firmware_smbios::copy_system(&mut sys) > 0 {
        dmi.manufacturer = smbios_string(&sys[0].manufacturer);
        dmi.product_name = smbios_string(&sys[0].product_name);
    }
    let mut chassis = [narf_firmware_smbios::SmbiosChassis::ZERO];
    if narf_firmware_smbios::copy_chassis(&mut chassis) > 0 {
        dmi.chassis_type = chassis[0].chassis_type & 0x7F;
    }
    dmi
}

/// Initialize the Intel HID Event Filter + Virtual Buttons
/// drivers.
pub fn init() {
    let dmi = read_dmi();
    let mut bus = AmlBus;
    let mut found = 0usize;

    for hid in FILTER_HIDS {
        for node in find_all_devices_by_hid(hid) {
            if let Some(dev) = bind_filter(&mut bus, &node.path, &dmi) {
                register_notify_handler(&node.path, on_notify);
                DEVICES.lock().push(dev);
                found += 1;
            }
        }
    }
    for hid in VBTN_HIDS {
        for node in find_all_devices_by_hid(hid) {
            let dev = bind_vbtn(&mut bus, &node.path);
            register_notify_handler(&node.path, on_notify);
            DEVICES.lock().push(dev);
            found += 1;
        }
    }

    if found > 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  intel-hid: registered {} device(s)",
            found
        );
    }
}
