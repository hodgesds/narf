//! HID Multi-Touch class driver — clean-room.
//!
//! This is the transport-neutral multi-touch class driver. The
//! existing single-touch driver in `drivers/usb/src/hid/touchpad.rs`
//! handles the relative-emit fallback for legacy PTPs; this module
//! claims modern multi-touch devices (Win8 PTP + standard Digitizer
//! touchscreens) and emits Linux Slot-Protocol-B-shaped
//! [`narf_input::TouchEvent`]s suitable for downstream gesture
//! engines.
//!
//! Per the project standing-rules: hard cutover. The single-touch
//! path stays for booted devices that don't expose a PTP feature
//! map; this driver wins for everything that does.
//!
//! ## Sources (public)
//!
//! - **HID 1.11 §6.2.2 / §7.2** — report descriptor + class request
//!     encoding.
//!     <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - **HID Usage Tables 1.4 §4 (Generic Desktop) / §16 (Digitizer)** —
//!     `Touchpad (0x0D/0x05)`, `Touchscreen (0x0D/0x04)`, `Finger
//!     (0x0D/0x22)`, `Tip Switch (0x0D/0x42)`, `Contact ID (0x0D/0x51)`,
//!     `Contact Count (0x0D/0x54)`, `Contact Count Maximum
//!     (0x0D/0x55)`, `Scan Time (0x0D/0x56)`, `Width (0x0D/0x48)`,
//!     `Height (0x0D/0x49)`, `Device Mode (0x0D/0x60)`.
//!     <https://usb.org/document-library/hid-usage-tables-14>
//! - **Microsoft Precision Touchpad implementation guide** — mode
//!     byte semantics + Configuration TLC layout.
//!     <https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchpad-windows-precision-touchpad-collection>
//! - **Linux Documentation/input/multi-touch-protocol.rst** — defines
//!     the Slot-Protocol-B emission shape this driver targets
//!     (`ABS_MT_SLOT`, `ABS_MT_TRACKING_ID`, `ABS_MT_POSITION_X/Y`,
//!     `SYN_REPORT` per frame).
//!
//! Linux ref citations (per project rule allowing GPL refs after
//! 2026-05-20):
//! - `linux/drivers/hid/hid-multitouch.c` overall structure
//! - L55-79 `MT_QUIRK_*` per-device quirk bits
//! - L198-241 `MT_CLS_*` class identifiers
//! - L267-458 `mt_classes[]` quirk-bundle table
//! - L621-654 `mt_allocate_application` — assigns
//!     `INPUT_MT_DIRECT` for Touchscreen vs `INPUT_MT_POINTER` for
//!     Touchpad, sets `MT_INPUTMODE_TOUCHPAD` byte for PTP devices.
//! - L1713-1748 `mt_set_modes` — drives the Feature SET for Device
//!     Mode + Latency / Surface / Button Switch.
//! - L2111+ `mt_devices[]` device-id table.
//!
//! ## What this driver does
//!
//! 1. **Match**: claim devices whose parsed Report Descriptor has
//!    either a `GenericDesktop.Touchpad` (digitizer page, usage
//!    0x05) OR `Digitizers.TouchScreen` (usage 0x04) Application
//!    Collection AND a `Contact ID` (0x51) field AND a `Tip Switch`
//!    (0x42) field. The PTP probe in `narf_hid::ptp` covers the
//!    touchpad shape; touchscreens go through
//!    `narf_hid::touchscreen`.
//!
//! 2. **PTP Feature set**: for the touchpad shape, write Device
//!    Mode = `TOUCHPAD` (0x03) via Feature Report so the firmware
//!    sends multi-touch reports on the wire.
//!
//! 3. **Max-contact discovery**: read `Contact Count Maximum`
//!    (0x55) from the Feature report; clamp to the class quirk's
//!    `max_contacts` override; fall back to the descriptor's
//!    logical-max, then the per-contact slot list length, then 5.
//!
//! 4. **Per-frame slot tracking**: assign each `contact_id` a
//!    stable slot 0..N for the lifetime of one finger (Down →
//!    Up); free the slot when Tip Switch drops.
//!
//! 5. **Emit Slot-Protocol-B**: per dirty slot, push one
//!    [`narf_input::TouchEvent`] with `state =
//!    Down | Move | Up`, the slot id, the tracking id (`None` =
//!    released), and the normalised `(x, y)`. The `narf-input`
//!    ring is the closest analogue of Linux's evdev — the
//!    consumer (libinput-style gesture engine) reconstructs the
//!    frame from the per-slot events.
//!
//! 6. **Buttons**: emit `ButtonEvent(BTN_LEFT)` /
//!    `ButtonEvent(BTN_RIGHT)` on press / release transitions.
//!
//! Transport (USB / i2c-HID) is out of scope here — those layers
//! feed bytes in via [`pump_decoded_ptp`] / [`pump_decoded_touch`],
//! and the bind layer they own (USB: `drivers/usb/src/hid/touchpad.rs`
//! today; the new MT bind path lives in this module) calls
//! [`MtDevice::attach`] once per device.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_hid::descriptor::ReportDescriptor;
use narf_hid::ptp::{self, DecodedReport as PtpDecoded, PtpProfile};
use narf_hid::touchscreen::{self, DecodedTouchReport, TouchscreenProfile};
use narf_hid::usage::digitizer;
use narf_input::{
    abs, push_global, AbsoluteEvent, InputEvent, PointerButtons, PointerEvent, TouchEvent,
    TouchState,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::hid_mt_features as mt_features;

/// Maximum simultaneously tracked contacts. Matches
/// `i2c_hid_touch::MAX_TOUCH_SLOTS` so a per-device slot table
/// drops in without re-walking sizes. Real-world touchpads ship
/// 5; high-end stylus-aware panels do 10; we cap at
/// [`mt_features::HARD_MAX_CONTACTS`] (32) for defense vs buggy
/// firmware advertising silly Contact Count Maximums.
pub const MAX_SLOTS: usize = 16;

// ── Class + quirk tables ──────────────────────────────────────────

crate::__mt_quirk_bitflags! {
    /// Per-device quirk bits. Bit values match
    /// `linux/drivers/hid/hid-multitouch.c:55-79` so cross-referencing
    /// a Linux device id table entry's MT_QUIRK_* set against this
    /// driver's behaviour is a 1:1 lookup.
    pub struct MtQuirks: u32 {
        const NOT_SEEN_MEANS_UP        = 1 << 0;
        const SLOT_IS_CONTACTID        = 1 << 1;
        const CYPRESS                  = 1 << 2;
        const SLOT_IS_CONTACTNUMBER    = 1 << 3;
        const ALWAYS_VALID             = 1 << 4;
        const VALID_IS_INRANGE         = 1 << 5;
        const VALID_IS_CONFIDENCE      = 1 << 6;
        const CONFIDENCE               = 1 << 7;
        const SLOT_IS_CONTACTID_MINUS_ONE = 1 << 8;
        const NO_AREA                  = 1 << 9;
        const IGNORE_DUPLICATES        = 1 << 10;
        const HOVERING                 = 1 << 11;
        const CONTACT_CNT_ACCURATE     = 1 << 12;
        const FORCE_GET_FEATURE        = 1 << 13;
        const FIX_CONST_CONTACT_ID     = 1 << 14;
        const TOUCH_SIZE_SCALING       = 1 << 15;
        const STICKY_FINGERS           = 1 << 16;
        const ASUS_CUSTOM_UP           = 1 << 17;
        const WIN8_PTP_BUTTONS         = 1 << 18;
        const SEPARATE_APP_REPORT      = 1 << 19;
        const FORCE_MULTI_INPUT        = 1 << 20;
        const DISABLE_WAKEUP           = 1 << 21;
        const ORIENTATION_INVERT       = 1 << 22;
        const APPLE_TOUCHBAR           = 1 << 23;
    }
}

/// Class identifier. Values match `MT_CLS_*` in
/// `linux/drivers/hid/hid-multitouch.c:198-239` for cross-reference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MtClass {
    Default = 0x0001,
    Serial = 0x0002,
    Confidence = 0x0003,
    ConfidenceContactId = 0x0004,
    ConfidenceMinusOne = 0x0005,
    Nsmu = 0x000a,
    Win8 = 0x0012,
    ExportAllInputs = 0x0013,
    Apple = 0x0114,
}

/// Per-class quirk bundle. Subset of `mt_classes[]` entries from
/// `linux/drivers/hid/hid-multitouch.c:267-458`, covering the four
/// classes the task spec calls out: Elan (Default), Synaptics
/// (Default), Apple Magic Trackpad 2 (Apple), Generic Win8 PTP
/// (Win8). Adding more entries is mechanical — copy the Linux
/// `MT_QUIRK_*` set into [`MtQuirks`] flags.
#[derive(Copy, Clone, Debug)]
pub struct MtClassEntry {
    pub class: MtClass,
    pub quirks: MtQuirks,
    /// Per-class hard cap on simultaneous contacts; `0` = use the
    /// descriptor's `Contact Count Maximum`. Mirrors
    /// `mt_class::maxcontacts` (`hid-multitouch.c:160`).
    pub max_contacts: u8,
    /// `true` for touchpads (Touch Pad collection); `false` for
    /// touchscreens. Mirrors `mt_class::is_indirect`
    /// (`hid-multitouch.c:161`).
    pub is_indirect: bool,
}

/// Table of recognised classes. Indexed by [`MtClass`] enum order;
/// look up via [`lookup_class`].
const MT_CLASSES: &[MtClassEntry] = &[
    // MT_CLS_DEFAULT — Elan, Synaptics, most generic PTPs.
    // Linux: hid-multitouch.c:268-270.
    MtClassEntry {
        class: MtClass::Default,
        quirks: MtQuirks(
            MtQuirks::ALWAYS_VALID.bits() | MtQuirks::CONTACT_CNT_ACCURATE.bits(),
        ),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_NSMU — "not seen means up".
    // Linux: hid-multitouch.c:271-272.
    MtClassEntry {
        class: MtClass::Nsmu,
        quirks: MtQuirks(MtQuirks::NOT_SEEN_MEANS_UP.bits()),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_SERIAL — single contact per report, time-multiplexed.
    // Linux: hid-multitouch.c:273-274.
    MtClassEntry {
        class: MtClass::Serial,
        quirks: MtQuirks(MtQuirks::ALWAYS_VALID.bits()),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_CONFIDENCE.
    // Linux: hid-multitouch.c:275-276.
    MtClassEntry {
        class: MtClass::Confidence,
        quirks: MtQuirks(MtQuirks::VALID_IS_CONFIDENCE.bits()),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_CONFIDENCE_CONTACT_ID.
    // Linux: hid-multitouch.c:277-279.
    MtClassEntry {
        class: MtClass::ConfidenceContactId,
        quirks: MtQuirks(
            MtQuirks::VALID_IS_CONFIDENCE.bits() | MtQuirks::SLOT_IS_CONTACTID.bits(),
        ),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_CONFIDENCE_MINUS_ONE.
    // Linux: hid-multitouch.c:280-282.
    MtClassEntry {
        class: MtClass::ConfidenceMinusOne,
        quirks: MtQuirks(
            MtQuirks::VALID_IS_CONFIDENCE.bits()
                | MtQuirks::SLOT_IS_CONTACTID_MINUS_ONE.bits(),
        ),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_WIN_8 — generic Microsoft Precision Touchpad.
    // Linux: hid-multitouch.c:294-301.
    MtClassEntry {
        class: MtClass::Win8,
        quirks: MtQuirks(
            MtQuirks::ALWAYS_VALID.bits()
                | MtQuirks::IGNORE_DUPLICATES.bits()
                | MtQuirks::HOVERING.bits()
                | MtQuirks::CONTACT_CNT_ACCURATE.bits()
                | MtQuirks::STICKY_FINGERS.bits()
                | MtQuirks::WIN8_PTP_BUTTONS.bits(),
        ),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_EXPORT_ALL_INPUTS — emit mouse + keyboard from the
    // same combo device alongside MT (we treat this identically
    // to Default for now; the secondary input path lives in the
    // existing single-touch driver).
    // Linux: hid-multitouch.c:302-305.
    MtClassEntry {
        class: MtClass::ExportAllInputs,
        quirks: MtQuirks(
            MtQuirks::ALWAYS_VALID.bits() | MtQuirks::CONTACT_CNT_ACCURATE.bits(),
        ),
        max_contacts: 0,
        is_indirect: true,
    },
    // MT_CLS_APPLE_TOUCHBAR — Apple Magic Trackpad 2 / Touch Bar.
    // Linux: hid-multitouch.c:434-439.
    MtClassEntry {
        class: MtClass::Apple,
        quirks: MtQuirks(
            MtQuirks::HOVERING.bits()
                | MtQuirks::SLOT_IS_CONTACTID_MINUS_ONE.bits()
                | MtQuirks::APPLE_TOUCHBAR.bits(),
        ),
        max_contacts: 11,
        is_indirect: true,
    },
];

/// Look up the class entry for a known [`MtClass`].
pub fn lookup_class(class: MtClass) -> &'static MtClassEntry {
    MT_CLASSES
        .iter()
        .find(|e| e.class == class)
        .unwrap_or(&MT_CLASSES[0])
}

/// Number of class entries the driver carries. Test helper +
/// boot-summary input.
pub fn class_table_len() -> usize {
    MT_CLASSES.len()
}

// ── Slot table ────────────────────────────────────────────────────

/// Per-slot tracking record. Owned by [`MtDevice::state`].
#[derive(Copy, Clone, Default, Debug)]
struct SlotRecord {
    /// `Some(contact_id)` while a finger is held in this slot;
    /// `None` when free.
    contact_id: Option<u8>,
    /// Whether this slot was seen in the last frame — used by the
    /// `NOT_SEEN_MEANS_UP` quirk to synthesise release events for
    /// firmwares that don't emit a final `tip=0` frame.
    seen_this_frame: bool,
}

/// Mutable per-device state the pump owns between reports.
#[derive(Debug)]
pub struct MtPumpState {
    slots: [SlotRecord; MAX_SLOTS],
    /// Last seen left-button state — used for press/release diff.
    last_left: bool,
    /// Last seen right-button state — only set when the device's
    /// descriptor exposes Button 2.
    last_right: bool,
}

impl Default for MtPumpState {
    fn default() -> Self {
        Self::new()
    }
}

impl MtPumpState {
    pub const fn new() -> Self {
        Self {
            slots: [SlotRecord {
                contact_id: None,
                seen_this_frame: false,
            }; MAX_SLOTS],
            last_left: false,
            last_right: false,
        }
    }

    /// Allocate or look up the slot for `contact_id`. Returns
    /// `None` when every slot is in use — caller drops the contact
    /// rather than thrash an existing slot, matching Linux's
    /// hid-multitouch on overflow.
    fn map_contact(&mut self, contact_id: u8) -> Option<u8> {
        // Reuse existing mapping first — same contact_id seen in
        // consecutive frames keeps its slot.
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.contact_id == Some(contact_id) {
                s.seen_this_frame = true;
                return Some(i as u8);
            }
        }
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.contact_id.is_none() {
                s.contact_id = Some(contact_id);
                s.seen_this_frame = true;
                return Some(i as u8);
            }
        }
        None
    }

    /// Look up the slot for `contact_id` without allocating.
    fn slot_of(&self, contact_id: u8) -> Option<u8> {
        self.slots
            .iter()
            .position(|s| s.contact_id == Some(contact_id))
            .map(|i| i as u8)
    }

    /// Release the slot mapped to `contact_id`.
    fn release(&mut self, contact_id: u8) {
        for s in self.slots.iter_mut() {
            if s.contact_id == Some(contact_id) {
                s.contact_id = None;
                s.seen_this_frame = false;
            }
        }
    }

    /// Begin a fresh frame: clear `seen_this_frame` on every slot
    /// so the `NOT_SEEN_MEANS_UP` quirk's end-of-frame sweep can
    /// release stale contacts.
    fn begin_frame(&mut self) {
        for s in self.slots.iter_mut() {
            s.seen_this_frame = false;
        }
    }

    /// Slot table snapshot — `(slot, contact_id)` pairs. Test
    /// helper; not used at runtime.
    #[doc(hidden)]
    pub fn active_contacts(&self) -> Vec<(u8, u8)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.contact_id.map(|c| (i as u8, c)))
            .collect()
    }
}

// ── Touch shape (touchpad vs touchscreen) ─────────────────────────

/// Discriminates between the two top-level collection shapes this
/// driver handles. Stored on [`MtDevice`] so the pump can pick the
/// right per-frame emit semantics:
/// - `TouchPad`: emit slot-protocol-B + `BTN_LEFT/RIGHT` from the
///   device's physical buttons.
/// - `TouchScreen`: emit absolute `ABS_X/ABS_Y` for the first
///   contact AND slot-protocol-B for every contact (gesture engines
///   want both; window-system pointer rides on contact 0).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtShape {
    TouchPad,
    TouchScreen,
}

impl MtShape {
    /// Resolve the shape from a parsed `ReportDescriptor`. Returns
    /// `Some(TouchPad)` iff the descriptor declares a Touch Pad
    /// Application Collection (Digitizer page, usage 0x05); else
    /// `Some(TouchScreen)` when it declares a Touch Screen
    /// (Digitizer page, usage 0x04); else `None` — caller treats
    /// that as "no MT shape here, fall back to other class
    /// drivers".
    pub fn detect(d: &ReportDescriptor) -> Option<Self> {
        for &(p, u) in d.top_level_apps.iter() {
            if p == digitizer::PAGE && u == digitizer::TOUCH_PAD {
                return Some(MtShape::TouchPad);
            }
        }
        for &(p, u) in d.top_level_apps.iter() {
            if p == digitizer::PAGE && u == digitizer::TOUCH_SCREEN {
                return Some(MtShape::TouchScreen);
            }
        }
        None
    }
}

// ── Bound device record + global registry ─────────────────────────

/// Two-arm union of bound profile data. For touchpads we keep the
/// PTP profile (Configuration TLC + Mode Feature is here); for
/// touchscreens we keep the touchscreen profile.
#[derive(Clone, Debug)]
pub enum MtProfile {
    Pad(PtpProfile),
    Screen(TouchscreenProfile),
}

/// One bound multi-touch device. Held in the global [`DEVICES`]
/// registry; transport pumps (USB / i2c-HID) drain reports via
/// [`pump_decoded_ptp`] / [`pump_decoded_touch`].
#[derive(Debug)]
pub struct MtDevice {
    pub shape: MtShape,
    pub class: MtClass,
    pub quirks: MtQuirks,
    pub max_contacts: u8,
    pub profile: MtProfile,
    state: IrqSafeSpinLock<MtPumpState>,
}

impl MtDevice {
    /// Construct an [`MtDevice`] from a parsed descriptor. Returns
    /// `None` if no MT shape was detected — caller falls back to
    /// the legacy single-touch path.
    pub fn attach(d: &ReportDescriptor, class: MtClass) -> Option<Arc<Self>> {
        let shape = MtShape::detect(d)?;
        let entry = lookup_class(class);
        match shape {
            MtShape::TouchPad => {
                let p = ptp::detect(d)?;
                let max_contacts = mt_features::resolve_max_contacts(
                    &p,
                    d,
                    if entry.max_contacts > 0 {
                        Some(entry.max_contacts)
                    } else {
                        None
                    },
                );
                Some(Arc::new(MtDevice {
                    shape,
                    class,
                    quirks: entry.quirks,
                    max_contacts,
                    profile: MtProfile::Pad(p),
                    state: IrqSafeSpinLock::new(MtPumpState::new()),
                }))
            }
            MtShape::TouchScreen => {
                let p = touchscreen::detect(d)?;
                let max_contacts = if entry.max_contacts > 0 {
                    entry
                        .max_contacts
                        .min(mt_features::HARD_MAX_CONTACTS)
                } else if p.contacts_max > 0 {
                    (p.contacts_max as u32)
                        .clamp(1, mt_features::HARD_MAX_CONTACTS as u32)
                        as u8
                } else {
                    mt_features::DEFAULT_MAX_CONTACTS
                };
                Some(Arc::new(MtDevice {
                    shape,
                    class,
                    quirks: entry.quirks,
                    max_contacts,
                    profile: MtProfile::Screen(p),
                    state: IrqSafeSpinLock::new(MtPumpState::new()),
                }))
            }
        }
    }

    /// PTP-shape pump: feed a decoded touchpad report into the
    /// driver. Emits Slot-Protocol-B [`TouchEvent`]s + button
    /// transitions and returns the number of events pushed.
    pub fn pump_ptp(&self, decoded: &PtpDecoded) -> usize {
        let mut st = self.state.lock();
        pump_ptp_inner(self, &mut st, decoded)
    }

    /// Touchscreen pump: feed a decoded touchscreen report.
    /// Emits absolute `ABS_X/ABS_Y` for contact 0 (matches Linux's
    /// `INPUT_MT_DIRECT` "shadow" mouse cursor) AND
    /// Slot-Protocol-B events for every contact.
    pub fn pump_screen(&self, decoded: &DecodedTouchReport) -> usize {
        let mut st = self.state.lock();
        pump_screen_inner(self, &mut st, decoded)
    }

    /// Snapshot the pump state for tests / boot diagnostics.
    #[doc(hidden)]
    pub fn snapshot_active_contacts(&self) -> Vec<(u8, u8)> {
        self.state.lock().active_contacts()
    }
}

/// Global registry of bound MT devices. The transport-specific
/// bind paths (USB / i2c-HID) push here after their probe succeeds;
/// the test harness reads [`attached_device_count`] to assert the
/// claim happened.
static DEVICES: IrqSafeSpinLock<Vec<Arc<MtDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// Stats counters surfaced for the boot panel + tests. Bumped from
/// the per-report pumps; readers see relaxed-ordering snapshots.
pub static MT_REPORTS_DECODED: AtomicU32 = AtomicU32::new(0);
pub static MT_TOUCH_EVENTS_EMITTED: AtomicU32 = AtomicU32::new(0);
pub static MT_BUTTON_EVENTS_EMITTED: AtomicU32 = AtomicU32::new(0);

/// Register a freshly-attached device. Transport bind layers call
/// this after [`MtDevice::attach`] returns `Some`.
pub fn register_device(dev: Arc<MtDevice>) {
    DEVICES.lock().push(dev);
}

/// Number of registered MT devices.
pub fn attached_device_count() -> usize {
    DEVICES.lock().len()
}

/// Snapshot of registered devices for pump-all loops.
pub fn devices_snapshot() -> Vec<Arc<MtDevice>> {
    DEVICES.lock().clone()
}

#[doc(hidden)]
pub fn __reset_registry_for_test() {
    DEVICES.lock().clear();
    MT_REPORTS_DECODED.store(0, Ordering::Relaxed);
    MT_TOUCH_EVENTS_EMITTED.store(0, Ordering::Relaxed);
    MT_BUTTON_EVENTS_EMITTED.store(0, Ordering::Relaxed);
}

// ── Per-shape pump logic ──────────────────────────────────────────

/// Convert one decoded PTP report into Slot-Protocol-B
/// `TouchEvent`s + button events. Mirrors the structure of
/// `i2c_hid_touch::pump_report` so the two pumps share the same
/// per-frame contract.
fn pump_ptp_inner(
    dev: &MtDevice,
    state: &mut MtPumpState,
    r: &PtpDecoded,
) -> usize {
    state.begin_frame();
    let mut emitted = 0usize;

    // Per-contact processing.
    let n = (r.contact_count as usize).min(r.contacts.len()).min(dev.max_contacts as usize);
    for c in r.contacts.iter().take(n) {
        let valid = is_contact_valid(dev.quirks, c.tip_switch, c.in_range, c.confidence);
        let cid = c.contact_id;

        if valid && c.tip_switch {
            let was_active = state.slot_of(cid).is_some();
            let slot = match state.map_contact(cid) {
                Some(s) => s,
                None => continue,
            };
            let st = if was_active {
                TouchState::Move
            } else {
                TouchState::Down
            };
            push_touch_for_ptp(slot, cid, c, st);
            emitted += 1;
        } else if let Some(slot) = state.slot_of(cid) {
            // Tip Switch dropped → release.
            push_touch_for_ptp(slot, cid, c, TouchState::Up);
            state.release(cid);
            emitted += 1;
        }
    }

    // `NOT_SEEN_MEANS_UP`: synthesise release for any slot that
    // didn't appear this frame. Some Asus / older Synaptics
    // firmware just stops emitting contacts when they're lifted,
    // expecting the host to time them out.
    if dev.quirks.contains(MtQuirks::NOT_SEEN_MEANS_UP) {
        // Snapshot stale (id, slot) pairs before mutating.
        let stale: Vec<(u8, u8)> = state
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let cid = s.contact_id?;
                if !s.seen_this_frame {
                    Some((i as u8, cid))
                } else {
                    None
                }
            })
            .collect();
        for (slot, cid) in stale {
            push_release_event(slot, cid);
            state.release(cid);
            emitted += 1;
        }
    }

    // Button transitions. Win8 PTP-class devices emit Button 1 on
    // the descriptor's Button page; in NARF's event model
    // primary / secondary clicks ride `PointerEvent` with
    // `PointerButtons::{LEFT,RIGHT}` — that's where the rest of the
    // pointer pipeline (cursor pump, libinput-style gesture
    // engine) already listens. We emit a zero-delta PointerEvent
    // on transition so the consumer sees the button-state change
    // without a synthetic motion event. BTN_RIGHT comes from a
    // hypothetical Button 2 the PTP profile doesn't yet expose;
    // when it does, the same diff path adds it.
    if r.button1 != state.last_left {
        let buttons = if r.button1 {
            PointerButtons::LEFT
        } else {
            PointerButtons::EMPTY
        };
        let _ = push_global(InputEvent::Pointer(PointerEvent {
            dx: 0,
            dy: 0,
            buttons,
        }));
        state.last_left = r.button1;
        MT_BUTTON_EVENTS_EMITTED.fetch_add(1, Ordering::Relaxed);
        emitted += 1;
    }

    MT_REPORTS_DECODED.fetch_add(1, Ordering::Relaxed);
    emitted
}

fn pump_screen_inner(
    dev: &MtDevice,
    state: &mut MtPumpState,
    r: &DecodedTouchReport,
) -> usize {
    state.begin_frame();
    let mut emitted = 0usize;

    let profile = match &dev.profile {
        MtProfile::Screen(p) => p,
        // Defense in depth: callers should never invoke
        // `pump_screen` on a touchpad MtDevice, but if they do,
        // bail rather than corrupt the slot state.
        MtProfile::Pad(_) => return 0,
    };
    let (x_min, x_max) = profile.x_range;
    let (y_min, y_max) = profile.y_range;

    let n = (r.contact_count as usize).min(r.contacts.len()).min(dev.max_contacts as usize);
    let mut primary_emitted = false;
    for c in r.contacts.iter().take(n) {
        let valid = is_contact_valid(dev.quirks, c.tip_switch, c.in_range, c.confidence);
        let cid = c.contact_id;

        // Per-spec for INPUT_MT_DIRECT: emit absolute X/Y on the
        // *first* in-range contact so a window-system "shadow"
        // cursor can ride contact 0 without re-deriving from MT.
        // Linux `mt_allocate_application` (hid-multitouch.c:635-637)
        // sets INPUT_MT_DIRECT for touchscreens; that flag drives
        // the same per-contact-0 ABS_X/ABS_Y emission. NOTE the
        // task spec says "PTP variant uses slot B" — read as "the
        // touchpad path goes through slot-B only"; touchscreens
        // emit absolute too.
        if valid && c.tip_switch && !primary_emitted {
            let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
                axis: abs::ABS_X,
                value: c.x,
            }));
            let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
                axis: abs::ABS_Y,
                value: c.y,
            }));
            emitted += 2;
            primary_emitted = true;
        }

        if valid && c.tip_switch {
            let was_active = state.slot_of(cid).is_some();
            let slot = match state.map_contact(cid) {
                Some(s) => s,
                None => continue,
            };
            let st = if was_active {
                TouchState::Move
            } else {
                TouchState::Down
            };
            push_touch_for_screen(slot, cid, c, st, x_min, x_max, y_min, y_max);
            emitted += 1;
        } else if let Some(slot) = state.slot_of(cid) {
            push_touch_for_screen(slot, cid, c, TouchState::Up, x_min, x_max, y_min, y_max);
            state.release(cid);
            emitted += 1;
        }
    }

    MT_REPORTS_DECODED.fetch_add(1, Ordering::Relaxed);
    emitted
}

/// `MT_QUIRK_*` validity policy from
/// `linux/drivers/hid/hid-multitouch.c:55-79`. Default precedence
/// matches `mt_post_parse_default_settings` defaulting:
/// - `ALWAYS_VALID` → always true
/// - `VALID_IS_INRANGE` → use the in-range bit
/// - `VALID_IS_CONFIDENCE` → use the confidence bit
/// - none → assume valid when tip is asserted (matches the
///   Microsoft PTP spec default)
fn is_contact_valid(q: MtQuirks, tip: bool, in_range: bool, confidence: bool) -> bool {
    if q.contains(MtQuirks::ALWAYS_VALID) {
        return true;
    }
    if q.contains(MtQuirks::VALID_IS_INRANGE) {
        return in_range;
    }
    if q.contains(MtQuirks::VALID_IS_CONFIDENCE) {
        return confidence;
    }
    tip
}

fn push_touch_for_ptp(
    slot: u8,
    contact_id: u8,
    c: &narf_hid::ptp::DecodedContact,
    state: TouchState,
) {
    let pressure = c.pressure.unwrap_or(0);
    let tracking_id = match state {
        TouchState::Up => None,
        _ => Some(contact_id as i32),
    };
    let _ = push_global(InputEvent::Touch(TouchEvent {
        slot,
        tracking_id,
        id: contact_id as u16,
        x: c.x,
        y: c.y,
        pressure,
        state,
    }));
    MT_TOUCH_EVENTS_EMITTED.fetch_add(1, Ordering::Relaxed);
}

#[allow(clippy::too_many_arguments)]
fn push_touch_for_screen(
    slot: u8,
    contact_id: u8,
    c: &narf_hid::touchscreen::DecodedTouchContact,
    state: TouchState,
    x_min: i32,
    x_max: i32,
    y_min: i32,
    y_max: i32,
) {
    let nx = TouchEvent::normalise_axis(c.x, x_min, x_max) as i32;
    let ny = TouchEvent::normalise_axis(c.y, y_min, y_max) as i32;
    let pressure = c.pressure.unwrap_or(0);
    let tracking_id = match state {
        TouchState::Up => None,
        _ => Some(contact_id as i32),
    };
    let _ = push_global(InputEvent::Touch(TouchEvent {
        slot,
        tracking_id,
        id: contact_id as u16,
        x: nx,
        y: ny,
        pressure,
        state,
    }));
    MT_TOUCH_EVENTS_EMITTED.fetch_add(1, Ordering::Relaxed);
}

/// Push a slot-release event for a contact that the device stopped
/// reporting (NOT_SEEN_MEANS_UP) — synthesises an Up event without
/// position update so consumers can clean up gesture state.
fn push_release_event(slot: u8, contact_id: u8) {
    let _ = push_global(InputEvent::Touch(TouchEvent {
        slot,
        tracking_id: None,
        id: contact_id as u16,
        x: 0,
        y: 0,
        pressure: 0,
        state: TouchState::Up,
    }));
    MT_TOUCH_EVENTS_EMITTED.fetch_add(1, Ordering::Relaxed);
}

// ── Initcall registration ─────────────────────────────────────────

/// Stage::Device initcall — currently a no-op marker that surfaces
/// "MT class driver staged" in the boot summary. Transport-specific
/// probes wire themselves into the device tree (USB / i2c-HID) and
/// call [`MtDevice::attach`] when they detect an MT-shaped report
/// descriptor.
pub fn register_initcalls() {
    use core::fmt::Write as _;
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "hid-multitouch", || {
        let _ = writeln!(
            narf_console::Writer,
            "  hid-multitouch: class table loaded ({} entries, MAX_SLOTS={})",
            class_table_len(),
            MAX_SLOTS,
        );
        InitResult::Ok
    });
}

// ── Local helpers + macros ────────────────────────────────────────

/// Re-exported tiny bitflags macro local to this module so the
/// `MtQuirks` declaration doesn't depend on `narf-input`'s
/// `bitflags_like!` exposing `const fn bits()` (which it does, but
/// the local macro lets us add bits without the upstream import).
#[macro_export]
#[doc(hidden)]
macro_rules! __mt_quirk_bitflags {
    (
        $(#[$outer:meta])*
        pub struct $name:ident: $repr:ty {
            $(const $flag:ident = $value:expr;)*
        }
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            pub const EMPTY: Self = Self(0);
            $(pub const $flag: Self = Self($value);)*

            #[inline] pub const fn bits(self) -> $repr { self.0 }
            #[inline] pub const fn from_bits_truncate(b: $repr) -> Self { Self(b) }
            #[inline] pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
            #[inline] pub fn insert(&mut self, other: Self) { self.0 |= other.0; }
            #[inline] pub fn remove(&mut self, other: Self) { self.0 &= !other.0; }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({:#b})", stringify!($name), self.0)
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
        }
        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
        }
        impl core::ops::BitAnd for $name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
        }
    };
}

// ── Test helpers (synth-driven smokes) ───────────────────────────

/// Build a synthetic `PtpDecoded` from `(contact_id, tip, x, y)`
/// tuples — keeps the smoke tests compact.
#[doc(hidden)]
pub fn __build_ptp_decoded_for_test(
    contacts: &[(u8, bool, i32, i32)],
    button1: bool,
) -> PtpDecoded {
    use narf_hid::ptp::DecodedContact;
    let mut decoded = Vec::with_capacity(contacts.len());
    for &(cid, tip, x, y) in contacts {
        decoded.push(DecodedContact {
            tip_switch: tip,
            contact_id: cid,
            x,
            y,
            pressure: None,
            in_range: tip,
            confidence: true,
        });
    }
    let n = decoded.len() as u8;
    PtpDecoded {
        contacts: decoded,
        contact_count: n,
        scan_time: 0,
        button1,
    }
}

/// Build a synthetic `DecodedTouchReport` for the touchscreen smoke
/// pump tests.
#[doc(hidden)]
pub fn __build_screen_decoded_for_test(
    contacts: &[(u8, bool, i32, i32)],
) -> DecodedTouchReport {
    use narf_hid::touchscreen::DecodedTouchContact;
    let mut decoded = Vec::with_capacity(contacts.len());
    for &(cid, tip, x, y) in contacts {
        decoded.push(DecodedTouchContact {
            tip_switch: tip,
            contact_id: cid,
            x,
            y,
            pressure: None,
            in_range: tip,
            confidence: true,
        });
    }
    let n = decoded.len() as u8;
    DecodedTouchReport {
        contacts: decoded,
        contact_count: n,
    }
}

/// Construct an `MtDevice` with synthesised PTP profile for tests
/// that need a pump but don't want to pay for descriptor parsing.
#[doc(hidden)]
pub fn __attach_synth_pad_for_test(class: MtClass, max_contacts: u8) -> Arc<MtDevice> {
    let entry = lookup_class(class);
    // Re-use the spec-shaped PTP descriptor blob from `narf-hid` to
    // get a real `PtpProfile`. The blob lives in a `static` so we
    // can call `parse` at runtime without an allocation up front.
    let blob = narf_hid::ptp::__ptp_descriptor_blob();
    let parsed = narf_hid::descriptor::parse(blob).expect("synth blob parses");
    let p = narf_hid::ptp::detect(&parsed).expect("synth blob is PTP");
    let max = if max_contacts > 0 {
        max_contacts
    } else {
        mt_features::DEFAULT_MAX_CONTACTS
    };
    Arc::new(MtDevice {
        shape: MtShape::TouchPad,
        class,
        quirks: entry.quirks,
        max_contacts: max,
        profile: MtProfile::Pad(p),
        state: IrqSafeSpinLock::new(MtPumpState::new()),
    })
}

/// Same as `__attach_synth_pad_for_test` but for the touchscreen
/// shape. Builds a synthetic descriptor inline since the
/// touchscreen module doesn't expose a public blob.
#[doc(hidden)]
pub fn __attach_synth_screen_for_test(
    class: MtClass,
    max_contacts: u8,
) -> Arc<MtDevice> {
    let entry = lookup_class(class);
    let blob = synth_touchscreen_descriptor_blob();
    let parsed = narf_hid::descriptor::parse(&blob).expect("synth blob parses");
    let p = narf_hid::touchscreen::detect(&parsed).expect("synth blob is touchscreen");
    let max = if max_contacts > 0 {
        max_contacts
    } else {
        mt_features::DEFAULT_MAX_CONTACTS
    };
    Arc::new(MtDevice {
        shape: MtShape::TouchScreen,
        class,
        quirks: entry.quirks,
        max_contacts: max,
        profile: MtProfile::Screen(p),
        state: IrqSafeSpinLock::new(MtPumpState::new()),
    })
}

/// Synthetic 1-contact Touchscreen Application Collection blob,
/// mirroring the Microsoft "Touchscreen Sample Report Descriptors"
/// shape so the touchscreen probe locks on. Single-contact is the
/// minimum shape — the smoke tests only need it to verify that
/// detect → pump pipeline works end-to-end.
fn synth_touchscreen_descriptor_blob() -> Vec<u8> {
    alloc::vec![
        0x05, 0x0D, // Usage Page (Digitizer)
        0x09, 0x04, // Usage (Touch Screen)
        0xA1, 0x01, // Collection (Application)
        0x85, 0x01, //   Report ID (1)
        0x09, 0x22, //   Usage (Finger)
        0xA1, 0x02, //   Collection (Logical)
        0x09, 0x42, //     Usage (Tip Switch)
        0x15, 0x00, //     Logical Min (0)
        0x25, 0x01, //     Logical Max (1)
        0x75, 0x01, //     Report Size (1)
        0x95, 0x01, //     Report Count (1)
        0x81, 0x02, //     Input (Data,Var,Abs)
        0x75, 0x07, //     Report Size (7) padding
        0x81, 0x03, //     Input (Cnst)
        0x09, 0x51, //     Usage (Contact ID)
        0x25, 0x7F, //     Logical Max (127)
        0x75, 0x08, //     Report Size (8)
        0x81, 0x02, //     Input
        0x05, 0x01, //     Usage Page (Generic Desktop)
        0x09, 0x30, //     Usage (X)
        0x26, 0xFF, 0x7F, // Logical Max (0x7FFF)
        0x75, 0x10, //     Report Size (16)
        0x81, 0x02, //     Input
        0x09, 0x31, //     Usage (Y)
        0x81, 0x02, //     Input
        0xC0,       //   End Collection
        0x05, 0x0D, //   Usage Page (Digitizer)
        0x09, 0x54, //   Usage (Contact Count)
        0x25, 0x02, //   Logical Max (2)
        0x75, 0x08, //   Report Size (8)
        0x95, 0x01, //   Report Count (1)
        0x81, 0x02, //   Input
        0xC0,       // End Collection
    ]
}
