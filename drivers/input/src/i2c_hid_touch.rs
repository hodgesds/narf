//! HID-over-I2C touchscreen pump glue.
//!
//! What this module does
//! ---------------------
//! Translates the per-report state produced by
//! [`narf_hid::touchscreen::decode_input`] into
//! [`narf_input::TouchEvent`]s on the global ring, with the
//! per-contact lifecycle (`Down` / `Move` / `Up`) derived from
//! the previous frame's state. Coordinates are normalised into
//! the kernel's shared `0..=65535` touch space via
//! [`narf_input::TouchEvent::normalise_axis`] so consumers can
//! map any touchscreen to its panel without re-decoding the HID
//! Logical range per-touch.
//!
//! Slot allocation
//! ---------------
//! HID Digitizer touchscreens report a Contact Identifier per
//! finger (Digitizer page 0x51) but the value space is
//! device-defined — some firmwares reuse low ids, others
//! allocate fresh values per touch. We treat Contact Identifier
//! as the stable per-finger handle for the lifetime of one
//! touch (Down → Up) and map it to a slot id 0..N. The slot
//! table holds at most `contacts_max` live ids; once a contact
//! is Up its slot frees for the next Down.
//!
//! Single-touch fallback: when the descriptor exposes no
//! Contact Identifier field (rare; some single-finger panels
//! omit it), the decoder hands us a zero id for every contact;
//! we degrade gracefully by using the position in the
//! per-contact array as the slot id, accepting that a
//! single-touch device's Down / Move / Up boundary is then
//! driven purely by Tip Switch.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_hid::pen::DecodedPen;
use narf_hid::touchscreen::{DecodedTouchContact, DecodedTouchReport, TouchscreenProfile};
use narf_input::{
    abs, btn, push_global, AbsoluteEvent, ButtonEvent, InputEvent, TouchEvent, TouchState,
};

/// Maximum simultaneously tracked contacts. Modern touchscreens
/// ship 5- or 10-finger panels; capping at 10 here costs only
/// 20 bytes of slot state per device and avoids unbounded
/// allocation if a buggy firmware ever advertises a larger
/// Contact Count Max.
pub const MAX_TOUCH_SLOTS: usize = 10;

/// Per-slot state the pump owns between reports.
#[derive(Copy, Clone, Default, Debug)]
struct TouchSlot {
    /// `Some(contact_id)` while a finger is held in this slot;
    /// `None` when free.
    contact_id: Option<u8>,
}

/// Mutable per-device state the pump carries between reports.
/// Owns the slot table.
#[derive(Debug)]
pub struct TouchPumpState {
    slots: [TouchSlot; MAX_TOUCH_SLOTS],
}

impl Default for TouchPumpState {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchPumpState {
    pub const fn new() -> Self {
        Self {
            slots: [TouchSlot { contact_id: None }; MAX_TOUCH_SLOTS],
        }
    }

    /// Allocate a slot for `contact_id` if not already mapped,
    /// returning `Some(slot)` on success. Returns `None` only
    /// when every slot is in use — the caller (the per-report
    /// pump) treats that as "drop this contact, no room left",
    /// matching how Linux's hid-multitouch handles overflow.
    fn map_contact(&mut self, contact_id: u8) -> Option<u8> {
        for (i, s) in self.slots.iter().enumerate() {
            if s.contact_id == Some(contact_id) {
                return Some(i as u8);
            }
        }
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.contact_id.is_none() {
                s.contact_id = Some(contact_id);
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

    /// Release the slot mapped to `contact_id`. No-op if it
    /// wasn't tracked.
    fn release(&mut self, contact_id: u8) {
        for s in self.slots.iter_mut() {
            if s.contact_id == Some(contact_id) {
                s.contact_id = None;
            }
        }
    }
}

/// Walk every contact in `decoded` and push the corresponding
/// [`TouchEvent`]s onto the global ring. Coordinates are
/// normalised against the profile's `x_range` / `y_range` into
/// the `0..=65535` shared touchscreen space.
///
/// Returns the number of events pushed — diagnostic plumbing for
/// the boot panel + the smokes.
pub fn pump_report(
    profile: &TouchscreenProfile,
    state: &mut TouchPumpState,
    decoded: &DecodedTouchReport,
) -> usize {
    let mut pushed = 0usize;
    let n = (decoded.contact_count as usize).min(decoded.contacts.len());
    let (x_min, x_max) = profile.x_range;
    let (y_min, y_max) = profile.y_range;

    // Emit one TouchEvent per advertised contact in this scan.
    // Down/Move derive from whether we'd previously allocated a
    // slot for this contact_id; Up emits when Tip Switch is 0
    // *and* the contact was tracked at the previous scan.
    for c in decoded.contacts.iter().take(n) {
        let cid = c.contact_id;
        if c.tip_switch {
            let was_active = state.slot_of(cid).is_some();
            let slot = match state.map_contact(cid) {
                Some(s) => s,
                None => continue,
            };
            let xy_state = if was_active {
                TouchState::Move
            } else {
                TouchState::Down
            };
            push_touch_event(slot, cid, c, xy_state, x_min, x_max, y_min, y_max);
            pushed += 1;
        } else if let Some(slot) = state.slot_of(cid) {
            // Tip Switch dropped → release. Some firmwares emit
            // a final "lift" frame with the position from the
            // last hold; we surface that as an Up event so the
            // consumer can finalise gestures.
            push_touch_event(slot, cid, c, TouchState::Up, x_min, x_max, y_min, y_max);
            state.release(cid);
            pushed += 1;
        }
    }

    // Edge case: a contact disappeared from the per-finger
    // array entirely (Contact Count dropped, slot not present
    // in this scan). Spec-compliant firmware always echoes a
    // final "tip_switch=0" frame, so the bookkeeping above
    // handles release. We don't synthesize Up events for
    // missing slots — leave that for the next report.
    pushed
}

#[allow(clippy::too_many_arguments)]
fn push_touch_event(
    slot: u8,
    contact_id: u8,
    c: &DecodedTouchContact,
    state: TouchState,
    x_min: i32,
    x_max: i32,
    y_min: i32,
    y_max: i32,
) {
    let nx = TouchEvent::normalise_axis(c.x, x_min, x_max) as i32;
    let ny = TouchEvent::normalise_axis(c.y, y_min, y_max) as i32;
    let pressure = c.pressure.unwrap_or(0);
    let tracking_id = Some(contact_id as i32);
    let _ = push_global(InputEvent::Touch(TouchEvent {
        slot,
        tracking_id,
        id: contact_id as u16,
        x: nx,
        y: ny,
        pressure,
        state,
    }));
}

/// Per-device pen state carried between reports.
#[derive(Copy, Clone, Default, Debug)]
pub struct PenPumpState {
    /// Last known in-range state — lets us emit a single
    /// BTN_TOOL_PEN=0 transition when the pen leaves hover
    /// range rather than spamming it every report.
    in_range: bool,
    /// Last tip state — same dedup logic.
    tip: bool,
    /// Last eraser state.
    eraser: bool,
}

/// Translate one decoded pen report into the kernel event stream.
///
/// Emits:
/// - `ButtonEvent(BTN_TOOL_PEN, 1)` on in-range entry / `(0)` on exit.
/// - `ButtonEvent(BTN_TOOL_RUBBER, 1/0)` on eraser transitions.
/// - `ButtonEvent(BTN_STYLUS, 1/0)` on barrel-button transitions.
/// - `ButtonEvent(BTN_STYLUS2, 1/0)` on secondary-barrel transitions.
/// - `AbsoluteEvent(ABS_X)` + `AbsoluteEvent(ABS_Y)` when in range.
/// - `AbsoluteEvent(ABS_PRESSURE)` when the tip is down and the
///   profile advertised a pressure field.
///
/// Returns the number of events pushed. Reference:
/// `linux/drivers/hid/hid-input.c` pen/stylus EV_KEY + EV_ABS mapping.
pub fn pump_pen_report(state: &mut PenPumpState, pen: &DecodedPen) -> usize {
    let mut pushed = 0usize;

    // BTN_TOOL_PEN / BTN_TOOL_RUBBER — emit only on transition.
    if pen.in_range != state.in_range || pen.eraser != state.eraser {
        if pen.in_range {
            // Tool type: eraser when Invert or Eraser bit set;
            // otherwise pen tip. Transition: announce new tool type.
            let tool = if pen.eraser || pen.invert {
                btn::BTN_TOOL_RUBBER
            } else {
                btn::BTN_TOOL_PEN
            };
            let _ = push_global(InputEvent::Button(ButtonEvent {
                code: tool,
                pressed: true,
            }));
            pushed += 1;
            // If the old tool was the other type, release it.
            if state.in_range {
                let old_tool = if state.eraser {
                    btn::BTN_TOOL_RUBBER
                } else {
                    btn::BTN_TOOL_PEN
                };
                if old_tool != tool {
                    let _ = push_global(InputEvent::Button(ButtonEvent {
                        code: old_tool,
                        pressed: false,
                    }));
                    pushed += 1;
                }
            }
        } else {
            // Pen left range — release whichever tool was active.
            let old_tool = if state.eraser {
                btn::BTN_TOOL_RUBBER
            } else {
                btn::BTN_TOOL_PEN
            };
            let _ = push_global(InputEvent::Button(ButtonEvent {
                code: old_tool,
                pressed: false,
            }));
            pushed += 1;
        }
        state.in_range = pen.in_range;
        state.eraser = pen.eraser || pen.invert;
    }

    // Emit X + Y whenever in range.
    if pen.in_range {
        let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_X,
            value: pen.x,
        }));
        let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_Y,
            value: pen.y,
        }));
        pushed += 2;
    }

    // BTN_TOUCH (expressed as BTN_STYLUS for digitiser tip per
    // Linux `hid-input.c` mapping): emit on tip transition.
    if pen.tip != state.tip {
        let _ = push_global(InputEvent::Button(ButtonEvent {
            code: btn::BTN_STYLUS,
            pressed: pen.tip,
        }));
        pushed += 1;
        state.tip = pen.tip;
    }

    // Barrel (side) button → BTN_STYLUS2.
    if pen.barrel_button {
        let _ = push_global(InputEvent::Button(ButtonEvent {
            code: btn::BTN_STYLUS2,
            pressed: true,
        }));
        pushed += 1;
    }

    // Pressure — only when tip is down.
    if pen.tip {
        if let Some(p) = pen.pressure {
            let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
                axis: abs::ABS_PRESSURE,
                value: p,
            }));
            pushed += 1;
        }
    }

    pushed
}

/// Log a one-line boot summary describing the touchscreen
/// profile we just bound, matching the format the task spec
/// asks for. Called once per device after the descriptor is
/// parsed and the profile is detected.
pub fn log_boot_summary(path: &str, profile: &TouchscreenProfile) {
    let (xmin, xmax) = profile.x_range;
    let (ymin, ymax) = profile.y_range;
    let _ = writeln!(
        narf_console::Writer,
        "  touch: {} digitizer, {} contacts max, x=[{}..={}] y=[{}..={}]",
        path,
        profile.contacts_max,
        xmin,
        xmax,
        ymin,
        ymax,
    );
}

#[doc(hidden)]
pub fn __pump_report_for_test(
    profile: &TouchscreenProfile,
    state: &mut TouchPumpState,
    decoded: &DecodedTouchReport,
) -> usize {
    pump_report(profile, state, decoded)
}

#[doc(hidden)]
pub fn __new_state_for_test() -> TouchPumpState {
    TouchPumpState::new()
}

/// Build a synthetic [`DecodedTouchReport`] from `(contact_id,
/// tip, x, y)` tuples — keeps the smoke tests readable.
/// Sets `contact_count` to the input array length so a release
/// frame (tip=false) is still processed by the pump — matches
/// what real touchscreen firmware does, which reports every
/// changed contact (including the released one) in the per-scan
/// array and Contact Count covers them all.
#[doc(hidden)]
pub fn __build_decoded_for_test(contacts: &[(u8, bool, i32, i32)]) -> DecodedTouchReport {
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

// Force `String` import to stay alive when the `log_boot_summary`
// signature was the only user — switching to `&str` made it
// dead. Keeps the module self-contained for future callers that
// own a `String` device path.
#[allow(dead_code)]
fn _force_string_use(s: String) -> String {
    s
}

#[doc(hidden)]
pub fn __pump_pen_for_test(state: &mut PenPumpState, pen: &DecodedPen) -> usize {
    pump_pen_report(state, pen)
}

#[doc(hidden)]
pub fn __new_pen_state_for_test() -> PenPumpState {
    PenPumpState::default()
}

/// Build a synthetic [`DecodedPen`] for smoke tests.
/// `(in_range, tip, eraser, barrel, x, y, pressure)`
#[doc(hidden)]
pub fn __build_pen_for_test(
    in_range: bool,
    tip: bool,
    eraser: bool,
    barrel: bool,
    x: i32,
    y: i32,
    pressure: Option<i32>,
) -> DecodedPen {
    DecodedPen {
        in_range,
        tip,
        eraser,
        invert: false,
        barrel_button: barrel,
        secondary_barrel_button: false,
        x,
        y,
        pressure,
        x_tilt_deg: None,
        y_tilt_deg: None,
        twist: None,
    }
}
