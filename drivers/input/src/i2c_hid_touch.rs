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

use narf_hid::pen::{DecodedPen, PenProfile};
use narf_hid::ptp::{DecodedReport as DecodedPtpReport, PtpProfile};
use narf_hid::touchscreen::{DecodedTouchContact, DecodedTouchReport, TouchscreenProfile};
use narf_input::evdev::{
    key as evkey, prop, DeviceCaps, DeviceNode, EvdevEvent, EventType, MtContactUpdate,
    MtEvdevState,
};
use narf_input::{
    abs, btn, push_global, AbsoluteEvent, AxisInfo, ButtonEvent, InputEvent, TouchEvent, TouchState,
};

// ── evdev capability constructors ─────────────────────────────────────────────
//
// Each constructor starts from the transport identity the bind layer
// discovered (name / phys / HID-descriptor ids) and adds the class
// capabilities + properties. The property bits are load-bearing:
// libinput classifies BUTTONPAD devices as touchpads and DIRECT
// devices as touchscreens/tablets; without them a PTP pad falls into
// the touchscreen heuristic and gestures/button handling break.

fn axis(min: i32, max: i32) -> AxisInfo {
    AxisInfo {
        min,
        max,
        fuzz: 0,
        flat: 0,
        res: 0,
    }
}

fn add_mt_axes(caps: &mut DeviceCaps, max_slots: usize, x: AxisInfo, y: AxisInfo) {
    caps.add_abs_info(abs::ABS_X, x);
    caps.add_abs_info(abs::ABS_Y, y);
    caps.add_abs_info(
        abs::ABS_MT_SLOT,
        axis(0, max_slots.saturating_sub(1) as i32),
    );
    caps.add_abs_info(abs::ABS_MT_TRACKING_ID, axis(0, 0xFFFF));
    caps.add_abs_info(abs::ABS_MT_POSITION_X, x);
    caps.add_abs_info(abs::ABS_MT_POSITION_Y, y);
}

/// Caps for a Precision Touchpad collection: slot-protocol-B axes over
/// the profile's logical ranges, clickpad button, `INPUT_PROP_POINTER
/// | INPUT_PROP_BUTTONPAD`.
pub fn build_ptp_caps(profile: &PtpProfile, identity: &DeviceCaps) -> DeviceCaps {
    let mut caps = identity.clone();
    let first = profile.contacts.first();
    let x = first
        .and_then(|c| c.x.as_ref())
        .map(|f| axis(f.logical_min, f.logical_max))
        .unwrap_or_else(|| axis(0, 0x7FFF));
    let y = first
        .and_then(|c| c.y.as_ref())
        .map(|f| axis(f.logical_min, f.logical_max))
        .unwrap_or_else(|| axis(0, 0x7FFF));
    add_mt_axes(&mut caps, profile.contacts_max.max(1), x, y);
    if let Some(f) = profile.contacts.iter().find_map(|c| c.pressure.as_ref()) {
        let p = axis(f.logical_min, f.logical_max);
        caps.add_abs_info(abs::ABS_PRESSURE, p);
        caps.add_abs_info(abs::ABS_MT_PRESSURE, p);
    }
    caps.add_key(evkey::BTN_TOUCH);
    if profile.button1.is_some() {
        caps.add_key(evkey::BTN_LEFT);
    }
    caps.add_prop(prop::POINTER);
    caps.add_prop(prop::BUTTONPAD);
    caps
}

/// Caps for a Touch Screen collection: MT axes over the panel ranges,
/// `INPUT_PROP_DIRECT`.
pub fn build_touchscreen_caps(profile: &TouchscreenProfile, identity: &DeviceCaps) -> DeviceCaps {
    let mut caps = identity.clone();
    add_mt_axes(
        &mut caps,
        profile.contacts_max.max(1),
        axis(profile.x_range.0, profile.x_range.1),
        axis(profile.y_range.0, profile.y_range.1),
    );
    if let Some(f) = profile.contacts.iter().find_map(|c| c.pressure.as_ref()) {
        let p = axis(f.logical_min, f.logical_max);
        caps.add_abs_info(abs::ABS_PRESSURE, p);
        caps.add_abs_info(abs::ABS_MT_PRESSURE, p);
    }
    caps.add_key(evkey::BTN_TOUCH);
    caps.add_prop(prop::DIRECT);
    caps
}

/// Caps for a Pen / stylus collection: tool keys, tip + barrel
/// buttons, X/Y + pressure (+ tilt when the descriptor carries it),
/// `INPUT_PROP_DIRECT`.
pub fn build_pen_caps(profile: &PenProfile, identity: &DeviceCaps) -> DeviceCaps {
    let mut caps = identity.clone();
    let f = &profile.fields;
    caps.add_abs_info(
        abs::ABS_X,
        axis(f.x.field.logical_min, f.x.field.logical_max),
    );
    caps.add_abs_info(
        abs::ABS_Y,
        axis(f.y.field.logical_min, f.y.field.logical_max),
    );
    if let Some(p) = &f.tip_pressure {
        caps.add_abs_info(
            abs::ABS_PRESSURE,
            axis(p.field.logical_min, p.field.logical_max),
        );
    }
    if let Some(t) = &f.x_tilt {
        caps.add_abs_info(
            abs::ABS_TILT_X,
            axis(t.field.logical_min, t.field.logical_max),
        );
    }
    if let Some(t) = &f.y_tilt {
        caps.add_abs_info(
            abs::ABS_TILT_Y,
            axis(t.field.logical_min, t.field.logical_max),
        );
    }
    caps.add_key(evkey::BTN_TOOL_PEN);
    caps.add_key(evkey::BTN_TOOL_RUBBER);
    caps.add_key(evkey::BTN_TOUCH);
    if f.barrel_switch.is_some() {
        caps.add_key(evkey::BTN_STYLUS);
    }
    if f.secondary_barrel_switch.is_some() {
        caps.add_key(evkey::BTN_STYLUS2);
    }
    caps.add_prop(prop::DIRECT);
    caps
}

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
    /// Slot-protocol-B emitter for the evdev node (the global-ring
    /// path above keeps its own Down/Move/Up lifecycle).
    evdev: MtEvdevState,
}

impl Default for TouchPumpState {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchPumpState {
    pub fn new() -> Self {
        Self {
            slots: [TouchSlot { contact_id: None }; MAX_TOUCH_SLOTS],
            evdev: MtEvdevState::new(MAX_TOUCH_SLOTS),
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
    pump_report_to_evdev(profile, state, decoded, None)
}

/// [`pump_report`] plus evdev publication: the same slot allocation
/// drives a slot-protocol-B frame on `node` (raw profile coordinates —
/// libinput maps them through the caps' `EVIOCGABS` ranges) when the
/// bind layer registered a touchscreen node.
pub fn pump_report_to_evdev(
    profile: &TouchscreenProfile,
    state: &mut TouchPumpState,
    decoded: &DecodedTouchReport,
    node: Option<&DeviceNode>,
) -> usize {
    let mut pushed = 0usize;
    let mut updates: Vec<MtContactUpdate> = Vec::new();
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
            updates.push(MtContactUpdate {
                slot: slot as usize,
                active: true,
                tracking_id: cid as i32,
                x: c.x,
                y: c.y,
                pressure: c.pressure,
            });
            pushed += 1;
        } else if let Some(slot) = state.slot_of(cid) {
            // Tip Switch dropped → release. Some firmwares emit
            // a final "lift" frame with the position from the
            // last hold; we surface that as an Up event so the
            // consumer can finalise gestures.
            push_touch_event(slot, cid, c, TouchState::Up, x_min, x_max, y_min, y_max);
            updates.push(MtContactUpdate {
                slot: slot as usize,
                active: false,
                tracking_id: cid as i32,
                x: c.x,
                y: c.y,
                pressure: None,
            });
            state.release(cid);
            pushed += 1;
        }
    }

    if let Some(node) = node {
        state.evdev.dispatch_frame(node, &updates, false, false);
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

// ── PTP (Precision Touchpad) evdev pump ───────────────────────────────────────

/// Per-device PTP evdev state: wire contact-id → MT slot allocation
/// plus the shared slot-protocol-B emitter. The bind layer keeps its
/// separate first-contact relative-pointer feed for the global ring;
/// this state exists purely for the evdev node.
#[derive(Debug)]
pub struct PtpPumpState {
    /// slot → wire contact id occupying it.
    slots: Vec<Option<u8>>,
    evdev: MtEvdevState,
}

impl PtpPumpState {
    pub fn new(max_slots: usize) -> Self {
        let max_slots = max_slots.max(1);
        Self {
            slots: alloc::vec![None; max_slots],
            evdev: MtEvdevState::new(max_slots),
        }
    }

    fn slot_of(&self, contact_id: u8) -> Option<usize> {
        self.slots.iter().position(|s| *s == Some(contact_id))
    }

    fn map_contact(&mut self, contact_id: u8) -> Option<usize> {
        if let Some(s) = self.slot_of(contact_id) {
            return Some(s);
        }
        let s = self.slots.iter().position(|s| s.is_none())?;
        self.slots[s] = Some(contact_id);
        Some(s)
    }
}

/// Publish one decoded PTP report to the touchpad's evdev node. Every
/// confident tip-down contact in the report becomes an MT contact —
/// including the second and later fingers the old global-ring path
/// dropped entirely. Returns the number of non-SYN evdev events
/// emitted.
pub fn pump_ptp_report_to_evdev(
    profile: &PtpProfile,
    state: &mut PtpPumpState,
    node: &DeviceNode,
    decoded: &DecodedPtpReport,
) -> usize {
    let _ = profile; // slot count + ranges were captured at caps build
    let mut updates: Vec<MtContactUpdate> = Vec::new();
    let n = (decoded.contact_count as usize).min(decoded.contacts.len());
    for c in decoded.contacts.iter().take(n) {
        let active = c.tip_switch && c.in_range && c.confidence;
        if active {
            match state.map_contact(c.contact_id) {
                Some(slot) => updates.push(MtContactUpdate {
                    slot,
                    active: true,
                    tracking_id: c.contact_id as i32,
                    x: c.x,
                    y: c.y,
                    pressure: c.pressure,
                }),
                None => continue,
            }
        } else if let Some(slot) = state.slot_of(c.contact_id) {
            updates.push(MtContactUpdate {
                slot,
                active: false,
                tracking_id: c.contact_id as i32,
                x: c.x,
                y: c.y,
                pressure: None,
            });
            state.slots[slot] = None;
        }
    }
    state
        .evdev
        .dispatch_frame(node, &updates, decoded.button1, false)
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
    // ── evdev dedup state (the global-ring path above is stateless
    // per event type; the evdev stream must be strictly edge-based) ──
    evdev_tool: Option<u16>,
    evdev_tip: bool,
    evdev_barrel: bool,
    evdev_secondary: bool,
    evdev_x: Option<i32>,
    evdev_y: Option<i32>,
    evdev_pressure: Option<i32>,
    evdev_tilt_x: Option<i32>,
    evdev_tilt_y: Option<i32>,
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
    pump_pen_report_to_evdev(state, pen, None)
}

/// [`pump_pen_report`] plus evdev publication with proper tablet
/// semantics: `BTN_TOOL_PEN`/`BTN_TOOL_RUBBER` announce the tool,
/// `BTN_TOUCH` carries the tip, `BTN_STYLUS`/`BTN_STYLUS2` the barrel
/// buttons, and X/Y/pressure/tilt ride as `EV_ABS` — one `SYN_REPORT`
/// per report that changed anything.
pub fn pump_pen_report_to_evdev(
    state: &mut PenPumpState,
    pen: &DecodedPen,
    node: Option<&DeviceNode>,
) -> usize {
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

    if let Some(node) = node {
        pushed += dispatch_pen_evdev_frame(state, pen, node);
    }

    pushed
}

/// Edge-based evdev emission for one pen report. Split out of
/// [`pump_pen_report_to_evdev`] so the global-ring translation above
/// stays byte-for-byte the path existing consumers see.
fn dispatch_pen_evdev_frame(
    state: &mut PenPumpState,
    pen: &DecodedPen,
    node: &DeviceNode,
) -> usize {
    let now = narf_time::monotonic_ns();
    let mut emitted = 0usize;
    let mut push = |type_: EventType, code: u16, value: i32| {
        node.dispatch(EvdevEvent {
            time: now,
            type_,
            code,
            value,
        });
        emitted += 1;
    };

    // Tool announcement: exactly one of PEN/RUBBER while in range.
    let tool = if pen.in_range {
        Some(if pen.eraser || pen.invert {
            evkey::BTN_TOOL_RUBBER
        } else {
            evkey::BTN_TOOL_PEN
        })
    } else {
        None
    };
    if tool != state.evdev_tool {
        if let Some(old) = state.evdev_tool {
            push(EventType::Key, old, 0);
        }
        if let Some(new) = tool {
            push(EventType::Key, new, 1);
        }
        state.evdev_tool = tool;
        // A tool change invalidates the cached axes: the next sample
        // must be reported in full for the new tool.
        state.evdev_x = None;
        state.evdev_y = None;
        state.evdev_pressure = None;
    }

    let tip = pen.in_range && pen.tip;
    if tip != state.evdev_tip {
        state.evdev_tip = tip;
        push(EventType::Key, evkey::BTN_TOUCH, if tip { 1 } else { 0 });
        if !tip {
            state.evdev_pressure = None;
        }
    }
    let barrel = pen.in_range && pen.barrel_button;
    if barrel != state.evdev_barrel {
        state.evdev_barrel = barrel;
        push(
            EventType::Key,
            evkey::BTN_STYLUS,
            if barrel { 1 } else { 0 },
        );
    }
    let secondary = pen.in_range && pen.secondary_barrel_button;
    if secondary != state.evdev_secondary {
        state.evdev_secondary = secondary;
        push(
            EventType::Key,
            evkey::BTN_STYLUS2,
            if secondary { 1 } else { 0 },
        );
    }

    if pen.in_range {
        if state.evdev_x != Some(pen.x) {
            state.evdev_x = Some(pen.x);
            push(EventType::Abs, abs::ABS_X, pen.x);
        }
        if state.evdev_y != Some(pen.y) {
            state.evdev_y = Some(pen.y);
            push(EventType::Abs, abs::ABS_Y, pen.y);
        }
        if tip {
            if let Some(p) = pen.pressure {
                if state.evdev_pressure != Some(p) {
                    state.evdev_pressure = Some(p);
                    push(EventType::Abs, abs::ABS_PRESSURE, p);
                }
            }
        }
        if let Some(t) = pen.x_tilt_deg {
            if state.evdev_tilt_x != Some(t) {
                state.evdev_tilt_x = Some(t);
                push(EventType::Abs, abs::ABS_TILT_X, t);
            }
        }
        if let Some(t) = pen.y_tilt_deg {
            if state.evdev_tilt_y != Some(t) {
                state.evdev_tilt_y = Some(t);
                push(EventType::Abs, abs::ABS_TILT_Y, t);
            }
        }
    }

    if emitted > 0 {
        node.dispatch(EvdevEvent::syn_report(now));
    }
    emitted
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

#[doc(hidden)]
pub fn __pump_report_to_evdev_for_test(
    profile: &TouchscreenProfile,
    state: &mut TouchPumpState,
    decoded: &DecodedTouchReport,
    node: &DeviceNode,
) -> usize {
    pump_report_to_evdev(profile, state, decoded, Some(node))
}

#[doc(hidden)]
pub fn __new_ptp_state_for_test(max_slots: usize) -> PtpPumpState {
    PtpPumpState::new(max_slots)
}

#[doc(hidden)]
pub fn __pump_ptp_to_evdev_for_test(
    profile: &PtpProfile,
    state: &mut PtpPumpState,
    node: &DeviceNode,
    decoded: &DecodedPtpReport,
) -> usize {
    pump_ptp_report_to_evdev(profile, state, node, decoded)
}

#[doc(hidden)]
pub fn __pump_pen_to_evdev_for_test(
    state: &mut PenPumpState,
    pen: &DecodedPen,
    node: &DeviceNode,
) -> usize {
    pump_pen_report_to_evdev(state, pen, Some(node))
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
