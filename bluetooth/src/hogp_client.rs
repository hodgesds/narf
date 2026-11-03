//! HOGP client: HID over GATT on a GATT-client (central) connection.
//!
//! Sources (public-only, no Linux source consulted):
//! - Bluetooth SIG, "HID over GATT Profile" v1.0 — the HID Service
//!   (0x1812) shape and the rule that a HOGP device exposes its
//!   reports as GATT characteristics, not as L2CAP channels.
//! - Bluetooth SIG, "HID Service" v1.0 — §3.1 HID Information layout,
//!   §3.4 Protocol Mode values (Boot 0x00, Report 0x01), §3.7
//!   Report Reference descriptor (report ID + report type).
//! - USB-IF, "Device Class Definition for HID" v1.11 — Appendix B.1
//!   (boot keyboard report: modifier byte, reserved byte, six
//!   keycodes) and Appendix B.2 (boot mouse report: button byte,
//!   X, Y). The boot layouts are the wire format this client
//!   decodes; the Report Map itself is NOT parsed here.
//! - USB-IF, "HID Usage Tables" v1.4 §10 (Keyboard / Keypad page
//!   0x07) — the Usage ID → `KeyCode` table below, transcribed
//!   from the same table the USB HID driver uses
//!   (`drivers/usb/src/hid/usage.rs`); the mapping data is
//!   spec text, not copied code.
//! - Bluetooth Core Spec Vol 3 Part G — Client Characteristic
//!   Configuration descriptor bits (bit 0 = notifications, bit 1 =
//!   indications).
//!
//! Role split: the pump's GATT *server* (peripheral role) mounts
//! the HID service via `crate::hogp::HidServiceBuilder`; this
//! client runs on central-role connections only, built from the
//! GATT client's discovery records by [`HogpClient::from_records`].
//! Notifications/indications drained from the client are routed
//! here by the pump's `hogp_route_drained` free function.
//!
//! What this client deliberately does NOT do:
//! - It does not parse the Report Map. Report-protocol input
//!   Reports are staged, undecoded, in [`HogpClient::take_undecoded`]
//!   for a later report-map-decoding lane; they are never silently
//!   dropped and never claimed decoded.
//! - It does not register an evdev DeviceNode. Routed events go to
//!   the legacy `narf_input` global rings (`push_key` /
//!   `push_global`), the same consumer path the USB HID drivers
//!   feed; evdev registration for BT HID devices is follow-up.
//! - It does not drive the HID Control Point (suspend / exit
//!   suspend) or the boot output reports (LEDs). Those value
//!   handles are exposed in [`HogpHandles`] for a later lane.

use alloc::vec::Vec;

use narf_input::{
    btn, push_global, push_key, ButtonEvent, InputEvent, KeyCode, PointerButtons, PointerEvent,
};

use crate::gatt::{
    CharacteristicRecord, DescriptorRecord, ServiceRecord, Uuid, CHAR_PROP_INDICATE,
    CHAR_PROP_NOTIFY, UUID_CCC_DESCRIPTOR, UUID_SERVICE_HID,
};
use crate::hogp::{
    BootKeyboardReport, BootMouseReport, HidInformation, ReportType,
    UUID_BOOT_KEYBOARD_INPUT_REPORT, UUID_BOOT_KEYBOARD_OUTPUT_REPORT,
    UUID_BOOT_MOUSE_INPUT_REPORT, UUID_HID_CONTROL_POINT, UUID_HID_INFORMATION, UUID_PROTOCOL_MODE,
    UUID_REPORT, UUID_REPORT_MAP, UUID_REPORT_REFERENCE,
};

/// One discovered Report characteristic: where its values arrive,
/// where its Report Reference lives, and — once the caller has read
/// the reference — how to label staged payloads. The ID and type
/// start unresolved: Find Information discovery yields descriptor
/// handles and UUIDs, not values, so the 0x2908 payload itself
/// must be read (via [`HogpClient::note_read`]) before the entry
/// can route anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidReportHandle {
    /// Value handle notifications/indications arrive on.
    pub value_handle: u16,
    /// CCCD handle to write for subscription, if the peer exposes one.
    pub cccd_handle: Option<u16>,
    /// Report Reference descriptor handle, for the resolving read.
    pub report_reference_handle: Option<u16>,
    /// Report ID from the Report Reference descriptor, once read.
    pub report_id: Option<u8>,
    /// Report type from the Report Reference descriptor, once read.
    pub report_type: Option<ReportType>,
}

/// Discovered HID service layout. Handles are the caller's
/// vocabulary for reads (HID Information, Report Map), the
/// Protocol Mode write, and CCCD subscriptions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HogpHandles {
    /// HID service declaration handle range.
    pub service_start: u16,
    pub service_end: u16,
    /// HID Information value handle (mandatory).
    pub hid_info: u16,
    /// Report Map value handle (mandatory).
    pub report_map: u16,
    /// HID Control Point value handle (mandatory).
    pub control_point: u16,
    /// Protocol Mode value handle, when the peer exposes one.
    pub protocol_mode: Option<u16>,
    /// Boot Keyboard Input Report value handle, when present.
    pub boot_keyboard_input: Option<u16>,
    /// Boot Keyboard Output Report value handle, when present.
    pub boot_keyboard_output: Option<u16>,
    /// Boot Mouse Input Report value handle, when present.
    pub boot_mouse_input: Option<u16>,
    /// Generic Report characteristics (report protocol).
    pub reports: Vec<HidReportHandle>,
    /// CCCD subscription targets, computed at discovery time from
    /// characteristic properties and CCCD handles: (cccd handle,
    /// notify?). Covers the boot input reports and every Report
    /// characteristic with a CCCD. NOTIFY wins when a
    /// characteristic offers both NOTIFY and INDICATE; a
    /// characteristic offering neither is not subscribable and
    /// contributes no target. Subscription does not depend on
    /// Report Reference resolution — only routing does.
    pub subscribe_targets: Vec<(u16, bool)>,
}

/// HOGP client state for one central-role connection.
///
/// Built once from discovery records; the pump then drives it with
/// reads (via [`HogpClient::note_read`]), the Protocol Mode write,
/// CCCD subscriptions, and drained notifications
/// ([`HogpClient::route`]).
#[derive(Debug)]
pub struct HogpClient {
    handles: HogpHandles,
    hid_info: Option<HidInformation>,
    report_map: Vec<u8>,
    boot_mode: bool,
    /// Last boot keyboard report, for press/release diffing.
    /// Starts all-zero, so the first report after connect diffs
    /// against "nothing pressed" — the same choice the USB boot
    /// keyboard driver makes.
    prev_kbd: BootKeyboardReport,
    /// Last boot mouse button byte, for press/release diffing.
    prev_mouse_buttons: u8,
    /// Report-protocol input Reports, staged undecoded:
    /// (report ID, raw value). Drained by [`HogpClient::take_undecoded`].
    undecoded: Vec<(u8, Vec<u8>)>,
}

impl HogpClient {
    /// Build a client from GATT discovery records. Returns `None`
    /// when no HID service (0x1812) is present, or when any of the
    /// three mandatory characteristics (HID Information, Report
    /// Map, HID Control Point) is missing — a peer that far from
    /// the HOGP shape is not a usable HID device.
    ///
    /// Descriptor association follows standard GATT layout: a
    /// descriptor belongs to the characteristic whose value handle
    /// precedes it, up to the next characteristic declaration (or
    /// the service end). Report entries are created with their
    /// ID/type unresolved — the 0x2908 value is read later via
    /// [`HogpClient::note_read`] — and route nothing until
    /// resolved (fail closed: an unidentified report cannot be
    /// labelled).
    pub fn from_records(
        services: &[ServiceRecord],
        characteristics: &[CharacteristicRecord],
        descriptors: &[DescriptorRecord],
    ) -> Option<Self> {
        let svc = services
            .iter()
            .find(|s| s.uuid == Uuid::U16(UUID_SERVICE_HID))?;
        let mut chars: Vec<&CharacteristicRecord> = characteristics
            .iter()
            .filter(|c| {
                c.declaration_handle >= svc.start_handle && c.declaration_handle <= svc.end_handle
            })
            .collect();
        chars.sort_by_key(|c| c.declaration_handle);
        let find = |uuid: u16| chars.iter().find(|c| c.uuid == Uuid::U16(uuid));
        let hid_info = find(UUID_HID_INFORMATION)?.value_handle;
        let report_map = find(UUID_REPORT_MAP)?.value_handle;
        let control_point = find(UUID_HID_CONTROL_POINT)?.value_handle;
        let protocol_mode = find(UUID_PROTOCOL_MODE).map(|c| c.value_handle);
        let boot_keyboard_input = find(UUID_BOOT_KEYBOARD_INPUT_REPORT).map(|c| c.value_handle);
        let boot_keyboard_output = find(UUID_BOOT_KEYBOARD_OUTPUT_REPORT).map(|c| c.value_handle);
        let boot_mouse_input = find(UUID_BOOT_MOUSE_INPUT_REPORT).map(|c| c.value_handle);

        // Descriptors owned by characteristic `i` sit strictly
        // between its value handle and the next declaration (or
        // the service end for the last characteristic).
        let window = |i: usize| -> (u16, u16) {
            let c = chars[i];
            let next = chars
                .get(i + 1)
                .map(|n| n.declaration_handle)
                .unwrap_or(svc.end_handle + 1);
            (c.value_handle, next)
        };
        let descriptor_in = |i: usize, uuid: u16| -> Option<u16> {
            let (lo, hi) = window(i);
            descriptors
                .iter()
                .find(|d| d.handle > lo && d.handle < hi && d.uuid == Uuid::U16(uuid))
                .map(|d| d.handle)
        };
        // Subscription targets: a characteristic's CCCD (from its
        // descriptor window) paired with NOTIFY-wins-over-INDICATE
        // from its properties. Boot inputs and Report
        // characteristics alike.
        let mut subscribe_targets = Vec::new();
        let mut sub_for = |i: usize| {
            let props = chars[i].properties;
            if let Some(cccd) = descriptor_in(i, UUID_CCC_DESCRIPTOR) {
                if props & CHAR_PROP_NOTIFY != 0 {
                    subscribe_targets.push((cccd, true));
                } else if props & CHAR_PROP_INDICATE != 0 {
                    subscribe_targets.push((cccd, false));
                }
            }
        };
        for (i, c) in chars.iter().enumerate() {
            if c.uuid == Uuid::U16(UUID_BOOT_KEYBOARD_INPUT_REPORT)
                || c.uuid == Uuid::U16(UUID_BOOT_MOUSE_INPUT_REPORT)
                || c.uuid == Uuid::U16(UUID_REPORT)
            {
                sub_for(i);
            }
        }
        // Report entries: CCCD and Report Reference handles come
        // from discovery; ID and type resolve later via note_read
        // of the 0x2908 value, never guessed here.
        let mut reports = Vec::new();
        for (i, c) in chars.iter().enumerate() {
            if c.uuid != Uuid::U16(UUID_REPORT) {
                continue;
            }
            reports.push(HidReportHandle {
                value_handle: c.value_handle,
                cccd_handle: descriptor_in(i, UUID_CCC_DESCRIPTOR),
                report_reference_handle: descriptor_in(i, UUID_REPORT_REFERENCE),
                report_id: None,
                report_type: None,
            });
        }

        Some(Self {
            handles: HogpHandles {
                service_start: svc.start_handle,
                service_end: svc.end_handle,
                hid_info,
                report_map,
                control_point,
                protocol_mode,
                boot_keyboard_input,
                boot_keyboard_output,
                boot_mouse_input,
                reports,
                subscribe_targets,
            },
            hid_info: None,
            report_map: Vec::new(),
            boot_mode: false,
            prev_kbd: BootKeyboardReport::default(),
            prev_mouse_buttons: 0,
            undecoded: Vec::new(),
        })
    }

    /// Discovered handle layout.
    pub fn handles(&self) -> &HogpHandles {
        &self.handles
    }

    /// Last decoded HID Information value, once read.
    pub fn hid_info(&self) -> Option<HidInformation> {
        self.hid_info
    }

    /// Last Report Map bytes read from the peer.
    pub fn report_map(&self) -> &[u8] {
        &self.report_map
    }

    /// Whether the client has been told boot protocol was selected
    /// (the Protocol Mode write was issued). Starts false (Report
    /// protocol is the HID Service default); the pump sets it via
    /// [`HogpClient::note_boot_mode`] after a successful write.
    pub fn boot_mode(&self) -> bool {
        self.boot_mode
    }

    /// Record that the Protocol Mode write completed.
    pub fn note_boot_mode(&mut self) {
        self.boot_mode = true;
    }

    /// Feed a characteristic or descriptor read back into the
    /// client. Consumed handles: HID Information (decoded),
    /// Report Map (stored raw), and any Report Reference
    /// descriptor (resolves that Report entry's ID and type).
    /// Other handles return false and are ignored. Returns true
    /// when the value was consumed.
    pub fn note_read(&mut self, handle: u16, value: &[u8]) -> bool {
        if handle == self.handles.hid_info {
            if let Ok(bytes) = <[u8; 4]>::try_from(value) {
                self.hid_info = Some(HidInformation::decode(&bytes));
                return true;
            }
            return false;
        }
        if handle == self.handles.report_map {
            self.report_map = value.to_vec();
            return true;
        }
        // Report Reference descriptor reads resolve their entry:
        // the first well-formed resolution wins; malformed values
        // (short, or an unknown report type) are rejected.
        let idx = self
            .handles
            .reports
            .iter()
            .position(|r| r.report_reference_handle == Some(handle));
        match idx {
            Some(i) => {
                let r = &mut self.handles.reports[i];
                if r.report_id.is_some() || value.len() < 2 {
                    return false;
                }
                let report_type = match value[1] {
                    0x01 => ReportType::Input,
                    0x02 => ReportType::Output,
                    0x03 => ReportType::Feature,
                    _ => return false,
                };
                r.report_id = Some(value[0]);
                r.report_type = Some(report_type);
                true
            }
            None => false,
        }
    }

    /// The Protocol Mode write that selects boot protocol, if the
    /// peer exposes Protocol Mode: (value handle, `[BOOT 0x00]`).
    /// Returns `None` when there is no Protocol Mode characteristic
    /// (a report-only device); the caller then stays in report
    /// protocol and only the staging queue applies.
    pub fn protocol_mode_write(&self) -> Option<(u16, [u8; 1])> {
        self.handles.protocol_mode.map(|h| (h, [0x00]))
    }

    /// CCCD subscription targets, computed at discovery time:
    /// (cccd handle, notify?). Covers the boot input reports and
    /// every Report characteristic with a CCCD. The caller issues
    /// one GATT-client subscribe per target.
    pub fn subscribe_targets(&self) -> &[(u16, bool)] {
        &self.handles.subscribe_targets
    }

    /// Route one drained notification/indication payload to the
    /// input subsystem. Returns the number of input events pushed
    /// (0 for unrecognised handles, malformed reports, and staged
    /// report-protocol payloads — staging is not an input event).
    pub fn route(&mut self, handle: u16, value: &[u8]) -> usize {
        if Some(handle) == self.handles.boot_keyboard_input {
            return self.route_boot_keyboard(value);
        }
        if Some(handle) == self.handles.boot_mouse_input {
            return self.route_boot_mouse(value);
        }
        // Only resolved input Reports stage: an unresolved entry
        // has no ID to label the payload with, and output/feature
        // reports are not input. (subscribe_targets never yields
        // an unsubscribable target, so an unresolved payload here
        // means an unsolicited peer notification — dropping it is
        // fail-closed, not data loss on a subscribed stream.)
        if let Some(r) = self.handles.reports.iter().find(|r| {
            r.value_handle == handle
                && r.report_type == Some(ReportType::Input)
                && r.report_id.is_some()
        }) {
            let id = r.report_id.unwrap_or(0);
            self.undecoded.push((id, value.to_vec()));
        }
        0
    }

    /// Drain staged report-protocol input Reports.
    pub fn take_undecoded(&mut self) -> Vec<(u8, Vec<u8>)> {
        core::mem::take(&mut self.undecoded)
    }

    /// Boot keyboard diff: modifier-byte transitions, then
    /// keycode-array transitions, mirroring the USB boot keyboard
    /// driver's diff semantics. Rollover (all six slots 0x01)
    /// suppresses keycode events — the slots are phantom state,
    /// not keys — while modifier transitions still apply.
    /// Usages 0x00 (empty), 0x01..=0x03 (error / post-fail /
    /// undefined), and 0xE0..=0xE7 (modifier-byte equivalents,
    /// already covered by the modifier byte) are filtered from
    /// the keycode diff. Out-of-table usages still emit
    /// `KeyCode::Unknown` events, per the USB table's contract.
    fn route_boot_keyboard(&mut self, value: &[u8]) -> usize {
        let Ok(bytes) = <[u8; 8]>::try_from(value) else {
            return 0;
        };
        let report = BootKeyboardReport::decode(&bytes);
        let mut pushed = 0usize;
        // Modifier byte, bit order (HID 1.11 B.1): LCtrl, LShift,
        // LAlt, LGUI, RCtrl, RShift, RAlt, RGUI.
        const MODS: [(u8, KeyCode); 8] = [
            (1 << 0, KeyCode::LeftCtrl),
            (1 << 1, KeyCode::LeftShift),
            (1 << 2, KeyCode::LeftAlt),
            (1 << 3, KeyCode::LeftMeta),
            (1 << 4, KeyCode::RightCtrl),
            (1 << 5, KeyCode::RightShift),
            (1 << 6, KeyCode::RightAlt),
            (1 << 7, KeyCode::RightMeta),
        ];
        let prev_mods = self.prev_kbd.modifiers;
        for (mask, code) in MODS {
            let was = prev_mods & mask != 0;
            let now = report.modifiers & mask != 0;
            if was != now && push_key(code, now) {
                pushed += 1;
            }
        }
        let rollover = report.keycodes.iter().all(|&k| k == 0x01);
        if !rollover {
            let prev = self.prev_kbd.keycodes;
            for &usage in prev.iter() {
                if usage_is_key(usage)
                    && !report.keycodes.contains(&usage)
                    && push_key(usage_to_keycode(usage), false)
                {
                    pushed += 1;
                }
            }
            for &usage in report.keycodes.iter() {
                if usage_is_key(usage)
                    && !prev.contains(&usage)
                    && push_key(usage_to_keycode(usage), true)
                {
                    pushed += 1;
                }
            }
            self.prev_kbd = report;
        } else {
            // Keep the last real keycode state; only modifiers move.
            self.prev_kbd.modifiers = report.modifiers;
        }
        pushed
    }

    /// Boot mouse diff, mirroring the USB boot mouse driver: a
    /// PointerEvent (with the current button state) on any change,
    /// plus one ButtonEvent per changed button bit.
    fn route_boot_mouse(&mut self, value: &[u8]) -> usize {
        if value.len() < 3 {
            return 0;
        }
        let report = BootMouseReport::decode(&[value[0], value[1], value[2]]);
        let prev = self.prev_mouse_buttons;
        let cur = report.buttons & 0x07;
        let mut pushed = 0usize;
        const BUTTONS: [(u8, u16, PointerButtons); 3] = [
            (1 << 0, btn::BTN_LEFT, PointerButtons::LEFT),
            (1 << 1, btn::BTN_RIGHT, PointerButtons::RIGHT),
            (1 << 2, btn::BTN_MIDDLE, PointerButtons::MIDDLE),
        ];
        let mut btns = PointerButtons::EMPTY;
        for (mask, _, flag) in BUTTONS {
            if cur & mask != 0 {
                btns |= flag;
            }
        }
        let moved = report.dx != 0 || report.dy != 0;
        if (cur != prev || moved)
            && push_global(InputEvent::Pointer(PointerEvent {
                dx: report.dx as i32,
                dy: report.dy as i32,
                buttons: btns,
            }))
        {
            pushed += 1;
        }
        for (mask, code, _) in BUTTONS {
            let was = prev & mask != 0;
            let now = cur & mask != 0;
            if was != now && push_global(InputEvent::Button(ButtonEvent { code, pressed: now })) {
                pushed += 1;
            }
        }
        self.prev_mouse_buttons = cur;
        pushed
    }
}

/// Keycode-array usages that denote real keys. Filters 0x00
/// (empty), 0x01..=0x03 (error roll-over / post-fail / undefined),
/// and 0xE0..=0xE7 (modifier-byte equivalents).
fn usage_is_key(usage: u8) -> bool {
    usage >= 0x04 && !(0xE0..=0xE7).contains(&usage)
}

/// HID Usage Page 0x07 (Keyboard / Keypad) → `KeyCode`.
///
/// Reference: USB-IF "HID Usage Tables" 1.4 §10. Transcribed from
/// the same table the USB HID driver uses; out-of-table Usage IDs
/// return `KeyCode::Unknown` so the caller can still emit
/// press/release events without dropping the input.
pub const fn usage_to_keycode(usage: u8) -> KeyCode {
    match usage {
        0x04 => KeyCode::A,
        0x05 => KeyCode::B,
        0x06 => KeyCode::C,
        0x07 => KeyCode::D,
        0x08 => KeyCode::E,
        0x09 => KeyCode::F,
        0x0A => KeyCode::G,
        0x0B => KeyCode::H,
        0x0C => KeyCode::I,
        0x0D => KeyCode::J,
        0x0E => KeyCode::K,
        0x0F => KeyCode::L,
        0x10 => KeyCode::M,
        0x11 => KeyCode::N,
        0x12 => KeyCode::O,
        0x13 => KeyCode::P,
        0x14 => KeyCode::Q,
        0x15 => KeyCode::R,
        0x16 => KeyCode::S,
        0x17 => KeyCode::T,
        0x18 => KeyCode::U,
        0x19 => KeyCode::V,
        0x1A => KeyCode::W,
        0x1B => KeyCode::X,
        0x1C => KeyCode::Y,
        0x1D => KeyCode::Z,

        0x1E => KeyCode::Key1,
        0x1F => KeyCode::Key2,
        0x20 => KeyCode::Key3,
        0x21 => KeyCode::Key4,
        0x22 => KeyCode::Key5,
        0x23 => KeyCode::Key6,
        0x24 => KeyCode::Key7,
        0x25 => KeyCode::Key8,
        0x26 => KeyCode::Key9,
        0x27 => KeyCode::Key0,

        0x28 => KeyCode::Enter,
        0x29 => KeyCode::Escape,
        0x2A => KeyCode::Backspace,
        0x2B => KeyCode::Tab,
        0x2C => KeyCode::Space,
        0x2D => KeyCode::Minus,
        0x2E => KeyCode::Equal,
        0x2F => KeyCode::LeftBrace,
        0x30 => KeyCode::RightBrace,
        0x31 => KeyCode::Backslash,
        // 0x32 (non-US #) maps to Backslash on US layouts.
        0x32 => KeyCode::Backslash,
        0x33 => KeyCode::Semicolon,
        0x34 => KeyCode::Apostrophe,
        0x35 => KeyCode::Grave,
        0x36 => KeyCode::Comma,
        0x37 => KeyCode::Dot,
        0x38 => KeyCode::Slash,
        0x39 => KeyCode::CapsLock,

        0x3A => KeyCode::F1,
        0x3B => KeyCode::F2,
        0x3C => KeyCode::F3,
        0x3D => KeyCode::F4,
        0x3E => KeyCode::F5,
        0x3F => KeyCode::F6,
        0x40 => KeyCode::F7,
        0x41 => KeyCode::F8,
        0x42 => KeyCode::F9,
        0x43 => KeyCode::F10,
        0x44 => KeyCode::F11,
        0x45 => KeyCode::F12,

        0x46 => KeyCode::SysRq, // PrintScreen
        0x47 => KeyCode::ScrollLock,
        0x48 => KeyCode::Pause,
        0x49 => KeyCode::Insert,
        0x4A => KeyCode::Home,
        0x4B => KeyCode::PageUp,
        0x4C => KeyCode::Delete,
        0x4D => KeyCode::End,
        0x4E => KeyCode::PageDown,
        0x4F => KeyCode::Right,
        0x50 => KeyCode::Left,
        0x51 => KeyCode::Down,
        0x52 => KeyCode::Up,

        0x53 => KeyCode::NumLock,
        0x54 => KeyCode::KpSlash,
        0x55 => KeyCode::KpAsterisk,
        0x56 => KeyCode::KpMinus,
        0x57 => KeyCode::KpPlus,
        0x58 => KeyCode::KpEnter,
        0x59 => KeyCode::Kp1,
        0x5A => KeyCode::Kp2,
        0x5B => KeyCode::Kp3,
        0x5C => KeyCode::Kp4,
        0x5D => KeyCode::Kp5,
        0x5E => KeyCode::Kp6,
        0x5F => KeyCode::Kp7,
        0x60 => KeyCode::Kp8,
        0x61 => KeyCode::Kp9,
        0x62 => KeyCode::Kp0,
        0x63 => KeyCode::KpDot,

        // 0x64 (non-US \) maps to Backslash on US layouts.
        0x64 => KeyCode::Backslash,
        0x65 => KeyCode::Menu, // Application / Compose

        0xE0 => KeyCode::LeftCtrl,
        0xE1 => KeyCode::LeftShift,
        0xE2 => KeyCode::LeftAlt,
        0xE3 => KeyCode::LeftMeta,
        0xE4 => KeyCode::RightCtrl,
        0xE5 => KeyCode::RightShift,
        0xE6 => KeyCode::RightAlt,
        0xE7 => KeyCode::RightMeta,

        _ => KeyCode::Unknown,
    }
}
