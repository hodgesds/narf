//! USB HID — Human Interface Device — clean-room.
//!
//! ## Reference
//!
//! - "Device Class Definition for Human Interface Devices (HID)"
//!   Version 1.11, 27 June 2001. Public document, usb.org. Section
//!   numbers below (`§7.x`) refer to that spec.
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - "Universal Serial Bus HID Usage Tables" 1.4 — for the keyboard
//!   usage page values (page 0x07).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//!
//! ## Scope
//!
//! HID *boot keyboard* protocol (§B.1) — the fixed 8-byte report
//! every HID-class keyboard supports out-of-reset:
//!
//! ```text
//!   byte 0 : modifier mask (LCtrl/LShift/LAlt/LGUI/RCtrl/RShift/RAlt/RGUI)
//!   byte 1 : reserved
//!   byte 2..7 : up to 6 simultaneously-pressed scancodes (HID Usage IDs)
//! ```
//!
//! Setting boot protocol is one Set Protocol class request (§7.2.6);
//! after that the kernel polls the interrupt-IN endpoint and gets
//! 8-byte reports.
//!
//! Pipeline:
//!   1. `enumerate_and_attach_keyboards` — walks every connected
//!      port, addresses + configures each device, and binds any HID
//!      Boot-Keyboard interface it finds. Runs as the
//!      `usb-hid-keyboard` Stage::Device initcall.
//!   2. `pump_all` — polls each bound keyboard once, diffs the new
//!      report against the previous one, and emits press/release
//!      `KeyEvent`s onto the `narf_input` global event ring.
//!   3. The `usage` submodule maps HID Usage Page 0x07 IDs onto
//!      `narf_input::KeyCode`. Coverage: every key a Boot-Protocol
//!      keyboard can emit — letters, digits, modifiers, F1-F12,
//!      navigation cluster, full numpad, GUI / Application keys.

use crate::xhci::{self, EndpointConfig, EndpointKind, Xhci};
use narf_input::{push_global, InputEvent, KeyCode, KeyEvent, Modifiers};
use narf_lib::sync::IrqSafeSpinLock;

extern crate alloc;
use alloc::vec::Vec;

pub mod usage;
pub use usage::usage_to_keycode;

/// USB Interface Class for HID.
pub const HID_INTERFACE_CLASS: u8 = 0x03;
/// HID Subclass: 1 = Boot Interface (keyboard / mouse).
pub const HID_SUBCLASS_BOOT: u8 = 0x01;
/// HID Boot Protocol: 1 = Keyboard, 2 = Mouse (§4.3).
pub const HID_PROTOCOL_KBD: u8 = 0x01;

// Class-specific request codes from §7.2.
pub(crate) const HID_REQ_SET_PROTOCOL: u8 = 0x0B;
pub(crate) const HID_REQ_SET_IDLE: u8 = 0x0A;
/// Boot protocol value (vs. 1 = Report Protocol).
pub(crate) const HID_BOOT_PROTOCOL: u16 = 0;
// Standard request code (USB 2.0 §9.4 table 9-4) for
// SET_CONFIGURATION. Standard requests other than this aren't
// needed in this driver, so we don't pull in a full enum.
pub(crate) const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

pub mod mouse;
pub mod touchpad;

/// Modifier mask bits in byte 0 of the boot keyboard report.
pub mod kbd_mod {
    pub const LCTRL: u8 = 1 << 0;
    pub const LSHIFT: u8 = 1 << 1;
    pub const LALT: u8 = 1 << 2;
    pub const LGUI: u8 = 1 << 3;
    pub const RCTRL: u8 = 1 << 4;
    pub const RSHIFT: u8 = 1 << 5;
    pub const RALT: u8 = 1 << 6;
    pub const RGUI: u8 = 1 << 7;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HidError {
    /// Device's interface descriptor didn't expose HID boot keyboard.
    NotBootKeyboard,
    /// Configuration descriptor didn't carry an Interrupt-IN endpoint.
    NoInterruptIn,
    /// `set_boot_protocol` failed (control transfer error).
    SetProtocolFailed,
    /// Underlying xHCI error.
    Xhci(xhci::XhciError),
}

impl From<xhci::XhciError> for HidError {
    fn from(e: xhci::XhciError) -> Self {
        HidError::Xhci(e)
    }
}

/// Decoded boot-keyboard report (§B.1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct KbdReport {
    pub modifiers: u8,
    pub keys: [u8; 6],
}

impl KbdReport {
    /// Construct a report from the 8-byte wire format. Byte 1 is
    /// reserved per spec — we discard it.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            modifiers: b[0],
            keys: [b[2], b[3], b[4], b[5], b[6], b[7]],
        }
    }
    /// `true` if the given HID Usage ID appears in the key array.
    pub fn pressed(&self, usage: u8) -> bool {
        self.keys.iter().any(|&k| k == usage)
    }
}

/// Boot-keyboard binding. Holds the slot id + interrupt-IN DCI;
/// caller polls via `read_report` (raw 8-byte report) or
/// `pump_once` (decoded → global input ring).
#[derive(Debug)]
pub struct BootKeyboard {
    pub slot_id: u8,
    pub interrupt_in_ep: u8, // DCI of the interrupt-IN endpoint
    pub interface_num: u8,
    /// Last report seen, used for press/release diffing in
    /// `pump_once`. Initialised to the all-zero report so the
    /// first non-empty poll fires presses for every key in it.
    pub(crate) last_report: KbdReport,
}

/// Walk a Configuration Descriptor (§9.6.3) tree looking for a HID
/// Boot Keyboard interface and its single interrupt-IN endpoint.
/// Returns `(interface_num, ep_config)` for the caller to feed into
/// `xhci::configure_endpoints`.
pub fn find_boot_keyboard(cfg: &[u8]) -> Result<(u8, EndpointConfig), HidError> {
    let mut i = 0usize;
    let mut in_match = false;
    let mut iface_num: u8 = 0;
    let mut int_in: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (§9.6.5).
            //   +2 bInterfaceNumber
            //   +5 bInterfaceClass
            //   +6 bInterfaceSubClass
            //   +7 bInterfaceProtocol
            4 if len >= 9 => {
                // Audit F-72: don't require bInterfaceSubClass == Boot.
                // Many modern internal laptop keyboards report Subclass=0
                // (no boot interface) even though they accept
                // SET_PROTOCOL(Boot) and emit boot-format reports. A
                // strict Boot-only match silently dropped them. We
                // still gate on bInterfaceProtocol == 1 (Keyboard) so
                // the bind targets only kbd-shaped interfaces; the
                // attach step issues SET_PROTOCOL(Boot) and abandons
                // on STALL, so non-boot-capable devices fall through
                // gracefully.
                in_match = cfg[i + 5] == HID_INTERFACE_CLASS
                    && (cfg[i + 6] == HID_SUBCLASS_BOOT || cfg[i + 6] == 0)
                    && cfg[i + 7] == HID_PROTOCOL_KBD;
                if in_match {
                    iface_num = cfg[i + 2];
                }
            }
            // Endpoint Descriptor (§9.6.6).
            //   +2 bEndpointAddress (bit 7 = IN)
            //   +3 bmAttributes (bits[1:0] = transfer type; 3 = interrupt)
            //   +4..=5 wMaxPacketSize
            5 if len >= 7 && in_match && int_in.is_none() => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
                if xfer_t == 3 && is_in {
                    int_in = Some(EndpointConfig {
                        ep_addr,
                        max_packet: mps,
                        kind: EndpointKind::InterruptIn,
                    });
                }
            }
            _ => {}
        }
        i += len;
    }
    match int_in {
        Some(ep) => Ok((iface_num, ep)),
        None => Err(HidError::NoInterruptIn),
    }
}

impl BootKeyboard {
    /// Bind a boot keyboard to an already-addressed + configured
    /// xHCI slot. Issues `Set Protocol(Boot)` so subsequent
    /// `read_report` calls return the fixed 8-byte format.
    pub fn attach(
        xhci_dev: &Xhci,
        slot_id: u8,
        interface_num: u8,
        interrupt_in_ep: u8,
    ) -> Result<Self, HidError> {
        // Set Protocol class request (§7.2.6):
        //   bmRequestType: 0x21 (Class | Interface | Host-to-Device)
        //   bRequest: SET_PROTOCOL
        //   wValue: 0 (Boot protocol)
        //   wIndex: interface number
        //   wLength: 0
        let mut nothing = [0u8; 0];
        xhci_dev
            .control_in(
                slot_id,
                0x21,
                HID_REQ_SET_PROTOCOL,
                HID_BOOT_PROTOCOL,
                interface_num as u16,
                &mut nothing,
            )
            .map_err(|_| HidError::SetProtocolFailed)?;
        // SET_IDLE(duration=0, reportID=0) — HID §7.2.4. Tells
        // the device "only send a report on state change", which
        // is what we want for a polled-pump keyboard. Many
        // BIOS-flashed keyboards will silently suppress reports
        // until SET_IDLE has been issued at least once. Failure
        // here is non-fatal (some devices STALL because they
        // don't implement the request); SET_PROTOCOL was the
        // load-bearing call.
        let _ = xhci_dev.control_in(
            slot_id,
            0x21,
            HID_REQ_SET_IDLE,
            0, // (duration<<8) | reportID — both zero
            interface_num as u16,
            &mut nothing,
        );
        // Pre-arm the interrupt-IN endpoint with one Normal TRB so
        // the controller starts polling the device immediately. The
        // first state-change report from the device completes that
        // TRB and posts a Transfer Event; our `pump_once` consumes
        // the event + restages a fresh TRB. Without this the device
        // never sees a token from the host and never produces any
        // input report.
        xhci_dev
            .arm_interrupt_in(slot_id, interrupt_in_ep, 8)
            .map_err(HidError::Xhci)?;
        Ok(BootKeyboard {
            slot_id,
            interrupt_in_ep,
            interface_num,
            last_report: KbdReport::default(),
        })
    }

    /// Drain any pending interrupt-IN report. Returns
    /// `Ok(Some(report))` if the device produced a state-change
    /// report since the last poll, `Ok(None)` if no report has
    /// arrived yet (the controller is still waiting on the device's
    /// next interrupt-IN response). Non-blocking: returns
    /// immediately. The caller drives cadence via `wait_for_irq`.
    pub fn read_report(&self, xhci_dev: &Xhci) -> Result<Option<KbdReport>, HidError> {
        let mut buf = [0u8; 8];
        match xhci_dev
            .poll_interrupt_in(self.slot_id, self.interrupt_in_ep, &mut buf)
            .map_err(HidError::Xhci)?
        {
            Some(_) => {
                REPORTS_READ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                Ok(Some(KbdReport::from_bytes(buf)))
            }
            None => Ok(None),
        }
    }

    /// Drain all pending reports and push press/release events to the
    /// global input ring. Returns the number of events emitted across
    /// however many reports arrived since the last call. Non-blocking
    /// (zero or more reports per call).
    pub fn pump_once(&mut self, xhci_dev: &Xhci) -> Result<usize, HidError> {
        let mut total = 0usize;
        while let Some(report) = self.read_report(xhci_dev)? {
            total += self.translate_report(report);
        }
        Ok(total)
    }

    /// Same diff logic as `pump_once`, but works from a caller-
    /// supplied report. Used by both the live pump and the
    /// in-tree smokes.
    pub fn translate_report(&mut self, report: KbdReport) -> usize {
        let n = translate_diff(&self.last_report, &report);
        self.last_report = report;
        n
    }

    /// Reset the diff baseline — the next report is treated as if
    /// no keys were previously pressed. Useful after re-attach.
    pub fn reset_diff(&mut self) {
        self.last_report = KbdReport::default();
    }
}

/// Decode the HID modifier byte (boot report byte 0) into a
/// `narf_input::Modifiers` set. CapsLock / NumLock / ScrollLock
/// aren't in the modifier byte (they're regular keys with their
/// own Usage IDs); only the eight Ctrl/Shift/Alt/GUI live there.
pub fn modifier_byte_to_modifiers(byte: u8) -> Modifiers {
    let mut m = Modifiers::from_bits_truncate(0);
    if byte & (kbd_mod::LCTRL | kbd_mod::RCTRL) != 0 {
        m.insert(Modifiers::CTRL);
    }
    if byte & (kbd_mod::LSHIFT | kbd_mod::RSHIFT) != 0 {
        m.insert(Modifiers::SHIFT);
    }
    if byte & (kbd_mod::LALT | kbd_mod::RALT) != 0 {
        m.insert(Modifiers::ALT);
    }
    if byte & (kbd_mod::LGUI | kbd_mod::RGUI) != 0 {
        m.insert(Modifiers::META);
    }
    m
}

/// Walk two consecutive boot-keyboard reports and emit press /
/// release `KeyEvent`s onto the global input ring. Returns the
/// number of events pushed.
fn translate_diff(prev: &KbdReport, cur: &KbdReport) -> usize {
    let cur_mods = modifier_byte_to_modifiers(cur.modifiers);
    let mut emitted = 0usize;

    // Modifier-byte transitions: bit-by-bit. Each bit corresponds
    // to a dedicated KeyCode (LCtrl / LShift / LAlt / LGui / ...).
    let mod_pairs: &[(u8, KeyCode)] = &[
        (kbd_mod::LCTRL, KeyCode::LeftCtrl),
        (kbd_mod::LSHIFT, KeyCode::LeftShift),
        (kbd_mod::LALT, KeyCode::LeftAlt),
        (kbd_mod::LGUI, KeyCode::LeftMeta),
        (kbd_mod::RCTRL, KeyCode::RightCtrl),
        (kbd_mod::RSHIFT, KeyCode::RightShift),
        (kbd_mod::RALT, KeyCode::RightAlt),
        (kbd_mod::RGUI, KeyCode::RightMeta),
    ];
    for &(bit, code) in mod_pairs {
        let was = prev.modifiers & bit != 0;
        let now = cur.modifiers & bit != 0;
        if was != now {
            push_global(InputEvent::Key(KeyEvent {
                code,
                pressed: now,
                modifiers: cur_mods,
            }));
            emitted += 1;
        }
    }

    // Roll-over indicator: a HID keyboard signals "more than 6
    // keys held" by writing 0x01 into all six positions. Don't
    // emit anything for those.
    let is_rollover = cur.keys.iter().all(|&k| k == 0x01);

    // Usage-array transitions. Both arrays are short (<= 6
    // entries); a nested membership check is fine.
    if !is_rollover {
        // Releases: keys in prev that aren't in cur.
        for &k in &prev.keys {
            if k == 0 || k == 0x01 {
                continue;
            }
            if !cur.keys.iter().any(|&c| c == k) {
                let code = usage_to_keycode(k);
                push_global(InputEvent::Key(KeyEvent {
                    code,
                    pressed: false,
                    modifiers: cur_mods,
                }));
                emitted += 1;
            }
        }
        // Presses: keys in cur that weren't in prev.
        for &k in &cur.keys {
            if k == 0 || k == 0x01 {
                continue;
            }
            if !prev.keys.iter().any(|&p| p == k) {
                let code = usage_to_keycode(k);
                push_global(InputEvent::Key(KeyEvent {
                    code,
                    pressed: true,
                    modifiers: cur_mods,
                }));
                emitted += 1;
            }
        }
    }

    emitted
}

// ── Hot-plug enumeration ──────────────────────────────────────────

/// System-wide registry of attached HID boot keyboards. Populated
/// by `enumerate_and_attach_keyboards`; consumed by `pump_all`.
static KEYBOARDS: IrqSafeSpinLock<Vec<BootKeyboard>> = IrqSafeSpinLock::new(Vec::new());

/// Walk every connected port on the supplied controller and try to
/// bring up a HID Boot Keyboard on each one. The flow per port:
///
///   1. `port_reset`  — push the port to the Enabled state.
///   2. `enable_slot` — get a slot id from the controller.
///   3. `address_device` — assign a USB address + DCI 1 (default
///      control endpoint).
///   4. `get_config_descriptor` (header, then full tree).
///   5. `find_boot_keyboard` — locate the HID interface +
///      interrupt-IN endpoint.
///   6. `configure_endpoints` — program the interrupt-IN EP into
///      the slot's input context.
///   7. `BootKeyboard::attach` — issue Set Protocol(Boot).
///
/// Returns the number of keyboards successfully attached. Any
/// per-port failure (no connection, no HID kbd interface,
/// command failure) is logged via the count and skipped — the
/// next port is still tried.
pub fn enumerate_and_attach_keyboards(xhci_dev: &Xhci) -> usize {
    let mut attached = 0usize;
    for (port, _portsc) in xhci_dev.connected_ports() {
        if try_attach_port(xhci_dev, port).is_ok() {
            attached += 1;
        }
    }
    attached
}

/// Per-port last-failure step. Single byte per port indexed by
/// (port-1). 0 = no failure recorded. Used by `note_attach_step`
/// to dedupe log lines so the supervisor's 16-ms retry cadence
/// doesn't fill the klog ring with the same failure repeatedly.
static LAST_KBD_FAIL_STEP: [core::sync::atomic::AtomicU8; 256] = {
    use core::sync::atomic::AtomicU8;
    [const { AtomicU8::new(0) }; 256]
};

/// Counts consecutive same-step failures per port. Used by
/// `note_attach_fail` to re-emit a log line every N cycles even if
/// the step hasn't changed (audit F-83) — useful when a device is
/// genuinely stuck and a logfile reader needs the periodic signal
/// to distinguish "still failing" from "logged once and forgotten".
#[allow(dead_code)]
static KBD_FAIL_REPEATS: [core::sync::atomic::AtomicU16; 256] = {
    use core::sync::atomic::AtomicU16;
    [const { AtomicU16::new(0) }; 256]
};

/// Identifiers for each step in `try_attach_port` — used as the
/// dedup key + the symbolic name printed to klog.
#[derive(Copy, Clone)]
enum AttachStep {
    Reset = 1,
    Speed = 2,
    EnableSlot = 3,
    AddressDevice = 4,
    GetCfgHeader = 5,
    GetCfgFull = 6,
    FindBootKbd = 7,
    ConfigureEndpoints = 8,
    SetConfiguration = 9,
    SetProtocol = 10,
}

impl AttachStep {
    fn name(self) -> &'static str {
        match self {
            AttachStep::Reset => "port_reset",
            AttachStep::Speed => "port_speed",
            AttachStep::EnableSlot => "enable_slot",
            AttachStep::AddressDevice => "address_device",
            AttachStep::GetCfgHeader => "get_cfg_head",
            AttachStep::GetCfgFull => "get_cfg_full",
            AttachStep::FindBootKbd => "find_boot_kbd",
            AttachStep::ConfigureEndpoints => "configure_endpoints",
            AttachStep::SetConfiguration => "set_configuration",
            AttachStep::SetProtocol => "set_protocol",
        }
    }
}

/// Log a per-port attach failure to klog, deduped by step so a
/// stuck enumeration loop doesn't fill the ring. Resets the
/// recorded step to 0 on every successful attach so a later
/// re-failure on the same port re-emits.
fn note_attach_fail(port: u8, step: AttachStep, err: &HidError) {
    use core::fmt::Write as _;
    use core::sync::atomic::Ordering;
    // Audit F-83: emit on first occurrence of a (port, step) pair,
    // then suppress repeats for ~64 cycles so a stuck enumeration
    // loop still surfaces a periodic "still failing" beat without
    // flooding klog. The supervisor cycles ~16 ms apart on real
    // hardware, so 64 ≈ once per second.
    const REPEAT_MASK: u16 = 63;
    let prev = LAST_KBD_FAIL_STEP[port as usize].swap(step as u8, Ordering::AcqRel);
    let same_step = prev == step as u8;
    let n = if same_step {
        KBD_FAIL_REPEATS[port as usize].fetch_add(1, Ordering::AcqRel)
    } else {
        KBD_FAIL_REPEATS[port as usize].store(0, Ordering::Release);
        0
    };
    if same_step && (n & REPEAT_MASK) != 0 {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  usb-hid: kbd port={} step={} err={:?}",
        port,
        step.name(),
        err
    );
}

fn note_attach_ok(port: u8) {
    use core::fmt::Write as _;
    use core::sync::atomic::{AtomicU64, Ordering};
    let was_failing = LAST_KBD_FAIL_STEP[port as usize].swap(0, Ordering::AcqRel) != 0;
    KBD_FAIL_REPEATS[port as usize].store(0, Ordering::Release);
    // Log a one-line "attached" notification per port so a real-HW
    // boot makes it obvious that the kbd pipeline came up. Bitmask
    // dedupes against the supervisor's per-cycle re-call.
    static ATTACHED_PORTS: AtomicU64 = AtomicU64::new(0);
    let bit = 1u64 << (port as u32 & 63);
    let prev = ATTACHED_PORTS.fetch_or(bit, Ordering::AcqRel);
    if prev & bit == 0 || was_failing {
        let _ = writeln!(
            narf_console::Writer,
            "  usb-hid: kbd attached on port {}",
            port
        );
    }
}

/// Public per-port attach used by the supervisor's per-port
/// retry loop. Returns Err on any failure (no kbd here, NotBoot,
/// xHCI command failure) so the supervisor can decide whether to
/// re-try (port still connected) or move on.
pub fn try_attach_keyboard_on_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    let r = try_attach_port(xhci_dev, port);
    if r.is_ok() {
        note_attach_ok(port);
    }
    r
}

/// Hub-downstream variant: caller has already issued port_reset on
/// the hub's downstream port, allocated `slot_id` via `enable_slot`,
/// and called `address_device_with` for the topology-aware address.
/// This entry point picks up from there: GET_DESCRIPTOR + refresh
/// EP0 MPS + class match + bind. `port` is the hub's downstream
/// port number (used purely for log dedup / failure attribution —
/// not for any xHCI register access). On failure the slot is
/// disabled so the caller doesn't leak it. On success the kbd is
/// added to the global registry and `note_attach_ok` records the
/// port for one-shot logging.
pub fn try_bind_kbd_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    port: u8,
    speed: xhci::PortSpeed,
) -> Result<(), HidError> {
    let r = bind_kbd_addressed_slot(xhci_dev, slot_id, port, speed);
    if r.is_err() {
        let _ = xhci_dev.disable_slot(slot_id);
    } else {
        note_attach_ok(port);
    }
    r
}

fn try_attach_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    xhci_dev.port_reset(port).map_err(|e| {
        let err = HidError::Xhci(e);
        note_attach_fail(port, AttachStep::Reset, &err);
        err
    })?;
    let speed = xhci_dev.port_speed(port).ok_or_else(|| {
        let err = HidError::NoInterruptIn;
        note_attach_fail(port, AttachStep::Speed, &err);
        err
    })?;
    let slot_id = xhci_dev.enable_slot().map_err(|e| {
        let err = HidError::Xhci(e);
        note_attach_fail(port, AttachStep::EnableSlot, &err);
        err
    })?;
    let res = (|| -> Result<(), HidError> {
        xhci_dev.address_device(slot_id, port, speed).map_err(|e| {
            let err = HidError::Xhci(e);
            note_attach_fail(port, AttachStep::AddressDevice, &err);
            err
        })?;
        bind_kbd_addressed_slot(xhci_dev, slot_id, port, speed)
    })();
    if res.is_err() {
        // Free the slot so a retry doesn't leak xHCI device
        // contexts. AMD Renoir's MaxSlots is typically 32 and a
        // laptop with multiple internal USB devices can burn
        // through them quickly across enumeration retries.
        let _ = xhci_dev.disable_slot(slot_id);
    }
    res
}

/// Post-address kbd bind: assumes the caller has already issued
/// port_reset / enable_slot / address_device(_with). Does the
/// device + config descriptor walk, EP0-MPS refresh, kbd interface
/// match, configure_endpoints, SET_CONFIGURATION, SET_PROTOCOL,
/// arm_interrupt_in, and registry push. Does NOT call disable_slot
/// on failure — caller's cleanup_guard handles that.
fn bind_kbd_addressed_slot(
    xhci_dev: &Xhci,
    slot_id: u8,
    port: u8,
    speed: xhci::PortSpeed,
) -> Result<(), HidError> {
        // GET_DESCRIPTOR(DEVICE) and refresh EP0 MaxPacketSize via
        // Evaluate Context if the device's real bMaxPacketSize0
        // differs from the speed-default we programmed at Address
        // Device time (audit F-22 + F-23). This matters for full-
        // speed devices (we initially seed MPS=8 — the smallest
        // legal — and most FS devices are actually 8/16/32/64).
        // High-speed defaults to 64 already.
        if let Ok(desc) = xhci_dev.get_device_descriptor(slot_id) {
            let mps0 = desc[7] as u16;
            // Valid Full-Speed values per USB 2.0 §9.6.1: 8/16/32/64.
            // Low-Speed must be 8. High-Speed must be 64. SuperSpeed
            // encodes the exponent (2^bMaxPacketSize0). Skip the
            // refresh on weird values rather than blindly trusting.
            let want = match speed {
                xhci::PortSpeed::Low | xhci::PortSpeed::Full
                    if matches!(mps0, 8 | 16 | 32 | 64) =>
                {
                    Some(mps0)
                }
                xhci::PortSpeed::High if mps0 == 64 => Some(64),
                xhci::PortSpeed::Super | xhci::PortSpeed::SuperPlus if mps0 <= 13 => {
                    Some(1u16 << mps0)
                }
                _ => None,
            };
            if let Some(real_mps) = want {
                let _ = xhci_dev.evaluate_context_ep0_mps(slot_id, real_mps);
            }
        }

        // Read the 9-byte cfg header to discover wTotalLength
        // and the bConfigurationValue we'll feed SET_CONFIGURATION.
        let mut head = [0u8; 9];
        let n = xhci_dev
            .get_config_descriptor(slot_id, 0, &mut head)
            .map_err(|e| {
                let err = HidError::Xhci(e);
                note_attach_fail(port, AttachStep::GetCfgHeader, &err);
                err
            })?;
        if n < 9 {
            let err = HidError::NotBootKeyboard;
            note_attach_fail(port, AttachStep::GetCfgHeader, &err);
            return Err(err);
        }
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        if total < 9 || total > 4096 {
            let err = HidError::NotBootKeyboard;
            note_attach_fail(port, AttachStep::GetCfgHeader, &err);
            return Err(err);
        }
        // bConfigurationValue lives at offset +5 of the cfg
        // descriptor (USB 2.0 §9.6.3 table 9-10). Required as
        // the wValue of SET_CONFIGURATION below.
        let cfg_value = head[5];

        // Pull the full tree.
        let mut full = alloc::vec![0u8; total];
        let n2 = xhci_dev
            .get_config_descriptor(slot_id, 0, &mut full)
            .map_err(|e| {
                let err = HidError::Xhci(e);
                note_attach_fail(port, AttachStep::GetCfgFull, &err);
                err
            })?;
        if n2 < total {
            full.truncate(n2);
        }

        let (iface, ep) = find_boot_keyboard(&full).map_err(|e| {
            note_attach_fail(port, AttachStep::FindBootKbd, &e);
            e
        })?;

        // Configure the controller-side endpoint context first
        // so the device-side SET_CONFIGURATION below can drive
        // traffic through the now-running rings.
        xhci_dev.configure_endpoints(slot_id, &[ep]).map_err(|e| {
            let err = HidError::Xhci(e);
            note_attach_fail(port, AttachStep::ConfigureEndpoints, &err);
            err
        })?;

        // SET_CONFIGURATION (USB 2.0 §9.4.7, bRequest=9). Without
        // this, the device stays in Address state and any class
        // request (SET_PROTOCOL, SET_IDLE) returns STALL — which
        // is the entire reason the keyboard pipeline was silent
        // on real-HW boots while QEMU's lax xhci stack worked.
        // bmRequestType: Host-to-Device | Standard | Device = 0x00.
        let mut nothing = [0u8; 0];
        xhci_dev
            .control_in(
                slot_id,
                0x00,
                STD_REQ_SET_CONFIGURATION,
                cfg_value as u16,
                0,
                &mut nothing,
            )
            .map_err(|_| {
                let err = HidError::SetProtocolFailed;
                note_attach_fail(port, AttachStep::SetConfiguration, &err);
                err
            })?;

        let interrupt_in_ep = ep.ep_addr & 0x0F; // DCI computed from this on RX
        let dci = (interrupt_in_ep * 2) + 1;
        let kbd = BootKeyboard::attach(xhci_dev, slot_id, iface, dci).map_err(|e| {
            note_attach_fail(port, AttachStep::SetProtocol, &e);
            e
        })?;
        KEYBOARDS.lock().push(kbd);
        Ok(())
}

/// Number of keyboards currently bound.
pub fn attached_keyboard_count() -> usize {
    KEYBOARDS.lock().len()
}

/// Drain one report from each attached keyboard, translating to
/// `KeyEvent`s on the global input ring. Returns total events
/// emitted across all keyboards.
///
/// Designed to be called from a polling task; per-poll cadence
/// matches the smallest interrupt-IN bInterval of the bound
/// keyboards, but a coarser cadence (e.g. 16 ms) is fine for a
/// kernel pump — the device buffers state-change reports.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    PUMP_ALL_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut g = KEYBOARDS.lock();
    let mut total = 0usize;
    for kbd in g.iter_mut() {
        if let Ok(n) = kbd.pump_once(xhci_dev) {
            total += n;
        }
    }
    total
}

/// Diagnostic counter: how many times `pump_all` has been called
/// since boot. Increments on every supervisor wake (xHCI IRQ or
/// 100 ms timeout). Surfaced in the FB status panel so a real-HW
/// observer can tell at a glance whether the supervisor is alive
/// — a stuck `0` means the supervisor task is wedged.
pub static PUMP_ALL_CALLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Diagnostic counter: how many non-empty `read_report` calls
/// have returned reports across all attached keyboards. Bumped
/// inside `pump_once`'s read loop. A value > 0 means xHCI is
/// delivering transfer events for the interrupt-IN endpoint;
/// stuck at 0 with `attached_keyboard_count() > 0` means the
/// kbd is bound but no reports are arriving (an xHCI ring /
/// IRQ / endpoint-state issue).
pub static REPORTS_READ: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

#[doc(hidden)]
pub fn __reset_keyboards_for_test() {
    KEYBOARDS.lock().clear();
}
