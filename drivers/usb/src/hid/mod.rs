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
//!   1. The USB supervisor addresses/configures a device and binds its
//!      selected keyboard interface through `try_bind_kbd_already_addressed`.
//!   2. `pump_all` — polls each bound keyboard once, diffs the new
//!      report against the previous one, and emits press/release
//!      events to both the console input ring and its evdev node.
//!   3. The `usage` submodule maps HID Usage Page 0x07 IDs onto
//!      `narf_input::KeyCode`. Coverage: every key a Boot-Protocol
//!      keyboard can emit — letters, digits, modifiers, F1-F12,
//!      navigation cluster, full numpad, GUI / Application keys.

use crate::xhci::{self, EndpointConfig, EndpointKind, Xhci};
use narf_input::evdev::{bus, InputId, ROUTER};
use narf_input::Modifiers;

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
/// Report protocol value — the device emits its full report-descriptor-
/// shaped reports (HID §7.2.6). Required for Precision Touchpads, which
/// otherwise stay in Boot Mouse mode and emit 3-byte boot-mouse reports
/// regardless of the descriptor we walked.
pub(crate) const HID_REPORT_PROTOCOL: u16 = 1;
// Standard request code (USB 2.0 §9.4 table 9-4) for
// SET_CONFIGURATION. Standard requests other than this aren't
// needed in this driver, so we don't pull in a full enum.
pub(crate) const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

pub mod apple;
pub mod consumer;
pub mod generic;
pub mod identity;
pub mod keyboard;
pub mod logitech_dj;
pub mod logitech_hidpp;
pub mod microsoft;
pub mod mouse;
pub mod report_descriptor;
pub mod touchpad;
pub mod wacom;
pub mod wacom_features;

#[cfg(any(test, feature = "kernel-test"))]
mod e2e_tests;

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
        self.keys.contains(&usage)
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
    /// Hub context — (parent hub slot id, downstream
    /// port) — when the keyboard sits behind a hub; `None` on a
    /// root port, whose ports are never idle-suspended. The
    /// pump feeds `attach::mark_port_activity` with it whenever
    /// a report completes, so an in-use keyboard's port never
    /// idle-suspends mid-typing (#840).
    pub hub_port: Option<(u8, u8)>,
    /// The live binding owns the same evdev-aware decoder used by the
    /// report-keyboard path. Its node survives until this binding is dropped.
    input: keyboard::UsbKeyboard,
}

/// Walk a Configuration Descriptor (§9.6.3) tree looking for a HID
/// Boot Keyboard interface and its single interrupt-IN endpoint.
/// Returns `(interface_num, ep_config)` for the caller to feed into
/// `xhci::configure_endpoints`.
pub fn find_boot_keyboard(cfg: &[u8]) -> Result<(u8, EndpointConfig), HidError> {
    if let Some(keyboard) = find_boot_interface(cfg, HID_PROTOCOL_KBD, HID_SUBCLASS_BOOT) {
        return Ok(keyboard);
    }
    // A declared boot mouse takes precedence over the subclass-zero keyboard
    // heuristic. Composite mice often expose macro keys on a second interface;
    // claiming that interface as the whole device would hide the real mouse.
    if find_boot_interface(cfg, mouse::HID_PROTOCOL_MOUSE, HID_SUBCLASS_BOOT).is_some() {
        return Err(HidError::NotBootKeyboard);
    }
    find_boot_interface(cfg, HID_PROTOCOL_KBD, 0).ok_or(HidError::NoInterruptIn)
}

/// Select an endpoint and its owning interface together. Only alternate zero
/// is active after SET_CONFIGURATION; never silently choose another alternate.
/// The caller tries a declared boot interface before subclass-zero heuristics.
pub(crate) fn find_boot_interface(
    cfg: &[u8],
    protocol: u8,
    subclass: u8,
) -> Option<(u8, EndpointConfig)> {
    let mut offset = 0;
    let mut interface = None;
    while offset + 2 <= cfg.len() {
        let len = cfg[offset] as usize;
        if len < 2 || offset + len > cfg.len() {
            break;
        }
        let descriptor = &cfg[offset..offset + len];
        match descriptor[1] {
            4 => {
                interface = (len >= 9
                    && descriptor[3] == 0
                    && descriptor[5] == HID_INTERFACE_CLASS
                    && descriptor[6] == subclass
                    && descriptor[7] == protocol)
                    .then(|| descriptor[2]);
            }
            5 if len >= 7 => {
                if let Some(iface) = interface {
                    let address = descriptor[2];
                    if address & 0x80 != 0 && descriptor[3] & 3 == 3 {
                        return Some((
                            iface,
                            EndpointConfig {
                                ep_addr: address,
                                max_packet: u16::from_le_bytes([descriptor[4], descriptor[5]]),
                                kind: EndpointKind::InterruptIn,
                                interval: descriptor[6],
                            },
                        ));
                    }
                }
            }
            _ => {}
        }
        offset += len;
    }
    None
}

impl BootKeyboard {
    pub(crate) fn from_configured_endpoint(
        slot_id: u8,
        interface_num: u8,
        interrupt_in_ep: u8,
        hub_port: Option<(u8, u8)>,
        identity: InputId,
    ) -> Self {
        Self {
            slot_id,
            interrupt_in_ep,
            interface_num,
            hub_port,
            input: keyboard::UsbKeyboard::publish_boot(
                slot_id,
                interface_num,
                interrupt_in_ep,
                identity,
            ),
        }
    }

    /// Bind a boot keyboard to an already-addressed + configured
    /// xHCI slot. Issues `Set Protocol(Boot)` so subsequent
    /// `read_report` calls return the fixed 8-byte format.
    pub async fn attach(
        xhci_dev: &Xhci,
        slot_id: u8,
        interface_num: u8,
        interrupt_in_ep: u8,
        hub_port: Option<(u8, u8)>,
        identity: InputId,
    ) -> Result<Self, HidError> {
        // Set Protocol class request (§7.2.6):
        //   bmRequestType: 0x21 (Class | Interface | Host-to-Device)
        //   bRequest: SET_PROTOCOL
        //   wValue: 0 (Boot protocol)
        //   wIndex: interface number
        //   wLength: 0
        xhci_dev
            .control_out(
                slot_id,
                0x21,
                HID_REQ_SET_PROTOCOL,
                HID_BOOT_PROTOCOL,
                interface_num as u16,
                &[],
            )
            .await
            .map_err(|_| HidError::SetProtocolFailed)?;
        // SET_IDLE(duration=0, reportID=0) — HID §7.2.4. Tells
        // the device "only send a report on state change", which
        // is what we want for a polled-pump keyboard. Many
        // BIOS-flashed keyboards will silently suppress reports
        // until SET_IDLE has been issued at least once. Failure
        // here is non-fatal (some devices STALL because they
        // don't implement the request); SET_PROTOCOL was the
        // load-bearing call.
        let _ = xhci_dev
            .control_out(
                slot_id,
                0x21,
                HID_REQ_SET_IDLE,
                0, // (duration<<8) | reportID — both zero
                interface_num as u16,
                &[],
            )
            .await;
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
        Ok(Self::from_configured_endpoint(
            slot_id,
            interface_num,
            interrupt_in_ep,
            hub_port,
            identity,
        ))
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
        let mut reports = 0usize;
        while let Some(report) = self.read_report(xhci_dev)? {
            reports += 1;
            total += self.translate_report(report);
        }
        // A completed interrupt-IN transfer is activity on the
        // binding's hub port (#840): feed it so the supervisor's
        // idle-suspend pass never gates a keyboard mid-typing.
        // Feeding keys on completed *transfers*, not emitted
        // events — a report that diffs to zero events still
        // proves the device is in use. No-op for root-attached
        // keyboards (`hub_port` is `None`).
        if reports > 0 {
            if let Some((hub_slot, port)) = self.hub_port {
                crate::attach::mark_port_activity(xhci_dev.id(), hub_slot, port);
            }
        }
        Ok(total)
    }

    /// Same diff logic as `pump_once`, but works from a caller-
    /// supplied report. Used by both the live pump and the
    /// in-tree smokes.
    pub fn translate_report(&mut self, report: KbdReport) -> usize {
        let mut raw = [0; 8];
        raw[0] = report.modifiers;
        raw[2..].copy_from_slice(&report.keys);
        keyboard::process_boot_report(&mut self.input, &raw)
    }

    /// Reset the diff baseline — the next report is treated as if
    /// no keys were previously pressed. Useful after re-attach.
    pub fn reset_diff(&mut self) {
        self.input.last_keys = [0; 6];
        self.input.last_mods = 0;
    }
}

impl Drop for BootKeyboard {
    fn drop(&mut self) {
        // Release held keys/modifiers in the legacy ring as well. Removing
        // the node marks existing evdev readers dead and wakes blocked reads.
        self.translate_report(KbdReport::default());
        ROUTER.unregister_device(self.input.evdev_id);
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

// ── Hot-plug enumeration ──────────────────────────────────────────

/// Attached HID boot keyboards, one registry per xHCI controller.
/// Populated by `enumerate_and_attach_keyboards`; consumed by `pump_all`.
static KEYBOARDS: crate::xhci::PerController<Vec<BootKeyboard>> = crate::per_controller_vec!();

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
pub async fn enumerate_and_attach_keyboards(xhci_dev: &Xhci) -> usize {
    let mut attached = 0usize;
    for (port, _portsc) in xhci_dev.connected_ports() {
        if try_attach_port(xhci_dev, port).await.is_ok() {
            attached += 1;
        }
    }
    attached
}

/// Per-port last-failure step. Single byte per port indexed by
/// (port-1). 0 = no failure recorded. Used by `note_attach_step`
/// to dedupe log lines so the supervisor's 16-ms retry cadence
/// doesn't fill the klog ring with the same failure repeatedly.
static LAST_KBD_FAIL_STEP: [core::sync::atomic::AtomicU8; 256 * crate::xhci::MAX_CONTROLLERS] = {
    use core::sync::atomic::AtomicU8;
    [const { AtomicU8::new(0) }; 256 * crate::xhci::MAX_CONTROLLERS]
};

/// Index of `(controller, port)` in the per-port log-dedup arrays.
fn port_log_index(controller: u8, port: u8) -> usize {
    usize::from(controller).min(crate::xhci::MAX_CONTROLLERS - 1) * 256 + usize::from(port)
}

/// Counts consecutive same-step failures per port. Used by
/// `note_attach_fail` to re-emit a log line every N cycles even if
/// the step hasn't changed (audit F-83) — useful when a device is
/// genuinely stuck and a logfile reader needs the periodic signal
/// to distinguish "still failing" from "logged once and forgotten".
#[allow(dead_code)]
static KBD_FAIL_REPEATS: [core::sync::atomic::AtomicU16; 256 * crate::xhci::MAX_CONTROLLERS] = {
    use core::sync::atomic::AtomicU16;
    [const { AtomicU16::new(0) }; 256 * crate::xhci::MAX_CONTROLLERS]
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
fn note_attach_fail(controller: u8, port: u8, step: AttachStep, err: &HidError) {
    use core::fmt::Write as _;
    use core::sync::atomic::Ordering;
    // Audit F-83: emit on first occurrence of a (port, step) pair,
    // then suppress repeats for ~64 cycles so a stuck enumeration
    // loop still surfaces a periodic "still failing" beat without
    // flooding klog. The supervisor cycles ~16 ms apart on real
    // hardware, so 64 ≈ once per second.
    const REPEAT_MASK: u16 = 63;
    let index = port_log_index(controller, port);
    let prev = LAST_KBD_FAIL_STEP[index].swap(step as u8, Ordering::AcqRel);
    let same_step = prev == step as u8;
    let n = if same_step {
        KBD_FAIL_REPEATS[index].fetch_add(1, Ordering::AcqRel)
    } else {
        KBD_FAIL_REPEATS[index].store(0, Ordering::Release);
        0
    };
    if same_step && (n & REPEAT_MASK) != 0 {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  usb-hid: kbd xhci{} port={} step={} err={:?}",
        controller,
        port,
        step.name(),
        err
    );
}

fn note_attach_ok(controller: u8, port: u8) {
    use core::fmt::Write as _;
    use core::sync::atomic::{AtomicU64, Ordering};
    let index = port_log_index(controller, port);
    let was_failing = LAST_KBD_FAIL_STEP[index].swap(0, Ordering::AcqRel) != 0;
    KBD_FAIL_REPEATS[index].store(0, Ordering::Release);
    // Log a one-line "attached" notification per port so a real-HW
    // boot makes it obvious that the kbd pipeline came up. Bitmask
    // dedupes against the supervisor's per-cycle re-call.
    static ATTACHED_PORTS: [AtomicU64; crate::xhci::MAX_CONTROLLERS] =
        [const { AtomicU64::new(0) }; crate::xhci::MAX_CONTROLLERS];
    let bit = 1u64 << (port as u32 & 63);
    let prev = ATTACHED_PORTS[index / 256].fetch_or(bit, Ordering::AcqRel);
    if prev & bit == 0 || was_failing {
        let _ = writeln!(
            narf_console::Writer,
            "  usb-hid: kbd attached on xhci{} port {}",
            controller,
            port
        );
    }
}

/// Public per-port attach used by the supervisor's per-port
/// retry loop. Returns Err on any failure (no kbd here, NotBoot,
/// xHCI command failure) so the supervisor can decide whether to
/// re-try (port still connected) or move on.
pub async fn try_attach_keyboard_on_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    let r = try_attach_port(xhci_dev, port).await;
    if r.is_ok() {
        note_attach_ok(xhci_dev.id(), port);
    }
    r
}

/// Hub-downstream variant: caller has already issued port_reset on
/// the hub's downstream port, allocated `slot_id` via `enable_slot`,
/// and called `address_device_with` for the topology-aware address.
/// This entry point picks up from there: GET_DESCRIPTOR + refresh
/// EP0 MPS + class match + bind. `port` is the hub's downstream
/// port number (used purely for log dedup / failure attribution —
/// not for any xHCI register access). On success the kbd is added
/// to the global registry and `note_attach_ok` records the port
/// for one-shot logging.
///
/// **Slot lifecycle**: this function does NOT call `disable_slot`
/// on failure. The dispatcher in `attach::dispatch_after_address`
/// owns slot lifecycle and only frees the slot once *every* class-
/// probe fallback has run and returned `UnknownClass`. Pattern
/// modeled on Linux's `usb_set_configuration` flow (configure →
/// enumerate → bind, free only on terminal mismatch — see
/// `drivers/usb/core/hub.c::usb_new_device`).
///
/// Previously this freed the slot internally on failure; subsequent
/// touchpad / CDC-ACM / MSC / UAC / UVC / CDC-NCM / btusb probes
/// then reused the same freed `slot_id`, and every control transfer
/// on it failed with a stale-slot CC — so only kbd and hub could
/// ever attach. Removed cleanly per the no-shims rule.
pub async fn try_bind_kbd_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    port: u8,
    speed: xhci::PortSpeed,
    hub_port: Option<(u8, u8)>,
) -> Result<(), HidError> {
    let r = bind_kbd_addressed_slot(xhci_dev, slot_id, port, speed, hub_port).await;
    if r.is_ok() {
        note_attach_ok(xhci_dev.id(), port);
    }
    r
}

async fn try_attach_port(xhci_dev: &Xhci, port: u8) -> Result<(), HidError> {
    xhci_dev.port_reset(port).await.map_err(|e| {
        let err = HidError::Xhci(e);
        note_attach_fail(xhci_dev.id(), port, AttachStep::Reset, &err);
        err
    })?;
    let speed = xhci_dev.port_speed(port).ok_or_else(|| {
        let err = HidError::NoInterruptIn;
        note_attach_fail(xhci_dev.id(), port, AttachStep::Speed, &err);
        err
    })?;
    let slot_id = xhci_dev.enable_slot().await.map_err(|e| {
        let err = HidError::Xhci(e);
        note_attach_fail(xhci_dev.id(), port, AttachStep::EnableSlot, &err);
        err
    })?;
    let res = async {
        xhci_dev
            .address_device(slot_id, port, speed)
            .await
            .map_err(|e| {
                let err = HidError::Xhci(e);
                note_attach_fail(xhci_dev.id(), port, AttachStep::AddressDevice, &err);
                err
            })?;
        bind_kbd_addressed_slot(xhci_dev, slot_id, port, speed, None).await
    }
    .await;
    if res.is_err() {
        // Free the slot so a retry doesn't leak xHCI device
        // contexts. AMD Renoir's MaxSlots is typically 32 and a
        // laptop with multiple internal USB devices can burn
        // through them quickly across enumeration retries.
        let _ = crate::attach::release_slot(xhci_dev, slot_id).await;
    }
    res
}

/// Post-address kbd bind: assumes the caller has already issued
/// port_reset / enable_slot / address_device(_with). Does the
/// device + config descriptor walk, EP0-MPS refresh, kbd interface
/// match, configure_endpoints, SET_CONFIGURATION, SET_PROTOCOL,
/// arm_interrupt_in, and registry push. Does NOT call disable_slot
/// on failure — caller's cleanup_guard handles that.
async fn bind_kbd_addressed_slot(
    xhci_dev: &Xhci,
    slot_id: u8,
    port: u8,
    speed: xhci::PortSpeed,
    hub_port: Option<(u8, u8)>,
) -> Result<(), HidError> {
    // GET_DESCRIPTOR(DEVICE) and refresh EP0 MaxPacketSize via
    // Evaluate Context if the device's real bMaxPacketSize0
    // differs from the speed-default we programmed at Address
    // Device time (audit F-22 + F-23). This matters for full-
    // speed devices (we initially seed MPS=8 — the smallest
    // legal — and most FS devices are actually 8/16/32/64).
    // High-speed defaults to 64 already.
    let descriptor = xhci_dev.get_device_descriptor(slot_id).await.ok();
    if let Some(desc) = descriptor {
        let mps0 = desc[7] as u16;
        // Valid Full-Speed values per USB 2.0 §9.6.1: 8/16/32/64.
        // Low-Speed must be 8. High-Speed must be 64. SuperSpeed
        // encodes the exponent (2^bMaxPacketSize0). Skip the
        // refresh on weird values rather than blindly trusting.
        let want = match speed {
            xhci::PortSpeed::Low | xhci::PortSpeed::Full if matches!(mps0, 8 | 16 | 32 | 64) => {
                Some(mps0)
            }
            xhci::PortSpeed::High if mps0 == 64 => Some(64),
            xhci::PortSpeed::Super | xhci::PortSpeed::SuperPlus if mps0 <= 13 => Some(1u16 << mps0),
            _ => None,
        };
        if let Some(real_mps) = want {
            let _ = xhci_dev.evaluate_context_ep0_mps(slot_id, real_mps).await;
        }
    }

    // Read the 9-byte cfg header to discover wTotalLength
    // and the bConfigurationValue we'll feed SET_CONFIGURATION.
    let mut head = [0u8; 9];
    let n = xhci_dev
        .get_config_descriptor(slot_id, 0, &mut head)
        .await
        .map_err(|e| {
            let err = HidError::Xhci(e);
            note_attach_fail(xhci_dev.id(), port, AttachStep::GetCfgHeader, &err);
            err
        })?;
    if n < 9 {
        let err = HidError::NotBootKeyboard;
        note_attach_fail(xhci_dev.id(), port, AttachStep::GetCfgHeader, &err);
        return Err(err);
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total) {
        let err = HidError::NotBootKeyboard;
        note_attach_fail(xhci_dev.id(), port, AttachStep::GetCfgHeader, &err);
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
        .await
        .map_err(|e| {
            let err = HidError::Xhci(e);
            note_attach_fail(xhci_dev.id(), port, AttachStep::GetCfgFull, &err);
            err
        })?;
    if n2 < total {
        full.truncate(n2);
    }

    let (iface, ep) = find_boot_keyboard(&full).inspect_err(|e| {
        note_attach_fail(xhci_dev.id(), port, AttachStep::FindBootKbd, e);
    })?;

    // Configure the controller-side endpoint context first
    // so the device-side SET_CONFIGURATION below can drive
    // traffic through the now-running rings.
    xhci_dev
        .configure_endpoints(slot_id, &[ep])
        .await
        .map_err(|e| {
            let err = HidError::Xhci(e);
            note_attach_fail(xhci_dev.id(), port, AttachStep::ConfigureEndpoints, &err);
            err
        })?;

    // SET_CONFIGURATION (USB 2.0 §9.4.7, bRequest=9). Without
    // this, the device stays in Address state and any class
    // request (SET_PROTOCOL, SET_IDLE) returns STALL — which
    // is the entire reason the keyboard pipeline was silent
    // on real-HW boots while QEMU's lax xhci stack worked.
    // bmRequestType: Host-to-Device | Standard | Device = 0x00.
    xhci_dev
        .control_out(
            slot_id,
            0x00,
            STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| {
            let err = HidError::SetProtocolFailed;
            note_attach_fail(xhci_dev.id(), port, AttachStep::SetConfiguration, &err);
            err
        })?;

    let interrupt_in_ep = ep.ep_addr & 0x0F; // DCI computed from this on RX
    let dci = (interrupt_in_ep * 2) + 1;
    let identity = descriptor.map_or(InputId::new(bus::USB, 0, 0, 0), |desc| {
        InputId::new(
            bus::USB,
            u16::from_le_bytes([desc[8], desc[9]]),
            u16::from_le_bytes([desc[10], desc[11]]),
            u16::from_le_bytes([desc[12], desc[13]]),
        )
    });
    let kbd = BootKeyboard::attach(xhci_dev, slot_id, iface, dci, hub_port, identity)
        .await
        .inspect_err(|e| {
            note_attach_fail(xhci_dev.id(), port, AttachStep::SetProtocol, e);
        })?;
    {
        KEYBOARDS.of(xhci_dev.id()).lock().push(kbd);
        ATTACHED_KEYBOARD_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }
    Ok(())
}

/// Decrement a lock-free binding counter by `n`, saturating at zero
/// (fixtures can push bindings without counting them).
pub(crate) fn saturating_sub(counter: &core::sync::atomic::AtomicU32, n: u32) {
    let _ = counter.fetch_update(
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Acquire,
        |v| Some(v.saturating_sub(n)),
    );
}

/// Lock-free atomic count of bound keyboards. Diagnostics
/// (fb::status::paint, panel counters) read this WITHOUT taking
/// the KEYBOARDS lock — that lock is held by `pump_all` for the
/// duration of every interrupt-IN read across every bound
/// keyboard, which on real silicon can be tens of ms. Reading
/// the lock from the diagnostic path would freeze the executor
/// (IrqSafeSpinLock disables IF on the waiter).
pub static ATTACHED_KEYBOARD_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Number of keyboards currently bound. Lock-free read of the
/// atomic snapshot — kept as a `fn` for source-compat with old
/// callers; equivalent to `ATTACHED_KEYBOARD_COUNT.load(...)`.
pub fn attached_keyboard_count() -> usize {
    ATTACHED_KEYBOARD_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize
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
    let mut g = KEYBOARDS.of(xhci_dev.id()).lock();
    let mut total = 0usize;
    for kbd in g.iter_mut() {
        let before = REPORTS_READ.load(core::sync::atomic::Ordering::Relaxed);
        let result = kbd.pump_once(xhci_dev);
        let got = REPORTS_READ.load(core::sync::atomic::Ordering::Relaxed) != before;
        note_pump(
            "kbd",
            xhci_dev.id(),
            kbd.slot_id,
            got,
            result.as_ref().err().map(|e| e as &dyn core::fmt::Debug),
        );
        if let Ok(n) = result {
            total += n;
        }
    }
    total
}

/// Bring-up visibility for the input pumps, whose errors are otherwise
/// dropped every cycle: log a binding's first report and its first error
/// (once each per controller/slot/class), so a boot shows whether
/// reports arrive, fail, or never come.
pub(crate) fn note_pump(
    class: &'static str,
    controller: u8,
    slot_id: u8,
    got_report: bool,
    error: Option<&dyn core::fmt::Debug>,
) {
    static SEEN: narf_lib::sync::IrqSafeSpinLock<
        alloc::collections::BTreeSet<(&'static str, u8, u8, bool)>,
    > = narf_lib::sync::IrqSafeSpinLock::new(alloc::collections::BTreeSet::new());
    let event = match (got_report, error) {
        (_, Some(_)) => false,
        (true, None) => true,
        (false, None) => return,
    };
    if !SEEN.lock().insert((class, controller, slot_id, event)) {
        return;
    }
    use core::fmt::Write as _;
    match error {
        Some(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  usb-hid: {class} xhci{controller} slot={slot_id} first pump error: {e:?}"
            );
        }
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  usb-hid: {class} xhci{controller} slot={slot_id} first report received"
            );
        }
    }
}

/// Snapshot the hub contexts of every live HID binding on `controller` across
/// the pumped classes (boot keyboards here, plus mouse /
/// touchpad / consumer), sorted and deduplicated — a composite
/// device can bind two classes on the same hub port.
/// Root-attached bindings (`hub_port` is `None`) are omitted:
/// root ports are never idle-suspended.
pub fn hub_ports(controller: u8) -> alloc::vec::Vec<(u8, u8)> {
    let mut v: alloc::vec::Vec<(u8, u8)> = {
        let g = KEYBOARDS.of(controller).lock();
        g.iter().filter_map(|k| k.hub_port).collect()
    };
    v.extend(mouse::hub_ports(controller));
    v.extend(touchpad::hub_ports(controller));
    v.extend(consumer::hub_ports(controller));
    v.sort_unstable();
    v.dedup();
    v
}

/// Supervisor wake step for hub-attached HID, run immediately
/// before the pump calls each cycle (#840). A suspended port
/// gates the device's interrupt endpoint, so the pump can
/// neither observe a report nor feed activity for it — and no
/// device-initiated path back exists in the tree (nothing
/// enables remote wakeup on HID devices or watches hub
/// port-change bits). For every HID-bound port the registry
/// currently marks suspended, resume it via the idempotent
/// `attach::resume_port`, then replace the resume sentinel
/// with a real tick via `attach::mark_port_activity`: the
/// resume opens a fresh idle window (the same rule
/// `attach::mark_ports_bound` applies at bind), so a device
/// that stays silent re-suspends after a full idle window
/// and is woken again on a later cycle, while a device that
/// starts reporting takes over its own feeding through the
/// pumps. Ports whose resume fails keep their suspended bit
/// and are retried on the next cycle.
pub async fn resume_suspended_hub_ports(xhci_dev: &Xhci) {
    // Collect binding contexts first, then snapshot the hub
    // registry — never hold HUBS across the HID registry locks
    // (the pumps nest the other way: registry lock held while
    // `mark_port_activity` takes HUBS).
    let controller = xhci_dev.id();
    let ports = hub_ports(controller);
    let targets = {
        let g = crate::attach::HUBS.of(controller).lock();
        crate::attach::suspended_ports_among(&g[..], &ports)
    };
    for (hub_slot, port) in targets {
        crate::attach::resume_port(xhci_dev, hub_slot, port).await;
        if !crate::attach::hub_port_is_suspended(controller, hub_slot, port) {
            crate::attach::mark_port_activity(controller, hub_slot, port);
        }
    }
}

/// Diagnostic counter: how many times `pump_all` has been called
/// since boot. Increments on every supervisor wake (xHCI IRQ or
/// 100 ms timeout). Surfaced in the FB status panel so a real-HW
/// observer can tell at a glance whether the supervisor is alive
/// — a stuck `0` means the supervisor task is wedged.
pub static PUMP_ALL_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostic counter: how many non-empty `read_report` calls
/// have returned reports across all attached keyboards. Bumped
/// inside `pump_once`'s read loop. A value > 0 means xHCI is
/// delivering transfer events for the interrupt-IN endpoint;
/// stuck at 0 with `attached_keyboard_count() > 0` means the
/// kbd is bound but no reports are arriving (an xHCI ring /
/// IRQ / endpoint-state issue).
pub static REPORTS_READ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Detach the boot keyboard bound to `slot_id` — the device was
/// unplugged, its hub went away, or the supervisor is tearing the
/// binding down before slot reclaim. Dropping the binding releases held
/// keys and removes its evdev node. Returns true when a binding was removed.
pub fn detach_boot_keyboard(controller: u8, slot_id: u8) -> bool {
    let mut g = KEYBOARDS.of(controller).lock();
    let before = g.len();
    g.retain(|k| k.slot_id != slot_id);
    let removed = before - g.len();
    crate::hid::saturating_sub(&ATTACHED_KEYBOARD_COUNT, removed as u32);
    removed != 0
}

/// Drop every boot-keyboard binding on `controller`. Called on a controller
/// recovery epoch change, where every slot is dead by construction
/// and no per-slot teardown applies.
pub fn clear_boot_keyboards(controller: u8) {
    let removed = {
        let mut g = KEYBOARDS.of(controller).lock();
        let n = g.len();
        g.clear();
        n
    };
    crate::hid::saturating_sub(&ATTACHED_KEYBOARD_COUNT, removed as u32);
}

#[doc(hidden)]
pub fn __reset_keyboards_for_test() {
    for (_, keyboards) in KEYBOARDS.each() {
        keyboards.lock().clear();
    }
    ATTACHED_KEYBOARD_COUNT.store(0, core::sync::atomic::Ordering::Release);
}

#[doc(hidden)]
pub fn __push_keyboard_for_test(kbd: BootKeyboard) {
    KEYBOARDS.of(0).lock().push(kbd);
}

#[doc(hidden)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn feed_keyboard_report_for_test(slot: u8, report: [u8; 8]) -> usize {
    KEYBOARDS
        .of(0)
        .lock()
        .iter_mut()
        .find(|kbd| kbd.slot_id == slot)
        .map_or(0, |kbd| kbd.translate_report(KbdReport::from_bytes(report)))
}
