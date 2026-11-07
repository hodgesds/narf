//! i8042 PS/2 mouse driver — AUX channel + IRQ 12.
//!
//! The i8042 controller multiplexes two PS/2 channels behind the
//! same data port (0x60). The keyboard channel uses IRQ 1; the
//! AUX (mouse) channel uses IRQ 12. Distinguishing the two from a
//! port-0x60 read is via the controller's status register: bit 5
//! (AUX_FULL) means the next data byte came from AUX. We use the
//! per-IRQ entry instead — IRQ 1 reads keyboard, IRQ 12 reads mouse —
//! so the status check is only used by the init path that drains
//! init replies.
//!
//! Standard PS/2 mouse 3-byte packet:
//!
//! ```
//!   byte 0 — status:
//!     bit 0: left button
//!     bit 1: right button
//!     bit 2: middle button
//!     bit 3: always 1 (sync)
//!     bit 4: X sign
//!     bit 5: Y sign
//!     bit 6: X overflow (ignored)
//!     bit 7: Y overflow (ignored)
//!   byte 1 — dx (signed via bit 4 of byte 0)
//!   byte 2 — dy (signed via bit 5 of byte 0; positive = up, so
//!            we negate to match the screen-down convention)
//! ```
//!
//! IntelliMouse / Explorer 4-byte packet (after the knock in
//! `crate::psmouse::negotiate_protocol` — sample rates 200/100/80
//! then `GETID` → 0x03, or 200/200/80 → 0x04; see
//! `psmouse.rs` for the grounded references):
//!
//! ```
//!   bytes 0..=2 — as above
//!   byte 3 — wheel / extra buttons:
//!     IntelliMouse: whole byte is the Z (wheel) movement,
//!       4-bit two's complement (-8..+7) sign-extended;
//!       reported as `REL_WHEEL = -(signed char)byte3` (Linux
//!       `psmouse_process_byte`).
//!     Explorer: bits 7-6 select the meaning — `0x80` vertical
//!       tilt scroll, `0x40` horizontal tilt scroll, `0x00`/`0xC0`
//!       wheel in the low nibble plus 4th button (bit 4,
//!       `BTN_SIDE`) and 5th button (bit 5, `BTN_EXTRA`).
//! ```
//!
//! Init sequence:
//!   1. Enable the AUX channel via cmd 0xA8.
//!   2. Set bit 1 (AUX IRQ) in the controller config; clear bit 5
//!      (AUX disable).
//!   3. Send 0xD4 + 0xFF on the data port to reset the device,
//!      then 0xD4 + 0xF6 (set defaults). Each pair is best-effort —
//!      a system without a PS/2 mouse won't ack but the kernel
//!      keeps booting.
//!   4. Negotiate the protocol (`psmouse::negotiate_protocol`):
//!      Synaptics/ALPS vendor probes, a reset to defaults, then
//!      the IntelliMouse/Explorer knocks. On failure the device
//!      stays a 3-byte standard mouse.
//!   5. Restore the sample rate to 100 (the knocks leave it at 80,
//!      or 40 after the Explorer tilt knock; Linux
//!      `psmouse_initialize` does the same), then 0xD4 + 0xF4
//!      (enable data reporting).

use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{
    evdev::{dispatch_pointer_wheel_to_node, key, rel, DeviceCaps, DeviceId, DeviceNode, ROUTER},
    push_global, InputEvent, PointerButtons, PointerEvent, ScrollEvent,
};

extern crate alloc;
use alloc::sync::Arc;

use crate::i8042::{PS2_CMD, PS2_DATA, PS2_STATUS};
use crate::psmouse::{self, Ps2Transport};

const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;

const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_WRITE_AUX: u8 = 0xD4;

const CONF_KBD_IRQ: u8 = 1 << 0;
const CONF_AUX_IRQ: u8 = 1 << 1;
const CONF_AUX_DIS: u8 = 1 << 5;

/// Controller-config wait; controller commands respond in µs.
const CONFIG_WAIT_MS: u64 = 5;
/// Mouse-channel reply wait; see i8042.rs for the EC-latency rationale.
/// PS/2 mouse reset also returns a 3rd "device id" byte that can
/// arrive up to ~100 ms after BAT.
const MOUSE_REPLY_MS: u64 = 100;
const MOUSE_BAT_MS: u64 = 500;

const MOUSE_ACK: u8 = 0xFA;
const MOUSE_BAT_OK: u8 = 0xAA;

#[derive(Debug)]
pub struct State {
    /// Bytes 0..=3 of the in-flight packet. `phase` tracks how many
    /// bytes we've collected. When phase reaches the negotiated
    /// packet length (3 standard, 4 IntelliMouse/Explorer — see
    /// `crate::psmouse::packet_len`), we emit the PointerEvent /
    /// ScrollEvent + reset to 0.
    pkt: [AtomicU8; 4],
    phase: AtomicU8,
    rel_dx_acc: AtomicI32,
    rel_dy_acc: AtomicI32,
    /// Accumulated wheel deltas (vertical / horizontal) since the
    /// last `take_wheel_delta()`; mirrors `rel_dx_acc`/`rel_dy_acc`.
    rel_wheel_acc: AtomicI32,
    rel_hwheel_acc: AtomicI32,
    /// Last reported button bitmask (bit0=left, bit1=right,
    /// bit2=middle, bit3=side/4th, bit4=extra/5th), so evdev
    /// `EV_KEY` events are emitted only on press/release edges.
    prev_buttons: AtomicU8,
    initialized: core::sync::atomic::AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            pkt: [
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
            ],
            phase: AtomicU8::new(0),
            rel_dx_acc: AtomicI32::new(0),
            rel_dy_acc: AtomicI32::new(0),
            rel_wheel_acc: AtomicI32::new(0),
            rel_hwheel_acc: AtomicI32::new(0),
            prev_buttons: AtomicU8::new(0),
            initialized: core::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

pub static STATE: State = State::new();

/// Evdev device node for the PS/2 mouse. Registered in `init()`.
static MOUSE_EVDEV_NODE: narf_lib::sync::IrqSafeSpinLock<Option<Arc<DeviceNode>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Evdev id of the registered mouse node, if any. `init()` used
/// to discard it, so no production path could ever unregister the
/// mouse — the re-probe hook (issue #771) needs it.
static MOUSE_EVDEV_ID: narf_lib::sync::IrqSafeSpinLock<Option<DeviceId>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Raw pointer cache for lock-free IRQ access.
static MOUSE_NODE_PTR: core::sync::atomic::AtomicPtr<DeviceNode> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn take_rel_delta() -> (i32, i32) {
    let dx = STATE.rel_dx_acc.swap(0, Ordering::AcqRel);
    let dy = STATE.rel_dy_acc.swap(0, Ordering::AcqRel);
    (dx, dy)
}

/// Take the accumulated wheel deltas since the last call:
/// `(vertical REL_WHEEL, horizontal REL_HWHEEL)`.
pub fn take_wheel_delta() -> (i32, i32) {
    let wheel = STATE.rel_wheel_acc.swap(0, Ordering::AcqRel);
    let hwheel = STATE.rel_hwheel_acc.swap(0, Ordering::AcqRel);
    (wheel, hwheel)
}

pub fn is_initialized() -> bool {
    STATE.initialized.load(Ordering::Acquire)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InitError {
    Timeout,
}

fn deadline_cycles(ms: u64) -> u64 {
    // `ns_to_cycles` is the calibrated fixed-point scale — 5 ms means
    // 5 ms at the ACTUAL TSC rate, not at a truncated integer GHz, and
    // it floors rather than collapsing to zero before calibration.
    narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ms.saturating_mul(1_000_000)))
}

fn wait_input_clear_ms(ms: u64) -> Result<(), InitError> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: 0x64 status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(InitError::Timeout)
}

fn wait_output_ms(ms: u64) -> Option<u8> {
    let deadline = deadline_cycles(ms);
    while narf_time::now_cycles() < deadline {
        // SAFETY: 0x64 status read.
        if unsafe { inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            // SAFETY: 0x60 data read.
            return Some(unsafe { inb(PS2_DATA) });
        }
        core::hint::spin_loop();
    }
    None
}

/// Send one byte to the AUX (mouse) device: `0xD4` prefix on the
/// command port, then the byte on the data port. Returns `true`
/// when the device ACKs (`0xFA`) within `MOUSE_REPLY_MS`.
fn aux_send(byte: u8) -> bool {
    let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
    // SAFETY: 0x64 cmd write; `CMD_WRITE_AUX` (0xD4) routes the next 0x60 byte
    // to the AUX (mouse) channel instead of the keyboard.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_WRITE_AUX);
    }
    let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
    // SAFETY: 0x60 data write; the preceding 0xD4 forwards this byte to the
    // AUX device.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_DATA, byte);
    }
    wait_output_ms(MOUSE_REPLY_MS) == Some(MOUSE_ACK)
}

/// Send a command byte plus one parameter byte to the AUX device
/// (e.g. `0xF3` + rate). Both bytes must ACK.
fn aux_send_param(cmd: u8, param: u8) -> bool {
    aux_send(cmd) && aux_send(param)
}

/// Reset the AUX device: `0xFF`, expect ACK, then BAT (`0xAA`,
/// up to ~500 ms), then the device-id byte (informational).
/// Restores power-on defaults (3-byte packets, rate 100,
/// reporting disabled).
fn aux_reset() -> bool {
    if !aux_send(psmouse::CMD_RESET) {
        return false;
    }
    if wait_output_ms(MOUSE_BAT_MS) != Some(MOUSE_BAT_OK) {
        return false;
    }
    // Device id (0x00 for standard mouse) follows BAT but
    // is informational; don't gate on it.
    let _ = wait_output_ms(MOUSE_REPLY_MS);
    true
}

/// `crate::psmouse::Ps2Transport` over the i8042 AUX channel.
/// Used by `psmouse::negotiate_protocol` during `init()`.
struct AuxTransport;

impl Ps2Transport for AuxTransport {
    fn send(&mut self, byte: u8) -> bool {
        aux_send(byte)
    }

    fn recv(&mut self) -> Option<u8> {
        wait_output_ms(MOUSE_REPLY_MS)
    }

    fn reset(&mut self) -> bool {
        aux_reset()
    }
}

/// Re-enable the AUX (mouse) channel: enable AUX, restore the
/// AUX-IRQ config, reset the mouse, set defaults, negotiate the
/// protocol, restore the sample rate, enable data reporting.
/// Returns whether the mouse is reporting — best effort: a system
/// without a PS/2 mouse returns `false`, not an error. A timeout
/// in the controller-side config exchange is an `Err`, matching
/// `init()`.
///
/// Shared verbatim by `init()` (steps 1-4) and `resume()` (#770):
/// resume re-runs exactly this bring-up instead of a second,
/// drift-prone copy of the sequence.
///
/// Exclusive-access contract (same as `init()`): `i8042::init`
/// already ran and no other agent is driving the 8042 ports
/// concurrently.
fn enable_mouse_channel() -> Result<bool, InitError> {
    // 1. Enable AUX channel.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: 0x64 cmd.
    unsafe {
        outb(PS2_CMD, CMD_ENABLE_AUX);
    }

    // 2. Update config: set AUX_IRQ, clear AUX_DIS.
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: 0x64 cmd write; input buffer drained above so the controller
    // accepts `CMD_READ_CONFIG` (0x20), which queues config byte to 0x60.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_READ_CONFIG);
    }
    let mut conf = wait_output_ms(CONFIG_WAIT_MS).ok_or(InitError::Timeout)?;
    conf |= CONF_AUX_IRQ;
    conf &= !CONF_AUX_DIS;
    conf |= CONF_KBD_IRQ;
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: 0x64 cmd write; input buffer drained above so `CMD_WRITE_CONFIG`
    // (0x60) is accepted, telling the controller the next 0x60 write is the
    // new config byte.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_WRITE_CONFIG);
    }
    wait_input_clear_ms(CONFIG_WAIT_MS)?;
    // SAFETY: 0x60 data write; input buffer drained above. Delivers the
    // recomputed config byte that the preceding `CMD_WRITE_CONFIG` is awaiting.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_DATA, conf);
    }

    // 3. Reset + verify ACK + BAT + device-id. AUX commands ride
    //    behind 0xD4 (WRITE_AUX) per the i8042 spec — every byte
    //    sent to the mouse needs the prefix.
    let mut reporting_ok = aux_reset();

    if reporting_ok {
        // 4a. Set defaults (0xF6) — ACK.
        if !aux_send(psmouse::CMD_SET_DEFAULTS) {
            reporting_ok = false;
        }
    }

    if reporting_ok {
        // 4b. Negotiate the protocol: Synaptics/ALPS vendor probes,
        // a reset to defaults, then the IntelliMouse/Explorer knocks
        // (see `crate::psmouse`). On any failure the device stays a
        // 3-byte standard mouse — the packet parser below keys off
        // the negotiated length, so a failed knock can never
        // corrupt the stream.
        let (hw, proto) = psmouse::negotiate_protocol(&mut AuxTransport);
        psmouse::set_detected(hw, proto);
    }

    if reporting_ok {
        // 4c. Restore the sample rate to 100 (Linux
        // `psmouse_initialize`): the knocks leave it at 80, or 40
        // after the Explorer tilt knock. Best-effort — a missed
        // restore only costs report rate, not correctness.
        let _ = aux_send_param(psmouse::CMD_SET_RATE, psmouse::RESTORE_RATE);
    }

    if reporting_ok {
        // 4d. Enable data reporting (0xF4) — ACK. This flips the
        // mouse from "idle" to "actively sending packets."
        if !aux_send(psmouse::CMD_ENABLE) {
            reporting_ok = false;
        }
    }

    Ok(reporting_ok)
}

/// Bring up the PS/2 mouse channel. Best-effort — most QEMU configs
/// don't expose a PS/2 mouse (USB / virtio-mouse instead), in
/// which case the device-side commands will time out and we
/// proceed without sending PointerEvents.
///
/// # Safety
/// BSP-only at the time of call; assumes `i8042::init` already
/// ran (so the keyboard channel is configured). Concurrent agents
/// driving 0x60/0x64 are forbidden.
pub unsafe fn init() -> Result<(), InitError> {
    if STATE.initialized.load(Ordering::Acquire) {
        return Ok(());
    }

    // 1-4. Enable the AUX channel + reset the mouse + enable reporting.
    // Shared with `resume()`; see `enable_mouse_channel`.
    let reporting_ok = enable_mouse_channel()?;
    let _ = reporting_ok; // tracked via STATE.initialized only; mouse
                          // doesn't have a separate panel atom yet.
    STATE.initialized.store(true, Ordering::Release);

    // Register the PS/2 mouse as an evdev device. Capabilities
    // follow the negotiated protocol: wheel mice advertise
    // `REL_WHEEL`, Explorer mice add `REL_HWHEEL` (4.0 tilt) plus
    // the 4th/5th buttons (`BTN_SIDE`/`BTN_EXTRA`). A Synaptics or
    // ALPS pad detected by the vendor probes keeps its vendor name
    // but reports relative packets until absolute mode lands.
    let proto = psmouse::protocol();
    let hw = psmouse::hardware();
    let name = match (hw, proto) {
        (psmouse::PsmouseHardware::Synaptics, _) => "PS/2 Synaptics TouchPad",
        (psmouse::PsmouseHardware::Alps, _) => "PS/2 ALPS TouchPad",
        (_, psmouse::PsmouseProtocol::IntelliMouse) => "PS/2 Wheel Mouse",
        (_, psmouse::PsmouseProtocol::Explorer | psmouse::PsmouseProtocol::ExplorerTilt) => {
            "PS/2 Explorer Mouse"
        }
        _ => "PS/2 Generic Mouse",
    };
    let mut caps = DeviceCaps::new();
    caps.set_identity(
        name,
        "isa0060/serio1/input0",
        "",
        narf_input::evdev::InputId::new(narf_input::evdev::bus::I8042, 0x0002, 0x0001, 0),
    );
    caps.add_prop(narf_input::evdev::prop::POINTER);
    caps.add_rel(rel::REL_X);
    caps.add_rel(rel::REL_Y);
    caps.add_key(key::BTN_LEFT);
    caps.add_key(key::BTN_RIGHT);
    caps.add_key(key::BTN_MIDDLE);
    match proto {
        psmouse::PsmouseProtocol::IntelliMouse => {
            caps.add_rel(rel::REL_WHEEL);
        }
        psmouse::PsmouseProtocol::Explorer => {
            caps.add_rel(rel::REL_WHEEL);
            caps.add_key(key::BTN_SIDE);
            caps.add_key(key::BTN_EXTRA);
        }
        psmouse::PsmouseProtocol::ExplorerTilt => {
            caps.add_rel(rel::REL_WHEEL);
            caps.add_rel(rel::REL_HWHEEL);
            caps.add_key(key::BTN_SIDE);
            caps.add_key(key::BTN_EXTRA);
        }
        psmouse::PsmouseProtocol::Standard => {}
    }
    let (dev_id, node_arc) = ROUTER.register_device(caps);
    MOUSE_NODE_PTR.store(Arc::as_ptr(&node_arc) as *mut DeviceNode, Ordering::Release);
    *MOUSE_EVDEV_NODE.lock() = Some(node_arc);
    *MOUSE_EVDEV_ID.lock() = Some(dev_id);

    Ok(())
}

// ── Device power management (#770) ─────────────────────────────
//
// The mouse channel is covered by the single "i8042" device-PM
// entry registered by `crate::i8042`; `i8042::pm_resume` calls
// this after re-enabling the keyboard channel.
//
// Resume: drop any partial packet + stale relative deltas (motion +
// wheel — the controller reset below means pre-suspend bytes will
// never complete — a split packet would otherwise wedge the phase
// machine or inject a stale jump), reset the button edge tracker
// (the reset leaves all buttons up; a button still held after
// resume must re-emit its press edge), then re-run the channel
// bring-up `init()` used. No-op when the mouse never
// initialised; the evdev node is NOT re-registered.

/// Re-enable the AUX channel after suspend. No-op when the mouse
/// never initialised.
pub(crate) fn resume() {
    STATE.phase.store(0, Ordering::Release);
    STATE.rel_dx_acc.store(0, Ordering::Release);
    STATE.rel_dy_acc.store(0, Ordering::Release);
    STATE.rel_wheel_acc.store(0, Ordering::Release);
    STATE.rel_hwheel_acc.store(0, Ordering::Release);
    STATE.prev_buttons.store(0, Ordering::Release);
    if !STATE.initialized.load(Ordering::Acquire) {
        return;
    }
    let _ = enable_mouse_channel();
}

/// Return the evdev `DeviceNode` for the PS/2 mouse if registered.
pub fn mouse_evdev_node() -> Option<Arc<DeviceNode>> {
    MOUSE_EVDEV_NODE.lock().clone()
}

/// Unregister the stale mouse node (if any) and clear the probe
/// state, so a fresh `init()` re-probes the AUX channel. Shared
/// by `reprobe()` and the test hook below — this is the half of
/// re-probe that does not touch the I/O ports.
fn drop_stale_registration() {
    if let Some(id) = MOUSE_EVDEV_ID.lock().take() {
        ROUTER.unregister_device(id);
    }
    *MOUSE_EVDEV_NODE.lock() = None;
    MOUSE_NODE_PTR.store(core::ptr::null_mut(), Ordering::Release);
    // A power-cycled mouse forgets any half-assembled packet and
    // any accumulated delta; the fresh probe starts clean.
    STATE.phase.store(0, Ordering::Release);
    STATE.rel_dx_acc.store(0, Ordering::Release);
    STATE.rel_dy_acc.store(0, Ordering::Release);
    STATE.rel_wheel_acc.store(0, Ordering::Release);
    STATE.rel_hwheel_acc.store(0, Ordering::Release);
    STATE.prev_buttons.store(0, Ordering::Release);
    STATE.initialized.store(false, Ordering::Release);
}

/// Re-probe the PS/2 mouse (AUX) channel after boot (issue
/// #771). Same shape as the keyboard hook in `i8042::reprobe`:
/// unregister the stale evdev node first, then re-run the full
/// `init()` probe, which registers a fresh node on success. A
/// failed probe leaves no node behind and leaves `initialized`
/// clear, so a later re-probe can retry.
///
/// # Safety
/// Same contract as `init()`: no other agent concurrently
/// driving the 8042 ports; call from task context, never IRQ
/// context. IRQ 12 is already routed, so a packet byte arriving
/// mid-probe may be consumed by a probe wait (failing that
/// probe step) or decoded normally by the IRQ handler.
pub unsafe fn reprobe() -> Result<(), InitError> {
    drop_stale_registration();
    // SAFETY: same exclusive-port-ownership contract as `init`;
    // the caller upholds it.
    unsafe { init() }
}

/// Test hook: seed a mouse registration the way `init()` does,
/// so fixtures can exercise the re-probe bookkeeping without
/// touching the I/O ports.
#[doc(hidden)]
pub fn __seed_mouse_registration_for_test(id: DeviceId, node: Arc<DeviceNode>) {
    MOUSE_NODE_PTR.store(Arc::as_ptr(&node) as *mut DeviceNode, Ordering::Release);
    *MOUSE_EVDEV_NODE.lock() = Some(node);
    *MOUSE_EVDEV_ID.lock() = Some(id);
}

/// Test hook: run exactly the unregister half of `reprobe()`.
#[doc(hidden)]
pub fn __drop_stale_mouse_registration_for_test() {
    drop_stale_registration();
}

/// Route a decoded packet (`dx`/`dy` motion, wheel deltas, full
/// button state) to the evdev node as one frame. Button `EV_KEY`
/// events are emitted only on press/release edges (compared against
/// `STATE.prev_buttons`) so a held button isn't re-reported every
/// packet. Without this the compositor saw motion but never clicks.
fn dispatch_packet_to_evdev(dx: i32, dy: i32, wheel: i32, hwheel: i32, buttons: PointerButtons) {
    let raw = MOUSE_NODE_PTR.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: `raw` is the `Arc::as_ptr` of the node stored once in `init()`
    // before IRQ 12 is armed; the Arc is held alive in `MOUSE_EVDEV_NODE`,
    // so the pointee outlives this borrow. Non-null checked just above.
    let node_ref: &DeviceNode = unsafe { &*raw };

    // bit0 left, bit1 right, bit2 middle, bit3 side/4th, bit4 extra/5th.
    let mut cur_btn = 0u8;
    if buttons.contains(PointerButtons::LEFT) {
        cur_btn |= 0x01;
    }
    if buttons.contains(PointerButtons::RIGHT) {
        cur_btn |= 0x02;
    }
    if buttons.contains(PointerButtons::MIDDLE) {
        cur_btn |= 0x04;
    }
    if buttons.contains(PointerButtons::SIDE) {
        cur_btn |= 0x08;
    }
    if buttons.contains(PointerButtons::EXTRA) {
        cur_btn |= 0x10;
    }
    let prev_btn = STATE.prev_buttons.swap(cur_btn, Ordering::AcqRel);
    let changed = cur_btn ^ prev_btn;
    let mut changes: [(u16, bool); 5] = [(0, false); 5];
    let mut n = 0;
    if changed & 0x01 != 0 {
        changes[n] = (key::BTN_LEFT, cur_btn & 0x01 != 0);
        n += 1;
    }
    if changed & 0x02 != 0 {
        changes[n] = (key::BTN_RIGHT, cur_btn & 0x02 != 0);
        n += 1;
    }
    if changed & 0x04 != 0 {
        changes[n] = (key::BTN_MIDDLE, cur_btn & 0x04 != 0);
        n += 1;
    }
    if changed & 0x08 != 0 {
        changes[n] = (key::BTN_SIDE, cur_btn & 0x08 != 0);
        n += 1;
    }
    if changed & 0x10 != 0 {
        changes[n] = (key::BTN_EXTRA, cur_btn & 0x10 != 0);
        n += 1;
    }
    dispatch_pointer_wheel_to_node(node_ref, dx, dy, wheel, hwheel, &changes[..n]);
}

/// Shared packet state machine: one byte in, one packet out when
/// the negotiated packet length is reached. Used by BOTH the IRQ
/// handler and the test feed — a single decode path, so a 4-byte
/// packet can never be parsed as 3-byte in one path and 4-byte in
/// the other (that would corrupt the stream, not just fail a test).
fn feed_byte(byte: u8) {
    // Packet length comes from the negotiated protocol (3 standard,
    // 4 IntelliMouse/Explorer). A failed knock leaves it at 3, so
    // a plain mouse can never be mis-parsed as a wheel mouse.
    let len = psmouse::packet_len() as u8;
    let phase = STATE.phase.load(Ordering::Acquire);
    if phase == 0 && (byte & 0x08) == 0 {
        // Sync bit not set — drop until we re-sync.
        return;
    }
    STATE.pkt[phase as usize].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < len {
        STATE.phase.store(next, Ordering::Release);
        return;
    }

    // Packet complete — decode.
    let b0 = STATE.pkt[0].load(Ordering::Acquire);
    let b1 = STATE.pkt[1].load(Ordering::Acquire) as i16;
    let b2 = STATE.pkt[2].load(Ordering::Acquire) as i16;
    let b3 = if len == 4 {
        STATE.pkt[3].load(Ordering::Acquire)
    } else {
        0
    };
    STATE.phase.store(0, Ordering::Release);

    let dx = if b0 & 0x10 != 0 { b1 - 256 } else { b1 } as i32;
    let dy_raw = if b0 & 0x20 != 0 { b2 - 256 } else { b2 } as i32;
    // PS/2 reports +Y as up; our screen convention is +Y is down.
    let dy = -dy_raw;

    let mut buttons = PointerButtons::EMPTY;
    if b0 & 0x01 != 0 {
        buttons.insert(PointerButtons::LEFT);
    }
    if b0 & 0x02 != 0 {
        buttons.insert(PointerButtons::RIGHT);
    }
    if b0 & 0x04 != 0 {
        buttons.insert(PointerButtons::MIDDLE);
    }

    // Wheel / extra buttons from the 4th byte (see `psmouse.rs`
    // for the Linux-grounded decode).
    let (wheel, hwheel) = match psmouse::protocol() {
        psmouse::PsmouseProtocol::IntelliMouse => (psmouse::decode_imps_wheel(b3), 0),
        psmouse::PsmouseProtocol::Explorer | psmouse::PsmouseProtocol::ExplorerTilt => {
            let w = psmouse::decode_imex(b3);
            if w.side {
                buttons.insert(PointerButtons::SIDE);
            }
            if w.extra {
                buttons.insert(PointerButtons::EXTRA);
            }
            (w.wheel, w.hwheel)
        }
        psmouse::PsmouseProtocol::Standard => (0, 0),
    };

    STATE.rel_dx_acc.fetch_add(dx, Ordering::Relaxed);
    STATE.rel_dy_acc.fetch_add(dy, Ordering::Relaxed);
    if wheel != 0 {
        STATE.rel_wheel_acc.fetch_add(wheel, Ordering::Relaxed);
    }
    if hwheel != 0 {
        STATE.rel_hwheel_acc.fetch_add(hwheel, Ordering::Relaxed);
    }
    narf_input::I8042_MOUSE_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);

    // Legacy global ring (for cursor pump / FB status panel).
    let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
    // Wheel scrolls ride the Scroll channel (same shape as the
    // virtio-input `REL_WHEEL` path: `dy` = vertical, `dx` =
    // horizontal), so the cursor pump and the scroll consumer
    // each see exactly the events they own.
    if wheel != 0 || hwheel != 0 {
        let _ = push_global(InputEvent::Scroll(ScrollEvent {
            dx: hwheel,
            dy: wheel,
        }));
    }

    // Evdev routing — motion + wheel + button edges in one frame.
    dispatch_packet_to_evdev(dx, dy, wheel, hwheel, buttons);
}

/// IRQ-12 handler. Reads one byte from 0x60 and feeds it through
/// the shared packet state machine.
///
/// # Safety
/// IRQ context only.
pub unsafe fn on_irq12() {
    // SAFETY: 0x60 data port read.
    let byte = unsafe { inb(PS2_DATA) };
    let irqs = narf_input::I8042_MOUSE_IRQ_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    // Log every 64 IRQs and at IRQ 1 — the user can grep
    // /dev/kmsg to see if PS/2 mouse activity is reaching the
    // ISR. Logging from inside on_irq12 is acceptable because
    // klog's IrqSafeSpinLock is disjoint from the console
    // backend's lock (see klog::record).
    if irqs == 1 || irqs % 64 == 0 {
        use core::fmt::Write as _;
        let pkts = narf_input::I8042_MOUSE_PACKET_COUNT.load(Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "  i8042-mouse: irqs={} packets={}",
            irqs,
            pkts
        );
    }

    feed_byte(byte);
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATE.phase.store(0, Ordering::Release);
    STATE.rel_dx_acc.store(0, Ordering::Release);
    STATE.rel_dy_acc.store(0, Ordering::Release);
    STATE.rel_wheel_acc.store(0, Ordering::Release);
    STATE.rel_hwheel_acc.store(0, Ordering::Release);
    STATE.prev_buttons.store(0, Ordering::Release);
    psmouse::set_detected(
        psmouse::PsmouseHardware::Generic,
        psmouse::PsmouseProtocol::Standard,
    );
    // Seeded registrations are fixture-owned (see the kbd hook);
    // clear the cached pointer so a later packet test cannot
    // dispatch into a fixture node.
    MOUSE_NODE_PTR.store(core::ptr::null_mut(), Ordering::Release);
    *MOUSE_EVDEV_NODE.lock() = None;
    *MOUSE_EVDEV_ID.lock() = None;
}

/// Test-only: force the negotiated protocol (lets packet fixtures
/// feed 4-byte packets without a device). Restored to `Standard`
/// by `__reset_for_test`.
pub fn set_protocol_for_test(proto: psmouse::PsmouseProtocol) {
    psmouse::set_protocol_for_test(proto);
}

/// Test-only synthetic packet feed: same logic as the IRQ handler
/// but bypasses port reads. Each call pushes one byte through the
/// state machine, exactly like a real IRQ would.
pub fn feed_byte_for_test(byte: u8) {
    feed_byte(byte);
}
