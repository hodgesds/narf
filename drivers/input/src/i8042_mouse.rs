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
//! Elantech absolute packets (after the magic knock + firmware
//! signature in `crate::psmouse::detect_elantech`, which also
//! enables absolute mode via the register writes in
//! `elantech_set_absolute_mode`):
//!
//! ```
//!   v1 — 4 bytes: byte 0 finger count + parity bits + buttons,
//!     byte 1 high coordinate bits, bytes 2/3 low X/Y.
//!   v2/v3/v4 — 6 bytes: byte 0 finger count (+ traces for v4),
//!     bytes 1/2 X (+ pressure high nibble), byte 3 width /
//!     packet-type bits, bytes 4/5 Y (+ pressure low nibble).
//!     v3 two-finger reports arrive as head + tail packet pairs;
//!     v4 adds per-finger head packets, delta motion packets,
//!     and status packets (finger bitmap). See `psmouse.rs` for
//!     the Linux-grounded layouts and the per-version checks.
//! ```
//!
//! Elantech packets have no `0x08` sync bit in byte 0, so the
//! relative path's resync rule does not apply to them — validity
//! comes from the per-version packet checks instead, and an
//! invalid packet is dropped whole (`PSMOUSE_BAD_DATA`).
//! Decoded frames ride the global ring as `AbsoluteEvent`
//! (`ABS_X`/`ABS_Y`, primary contact) + per-slot `TouchEvent`s,
//! and the evdev node as one protocol-B MT frame per packet.
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
//!      Synaptics/ALPS/Elantech vendor probes, a reset to defaults,
//!      then the IntelliMouse/Explorer knocks. On failure the
//!      device stays a 3-byte standard mouse. An Elantech match
//!      returns before the reset/knocks, with absolute mode
//!      already enabled.
//!   5. Restore the sample rate to 100 (the knocks leave it at 80,
//!      or 40 after the Explorer tilt knock; Linux
//!      `psmouse_initialize` does the same). The restore is skipped
//!      for Elantech — a rate set loses register 0x07 on v4 hardware
//!      (Linux `elantech_set_rate_restore_reg_07`).
//! ALPS absolute mode (`crate::alps`): once a pad is identified
//! (see `alps::probe_alps` — the probe itself lives with the
//! vendor negotiation in `psmouse`, landed in #1676) the packet
//! length becomes 6 bytes (8 for v4) and complete packets are
//! decoded by `alps::AlpsDecoder`. Touchpad reports ride the
//! global ring as `TouchEvent`s (one per live slot, with `Down` /
//! `Move` / `Up` state) plus single-touch `AbsoluteEvent`s, and
//! evdev via the slot-protocol-B emitter (`MtEvdevState`).
//! Trackstick and bare-PS/2 packets ride the relative
//! `PointerEvent` path. Activation is explicit
//! (`set_alps_protocol`); until then the 3-byte path below is
//! byte-for-byte the old behaviour. Wiring `alps::probe_alps`
//! into `psmouse::negotiate_protocol` so the negotiated model
//! selects the decoder is a follow-up (see the PR body).
//!   6. Synaptics absolute-mode enablement (`crate::psmouse`):
//!      detect (4x SETRES(0) + GETINFO, byte 0x47), query the
//!      hardware (identify/model/firmware/board/capability/
//!      resolution), then set the absolute mode byte (ABSOLUTE +
//!      HIGH_RATE + W_MODE + DISABLE_GESTURE, committed with
//!      SETRATE 0x14). Only attempted when the negotiated hardware
//!      is Synaptics — an Elantech match claims the device outright
//!      and must see no further probes. On success the pad streams
//!      6-byte absolute packets; on any failure it stays a 3-byte
//!      relative mouse.
//!   7. Send 0xD4 + 0xF4 (enable data reporting). This flips the
//!      mouse from "idle" to "actively sending packets" — for a
//!      negotiated Synaptics pad, the 6-byte absolute stream.
//!
//! A negotiated Synaptics pad reports absolute finger position
//! (`ABS_X` / `ABS_Y` / `ABS_PRESSURE` + `BTN_TOUCH`, Linux
//! `synaptics_process_packet` semantics: BTN_TOUCH hysteresis
//! `z > 30` on / `z < 25` off, X/Y only when `z > 0 && x > 1`).
//! The legacy global ring still gets pixel-scale relative deltas
//! derived from successive absolute samples (same shape as the
//! virtio-tablet `abs_to_px` bridge), and the absolute cursor
//! position is published via `set_cursor_abs_px` so the kernel
//! cursor sits at the true finger position.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{
    abs,
    btn::{BTN_TOOL_DOUBLETAP, BTN_TOOL_QUADTAP, BTN_TOOL_TRIPLETAP},
    evdev::{
        dispatch_key_to_node, dispatch_pointer_wheel_to_node, dispatch_synaptics_abs_to_node, key,
        prop, rel, DeviceCaps, DeviceId, DeviceNode, MtContactUpdate, MtEvdevState, ROUTER,
    },
    push_global, scanout_dims, set_cursor_abs_px, AbsoluteEvent, AxisInfo, InputEvent,
    PointerButtons, PointerEvent, ScrollEvent, TouchEvent, TouchState,
};

extern crate alloc;
use alloc::sync::Arc;

use crate::alps::{self, AlpsDecode, AlpsDecoder, AlpsEvent, AlpsFields, AlpsProtocol};
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
    /// Bytes 0..=7 of the in-flight packet. `phase` tracks how many
    /// bytes we've collected. When phase reaches the negotiated
    /// packet length (3 standard, 4 IntelliMouse/Explorer/Elantech
    /// v1, 6 Synaptics absolute / Elantech v2–v4 / ALPS, 8 ALPS v4
    /// — see `crate::psmouse::packet_len` and
    /// `alps::AlpsDecoder::packet_len`), we emit the PointerEvent /
    /// ScrollEvent / absolute frame + reset to 0.
    pkt: [AtomicU8; 8],
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
    /// Last finger-down absolute position in scanout pixels (for the
    /// legacy relative bridge); `i32::MIN` = no sample yet.
    prev_abs_px: AtomicI32,
    prev_abs_py: AtomicI32,
    /// BTN_TOUCH hysteresis state (Linux `synaptics_process_packet`:
    /// asserts when `z > 30`, releases when `z < 25`).
    touch_pressed: core::sync::atomic::AtomicBool,
    /// Streaming Synaptics packet type, as a
    /// [`psmouse::SynapticsPktType`] discriminant (0=NewAbs,
    /// 1=Strict, 2=Relaxed, 3=OldAbs). Starts as
    /// `SynapticsPktType::initial(newabs)`; a NEWABS pad is
    /// classified strict/relaxed from its first full packet
    /// (Linux `synaptics_detect_pkt_type`).
    syn_pkt_type: AtomicU8,
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
            prev_abs_px: AtomicI32::new(i32::MIN),
            prev_abs_py: AtomicI32::new(i32::MIN),
            touch_pressed: core::sync::atomic::AtomicBool::new(false),
            syn_pkt_type: AtomicU8::new(0),
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

/// Elantech decode state (v3 head stash, v4 finger slots, v1
/// jumpy-cursor counter). Only ever taken on the IRQ/test feed
/// path, so IRQ context is safe.
static ELANTECH_STATE: narf_lib::sync::IrqSafeSpinLock<psmouse::ElantechState> =
    narf_lib::sync::IrqSafeSpinLock::new(psmouse::ElantechState::new());
/// Previous Elantech touch slots, for `TouchEvent` Down/Move/Up
/// derivation on the global ring.
static ELANTECH_PREV: narf_lib::sync::IrqSafeSpinLock<[psmouse::ElantechSlot; 5]> =
    narf_lib::sync::IrqSafeSpinLock::new([psmouse::ElantechSlot::new(); 5]);
/// Evdev protocol-B MT emitter for the Elantech pad (5 slots).
/// Created in `init()` once the protocol is known; `None` in
/// tests that only force the protocol (global-ring assertions
/// still run there).
static ELANTECH_MT: narf_lib::sync::IrqSafeSpinLock<Option<MtEvdevState>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
// ── ALPS absolute-mode state ────────────────────────────────────────────────

/// Default protocol for the inert decoder (v3, first-byte check
/// `0x8f/0x8f`, no flags). Only used while ALPS is inactive;
/// [`set_alps_protocol`] replaces it with the negotiated model.
const ALPS_DEFAULT_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: alps::AlpsVersion::V3,
    byte0: 0x8f,
    mask0: 0x8f,
    flags: 0,
};

/// ALPS IRQ state, held behind one lock. The packet bytes
/// themselves live in [`State::pkt`] (atomics, shared with the
/// 3-byte path); everything ALPS-specific — the decoder's
/// multi-packet state, the evdev MT emitter, the previous
/// TouchEvent slots — lives here.
///
/// Locking: the feed path takes this lock only while ALPS is
/// active, and only to decode a completed packet and compute
/// its output actions. The computed global-ring events are
/// pushed after the lock is dropped (the ring takes its own
/// lock); the evdev dispatch runs under this lock because the
/// MT emitter state lives here. No other code takes this lock
/// while holding a ring or node lock, so the order is acyclic.
#[derive(Debug)]
struct AlpsState {
    /// An ALPS protocol is active (set by
    /// [`set_alps_protocol`], cleared by
    /// [`clear_alps_protocol`] / [`__reset_for_test`]).
    active: bool,
    /// Packet decoder for the negotiated protocol.
    decoder: AlpsDecoder,
    /// Slot-protocol-B evdev emitter (created on activation).
    mt: Option<MtEvdevState>,
    /// Bitmask of TouchEvent slots live in the previous frame.
    prev_slots: u8,
    /// Last reported position per slot (Up events reuse it —
    /// Linux reports no position on a lift).
    prev_pos: [(i32, i32); 4],
    /// Touchpad button bitmask in the previous frame
    /// (`PointerButtons` bits: left/right/middle/forward/back),
    /// so the ring PointerEvent is pushed on change only and
    /// the middle-button evdev edge is derived from it.
    prev_buttons: u8,
    /// Stashed 6-byte packet awaiting its 3 interleaved
    /// extension bytes (v2 `ALPS_PS2_INTERLEAVED` only).
    pending_interleaved: Option<[u8; 6]>,
    /// Extension bytes collected so far.
    ext: [u8; 3],
    /// Extension bytes collected (0..3).
    ext_phase: u8,
    /// Collecting interleaved extension bytes.
    extending: bool,
    /// This packet's byte 3 triggered the interleave path, so
    /// the remaining bytes skip the high-bit validation (Linux
    /// `alps_process_byte` checks the interleave before the
    /// validation — the stuffed PS/2 dx/dy bytes may have bit 7
    /// set).
    interleaved_collecting: bool,
    /// The byte at phase 0 started a bare 3-byte PS/2 packet
    /// from the pass-through port (`ALPS_PASS` devices, never
    /// v8 — Linux cannot distinguish a v8 first byte from a
    /// PS/2 packet's).
    bare_candidate: bool,
}

impl AlpsState {
    const fn new() -> Self {
        AlpsState {
            active: false,
            decoder: AlpsDecoder::new(ALPS_DEFAULT_PROTOCOL),
            mt: None,
            prev_slots: 0,
            prev_pos: [(0, 0); 4],
            prev_buttons: 0,
            pending_interleaved: None,
            ext: [0; 3],
            ext_phase: 0,
            extending: false,
            interleaved_collecting: false,
            bare_candidate: false,
        }
    }

    fn reset(&mut self) {
        self.active = false;
        self.decoder = AlpsDecoder::new(ALPS_DEFAULT_PROTOCOL);
        self.mt = None;
        self.prev_slots = 0;
        self.prev_pos = [(0, 0); 4];
        self.prev_buttons = 0;
        self.pending_interleaved = None;
        self.ext = [0; 3];
        self.ext_phase = 0;
        self.extending = false;
        self.interleaved_collecting = false;
        self.bare_candidate = false;
    }
}

static ALPS: narf_lib::sync::IrqSafeSpinLock<AlpsState> =
    narf_lib::sync::IrqSafeSpinLock::new(AlpsState::new());

/// Whether an ALPS protocol is active (cheap atomic check for
/// the per-byte feed path; the full state lives in [`ALPS`]).
static ALPS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Activate ALPS absolute mode for a negotiated protocol.
/// `dev_id` is the pad's E7 signature (selects the SS4-Plus
/// v8 multi-finger macros). The packet length becomes 6 (8 for
/// v4) from the next byte; any partial 3-byte packet is
/// discarded. Called once from the probe/negotiation path
/// (after `alps::probe_alps` + `alps::enter_absolute_mode`
/// succeed) and by tests.
pub fn set_alps_protocol(protocol: AlpsProtocol, dev_id: [u8; 3]) {
    STATE.phase.store(0, Ordering::Release);
    let mut alps = ALPS.lock();
    alps.reset();
    alps.active = true;
    alps.decoder = AlpsDecoder::with_dev_id(protocol, dev_id);
    alps.mt = Some(MtEvdevState::new(4));
    ALPS_ACTIVE.store(true, Ordering::Release);
}

/// Deactivate ALPS absolute mode (back to 3-byte packets).
pub fn clear_alps_protocol() {
    STATE.phase.store(0, Ordering::Release);
    ALPS.lock().reset();
    ALPS_ACTIVE.store(false, Ordering::Release);
}

/// The active ALPS protocol, if any.
pub fn alps_protocol() -> Option<AlpsProtocol> {
    if ALPS_ACTIVE.load(Ordering::Acquire) {
        Some(ALPS.lock().decoder.protocol)
    } else {
        None
    }
}

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
/// Used by `psmouse::negotiate_protocol` and
/// `psmouse::synaptics_enable_absolute` during `init()`.
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
/// protocol, restore the sample rate, attempt Synaptics absolute-mode
/// enablement, enable data reporting.
/// Returns whether the mouse is reporting — best effort: a system
/// without a PS/2 mouse returns `false`, not an error. A timeout
/// in the controller-side config exchange is an `Err`, matching
/// `init()`.
///
/// Shared verbatim by `init()` (steps 1-7) and `resume()` (#770):
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
        // 4a. Set defaults (0xF6) — ACK. This also clears the
        // Absolute mode bit (Guide §2.5), so the pad is in
        // relative mode for the negotiation below.
        if !aux_send(psmouse::CMD_SET_DEFAULTS) {
            reporting_ok = false;
        }
    }

    if reporting_ok {
        // 4b. Negotiate the protocol: Synaptics/ALPS/Elantech
        // vendor probes, a reset to defaults, then the
        // IntelliMouse/Explorer knocks (see `crate::psmouse`). On
        // any failure the device stays a 3-byte standard mouse —
        // the packet parser below keys off the negotiated length,
        // so a failed knock can never corrupt the stream. An
        // Elantech match returns before the reset/knocks, with
        // absolute mode already enabled.
        let (hw, proto) = psmouse::negotiate_protocol(&mut AuxTransport);
        psmouse::set_detected(hw, proto);
    }

    if reporting_ok {
        // 4c. Restore the sample rate to 100 (Linux
        // `psmouse_initialize`): the knocks leave it at 80, or 40
        // after the Explorer tilt knock. Best-effort — a missed
        // restore only costs report rate, not correctness.
        // Skipped for Elantech: a rate set loses register 0x07 on
        // v4 hardware (Linux `elantech_set_rate_restore_reg_07`
        // exists for exactly this reason), and absolute mode does
        // not need a 100 Hz sample rate.
        let proto = psmouse::protocol();
        if !matches!(
            proto,
            psmouse::PsmouseProtocol::ElantechV1 | psmouse::PsmouseProtocol::Elantech
        ) {
            let _ = aux_send_param(psmouse::CMD_SET_RATE, psmouse::RESTORE_RATE);
        }
    }

    if reporting_ok && psmouse::hardware() == psmouse::PsmouseHardware::Synaptics {
        // 4d. Synaptics absolute-mode enablement (see
        // `crate::psmouse`): detect, query, mode set. Must run
        // while reporting is still disabled and before the 0xF4
        // enable below. Only attempted on a negotiated Synaptics
        // pad — an Elantech match claims the device outright and
        // must see no further probes. On any failure the pad stays
        // a 3-byte relative mouse — the packet parser keys off the
        // negotiated length, so a failed enablement can never
        // corrupt the stream.
        match psmouse::synaptics_enable_absolute(&mut AuxTransport, psmouse::SYNAPTICS_RATE) {
            Ok(hw) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  i8042-mouse: Synaptics pad: model {:#08x} fw {:#08x} caps {:#08x} mode {:#04x}",
                    hw.model_id, hw.firmware_id, hw.capabilities, hw.mode,
                );
                psmouse::set_detected(
                    psmouse::PsmouseHardware::Synaptics,
                    psmouse::PsmouseProtocol::SynapticsAbsolute,
                );
                STATE.syn_pkt_type.store(
                    psmouse::SynapticsPktType::initial(hw.newabs) as u8,
                    Ordering::Release,
                );
            }
            Err(e) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  i8042-mouse: Synaptics enablement failed ({:?}); staying relative",
                    e,
                );
            }
        }
    }

    if reporting_ok {
        // 4e. Enable data reporting (0xF4) — ACK. This flips the
        // mouse from "idle" to "actively sending packets" — for a
        // negotiated Synaptics pad, the 6-byte absolute stream.
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
    // follow the negotiated protocol: a Synaptics pad in absolute
    // mode advertises ABS_X/ABS_Y (nominal ranges — the queried
    // min/max are a later refinement) + ABS_PRESSURE + BTN_TOUCH
    // + BTN_LEFT/RIGHT (Linux `set_input_params`); wheel mice
    // advertise `REL_WHEEL`, Explorer mice add `REL_HWHEEL`
    // (4.0 tilt) plus the 4th/5th buttons (`BTN_SIDE`/`BTN_EXTRA`).
    // A Synaptics or ALPS pad detected by the vendor probes keeps
    // its vendor name; an Elantech pad reports absolute packets
    // (`ABS_X`/`ABS_Y` + protocol-B MT slots) and no relative axes
    // at all.
    let proto = psmouse::protocol();
    let hw = psmouse::hardware();
    let absolute = proto == psmouse::PsmouseProtocol::SynapticsAbsolute;
    let is_elantech = matches!(
        proto,
        psmouse::PsmouseProtocol::ElantechV1 | psmouse::PsmouseProtocol::Elantech
    );
    let mut caps = DeviceCaps::new();
    if absolute {
        caps.set_identity(
            "PS/2 Synaptics TouchPad",
            "isa0060/serio1/input0",
            "",
            narf_input::evdev::InputId::new(narf_input::evdev::bus::I8042, 0x0002, 0x0001, 0),
        );
        caps.add_prop(narf_input::evdev::prop::POINTER);
        caps.add_abs_info(
            abs::ABS_X,
            AxisInfo {
                min: psmouse::SYN_X_MIN_NOMINAL,
                max: psmouse::SYN_X_MAX_NOMINAL,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
        );
        caps.add_abs_info(
            abs::ABS_Y,
            AxisInfo {
                min: psmouse::SYN_Y_MIN_NOMINAL,
                max: psmouse::SYN_Y_MAX_NOMINAL,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
        );
        caps.add_abs_info(
            abs::ABS_PRESSURE,
            AxisInfo {
                min: 0,
                max: 255,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
        );
        caps.add_key(key::BTN_LEFT);
        caps.add_key(key::BTN_RIGHT);
        caps.add_key(key::BTN_TOUCH);
    } else {
        let name = match (hw, proto) {
            (psmouse::PsmouseHardware::Elantech, _) => "PS/2 Elantech TouchPad",
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
        if !is_elantech {
            caps.add_rel(rel::REL_X);
            caps.add_rel(rel::REL_Y);
        }
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
            // Elantech absolute caps are declared in the `is_elantech`
            // block just below (ABS_X/Y + MT slots, no REL axes).
            psmouse::PsmouseProtocol::ElantechV1 | psmouse::PsmouseProtocol::Elantech => {}
        }
        if is_elantech {
            // Absolute axes + protocol-B MT slots, same shape as the
            // I2C-HID touch driver (`add_mt_axes`): `ABS_X`/`ABS_Y`
            // span the negotiated device ranges, `ABS_MT_SLOT` spans
            // the 5 v4 slots, and pressure/width ride only when the
            // firmware reports them.
            if let Some(info) = psmouse::elantech_info() {
                let axis = |max: u32| AxisInfo {
                    min: 0,
                    max: max as i32,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
                caps.add_abs_info(abs::ABS_X, axis(info.x_max));
                caps.add_abs_info(abs::ABS_Y, axis(info.y_max));
                caps.add_abs_info(abs::ABS_MT_SLOT, axis(4));
                caps.add_abs_info(abs::ABS_MT_TRACKING_ID, axis(0xFFFF));
                caps.add_abs_info(abs::ABS_MT_POSITION_X, axis(info.x_max));
                caps.add_abs_info(abs::ABS_MT_POSITION_Y, axis(info.y_max));
                if info.reports_pressure {
                    let pressure = axis(255);
                    caps.add_abs_info(abs::ABS_PRESSURE, pressure);
                    caps.add_abs_info(abs::ABS_TOOL_WIDTH, axis(15));
                    caps.add_abs_info(abs::ABS_MT_PRESSURE, pressure);
                }
                caps.add_key(key::BTN_TOUCH);
                caps.add_key(key::BTN_TOOL_FINGER);
                caps.add_key(BTN_TOOL_DOUBLETAP);
                caps.add_key(BTN_TOOL_TRIPLETAP);
                if info.hw_version >= 2 {
                    caps.add_key(BTN_TOOL_QUADTAP);
                }
                if info.buttonpad {
                    caps.add_prop(prop::BUTTONPAD);
                }
                *ELANTECH_MT.lock() = Some(MtEvdevState::new(5));
            }
        }
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
    STATE.prev_abs_px.store(i32::MIN, Ordering::Release);
    STATE.prev_abs_py.store(i32::MIN, Ordering::Release);
    STATE.touch_pressed.store(false, Ordering::Release);
    STATE.syn_pkt_type.store(0, Ordering::Release);
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

/// Route a decoded Synaptics absolute packet to the evdev node
/// as one frame: ABS_X/ABS_Y (when `moved`), ABS_PRESSURE,
/// BTN_TOUCH on hysteresis edges, BTN_LEFT/RIGHT on press/release
/// edges, one SYN_REPORT (via `dispatch_synaptics_abs_to_node`).
fn dispatch_absolute_to_evdev(
    hw: &psmouse::SynapticsHwState,
    y_inv: i32,
    moved: bool,
    touch: Option<bool>,
) {
    let raw = MOUSE_NODE_PTR.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: `raw` is the `Arc::as_ptr` of the node stored once in `init()`
    // before IRQ 12 is armed (or by `__set_evdev_node_for_test`, which keeps
    // the Arc alive in `MOUSE_EVDEV_NODE`); the Arc is held alive, so the
    // pointee outlives this borrow. Non-null checked just above.
    let node_ref: &DeviceNode = unsafe { &*raw };

    let cur_btn = (if hw.left { 0x01 } else { 0 }) | (if hw.right { 0x02 } else { 0 });
    let prev_btn = STATE.prev_buttons.swap(cur_btn, Ordering::AcqRel);
    let changed = cur_btn ^ prev_btn;
    let mut changes: [(u16, bool); 2] = [(0, false); 2];
    let mut n = 0;
    if changed & 0x01 != 0 {
        changes[n] = (key::BTN_LEFT, cur_btn & 0x01 != 0);
        n += 1;
    }
    if changed & 0x02 != 0 {
        changes[n] = (key::BTN_RIGHT, cur_btn & 0x02 != 0);
        n += 1;
    }
    dispatch_synaptics_abs_to_node(
        node_ref,
        hw.x,
        y_inv,
        hw.z as i32,
        moved,
        touch,
        &changes[..n],
    );
}

/// Map an absolute sample onto the on-screen pixel `span` of its
/// axis using the advertised range (virtio-tablet `abs_to_px`
/// shape: clamp into the range, then scale linearly).
fn syn_abs_to_px(v: i32, min: i32, max: i32, span: i64) -> i32 {
    if max > min {
        (((v.clamp(min, max) - min) as i64 * span) / (max - min) as i64) as i32
    } else {
        0
    }
}

/// Decode a completed 6-byte Synaptics absolute packet (Linux
/// `synaptics_process_packet`, single-finger path): evdev ABS +
/// BTN_TOUCH + buttons, plus the legacy relative bridge.
fn decode_absolute_packet() {
    let mut buf = [0u8; 6];
    for (i, slot) in STATE.pkt.iter().take(6).enumerate() {
        buf[i] = slot.load(Ordering::Acquire);
    }
    let mut pkt_type =
        psmouse::SynapticsPktType::from_u8(STATE.syn_pkt_type.load(Ordering::Acquire));
    // The first full NEWABS packet classifies the pad as strict
    // or relaxed (Linux `synaptics_detect_pkt_type`).
    if pkt_type == psmouse::SynapticsPktType::NewAbs {
        pkt_type = psmouse::synaptics_detect_pkt_type(&buf);
        STATE.syn_pkt_type.store(pkt_type as u8, Ordering::Release);
    }
    let hw = match pkt_type {
        psmouse::SynapticsPktType::OldAbs => psmouse::decode_synaptics_oldabs(&buf),
        _ => psmouse::decode_synaptics_newabs(&buf),
    };
    // X/Y are reported only for a real finger (Linux:
    // `hw.z > 0 && hw.x > 1`); pressure, touch and buttons are
    // reported on every packet.
    let moved = hw.z > 0 && hw.x > 1;
    let y_inv = psmouse::synaptics_invert_y(hw.y);

    // BTN_TOUCH hysteresis: asserts when `z > 30`, releases
    // when `z < 25`; between the thresholds the state holds.
    let touch_change = if hw.z > psmouse::SYN_TOUCH_ON_Z {
        if STATE.touch_pressed.swap(true, Ordering::AcqRel) {
            None
        } else {
            Some(true)
        }
    } else if hw.z < psmouse::SYN_TOUCH_OFF_Z {
        if STATE.touch_pressed.swap(false, Ordering::AcqRel) {
            Some(false)
        } else {
            None
        }
    } else {
        None
    };

    dispatch_absolute_to_evdev(&hw, y_inv, moved, touch_change);
    narf_input::I8042_MOUSE_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);

    // Legacy bridge (virtio-tablet shape): map the absolute
    // sample onto scanout pixels and publish the true cursor
    // position; the delta between successive pixel samples
    // keeps the legacy ring / rel accumulator moving at pixel
    // scale instead of raw pad units. No scanout yet (dims 0) →
    // skip the bridge for this frame; evdev above already
    // carried the absolute position.
    if moved {
        let (scan_w, scan_h) = scanout_dims();
        if scan_w != 0 && scan_h != 0 {
            let px = syn_abs_to_px(
                hw.x,
                psmouse::SYN_X_MIN_NOMINAL,
                psmouse::SYN_X_MAX_NOMINAL,
                scan_w as i64,
            )
            .clamp(0, scan_w.saturating_sub(1) as i32);
            let py = syn_abs_to_px(
                y_inv,
                psmouse::SYN_Y_MIN_NOMINAL,
                psmouse::SYN_Y_MAX_NOMINAL,
                scan_h as i64,
            )
            .clamp(0, scan_h.saturating_sub(1) as i32);
            set_cursor_abs_px(px as u32, py as u32);
            let prev_x = STATE.prev_abs_px.swap(px, Ordering::AcqRel);
            let prev_y = STATE.prev_abs_py.swap(py, Ordering::AcqRel);
            if prev_x != i32::MIN && prev_y != i32::MIN {
                let dx = px - prev_x;
                let dy = py - prev_y;
                let mut buttons = PointerButtons::EMPTY;
                if hw.left {
                    buttons.insert(PointerButtons::LEFT);
                }
                if hw.right {
                    buttons.insert(PointerButtons::RIGHT);
                }
                STATE.rel_dx_acc.fetch_add(dx, Ordering::Relaxed);
                STATE.rel_dy_acc.fetch_add(dy, Ordering::Relaxed);
                let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
            }
        }
    } else {
        // Finger lifted: the next touchdown starts a fresh
        // stroke so the cursor cannot jump across the pad.
        STATE.prev_abs_px.store(i32::MIN, Ordering::Release);
        STATE.prev_abs_py.store(i32::MIN, Ordering::Release);
    }
}

/// Shared packet state machine: one byte in, one packet out when
/// the negotiated packet length is reached. Used by BOTH the IRQ
/// handler and the test feed — a single decode path, so a 4-byte
/// packet can never be parsed as 3-byte in one path and 4-byte in
/// the other (that would corrupt the stream, not just fail a test).
/// Elantech absolute packets take their own branch: byte 0 carries
/// finger counts / traces / parity, not the PS/2 sync bit, so the
/// `0x08` resync below would drop live v2/v3/v4 packets.
/// ALPS absolute packets take the first branch while an ALPS
/// protocol is active; everything else is the relative path.
/// Synaptics absolute packets take their own branch too: bytes
/// 0..=4 are validated per packet type and a bad byte drops the
/// partial packet (Linux `synaptics_validate_byte`).
fn feed_byte(byte: u8) {
    if ALPS_ACTIVE.load(Ordering::Acquire) {
        feed_byte_alps(byte);
    } else {
        match psmouse::protocol() {
            psmouse::PsmouseProtocol::ElantechV1 | psmouse::PsmouseProtocol::Elantech => {
                feed_elantech_byte(byte)
            }
            psmouse::PsmouseProtocol::SynapticsAbsolute => feed_synaptics_byte(byte),
            _ => feed_relative_byte(byte),
        }
    }
}

/// Synaptics absolute-packet feed: collect 6 bytes, validating
/// bytes 0..=4 per current packet type (Linux
/// `synaptics_validate_byte`, idx 0..=4) and dropping the partial
/// packet on the first bad byte; then decode.
fn feed_synaptics_byte(byte: u8) {
    let phase = STATE.phase.load(Ordering::Acquire) as usize;
    if phase <= 4 {
        let mut probe = [0u8; 6];
        for (i, slot) in STATE.pkt.iter().take(6).enumerate() {
            probe[i] = slot.load(Ordering::Acquire);
        }
        probe[phase] = byte;
        let pkt_type =
            psmouse::SynapticsPktType::from_u8(STATE.syn_pkt_type.load(Ordering::Acquire));
        if !psmouse::synaptics_validate_byte(&probe, phase, pkt_type) {
            STATE.phase.store(0, Ordering::Release);
            return;
        }
    }
    STATE.pkt[phase].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < 6 {
        STATE.phase.store(next as u8, Ordering::Release);
        return;
    }
    STATE.phase.store(0, Ordering::Release);
    decode_absolute_packet();
}

/// Elantech absolute-packet feed: collect `packet_len` bytes with
/// no sync-bit filtering, then run the per-version packet check
/// and decode (Linux `elantech_process_byte`). An invalid packet
/// is dropped and the phase resets (`PSMOUSE_BAD_DATA`); a
/// debounce packet is ignored whole; a v3 head packet only
/// stashes its finger and produces no frame yet.
fn feed_elantech_byte(byte: u8) {
    let len = psmouse::packet_len() as u8;
    let phase = STATE.phase.load(Ordering::Acquire);
    STATE.pkt[phase as usize].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < len {
        STATE.phase.store(next, Ordering::Release);
        return;
    }
    STATE.phase.store(0, Ordering::Release);
    let mut raw = [0u8; 6];
    for (i, b) in raw.iter_mut().enumerate().take(len as usize) {
        *b = STATE.pkt[i].load(Ordering::Acquire);
    }
    let Some(info) = psmouse::elantech_info() else {
        return;
    };
    let frame = {
        let mut state = ELANTECH_STATE.lock();
        match psmouse::protocol() {
            psmouse::PsmouseProtocol::ElantechV1 => {
                let p4 = [raw[0], raw[1], raw[2], raw[3]];
                if !psmouse::elantech_packet_check_v1(&p4, info.fw_version) {
                    return;
                }
                psmouse::decode_elantech_v1(
                    &mut state,
                    &p4,
                    info.fw_version,
                    info.y_max,
                    info.jumpy_cursor,
                )
            }
            _ => {
                if info.hw_version == 2 {
                    // Ignore debounce.
                    if psmouse::elantech_is_debounce_v2(&raw) {
                        return;
                    }
                    if !psmouse::elantech_packet_check_v2(&raw, info.reports_pressure) {
                        return;
                    }
                    Some(psmouse::decode_elantech_v2(&mut state, &raw, info.y_max))
                } else if info.hw_version == 3 {
                    match psmouse::elantech_packet_check_v3(&raw, info.crc_enabled) {
                        psmouse::ElantechPacket::Unknown
                        | psmouse::ElantechPacket::Debounce
                        | psmouse::ElantechPacket::Trackpoint => return,
                        t => psmouse::decode_elantech_v3(
                            &mut state,
                            &raw,
                            t,
                            info.y_max,
                            info.buttonpad,
                        ),
                    }
                } else {
                    match psmouse::elantech_packet_check_v4(
                        &raw,
                        info.crc_enabled,
                        info.fw_version,
                        info.samples_1,
                        info.has_trackpoint,
                    ) {
                        psmouse::ElantechPacket::Unknown | psmouse::ElantechPacket::Trackpoint => {
                            return
                        }
                        t => psmouse::decode_elantech_v4(
                            &mut state,
                            &raw,
                            t,
                            info.y_max,
                            info.width,
                            info.buttonpad,
                        ),
                    }
                }
            }
        }
    };
    let Some(frame) = frame else {
        return;
    };
    narf_input::I8042_MOUSE_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
    dispatch_elantech_frame(&frame, &info);
}

/// Route one decoded Elantech frame: absolute X/Y for the primary
/// contact plus per-slot `TouchEvent`s (Down/Move/Up from the
/// previous frame) on the global ring, and one protocol-B MT frame
/// on the evdev node (`ABS_X`/`ABS_Y` follow the lowest live slot,
/// `BTN_TOUCH` tracks any contact, integrated buttons ride as
/// `BTN_LEFT`/`BTN_RIGHT` edges — `MtEvdevState` owns those wire
/// rules; a no-change frame emits nothing there).
fn dispatch_elantech_frame(frame: &psmouse::ElantechFrame, info: &psmouse::ElantechInfo) {
    if frame.fingers != 0 {
        let primary = frame.slots[0];
        let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_X,
            value: primary.x as i32,
        }));
        let _ = push_global(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_Y,
            value: primary.y as i32,
        }));
    }
    let mut prev = ELANTECH_PREV.lock();
    for (slot, s) in frame.slots.iter().enumerate() {
        let was = prev[slot].active;
        let state = match (was, s.active) {
            (false, true) => Some(TouchState::Down),
            (true, true) => Some(TouchState::Move),
            (true, false) => Some(TouchState::Up),
            (false, false) => None,
        };
        if let Some(state) = state {
            // A release reports the last known position.
            let (x, y) = if s.active {
                (s.x, s.y)
            } else {
                (prev[slot].x, prev[slot].y)
            };
            let _ = push_global(InputEvent::Touch(TouchEvent {
                slot: slot as u8,
                tracking_id: if s.active { Some(slot as i32) } else { None },
                id: slot as u16,
                x: x as i32,
                y: y as i32,
                pressure: if info.reports_pressure {
                    s.pressure as i32
                } else {
                    0
                },
                state,
            }));
        }
    }
    *prev = frame.slots;
    drop(prev);
    let raw = MOUSE_NODE_PTR.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    let mut mt = ELANTECH_MT.lock();
    let Some(mt) = mt.as_mut() else {
        return;
    };
    // SAFETY: `raw` is the `Arc::as_ptr` of the node stored once in `init()`
    // before IRQ 12 is armed; the Arc is held alive in `MOUSE_EVDEV_NODE`,
    // so the pointee outlives this borrow. Non-null checked just above.
    let node_ref: &DeviceNode = unsafe { &*raw };
    let mut updates = [MtContactUpdate {
        slot: 0,
        active: false,
        tracking_id: 0,
        x: 0,
        y: 0,
        pressure: None,
    }; 5];
    for (slot, s) in frame.slots.iter().enumerate() {
        updates[slot] = MtContactUpdate {
            slot,
            active: s.active,
            tracking_id: slot as i32,
            x: s.x as i32,
            y: s.y as i32,
            pressure: if info.reports_pressure && s.active {
                Some(s.pressure as i32)
            } else {
                None
            },
        };
    }
    mt.dispatch_frame(node_ref, &updates, frame.left, frame.right);
}

fn feed_relative_byte(byte: u8) {
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
        // Elantech never reaches this function (`feed_byte`
        // routes it to `feed_elantech_byte`).
        psmouse::PsmouseProtocol::ElantechV1 | psmouse::PsmouseProtocol::Elantech => (0, 0),
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
/// the shared packet state machine (ALPS / Elantech / relative
/// dispatch — see `feed_byte`); on completion the decoded events
/// ride the global ring and the relative delta accumulates.
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
    STATE.prev_abs_px.store(i32::MIN, Ordering::Release);
    STATE.prev_abs_py.store(i32::MIN, Ordering::Release);
    STATE.touch_pressed.store(false, Ordering::Release);
    STATE.syn_pkt_type.store(0, Ordering::Release);
    *ELANTECH_STATE.lock() = psmouse::ElantechState::new();
    *ELANTECH_PREV.lock() = [psmouse::ElantechSlot::new(); 5];
    *ELANTECH_MT.lock() = None;
    ALPS.lock().reset();
    ALPS_ACTIVE.store(false, Ordering::Release);
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

/// Test-only: force an Elantech protocol + info pair (lets
/// absolute-packet fixtures feed without a device). Restored by
/// `__reset_for_test` (which clears the info via `set_detected`).
pub fn set_elantech_for_test(proto: psmouse::PsmouseProtocol, info: &psmouse::ElantechInfo) {
    psmouse::set_elantech_info_for_test(info);
    psmouse::set_protocol_for_test(proto);
}

/// Test-only: force Synaptics absolute mode with the given packet
/// flavour, so packet fixtures can feed 6-byte packets without a
/// device. `__reset_for_test` restores `Standard`.
pub fn set_synaptics_absolute_for_test(newabs: bool) {
    psmouse::set_detected(
        psmouse::PsmouseHardware::Synaptics,
        psmouse::PsmouseProtocol::SynapticsAbsolute,
    );
    STATE.syn_pkt_type.store(
        psmouse::SynapticsPktType::initial(newabs) as u8,
        Ordering::Release,
    );
}

/// Test-only: point the IRQ-path evdev dispatch at `node`
/// (mirrors what `init()` does after registering the device).
/// The node is kept alive in `MOUSE_EVDEV_NODE`; call
/// `__reset_for_test` afterwards to release it.
pub fn __set_evdev_node_for_test(node: &Arc<DeviceNode>) {
    MOUSE_NODE_PTR.store(Arc::as_ptr(node) as *mut DeviceNode, Ordering::Release);
    *MOUSE_EVDEV_NODE.lock() = Some(node.clone());
}

/// Test-only synthetic packet feed: same logic as the IRQ handler
/// but bypasses port reads. Each call pushes one byte through the
/// state machine, exactly like a real IRQ would.
pub fn feed_byte_for_test(byte: u8) {
    feed_byte(byte);
}

// ── ALPS packet path ────────────────────────────────────────────────────────

/// Global-ring events computed for one decoded ALPS packet.
/// Built while the ALPS lock is held, pushed after it is
/// dropped (the ring takes its own lock). At most one decode
/// produces two touchpad reports (the v1/v2 tap-and-drag
/// synthetic lift + the real packet), each at most 4 touch
/// events + 3 absolute events + 1 pointer event + 1 scroll
/// event; 16 slots cannot overflow.
struct AlpsEmit {
    ring: [Option<InputEvent>; 16],
    len: usize,
}

impl AlpsEmit {
    const fn new() -> Self {
        AlpsEmit {
            ring: [None; 16],
            len: 0,
        }
    }

    fn push(&mut self, ev: InputEvent) {
        if self.len < self.ring.len() {
            self.ring[self.len] = Some(ev);
            self.len += 1;
        }
    }

    fn push_to_ring(self) {
        for ev in self.ring.iter().flatten() {
            let _ = push_global(*ev);
        }
    }
}

/// The ALPS byte feed. Mirrors Linux `alps_process_byte`:
/// the bare-PS/2 check, the interleaved check, the first-byte
/// check, the per-byte validation, then the completed-packet
/// decode. Runs under the ALPS lock; the computed ring events
/// are pushed after the lock is dropped.
fn feed_byte_alps(byte: u8) {
    let mut alps = ALPS.lock();

    // Extension bytes for a stashed interleaved packet.
    if alps.extending {
        if alps.ext_phase == 0 {
            if byte & 0x80 != 0 {
                // A new packet (or garbage) instead of the ALPS
                // tail: process the stashed packet as a plain
                // v2 packet when its tail bytes are clean and
                // this byte starts a valid packet; otherwise
                // drop both and resync (Linux BAD_DATA).
                let stashed = alps.pending_interleaved.take().unwrap_or([0; 6]);
                alps.extending = false;
                let tail_clean = (stashed[3] | stashed[4] | stashed[5]) & 0x80 == 0;
                if tail_clean && alps.decoder.is_valid_first_byte(byte) {
                    let decoded = alps.decoder.decode(&stashed);
                    let mut out = AlpsEmit::new();
                    emit_decoded(&mut alps, decoded, &mut out);
                    drop(alps);
                    out.push_to_ring();
                    STATE.pkt[0].store(byte, Ordering::Release);
                    STATE.phase.store(1, Ordering::Release);
                } else {
                    STATE.phase.store(0, Ordering::Release);
                }
                return;
            }
            alps.ext[0] = byte;
            alps.ext_phase = 1;
            return;
        }
        let ext_phase = alps.ext_phase as usize;
        alps.ext[ext_phase] = byte;
        alps.ext_phase += 1;
        if alps.ext_phase < 3 {
            return;
        }
        let stashed = alps.pending_interleaved.take().unwrap_or([0; 6]);
        let ext = alps.ext;
        alps.extending = false;
        alps.ext_phase = 0;
        STATE.phase.store(0, Ordering::Release);
        let mut frame = [0u8; 9];
        frame[..6].copy_from_slice(&stashed);
        frame[6..].copy_from_slice(&ext);
        let decoded = alps.decoder.decode_interleaved_v2(&frame);
        let mut out = AlpsEmit::new();
        emit_decoded(&mut alps, decoded, &mut out);
        drop(alps);
        out.push_to_ring();
        return;
    }

    let phase = STATE.phase.load(Ordering::Acquire);
    if phase == 0 {
        // Sync: an ALPS first byte, or (PASS devices, never
        // v8) a bare 3-byte PS/2 packet from the pass-through
        // port (Linux `alps_process_byte` bare-packet check).
        if alps.decoder.is_valid_first_byte(byte) {
            alps.bare_candidate = false;
        } else if alps.decoder.protocol.flags & alps::FLAG_PASS != 0
            && alps.decoder.version() != alps::AlpsVersion::V8
            && (byte & 0xc8) == 0x08
        {
            alps.bare_candidate = true;
        } else {
            // Sync byte not recognised — drop until we re-sync.
            return;
        }
    }
    STATE.pkt[phase as usize].store(byte, Ordering::Release);
    let next = phase + 1;

    // A bare pass-through packet completes at 3 bytes.
    if alps.bare_candidate && next == 3 {
        let pkt = [
            STATE.pkt[0].load(Ordering::Acquire),
            STATE.pkt[1].load(Ordering::Acquire),
            STATE.pkt[2].load(Ordering::Acquire),
        ];
        STATE.phase.store(0, Ordering::Release);
        alps.bare_candidate = false;
        let ev = AlpsDecoder::decode_bare_ps2(&pkt);
        let mut out = AlpsEmit::new();
        emit_decoded(&mut alps, AlpsDecode::one(ev), &mut out);
        drop(alps);
        out.push_to_ring();
        return;
    }

    // The interleave trigger is checked before validation
    // (Linux `alps_process_byte` order): byte 3 with low
    // nibble 0x0f on a v2 interleaved pad means a PS/2 packet
    // is stuffed in the middle of the ALPS packet.
    if next == 4
        && alps.decoder.version() == alps::AlpsVersion::V2
        && alps.decoder.protocol.flags & alps::FLAG_PS2_INTERLEAVED != 0
        && (byte & 0x0f) == 0x0f
    {
        alps.interleaved_collecting = true;
    }

    // Per-byte validation (skipped while collecting an
    // interleaved packet — the stuffed dx/dy bytes may have
    // bit 7 set — and for bare pass-through packets).
    if !alps.interleaved_collecting && !alps.bare_candidate {
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate().take(next as usize) {
            *b = STATE.pkt[i].load(Ordering::Acquire);
        }
        if !alps
            .decoder
            .is_valid_packet_byte(&buf[..next as usize], next as usize)
        {
            STATE.phase.store(0, Ordering::Release);
            alps.interleaved_collecting = false;
            alps.bare_candidate = false;
            return;
        }
    }

    let len = alps.decoder.packet_len();
    if (next as usize) < len {
        STATE.phase.store(next, Ordering::Release);
        return;
    }

    // Packet complete.
    let mut pkt = [0u8; 8];
    for i in 0..len {
        pkt[i] = STATE.pkt[i].load(Ordering::Acquire);
    }
    STATE.phase.store(0, Ordering::Release);
    let interleaved = alps.interleaved_collecting;
    alps.interleaved_collecting = false;
    alps.bare_candidate = false;
    if interleaved {
        // Stash the 6-byte packet and wait for the 3
        // extension bytes (Linux starts a 20 ms flush timer
        // here; without one a trailing interleaved-looking
        // packet stays stashed until more bytes arrive).
        let mut stashed = [0u8; 6];
        stashed.copy_from_slice(&pkt[..6]);
        alps.pending_interleaved = Some(stashed);
        alps.extending = true;
        alps.ext_phase = 0;
        return;
    }
    let decoded = alps.decoder.decode(&pkt[..len]);
    let mut out = AlpsEmit::new();
    emit_decoded(&mut alps, decoded, &mut out);
    drop(alps);
    out.push_to_ring();
}

/// Emit one decoded ALPS packet: evdev dispatch runs here
/// (under the ALPS lock — the MT emitter state lives in it),
/// global-ring events accumulate in `out` for the caller to
/// push after dropping the lock.
fn emit_decoded(alps: &mut AlpsState, decoded: alps::AlpsDecode, out: &mut AlpsEmit) {
    for ev in decoded.events.iter().flatten() {
        match *ev {
            AlpsEvent::Touchpad(f) => emit_touchpad(alps, &f, out),
            AlpsEvent::Trackstick {
                dx,
                dy,
                left,
                right,
                middle,
                ..
            } => emit_relative(dx, dy, left, right, middle, out),
            AlpsEvent::BarePs2 {
                dx,
                dy,
                left,
                right,
                middle,
            } => emit_relative(dx, dy, left, right, middle, out),
        }
    }
}

/// Emit a touchpad report: TouchEvents per slot (with
/// Down/Move/Up state from the previous frame), single-touch
/// AbsoluteEvents, a PointerEvent on button change, a
/// ScrollEvent for the v1/v2 wheel, and the evdev MT frame
/// (slot protocol B + BTN_TOUCH + left/right; the middle
/// button rides a separate key edge — the MT emitter covers
/// left/right only).
fn emit_touchpad(alps: &mut AlpsState, f: &AlpsFields, out: &mut AlpsEmit) {
    let live = (f.fingers as usize).min(4);
    let mut updates: [MtContactUpdate; 8] = [MtContactUpdate {
        slot: 0,
        active: false,
        tracking_id: 0,
        x: 0,
        y: 0,
        pressure: None,
    }; 8];
    let mut n_updates = 0usize;
    for slot in 0..4 {
        let was_live = alps.prev_slots & (1 << slot) != 0;
        let is_live = slot < live;
        if is_live {
            let (x, y) = (f.mt[slot].x, f.mt[slot].y);
            let state = if was_live {
                TouchState::Move
            } else {
                TouchState::Down
            };
            out.push(InputEvent::Touch(TouchEvent {
                slot: slot as u8,
                tracking_id: Some(slot as i32),
                id: slot as u16,
                x,
                y,
                pressure: f.pressure,
                state,
            }));
            alps.prev_pos[slot] = (x, y);
            updates[n_updates] = MtContactUpdate {
                slot,
                active: true,
                tracking_id: slot as i32,
                x,
                y,
                pressure: Some(f.pressure),
            };
            n_updates += 1;
        } else if was_live {
            let (x, y) = alps.prev_pos[slot];
            out.push(InputEvent::Touch(TouchEvent {
                slot: slot as u8,
                tracking_id: Some(slot as i32),
                id: slot as u16,
                x,
                y,
                pressure: 0,
                state: TouchState::Up,
            }));
            updates[n_updates] = MtContactUpdate {
                slot,
                active: false,
                tracking_id: 0,
                x: 0,
                y: 0,
                pressure: None,
            };
            n_updates += 1;
        }
    }
    // Previous-frame slot mask for the next report.
    let mut mask = 0u8;
    for slot in 0..live {
        mask |= 1 << slot;
    }
    alps.prev_slots = mask;

    // Single-touch compatibility axes follow slot 0.
    if live > 0 {
        out.push(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_X,
            value: f.mt[0].x,
        }));
        out.push(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_Y,
            value: f.mt[0].y,
        }));
        out.push(InputEvent::Absolute(AbsoluteEvent {
            axis: abs::ABS_PRESSURE,
            value: f.pressure,
        }));
    }

    // Pointer buttons on change only (the evdev path also
    // emits edges; the ring consumer wants the same).
    let prev_mask = alps.prev_buttons;
    let mut buttons = PointerButtons::EMPTY;
    if f.left {
        buttons.insert(PointerButtons::LEFT);
    }
    if f.right {
        buttons.insert(PointerButtons::RIGHT);
    }
    if f.middle {
        buttons.insert(PointerButtons::MIDDLE);
    }
    if f.forward {
        buttons.insert(PointerButtons::FORWARD);
    }
    if f.back {
        buttons.insert(PointerButtons::BACK);
    }
    let cur_mask = buttons.bits();
    if cur_mask != prev_mask {
        alps.prev_buttons = cur_mask;
        out.push(InputEvent::Pointer(PointerEvent {
            dx: 0,
            dy: 0,
            buttons,
        }));
    }

    if f.wheel != 0 {
        out.push(InputEvent::Scroll(ScrollEvent { dx: 0, dy: f.wheel }));
    }

    // Evdev: MT frame (left/right + BTN_TOUCH) plus the middle
    // button edge, which the MT emitter does not cover.
    let raw = MOUSE_NODE_PTR.load(Ordering::Acquire);
    if !raw.is_null() {
        // SAFETY: same as `dispatch_packet_to_evdev` — the Arc
        // is held alive in `MOUSE_EVDEV_NODE`.
        let node_ref: &DeviceNode = unsafe { &*raw };
        if let Some(mt) = alps.mt.as_mut() {
            mt.dispatch_frame(node_ref, &updates[..n_updates], f.left, f.right);
        }
        if f.middle != (prev_mask & PointerButtons::MIDDLE.bits() != 0) {
            dispatch_key_to_node(node_ref, key::BTN_MIDDLE, f.middle);
        }
    }
}

/// Emit relative motion (trackstick / bare-PS/2 packet): the
/// relative accumulator, the packet count, a PointerEvent, and
/// the evdev pointer frame.
fn emit_relative(dx: i32, dy: i32, left: bool, right: bool, middle: bool, out: &mut AlpsEmit) {
    let mut buttons = PointerButtons::EMPTY;
    if left {
        buttons.insert(PointerButtons::LEFT);
    }
    if right {
        buttons.insert(PointerButtons::RIGHT);
    }
    if middle {
        buttons.insert(PointerButtons::MIDDLE);
    }
    STATE.rel_dx_acc.fetch_add(dx, Ordering::Relaxed);
    STATE.rel_dy_acc.fetch_add(dy, Ordering::Relaxed);
    narf_input::I8042_MOUSE_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
    out.push(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));
    dispatch_packet_to_evdev(dx, dy, 0, 0, buttons);
}
