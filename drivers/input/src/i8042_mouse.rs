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
//! Init sequence:
//!   1. Enable the AUX channel via cmd 0xA8.
//!   2. Set bit 1 (AUX IRQ) in the controller config; clear bit 5
//!      (AUX disable).
//!   3. Send 0xD4 + 0xFF on the data port to reset the device,
//!      then 0xD4 + 0xF6 (set defaults). Each pair is best-effort —
//!      a system without a PS/2 mouse won't ack but the kernel
//!      keeps booting.
//!   4. Synaptics absolute-mode enablement (`crate::psmouse`):
//!      detect (4x SETRES(0) + GETINFO, byte 0x47), query the
//!      hardware (identify/model/firmware/board/capability/
//!      resolution), then set the absolute mode byte (ABSOLUTE +
//!      HIGH_RATE + W_MODE + DISABLE_GESTURE, committed with
//!      SETRATE 0x14). On success the pad streams 6-byte absolute
//!      packets; on any failure it stays a 3-byte relative mouse.
//!   5. Send 0xD4 + 0xF4 (enable data reporting). This flips the
//!      mouse from "idle" to "actively sending packets."
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

use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{
    abs as abs_code,
    evdev::{
        dispatch_pointer_to_node, dispatch_synaptics_abs_to_node, key, rel, DeviceCaps, DeviceNode,
        ROUTER,
    },
    push_global, scanout_dims, set_cursor_abs_px, AxisInfo, InputEvent, PointerButtons,
    PointerEvent,
};

use crate::psmouse::{self, Ps2Transport};

extern crate alloc;
use alloc::sync::Arc;

use crate::i8042::{PS2_CMD, PS2_DATA, PS2_STATUS};

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
    /// Bytes 0.. of the in-flight packet (3-byte relative or
    /// 6-byte Synaptics absolute). `phase` tracks how many bytes
    /// we've collected. When phase reaches the negotiated packet
    /// length, we emit the event(s) + reset to 0.
    pkt: [AtomicU8; 6],
    phase: AtomicU8,
    rel_dx_acc: AtomicI32,
    rel_dy_acc: AtomicI32,
    /// Last reported button bitmask (bit0=left, bit1=right, bit2=middle),
    /// so evdev `EV_KEY` events are emitted only on press/release edges.
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
            ],
            phase: AtomicU8::new(0),
            rel_dx_acc: AtomicI32::new(0),
            rel_dy_acc: AtomicI32::new(0),
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

/// Raw pointer cache for lock-free IRQ access.
static MOUSE_NODE_PTR: core::sync::atomic::AtomicPtr<DeviceNode> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn take_rel_delta() -> (i32, i32) {
    let dx = STATE.rel_dx_acc.swap(0, Ordering::AcqRel);
    let dy = STATE.rel_dy_acc.swap(0, Ordering::AcqRel);
    (dx, dy)
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
/// Used by `psmouse::synaptics_enable_absolute` during `init()`.
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
        // 4b. Synaptics absolute-mode enablement (see
        // `crate::psmouse`): detect, query, mode set. Must run
        // while reporting is still disabled and before the 0xF4
        // enable below. On any failure the pad stays a 3-byte
        // relative mouse — the packet parser keys off the
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
        // 4c. Enable data reporting (0xF4) — ACK. This flips the
        // mouse from "idle" to "actively sending packets" — for a
        // negotiated Synaptics pad, the 6-byte absolute stream.
        if !aux_send(psmouse::CMD_ENABLE) {
            reporting_ok = false;
        }
    }

    let _ = reporting_ok; // tracked via STATE.initialized only; mouse
                          // doesn't have a separate panel atom yet.
    STATE.initialized.store(true, Ordering::Release);

    // Register the PS/2 mouse as an evdev device. Capabilities
    // follow the negotiated protocol: a Synaptics pad in absolute
    // mode advertises ABS_X/ABS_Y (nominal ranges — the queried
    // min/max are a later refinement) + ABS_PRESSURE + BTN_TOUCH
    // + BTN_LEFT/RIGHT (Linux `set_input_params`); anything else
    // stays the relative pointer from before.
    let absolute = psmouse::protocol() == psmouse::PsmouseProtocol::SynapticsAbsolute;
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
            abs_code::ABS_X,
            AxisInfo {
                min: psmouse::SYN_X_MIN_NOMINAL,
                max: psmouse::SYN_X_MAX_NOMINAL,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
        );
        caps.add_abs_info(
            abs_code::ABS_Y,
            AxisInfo {
                min: psmouse::SYN_Y_MIN_NOMINAL,
                max: psmouse::SYN_Y_MAX_NOMINAL,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
        );
        caps.add_abs_info(
            abs_code::ABS_PRESSURE,
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
        caps.set_identity(
            "PS/2 Generic Mouse",
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
    }
    let (_dev_id, node_arc) = ROUTER.register_device(caps);
    MOUSE_NODE_PTR.store(Arc::as_ptr(&node_arc) as *mut DeviceNode, Ordering::Release);
    *MOUSE_EVDEV_NODE.lock() = Some(node_arc);

    Ok(())
}

/// Return the evdev `DeviceNode` for the PS/2 mouse if registered.
pub fn mouse_evdev_node() -> Option<Arc<DeviceNode>> {
    MOUSE_EVDEV_NODE.lock().clone()
}

/// Route a decoded packet (`dx`/`dy` motion + raw button byte `b0`) to the
/// evdev node as one frame. Button `EV_KEY` events are emitted only on
/// press/release edges (compared against `STATE.prev_buttons`) so a held
/// button isn't re-reported every packet. Without this the compositor saw
/// motion but never clicks.
fn dispatch_packet_to_evdev(dx: i32, dy: i32, b0: u8) {
    let raw = MOUSE_NODE_PTR.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: `raw` is the `Arc::as_ptr` of the node stored once in `init()`
    // before IRQ 12 is armed; the Arc is held alive in `MOUSE_EVDEV_NODE`,
    // so the pointee outlives this borrow. Non-null checked just above.
    let node_ref: &DeviceNode = unsafe { &*raw };

    let cur_btn = b0 & 0x07; // bit0 left, bit1 right, bit2 middle
    let prev_btn = STATE.prev_buttons.swap(cur_btn, Ordering::AcqRel);
    let changed = cur_btn ^ prev_btn;
    let mut changes: [(u16, bool); 3] = [(0, false); 3];
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
    dispatch_pointer_to_node(node_ref, dx, dy, &changes[..n]);
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

/// Decode a completed 3-byte relative packet (existing behaviour).
fn decode_relative_packet() {
    let b0 = STATE.pkt[0].load(Ordering::Acquire);
    let b1 = STATE.pkt[1].load(Ordering::Acquire) as i16;
    let b2 = STATE.pkt[2].load(Ordering::Acquire) as i16;

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

    STATE.rel_dx_acc.fetch_add(dx, Ordering::Relaxed);
    STATE.rel_dy_acc.fetch_add(dy, Ordering::Relaxed);
    narf_input::I8042_MOUSE_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);

    // Legacy global ring (for cursor pump / FB status panel).
    let _ = push_global(InputEvent::Pointer(PointerEvent { dx, dy, buttons }));

    // Evdev routing — motion + button edges in one frame.
    dispatch_packet_to_evdev(dx, dy, b0);
}

/// Decode a completed 6-byte Synaptics absolute packet (Linux
/// `synaptics_process_packet`, single-finger path): evdev ABS +
/// BTN_TOUCH + buttons, plus the legacy relative bridge.
fn decode_absolute_packet() {
    let mut buf = [0u8; 6];
    for (i, slot) in STATE.pkt.iter().enumerate() {
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

/// One shared packet state machine for IRQ 12 and the test feed:
/// collect bytes up to the negotiated packet length, then decode.
/// A 3-byte packet re-syncs on the status sync bit; a 6-byte
/// Synaptics packet validates every byte except the last (Linux
/// `synaptics_validate_byte`, idx 0..=4) and drops the partial
/// packet on the first bad byte.
fn feed_byte(byte: u8) {
    let pkt_len = psmouse::packet_len();
    let phase = STATE.phase.load(Ordering::Acquire) as usize;
    if pkt_len == 6 {
        if phase <= 4 {
            let mut probe = [0u8; 6];
            for (i, slot) in STATE.pkt.iter().enumerate() {
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
    } else if phase == 0 && (byte & 0x08) == 0 {
        // Sync bit not set — drop until we re-sync.
        return;
    }
    STATE.pkt[phase].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < pkt_len {
        STATE.phase.store(next as u8, Ordering::Release);
        return;
    }
    STATE.phase.store(0, Ordering::Release);
    if pkt_len == 6 {
        decode_absolute_packet();
    } else {
        decode_relative_packet();
    }
}

/// IRQ-12 handler. Reads one byte from 0x60 and pushes it through
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
    STATE.prev_buttons.store(0, Ordering::Release);
    STATE.prev_abs_px.store(i32::MIN, Ordering::Release);
    STATE.prev_abs_py.store(i32::MIN, Ordering::Release);
    STATE.touch_pressed.store(false, Ordering::Release);
    STATE.syn_pkt_type.store(0, Ordering::Release);
    psmouse::set_protocol_for_test(psmouse::PsmouseProtocol::Standard);
    MOUSE_NODE_PTR.store(core::ptr::null_mut(), Ordering::Release);
    *MOUSE_EVDEV_NODE.lock() = None;
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
