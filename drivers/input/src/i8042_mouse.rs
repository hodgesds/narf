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
//!      then 0xD4 + 0xF6 (set defaults), 0xD4 + 0xF4 (enable
//!      data reporting). Each pair is best-effort — a system
//!      without a PS/2 mouse won't ack but the kernel keeps
//!      booting.
//!
//! ALPS absolute mode (`crate::alps`): once a pad is identified
//! (see `alps::probe_alps` — the probe itself lives with the
//! vendor negotiation in `psmouse`, PR #1676) the packet length
//! becomes 6 bytes (8 for v4) and complete packets are decoded
//! by `alps::AlpsDecoder`. Touchpad reports ride the global ring
//! as `TouchEvent`s (one per live slot, with `Down` / `Move` /
//! `Up` state) plus single-touch `AbsoluteEvent`s, and evdev via
//! the slot-protocol-B emitter (`MtEvdevState`). Trackstick and
//! bare-PS/2 packets ride the relative `PointerEvent` path.
//! Activation is explicit (`set_alps_protocol`); until then the
//! 3-byte path below is byte-for-byte the old behaviour.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

use narf_arch::x86_64::io_port::{inb, outb};
use narf_input::{
    abs,
    evdev::{
        dispatch_key_to_node, dispatch_pointer_to_node, key, rel, DeviceCaps, DeviceNode,
        MtContactUpdate, MtEvdevState, ROUTER,
    },
    push_global, AbsoluteEvent, InputEvent, PointerButtons, PointerEvent, ScrollEvent, TouchEvent,
    TouchState,
};

extern crate alloc;
use alloc::sync::Arc;

use crate::alps::{self, AlpsDecode, AlpsDecoder, AlpsEvent, AlpsFields, AlpsProtocol};
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
    /// Bytes 0..=7 of the in-flight packet. `phase` tracks how
    /// many bytes we've collected. When phase reaches the
    /// negotiated packet length (3 standard, 6 ALPS, 8 ALPS v4)
    /// we emit the decoded events + reset to 0.
    pkt: [AtomicU8; 8],
    phase: AtomicU8,
    rel_dx_acc: AtomicI32,
    rel_dy_acc: AtomicI32,
    /// Last reported button bitmask (bit0=left, bit1=right, bit2=middle),
    /// so evdev `EV_KEY` events are emitted only on press/release edges.
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
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
            ],
            phase: AtomicU8::new(0),
            rel_dx_acc: AtomicI32::new(0),
            rel_dy_acc: AtomicI32::new(0),
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

/// Raw pointer cache for lock-free IRQ access.
static MOUSE_NODE_PTR: core::sync::atomic::AtomicPtr<DeviceNode> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

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
    let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
    // SAFETY: 0x64 cmd write; `CMD_WRITE_AUX` (0xD4) routes the next 0x60 byte
    // to the AUX (mouse) channel instead of the keyboard.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_CMD, CMD_WRITE_AUX);
    }
    let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
    // SAFETY: 0x60 data write; the preceding 0xD4 forwards this 0xFF (mouse
    // reset) to the AUX device.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        outb(PS2_DATA, 0xFF);
    }
    let mut reporting_ok = wait_output_ms(MOUSE_REPLY_MS) == Some(MOUSE_ACK);
    if reporting_ok {
        if wait_output_ms(MOUSE_BAT_MS) != Some(MOUSE_BAT_OK) {
            reporting_ok = false;
        }
        // Device id (0x00 for standard mouse) follows BAT but
        // is informational; don't gate on it.
        let _ = wait_output_ms(MOUSE_REPLY_MS);
    }

    if reporting_ok {
        // 4a. Set defaults (0xF6) — ACK.
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        // SAFETY: 0x64 cmd write; `CMD_WRITE_AUX` (0xD4) routes the next 0x60
        // byte to the AUX (mouse) channel.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            outb(PS2_CMD, CMD_WRITE_AUX);
        }
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        // SAFETY: 0x60 data write; the preceding 0xD4 forwards this 0xF6 (set
        // defaults) to the AUX device.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            outb(PS2_DATA, 0xF6);
        }
        if wait_output_ms(MOUSE_REPLY_MS) != Some(MOUSE_ACK) {
            reporting_ok = false;
        }
    }

    if reporting_ok {
        // 4b. Enable data reporting (0xF4) — ACK. This flips the
        // mouse from "idle" to "actively sending packets."
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        // SAFETY: 0x64 cmd write; `CMD_WRITE_AUX` (0xD4) routes the next 0x60
        // byte to the AUX (mouse) channel.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            outb(PS2_CMD, CMD_WRITE_AUX);
        }
        let _ = wait_input_clear_ms(MOUSE_REPLY_MS);
        // SAFETY: 0x60 data write; the preceding 0xD4 forwards this 0xF4 (enable
        // data reporting) to the AUX device.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            outb(PS2_DATA, 0xF4);
        }
        if wait_output_ms(MOUSE_REPLY_MS) != Some(MOUSE_ACK) {
            reporting_ok = false;
        }
    }

    let _ = reporting_ok; // tracked via STATE.initialized only; mouse
                          // doesn't have a separate panel atom yet.
    STATE.initialized.store(true, Ordering::Release);

    // Register the PS/2 mouse as an evdev device.
    let mut caps = DeviceCaps::new();
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

/// IRQ-12 handler. Reads one byte from 0x60, advances the
/// packet state machine, and on completion pushes the decoded
/// events + accumulates the relative delta.
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
    ALPS.lock().reset();
    ALPS_ACTIVE.store(false, Ordering::Release);
}

/// Test-only synthetic packet feed: same logic as the IRQ handler
/// but bypasses port reads. Each call pushes one byte through the
/// state machine, exactly like a real IRQ would.
pub fn feed_byte_for_test(byte: u8) {
    feed_byte(byte);
}

/// Route one AUX byte through the packet state machine: the
/// 3-byte path while ALPS is inactive, the ALPS packet path
/// once a protocol is negotiated.
fn feed_byte(byte: u8) {
    if ALPS_ACTIVE.load(Ordering::Acquire) {
        feed_byte_alps(byte);
    } else {
        feed_byte_standard(byte);
    }
}

/// The bare 3-byte PS/2 path (unchanged behaviour).
fn feed_byte_standard(byte: u8) {
    let phase = STATE.phase.load(Ordering::Acquire);
    if phase == 0 && (byte & 0x08) == 0 {
        // Sync bit not set — drop until we re-sync.
        return;
    }
    STATE.pkt[phase as usize].store(byte, Ordering::Release);
    let next = phase + 1;
    if next < 3 {
        STATE.phase.store(next, Ordering::Release);
        return;
    }
    STATE.phase.store(0, Ordering::Release);
    complete_standard_packet();
}

/// Decode + emit a completed 3-byte packet (shared by the IRQ
/// and test feed paths).
fn complete_standard_packet() {
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
    let b0 = (left as u8) | ((right as u8) << 1) | ((middle as u8) << 2);
    dispatch_packet_to_evdev(dx, dy, b0);
}
